from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from bgp_incident_detection.audit import parse_utc, write_csv
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import parse_utc, write_csv


ROSTER_PATH = Path("data/roster_v2/frozen_incident_roster_v2.csv")
MANIFEST_PATH = Path("data/partitions_v2/frozen_partition_manifest_v2.csv")
PILOT_DIR = Path("data/pilot")
RAW_MRT_DIR = Path("data/raw_mrt/pilot")
PILOT_MANIFEST = PILOT_DIR / "mrt_pilot_incidents_v1.csv"
ACQUISITION_PLAN = PILOT_DIR / "mrt_pilot_acquisition_plan_v1.csv"
ACQUISITION_AUDIT = PILOT_DIR / "mrt_pilot_acquisition_audit.csv"
ROUTEVIEWS_PLAN = PILOT_DIR / "routeviews_source_plan_v1.md"

PILOT_VERSION = "v1"
DEFAULT_COLLECTOR = "route-views2"
DEFAULT_BUFFER_BEFORE_MINUTES = 60
DEFAULT_BUFFER_AFTER_MINUTES = 60
PILOT_BUCKET_QUANTILES = {
    "short": 0.10,
    "median": 0.50,
    "long": 0.90,
}
CLASS_LABELS = ("Hijack", "Leak", "Outage")


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def load_train_roster(
    roster_path: Path = ROSTER_PATH,
    manifest_path: Path = MANIFEST_PATH,
) -> list[dict[str, str]]:
    roster = {row["incident_uid"]: row for row in load_csv(roster_path)}
    manifest = load_csv(manifest_path)
    rows = []
    for partition_row in manifest:
        if partition_row["partition"] != "train":
            continue
        row = dict(roster[partition_row["incident_uid"]])
        row["partition"] = partition_row["partition"]
        rows.append(row)
    return rows


def percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("cannot calculate percentile for an empty sequence")
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def select_pilot_incidents(train_rows: list[dict[str, str]]) -> list[dict[str, str]]:
    selected: list[dict[str, str]] = []
    for category in CLASS_LABELS:
        category_rows = [row for row in train_rows if row["category"] == category]
        if len(category_rows) < len(PILOT_BUCKET_QUANTILES):
            raise ValueError(f"not enough TRAIN rows for {category}")
        durations = [float(row["duration_minutes"]) for row in category_rows]
        used: set[str] = set()
        for bucket, quantile in PILOT_BUCKET_QUANTILES.items():
            target = percentile(durations, quantile)
            candidates = sorted(
                [row for row in category_rows if row["incident_uid"] not in used],
                key=lambda row: (
                    abs(float(row["duration_minutes"]) - target),
                    -float(row.get("quality_score") or 0),
                    row["incident_uid"],
                ),
            )
            row = dict(candidates[0])
            row["pilot_duration_bucket"] = bucket
            row["pilot_duration_target_minutes"] = round(target, 3)
            used.add(row["incident_uid"])
            selected.append(row)
    return selected


def floor_to_15_minutes(value: datetime) -> datetime:
    return value.replace(minute=(value.minute // 15) * 15, second=0, microsecond=0)


def ceil_to_15_minutes(value: datetime) -> datetime:
    floored = floor_to_15_minutes(value)
    if value == floored:
        return value
    return floored + timedelta(minutes=15)


def isoformat_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def routeviews_month_path(value: datetime) -> str:
    return f"{value.year}.{value.month:02d}"


def routeviews_update_filename(value: datetime) -> str:
    return f"updates.{value:%Y%m%d.%H%M}.bz2"


def routeviews_base_url(collector: str = DEFAULT_COLLECTOR) -> str:
    if collector == "route-views2":
        return "https://archive.routeviews.org/bgpdata/"
    return f"https://archive.routeviews.org/{collector}/bgpdata/"


def routeviews_update_url(value: datetime, collector: str = DEFAULT_COLLECTOR) -> str:
    return f"{routeviews_base_url(collector)}{routeviews_month_path(value)}/UPDATES/{routeviews_update_filename(value)}"


def iter_update_slots(start: datetime, end: datetime) -> list[datetime]:
    slots: list[datetime] = []
    cursor = start
    while cursor <= end:
        slots.append(cursor)
        cursor += timedelta(minutes=15)
    return slots


def local_destination(row: dict[str, str], raw_root: Path = RAW_MRT_DIR) -> str:
    return str(raw_root / row["incident_uid"].replace(":", "_"))


def source_provenance(row: dict[str, str]) -> str:
    if row.get("source_url"):
        return row["source_url"]
    if "Cloudflare Radar" in row.get("notes", ""):
        return f"Cloudflare Radar event id {row['incident_id']}"
    return f"source record id {row['incident_id']}"


def build_pilot_manifest_rows(selected: list[dict[str, str]]) -> list[dict[str, object]]:
    rows = []
    for row in selected:
        leak_value = row["primary_asn"] if row["category"] == "Leak" else ""
        leak_seg = row["affected_asns"] if row["category"] == "Leak" else ""
        rows.append(
            {
                "incident_uid": row["incident_uid"],
                "category": row["category"],
                "partition": row["partition"],
                "start_utc": row["start_utc"],
                "end_utc": row["end_utc"],
                "duration_minutes": row["duration_minutes"],
                "affected_asns": row.get("affected_asns", ""),
                "affected_prefixes": row.get("affected_prefixes", ""),
                "leak_asn": leak_value,
                "leak_seg": leak_seg,
                "source/provenance": source_provenance(row),
                "pilot_duration_bucket": row["pilot_duration_bucket"],
            }
        )
    return rows


def build_acquisition_plan_rows(
    selected: list[dict[str, str]],
    collector: str = DEFAULT_COLLECTOR,
    buffer_before_minutes: int = DEFAULT_BUFFER_BEFORE_MINUTES,
    buffer_after_minutes: int = DEFAULT_BUFFER_AFTER_MINUTES,
) -> list[dict[str, object]]:
    rows = []
    for row in selected:
        incident_start = parse_utc(row["start_utc"])
        incident_end = parse_utc(row["end_utc"])
        if not incident_start or not incident_end:
            raise ValueError(f"invalid timestamps for {row['incident_uid']}")
        collection_start = floor_to_15_minutes(incident_start - timedelta(minutes=buffer_before_minutes))
        collection_end = ceil_to_15_minutes(incident_end + timedelta(minutes=buffer_after_minutes))
        slots = iter_update_slots(collection_start, collection_end)
        urls = [routeviews_update_url(slot, collector) for slot in slots]
        rows.append(
            {
                "incident_uid": row["incident_uid"],
                "category": row["category"],
                "partition": row["partition"],
                "collector": collector,
                "collection_buffer_before_minutes": buffer_before_minutes,
                "collection_buffer_after_minutes": buffer_after_minutes,
                "collection_start": isoformat_z(collection_start),
                "collection_end": isoformat_z(collection_end),
                "mrt_urls": json.dumps(urls),
                "expected_file_count": len(urls),
                "local_destination": local_destination(row),
                "availability_check_status": "not_checked_dry_run",
            }
        )
    return rows


def audit_rows(
    selected: list[dict[str, str]],
    plan_rows: list[dict[str, object]],
) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    selected_by_uid = {row["incident_uid"]: row for row in selected}
    for plan in plan_rows:
        row = selected_by_uid[plan["incident_uid"]]
        start = parse_utc(row["start_utc"])
        end = parse_utc(row["end_utc"])
        collection_start = parse_utc(str(plan["collection_start"]))
        collection_end = parse_utc(str(plan["collection_end"]))
        urls = json.loads(str(plan["mrt_urls"]))
        checks = [
            (
                "incident_belongs_to_train",
                row["partition"] == "train",
                f"partition={row['partition']}",
            ),
            (
                "valid_utc_timestamps",
                bool(start and end and start < end),
                f"start={row['start_utc']} end={row['end_utc']}",
            ),
            (
                "acquisition_window_valid",
                bool(collection_start and collection_end and collection_start <= start and collection_end >= end),
                f"collection_start={plan['collection_start']} collection_end={plan['collection_end']}",
            ),
            (
                "routeviews_url_generation_valid",
                bool(urls and all(url.startswith("https://archive.routeviews.org/") and url.endswith(".bz2") for url in urls)),
                f"expected_file_count={plan['expected_file_count']}",
            ),
            (
                "expected_mrt_files_found_available",
                None,
                "dry-run only; remote HEAD availability not checked and no MRT files downloaded",
            ),
            (
                "no_validation_holdout_incident_used",
                row["partition"] == "train",
                "pilot selection restricted to TRAIN",
            ),
        ]
        for check_name, passed, evidence in checks:
            if passed is None:
                status = "REVIEW"
            else:
                status = "PASS" if passed else "FAIL"
            output.append(
                {
                    "incident_uid": row["incident_uid"],
                    "category": row["category"],
                    "partition": row["partition"],
                    "check_name": check_name,
                    "status": status,
                    "evidence": evidence,
                }
            )
    return output


def write_routeviews_plan(path: Path = ROUTEVIEWS_PLAN, collector: str = DEFAULT_COLLECTOR) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                "# RouteViews Source Plan v1",
                "",
                f"- Collector: `{collector}`",
                "- Source: RouteViews archive UPDATE files.",
                "- Archive URL pattern for named collectors: `https://archive.routeviews.org/<collector>/bgpdata/YYYY.MM/UPDATES/updates.YYYYMMDD.HHMM.bz2`",
                "- Initial pilot collector path for `route-views2`: `https://archive.routeviews.org/bgpdata/YYYY.MM/UPDATES/updates.YYYYMMDD.HHMM.bz2`",
                "- UPDATE cadence: 15-minute UTC slots.",
                "- Filename convention: `updates.YYYYMMDD.HHMM.bz2`.",
                "- UTC handling: incident timestamps are parsed as UTC; collection starts are floored to the previous 15-minute boundary and collection ends are ceiled to the next 15-minute boundary after adding configurable context buffers.",
                "- This phase is dry-run only. URL availability is marked REVIEW until a non-downloading remote availability check is approved and performed.",
                "- RIPE RIS is not used in this pilot unless a later review shows RouteViews coverage is inadequate for a selected incident.",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def create_raw_destination_dirs(selected: list[dict[str, str]], raw_root: Path = RAW_MRT_DIR) -> None:
    for row in selected:
        Path(local_destination(row, raw_root)).mkdir(parents=True, exist_ok=True)


def run_dry_run(
    collector: str = DEFAULT_COLLECTOR,
    buffer_before_minutes: int = DEFAULT_BUFFER_BEFORE_MINUTES,
    buffer_after_minutes: int = DEFAULT_BUFFER_AFTER_MINUTES,
) -> dict[str, list[dict[str, object]]]:
    train_rows = load_train_roster()
    selected = select_pilot_incidents(train_rows)
    pilot_rows = build_pilot_manifest_rows(selected)
    plan_rows = build_acquisition_plan_rows(selected, collector, buffer_before_minutes, buffer_after_minutes)
    audit = audit_rows(selected, plan_rows)
    write_csv(
        PILOT_MANIFEST,
        pilot_rows,
        [
            "incident_uid",
            "category",
            "partition",
            "start_utc",
            "end_utc",
            "duration_minutes",
            "affected_asns",
            "affected_prefixes",
            "leak_asn",
            "leak_seg",
            "source/provenance",
            "pilot_duration_bucket",
        ],
    )
    write_csv(
        ACQUISITION_PLAN,
        plan_rows,
        [
            "incident_uid",
            "category",
            "partition",
            "collector",
            "collection_buffer_before_minutes",
            "collection_buffer_after_minutes",
            "collection_start",
            "collection_end",
            "mrt_urls",
            "expected_file_count",
            "local_destination",
            "availability_check_status",
        ],
    )
    write_csv(
        ACQUISITION_AUDIT,
        audit,
        ["incident_uid", "category", "partition", "check_name", "status", "evidence"],
    )
    write_routeviews_plan(collector=collector)
    create_raw_destination_dirs(selected)
    return {"pilot": pilot_rows, "plan": plan_rows, "audit": audit}


def print_dry_run(results: dict[str, list[dict[str, object]]]) -> None:
    print("MRT acquisition pilot dry-run")
    print("Pilot incidents:", len(results["pilot"]))
    print("Pilot class counts:", dict(Counter(row["category"] for row in results["pilot"])))
    for row in results["plan"]:
        urls = json.loads(str(row["mrt_urls"]))
        preview = urls[:3]
        if len(urls) > 3:
            preview.append(f"... {len(urls) - 3} more URLs")
        print(
            json.dumps(
                {
                    "incident_uid": row["incident_uid"],
                    "collector": row["collector"],
                    "collection_start": row["collection_start"],
                    "collection_end": row["collection_end"],
                    "MRT URLs": preview,
                    "expected_file_count": row["expected_file_count"],
                    "local_destination": row["local_destination"],
                },
                sort_keys=True,
            )
        )
    print("Audit status counts:", dict(Counter(row["status"] for row in results["audit"])))
    print("Dry-run only: no MRT files downloaded.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the RouteViews MRT pilot acquisition dry-run plan.")
    parser.add_argument("--collector", default=DEFAULT_COLLECTOR)
    parser.add_argument("--buffer-before-minutes", type=int, default=DEFAULT_BUFFER_BEFORE_MINUTES)
    parser.add_argument("--buffer-after-minutes", type=int, default=DEFAULT_BUFFER_AFTER_MINUTES)
    args = parser.parse_args()
    results = run_dry_run(args.collector, args.buffer_before_minutes, args.buffer_after_minutes)
    print_dry_run(results)


if __name__ == "__main__":
    main()
