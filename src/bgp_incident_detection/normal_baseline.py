from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    from bgp_incident_detection.audit import parse_listish, parse_utc, write_csv
    from bgp_incident_detection.behavioral_features import FEATURE_INVENTORY
    from bgp_incident_detection.mrt_acquisition import (
        DEFAULT_COLLECTOR,
        ceil_to_15_minutes,
        floor_to_15_minutes,
        isoformat_z,
        iter_update_slots,
        routeviews_update_url,
    )
    from bgp_incident_detection.mrt_download import CONTEXT_BUFFER_MINUTES
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import parse_listish, parse_utc, write_csv
    from src.bgp_incident_detection.behavioral_features import FEATURE_INVENTORY
    from src.bgp_incident_detection.mrt_acquisition import (
        DEFAULT_COLLECTOR,
        ceil_to_15_minutes,
        floor_to_15_minutes,
        isoformat_z,
        iter_update_slots,
        routeviews_update_url,
    )
    from src.bgp_incident_detection.mrt_download import CONTEXT_BUFFER_MINUTES


PILOT_DIR = Path("data/pilot")
CONFIG_DIR = Path("config")
ROSTER = Path("data/roster_v2/frozen_incident_roster_v2.csv")
PARTITION_MANIFEST = Path("data/partitions_v2/frozen_partition_manifest_v2.csv")
PILOT_MANIFEST = PILOT_DIR / "mrt_pilot_incidents_v1.csv"
ACTIVE_SEGMENTS = PILOT_DIR / "pilot_candidate_active_segments_v1.csv"

BEHAVIORAL_SCHEMA_YAML = CONFIG_DIR / "behavioral_feature_schema_v1.yaml"
BEHAVIORAL_SCHEMA_FREEZE = PILOT_DIR / "behavioral_feature_schema_freeze_v1.csv"
NORMAL_CANDIDATES = PILOT_DIR / "normal_candidate_periods_v1.csv"
BUFFER_SENSITIVITY = PILOT_DIR / "normal_exclusion_buffer_sensitivity_v1.csv"
STABILITY_SENSITIVITY = PILOT_DIR / "normal_sustained_stability_sensitivity_v1.csv"
NORMAL_POLICY = PILOT_DIR / "normal_baseline_qualification_policy_v1.md"
NORMAL_ACQUISITION_PLAN = PILOT_DIR / "normal_mrt_acquisition_plan_v1.csv"
NORMAL_SUMMARY = PILOT_DIR / "normal_baseline_candidate_summary_v1.csv"

BEHAVIORAL_FEATURE_VERSION = "v1"
BEHAVIORAL_FEATURE_COUNT = 44
DATE_OFFSETS = (-14, -7, -3, -1, 1, 3, 7, 14)
BUFFER_OPTIONS_MINUTES = (30, 60, 120)
PROVISIONAL_BUFFER_MINUTES = 60
STABILITY_WINDOWS = (3, 6, 12)
GAP_RULE = "max_gap_between_active_bins<=60m"


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def parse_required(value: str) -> datetime:
    parsed = parse_utc(value)
    if not parsed:
        raise ValueError(f"invalid timestamp: {value}")
    return parsed


def interval_overlaps(start_a: datetime, end_a: datetime, start_b: datetime, end_b: datetime) -> bool:
    return start_a < end_b and start_b < end_a


def first_value(value: str | None) -> str:
    values = parse_listish(value)
    return values[0] if values else ""


def representative_anchor(row: dict[str, str]) -> tuple[str, str]:
    if row["category"] == "Leak":
        asn = row.get("leak_asn") or first_value(row.get("affected_asns"))
    else:
        asn = first_value(row.get("affected_asns"))
    prefix = first_value(row.get("affected_prefixes"))
    return asn, prefix


def roster_index(rows: list[dict[str, str]]) -> list[dict[str, object]]:
    indexed = []
    for row in rows:
        start = parse_utc(row.get("start_utc"))
        end = parse_utc(row.get("end_utc"))
        if not start or not end:
            continue
        indexed.append(
            {
                "incident_uid": row["incident_uid"],
                "category": row["category"],
                "start": start,
                "end": end,
                "asns": set(parse_listish(row.get("primary_asn"))) | set(parse_listish(row.get("affected_asns"))),
                "prefixes": set(parse_listish(row.get("affected_prefixes"))),
            }
        )
    return indexed


def related_incident_overlap(
    candidate_start: datetime,
    candidate_end: datetime,
    affected_asn: str,
    affected_prefix: str,
    known_incidents: list[dict[str, object]],
    exclude_incident_uid: str,
    buffer_minutes: int = 0,
) -> tuple[bool, list[str]]:
    matches = []
    buffer = timedelta(minutes=buffer_minutes)
    start = candidate_start - buffer
    end = candidate_end + buffer
    for incident in known_incidents:
        if incident["incident_uid"] == exclude_incident_uid:
            continue
        same_asn = bool(affected_asn and affected_asn in incident["asns"])
        same_prefix = bool(affected_prefix and affected_prefix in incident["prefixes"])
        if not same_asn and not same_prefix:
            continue
        if interval_overlaps(start, end, incident["start"], incident["end"]):
            matches.append(str(incident["incident_uid"]))
    return bool(matches), sorted(set(matches))


def active_ranges_for_pilot() -> dict[str, list[tuple[str, datetime, datetime]]]:
    pilot = {row["incident_uid"]: row for row in load_csv(PILOT_MANIFEST)}
    ranges: dict[str, list[tuple[str, datetime, datetime]]] = defaultdict(list)
    for row in load_csv(ACTIVE_SEGMENTS):
        if row["gap_rule"] != GAP_RULE:
            continue
        if row["category"] not in {"Hijack", "Leak"}:
            continue
        start = parse_required(row["active_segment_start"])
        end = parse_required(row["active_segment_end"])
        ranges[row["incident_uid"]].append((f"segment_{row['active_segment_index']}", start, end))
    for uid, row in pilot.items():
        if row["category"] == "Outage":
            ranges[uid].append(("documented_outage_interval", parse_required(row["start_utc"]), parse_required(row["end_utc"])))
    return {uid: sorted(values, key=lambda item: item[1]) for uid, values in ranges.items()}


def five_minute_window_count(start: datetime, end: datetime) -> int:
    if end <= start:
        return 0
    return int((end - start).total_seconds() // 300 + (1 if (end - start).total_seconds() % 300 else 0))


def build_candidate_periods(buffer_minutes: int = PROVISIONAL_BUFFER_MINUTES) -> list[dict[str, object]]:
    pilot_rows = load_csv(PILOT_MANIFEST)
    known = roster_index(load_csv(ROSTER))
    active_ranges = active_ranges_for_pilot()
    candidates: list[dict[str, object]] = []
    for row in pilot_rows:
        affected_asn, affected_prefix = representative_anchor(row)
        for segment_id, incident_start, incident_end in active_ranges[row["incident_uid"]]:
            for offset in DATE_OFFSETS:
                candidate_start = incident_start + timedelta(days=offset)
                candidate_end = incident_end + timedelta(days=offset)
                direct_overlap, direct_ids = related_incident_overlap(
                    candidate_start,
                    candidate_end,
                    affected_asn,
                    affected_prefix,
                    known,
                    row["incident_uid"],
                    buffer_minutes=0,
                )
                buffer_overlap, buffer_ids = related_incident_overlap(
                    candidate_start,
                    candidate_end,
                    affected_asn,
                    affected_prefix,
                    known,
                    row["incident_uid"],
                    buffer_minutes=buffer_minutes,
                )
                if direct_overlap:
                    status = "REJECT_KNOWN_INCIDENT_OVERLAP"
                elif buffer_overlap:
                    status = "REJECT_INCIDENT_BUFFER"
                else:
                    status = "NORMAL_CANDIDATE"
                candidates.append(
                    {
                        "incident_uid": row["incident_uid"],
                        "category": row["category"],
                        "affected_asn": affected_asn,
                        "affected_prefix": affected_prefix,
                        "incident_start": isoformat_z(incident_start),
                        "incident_end": isoformat_z(incident_end),
                        "candidate_date": candidate_start.date().isoformat(),
                        "candidate_start": isoformat_z(candidate_start),
                        "candidate_end": isoformat_z(candidate_end),
                        "days_from_incident": offset,
                        "same_time_of_day": "True",
                        "known_incident_overlap": "True" if direct_overlap else "False",
                        "candidate_status": status,
                        "notes": "; ".join(
                            [
                                f"active_range={segment_id}",
                                f"buffer_minutes={buffer_minutes}",
                                f"direct_overlap_ids={json.dumps(direct_ids, separators=(',', ':'))}",
                                f"buffer_overlap_ids={json.dumps(buffer_ids, separators=(',', ':'))}",
                            ]
                        ),
                    }
                )
    return candidates


def buffer_sensitivity() -> list[dict[str, object]]:
    output = []
    for buffer in BUFFER_OPTIONS_MINUTES:
        rows = build_candidate_periods(buffer)
        counts = Counter(row["candidate_status"] for row in rows)
        output.append(
            {
                "incident_exclusion_buffer_minutes": buffer,
                "candidate_periods": len(rows),
                "normal_candidate_periods": counts["NORMAL_CANDIDATE"],
                "known_overlap_rejections": counts["REJECT_KNOWN_INCIDENT_OVERLAP"],
                "buffer_rejections": counts["REJECT_INCIDENT_BUFFER"],
                "recommendation": "PROVISIONAL_NORMAL_PILOT" if buffer == PROVISIONAL_BUFFER_MINUTES else "sensitivity_only",
                "notes": "buffer applies around known related incidents; rejected windows remain UNKNOWN, not NORMAL",
            }
        )
    return output


def stability_sensitivity(candidate_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    normal_rows = [row for row in candidate_rows if row["candidate_status"] == "NORMAL_CANDIDATE"]
    output = []
    for window_requirement in STABILITY_WINDOWS:
        surviving = 0
        candidate_windows = 0
        for row in normal_rows:
            start = parse_required(str(row["candidate_start"]))
            end = parse_required(str(row["candidate_end"]))
            windows = five_minute_window_count(start, end)
            candidate_windows += windows
            if windows >= window_requirement:
                surviving += 1
        output.append(
            {
                "minimum_consecutive_stable_windows": window_requirement,
                "minimum_stable_minutes": window_requirement * 5,
                "normal_candidate_periods": len(normal_rows),
                "candidate_periods_long_enough": surviving,
                "candidate_windows_in_long_enough_periods": sum(
                    five_minute_window_count(parse_required(str(row["candidate_start"])), parse_required(str(row["candidate_end"])))
                    for row in normal_rows
                    if five_minute_window_count(parse_required(str(row["candidate_start"])), parse_required(str(row["candidate_end"]))) >= window_requirement
                ),
                "total_candidate_windows": candidate_windows,
                "recommendation": "PROVISIONAL_NORMAL_PILOT" if window_requirement == 6 else "sensitivity_only",
                "notes": "feasibility only; behavioral stability cannot be verified until Normal MRT data are downloaded and parsed",
            }
        )
    return output


def acquisition_plan(candidate_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    rows = []
    for row in candidate_rows:
        if row["candidate_status"] != "NORMAL_CANDIDATE":
            continue
        candidate_start = parse_required(str(row["candidate_start"]))
        candidate_end = parse_required(str(row["candidate_end"]))
        collection_start = floor_to_15_minutes(candidate_start - timedelta(minutes=CONTEXT_BUFFER_MINUTES))
        collection_end = ceil_to_15_minutes(candidate_end + timedelta(minutes=CONTEXT_BUFFER_MINUTES))
        for slot in iter_update_slots(collection_start, collection_end):
            rows.append(
                {
                    "incident_uid": row["incident_uid"],
                    "category": row["category"],
                    "associated_partition": "train",
                    "candidate_start": row["candidate_start"],
                    "candidate_end": row["candidate_end"],
                    "routeviews_collector": DEFAULT_COLLECTOR,
                    "collection_start": isoformat_z(collection_start),
                    "collection_end": isoformat_z(collection_end),
                    "mrt_timestamp": isoformat_z(slot),
                    "mrt_url": routeviews_update_url(slot, DEFAULT_COLLECTOR),
                    "expected_file_count_for_period": len(iter_update_slots(collection_start, collection_end)),
                    "remote_available": "NOT_CHECKED",
                    "status_code": "",
                    "estimated_content_length": "",
                    "notes": "dry-run only; no Normal MRT download in this step",
                }
            )
    return rows


def check_url(url: str, timeout_seconds: float = 8.0) -> tuple[str, str, str]:
    request = Request(url, method="HEAD", headers={"User-Agent": "bgp-incident-detection-pipeline/0.1"})
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            return str(200 <= response.status < 400), str(response.status), response.headers.get("Content-Length") or ""
    except HTTPError as error:
        return "False", str(error.code), ""
    except URLError as error:
        return "NOT_CHECKED", "", f"URLError: {error.reason}"


def optionally_check_availability(rows: list[dict[str, object]], max_urls: int = 24) -> list[dict[str, object]]:
    checked: dict[str, tuple[str, str, str]] = {}
    for row in rows[:max_urls]:
        url = str(row["mrt_url"])
        if url not in checked:
            checked[url] = check_url(url)
    output = []
    for row in rows:
        new_row = dict(row)
        if str(row["mrt_url"]) in checked:
            available, status_code, value = checked[str(row["mrt_url"])]
            new_row["remote_available"] = available
            new_row["status_code"] = status_code
            if available in {"True", "False"}:
                new_row["estimated_content_length"] = value
            else:
                new_row["notes"] = f"availability not checked due to network error: {value}"
        output.append(new_row)
    return output


def candidate_summary(candidate_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    by_uid: dict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    for row in candidate_rows:
        by_uid[(str(row["incident_uid"]), str(row["affected_asn"]))].append(row)
    output = []
    for (incident_uid, affected_asn), rows in sorted(by_uid.items()):
        counts = Counter(row["candidate_status"] for row in rows)
        candidate_windows = sum(
            five_minute_window_count(parse_required(str(row["candidate_start"])), parse_required(str(row["candidate_end"])))
            for row in rows
            if row["candidate_status"] == "NORMAL_CANDIDATE"
        )
        output.append(
            {
                "incident_uid": incident_uid,
                "affected_asn": affected_asn,
                "candidate_period_count": len(rows),
                "candidate_window_count": candidate_windows,
                "known_overlap_rejections": counts["REJECT_KNOWN_INCIDENT_OVERLAP"],
                "buffer_rejections": counts["REJECT_INCIDENT_BUFFER"],
                "provisional_normal_candidates": counts["NORMAL_CANDIDATE"],
                "status": "PASS" if counts["NORMAL_CANDIDATE"] else "REVIEW",
            }
        )
    return output


def freeze_behavioral_schema() -> None:
    inventory = load_csv(FEATURE_INVENTORY)
    rows = []
    yaml_lines = [
        "behavioral_feature_version: v1",
        "behavioral_feature_count: 44",
        "status: FROZEN_FOR_PILOT",
        "notes: Schema freezes the 44 reproducible behavioral features from the TRAIN pilot; sparse REVIEW features remain included for full-corpus reassessment.",
        "features:",
    ]
    for index, row in enumerate(inventory, start=1):
        frozen = {
            "behavioral_feature_version": BEHAVIORAL_FEATURE_VERSION,
            "behavioral_feature_count": BEHAVIORAL_FEATURE_COUNT,
            "feature_order": index,
            **row,
        }
        rows.append(frozen)
        yaml_lines.extend(
            [
                f"  - order: {index}",
                f"    feature_name: {row['feature_name']}",
                f"    feature_group: {row['feature_group']}",
                f"    definition: {json.dumps(row['definition'])}",
                f"    formula: {json.dumps(row['formula'])}",
                f"    source_fields: {json.dumps(row['source_fields'])}",
                f"    aggregation_method: {json.dumps(row['aggregation_method'])}",
                f"    zero_window_behavior: {json.dumps(row['zero_window_behavior'])}",
                f"    verification_status: {row['verification_status']}",
            ]
        )
    write_csv(
        BEHAVIORAL_SCHEMA_FREEZE,
        rows,
        [
            "behavioral_feature_version",
            "behavioral_feature_count",
            "feature_order",
            "feature_name",
            "feature_group",
            "definition",
            "formula",
            "source_fields",
            "aggregation_method",
            "zero_window_behavior",
            "available_in_new_pipeline",
            "historical_source",
            "verification_status",
            "notes",
        ],
    )
    BEHAVIORAL_SCHEMA_YAML.parent.mkdir(parents=True, exist_ok=True)
    BEHAVIORAL_SCHEMA_YAML.write_text("\n".join(yaml_lines) + "\n", encoding="utf-8")


def write_policy() -> None:
    NORMAL_POLICY.write_text(
        "\n".join(
            [
                "# Normal Baseline Qualification Policy v1",
                "",
                "NORMAL examples are required to provide Stage 1 with trustworthy examples of ordinary, stable BGP behavior. Stage 1 will later learn NORMAL versus INCIDENT, where Hijack, Leak, and Outage windows are INCIDENT examples.",
                "",
                "Absence of a known incident is not enough to declare a window NORMAL. PRE_CONTEXT, POST_CONTEXT, and UNKNOWN windows remain unchanged unless they independently pass this separate Normal qualification workflow.",
                "",
                "Candidate periods are selected from TRAIN incidents only, using the same representative ASN/network and, where available, representative prefix. Candidate dates preserve the incident time of day and evaluate offsets of 1, 3, 7, and 14 days before and after the incident-active period.",
                "",
                "Candidates overlapping any known frozen Roster v2 Hijack, Leak, or Outage involving the same ASN/network or prefix are rejected. A parameterized incident exclusion buffer is applied around related known incidents. The pilot recommends 60 minutes provisionally; rejected buffer-adjacent windows remain UNKNOWN.",
                "",
                "Future qualification must use the 44 behavioral features with baseline-relative checks, such as median, IQR, MAD, and percentile comparisons from TRAIN-only candidate controls. The rules should check origin stability, announcement/withdrawal bursts, AS_PATH instability, prefix deaggregation, MOAS/origin-diversity anomalies, path prepending/path-change anomalies, and sustained stability across consecutive windows.",
                "",
                "A single isolated 5-minute window should not qualify as NORMAL by itself. The pilot evaluates 3, 6, and 12 consecutive 5-minute windows and recommends 6 windows, or 30 minutes, as the provisional Normal MRT pilot requirement.",
                "",
                "Normal qualification rules are dataset-construction rules only. They must not become live inference logic. During inference, the trained ML classifier predicts NORMAL or INCIDENT from the feature vector.",
                "",
                "This dry-run creates NORMAL_CANDIDATE periods and an MRT acquisition plan only. It does not download Normal MRT data and does not create NORMAL_VERIFIED labels.",
                "",
            ]
        ),
        encoding="utf-8",
    )


def run(check_availability: bool = False) -> dict[str, list[dict[str, object]]]:
    freeze_behavioral_schema()
    candidates = build_candidate_periods()
    buffer_rows = buffer_sensitivity()
    stability_rows = stability_sensitivity(candidates)
    plan_rows = acquisition_plan(candidates)
    if check_availability:
        plan_rows = optionally_check_availability(plan_rows)
    summary_rows = candidate_summary(candidates)
    write_policy()
    write_csv(
        NORMAL_CANDIDATES,
        candidates,
        [
            "incident_uid",
            "category",
            "affected_asn",
            "affected_prefix",
            "incident_start",
            "incident_end",
            "candidate_date",
            "candidate_start",
            "candidate_end",
            "days_from_incident",
            "same_time_of_day",
            "known_incident_overlap",
            "candidate_status",
            "notes",
        ],
    )
    write_csv(
        BUFFER_SENSITIVITY,
        buffer_rows,
        [
            "incident_exclusion_buffer_minutes",
            "candidate_periods",
            "normal_candidate_periods",
            "known_overlap_rejections",
            "buffer_rejections",
            "recommendation",
            "notes",
        ],
    )
    write_csv(
        STABILITY_SENSITIVITY,
        stability_rows,
        [
            "minimum_consecutive_stable_windows",
            "minimum_stable_minutes",
            "normal_candidate_periods",
            "candidate_periods_long_enough",
            "candidate_windows_in_long_enough_periods",
            "total_candidate_windows",
            "recommendation",
            "notes",
        ],
    )
    write_csv(
        NORMAL_ACQUISITION_PLAN,
        plan_rows,
        [
            "incident_uid",
            "category",
            "associated_partition",
            "candidate_start",
            "candidate_end",
            "routeviews_collector",
            "collection_start",
            "collection_end",
            "mrt_timestamp",
            "mrt_url",
            "expected_file_count_for_period",
            "remote_available",
            "status_code",
            "estimated_content_length",
            "notes",
        ],
    )
    write_csv(
        NORMAL_SUMMARY,
        summary_rows,
        [
            "incident_uid",
            "affected_asn",
            "candidate_period_count",
            "candidate_window_count",
            "known_overlap_rejections",
            "buffer_rejections",
            "provisional_normal_candidates",
            "status",
        ],
    )
    return {
        "candidates": candidates,
        "buffer_sensitivity": buffer_rows,
        "stability_sensitivity": stability_rows,
        "acquisition_plan": plan_rows,
        "summary": summary_rows,
    }


def print_summary(results: dict[str, list[dict[str, object]]]) -> None:
    candidates = results["candidates"]
    plan = results["acquisition_plan"]
    counts = Counter(row["candidate_status"] for row in candidates)
    offsets = Counter(row["days_from_incident"] for row in candidates if row["candidate_status"] == "NORMAL_CANDIDATE")
    print(f"candidate_periods={len(candidates)}")
    print(f"candidate_status_counts={dict(counts)}")
    print(f"candidate_windows={sum(five_minute_window_count(parse_required(str(row['candidate_start'])), parse_required(str(row['candidate_end']))) for row in candidates if row['candidate_status'] == 'NORMAL_CANDIDATE')}")
    print(f"acquisition_plan_files={len(plan)}")
    print(f"practical_offsets={dict(sorted(offsets.items()))}")
    print(f"provisional_buffer_minutes={PROVISIONAL_BUFFER_MINUTES}")
    print("provisional_sustained_stability_windows=6")


def main() -> None:
    parser = argparse.ArgumentParser(description="Design and dry-run Normal baseline candidate selection.")
    parser.add_argument("--check-availability", action="store_true")
    args = parser.parse_args()
    results = run(check_availability=args.check_availability)
    print_summary(results)


if __name__ == "__main__":
    main()
