from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    from bgp_incident_detection.audit import parse_utc, write_csv
    from bgp_incident_detection.mrt_acquisition import (
        DEFAULT_COLLECTOR,
        ceil_to_15_minutes,
        floor_to_15_minutes,
        iter_update_slots,
        routeviews_update_url,
    )
    from bgp_incident_detection.normal_baseline import CONTEXT_BUFFER_MINUTES
    from bgp_incident_detection.normal_candidate_v2 import NORMAL_REPLACEMENT_CANDIDATES
    from bgp_incident_detection.rib_normal import (
        RAW_RIB_DIR,
        RibState,
        compact_set,
        inspect_rib,
        nearest_ribs,
        routeviews_rib_url,
        top_paths,
        validate_bzip2,
    )
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import parse_utc, write_csv
    from src.bgp_incident_detection.mrt_acquisition import (
        DEFAULT_COLLECTOR,
        ceil_to_15_minutes,
        floor_to_15_minutes,
        iter_update_slots,
        routeviews_update_url,
    )
    from src.bgp_incident_detection.normal_baseline import CONTEXT_BUFFER_MINUTES
    from src.bgp_incident_detection.normal_candidate_v2 import NORMAL_REPLACEMENT_CANDIDATES
    from src.bgp_incident_detection.rib_normal import (
        RAW_RIB_DIR,
        RibState,
        compact_set,
        inspect_rib,
        nearest_ribs,
        routeviews_rib_url,
        top_paths,
        validate_bzip2,
    )


PILOT_DIR = Path("data/pilot")
NORMAL_DURATION_DISPOSITION = PILOT_DIR / "normal_replacement_duration_disposition_v1.csv"
NORMAL_REPLACEMENT_RIB_VISIBILITY = PILOT_DIR / "normal_replacement_rib_visibility_v1.csv"
NORMAL_REPLACEMENT_COLLECTOR_SELECTION = PILOT_DIR / "normal_replacement_collector_selection_v1.csv"
NORMAL_UPDATE_READY_CANDIDATES = PILOT_DIR / "normal_update_ready_candidates_v1.csv"
NORMAL_UPDATE_READY_ACQUISITION_PLAN = PILOT_DIR / "normal_update_ready_acquisition_plan_v1.csv"

MIN_STABILITY_MINUTES = 30
COLLECTOR_SEQUENCE = [
    "route-views2",
    "route-views3",
    "route-views4",
    "route-views5",
    "route-views6",
    "route-views.eqix",
    "route-views.isc",
    "route-views.linx",
    "route-views.sg",
    "route-views.sydney",
    "route-views.telxatl",
    "route-views.wide",
]


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def parse_required(value: str) -> datetime:
    parsed = parse_utc(value)
    if not parsed:
        raise ValueError(f"invalid UTC timestamp: {value}")
    return parsed


def isoformat_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def candidate_period_id(row: dict[str, str]) -> str:
    safe_time = row["candidate_start"].replace(":", "").replace("-", "").replace(".000Z", "Z")
    return f"{row['associated_incident_uid'].replace(':', '_')}_offset_{int(row['days_from_incident']):+d}_{safe_time}"


def duration_minutes(row: dict[str, str]) -> float:
    return (parse_required(row["candidate_end"]) - parse_required(row["candidate_start"])).total_seconds() / 60


def replacement_rows() -> list[dict[str, str]]:
    return load_csv(NORMAL_REPLACEMENT_CANDIDATES)


def duration_disposition(rows: list[dict[str, str]]) -> list[dict[str, object]]:
    output = []
    for row in rows:
        duration = duration_minutes(row)
        if duration < MIN_STABILITY_MINUTES:
            output.append(
                {
                    "associated_incident_uid": row["associated_incident_uid"],
                    "candidate_period_id": candidate_period_id(row),
                    "candidate_start": row["candidate_start"],
                    "candidate_end": row["candidate_end"],
                    "candidate_duration_minutes": int(duration),
                    "reason": "INELIGIBLE_DURATION: candidate duration is shorter than the provisional 30-minute sustained-stability requirement",
                    "duration_status": "INELIGIBLE_DURATION",
                }
            )
    write_csv(
        NORMAL_DURATION_DISPOSITION,
        output,
        [
            "associated_incident_uid",
            "candidate_period_id",
            "candidate_start",
            "candidate_end",
            "candidate_duration_minutes",
            "reason",
            "duration_status",
        ],
    )
    return output


def head_url(url: str, timeout_seconds: float = 12.0) -> tuple[bool, str, int, str]:
    request = Request(url, method="HEAD", headers={"User-Agent": "bgp-incident-detection-pipeline/0.1"})
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            return 200 <= response.status < 400, str(response.status), int(response.headers.get("Content-Length") or 0), "HEAD"
    except HTTPError as error:
        return False, str(error.code), 0, f"HTTPError: {error.reason}"
    except URLError as error:
        return False, "", 0, f"URLError: {error.reason}"


def local_rib_path(slot: datetime, collector: str) -> str:
    return str(RAW_RIB_DIR / collector / f"{slot.year}.{slot.month:02d}" / f"rib.{slot:%Y%m%d.%H%M}.bz2")


def download_file(url: str, local_path: str) -> tuple[bool, int, str, str]:
    path = Path(local_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.stat().st_size > 0 and validate_bzip2(path):
        return True, path.stat().st_size, sha256(path), "cached"
    request = Request(url, headers={"User-Agent": "bgp-incident-detection-pipeline/0.1"})
    try:
        with urlopen(request, timeout=300.0) as response:
            path.write_bytes(response.read())
        valid = path.exists() and path.stat().st_size > 0 and validate_bzip2(path)
        return valid, path.stat().st_size if path.exists() else 0, sha256(path) if valid else "", "downloaded"
    except (HTTPError, URLError) as error:
        return False, 0, "", str(error)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def rib_url_for(slot: datetime, collector: str) -> str:
    if collector == DEFAULT_COLLECTOR:
        return routeviews_rib_url(slot, collector)
    return f"https://archive.routeviews.org/{collector}/bgpdata/{slot.year}.{slot.month:02d}/RIBS/rib.{slot:%Y%m%d.%H%M}.bz2"


def summarize_state(state: RibState) -> dict[str, object]:
    return {
        "visible": state.route_present,
        "origins": compact_set(state.origins),
        "paths": top_paths(state.paths),
        "peer_count": len(state.peer_asns),
        "prefix_count": len(state.prefixes),
        "timed_out": state.scan_timed_out,
        "matched_rows": state.matched_rows,
    }


def state_passes(before: RibState, after: RibState, affected_prefix: str) -> tuple[bool, str]:
    route_stable = before.route_present and after.route_present
    prefix_stable = True if not affected_prefix else affected_prefix in before.prefixes and affected_prefix in after.prefixes
    if route_stable and prefix_stable:
        return True, "PASS"
    if not route_stable:
        return False, "NO_OBSERVABILITY"
    return False, "RIB_REVIEW"


def inspect_candidate_on_collector(row: dict[str, str], collector: str) -> dict[str, object]:
    start = parse_required(row["candidate_start"])
    end = parse_required(row["candidate_end"])
    before, after, _ = nearest_ribs(start, end, DEFAULT_COLLECTOR)
    before_url = rib_url_for(before, collector)
    after_url = rib_url_for(after, collector)
    before_available, before_status, before_size, before_notes = head_url(before_url)
    after_available, after_status, after_size, after_notes = head_url(after_url)
    historically_available = before_available and after_available
    before_state = RibState()
    after_state = RibState()
    if historically_available:
        before_path = local_rib_path(before, collector)
        after_path = local_rib_path(after, collector)
        before_ok, _, _, _ = download_file(before_url, before_path)
        after_ok, _, _, _ = download_file(after_url, after_path)
        if before_ok:
            before_state = inspect_rib(before_path, row["affected_asn"], row.get("affected_prefix") or "")
        if after_ok:
            after_state = inspect_rib(after_path, row["affected_asn"], row.get("affected_prefix") or "")
    passes, status = state_passes(before_state, after_state, row.get("affected_prefix") or "")
    before_summary = summarize_state(before_state)
    after_summary = summarize_state(after_state)
    prefix_applicable = bool(row.get("affected_prefix"))
    return {
        "candidate_period_id": candidate_period_id(row),
        "associated_incident_uid": row["associated_incident_uid"],
        "category": row["category"],
        "affected_asn": row["affected_asn"],
        "affected_prefix": row.get("affected_prefix") or "",
        "collector": collector,
        "rib_before_timestamp": isoformat_z(before),
        "rib_after_timestamp": isoformat_z(after),
        "rib_before_url": before_url,
        "rib_after_url": after_url,
        "historically_available": str(historically_available),
        "asn_visible_before": str(before_state.route_present),
        "asn_visible_after": str(after_state.route_present),
        "prefix_visible_before": str(row.get("affected_prefix") in before_state.prefixes) if prefix_applicable else "NOT_APPLICABLE",
        "prefix_visible_after": str(row.get("affected_prefix") in after_state.prefixes) if prefix_applicable else "NOT_APPLICABLE",
        "origin_before": before_summary["origins"],
        "origin_after": after_summary["origins"],
        "origin_stable": str(bool(before_state.origins) and before_state.origins == after_state.origins),
        "route_presence_stable": str(before_state.route_present and after_state.route_present),
        "rib_visibility_status": status,
        "peer_visibility_before": before_summary["peer_count"],
        "peer_visibility_after": after_summary["peer_count"],
        "prefix_count_before": before_summary["prefix_count"],
        "prefix_count_after": after_summary["prefix_count"],
        "path_before": before_summary["paths"],
        "path_after": after_summary["paths"],
        "notes": (
            f"before_head={before_status or before_notes}; after_head={after_status or after_notes}; "
            "collector evaluated by RIB observability only"
        ),
        "selected": "False",
        "selection_reason": "",
        "estimated_rib_bytes": before_size + after_size,
    }


def classify_replacements(rows: list[dict[str, str]]) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    duration_disposition(rows)
    eligible = [row for row in rows if duration_minutes(row) >= MIN_STABILITY_MINUTES and row["known_incident_overlap"] == "False"]
    visibility_rows = []
    selection_rows = []
    ready = []
    for row in eligible:
        selected = None
        checked_for_row = []
        for collector in COLLECTOR_SEQUENCE:
            result = inspect_candidate_on_collector(row, collector)
            checked_for_row.append(result)
            if result["rib_visibility_status"] == "PASS" and selected is None:
                selected = result
                if collector == DEFAULT_COLLECTOR:
                    break
        for result in checked_for_row:
            is_selected = selected is not None and result["collector"] == selected["collector"]
            result["selected"] = str(is_selected)
            if is_selected:
                result["selection_reason"] = "selected first collector in deterministic sequence with positive RIB ASN/origin visibility"
            elif result["rib_visibility_status"] == "PASS":
                result["selection_reason"] = "positive visibility available but earlier collector already selected"
            else:
                result["selection_reason"] = "not selected; visibility unavailable or requires review"
            selection_rows.append(
                {
                    "candidate_period_id": result["candidate_period_id"],
                    "collector": result["collector"],
                    "historically_available": result["historically_available"],
                    "asn_visible": str(result["asn_visible_before"] == "True" and result["asn_visible_after"] == "True"),
                    "prefix_visible": (
                        "NOT_APPLICABLE"
                        if not result["affected_prefix"]
                        else str(result["prefix_visible_before"] == "True" and result["prefix_visible_after"] == "True")
                    ),
                    "selected": result["selected"],
                    "selection_reason": result["selection_reason"],
                }
            )
        visibility_rows.extend(checked_for_row)
        if selected:
            ready.append(update_ready_row(row, selected))
    write_visibility(visibility_rows)
    write_collector_selection(selection_rows)
    write_update_ready(ready)
    write_update_plan(ready)
    return visibility_rows, selection_rows, ready


def update_ready_row(row: dict[str, str], selected: dict[str, object]) -> dict[str, object]:
    duration = int(duration_minutes(row))
    return {
        "candidate_period_id": candidate_period_id(row),
        "associated_incident_uid": row["associated_incident_uid"],
        "associated_category": row["category"],
        "affected_asn": row["affected_asn"],
        "affected_prefix": row.get("affected_prefix") or "",
        "candidate_start": row["candidate_start"],
        "candidate_end": row["candidate_end"],
        "duration_minutes": duration,
        "collector": selected["collector"],
        "rib_before": selected["rib_before_timestamp"],
        "rib_after": selected["rib_after_timestamp"],
        "origin_stable": selected["origin_stable"],
        "known_incident_overlap": row["known_incident_overlap"],
        "exclusion_buffer_pass": str(row["known_incident_overlap"] == "False"),
        "final_prescreen_status": "UPDATE_READY",
    }


def write_visibility(rows: list[dict[str, object]]) -> None:
    write_csv(
        NORMAL_REPLACEMENT_RIB_VISIBILITY,
        rows,
        [
            "candidate_period_id",
            "associated_incident_uid",
            "category",
            "affected_asn",
            "affected_prefix",
            "collector",
            "rib_before_timestamp",
            "rib_after_timestamp",
            "asn_visible_before",
            "asn_visible_after",
            "prefix_visible_before",
            "prefix_visible_after",
            "origin_before",
            "origin_after",
            "origin_stable",
            "route_presence_stable",
            "rib_visibility_status",
            "notes",
        ],
    )


def write_collector_selection(rows: list[dict[str, object]]) -> None:
    write_csv(
        NORMAL_REPLACEMENT_COLLECTOR_SELECTION,
        rows,
        [
            "candidate_period_id",
            "collector",
            "historically_available",
            "asn_visible",
            "prefix_visible",
            "selected",
            "selection_reason",
        ],
    )


def write_update_ready(rows: list[dict[str, object]]) -> None:
    write_csv(
        NORMAL_UPDATE_READY_CANDIDATES,
        rows,
        [
            "candidate_period_id",
            "associated_incident_uid",
            "associated_category",
            "affected_asn",
            "affected_prefix",
            "candidate_start",
            "candidate_end",
            "duration_minutes",
            "collector",
            "rib_before",
            "rib_after",
            "origin_stable",
            "known_incident_overlap",
            "exclusion_buffer_pass",
            "final_prescreen_status",
        ],
    )


def update_slots(start_text: str, end_text: str) -> list[datetime]:
    start = floor_to_15_minutes(parse_required(start_text) - timedelta(minutes=CONTEXT_BUFFER_MINUTES))
    end = ceil_to_15_minutes(parse_required(end_text) + timedelta(minutes=CONTEXT_BUFFER_MINUTES))
    return iter_update_slots(start, end)


def write_update_plan(ready_rows: list[dict[str, object]]) -> None:
    plan = []
    for row in ready_rows:
        for slot in update_slots(str(row["candidate_start"]), str(row["candidate_end"])):
            url = routeviews_update_url(slot, str(row["collector"]))
            available, status, size, notes = head_url(url)
            plan.append(
                {
                    "candidate_period_id": row["candidate_period_id"],
                    "associated_incident_uid": row["associated_incident_uid"],
                    "associated_category": row["associated_category"],
                    "collector": row["collector"],
                    "collection_start": isoformat_z(update_slots(str(row["candidate_start"]), str(row["candidate_end"]))[0]),
                    "collection_end": isoformat_z(update_slots(str(row["candidate_start"]), str(row["candidate_end"]))[-1]),
                    "mrt_timestamp": isoformat_z(slot),
                    "mrt_url": url,
                    "remote_available": str(available),
                    "status_code": status,
                    "estimated_content_length": size,
                    "notes": f"{notes}; dry-run only, no UPDATE download",
                }
            )
    write_csv(
        NORMAL_UPDATE_READY_ACQUISITION_PLAN,
        plan,
        [
            "candidate_period_id",
            "associated_incident_uid",
            "associated_category",
            "collector",
            "collection_start",
            "collection_end",
            "mrt_timestamp",
            "mrt_url",
            "remote_available",
            "status_code",
            "estimated_content_length",
            "notes",
        ],
    )


def run() -> dict[str, object]:
    rows = replacement_rows()
    visibility, selection, ready = classify_replacements(rows)
    duration_rows = load_csv(NORMAL_DURATION_DISPOSITION)
    plan = load_csv(NORMAL_UPDATE_READY_ACQUISITION_PLAN)
    return {
        "duration_ineligible": len(duration_rows),
        "visibility_rows": len(visibility),
        "positive_rib_visibility_candidates": len({row["candidate_period_id"] for row in visibility if row["rib_visibility_status"] == "PASS"}),
        "alternate_collector_required": len({row["candidate_period_id"] for row in selection if row["selected"] == "True" and row["collector"] != DEFAULT_COLLECTOR}),
        "update_ready": len(ready),
        "update_ready_file_count": len(plan),
        "update_ready_estimated_mib": round(sum(int(row["estimated_content_length"]) for row in plan) / 1024 / 1024, 2) if plan else 0,
        "status_counts": dict(Counter(row["rib_visibility_status"] for row in visibility)),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Resolve RIB visibility for Normal replacement candidates")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if not args.run:
        parser.error("choose --run")
    print(json.dumps(run(), indent=2))


if __name__ == "__main__":
    main()
