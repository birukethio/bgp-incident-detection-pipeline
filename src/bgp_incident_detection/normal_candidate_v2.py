from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from datetime import timedelta
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
        routeviews_base_url,
        routeviews_month_path,
        routeviews_update_url,
    )
    from bgp_incident_detection.normal_baseline import CONTEXT_BUFFER_MINUTES, NORMAL_CANDIDATES
    from bgp_incident_detection.normal_pilot import NORMAL_PERIODS
    from bgp_incident_detection.rib_normal import (
        RIB_ACQUISITION_PLAN,
        RIB_STABILITY,
        RIB_UPDATE_QUALIFICATION,
        nearest_ribs,
        routeviews_rib_url,
    )
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import parse_utc, write_csv
    from src.bgp_incident_detection.mrt_acquisition import (
        DEFAULT_COLLECTOR,
        ceil_to_15_minutes,
        floor_to_15_minutes,
        iter_update_slots,
        routeviews_base_url,
        routeviews_month_path,
        routeviews_update_url,
    )
    from src.bgp_incident_detection.normal_baseline import CONTEXT_BUFFER_MINUTES, NORMAL_CANDIDATES
    from src.bgp_incident_detection.normal_pilot import NORMAL_PERIODS
    from src.bgp_incident_detection.rib_normal import (
        RIB_ACQUISITION_PLAN,
        RIB_STABILITY,
        RIB_UPDATE_QUALIFICATION,
        nearest_ribs,
        routeviews_rib_url,
    )


PILOT_DIR = Path("data/pilot")
FROZEN_ROSTER = Path("data/roster_v2/frozen_incident_roster_v2.csv")
FROZEN_PARTITIONS = Path("data/partitions_v2/frozen_partition_manifest_v2.csv")

NORMAL_FAILURE_DIAGNOSIS = PILOT_DIR / "normal_failure_diagnosis_v1.csv"
NORMAL_COLLECTOR_VISIBILITY = PILOT_DIR / "normal_collector_visibility_v1.csv"
NORMAL_REPLACEMENT_CANDIDATES = PILOT_DIR / "normal_replacement_candidates_v1.csv"
NORMAL_CANDIDATE_SELECTION_POLICY = PILOT_DIR / "normal_candidate_selection_policy_v2.md"

FAILED_CATEGORIES = {"Hijack", "Leak"}
ALTERNATE_COLLECTORS = [
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


def parse_required(value: str):
    parsed = parse_utc(value)
    if not parsed:
        raise ValueError(f"invalid timestamp: {value}")
    return parsed


def isoformat_z(value) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def period_key_from_candidate(row: dict[str, str]) -> str:
    safe_time = row["candidate_start"].replace(":", "").replace("-", "").replace(".000Z", "Z")
    return f"{row['incident_uid'].replace(':', '_')}_offset_{int(row['days_from_incident']):+d}_{safe_time}"


def head_url(url: str, timeout_seconds: float = 12.0) -> tuple[str, str, int, str]:
    request = Request(url, method="HEAD", headers={"User-Agent": "bgp-incident-detection-pipeline/0.1"})
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            return str(200 <= response.status < 400), str(response.status), int(response.headers.get("Content-Length") or 0), "HEAD"
    except HTTPError as error:
        return "False", str(error.code), 0, f"HTTPError: {error.reason}"
    except URLError as error:
        return "False", "", 0, f"URLError: {error.reason}"


def collector_rib_url(slot, collector: str) -> str:
    if collector == DEFAULT_COLLECTOR:
        return routeviews_rib_url(slot, collector)
    return f"{routeviews_base_url(collector)}{routeviews_month_path(slot)}/RIBS/rib.{slot:%Y%m%d.%H%M}.bz2"


def update_file_count(start_text: str, end_text: str) -> int:
    start = floor_to_15_minutes(parse_required(start_text) - timedelta(minutes=CONTEXT_BUFFER_MINUTES))
    end = ceil_to_15_minutes(parse_required(end_text) + timedelta(minutes=CONTEXT_BUFFER_MINUTES))
    return len(iter_update_slots(start, end))


def period_duration_minutes(row: dict[str, str]) -> float:
    return (parse_required(row["candidate_end"]) - parse_required(row["candidate_start"])).total_seconds() / 60


def load_failed_hijack_leak_periods() -> list[dict[str, str]]:
    periods = {row["candidate_period_id"]: row for row in load_csv(NORMAL_PERIODS)}
    qualification = load_csv(RIB_UPDATE_QUALIFICATION)
    failed_ids = {
        row["candidate_period_id"]
        for row in qualification
        if row["final_state"] != "NORMAL_VERIFIED"
        and periods[row["candidate_period_id"]]["associated_category"] in FAILED_CATEGORIES
    }
    return [periods[period_id] for period_id in sorted(failed_ids)]


def stability_summary() -> dict[str, dict[str, object]]:
    rows = load_csv(RIB_STABILITY)
    output: dict[str, dict[str, object]] = {}
    for period_id, group in group_by(rows, "candidate_period_id").items():
        output[period_id] = {
            "rib_before_visible": any(row["route_present_before"] == "True" for row in group),
            "rib_after_visible": any(row["route_present_after"] == "True" for row in group),
            "origin_stable": any(row["origin_stable"] == "True" for row in group),
            "route_stable": any(row["route_presence_stable"] == "True" for row in group),
            "path_stable": any(row["path_stability_status"] == "STABLE_EXACT" for row in group),
            "prefix_visible": any(row["prefix"] for row in group),
            "timed_out": any(row.get("rib_scan_timed_out_before") == "True" or row.get("rib_scan_timed_out_after") == "True" for row in group),
        }
    return output


def group_by(rows: list[dict[str, str]], key: str) -> dict[str, list[dict[str, str]]]:
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[row[key]].append(row)
    return grouped


def diagnose_failures() -> list[dict[str, object]]:
    failed = load_failed_hijack_leak_periods()
    stability = stability_summary()
    qualification = group_by(load_csv(RIB_UPDATE_QUALIFICATION), "candidate_period_id")
    rows = []
    for period in failed:
        period_id = period["candidate_period_id"]
        st = stability.get(period_id, {})
        q_rows = qualification.get(period_id, [])
        relevant_updates = sum(int(row["relevant_update_count"]) for row in q_rows)
        suspicious = sum(row["suspicious_update_detected"] == "True" for row in q_rows)
        stable_windows = sum(row["qualification_status"] in {"PASS_RIB_STABLE_SILENCE", "PASS_RIB_STABLE_LOW_UPDATE"} for row in q_rows)
        duration = period_duration_minutes(
            {"candidate_start": period["candidate_start"], "candidate_end": period["candidate_end"]}
        )
        if period["known_incident_overlap"] == "True":
            failure_type = "KNOWN_INCIDENT_OVERLAP"
            broad = "OTHER"
            reason = "candidate overlaps a known incident exclusion window"
            action = "reject candidate; choose another control date"
        elif not st.get("rib_before_visible", False) or not st.get("rib_after_visible", False):
            failure_type = "NO_RIB_VISIBILITY"
            broad = "INSUFFICIENT_OBSERVABILITY"
            reason = "route-views2 RIB snapshots did not confirm before/after visibility for the associated ASN/prefix"
            action = "try historically available alternate collectors or choose an RIB-visible replacement"
        elif suspicious:
            failure_type = "UPDATE_INSTABILITY"
            broad = "EVIDENCE_OF_NON_NORMAL_BEHAVIOR"
            reason = "candidate had suspicious relevant UPDATE activity"
            action = "do not promote; choose another control period"
        elif stable_windows < 6 or duration < 30:
            failure_type = "INSUFFICIENT_STABILITY"
            broad = "INSUFFICIENT_STABILITY_DURATION"
            reason = "candidate did not contain six consecutive stable 5-minute windows under the provisional 30-minute rule"
            action = "select a candidate period with at least 30 minutes of RIB-confirmed stability"
        else:
            failure_type = "OTHER"
            broad = "OTHER"
            reason = "candidate failed final qualification despite partial evidence; manual review needed"
            action = "review evidence table before reuse"
        rows.append(
            {
                "candidate_period_id": period_id,
                "associated_incident_uid": period["associated_incident_uid"],
                "category": period["associated_category"],
                "affected_asn": period["affected_asn"],
                "affected_prefix": period["affected_prefix"],
                "rib_before_visible": str(st.get("rib_before_visible", False)),
                "rib_after_visible": str(st.get("rib_after_visible", False)),
                "origin_stable": str(st.get("origin_stable", False)),
                "route_stable": str(st.get("route_stable", False)),
                "path_stable": str(st.get("path_stable", False)),
                "relevant_update_count": relevant_updates,
                "suspicious_update_count": suspicious,
                "stable_window_count": stable_windows,
                "failure_reason": reason,
                "failure_type": failure_type,
                "failure_class": broad,
                "recommended_action": action,
            }
        )
    write_csv(
        NORMAL_FAILURE_DIAGNOSIS,
        rows,
        [
            "candidate_period_id",
            "associated_incident_uid",
            "category",
            "affected_asn",
            "affected_prefix",
            "rib_before_visible",
            "rib_after_visible",
            "origin_stable",
            "route_stable",
            "path_stable",
            "relevant_update_count",
            "suspicious_update_count",
            "stable_window_count",
            "failure_reason",
            "failure_type",
            "failure_class",
            "recommended_action",
        ],
    )
    return rows


def build_collector_visibility() -> list[dict[str, object]]:
    rows = []
    for period in load_failed_hijack_leak_periods():
        start = parse_required(period["candidate_start"])
        end = parse_required(period["candidate_end"])
        before, after, cadence = nearest_ribs(start, end, DEFAULT_COLLECTOR)
        for collector in ALTERNATE_COLLECTORS:
            before_url = collector_rib_url(before, collector)
            after_url = collector_rib_url(after, collector)
            before_available, before_status, before_size, before_notes = head_url(before_url)
            after_available, after_status, after_size, after_notes = head_url(after_url)
            existing_routeviews2 = stability_summary().get(period["candidate_period_id"], {})
            is_routeviews2 = collector == DEFAULT_COLLECTOR
            rows.append(
                {
                    "candidate_period_id": period["candidate_period_id"],
                    "associated_incident_uid": period["associated_incident_uid"],
                    "category": period["associated_category"],
                    "collector": collector,
                    "affected_asn": period["affected_asn"],
                    "affected_prefix": period["affected_prefix"],
                    "rib_before_timestamp": isoformat_z(before),
                    "rib_after_timestamp": isoformat_z(after),
                    "rib_before_url": before_url,
                    "rib_after_url": after_url,
                    "historical_availability": str(before_available == "True" and after_available == "True"),
                    "asn_visible": str(existing_routeviews2.get("route_stable", False)) if is_routeviews2 else "UNKNOWN_NOT_PARSED",
                    "prefix_visible": str(existing_routeviews2.get("prefix_visible", False)) if is_routeviews2 and period["affected_prefix"] else ("NOT_APPLICABLE" if not period["affected_prefix"] else "UNKNOWN_NOT_PARSED"),
                    "relevant_route_or_peer_count": "AVAILABLE_IN_RIB_STABILITY" if is_routeviews2 else "NOT_PARSED_LIGHTWEIGHT_CHECK_ONLY",
                    "rib_before_status_code": before_status,
                    "rib_after_status_code": after_status,
                    "estimated_rib_bytes": before_size + after_size,
                    "notes": f"{cadence}; before={before_notes}; after={after_notes}; collector choice must be based on observability only",
                }
            )
    write_csv(
        NORMAL_COLLECTOR_VISIBILITY,
        rows,
        [
            "candidate_period_id",
            "associated_incident_uid",
            "category",
            "collector",
            "affected_asn",
            "affected_prefix",
            "rib_before_timestamp",
            "rib_after_timestamp",
            "rib_before_url",
            "rib_after_url",
            "historical_availability",
            "asn_visible",
            "prefix_visible",
            "relevant_route_or_peer_count",
            "rib_before_status_code",
            "rib_after_status_code",
            "estimated_rib_bytes",
            "notes",
        ],
    )
    return rows


def replacement_candidate_score(row: dict[str, str]) -> tuple[int, int, int]:
    duration_ok = int(period_duration_minutes(row) >= 30)
    offset_distance = abs(int(row["days_from_incident"]))
    offset_preference = 1 if offset_distance in {7, 14} else 0
    return duration_ok, offset_preference, offset_distance


def build_replacement_candidates() -> list[dict[str, object]]:
    failed_uids = {row["associated_incident_uid"] for row in load_failed_hijack_leak_periods()}
    all_candidates = [
        row for row in load_csv(NORMAL_CANDIDATES)
        if row["incident_uid"] in failed_uids and row["candidate_status"] == "NORMAL_CANDIDATE"
    ]
    existing = {row["candidate_period_id"] for row in load_csv(NORMAL_PERIODS)}
    selected = []
    for uid, group in group_by(all_candidates, "incident_uid").items():
        options = [row for row in group if period_key_from_candidate(row) not in existing]
        options = sorted(options, key=lambda row: replacement_candidate_score(row), reverse=True)[:4]
        for row in options:
            start = parse_required(row["candidate_start"])
            end = parse_required(row["candidate_end"])
            before, after, cadence = nearest_ribs(start, end, DEFAULT_COLLECTOR)
            before_url = routeviews_rib_url(before, DEFAULT_COLLECTOR)
            after_url = routeviews_rib_url(after, DEFAULT_COLLECTOR)
            before_available, before_status, before_size, _ = head_url(before_url)
            after_available, after_status, after_size, _ = head_url(after_url)
            duration = period_duration_minutes(row)
            historical_available = before_available == "True" and after_available == "True"
            if row["known_incident_overlap"] == "True":
                status = "REJECT_KNOWN_INCIDENT_OVERLAP"
            elif duration < 30:
                status = "REVIEW_TOO_SHORT_FOR_30M_RULE"
            elif historical_available:
                status = "RIB_AVAILABLE_NEEDS_VISIBILITY_PARSE"
            else:
                status = "REVIEW_RIB_NOT_AVAILABLE"
            selected.append(
                {
                    "associated_incident_uid": row["incident_uid"],
                    "category": row["category"],
                    "affected_asn": row["affected_asn"],
                    "affected_prefix": row["affected_prefix"],
                    "candidate_start": row["candidate_start"],
                    "candidate_end": row["candidate_end"],
                    "days_from_incident": row["days_from_incident"],
                    "collector": DEFAULT_COLLECTOR,
                    "rib_before_timestamp": isoformat_z(before),
                    "rib_after_timestamp": isoformat_z(after),
                    "rib_visible": "UNKNOWN_NEEDS_RIB_VISIBILITY_PARSE",
                    "origin_visible": "UNKNOWN_NEEDS_RIB_VISIBILITY_PARSE",
                    "known_incident_overlap": row["known_incident_overlap"],
                    "pre_screen_status": status,
                    "estimated_update_file_count": update_file_count(row["candidate_start"], row["candidate_end"]),
                    "estimated_rib_bytes": before_size + after_size,
                    "reason_selected": (
                        "best available existing-pool alternative by distance/duration; "
                        "RIB availability checked, visibility parse still required before UPDATE acquisition"
                    ),
                    "notes": cadence,
                }
            )
    write_csv(
        NORMAL_REPLACEMENT_CANDIDATES,
        selected,
        [
            "associated_incident_uid",
            "category",
            "affected_asn",
            "affected_prefix",
            "candidate_start",
            "candidate_end",
            "days_from_incident",
            "collector",
            "rib_before_timestamp",
            "rib_after_timestamp",
            "rib_visible",
            "origin_visible",
            "known_incident_overlap",
            "pre_screen_status",
            "estimated_update_file_count",
            "estimated_rib_bytes",
            "reason_selected",
            "notes",
        ],
    )
    return selected


def write_policy() -> None:
    NORMAL_CANDIDATE_SELECTION_POLICY.write_text(
        """# Normal Candidate Selection Policy v2

This policy is diagnostic and provisional. It does not create final Normal labels and does not alter the frozen incident roster or partitions.

## Principle

NORMAL is not inferred from absence of a known incident. A Normal control window requires positive evidence of stable routing state plus absence of suspicious routing changes.

## Selection Order

1. Start from an associated TRAIN incident/network only.
2. Generate candidate control dates using calendar offsets, preserving similar time-of-day where practical.
3. Reject candidates overlapping any known incident or incident exclusion buffer.
4. Require the candidate period to support at least 30 minutes of sustained stability under the provisional rule.
5. Identify nearest before/after RouteViews RIB snapshots for the historical date.
6. Pre-screen RIB availability before downloading UPDATE files.
7. Confirm RIB visibility for the exact prefix when available; otherwise confirm ASN/network visibility.
8. Confirm expected origin stability across before/after RIB snapshots.
9. Select the collector deterministically by observability:
   - try the preferred collector first,
   - if the ASN/prefix is not visible, try historically available alternate collectors,
   - record the collector used and the reason,
   - never choose a collector because it produces the desired label.
10. Only after the RIB pre-screen passes, acquire UPDATE files for the candidate period.
11. Apply RIB + UPDATE stability qualification.
12. Assign `NORMAL_VERIFIED` only when positive stability evidence is present; otherwise keep `UNKNOWN`.

## Current Pilot Interpretation

The prior UPDATE-only method rejected stable silence because UPDATE archives record route changes, not persistent route state. The RIB-assisted method is the correct methodological direction. The remaining work before scaling is operational: use indexed or compiled RIB inspection and improve candidate selection for Hijack/Leak controls, especially when original candidate periods are shorter than 30 minutes.
""",
        encoding="utf-8",
    )


def run() -> dict[str, object]:
    diagnosis = diagnose_failures()
    visibility = build_collector_visibility()
    replacements = build_replacement_candidates()
    write_policy()
    return {
        "failed_controls": len(diagnosis),
        "failure_types": dict(Counter(row["failure_type"] for row in diagnosis)),
        "failure_classes": dict(Counter(row["failure_class"] for row in diagnosis)),
        "collector_visibility_rows": len(visibility),
        "replacement_candidates": len(replacements),
        "replacement_ready_for_update_acquisition": sum(
            row["pre_screen_status"] == "RIB_VISIBLE_READY_FOR_UPDATE_ACQUISITION" for row in replacements
        ),
        "replacement_needing_rib_visibility_parse": sum(
            row["pre_screen_status"] == "RIB_AVAILABLE_NEEDS_VISIBILITY_PARSE" for row in replacements
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Diagnose failed Normal controls and define candidate-selection policy v2")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if not args.run:
        parser.error("choose --run")
    print(json.dumps(run(), indent=2))


if __name__ == "__main__":
    main()
