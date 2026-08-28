from __future__ import annotations

import argparse
import csv
import math
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from statistics import mean, median

try:
    from bgp_incident_detection.audit import parse_utc, write_csv
    from bgp_incident_detection.mrt_parser import (
        PARSED_FIELDS,
        parse_as_path_set,
        prepare_relevance_metadata,
        match_relevance_prepared,
        load_csv,
    )
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import parse_utc, write_csv
    from src.bgp_incident_detection.mrt_parser import (
        PARSED_FIELDS,
        parse_as_path_set,
        prepare_relevance_metadata,
        match_relevance_prepared,
        load_csv,
    )


PILOT_DIR = Path("data/pilot")
PARSED_DIR = Path("data/parsed_mrt/pilot")
PILOT_MANIFEST = PILOT_DIR / "mrt_pilot_incidents_v1.csv"
DOWNLOAD_MANIFEST = PILOT_DIR / "mrt_pilot_download_manifest_v1.csv"
ACTIVE_SEGMENTS = PILOT_DIR / "pilot_candidate_active_segments_v1.csv"

WINDOW_COUNTS = PILOT_DIR / "five_minute_window_observation_counts_v1.csv"
DENSITY_SUMMARY = PILOT_DIR / "five_minute_window_density_summary_v1.csv"
INCIDENT_COVERAGE = PILOT_DIR / "five_minute_incident_coverage_v1.csv"

WINDOW_FIELDS = [
    "incident_uid",
    "category",
    "partition",
    "window_id",
    "window_start",
    "window_end",
    "temporal_status",
    "raw_observation_count",
    "relevant_observation_count",
    "announcement_count",
    "withdrawal_count",
    "unique_prefixes",
    "unique_peer_asns",
    "unique_origin_asns",
    "unique_as_paths",
]


def floor_to_five_minutes(timestamp: datetime) -> datetime:
    floored_minute = timestamp.minute - (timestamp.minute % 5)
    return timestamp.replace(minute=floored_minute, second=0, microsecond=0)


def format_utc(timestamp: datetime) -> str:
    return timestamp.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def window_id(incident_uid: str, window_start: datetime) -> str:
    compact = format_utc(window_start).replace(":", "").replace("-", "").replace(".000Z", "Z")
    return f"{incident_uid}_{compact}"


def parsed_output_path(incident_uid: str) -> Path:
    return PARSED_DIR / incident_uid.replace(":", "_") / "parsed_bgp_observations.csv"


def five_minute_windows(start: datetime, end: datetime) -> list[datetime]:
    if end <= start:
        return []
    windows = []
    current = floor_to_five_minutes(start)
    while current < end:
        windows.append(current)
        current += timedelta(minutes=5)
    return windows


def build_download_windows(download_rows: list[dict[str, str]]) -> dict[str, set[datetime]]:
    windows_by_uid: dict[str, set[datetime]] = defaultdict(set)
    for row in download_rows:
        mrt_start = parse_utc(row["mrt_timestamp"])
        if not mrt_start:
            continue
        for offset in (0, 5, 10):
            windows_by_uid[row["incident_uid"]].add(mrt_start + timedelta(minutes=offset))
    return windows_by_uid


def load_active_ranges(
    incidents: dict[str, dict[str, str]],
    active_rows: list[dict[str, str]],
    gap_rule: str = "max_gap_between_active_bins<=60m",
) -> dict[str, list[tuple[datetime, datetime]]]:
    ranges: dict[str, list[tuple[datetime, datetime]]] = defaultdict(list)
    for incident_uid, incident in incidents.items():
        if incident["category"] == "Outage":
            start = parse_utc(incident["start_utc"])
            end = parse_utc(incident["end_utc"])
            if start and end:
                ranges[incident_uid].append((start, end))
    for row in active_rows:
        if row.get("gap_rule") != gap_rule:
            continue
        start = parse_utc(row["active_segment_start"])
        end = parse_utc(row["active_segment_end"])
        if start and end:
            ranges[row["incident_uid"]].append((start, end))
    return {uid: sorted(values) for uid, values in ranges.items()}


def temporal_status(window_start: datetime, active_ranges: list[tuple[datetime, datetime]]) -> str:
    window_end = window_start + timedelta(minutes=5)
    for active_start, active_end in active_ranges:
        if window_start < active_end and active_start < window_end:
            return "INCIDENT_ACTIVE"
    if not active_ranges:
        return "UNKNOWN"
    first_start = min(start for start, _ in active_ranges)
    last_end = max(end for _, end in active_ranges)
    if window_end <= first_start:
        return "PRE_CONTEXT"
    if window_start >= last_end:
        return "POST_CONTEXT"
    return "UNKNOWN"


def init_window_row(
    incident: dict[str, str],
    window_start: datetime,
    status: str,
) -> dict[str, object]:
    return {
        "incident_uid": incident["incident_uid"],
        "category": incident["category"],
        "partition": incident["partition"],
        "window_id": window_id(incident["incident_uid"], window_start),
        "window_start": format_utc(window_start),
        "window_end": format_utc(window_start + timedelta(minutes=5)),
        "temporal_status": status,
        "raw_observation_count": 0,
        "relevant_observation_count": 0,
        "announcement_count": 0,
        "withdrawal_count": 0,
        "unique_prefixes": set(),
        "unique_peer_asns": set(),
        "unique_origin_asns": set(),
        "unique_as_paths": set(),
    }


def parse_minimal_row(parts: list[str], incident_uid: str) -> dict[str, str] | None:
    if len(parts) != len(PARSED_FIELDS):
        return None
    return {
        "incident_uid": incident_uid,
        "bgp_timestamp_utc": parts[3],
        "peer_asn": parts[5],
        "announcement_or_withdrawal": parts[7],
        "prefix": parts[8],
        "as_path": parts[9],
        "origin_asn": parts[10],
    }


def increment_window(row: dict[str, object], observation: dict[str, str], is_relevant: bool) -> None:
    row["raw_observation_count"] = int(row["raw_observation_count"]) + 1
    if not is_relevant:
        return
    row["relevant_observation_count"] = int(row["relevant_observation_count"]) + 1
    if observation["announcement_or_withdrawal"] == "announcement":
        row["announcement_count"] = int(row["announcement_count"]) + 1
    elif observation["announcement_or_withdrawal"] == "withdrawal":
        row["withdrawal_count"] = int(row["withdrawal_count"]) + 1
    if observation["prefix"]:
        row["unique_prefixes"].add(observation["prefix"])
    if observation["peer_asn"]:
        row["unique_peer_asns"].add(observation["peer_asn"])
    if observation["origin_asn"]:
        row["unique_origin_asns"].add(observation["origin_asn"])
    if observation["as_path"]:
        row["unique_as_paths"].add(observation["as_path"])


def finalize_window_rows(rows_by_key: dict[tuple[str, datetime], dict[str, object]]) -> list[dict[str, object]]:
    finalized = []
    for _, row in sorted(rows_by_key.items(), key=lambda item: (item[0][0], item[0][1])):
        clean = dict(row)
        for field in ("unique_prefixes", "unique_peer_asns", "unique_origin_asns", "unique_as_paths"):
            clean[field] = len(clean[field])
        finalized.append(clean)
    return finalized


def percentile(values: list[int], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * q
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[int(position)])
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def density_summary(window_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    by_uid: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in window_rows:
        by_uid[str(row["incident_uid"])].append(row)
    output = []
    for incident_uid, rows in sorted(by_uid.items()):
        counts = [int(row["relevant_observation_count"]) for row in rows]
        status_counts = Counter(str(row["temporal_status"]) for row in rows)
        output.append(
            {
                "incident_uid": incident_uid,
                "category": rows[0]["category"],
                "partition": rows[0]["partition"],
                "five_minute_windows": len(rows),
                "incident_active_windows": status_counts["INCIDENT_ACTIVE"],
                "pre_context_windows": status_counts["PRE_CONTEXT"],
                "post_context_windows": status_counts["POST_CONTEXT"],
                "unknown_windows": status_counts["UNKNOWN"],
                "minimum_observations_per_window": min(counts) if counts else 0,
                "median_observations_per_window": round(median(counts), 3) if counts else 0,
                "mean_observations_per_window": round(mean(counts), 3) if counts else 0,
                "p90_observations_per_window": round(percentile(counts, 0.9), 3),
                "maximum_observations_per_window": max(counts) if counts else 0,
            }
        )
    return output


def coverage_summary(window_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    by_uid: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in window_rows:
        by_uid[str(row["incident_uid"])].append(row)
    output = []
    for incident_uid, rows in sorted(by_uid.items()):
        active_rows = [row for row in rows if row["temporal_status"] == "INCIDENT_ACTIVE"]
        empty_rows = [row for row in rows if int(row["relevant_observation_count"]) == 0]
        active_with_evidence = [row for row in active_rows if int(row["relevant_observation_count"]) > 0]
        empty_active = [row for row in active_rows if int(row["relevant_observation_count"]) == 0]
        category = str(rows[0]["category"])
        supported = len(active_with_evidence) > 0
        if category in {"Hijack", "Leak"}:
            notes = (
                "candidate active segments have RouteViews-relevant observations"
                if supported
                else "candidate active segments have no directly relevant RouteViews observations"
            )
        else:
            notes = (
                "documented outage interval has RouteViews observations involving affected ASN metadata"
                if supported
                else "documented outage interval has no directly relevant RouteViews observations"
            )
        output.append(
            {
                "incident_uid": incident_uid,
                "category": category,
                "partition": rows[0]["partition"],
                "total_windows": len(rows),
                "incident_active_windows": len(active_rows),
                "active_windows_with_evidence": len(active_with_evidence),
                "active_windows_with_zero_relevant_observations": len(empty_active),
                "empty_windows": len(empty_rows),
                "empty_incident_active_windows": len(empty_active),
                "empty_pre_context_windows": sum(1 for row in empty_rows if row["temporal_status"] == "PRE_CONTEXT"),
                "empty_post_context_windows": sum(1 for row in empty_rows if row["temporal_status"] == "POST_CONTEXT"),
                "empty_unknown_windows": sum(1 for row in empty_rows if row["temporal_status"] == "UNKNOWN"),
                "observations_visible_during_expected_active_window": "YES" if supported else "NO",
                "routeviews_supports_candidate_active_segments": "YES" if supported else "NO",
                "notes": notes,
            }
        )
    return output


def build_windows(incident_uids: set[str] | None = None) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    incidents = {row["incident_uid"]: row for row in load_csv(PILOT_MANIFEST)}
    if incident_uids is not None:
        incidents = {uid: row for uid, row in incidents.items() if uid in incident_uids}
    download_rows = [row for row in load_csv(DOWNLOAD_MANIFEST) if row["incident_uid"] in incidents]
    active_rows = load_csv(ACTIVE_SEGMENTS)
    windows_by_uid = build_download_windows(download_rows)
    active_ranges = load_active_ranges(incidents, active_rows)
    relevance_metadata = prepare_relevance_metadata(incidents)

    rows_by_key: dict[tuple[str, datetime], dict[str, object]] = {}
    for incident_uid, starts in windows_by_uid.items():
        incident = incidents[incident_uid]
        for start in starts:
            rows_by_key[(incident_uid, start)] = init_window_row(
                incident,
                start,
                temporal_status(start, active_ranges.get(incident_uid, [])),
            )

    for incident_uid in sorted(incidents):
        path = parsed_output_path(incident_uid)
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.reader(handle)
            header = next(reader)
            if header != PARSED_FIELDS:
                raise ValueError(f"Unexpected parsed schema in {path}")
            for parts in reader:
                observation = parse_minimal_row(parts, incident_uid)
                if observation is None:
                    continue
                timestamp = parse_utc(observation["bgp_timestamp_utc"])
                if not timestamp:
                    continue
                start = floor_to_five_minutes(timestamp)
                key = (incident_uid, start)
                if key not in rows_by_key:
                    rows_by_key[key] = init_window_row(
                        incidents[incident_uid],
                        start,
                        temporal_status(start, active_ranges.get(incident_uid, [])),
                    )
                increment_window(
                    rows_by_key[key],
                    observation,
                    match_relevance_prepared(observation, relevance_metadata[incident_uid]),
                )

    window_rows = finalize_window_rows(rows_by_key)
    return window_rows, density_summary(window_rows), coverage_summary(window_rows)


def write_outputs(window_rows: list[dict[str, object]], density_rows: list[dict[str, object]], coverage_rows: list[dict[str, object]]) -> None:
    write_csv(WINDOW_COUNTS, window_rows, WINDOW_FIELDS)
    write_csv(
        DENSITY_SUMMARY,
        density_rows,
        [
            "incident_uid",
            "category",
            "partition",
            "five_minute_windows",
            "incident_active_windows",
            "pre_context_windows",
            "post_context_windows",
            "unknown_windows",
            "minimum_observations_per_window",
            "median_observations_per_window",
            "mean_observations_per_window",
            "p90_observations_per_window",
            "maximum_observations_per_window",
        ],
    )
    write_csv(
        INCIDENT_COVERAGE,
        coverage_rows,
        [
            "incident_uid",
            "category",
            "partition",
            "total_windows",
            "incident_active_windows",
            "active_windows_with_evidence",
            "active_windows_with_zero_relevant_observations",
            "empty_windows",
            "empty_incident_active_windows",
            "empty_pre_context_windows",
            "empty_post_context_windows",
            "empty_unknown_windows",
            "observations_visible_during_expected_active_window",
            "routeviews_supports_candidate_active_segments",
            "notes",
        ],
    )


def print_summary(window_rows: list[dict[str, object]], density_rows: list[dict[str, object]], coverage_rows: list[dict[str, object]]) -> None:
    status_counts = Counter(str(row["temporal_status"]) for row in window_rows)
    class_counts = Counter(str(row["category"]) for row in window_rows)
    total_relevant = sum(int(row["relevant_observation_count"]) for row in window_rows)
    empty = sum(1 for row in window_rows if int(row["relevant_observation_count"]) == 0)
    print(f"five_minute_windows={len(window_rows)}")
    print(f"status_counts={dict(status_counts)}")
    print(f"class_counts={dict(class_counts)}")
    print(f"relevant_observations={total_relevant}")
    print(f"empty_windows={empty}")
    print("coverage:")
    for row in coverage_rows:
        print(row)
    print("density:")
    for row in density_rows:
        print(row)


def main() -> None:
    parser = argparse.ArgumentParser(description="Construct and inspect 5-minute pilot windows.")
    parser.add_argument("--incident-uid", action="append", default=None)
    args = parser.parse_args()
    incident_uids = set(args.incident_uid) if args.incident_uid else None
    window_rows, density_rows, coverage_rows = build_windows(incident_uids)
    if incident_uids is None:
        write_outputs(window_rows, density_rows, coverage_rows)
    print_summary(window_rows, density_rows, coverage_rows)


if __name__ == "__main__":
    main()
