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
    from bgp_incident_detection.mrt_acquisition import (
        ACQUISITION_PLAN,
        PILOT_MANIFEST,
        ceil_to_15_minutes,
        floor_to_15_minutes,
        iter_update_slots,
    )
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import parse_utc, write_csv
    from src.bgp_incident_detection.mrt_acquisition import (
        ACQUISITION_PLAN,
        PILOT_MANIFEST,
        ceil_to_15_minutes,
        floor_to_15_minutes,
        iter_update_slots,
    )


PILOT_DIR = Path("data/pilot")
RAW_HIJACKS = Path("cloudflare_incidents/raw_hijacks_all_available_to_2026-01_cloudflare.json")
RAW_LEAKS = Path("cloudflare_incidents/raw_leaks_all_available_to_2026-01_cloudflare.json")

OBSERVATION_TIMELINE = PILOT_DIR / "pilot_event_observation_timeline_v1.csv"
ACTIVE_BINS = PILOT_DIR / "pilot_active_bins_v1.csv"
GAP_ANALYSIS = PILOT_DIR / "pilot_active_gap_analysis_v1.csv"
THRESHOLD_SENSITIVITY = PILOT_DIR / "pilot_active_window_threshold_sensitivity_v1.csv"
CANDIDATE_SEGMENTS = PILOT_DIR / "pilot_candidate_active_segments_v1.csv"
VOLUME_COMPARISON = PILOT_DIR / "pilot_active_window_volume_comparison_v1.csv"
POLICY_RECOMMENDATION = PILOT_DIR / "pilot_active_window_policy_recommendation_v1.md"

THRESHOLDS_MINUTES = (5, 10, 15, 30, 60)
BIN_MINUTES = 5
CONTEXT_BUFFER_MINUTES = 60


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def load_raw_index(path: Path) -> dict[str, dict[str, object]]:
    records = json.loads(path.read_text(encoding="utf-8"))
    return {str(record["id"]): record for record in records}


def isoformat_ms(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def floor_to_5_minutes(value: datetime) -> datetime:
    return value.replace(minute=(value.minute // BIN_MINUTES) * BIN_MINUTES, second=0, microsecond=0)


def ceil_to_5_minutes(value: datetime) -> datetime:
    floored = floor_to_5_minutes(value)
    if value == floored:
        return value
    return floored + timedelta(minutes=BIN_MINUTES)


def parse_required(value: str) -> datetime:
    parsed = parse_utc(value)
    if not parsed:
        raise ValueError(f"invalid UTC timestamp: {value}")
    return parsed


def pilot_incident_rows() -> list[dict[str, str]]:
    return [row for row in load_csv(PILOT_MANIFEST) if row["category"] in {"Hijack", "Leak"}]


def observation_rows() -> list[dict[str, object]]:
    hijacks = load_raw_index(RAW_HIJACKS)
    leaks = load_raw_index(RAW_LEAKS)
    output: list[dict[str, object]] = []
    for row in pilot_incident_rows():
        source_record_id = row["incident_uid"].split(":", 1)[1]
        if row["category"] == "Hijack":
            raw = hijacks[source_record_id]
            observations = [
                ("first_hijack_evidence", raw.get("min_hijack_ts")),
                ("last_hijack_evidence", raw.get("max_hijack_ts")),
            ]
            asn = raw.get("hijacker_asn", row.get("leak_asn", ""))
            prefixes = raw.get("prefixes") or [""]
        else:
            raw = leaks[source_record_id]
            observations = [
                ("detected_ts", raw.get("detected_ts")),
                ("first_leak_evidence", raw.get("min_ts")),
                ("last_leak_evidence", raw.get("max_ts")),
            ]
            asn = raw.get("leak_asn", row.get("leak_asn", ""))
            prefixes = [""]

        seen: set[tuple[str, str]] = set()
        for observation_type, timestamp in observations:
            if not timestamp:
                continue
            parsed = parse_required(str(timestamp))
            key = (observation_type, isoformat_ms(parsed))
            if key in seen:
                continue
            seen.add(key)
            output.append(
                {
                    "incident_uid": row["incident_uid"],
                    "category": row["category"],
                    "observation_timestamp": isoformat_ms(parsed),
                    "observation_type": f"{observation_type};detector_boundary",
                    "asn": asn,
                    "prefix": prefixes[0] if prefixes else "",
                    "source_record_id": source_record_id,
                }
            )
    return sorted(output, key=lambda item: (str(item["incident_uid"]), str(item["observation_timestamp"]), str(item["observation_type"])))


def bin_rows(observations: list[dict[str, object]]) -> list[dict[str, object]]:
    observations_by_uid: dict[str, list[dict[str, object]]] = {}
    for row in observations:
        observations_by_uid.setdefault(str(row["incident_uid"]), []).append(row)

    output: list[dict[str, object]] = []
    for incident_uid, rows in observations_by_uid.items():
        category = str(rows[0]["category"])
        timestamps = [parse_required(str(row["observation_timestamp"])) for row in rows]
        start_bin = floor_to_5_minutes(min(timestamps))
        end_bin = floor_to_5_minutes(max(timestamps))
        active_by_bin: dict[datetime, list[dict[str, object]]] = {}
        for row in rows:
            active_by_bin.setdefault(floor_to_5_minutes(parse_required(str(row["observation_timestamp"]))), []).append(row)

        cursor = start_bin
        while cursor <= end_bin:
            active_rows = active_by_bin.get(cursor, [])
            output.append(
                {
                    "incident_uid": incident_uid,
                    "category": category,
                    "bin_start_utc": isoformat_ms(cursor),
                    "bin_end_utc": isoformat_ms(cursor + timedelta(minutes=BIN_MINUTES)),
                    "activity_status": "ACTIVE" if active_rows else "SILENT",
                    "observation_count": len(active_rows),
                    "observation_types": json.dumps(sorted(str(row["observation_type"]) for row in active_rows)),
                    "notes": "event-specific detector evidence bin" if active_rows else "SILENT/UNKNOWN; not Normal",
                }
            )
            cursor += timedelta(minutes=BIN_MINUTES)
    return output


def percentile(values: list[float], quantile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def active_bin_starts(bins: list[dict[str, object]]) -> dict[str, list[datetime]]:
    output: dict[str, list[datetime]] = {}
    for row in bins:
        if row["activity_status"] == "ACTIVE":
            output.setdefault(str(row["incident_uid"]), []).append(parse_required(str(row["bin_start_utc"])))
    return {uid: sorted(starts) for uid, starts in output.items()}


def gap_analysis_rows(observations: list[dict[str, object]], bins: list[dict[str, object]]) -> list[dict[str, object]]:
    by_uid: dict[str, list[dict[str, object]]] = {}
    for row in observations:
        by_uid.setdefault(str(row["incident_uid"]), []).append(row)
    active_starts = active_bin_starts(bins)
    output: list[dict[str, object]] = []
    for incident_uid, rows in by_uid.items():
        timestamps = sorted(parse_required(str(row["observation_timestamp"])) for row in rows)
        gaps = [
            (right - left).total_seconds() / 60
            for left, right in zip(timestamps, timestamps[1:])
        ]
        incident_bins = [row for row in bins if row["incident_uid"] == incident_uid]
        active_count = len(active_starts.get(incident_uid, []))
        silent_count = sum(1 for row in incident_bins if row["activity_status"] == "SILENT")
        first_to_last = (timestamps[-1] - timestamps[0]).total_seconds() / 60
        output.append(
            {
                "incident_uid": incident_uid,
                "category": rows[0]["category"],
                "observation_count": len(rows),
                "active_5min_bin_count": active_count,
                "silent_5min_bin_count": silent_count,
                "maximum_silent_gap_minutes": max(gaps) if gaps else 0.0,
                "median_gap_between_observations_minutes": percentile(gaps, 0.50),
                "p90_gap_between_observations_minutes": percentile(gaps, 0.90),
                "total_first_to_last_detector_span_minutes": round(first_to_last, 3),
                "total_evidence_active_duration_minutes": active_count * BIN_MINUTES,
                "evidence_limitation": "boundary_only_source_record; dense event observation timestamps unavailable locally",
            }
        )
    return output


def merge_segments(starts: list[datetime], threshold_minutes: int) -> list[tuple[datetime, datetime, int]]:
    if not starts:
        return []
    segments: list[tuple[datetime, datetime, int]] = []
    segment_start = starts[0]
    previous = starts[0]
    count = 1
    for current in starts[1:]:
        gap = (current - previous).total_seconds() / 60
        if gap <= threshold_minutes:
            previous = current
            count += 1
        else:
            segments.append((segment_start, previous + timedelta(minutes=BIN_MINUTES), count))
            segment_start = current
            previous = current
            count = 1
    segments.append((segment_start, previous + timedelta(minutes=BIN_MINUTES), count))
    return segments


def file_count_for_segments(segments: list[tuple[datetime, datetime, int]], buffer_minutes: int = CONTEXT_BUFFER_MINUTES) -> int:
    slots: set[datetime] = set()
    for start, end, _ in segments:
        collection_start = floor_to_15_minutes(start - timedelta(minutes=buffer_minutes))
        collection_end = ceil_to_15_minutes(end + timedelta(minutes=buffer_minutes))
        slots.update(iter_update_slots(collection_start, collection_end))
    return len(slots)


def threshold_outputs(
    bins: list[dict[str, object]],
    plan_rows: list[dict[str, str]],
) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    starts_by_uid = active_bin_starts(bins)
    plan_by_uid = {row["incident_uid"]: row for row in plan_rows}
    sensitivity: list[dict[str, object]] = []
    segments_rows: list[dict[str, object]] = []
    volume_rows: list[dict[str, object]] = []

    for incident_uid, starts in starts_by_uid.items():
        category = next(row["category"] for row in bins if row["incident_uid"] == incident_uid)
        original_file_count = int(plan_by_uid[incident_uid]["expected_file_count"])
        original_span = minutes_between(plan_by_uid[incident_uid]["collection_start"], plan_by_uid[incident_uid]["collection_end"])
        for threshold in THRESHOLDS_MINUTES:
            segments = merge_segments(starts, threshold)
            active_duration = sum((end - start).total_seconds() / 60 for start, end, _ in segments)
            active_files = file_count_for_segments(segments)
            reduction = original_file_count - active_files
            sensitivity.append(
                {
                    "incident_uid": incident_uid,
                    "category": category,
                    "gap_rule": f"max_gap_between_active_bins<={threshold}m",
                    "threshold_minutes": threshold,
                    "resulting_active_segments": len(segments),
                    "total_active_duration_minutes": round(active_duration, 3),
                    "original_collection_span_minutes": round(original_span, 3),
                    "reduction_vs_original_span_percent": round((1 - (active_duration / original_span)) * 100, 3) if original_span else 0.0,
                    "expected_routeviews_file_count": active_files,
                }
            )
            if threshold == 60:
                volume_rows.append(
                    {
                        "incident_uid": incident_uid,
                        "category": category,
                        "gap_rule": f"max_gap_between_active_bins<={threshold}m",
                        "original_planned_file_count": original_file_count,
                        "active_window_planned_file_count": active_files,
                        "absolute_reduction": reduction,
                        "percentage_reduction": round((reduction / original_file_count) * 100, 3) if original_file_count else 0.0,
                        "caution": "boundary-only observations; file-count reduction is not a final label-window decision",
                    }
                )
            for index, (start, end, count) in enumerate(segments, start=1):
                segments_rows.append(
                    {
                        "incident_uid": incident_uid,
                        "category": category,
                        "active_segment_index": index,
                        "active_segment_start": isoformat_ms(start),
                        "active_segment_end": isoformat_ms(end),
                        "active_bin_count": count,
                        "gap_rule": f"max_gap_between_active_bins<={threshold}m",
                    }
                )
    return sensitivity, segments_rows, volume_rows


def minutes_between(start_text: str, end_text: str) -> float:
    return (parse_required(end_text) - parse_required(start_text)).total_seconds() / 60


def write_policy(
    gap_rows: list[dict[str, object]],
    sensitivity_rows: list[dict[str, object]],
    volume_rows: list[dict[str, object]],
    path: Path = POLICY_RECOMMENDATION,
) -> None:
    sparse = [row for row in gap_rows if row["evidence_limitation"]]
    total_original = sum(int(row["original_planned_file_count"]) for row in volume_rows)
    total_active = sum(int(row["active_window_planned_file_count"]) for row in volume_rows)
    reduction = total_original - total_active
    reduction_pct = round((reduction / total_original) * 100, 3) if total_original else 0.0
    max_gap = max(float(row["maximum_silent_gap_minutes"]) for row in gap_rows)
    threshold_counts = Counter(row["threshold_minutes"] for row in sensitivity_rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                "# Pilot Active-Window Policy Recommendation v1",
                "",
                "## Evidence Status",
                "",
                f"- Hijack/Leak pilot incidents analyzed: `{len(gap_rows)}`",
                f"- Incidents with boundary-only local detector observations: `{len(sparse)}`",
                f"- Maximum observed first-to-last boundary gap: `{round(max_gap, 3)}` minutes",
                "- The local Cloudflare raw records expose first/last event evidence and aggregate counts, but not dense per-message observation timelines for these six pilot events.",
                "- ACTIVE means detector-supported incident activity. SILENT/UNKNOWN does not mean Normal.",
                "",
                "## Threshold Recommendation",
                "",
                "- Do not freeze a final `max_gap_between_active_bins` from this boundary-only pilot evidence.",
                "- For the next download pilot, use the 60-minute context buffer unchanged.",
                "- Before scaling acquisition, recover or derive dense event-specific observations from MRT parsing or a detector detail source, then re-evaluate candidate thresholds of 5, 10, 15, 30, and 60 minutes.",
                "- If a provisional threshold is needed only for acquisition scoping, `60 minutes` is the least fragmented tested rule, but it remains provisional and should not become a training label rule yet.",
                "",
                "## Acquisition Volume Effect at 60-Minute Candidate Rule",
                "",
                f"- Original planned Hijack/Leak files: `{total_original}`",
                f"- Candidate active-window files: `{total_active}`",
                f"- Absolute reduction: `{reduction}` files",
                f"- Percentage reduction: `{reduction_pct}%`",
                "",
                "## Decision",
                "",
                "- Outage windows remain acceptable as documented Cloudflare intervals.",
                "- Hijack/Leak active-window extraction is not fully defensible from the current local detector records alone because all six pilot timelines are boundary-only.",
                "- Recommended next action: either download a very small MRT subset for the short/median incidents first, or acquire enough MRT around the boundary-supported active bins to derive dense observation evidence before downloading the full long spans.",
                "",
                "## Threshold Rows Generated",
                "",
                f"- Sensitivity rows by threshold: `{dict(threshold_counts)}`",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def run() -> dict[str, list[dict[str, object]]]:
    observations = observation_rows()
    bins = bin_rows(observations)
    gap_rows = gap_analysis_rows(observations, bins)
    plan_rows = [row for row in load_csv(ACQUISITION_PLAN) if row["category"] in {"Hijack", "Leak"}]
    sensitivity, segments, volume = threshold_outputs(bins, plan_rows)

    write_csv(
        OBSERVATION_TIMELINE,
        observations,
        ["incident_uid", "category", "observation_timestamp", "observation_type", "asn", "prefix", "source_record_id"],
    )
    write_csv(
        ACTIVE_BINS,
        bins,
        ["incident_uid", "category", "bin_start_utc", "bin_end_utc", "activity_status", "observation_count", "observation_types", "notes"],
    )
    write_csv(
        GAP_ANALYSIS,
        gap_rows,
        [
            "incident_uid",
            "category",
            "observation_count",
            "active_5min_bin_count",
            "silent_5min_bin_count",
            "maximum_silent_gap_minutes",
            "median_gap_between_observations_minutes",
            "p90_gap_between_observations_minutes",
            "total_first_to_last_detector_span_minutes",
            "total_evidence_active_duration_minutes",
            "evidence_limitation",
        ],
    )
    write_csv(
        THRESHOLD_SENSITIVITY,
        sensitivity,
        [
            "incident_uid",
            "category",
            "gap_rule",
            "threshold_minutes",
            "resulting_active_segments",
            "total_active_duration_minutes",
            "original_collection_span_minutes",
            "reduction_vs_original_span_percent",
            "expected_routeviews_file_count",
        ],
    )
    write_csv(
        CANDIDATE_SEGMENTS,
        segments,
        ["incident_uid", "category", "active_segment_index", "active_segment_start", "active_segment_end", "active_bin_count", "gap_rule"],
    )
    write_csv(
        VOLUME_COMPARISON,
        volume,
        [
            "incident_uid",
            "category",
            "gap_rule",
            "original_planned_file_count",
            "active_window_planned_file_count",
            "absolute_reduction",
            "percentage_reduction",
            "caution",
        ],
    )
    write_policy(gap_rows, sensitivity, volume)
    return {
        "observations": observations,
        "bins": bins,
        "gap_analysis": gap_rows,
        "sensitivity": sensitivity,
        "segments": segments,
        "volume": volume,
    }


def print_report(results: dict[str, list[dict[str, object]]]) -> None:
    print("Pilot active-window analysis complete")
    print("Observation rows:", len(results["observations"]))
    print("Active/Silent bins:", dict(Counter(row["activity_status"] for row in results["bins"])))
    print("Gap rows:", len(results["gap_analysis"]))
    print("Threshold sensitivity rows:", len(results["sensitivity"]))
    print("Candidate segment rows:", len(results["segments"]))
    print("Volume comparison:")
    for row in results["volume"]:
        print(json.dumps(row, sort_keys=True))
    print("No MRT files downloaded.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build pilot active-window analysis from detector-specific observations.")
    parser.parse_args()
    results = run()
    print_report(results)


if __name__ == "__main__":
    main()
