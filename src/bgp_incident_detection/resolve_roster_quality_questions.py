from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from statistics import median

try:
    from bgp_incident_detection.audit import asn_set, country_set, interval, prefix_set, write_csv
    from bgp_incident_detection.review_triage import (
        PARTITION_DIR,
        REVIEW_DIR,
        load_csv,
        load_partition_rows,
        pct_temporal_overlap,
        source_provenance,
    )
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import asn_set, country_set, interval, prefix_set, write_csv
    from src.bgp_incident_detection.review_triage import (
        PARTITION_DIR,
        REVIEW_DIR,
        load_csv,
        load_partition_rows,
        pct_temporal_overlap,
        source_provenance,
    )


RAW_FILES = {
    "Hijack": Path("cloudflare_incidents/raw_hijacks_all_available_to_2026-01_cloudflare.json"),
    "Leak": Path("cloudflare_incidents/raw_leaks_all_available_to_2026-01_cloudflare.json"),
    "Outage": Path("cloudflare_incidents/raw_outages_all_available_to_2026-01_cloudflare.json"),
}


def load_raw_index() -> dict[str, dict[str, dict[str, object]]]:
    index: dict[str, dict[str, dict[str, object]]] = {}
    for category, path in RAW_FILES.items():
        with path.open(encoding="utf-8") as handle:
            records = json.load(handle)
        index[category] = {str(record["id"]): record for record in records}
    return index


def minutes(row: dict[str, str]) -> float:
    try:
        return float(row.get("duration_minutes", "nan"))
    except ValueError:
        return math.nan


def observation_count(row: dict[str, str], raw_record: dict[str, object] | None) -> int | None:
    if not raw_record:
        return None
    if row["category"] == "Hijack":
        return int(raw_record.get("hijack_msgs_count") or 0)
    if row["category"] == "Leak":
        return int(raw_record.get("leak_count") or 0)
    return None


def observation_density(row: dict[str, str], raw_record: dict[str, object] | None) -> float | None:
    count = observation_count(row, raw_record)
    duration = minutes(row)
    if count is None or math.isnan(duration) or duration <= 0:
        return None
    windows = max(1, math.ceil(duration / 5))
    return count / windows


def window_method(row: dict[str, str], raw_record: dict[str, object] | None) -> str:
    category = row["category"]
    duration = minutes(row)
    density = observation_density(row, raw_record)
    if category == "Outage":
        return "use_reported_startDate_endDate_as_documented_outage_interval; review very long events before collection"
    if category == "Hijack":
        if not math.isnan(duration) and duration > 24 * 60:
            return "derive event-active subwindows from hijack observations; do not assume continuous activity across full min/max span"
        if density is not None and density < 1:
            return "use min_hijack_ts_to_max_hijack_ts cautiously; sparse observations suggest active subwindow review"
        return "current min_hijack_ts_to_max_hijack_ts is acceptable as first/last evidence interval"
    if not math.isnan(duration) and duration > 24 * 60:
        return "derive leak-active subwindows from route-leak observations; do not assume continuous activity across full min/max span"
    if density is not None and density < 1:
        return "use min_ts_to_max_ts cautiously; sparse observations suggest active subwindow review"
    return "current min_ts_to_max_ts is acceptable as first/last observation interval"


def timestamp_semantics_resolution(rows: list[dict[str, str]], raw_index: dict[str, dict[str, dict[str, object]]]) -> list[dict[str, object]]:
    evidence_by_category: dict[str, dict[str, object]] = {}
    for category in ("Hijack", "Leak", "Outage"):
        subset = [row for row in rows if row["category"] == category]
        long_subset = [row for row in subset if minutes(row) > 24 * 60]
        densities = []
        counts = []
        for row in subset:
            raw = raw_index[category].get(row["incident_id"])
            density = observation_density(row, raw)
            count = observation_count(row, raw)
            if density is not None:
                densities.append(density)
            if count is not None:
                counts.append(count)
        sparse_long = 0
        for row in long_subset:
            raw = raw_index[category].get(row["incident_id"])
            density = observation_density(row, raw)
            if density is not None and density < 1:
                sparse_long += 1
        evidence_by_category[category] = {
            "incident_count": len(subset),
            "long_gt_24h": len(long_subset),
            "median_observation_density_per_5min_window": round(median(densities), 4) if densities else "",
            "sparse_long_intervals_density_lt_1": sparse_long,
            "raw_fields_observed": sorted(raw_index[category][next(iter(raw_index[category]))].keys()) if raw_index[category] else [],
        }
    return [
        {
            "category": "Hijack",
            "field_start": "min_hijack_ts",
            "field_end": "max_hijack_ts",
            "semantic_meaning": "first and last Cloudflare hijack-specific detector observations associated with the event",
            "continuous_event_window_yes_no": "no_not_proven_continuous",
            "safe_for_labeling_yes_no": "yes_for_short_dense_events; review_for_long_sparse_events",
            "recommended_label_window_method": "use min/max as bounding evidence only; for long events define active subwindows from hijack observation timestamps before feature extraction",
            "evidence": json.dumps(evidence_by_category["Hijack"], sort_keys=True),
        },
        {
            "category": "Leak",
            "field_start": "min_ts_or_detected_ts",
            "field_end": "max_ts",
            "semantic_meaning": "first and last observations associated with the Cloudflare route-leak detector event; detected_ts is detector creation/fallback time",
            "continuous_event_window_yes_no": "no_not_proven_continuous",
            "safe_for_labeling_yes_no": "review_required_for_long_or_sparse_events",
            "recommended_label_window_method": "treat min_ts/max_ts as detector observation span; recover route-leak active subwindows or cap/select windows after inspecting observation distribution",
            "evidence": json.dumps(evidence_by_category["Leak"], sort_keys=True),
        },
        {
            "category": "Outage",
            "field_start": "startDate",
            "field_end": "endDate",
            "semantic_meaning": "documented reported outage interval from Cloudflare outage event metadata",
            "continuous_event_window_yes_no": "yes_reasonable_reported_interval",
            "safe_for_labeling_yes_no": "yes_with_manual_review_for_policy_or_regional_scope",
            "recommended_label_window_method": "use reported startDate/endDate as outage label interval; keep one real-world outage as one incident",
            "evidence": json.dumps(evidence_by_category["Outage"], sort_keys=True),
        },
    ]


def incident_window_recommendations(rows: list[dict[str, str]], raw_index: dict[str, dict[str, dict[str, object]]]) -> list[dict[str, object]]:
    output = []
    for row in rows:
        category = row["category"]
        raw = raw_index[category].get(row["incident_id"])
        duration = minutes(row)
        density = observation_density(row, raw)
        if category == "Outage":
            status = "SAFE_CURRENT_TIMESTAMPS"
            if duration > 24 * 60:
                status = "REDEFINE_LABEL_WINDOW"
        elif duration > 24 * 60 or (density is not None and density < 1):
            status = "REDEFINE_LABEL_WINDOW"
        elif math.isnan(duration):
            status = "UNDEFENSIBLE_WINDOW"
        else:
            status = "SAFE_CURRENT_TIMESTAMPS"
        output.append(
            {
                "incident_uid": row["incident_uid"],
                "category": category,
                "partition": row["partition"],
                "duration_minutes": row.get("duration_minutes", ""),
                "observation_count": observation_count(row, raw) if observation_count(row, raw) is not None else "",
                "observation_density_per_5min_window": round(density, 4) if density is not None else "",
                "window_resolution_status": status,
                "recommended_label_window_method": window_method(row, raw),
            }
        )
    return output


def parse_json_cell(value: str) -> list[str]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
        return [str(item) for item in parsed]
    except json.JSONDecodeError:
        return []


def canonical_incident(group_rows: list[dict[str, str]]) -> str:
    return sorted(group_rows, key=lambda row: (-len(prefix_set(row)), -len(asn_set(row)), minutes(row), row["incident_uid"]))[0]["incident_uid"]


def classify_group(group: dict[str, str], rows_by_uid: dict[str, dict[str, str]], pair_rows: list[dict[str, str]]) -> dict[str, object]:
    uids = parse_json_cell(group["incident_uids"])
    group_rows = [rows_by_uid[uid] for uid in uids if uid in rows_by_uid]
    categories = sorted({row["category"] for row in group_rows})
    partitions = sorted({row["partition"] for row in group_rows})
    relevant_pairs = [row for row in pair_rows if row["incident_uid_1"] in uids and row["incident_uid_2"] in uids]
    high_pairs = [row for row in relevant_pairs if row["duplicate_triage"] == "HIGH_DUPLICATE_CONFIDENCE"]
    possible_pairs = [row for row in relevant_pairs if row["duplicate_triage"] == "POSSIBLE_DUPLICATE"]
    max_temporal = max([float(row["percentage_temporal_overlap"]) for row in relevant_pairs] or [0])
    exact_prefix_pairs = sum(1 for row in relevant_pairs if row["exact_same_prefix"] == "True")
    shared_asn_pairs = sum(1 for row in relevant_pairs if int(row["affected_asn_overlap_count"] or 0) > 0 or row["same_primary_asn"] == "True")
    same_country_pairs = sum(1 for row in relevant_pairs if row["same_country_network"] == "True")
    mixed_categories = len(categories) > 1

    if high_pairs and not mixed_categories and (exact_prefix_pairs or shared_asn_pairs or same_country_pairs):
        classification = "TRUE_DUPLICATE"
        action = "collapse_duplicate_records_in_future_roster_v2_after_manual_confirmation"
    elif mixed_categories or (len(group_rows) > 2 and (shared_asn_pairs or exact_prefix_pairs or max_temporal >= 50)):
        classification = "SAME_BROAD_EVENT_DIFFERENT_COMPONENT"
        action = "keep_or_model_as_related_components; do_not_collapse_without_domain_review"
    elif not high_pairs and possible_pairs:
        classification = "UNRESOLVED"
        action = "manual_review_required_before_roster_v2"
    else:
        classification = "DISTINCT_INCIDENTS"
        action = "keep_as_separate_incidents"
    evidence = {
        "incident_count": len(group_rows),
        "categories": categories,
        "partitions": partitions,
        "high_confidence_pair_count": len(high_pairs),
        "possible_pair_count": len(possible_pairs),
        "max_temporal_overlap_pct": max_temporal,
        "exact_prefix_pair_count": exact_prefix_pairs,
        "shared_asn_pair_count": shared_asn_pairs,
        "same_country_pair_count": same_country_pairs,
    }
    return {
        "group_id": group["duplicate_group_id"],
        "incident_uids": json.dumps(uids),
        "categories": json.dumps(categories),
        "partitions": json.dumps(partitions),
        "classification": classification,
        "evidence": json.dumps(evidence, sort_keys=True),
        "recommended_canonical_incident": canonical_incident(group_rows) if group_rows else "",
        "recommended_action": action,
    }


def duplicate_resolution(rows: list[dict[str, str]], review_dir: Path = REVIEW_DIR) -> list[dict[str, object]]:
    rows_by_uid = {row["incident_uid"]: row for row in rows}
    groups = load_csv(review_dir / "duplicate_candidate_groups.csv")
    pairs = load_csv(review_dir / "duplicate_pair_triage.csv")
    return [classify_group(group, rows_by_uid, pairs) for group in groups]


def summary_rows(window_rows: list[dict[str, object]], duplicate_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    window_counts = Counter(row["window_resolution_status"] for row in window_rows)
    group_counts = Counter(row["classification"] for row in duplicate_rows)
    removed_if_collapsed = 0
    removed_by_class: Counter[str] = Counter()
    for row in duplicate_rows:
        if row["classification"] != "TRUE_DUPLICATE":
            continue
        uids = parse_json_cell(str(row["incident_uids"]))
        if len(uids) > 1:
            removed_if_collapsed += len(uids) - 1
            for uid in sorted(uids):
                if uid != row["recommended_canonical_incident"]:
                    removed_by_class[uid.split(":", 1)[0]] += 1
    return [
        {"metric": "safe_current_timestamps", "value": window_counts["SAFE_CURRENT_TIMESTAMPS"], "notes": "usable with current timestamps under current diagnostic rule"},
        {"metric": "need_redefined_label_interval", "value": window_counts["REDEFINE_LABEL_WINDOW"], "notes": "mostly long/sparse Hijack and Leak intervals"},
        {"metric": "undefensible_window", "value": window_counts["UNDEFENSIBLE_WINDOW"], "notes": "missing or invalid duration/timestamp evidence"},
        {"metric": "true_duplicate_groups", "value": group_counts["TRUE_DUPLICATE"], "notes": "recommend collapse only in roster v2 after manual confirmation"},
        {"metric": "same_broad_event_component_groups", "value": group_counts["SAME_BROAD_EVENT_DIFFERENT_COMPONENT"], "notes": "related broader event, not automatically duplicate"},
        {"metric": "distinct_incident_groups", "value": group_counts["DISTINCT_INCIDENTS"], "notes": "candidate group appears separable"},
        {"metric": "unresolved_duplicate_groups", "value": group_counts["UNRESOLVED"], "notes": "manual evidence needed"},
        {"metric": "incidents_removed_if_true_duplicates_collapsed", "value": removed_if_collapsed, "notes": json.dumps(dict(removed_by_class), sort_keys=True)},
    ]


def run_resolution(partition_dir: Path = PARTITION_DIR, review_dir: Path = REVIEW_DIR) -> dict[str, object]:
    rows = load_partition_rows(partition_dir)
    raw_index = load_raw_index()
    timestamp_rows = timestamp_semantics_resolution(rows, raw_index)
    window_rows = incident_window_recommendations(rows, raw_index)
    duplicate_rows = duplicate_resolution(rows, review_dir)
    summaries = summary_rows(window_rows, duplicate_rows)

    write_csv(
        review_dir / "timestamp_semantics_resolution.csv",
        timestamp_rows,
        ["category", "field_start", "field_end", "semantic_meaning", "continuous_event_window_yes_no", "safe_for_labeling_yes_no", "recommended_label_window_method", "evidence"],
    )
    write_csv(
        review_dir / "incident_window_resolution_recommendations.csv",
        window_rows,
        ["incident_uid", "category", "partition", "duration_minutes", "observation_count", "observation_density_per_5min_window", "window_resolution_status", "recommended_label_window_method"],
    )
    write_csv(
        review_dir / "duplicate_resolution_recommendations.csv",
        duplicate_rows,
        ["group_id", "incident_uids", "categories", "partitions", "classification", "evidence", "recommended_canonical_incident", "recommended_action"],
    )
    write_csv(
        review_dir / "roster_quality_resolution_summary.csv",
        summaries,
        ["metric", "value", "notes"],
    )
    return {
        "timestamp_semantics_resolution": timestamp_rows,
        "incident_window_recommendations": window_rows,
        "duplicate_resolution_recommendations": duplicate_rows,
        "summary": summaries,
    }


def print_report(results: dict[str, object]) -> None:
    window_counts = Counter(row["window_resolution_status"] for row in results["incident_window_recommendations"])
    duplicate_counts = Counter(row["classification"] for row in results["duplicate_resolution_recommendations"])
    removed = next(row["value"] for row in results["summary"] if row["metric"] == "incidents_removed_if_true_duplicates_collapsed")
    print("Roster quality resolution complete")
    print("Window resolution:", dict(window_counts))
    print("Duplicate group resolution:", dict(duplicate_counts))
    print(f"Incidents removed if true duplicates collapsed: {removed}")
    print("Recommendation before roster v2: review true duplicates first, then define class-specific active-window rules for long Hijack/Leak intervals.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Resolve remaining roster-quality questions without changing frozen data.")
    parser.add_argument("--partition-dir", type=Path, default=PARTITION_DIR)
    parser.add_argument("--review-dir", type=Path, default=REVIEW_DIR)
    args = parser.parse_args()
    results = run_resolution(args.partition_dir, args.review_dir)
    print_report(results)


if __name__ == "__main__":
    main()
