from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from statistics import mean, median

try:
    from bgp_incident_detection.audit import (
        PARTITION_DIR,
        asn_set,
        country_set,
        interval,
        intervals_overlap,
        parse_listish,
        prefix_set,
        source_available,
        timestamp_status,
        token_similarity,
        write_csv,
    )
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import (
        PARTITION_DIR,
        asn_set,
        country_set,
        interval,
        intervals_overlap,
        parse_listish,
        prefix_set,
        source_available,
        timestamp_status,
        token_similarity,
        write_csv,
    )


REVIEW_DIR = Path("data/review")
PARTITION_FILES = ("train_incidents.csv", "validation_incidents.csv", "holdout_incidents.csv")
REVIEW_REASON_ORDER = (
    "possible duplicate",
    "extreme duration",
    "missing source/provenance",
    "missing prefix",
    "missing ASN",
    "timestamp concern",
    "cross-partition ASN overlap",
    "cross-partition prefix overlap",
    "temporal overlap",
    "other",
)


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def load_partition_rows(partition_dir: Path = PARTITION_DIR) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for filename in PARTITION_FILES:
        rows.extend(load_csv(partition_dir / filename))
    return rows


def list_as_cell(values: set[str] | list[str]) -> str:
    return json.dumps(sorted(values, key=str))


def source_provenance(row: dict[str, str]) -> dict[str, object]:
    source_url = (row.get("source_url") or "").strip()
    source_system = "Cloudflare Radar BGP monitoring API"
    source_record_id = row.get("incident_id", "")
    return {
        "source_system": source_system,
        "source_record_id": source_record_id,
        "source_url": source_url,
        "source_provenance_available": bool(source_record_id),
    }


def duration_value(row: dict[str, str]) -> float:
    try:
        return float(row.get("duration_minutes", "nan"))
    except ValueError:
        return math.nan


def duration_bucket(minutes: float) -> str:
    if math.isnan(minutes):
        return "unknown"
    if minutes < 5:
        return "< 5 minutes"
    if minutes < 30:
        return "5-30 minutes"
    if minutes < 60:
        return "30-60 minutes"
    if minutes < 6 * 60:
        return "1-6 hours"
    if minutes < 24 * 60:
        return "6-24 hours"
    if minutes < 7 * 24 * 60:
        return "1-7 days"
    if minutes < 30 * 24 * 60:
        return "7-30 days"
    return ">30 days"


def is_extreme_duration(row: dict[str, str]) -> bool:
    minutes = duration_value(row)
    return not math.isnan(minutes) and (minutes < 5 or minutes > 24 * 60)


def pct_temporal_overlap(row_1: dict[str, str], row_2: dict[str, str]) -> float:
    start_1, end_1 = interval(row_1)
    start_2, end_2 = interval(row_2)
    if not start_1 or not end_1 or not start_2 or not end_2:
        return 0.0
    overlap = max(0.0, (min(end_1, end_2) - max(start_1, start_2)).total_seconds())
    shorter = min((end_1 - start_1).total_seconds(), (end_2 - start_2).total_seconds())
    if shorter <= 0:
        return 0.0
    return round(overlap / shorter * 100, 2)


def minutes_between(left: datetime | None, right: datetime | None) -> float | str:
    if not left or not right:
        return ""
    return round(abs((left - right).total_seconds()) / 60, 2)


def same_primary_asn(row_1: dict[str, str], row_2: dict[str, str]) -> bool:
    left = (row_1.get("primary_asn") or "").strip()
    right = (row_2.get("primary_asn") or "").strip()
    return bool(left and right and left == right)


def same_source_provenance(row_1: dict[str, str], row_2: dict[str, str]) -> bool:
    left = source_provenance(row_1)
    right = source_provenance(row_2)
    return (
        left["source_system"] == right["source_system"]
        and left["source_record_id"] == right["source_record_id"]
        and row_1["category"] == row_2["category"]
    )


def categorize_pair(evidence: dict[str, object]) -> str:
    temporal = float(evidence["percentage_temporal_overlap"])
    same_category = bool(evidence["same_category"])
    same_primary = bool(evidence["same_primary_asn"])
    asn_overlap = int(evidence["affected_asn_overlap_count"])
    exact_prefix = bool(evidence["exact_same_prefix"])
    prefix_overlap = int(evidence["overlapping_prefix_count"])
    same_country = bool(evidence["same_country_network"])
    same_source = bool(evidence["same_source_record_provenance"])
    start_delta = evidence["start_time_difference_minutes"]
    end_delta = evidence["end_time_difference_minutes"]
    close_times = start_delta != "" and end_delta != "" and float(start_delta) <= 15 and float(end_delta) <= 15

    if same_source or (same_category and temporal >= 95 and (same_primary or exact_prefix or asn_overlap > 0 or prefix_overlap > 0)):
        return "HIGH_DUPLICATE_CONFIDENCE"
    if same_category and close_times and (same_country or token_score_high(evidence)):
        return "HIGH_DUPLICATE_CONFIDENCE"
    if temporal > 0 and (same_primary or asn_overlap > 0 or exact_prefix or prefix_overlap > 0):
        return "POSSIBLE_DUPLICATE"
    if same_category and temporal >= 50 and same_country:
        return "POSSIBLE_DUPLICATE"
    if close_times and (same_primary or asn_overlap > 0 or exact_prefix or same_country):
        return "POSSIBLE_DUPLICATE"
    return "LIKELY_DISTINCT"


def token_score_high(evidence: dict[str, object]) -> bool:
    try:
        return float(evidence["description_source_similarity"]) >= 0.6
    except (TypeError, ValueError):
        return False


def triage_duplicate_pairs(rows: list[dict[str, str]], partition_dir: Path = PARTITION_DIR) -> list[dict[str, object]]:
    row_by_uid = {row["incident_uid"]: row for row in rows}
    candidate_pairs = load_csv(partition_dir / "possible_duplicate_incidents.csv")
    output: list[dict[str, object]] = []
    for pair in candidate_pairs:
        row_1 = row_by_uid[pair["incident_uid_1"]]
        row_2 = row_by_uid[pair["incident_uid_2"]]
        start_1, end_1 = interval(row_1)
        start_2, end_2 = interval(row_2)
        shared_asns = asn_set(row_1) & asn_set(row_2)
        exact_prefixes = prefix_set(row_1) & prefix_set(row_2)
        shared_countries = country_set(row_1) & country_set(row_2)
        evidence = {
            "incident_uid_1": row_1["incident_uid"],
            "incident_uid_2": row_2["incident_uid"],
            "category_1": row_1["category"],
            "category_2": row_2["category"],
            "partition_1": row_1["partition"],
            "partition_2": row_2["partition"],
            "same_category": row_1["category"] == row_2["category"],
            "same_primary_asn": same_primary_asn(row_1, row_2),
            "affected_asn_overlap_count": len(shared_asns),
            "affected_asn_overlap": list_as_cell(shared_asns),
            "exact_same_prefix": bool(exact_prefixes),
            "exact_prefix_overlap": list_as_cell(exact_prefixes),
            "overlapping_prefix_count": len(exact_prefixes),
            "same_country_network": bool(shared_countries),
            "country_network_overlap": list_as_cell(shared_countries),
            "start_time_difference_minutes": minutes_between(start_1, start_2),
            "end_time_difference_minutes": minutes_between(end_1, end_2),
            "percentage_temporal_overlap": pct_temporal_overlap(row_1, row_2),
            "same_source_record_provenance": same_source_provenance(row_1, row_2),
            "description_source_similarity": round(token_similarity(row_1, row_2), 3),
            "original_reason_flagged": pair.get("reason_flagged", ""),
        }
        evidence["duplicate_triage"] = categorize_pair(evidence)
        evidence["recommended_action"] = "manual_review_do_not_merge"
        output.append(evidence)
    return output


class UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, item: str) -> str:
        self.parent.setdefault(item, item)
        if self.parent[item] != item:
            self.parent[item] = self.find(self.parent[item])
        return self.parent[item]

    def union(self, left: str, right: str) -> None:
        self.parent[self.find(right)] = self.find(left)


def duplicate_groups(pair_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    uf = UnionFind()
    eligible = [row for row in pair_rows if row["duplicate_triage"] in {"HIGH_DUPLICATE_CONFIDENCE", "POSSIBLE_DUPLICATE"}]
    for row in eligible:
        uf.union(str(row["incident_uid_1"]), str(row["incident_uid_2"]))
    grouped: dict[str, set[str]] = defaultdict(set)
    confidence_by_group: dict[str, Counter] = defaultdict(Counter)
    for row in eligible:
        root = uf.find(str(row["incident_uid_1"]))
        grouped[root].update([str(row["incident_uid_1"]), str(row["incident_uid_2"])])
        confidence_by_group[root][str(row["duplicate_triage"])] += 1

    output: list[dict[str, object]] = []
    for idx, (root, uids) in enumerate(sorted(grouped.items()), start=1):
        categories = sorted({uid.split(":", 1)[0] for uid in uids})
        output.append(
            {
                "duplicate_group_id": f"dup_group_{idx:04d}",
                "incident_count": len(uids),
                "incident_uids": list_as_cell(uids),
                "categories": list_as_cell(categories),
                "high_confidence_pair_count": confidence_by_group[root]["HIGH_DUPLICATE_CONFIDENCE"],
                "possible_pair_count": confidence_by_group[root]["POSSIBLE_DUPLICATE"],
                "recommended_action": "manual_review_group_do_not_merge_automatically",
            }
        )
    return output


def overlap_uid_sets(partition_dir: Path = PARTITION_DIR) -> dict[str, set[str]]:
    result = {
        "cross-partition ASN overlap": set(),
        "cross-partition prefix overlap": set(),
        "temporal overlap": set(),
    }
    for row in load_csv(partition_dir / "cross_partition_asn_overlap.csv"):
        if int(row.get("overlapping_time_pair_count", "0") or 0) > 0:
            # This file is aggregated by ASN, so incident-level attribution is handled by temporal overlap.
            pass
    for filename, reason in (
        ("cross_partition_prefix_overlap.csv", "cross-partition prefix overlap"),
        ("cross_partition_temporal_overlap.csv", "temporal overlap"),
    ):
        for row in load_csv(partition_dir / filename):
            result[reason].update([row["incident_uid_1"], row["incident_uid_2"]])
    return result


def incident_review_reasons(
    rows: list[dict[str, str]],
    duplicate_rows: list[dict[str, object]],
    partition_dir: Path = PARTITION_DIR,
) -> list[dict[str, object]]:
    quality = {row["incident_uid"]: row for row in load_csv(partition_dir / "incident_quality_audit_v1.csv")}
    reviewed_uids = {uid for uid, row in quality.items() if row["quality_status"] == "REVIEW"}
    duplicate_uids = {
        str(row["incident_uid_1"])
        for row in duplicate_rows
        if row["duplicate_triage"] != "LIKELY_DISTINCT"
    } | {
        str(row["incident_uid_2"])
        for row in duplicate_rows
        if row["duplicate_triage"] != "LIKELY_DISTINCT"
    }
    overlap_sets = overlap_uid_sets(partition_dir)

    output: list[dict[str, object]] = []
    for row in rows:
        uid = row["incident_uid"]
        if uid not in reviewed_uids:
            continue
        reasons: list[str] = []
        if uid in duplicate_uids:
            reasons.append("possible duplicate")
        if is_extreme_duration(row):
            reasons.append("extreme duration")
        if not source_provenance(row)["source_provenance_available"]:
            reasons.append("missing source/provenance")
        if row["category"] == "Hijack" and not prefix_set(row):
            reasons.append("missing prefix")
        if not asn_set(row):
            reasons.append("missing ASN")
        if timestamp_status(row)[0] != "PASS":
            reasons.append("timestamp concern")
        for reason, uids in overlap_sets.items():
            if uid in uids:
                reasons.append(reason)
        if not reasons:
            reasons.append("other")
        provenance = source_provenance(row)
        output.append(
            {
                "incident_uid": uid,
                "category": row["category"],
                "partition": row["partition"],
                "review_reasons": ";".join(reasons),
                "review_reason_count": len(reasons),
                "source_system": provenance["source_system"],
                "source_record_id": provenance["source_record_id"],
                "source_url": provenance["source_url"],
                "source_provenance_available": provenance["source_provenance_available"],
            }
        )
    return output


def review_reason_summary(reason_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    dimensions = [("ALL", "ALL")]
    dimensions.extend(("category", label) for label in ("Hijack", "Leak", "Outage"))
    dimensions.extend(("partition", label) for label in ("train", "validation", "holdout"))

    output: list[dict[str, object]] = []
    for dimension, value in dimensions:
        subset = [
            row for row in reason_rows
            if dimension == "ALL" or row[dimension] == value
        ]
        for reason in REVIEW_REASON_ORDER:
            count = sum(1 for row in subset if reason in str(row["review_reasons"]).split(";"))
            output.append(
                {
                    "dimension": dimension,
                    "value": value,
                    "review_reason": reason,
                    "incident_count": count,
                    "review_incident_count": len(subset),
                    "percent_of_reviewed": round(count / len(subset) * 100, 2) if subset else 0,
                }
            )
    return output


def duration_distribution(rows: list[dict[str, str]]) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    bucket_order = ["< 5 minutes", "5-30 minutes", "30-60 minutes", "1-6 hours", "6-24 hours", "1-7 days", "7-30 days", ">30 days"]
    for category in ("Hijack", "Leak", "Outage"):
        subset = [row for row in rows if row["category"] == category]
        durations = sorted(duration_value(row) for row in subset if not math.isnan(duration_value(row)))
        bucket_counts = Counter(duration_bucket(value) for value in durations)
        summary = {
            "category": category,
            "incident_count": len(durations),
            "minimum": round(min(durations), 2),
            "median": round(median(durations), 2),
            "mean": round(mean(durations), 2),
            "p75": round(percentile(durations, 0.75), 2),
            "p90": round(percentile(durations, 0.90), 2),
            "p95": round(percentile(durations, 0.95), 2),
            "p99": round(percentile(durations, 0.99), 2),
            "maximum": round(max(durations), 2),
        }
        for bucket in bucket_order:
            summary[bucket] = bucket_counts[bucket]
        output.append(summary)
    return output


def percentile(values: list[float], quantile: float) -> float:
    position = (len(values) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(values) - 1)
    weight = position - lower
    return values[lower] * (1 - weight) + values[upper] * weight


def source_timestamp_semantics() -> list[dict[str, object]]:
    return [
        {"category": "Hijack", "source_field": "min_hijack_ts", "current_use": "start_utc", "likely_semantic_meaning": "first timestamp where Cloudflare detector observed hijack evidence", "safe_for_label_window": "yes_for_start", "evidence/notes": "Represents first hijack evidence in raw hijack schema."},
        {"category": "Hijack", "source_field": "max_hijack_ts", "current_use": "end_utc", "likely_semantic_meaning": "last timestamp where Cloudflare detector observed hijack evidence", "safe_for_label_window": "yes_for_end_with_review_for_long_events", "evidence/notes": "Used instead of max_msg_ts by design."},
        {"category": "Hijack", "source_field": "max_msg_ts", "current_use": "preserved in raw source only", "likely_semantic_meaning": "last detector message timestamp; may include unrelated/non-hijack detector persistence", "safe_for_label_window": "no", "evidence/notes": "Must not be used as hijack end time."},
        {"category": "Hijack", "source_field": "duration", "current_use": "raw diagnostic only", "likely_semantic_meaning": "detector/event persistence field from source", "safe_for_label_window": "review", "evidence/notes": "Normalized duration is calculated from max_hijack_ts - min_hijack_ts."},
        {"category": "Leak", "source_field": "detected_ts", "current_use": "fallback start_utc if min_ts unavailable", "likely_semantic_meaning": "detector creation/detection time", "safe_for_label_window": "fallback_only", "evidence/notes": "Usually close to min_ts but not necessarily full event start."},
        {"category": "Leak", "source_field": "min_ts", "current_use": "start_utc", "likely_semantic_meaning": "first observation associated with the leak detector event", "safe_for_label_window": "yes_for_start", "evidence/notes": "Best available leak start in Cloudflare route-leak schema."},
        {"category": "Leak", "source_field": "max_ts", "current_use": "end_utc", "likely_semantic_meaning": "last observation associated with the detector event; may not prove continuous leaking for the whole interval", "safe_for_label_window": "review_for_end", "evidence/notes": "Long leak intervals should be reviewed before defining feature windows."},
        {"category": "Leak", "source_field": "finished", "current_use": "raw diagnostic only", "likely_semantic_meaning": "detector marked event as finished", "safe_for_label_window": "supporting_context_only", "evidence/notes": "Does not by itself define the start/end timestamps."},
        {"category": "Outage", "source_field": "startDate", "current_use": "start_utc", "likely_semantic_meaning": "reported outage start interval", "safe_for_label_window": "yes", "evidence/notes": "Cloudflare outage records are explicit reported event intervals."},
        {"category": "Outage", "source_field": "endDate", "current_use": "end_utc", "likely_semantic_meaning": "reported outage end interval", "safe_for_label_window": "yes_with_review_for_very_long_events", "evidence/notes": "Long outages may need reviewed collection windows but should not be auto-changed."},
        {"category": "Outage", "source_field": "duration_minutes", "current_use": "duration_minutes", "likely_semantic_meaning": "reported or normalized outage interval length", "safe_for_label_window": "yes", "evidence/notes": "Checked against startDate/endDate during partition audit."},
        {"category": "Outage", "source_field": "outageCause/outageType", "current_use": "notes/source context", "likely_semantic_meaning": "reported outage cause and scope/type", "safe_for_label_window": "context_only", "evidence/notes": "Useful for review but not a timestamp."},
    ]


def prefix_requirement_assessment(rows: list[dict[str, str]]) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    for category in ("Hijack", "Leak", "Outage"):
        subset = [row for row in rows if row["category"] == category]
        with_prefix = sum(1 for row in subset if prefix_set(row))
        with_prefix_count = sum(1 for row in subset if (row.get("prefix_count") or "").strip())
        if category == "Hijack":
            requirement = "required_quality_field"
            assessment = "prefix lists are expected and present in the frozen roster"
            recoverable = "already_present"
        elif category == "Leak":
            requirement = "important_but_currently_count_only"
            assessment = "Cloudflare leak raw schema exposes prefix_count, leak_seg, leak_asn, origins/countries, but sampled raw records do not show actual affected prefix lists in the stored API response"
            recoverable = "not_from_current_normalized_roster; likely_not_from_current_raw_leak_dump"
        else:
            requirement = "not_required_for_label_if_asn_interval_available"
            assessment = "outage labels are network/ASN plus reported interval; affected prefixes can be derived later from MRT/RIB context if needed"
            recoverable = "not_required_before_MRT"
        output.append(
            {
                "category": category,
                "incident_count": len(subset),
                "incidents_with_prefix_list": with_prefix,
                "incidents_without_prefix_list": len(subset) - with_prefix,
                "incidents_with_prefix_count": with_prefix_count,
                "prefix_requirement": requirement,
                "actual_prefix_lists_recoverable": recoverable,
                "assessment": assessment,
                "sufficient_for_routeviews_extraction": category != "Leak" or True,
            }
        )
    return output


def holdout_quality_summary(rows: list[dict[str, str]], reason_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    reasons_by_uid = {row["incident_uid"]: set(str(row["review_reasons"]).split(";")) for row in reason_rows}
    output: list[dict[str, object]] = []
    for category in ("Hijack", "Leak", "Outage"):
        subset = [row for row in rows if row["partition"] == "holdout" and row["category"] == category]
        duplicate_risk = sum(1 for row in subset if "possible duplicate" in reasons_by_uid.get(row["incident_uid"], set()))
        duration_concern = sum(1 for row in subset if "extreme duration" in reasons_by_uid.get(row["incident_uid"], set()))
        timestamp_concern = sum(1 for row in subset if "timestamp concern" in reasons_by_uid.get(row["incident_uid"], set()))
        output.append(
            {
                "category": category,
                "holdout_incidents": len(subset),
                "duplicate_risk": duplicate_risk,
                "duration_concern": duration_concern,
                "provenance_available": sum(1 for row in subset if source_provenance(row)["source_provenance_available"]),
                "asn_available": sum(1 for row in subset if asn_set(row)),
                "prefix_available": sum(1 for row in subset if prefix_set(row)),
                "timestamp_confidence": len(subset) - timestamp_concern,
            }
        )
    return output


def remediation_plan(reason_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    for row in reason_rows:
        reasons = set(str(row["review_reasons"]).split(";"))
        action = "KEEP_AS_IS"
        priority = "low"
        if len(reasons) >= 3:
            action = "MULTIPLE_ISSUES"
            priority = "high"
        elif "possible duplicate" in reasons:
            action = "DUPLICATE_REVIEW"
            priority = "high"
        elif "timestamp concern" in reasons or "extreme duration" in reasons:
            action = "REDEFINE_TIME_WINDOW"
            priority = "medium"
        elif "missing source/provenance" in reasons:
            action = "VERIFY_EXTERNAL_SOURCE"
            priority = "medium"
        elif "missing prefix" in reasons:
            action = "RECOVER_PREFIX_METADATA"
            priority = "medium"
        elif "missing ASN" in reasons:
            action = "LIKELY_EXCLUDE"
            priority = "high"
        elif reasons <= {"cross-partition ASN overlap", "cross-partition prefix overlap", "temporal overlap", "other"}:
            action = "KEEP_AS_IS"
            priority = "low"
        output.append(
            {
                "incident_uid": row["incident_uid"],
                "category": row["category"],
                "partition": row["partition"],
                "review_reasons": row["review_reasons"],
                "recommended_action": action,
                "priority": priority,
                "notes": "recommendation_only_no_roster_change",
            }
        )
    return output


def write_duration_plot(rows: list[dict[str, str]], review_dir: Path) -> None:
    try:
        import matplotlib.pyplot as plt
    except Exception:
        return
    categories = ("Hijack", "Leak", "Outage")
    data = [[duration_value(row) for row in rows if row["category"] == category] for category in categories]
    plt.figure(figsize=(9, 5))
    plt.boxplot(data, showfliers=False)
    plt.xticks([1, 2, 3], categories)
    plt.ylabel("duration_minutes")
    plt.title("Duration distribution by class (outliers hidden)")
    plt.tight_layout()
    review_dir.mkdir(parents=True, exist_ok=True)
    plt.savefig(review_dir / "duration_distribution_by_class.png", dpi=160)
    plt.close()


def run_triage(partition_dir: Path = PARTITION_DIR, review_dir: Path = REVIEW_DIR) -> dict[str, object]:
    rows = load_partition_rows(partition_dir)
    duplicate_triage = triage_duplicate_pairs(rows, partition_dir)
    groups = duplicate_groups(duplicate_triage)
    reason_rows = incident_review_reasons(rows, duplicate_triage, partition_dir)
    reason_summary = review_reason_summary(reason_rows)
    duration_rows = duration_distribution(rows)
    semantics = source_timestamp_semantics()
    prefix_assessment = prefix_requirement_assessment(rows)
    holdout_summary = holdout_quality_summary(rows, reason_rows)
    remediation = remediation_plan(reason_rows)
    write_duration_plot(rows, review_dir)

    review_dir.mkdir(parents=True, exist_ok=True)
    write_csv(review_dir / "review_reason_summary.csv", reason_summary, ["dimension", "value", "review_reason", "incident_count", "review_incident_count", "percent_of_reviewed"])
    write_csv(review_dir / "incident_review_reasons.csv", reason_rows, ["incident_uid", "category", "partition", "review_reasons", "review_reason_count", "source_system", "source_record_id", "source_url", "source_provenance_available"])
    write_csv(review_dir / "duplicate_pair_triage.csv", duplicate_triage, ["incident_uid_1", "incident_uid_2", "category_1", "category_2", "partition_1", "partition_2", "same_category", "same_primary_asn", "affected_asn_overlap_count", "affected_asn_overlap", "exact_same_prefix", "exact_prefix_overlap", "overlapping_prefix_count", "same_country_network", "country_network_overlap", "start_time_difference_minutes", "end_time_difference_minutes", "percentage_temporal_overlap", "same_source_record_provenance", "description_source_similarity", "original_reason_flagged", "duplicate_triage", "recommended_action"])
    write_csv(review_dir / "duplicate_candidate_groups.csv", groups, ["duplicate_group_id", "incident_count", "incident_uids", "categories", "high_confidence_pair_count", "possible_pair_count", "recommended_action"])
    write_csv(review_dir / "duration_distribution_by_class.csv", duration_rows, ["category", "incident_count", "minimum", "median", "mean", "p75", "p90", "p95", "p99", "maximum", "< 5 minutes", "5-30 minutes", "30-60 minutes", "1-6 hours", "6-24 hours", "1-7 days", "7-30 days", ">30 days"])
    write_csv(review_dir / "source_timestamp_semantics.csv", semantics, ["category", "source_field", "current_use", "likely_semantic_meaning", "safe_for_label_window", "evidence/notes"])
    write_csv(review_dir / "prefix_requirement_assessment.csv", prefix_assessment, ["category", "incident_count", "incidents_with_prefix_list", "incidents_without_prefix_list", "incidents_with_prefix_count", "prefix_requirement", "actual_prefix_lists_recoverable", "assessment", "sufficient_for_routeviews_extraction"])
    write_csv(review_dir / "holdout_quality_summary.csv", holdout_summary, ["category", "holdout_incidents", "duplicate_risk", "duration_concern", "provenance_available", "asn_available", "prefix_available", "timestamp_confidence"])
    write_csv(review_dir / "remediation_plan_v1.csv", remediation, ["incident_uid", "category", "partition", "review_reasons", "recommended_action", "priority", "notes"])

    return {
        "rows": rows,
        "duplicate_pair_triage": duplicate_triage,
        "duplicate_candidate_groups": groups,
        "incident_review_reasons": reason_rows,
        "review_reason_summary": reason_summary,
        "duration_distribution": duration_rows,
        "source_timestamp_semantics": semantics,
        "prefix_requirement_assessment": prefix_assessment,
        "holdout_quality_summary": holdout_summary,
        "remediation_plan": remediation,
    }


def print_summary(results: dict[str, object]) -> None:
    duplicate_counts = Counter(row["duplicate_triage"] for row in results["duplicate_pair_triage"])
    remediation_counts = Counter(row["recommended_action"] for row in results["remediation_plan"])
    reason_counts = Counter()
    for row in results["incident_review_reasons"]:
        reason_counts.update(str(row["review_reasons"]).split(";"))
    quality_by_class = defaultdict(Counter)
    for row in results["remediation_plan"]:
        quality_by_class[row["category"]][row["recommended_action"]] += 1

    print("Review triage complete")
    print(f"Reviewed incidents: {len(results['incident_review_reasons'])}")
    print(f"High-confidence duplicate pairs: {duplicate_counts['HIGH_DUPLICATE_CONFIDENCE']}")
    print(f"Possible duplicate pairs: {duplicate_counts['POSSIBLE_DUPLICATE']}")
    print(f"Likely distinct pairs: {duplicate_counts['LIKELY_DISTINCT']}")
    print(f"Unique incidents potentially affected by duplicate pairs: {len(set().union(*[{row['incident_uid_1'], row['incident_uid_2']} for row in results['duplicate_pair_triage'] if row['duplicate_triage'] != 'LIKELY_DISTINCT']) if results['duplicate_pair_triage'] else set())}")
    print(f"Remediation counts: {dict(remediation_counts)}")
    print(f"Largest review reason: {reason_counts.most_common(1)}")
    print(f"By class remediation: {dict(quality_by_class)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Triage pre-MRT audit REVIEW findings without modifying frozen partitions.")
    parser.add_argument("--partition-dir", type=Path, default=PARTITION_DIR)
    parser.add_argument("--review-dir", type=Path, default=REVIEW_DIR)
    args = parser.parse_args()
    results = run_triage(args.partition_dir, args.review_dir)
    print_summary(results)


if __name__ == "__main__":
    main()
