from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter
from datetime import datetime
from pathlib import Path

try:
    from bgp_incident_detection.audit import asn_set, parse_utc, prefix_set, source_available, timestamp_status, write_csv
    from bgp_incident_detection.review_triage import load_csv, load_partition_rows, source_provenance
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import asn_set, parse_utc, prefix_set, source_available, timestamp_status, write_csv
    from src.bgp_incident_detection.review_triage import load_csv, load_partition_rows, source_provenance


PARTITION_DIR = Path("data/partitions")
REVIEW_DIR = Path("data/review")
ROSTER_V2_DIR = Path("data/roster_v2")
UNSAMPLED_POOL = Path("cloudflare_incidents/training_ready_bgp_incident_roster_all_available_to_2026-01.csv")
TARGET_PER_CLASS = 473
ROSTER_VERSION = "v2"
CLASS_LABELS = ("Hijack", "Leak", "Outage")


def incident_uid(row: dict[str, str]) -> str:
    return row.get("incident_uid") or f"{row.get('category', '')}:{row.get('incident_id', '')}"


def parse_json_cell(value: str) -> list[str]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
        return [str(item) for item in parsed]
    except json.JSONDecodeError:
        return []


def duration_minutes(row: dict[str, str]) -> float:
    try:
        return float(row.get("duration_minutes", "nan"))
    except ValueError:
        return math.nan


def quality_value(row: dict[str, str]) -> float:
    try:
        return float(row.get("quality_score", "0") or 0)
    except ValueError:
        return 0.0


def confidence_value(row: dict[str, str]) -> float:
    try:
        return float(row.get("confidence_score", "0") or 0)
    except ValueError:
        return 0.0


def count_value(row: dict[str, str], field: str) -> float:
    try:
        return float(row.get(field, "0") or 0)
    except ValueError:
        return 0.0


def timestamp_ok(row: dict[str, str]) -> bool:
    return timestamp_status(row)[0] == "PASS"


def provenance_available(row: dict[str, str]) -> bool:
    return bool(source_provenance(row)["source_provenance_available"])


def canonical_score(row: dict[str, str]) -> tuple[float, float, float, float, float, float, float, str]:
    return (
        1.0 if provenance_available(row) else 0.0,
        1.0 if source_available(row) else 0.0,
        1.0 if asn_set(row) else 0.0,
        1.0 if prefix_set(row) else 0.0,
        1.0 if timestamp_ok(row) else 0.0,
        quality_value(row) + confidence_value(row),
        count_value(row, "prefix_count") + count_value(row, "peer_count"),
        incident_uid(row),
    )


def choose_canonical(group_rows: list[dict[str, str]]) -> dict[str, str]:
    return sorted(group_rows, key=canonical_score, reverse=True)[0]


def true_duplicate_groups(review_dir: Path = REVIEW_DIR) -> list[dict[str, str]]:
    return [
        row
        for row in load_csv(review_dir / "duplicate_resolution_recommendations.csv")
        if row["classification"] == "TRUE_DUPLICATE"
    ]


def duplicate_canonicalization_plan(
    rows_by_uid: dict[str, dict[str, str]],
    groups: list[dict[str, str]],
) -> tuple[list[dict[str, object]], set[str]]:
    output: list[dict[str, object]] = []
    excluded: set[str] = set()
    for group in groups:
        uids = parse_json_cell(group["incident_uids"])
        group_rows = [rows_by_uid[uid] for uid in uids if uid in rows_by_uid]
        canonical = choose_canonical(group_rows)
        duplicate_uids = [uid for uid in uids if uid != incident_uid(canonical)]
        excluded.update(duplicate_uids)
        output.append(
            {
                "group_id": group["group_id"],
                "canonical_incident_uid": incident_uid(canonical),
                "duplicate_incident_uids": json.dumps(duplicate_uids),
                "category": canonical["category"],
                "reason_selected": (
                    "selected by deterministic quality score: provenance, source URL, ASN/prefix completeness, "
                    "timestamp validity, confidence/quality metadata, and visibility counts"
                ),
                "records_to_exclude_from_v2": json.dumps(duplicate_uids),
            }
        )
    return output, excluded


def normalize_candidate_row(row: dict[str, str]) -> dict[str, str]:
    normalized = dict(row)
    normalized["incident_uid"] = incident_uid(normalized)
    return normalized


def candidate_score(row: dict[str, str]) -> tuple[float, float, float, float, float, float, float, str]:
    duration = duration_minutes(row)
    if math.isnan(duration):
        duration = 0.0
    # Favor useful but not pathological examples; active-window policy will handle very long spans later.
    duration_score = min(duration, 7 * 24 * 60) / (7 * 24 * 60)
    return (
        1.0 if timestamp_ok(row) else 0.0,
        1.0 if asn_set(row) else 0.0,
        1.0 if provenance_available(row) else 0.0,
        1.0 if (row["category"] != "Hijack" or prefix_set(row)) else 0.0,
        confidence_value(row),
        count_value(row, "prefix_count") + count_value(row, "peer_count"),
        duration_score,
        incident_uid(row),
    )


def candidate_stratum(row: dict[str, str]) -> tuple[str, str, str, str]:
    start = row.get("start_utc", "")
    try:
        year = str(parse_utc(start).year) if start else "unknown_year"
    except ValueError:
        year = "unknown_year"
    asn_bucket = "asn_present" if asn_set(row) else "asn_missing"
    country = (row.get("countries", "") or "unknown_country")[:24]
    duration = duration_minutes(row)
    if math.isnan(duration):
        duration_bucket = "duration_unknown"
    elif duration <= 360:
        duration_bucket = "duration_short"
    elif duration <= 1440:
        duration_bucket = "duration_medium"
    else:
        duration_bucket = "duration_long"
    return year, asn_bucket, country, duration_bucket


def stream_candidates(path: Path = UNSAMPLED_POOL) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        return [normalize_candidate_row(row) for row in reader]


def select_replacements(
    v2_seed_rows: list[dict[str, str]],
    excluded_duplicate_uids: set[str],
    groups: list[dict[str, str]],
    pool_path: Path = UNSAMPLED_POOL,
) -> tuple[list[dict[str, str]], dict[str, int], dict[str, int]]:
    represented = {incident_uid(row) for row in v2_seed_rows}
    known_group_uids = set()
    for group in groups:
        known_group_uids.update(parse_json_cell(group["incident_uids"]))
    counts = Counter(row["category"] for row in v2_seed_rows)
    needed = {category: TARGET_PER_CLASS - counts[category] for category in CLASS_LABELS}
    candidates_by_category: dict[str, list[dict[str, str]]] = {category: [] for category in CLASS_LABELS}
    for row in stream_candidates(pool_path):
        uid = incident_uid(row)
        category = row.get("category", "")
        if category not in candidates_by_category:
            continue
        if uid in represented or uid in excluded_duplicate_uids or uid in known_group_uids:
            continue
        if not timestamp_ok(row) or not asn_set(row):
            continue
        if category == "Hijack" and not prefix_set(row):
            continue
        candidates_by_category[category].append(row)

    replacements: list[dict[str, str]] = []
    found: dict[str, int] = {}
    for category in CLASS_LABELS:
        wanted = needed[category]
        if wanted <= 0:
            found[category] = 0
            continue
        sorted_candidates = sorted(
            candidates_by_category[category],
            key=lambda row: (candidate_stratum(row), candidate_score(row)),
            reverse=True,
        )
        selected = sorted(sorted_candidates[:wanted], key=candidate_score, reverse=True)
        for row in selected:
            row["v2_selection_reason"] = (
                "replacement selected from unsampled Cloudflare pool using timestamp validity, ASN availability, "
                "expected prefix availability, provenance/event ID, confidence/visibility, duration, and diversity strata"
            )
            row["v2_record_role"] = "replacement"
            row["roster_version"] = ROSTER_VERSION
            row["partition"] = ""
        replacements.extend(selected)
        found[category] = len(selected)
    return replacements, needed, found


def make_v2_rows(seed_rows: list[dict[str, str]], replacements: list[dict[str, str]]) -> list[dict[str, str]]:
    output: list[dict[str, str]] = []
    for row in seed_rows:
        new_row = dict(row)
        new_row["roster_version"] = ROSTER_VERSION
        new_row["v2_record_role"] = "retained_v1_canonical_or_nonduplicate"
        new_row.setdefault("v2_selection_reason", "")
        new_row["partition"] = ""
        output.append(new_row)
    output.extend(replacements)
    return sorted(output, key=lambda row: (row["category"], row.get("start_utc", ""), incident_uid(row)))


def write_active_window_policy(path: Path) -> None:
    text = """# Active Window Policy v1

This policy defines label-window construction for roster v2. It is not applied to raw BGP data yet.

## Outage

- Use `label_start = startDate`.
- Use `label_end = endDate`.
- Treat the interval as the documented outage interval unless an individual outage has a quality flag requiring review.
- Preserve one real-world outage as one incident.

## Hijack

`min_hijack_ts -> max_hijack_ts` is a first/last hijack-specific detector-evidence span, not proof of continuous hijack activity.

For feature labeling, use event-specific hijack observations:

- Divide the bounding interval into 5-minute bins.
- Mark a bin active only if hijack-specific detector observations occur in or sufficiently near that bin.
- Merge consecutive active bins into incident-active segments.
- Do not automatically label long silent gaps as Hijack.
- Silent gaps should remain `UNKNOWN` until a continuity threshold is justified from observed detector-message distributions.
- Keep the gap/continuity threshold parameterized for analysis, for example `max_silent_gap_bins`.

## Leak

`min_ts/detected_ts -> max_ts` is a route-leak detector observation span, not proof of continuous leaking.

For feature labeling, use event-specific leak observations:

- Divide the bounding interval into 5-minute bins.
- Mark a bin active only if leak-specific detector observations occur in or sufficiently near that bin.
- Merge consecutive active bins into leak-active segments.
- Do not automatically label long silent gaps as Leak.
- Silent gaps should remain `UNKNOWN`.
- Keep the gap/continuity threshold parameterized and select it only after inspecting observation density/gap distributions.
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def replacement_rows_for_csv(rows: list[dict[str, str]]) -> list[dict[str, object]]:
    return [
        {
            "incident_uid": incident_uid(row),
            "incident_id": row.get("incident_id", ""),
            "category": row.get("category", ""),
            "start_utc": row.get("start_utc", ""),
            "end_utc": row.get("end_utc", ""),
            "duration_minutes": row.get("duration_minutes", ""),
            "primary_asn": row.get("primary_asn", ""),
            "affected_asns": row.get("affected_asns", ""),
            "affected_prefixes": row.get("affected_prefixes", ""),
            "prefix_count": row.get("prefix_count", ""),
            "peer_count": row.get("peer_count", ""),
            "countries": row.get("countries", ""),
            "source_url": row.get("source_url", ""),
            "selection_reason": row.get("v2_selection_reason", ""),
        }
        for row in rows
    ]


def v2_quality_audit(v2_rows: list[dict[str, str]], true_duplicate_excluded: set[str]) -> list[dict[str, object]]:
    counts = Counter(row["category"] for row in v2_rows)
    uids = [incident_uid(row) for row in v2_rows]
    duplicate_uid_count = len(uids) - len(set(uids))
    known_true_duplicate_members_remaining = len(set(uids) & true_duplicate_excluded)
    timestamp_missing = sum(1 for row in v2_rows if not row.get("start_utc") or not row.get("end_utc"))
    timestamp_bad = sum(1 for row in v2_rows if not timestamp_ok(row))
    asn_missing = sum(1 for row in v2_rows if not asn_set(row))
    hijack_prefix_missing = sum(1 for row in v2_rows if row["category"] == "Hijack" and not prefix_set(row))
    leak_prefix_missing = sum(1 for row in v2_rows if row["category"] == "Leak" and not prefix_set(row))
    outage_prefix_missing = sum(1 for row in v2_rows if row["category"] == "Outage" and not prefix_set(row))
    provenance_missing = sum(1 for row in v2_rows if not provenance_available(row))
    rows = [
        audit_row("total_incident_count", len(v2_rows), "PASS" if len(v2_rows) == 1419 else "FAIL", "exactly 1,419 incidents required"),
        audit_row("class_balance", min(counts.values()) if counts else 0, "PASS" if all(counts[c] == TARGET_PER_CLASS for c in CLASS_LABELS) else "FAIL", json.dumps(dict(counts), sort_keys=True)),
        audit_row("incident_uid_uniqueness", duplicate_uid_count, "PASS" if duplicate_uid_count == 0 else "FAIL", "incident_uid must be unique"),
        audit_row("known_true_duplicates_excluded", known_true_duplicate_members_remaining, "PASS" if known_true_duplicate_members_remaining == 0 else "FAIL", "non-canonical true duplicate members should not appear in v2"),
        audit_row("timestamp_completeness", timestamp_missing, "PASS" if timestamp_missing == 0 else "FAIL", "start/end timestamps must exist"),
        audit_row("timestamp_validity", timestamp_bad, "PASS" if timestamp_bad == 0 else "FAIL", "start < end and duration should match"),
        audit_row("ASN_completeness", asn_missing, "PASS" if asn_missing == 0 else "REVIEW", "all selected v2 incidents should have ASN evidence"),
        audit_row("Hijack_prefix_completeness", hijack_prefix_missing, "PASS" if hijack_prefix_missing == 0 else "REVIEW", "Hijack prefix list is expected"),
        audit_row("Leak_prefix_completeness", leak_prefix_missing, "REVIEW" if leak_prefix_missing else "PASS", "Leak source currently provides counts/segments but not actual prefix lists"),
        audit_row("Outage_prefix_completeness", outage_prefix_missing, "PASS", "Outage can be ASN/network interval based; prefix list not required before MRT"),
        audit_row("provenance_completeness", provenance_missing, "PASS" if provenance_missing == 0 else "REVIEW", "Cloudflare event ID counts as provenance even without URL"),
        audit_row("v2_split_required", 1, "REVIEW", "v1 partitions must not be reused; create a new incident-level split after v2 QC passes"),
    ]
    return rows


def audit_row(check_name: str, count: int, status: str, interpretation: str) -> dict[str, object]:
    return {
        "check_name": check_name,
        "result": status,
        "count": count,
        "status": status,
        "interpretation": interpretation,
        "action_required": "review_before_freeze" if status == "REVIEW" else ("fix_before_freeze" if status == "FAIL" else "none"),
    }


def write_v2_roster(path: Path, rows: list[dict[str, str]]) -> None:
    field_order = [
        "incident_uid",
        "incident_id",
        "incident_name",
        "category",
        "incident_date",
        "start_utc",
        "end_utc",
        "duration_minutes",
        "primary_asn",
        "affected_asns",
        "affected_prefixes",
        "prefix_count",
        "peer_count",
        "countries",
        "source_url",
        "confidence_score",
        "routeviews_collection_start",
        "routeviews_collection_end",
        "five_minute_window_count",
        "partition",
        "notes",
        "sampling_stratum",
        "quality_score",
        "quality_rank_within_stratum",
        "roster_version",
        "v2_record_role",
        "v2_selection_reason",
    ]
    write_csv(path, rows, field_order)


def run_build(
    partition_dir: Path = PARTITION_DIR,
    review_dir: Path = REVIEW_DIR,
    output_dir: Path = ROSTER_V2_DIR,
    pool_path: Path = UNSAMPLED_POOL,
) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    v1_rows = load_partition_rows(partition_dir)
    rows_by_uid = {incident_uid(row): row for row in v1_rows}
    groups = true_duplicate_groups(review_dir)
    plan, excluded = duplicate_canonicalization_plan(rows_by_uid, groups)
    retained = [row for row in v1_rows if incident_uid(row) not in excluded]
    post_counts = Counter(row["category"] for row in retained)
    replacements, needed, found = select_replacements(retained, excluded, groups, pool_path)
    v2_rows = make_v2_rows(retained, replacements)
    audit = v2_quality_audit(v2_rows, excluded)
    summary = [
        {"metric": "post_duplicate_collapse_Hijack", "value": post_counts["Hijack"]},
        {"metric": "post_duplicate_collapse_Leak", "value": post_counts["Leak"]},
        {"metric": "post_duplicate_collapse_Outage", "value": post_counts["Outage"]},
        {"metric": "replacements_needed_Hijack", "value": needed["Hijack"]},
        {"metric": "replacements_needed_Leak", "value": needed["Leak"]},
        {"metric": "replacements_needed_Outage", "value": needed["Outage"]},
        {"metric": "replacements_found_Hijack", "value": found["Hijack"]},
        {"metric": "replacements_found_Leak", "value": found["Leak"]},
        {"metric": "replacements_found_Outage", "value": found["Outage"]},
        {"metric": "v2_total", "value": len(v2_rows)},
        {"metric": "v2_Hijack", "value": Counter(row["category"] for row in v2_rows)["Hijack"]},
        {"metric": "v2_Leak", "value": Counter(row["category"] for row in v2_rows)["Leak"]},
        {"metric": "v2_Outage", "value": Counter(row["category"] for row in v2_rows)["Outage"]},
    ]

    write_csv(output_dir / "duplicate_canonicalization_plan.csv", plan, ["group_id", "canonical_incident_uid", "duplicate_incident_uids", "category", "reason_selected", "records_to_exclude_from_v2"])
    write_csv(output_dir / "replacement_incidents.csv", replacement_rows_for_csv(replacements), ["incident_uid", "incident_id", "category", "start_utc", "end_utc", "duration_minutes", "primary_asn", "affected_asns", "affected_prefixes", "prefix_count", "peer_count", "countries", "source_url", "selection_reason"])
    write_active_window_policy(output_dir / "active_window_policy_v1.md")
    write_v2_roster(output_dir / "balanced_incident_roster_v2.csv", v2_rows)
    write_csv(output_dir / "roster_v2_quality_audit.csv", audit, ["check_name", "result", "count", "status", "interpretation", "action_required"])
    write_csv(output_dir / "roster_v2_summary.csv", summary, ["metric", "value"])
    return {
        "canonicalization_plan": plan,
        "retained": retained,
        "post_counts": post_counts,
        "replacement_needed": needed,
        "replacement_found": found,
        "replacements": replacements,
        "v2_rows": v2_rows,
        "audit": audit,
        "summary": summary,
    }


def print_report(results: dict[str, object]) -> None:
    v2_counts = Counter(row["category"] for row in results["v2_rows"])
    audit_status = Counter(row["status"] for row in results["audit"])
    print("Roster v2 proposal complete")
    print(f"Counts after duplicate collapse: {dict(results['post_counts'])}")
    print(f"Replacements needed: {results['replacement_needed']}")
    print(f"Replacements found: {results['replacement_found']}")
    print(f"v2 counts: {dict(v2_counts)}")
    print(f"QC statuses: {dict(audit_status)}")
    print("Do not reuse v1 partitions; create a new v2 incident-level split after QC review.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build proposed roster v2 remediation plan without changing v1 files.")
    parser.add_argument("--partition-dir", type=Path, default=PARTITION_DIR)
    parser.add_argument("--review-dir", type=Path, default=REVIEW_DIR)
    parser.add_argument("--output-dir", type=Path, default=ROSTER_V2_DIR)
    parser.add_argument("--pool", type=Path, default=UNSAMPLED_POOL)
    args = parser.parse_args()
    results = run_build(args.partition_dir, args.review_dir, args.output_dir, args.pool)
    print_report(results)


if __name__ == "__main__":
    main()
