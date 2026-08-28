from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import ipaddress
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, median

try:
    from bgp_incident_detection.partitioning import CLASS_LABELS, PARTITION_TARGETS, parse_utc
except ModuleNotFoundError:
    from src.bgp_incident_detection.partitioning import CLASS_LABELS, PARTITION_TARGETS, parse_utc


PARTITION_DIR = Path("data/partitions")
PARTITION_FILES = {
    "train": "train_incidents.csv",
    "validation": "validation_incidents.csv",
    "holdout": "holdout_incidents.csv",
}
MANIFEST_FILE = "frozen_partition_manifest.csv"
AUDIT_VERSION = "v1"
KNOWN_COLLISION_IDS = ("431", "643", "646", "1415")


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, object]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def load_frozen_partitions(partition_dir: Path = PARTITION_DIR) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    rows: list[dict[str, str]] = []
    for partition, filename in PARTITION_FILES.items():
        for row in load_csv(partition_dir / filename):
            if row.get("partition") != partition:
                raise ValueError(f"{filename} contains row with partition={row.get('partition')}")
            rows.append(row)
    manifest = load_csv(partition_dir / MANIFEST_FILE)
    return rows, manifest


def file_hashes(paths: list[Path]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in paths:
        hashes[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes


def partition_file_paths(partition_dir: Path = PARTITION_DIR) -> list[Path]:
    return [partition_dir / filename for filename in PARTITION_FILES.values()] + [partition_dir / MANIFEST_FILE]


def parse_listish(value: str | None) -> list[str]:
    if not value:
        return []
    raw = value.strip()
    try:
        parsed = ast.literal_eval(raw)
        if isinstance(parsed, list):
            return [str(item).strip() for item in parsed if str(item).strip()]
        if parsed:
            return [str(parsed).strip()]
    except (SyntaxError, ValueError):
        pass
    cleaned = raw.strip("[]")
    return [part.strip().strip("\"'") for part in cleaned.split(",") if part.strip().strip("\"'")]


def asn_set(row: dict[str, str]) -> set[str]:
    values: set[str] = set()
    for field in ("primary_asn", "affected_asns"):
        for item in parse_listish(row.get(field)):
            digits = re.findall(r"\d+", item)
            values.update(digits)
    for item in re.findall(r"\bAS(\d+)\b", " ".join([row.get("incident_name", ""), row.get("notes", "")]), re.I):
        values.add(item)
    return values


def prefix_set(row: dict[str, str]) -> set[str]:
    values: set[str] = set()
    for item in parse_listish(row.get("affected_prefixes")):
        candidate = item.strip()
        try:
            values.add(str(ipaddress.ip_network(candidate, strict=False)))
        except ValueError:
            continue
    return values


def country_set(row: dict[str, str]) -> set[str]:
    return {item for item in parse_listish(row.get("countries")) if item and item.lower() != "unknown"}


def source_available(row: dict[str, str]) -> bool:
    return bool((row.get("source_url") or "").strip())


def text_tokens(row: dict[str, str]) -> set[str]:
    text = " ".join(
        [
            row.get("incident_name", ""),
            row.get("source_url", ""),
        ]
    ).lower()
    stop = {"https", "http", "source", "hijack", "leak", "outage", "cloudflare", "radar"}
    return {token for token in re.findall(r"[a-z0-9]{4,}", text) if token not in stop}


def token_similarity(row_1: dict[str, str], row_2: dict[str, str]) -> float:
    left = text_tokens(row_1)
    right = text_tokens(row_2)
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def interval(row: dict[str, str]) -> tuple[datetime | None, datetime | None]:
    return parse_utc(row.get("start_utc")), parse_utc(row.get("end_utc"))


def intervals_overlap(row_1: dict[str, str], row_2: dict[str, str]) -> bool:
    start_1, end_1 = interval(row_1)
    start_2, end_2 = interval(row_2)
    if not start_1 or not end_1 or not start_2 or not end_2:
        return False
    return start_1 < end_2 and start_2 < end_1


def timestamp_status(row: dict[str, str]) -> tuple[str, str, float | None]:
    try:
        start, end = interval(row)
    except ValueError as exc:
        return "FAIL", f"timestamp parse error: {exc}", None
    if not start:
        return "FAIL", "missing start_utc", None
    if not end:
        return "FAIL", "missing end_utc", None
    if start >= end:
        return "FAIL", "start_utc is not before end_utc", None
    calculated = (end - start).total_seconds() / 60
    recorded_raw = row.get("duration_minutes", "")
    try:
        recorded = float(recorded_raw)
    except ValueError:
        return "REVIEW", "duration_minutes missing or non-numeric", calculated
    if abs(recorded - round(calculated)) > 1:
        return "REVIEW", f"duration mismatch: recorded={recorded_raw}, calculated={calculated:.2f}", calculated
    return "PASS", "", calculated


def validate_counts(rows: list[dict[str, str]]) -> dict[str, object]:
    partition_counts = Counter(row["partition"] for row in rows)
    class_partition_counts = Counter((row["partition"], row["category"]) for row in rows)
    uid_counts = Counter(row["incident_uid"] for row in rows)
    overlaps = cross_partition_uid_overlap(rows)
    return {
        "partition_counts": partition_counts,
        "class_partition_counts": class_partition_counts,
        "duplicate_uids": [uid for uid, count in uid_counts.items() if count > 1],
        "overlap_count": sum(overlaps.values()),
        "overlaps": overlaps,
    }


def cross_partition_uid_overlap(rows: list[dict[str, str]]) -> dict[str, int]:
    by_partition = {
        partition: {row["incident_uid"] for row in rows if row["partition"] == partition}
        for partition in PARTITION_FILES
    }
    return {
        "train_validation": len(by_partition["train"] & by_partition["validation"]),
        "train_holdout": len(by_partition["train"] & by_partition["holdout"]),
        "validation_holdout": len(by_partition["validation"] & by_partition["holdout"]),
    }


def manifest_matches_partitions(rows: list[dict[str, str]], manifest: list[dict[str, str]]) -> tuple[bool, list[str]]:
    key_fields = ("incident_uid", "incident_id", "category", "partition", "start_utc", "end_utc", "duration_minutes")
    row_map = {row["incident_uid"]: tuple(row.get(field, "") for field in key_fields) for row in rows}
    manifest_map = {row["incident_uid"]: tuple(row.get(field, "") for field in key_fields) for row in manifest}
    differences: list[str] = []
    if set(row_map) != set(manifest_map):
        missing = sorted(set(row_map) - set(manifest_map))
        extra = sorted(set(manifest_map) - set(row_map))
        differences.append(f"manifest UID mismatch missing={missing[:5]} extra={extra[:5]}")
    for uid in sorted(set(row_map) & set(manifest_map)):
        if row_map[uid] != manifest_map[uid]:
            differences.append(uid)
            if len(differences) >= 10:
                break
    return not differences, differences


def known_cross_schema_collisions(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    collisions: list[dict[str, str]] = []
    by_raw_id: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_raw_id[row["incident_id"]].append(row)
    for incident_id in sorted(by_raw_id, key=lambda value: int(value) if value.isdigit() else value):
        if len(by_raw_id[incident_id]) <= 1:
            continue
        for row in sorted(by_raw_id[incident_id], key=lambda item: item["incident_uid"]):
            collisions.append(
                {
                    "incident_id": incident_id,
                    "incident_uid": row["incident_uid"],
                    "category": row["category"],
                    "partition": row["partition"],
                }
            )
    return collisions


def duration_audit(rows: list[dict[str, str]]) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    for row in rows:
        status, reason, calculated = timestamp_status(row)
        duration = calculated
        flags = duration_flags(duration)
        output.append(
            {
                "incident_uid": row["incident_uid"],
                "incident_id": row["incident_id"],
                "category": row["category"],
                "partition": row["partition"],
                "start_utc": row.get("start_utc", ""),
                "end_utc": row.get("end_utc", ""),
                "recorded_duration_minutes": row.get("duration_minutes", ""),
                "calculated_duration_minutes": f"{duration:.2f}" if duration is not None else "",
                "timestamp_status": status,
                "duration_flags": ";".join(flags),
                "review_reason": reason,
            }
        )
    return output


def duration_flags(duration: float | None) -> list[str]:
    flags: list[str] = []
    if duration is not None:
        if duration < 5:
            flags.append("duration_lt_5_minutes")
        if duration > 24 * 60:
            flags.append("duration_gt_24_hours")
        if duration > 7 * 24 * 60:
            flags.append("duration_gt_7_days")
        if duration > 30 * 24 * 60:
            flags.append("duration_gt_30_days")
    return flags


def percentile(values: list[float], quantile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def duration_summary(rows: list[dict[str, str]]) -> list[dict[str, object]]:
    summaries: list[dict[str, object]] = []
    for category in CLASS_LABELS:
        for partition in PARTITION_FILES:
            durations = []
            for row in rows:
                if row["category"] == category and row["partition"] == partition:
                    _, _, calculated = timestamp_status(row)
                    if calculated is not None:
                        durations.append(calculated)
            summaries.append(
                {
                    "category": category,
                    "partition": partition,
                    "count": len(durations),
                    "minimum": round(min(durations), 2) if durations else "",
                    "median": round(median(durations), 2) if durations else "",
                    "mean": round(mean(durations), 2) if durations else "",
                    "p75": round(percentile(durations, 0.75), 2) if durations else "",
                    "p90": round(percentile(durations, 0.90), 2) if durations else "",
                    "p95": round(percentile(durations, 0.95), 2) if durations else "",
                    "maximum": round(max(durations), 2) if durations else "",
                }
            )
    return summaries


def completeness_summary(rows: list[dict[str, str]]) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    for category in CLASS_LABELS:
        for partition in ("ALL", *PARTITION_FILES.keys()):
            subset = [row for row in rows if row["category"] == category and (partition == "ALL" or row["partition"] == partition)]
            if not subset:
                continue
            asn_count = sum(1 for row in subset if asn_set(row))
            prefix_count = sum(1 for row in subset if prefix_set(row))
            source_count = sum(1 for row in subset if source_available(row))
            output.append(
                {
                    "category": category,
                    "partition": partition,
                    "incident_count": len(subset),
                    "with_asn": asn_count,
                    "without_asn": len(subset) - asn_count,
                    "with_asn_pct": round(asn_count / len(subset) * 100, 2),
                    "with_prefix": prefix_count,
                    "without_prefix": len(subset) - prefix_count,
                    "with_prefix_pct": round(prefix_count / len(subset) * 100, 2),
                    "with_source_url": source_count,
                    "without_source_url": len(subset) - source_count,
                    "with_source_url_pct": round(source_count / len(subset) * 100, 2),
                }
            )
    return output


def cross_partition_asn_overlap(rows: list[dict[str, str]]) -> list[dict[str, object]]:
    asn_to_rows: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        for asn in asn_set(row):
            asn_to_rows[asn].append(row)
    output: list[dict[str, object]] = []
    for asn, asn_rows in sorted(asn_to_rows.items(), key=lambda item: int(item[0])):
        partitions = sorted({row["partition"] for row in asn_rows})
        if len(partitions) < 2:
            continue
        for left_idx, left in enumerate(partitions):
            for right in partitions[left_idx + 1 :]:
                left_rows = [row for row in asn_rows if row["partition"] == left]
                right_rows = [row for row in asn_rows if row["partition"] == right]
                related_pairs = sum(1 for row_1 in left_rows for row_2 in right_rows if intervals_overlap(row_1, row_2))
                output.append(
                    {
                        "asn": asn,
                        "partition_1": left,
                        "partition_2": right,
                        "incident_count_1": len(left_rows),
                        "incident_count_2": len(right_rows),
                        "overlapping_time_pair_count": related_pairs,
                        "interpretation": "diagnostic_overlap_not_automatic_leakage",
                    }
                )
    return output


def cross_partition_prefix_overlap(rows: list[dict[str, str]]) -> list[dict[str, object]]:
    prefix_to_rows: dict[str, list[dict[str, str]]] = defaultdict(list)
    network_by_prefix: dict[str, ipaddress._BaseNetwork] = {}
    for row in rows:
        for prefix in prefix_set(row):
            network = ipaddress.ip_network(prefix, strict=False)
            prefix_to_rows[prefix].append(row)
            network_by_prefix[prefix] = network

    output: list[dict[str, object]] = []
    seen: set[tuple[str, str, str, str, str]] = set()

    def add_rows(prefix_1: str, prefix_2: str, relation: str) -> None:
        for row_1 in prefix_to_rows[prefix_1]:
            for row_2 in prefix_to_rows[prefix_2]:
                if row_1["incident_uid"] == row_2["incident_uid"]:
                    continue
                if row_1["incident_uid"] > row_2["incident_uid"]:
                    continue
                key = (row_1["incident_uid"], row_2["incident_uid"], prefix_1, prefix_2, relation)
                if key in seen:
                    continue
                seen.add(key)
                if row_1["partition"] == row_2["partition"]:
                    continue
                output.append(
                    {
                        "incident_uid_1": row_1["incident_uid"],
                        "incident_uid_2": row_2["incident_uid"],
                        "category_1": row_1["category"],
                        "category_2": row_2["category"],
                        "partition_1": row_1["partition"],
                        "partition_2": row_2["partition"],
                        "prefix_1": prefix_1,
                        "prefix_2": prefix_2,
                        "relationship": relation,
                        "time_windows_overlap": intervals_overlap(row_1, row_2),
                        "interpretation": "diagnostic_prefix_overlap_not_automatic_leakage",
                    }
                )

    for prefix, prefix_rows in prefix_to_rows.items():
        if len({row["partition"] for row in prefix_rows}) >= 2:
            add_rows(prefix, prefix, "exact")

    # Practical subnet/supernet check: look only for exact supernet prefixes
    # that also appear in the frozen roster, instead of all pairwise comparisons.
    known_prefixes = set(prefix_to_rows)
    for prefix, network in network_by_prefix.items():
        for prefix_length in range(network.prefixlen - 1, -1, -1):
            supernet = str(network.supernet(new_prefix=prefix_length))
            if supernet not in known_prefixes:
                continue
            relation = "prefix_1_subnet_of_prefix_2"
            add_rows(prefix, supernet, relation)
    return output


def cross_partition_temporal_overlap(rows: list[dict[str, str]]) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    ordered = sorted(rows, key=lambda row: row.get("start_utc", ""))
    for idx, row_1 in enumerate(ordered):
        start_1, end_1 = interval(row_1)
        if not start_1 or not end_1:
            continue
        for row_2 in ordered[idx + 1 :]:
            start_2, end_2 = interval(row_2)
            if not start_2 or not end_2:
                continue
            if start_2 >= end_1:
                break
            if row_1["partition"] == row_2["partition"]:
                continue
            shared_asns = sorted(asn_set(row_1) & asn_set(row_2), key=lambda item: int(item))
            shared_prefixes = sorted(prefix_set(row_1) & prefix_set(row_2))
            output.append(
                {
                    "incident_uid_1": row_1["incident_uid"],
                    "incident_uid_2": row_2["incident_uid"],
                    "category_1": row_1["category"],
                    "category_2": row_2["category"],
                    "partition_1": row_1["partition"],
                    "partition_2": row_2["partition"],
                    "start_utc_1": row_1.get("start_utc", ""),
                    "end_utc_1": row_1.get("end_utc", ""),
                    "start_utc_2": row_2.get("start_utc", ""),
                    "end_utc_2": row_2.get("end_utc", ""),
                    "same_class": row_1["category"] == row_2["category"],
                    "different_classes": row_1["category"] != row_2["category"],
                    "shared_asns": list_as_json(shared_asns),
                    "shared_prefixes": list_as_json(shared_prefixes),
                    "holdout_related_risk": "holdout" in {row_1["partition"], row_2["partition"]} and bool(shared_asns or shared_prefixes),
                }
            )
    return output


def possible_duplicates(rows: list[dict[str, str]]) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    ordered = sorted(rows, key=lambda row: row.get("start_utc", ""))
    for idx, row_1 in enumerate(ordered):
        start_1, end_1 = interval(row_1)
        if not start_1 or not end_1:
            continue
        for row_2 in ordered[idx + 1 :]:
            start_2, end_2 = interval(row_2)
            if not start_2 or not end_2:
                continue
            start_delta_minutes = abs((start_2 - start_1).total_seconds()) / 60
            if start_2 > end_1 and start_delta_minutes > 60:
                break
            end_delta_minutes = abs((end_2 - end_1).total_seconds()) / 60
            overlapping_time = start_1 < end_2 and start_2 < end_1
            similar_time = start_delta_minutes <= 15 or end_delta_minutes <= 15
            shared_asns = sorted(asn_set(row_1) & asn_set(row_2), key=lambda item: int(item))
            shared_prefixes = sorted(prefix_set(row_1) & prefix_set(row_2))
            shared_countries = sorted(country_set(row_1) & country_set(row_2))
            text_score = token_similarity(row_1, row_2)
            reasons: list[str] = []
            if overlapping_time:
                reasons.append("overlapping_event_windows")
            if similar_time:
                reasons.append("similar_start_or_end_time")
            if shared_asns:
                reasons.append("shared_asn")
            if shared_prefixes:
                reasons.append("shared_prefix")
            if shared_countries:
                reasons.append("shared_country")
            if text_score >= 0.35:
                reasons.append("similar_description_or_source_metadata")

            strong_shared_evidence = bool(shared_asns or shared_prefixes or text_score >= 0.45)
            if (overlapping_time or similar_time) and strong_shared_evidence:
                output.append(
                    {
                        "incident_uid_1": row_1["incident_uid"],
                        "incident_uid_2": row_2["incident_uid"],
                        "category_1": row_1["category"],
                        "category_2": row_2["category"],
                        "partition_1": row_1["partition"],
                        "partition_2": row_2["partition"],
                        "reason_flagged": ";".join(reasons),
                        "similarity_evidence": (
                            f"shared_asns={list_as_json(shared_asns)}; "
                            f"shared_prefixes={list_as_json(shared_prefixes)}; "
                            f"shared_countries={list_as_json(shared_countries)}; "
                            f"text_similarity={text_score:.3f}; "
                            f"start_delta_minutes={start_delta_minutes:.2f}; "
                            f"end_delta_minutes={end_delta_minutes:.2f}"
                        ),
                        "recommended_action": "manual_review_do_not_merge_automatically",
                    }
                )
    return output


def list_as_json(values: list[str]) -> str:
    return "[" + ",".join(f'"{value}"' for value in values) + "]"


def incident_quality(rows: list[dict[str, str]], duplicate_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    duplicate_uids = {
        str(row["incident_uid_1"]) for row in duplicate_rows
    } | {
        str(row["incident_uid_2"]) for row in duplicate_rows
    }
    output: list[dict[str, object]] = []
    for row in rows:
        timestamp, reason, _ = timestamp_status(row)
        _, _, calculated_duration = timestamp_status(row)
        flags: list[str] = []
        if row["incident_uid"] in duplicate_uids:
            flags.append("possible_duplicate")
        if timestamp != "PASS":
            flags.append("timestamp_review")
        flags.extend(duration_flags(calculated_duration))
        if not asn_set(row):
            flags.append("missing_asn")
        quality_status = "PASS" if not flags else "REVIEW"
        completeness_notes: list[str] = []
        if not prefix_set(row):
            completeness_notes.append("missing_prefix_diagnostic")
        if not source_available(row):
            completeness_notes.append("missing_source_url_diagnostic")
        output.append(
            {
                "incident_uid": row["incident_uid"],
                "category": row["category"],
                "partition": row["partition"],
                "start_utc": row.get("start_utc", ""),
                "end_utc": row.get("end_utc", ""),
                "duration_minutes": row.get("duration_minutes", ""),
                "asn_available": bool(asn_set(row)),
                "prefix_available": bool(prefix_set(row)),
                "source_available": source_available(row),
                "possible_duplicate": row["incident_uid"] in duplicate_uids,
                "timestamp_status": timestamp,
                "quality_status": quality_status,
                "review_reason": ";".join(flags + completeness_notes + ([reason] if reason else [])),
            }
        )
    return output


def partition_diversity_summary(rows: list[dict[str, str]]) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    for partition in PARTITION_FILES:
        subset = [row for row in rows if row["partition"] == partition]
        output.append(
            {
                "partition": partition,
                "incident_count": len(subset),
                "year_count": len({parse_utc(row["start_utc"]).year for row in subset if row.get("start_utc")}),
                "country_count": len(set().union(*(country_set(row) for row in subset))),
                "asn_count": len(set().union(*(asn_set(row) for row in subset))),
                "prefix_count": len(set().union(*(prefix_set(row) for row in subset))),
                "duration_median": round(median([float(row["duration_minutes"]) for row in subset]), 2),
            }
        )
    return output


def integrity_summary(
    rows: list[dict[str, str]],
    manifest: list[dict[str, str]],
    duplicate_rows: list[dict[str, object]],
    duration_rows: list[dict[str, object]],
    asn_rows: list[dict[str, object]],
    prefix_rows: list[dict[str, object]],
    temporal_rows: list[dict[str, object]],
    quality_rows: list[dict[str, object]],
) -> list[dict[str, object]]:
    counts = validate_counts(rows)
    manifest_ok, manifest_diffs = manifest_matches_partitions(rows, manifest)
    timestamp_failures = [row for row in duration_rows if row["timestamp_status"] == "FAIL"]
    timestamp_reviews = [row for row in duration_rows if row["timestamp_status"] == "REVIEW"]
    extreme_duration_count = sum(1 for row in duration_rows if row["duration_flags"])
    completeness = completeness_summary(rows)
    missing_asn = sum(int(row["without_asn"]) for row in completeness if row["partition"] == "ALL")
    missing_prefix = sum(int(row["without_prefix"]) for row in completeness if row["partition"] == "ALL")
    missing_source = sum(int(row["without_source_url"]) for row in completeness if row["partition"] == "ALL")
    diversity = partition_diversity_summary(rows)
    duration_medians = [float(row["duration_median"]) for row in diversity]
    diversity_ratio = max(duration_medians) / min(duration_medians) if min(duration_medians) else 999
    diversity_status = "REVIEW" if diversity_ratio > 2 else "PASS"

    summary = [
        check("incident UID uniqueness", len(counts["duplicate_uids"]), "PASS" if not counts["duplicate_uids"] else "FAIL", "incident_uid uniquely identifies the experimental unit", "none"),
        check("partition overlap", counts["overlap_count"], "PASS" if counts["overlap_count"] == 0 else "FAIL", "no incident_uid may appear in more than one partition", "none"),
        check("manifest match", len(manifest_diffs), "PASS" if manifest_ok else "FAIL", "partition CSV rows must match frozen manifest", "none"),
        check("duplicate-event risk", len(duplicate_rows), "REVIEW" if duplicate_rows else "PASS", "possible real-world duplicate incidents are diagnostic only", "manual review flagged pairs"),
        check("timestamp validity", len(timestamp_failures) + len(timestamp_reviews), "FAIL" if timestamp_failures else ("REVIEW" if timestamp_reviews else "PASS"), "timestamps parse, start precedes end, duration matches", "review timestamp rows"),
        check("extreme-duration events", extreme_duration_count, "REVIEW" if extreme_duration_count else "PASS", "very short and long incidents are retained but flagged", "review before selecting windows"),
        check("ASN completeness", missing_asn, "REVIEW" if missing_asn else "PASS", "missing ASN reduces BGP feature anchoring confidence", "review incidents without ASN"),
        check("prefix completeness", missing_prefix, "REVIEW" if missing_prefix else "PASS", "prefix may be absent for outage labels", "review incidents without prefix"),
        check("source/reference completeness", missing_source, "REVIEW" if missing_source else "PASS", "source URLs improve label traceability", "review incidents without source URL"),
        check("ASN overlap", len(asn_rows), "REVIEW" if asn_rows else "PASS", "same ASN across partitions is diagnostic, not automatic leakage", "review overlapping-time ASN pairs separately"),
        check("prefix overlap", len(prefix_rows), "REVIEW" if prefix_rows else "PASS", "same or related prefixes across partitions are diagnostic", "review exact and subnet/supernet overlaps"),
        check("temporal overlap", len(temporal_rows), "REVIEW" if temporal_rows else "PASS", "simultaneous events can be independent or related", "review holdout-related overlaps"),
        check("partition diversity", len(diversity), diversity_status, "partition duration/year/country/ASN/prefix distributions are comparable enough for pre-MRT stage", "inspect notebook plots"),
        check("quality audit row count", len(quality_rows), "PASS" if len(quality_rows) == 1419 else "FAIL", "one quality row per incident_uid", "none"),
    ]
    return summary


def check(name: str, count: int, status: str, interpretation: str, action: str) -> dict[str, object]:
    return {
        "check_name": name,
        "result": status,
        "count": count,
        "status": status,
        "interpretation": interpretation,
        "action_required": action,
    }


def run_audit(partition_dir: Path = PARTITION_DIR) -> dict[str, object]:
    rows, manifest = load_frozen_partitions(partition_dir)
    duplicate_rows = possible_duplicates(rows)
    duration_rows = duration_audit(rows)
    asn_rows = cross_partition_asn_overlap(rows)
    prefix_rows = cross_partition_prefix_overlap(rows)
    temporal_rows = cross_partition_temporal_overlap(rows)
    quality_rows = incident_quality(rows, duplicate_rows)
    integrity_rows = integrity_summary(rows, manifest, duplicate_rows, duration_rows, asn_rows, prefix_rows, temporal_rows, quality_rows)
    collisions = known_cross_schema_collisions(rows)
    duration_summaries = duration_summary(rows)
    completeness = completeness_summary(rows)
    diversity = partition_diversity_summary(rows)

    write_csv(
        partition_dir / "possible_duplicate_incidents.csv",
        duplicate_rows,
        ["incident_uid_1", "incident_uid_2", "category_1", "category_2", "partition_1", "partition_2", "reason_flagged", "similarity_evidence", "recommended_action"],
    )
    write_csv(
        partition_dir / "incident_duration_audit.csv",
        duration_rows,
        ["incident_uid", "incident_id", "category", "partition", "start_utc", "end_utc", "recorded_duration_minutes", "calculated_duration_minutes", "timestamp_status", "duration_flags", "review_reason"],
    )
    write_csv(
        partition_dir / "cross_partition_asn_overlap.csv",
        asn_rows,
        ["asn", "partition_1", "partition_2", "incident_count_1", "incident_count_2", "overlapping_time_pair_count", "interpretation"],
    )
    write_csv(
        partition_dir / "cross_partition_prefix_overlap.csv",
        prefix_rows,
        ["incident_uid_1", "incident_uid_2", "category_1", "category_2", "partition_1", "partition_2", "prefix_1", "prefix_2", "relationship", "time_windows_overlap", "interpretation"],
    )
    write_csv(
        partition_dir / "cross_partition_temporal_overlap.csv",
        temporal_rows,
        ["incident_uid_1", "incident_uid_2", "category_1", "category_2", "partition_1", "partition_2", "start_utc_1", "end_utc_1", "start_utc_2", "end_utc_2", "same_class", "different_classes", "shared_asns", "shared_prefixes", "holdout_related_risk"],
    )
    write_csv(
        partition_dir / "partition_integrity_audit_v1.csv",
        integrity_rows,
        ["check_name", "result", "count", "status", "interpretation", "action_required"],
    )
    write_csv(
        partition_dir / "incident_quality_audit_v1.csv",
        quality_rows,
        ["incident_uid", "category", "partition", "start_utc", "end_utc", "duration_minutes", "asn_available", "prefix_available", "source_available", "possible_duplicate", "timestamp_status", "quality_status", "review_reason"],
    )
    write_csv(
        partition_dir / "cross_schema_incident_id_collisions.csv",
        collisions,
        ["incident_id", "incident_uid", "category", "partition"],
    )
    write_csv(
        partition_dir / "incident_duration_summary_by_class_partition.csv",
        duration_summaries,
        ["category", "partition", "count", "minimum", "median", "mean", "p75", "p90", "p95", "maximum"],
    )
    write_csv(
        partition_dir / "partition_completeness_summary_v1.csv",
        completeness,
        ["category", "partition", "incident_count", "with_asn", "without_asn", "with_asn_pct", "with_prefix", "without_prefix", "with_prefix_pct", "with_source_url", "without_source_url", "with_source_url_pct"],
    )
    write_csv(
        partition_dir / "partition_diversity_summary_v1.csv",
        diversity,
        ["partition", "incident_count", "year_count", "country_count", "asn_count", "prefix_count", "duration_median"],
    )

    return {
        "rows": rows,
        "manifest": manifest,
        "possible_duplicates": duplicate_rows,
        "duration_audit": duration_rows,
        "duration_summary": duration_summaries,
        "completeness_summary": completeness,
        "cross_schema_collisions": collisions,
        "asn_overlap": asn_rows,
        "prefix_overlap": prefix_rows,
        "temporal_overlap": temporal_rows,
        "quality_audit": quality_rows,
        "integrity_audit": integrity_rows,
        "diversity_summary": diversity,
    }


def overall_status(integrity_rows: list[dict[str, object]]) -> str:
    statuses = {str(row["status"]) for row in integrity_rows}
    if "FAIL" in statuses:
        return "FAIL"
    if "REVIEW" in statuses:
        return "REVIEW"
    return "PASS"


def print_report(results: dict[str, object]) -> None:
    integrity_rows = results["integrity_audit"]
    quality_rows = results["quality_audit"]
    duration_rows = results["duration_audit"]
    duplicate_rows = results["possible_duplicates"]
    completeness = results["completeness_summary"]
    collisions = results["cross_schema_collisions"]
    extreme_duration_count = sum(1 for row in duration_rows if row["duration_flags"])
    manual_review_count = sum(1 for row in quality_rows if row["quality_status"] != "PASS")

    print(f"Overall status: {overall_status(integrity_rows)}")
    print(f"Incidents requiring manual review: {manual_review_count}")
    print(f"Possible duplicate-event pairs: {len(duplicate_rows)}")
    print(f"Extreme-duration events: {extreme_duration_count}")
    print("\nKnown cross-schema raw incident_id collisions:")
    print("incident_id | incident_uid | category | partition")
    for row in collisions:
        print(f"{row['incident_id']} | {row['incident_uid']} | {row['category']} | {row['partition']}")
    print("\nCompleteness by class:")
    for row in completeness:
        if row["partition"] == "ALL":
            print(
                f"{row['category']}: ASN {row['with_asn']}/{row['incident_count']} "
                f"({row['with_asn_pct']}%), prefix {row['with_prefix']}/{row['incident_count']} "
                f"({row['with_prefix_pct']}%), source {row['with_source_url']}/{row['incident_count']} "
                f"({row['with_source_url_pct']}%)"
            )
    print("\nRecommendation: REVIEW before MRT acquisition; do not re-split or alter labels.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit frozen incident partitions before MRT acquisition.")
    parser.add_argument("--partition-dir", type=Path, default=PARTITION_DIR)
    args = parser.parse_args()
    results = run_audit(args.partition_dir)
    print_report(results)


if __name__ == "__main__":
    main()
