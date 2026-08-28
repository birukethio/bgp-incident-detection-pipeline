from __future__ import annotations

import argparse
import csv
import json
import random
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, median

try:
    from bgp_incident_detection.audit import asn_set, country_set, parse_utc, prefix_set, timestamp_status, write_csv
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import asn_set, country_set, parse_utc, prefix_set, timestamp_status, write_csv


ROSTER_V2_DIR = Path("data/roster_v2")
PARTITION_V2_DIR = Path("data/partitions_v2")
SOURCE_ROSTER = ROSTER_V2_DIR / "balanced_incident_roster_v2.csv"
FROZEN_ROSTER = ROSTER_V2_DIR / "frozen_incident_roster_v2.csv"
FREEZE_READINESS = ROSTER_V2_DIR / "roster_v2_freeze_readiness.csv"
RANDOM_SEED = 20260828
ROSTER_VERSION = "v2"
ROSTER_STATUS = "FROZEN"
SPLIT_VERSION = "v2"
TARGET_PER_CLASS = 473
PARTITION_TARGETS = {"train": 331, "validation": 71, "holdout": 71}
CLASS_LABELS = ("Hijack", "Leak", "Outage")


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def source_commit() -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()


def freeze_date() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def validate_freeze_readiness(path: Path = FREEZE_READINESS) -> dict[str, str]:
    rows = load_csv(path)
    if len(rows) != 1:
        raise ValueError("freeze readiness file must contain exactly one row")
    row = rows[0]
    if row.get("recommendation") != "FREEZE":
        raise ValueError(f"roster v2 is not ready to freeze: {row.get('recommendation')}")
    if row.get("remaining_blockers") != "none":
        raise ValueError(f"roster v2 has remaining blockers: {row.get('remaining_blockers')}")
    return row


def validate_roster(rows: list[dict[str, str]]) -> None:
    if len(rows) != TARGET_PER_CLASS * len(CLASS_LABELS):
        raise ValueError(f"expected 1419 rows, found {len(rows)}")
    counts = Counter(row.get("category", "") for row in rows)
    if any(counts[label] != TARGET_PER_CLASS for label in CLASS_LABELS):
        raise ValueError(f"class count mismatch: {dict(counts)}")
    uids = [row.get("incident_uid", "") for row in rows]
    if any(not uid for uid in uids) or len(set(uids)) != len(uids):
        raise ValueError("incident_uid values must be present and unique")
    bad_timestamps = [row["incident_uid"] for row in rows if timestamp_status(row)[0] != "PASS"]
    if bad_timestamps:
        raise ValueError(f"timestamp validation failed for {bad_timestamps[:10]}")


def freeze_roster(
    source_path: Path = SOURCE_ROSTER,
    output_path: Path = FROZEN_ROSTER,
    freeze_date_value: str | None = None,
    source_commit_value: str | None = None,
) -> list[dict[str, str]]:
    validate_freeze_readiness()
    rows = load_csv(source_path)
    validate_roster(rows)
    freeze_date_value = freeze_date_value or freeze_date()
    source_commit_value = source_commit_value or source_commit()
    frozen = []
    for row in rows:
        new_row = dict(row)
        new_row["roster_version"] = ROSTER_VERSION
        new_row["roster_status"] = ROSTER_STATUS
        new_row["freeze_date"] = freeze_date_value
        new_row["source_commit"] = source_commit_value
        frozen.append(new_row)
    fieldnames = list(rows[0].keys())
    for field in ("roster_version", "roster_status", "freeze_date", "source_commit"):
        if field not in fieldnames:
            fieldnames.append(field)
    write_csv(output_path, frozen, fieldnames)
    return frozen


def first_country(row: dict[str, str]) -> str:
    countries = sorted(country_set(row))
    return countries[0] if countries else "unknown_country"


def duration_bucket(row: dict[str, str]) -> str:
    duration = float(row.get("duration_minutes", "0") or 0)
    if duration <= 30:
        return "duration_0_30"
    if duration <= 360:
        return "duration_31_360"
    if duration <= 1440:
        return "duration_361_1440"
    if duration <= 10080:
        return "duration_1_7d"
    return "duration_gt_7d"


def prefix_bucket(row: dict[str, str]) -> str:
    try:
        count = float(row.get("prefix_count", "") or 0)
    except ValueError:
        count = 0
    if count <= 1:
        return "prefix_0_1"
    if count <= 10:
        return "prefix_2_10"
    if count <= 100:
        return "prefix_11_100"
    return "prefix_gt_100"


def diversity_key(row: dict[str, str]) -> tuple[str, str, str, str, str]:
    start = parse_utc(row.get("start_utc"))
    year = str(start.year) if start else "unknown_year"
    asn_bucket = "asn_present" if asn_set(row) else "asn_missing"
    return year, duration_bucket(row), asn_bucket, first_country(row), prefix_bucket(row)


def assign_category(rows: list[dict[str, str]], seed: int) -> list[dict[str, str]]:
    rng = random.Random(seed)
    buckets: dict[tuple[str, str, str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        buckets[diversity_key(row)].append(row)
    bucket_items = list(buckets.items())
    rng.shuffle(bucket_items)
    for _, bucket_rows in bucket_items:
        rng.shuffle(bucket_rows)

    assigned: list[dict[str, str]] = []
    fill_counts = {partition: 0 for partition in PARTITION_TARGETS}
    active = True
    while active:
        active = False
        for _, bucket_rows in bucket_items:
            if not bucket_rows:
                continue
            active = True
            available = [name for name, target in PARTITION_TARGETS.items() if fill_counts[name] < target]
            if not available:
                break
            partition = min(available, key=lambda name: (fill_counts[name] / PARTITION_TARGETS[name], name))
            row = dict(bucket_rows.pop())
            row["partition"] = partition
            row["random_seed"] = str(RANDOM_SEED)
            row["split_version"] = SPLIT_VERSION
            assigned.append(row)
            fill_counts[partition] += 1
    if fill_counts != PARTITION_TARGETS:
        raise ValueError(f"partition target mismatch: {fill_counts}")
    return assigned


def split_roster(rows: list[dict[str, str]], seed: int = RANDOM_SEED) -> list[dict[str, str]]:
    validate_roster(rows)
    by_category: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_category[row["category"]].append(row)
    assigned: list[dict[str, str]] = []
    for category in CLASS_LABELS:
        assigned.extend(assign_category(by_category[category], seed + sum(ord(char) for char in category)))
    return sorted(assigned, key=lambda row: (row["partition"], row["category"], row["start_utc"], row["incident_uid"]))


def validate_split(rows: list[dict[str, str]], assignments: list[dict[str, str]]) -> dict[str, object]:
    source_uids = {row["incident_uid"] for row in rows}
    assigned_uids = [row["incident_uid"] for row in assignments]
    partition_counts = Counter(row["partition"] for row in assignments)
    class_partition_counts = Counter((row["partition"], row["category"]) for row in assignments)
    overlaps = overlap_counts(assignments)
    errors: list[str] = []
    if set(assigned_uids) != source_uids or len(assigned_uids) != len(set(assigned_uids)):
        errors.append("every incident must appear exactly once")
    expected_counts = {partition: target * len(CLASS_LABELS) for partition, target in PARTITION_TARGETS.items()}
    if dict(partition_counts) != expected_counts:
        errors.append(f"partition counts mismatch: {dict(partition_counts)}")
    for partition, target in PARTITION_TARGETS.items():
        for category in CLASS_LABELS:
            if class_partition_counts[(partition, category)] != target:
                errors.append(f"{partition}/{category} count mismatch")
    if any(overlaps.values()):
        errors.append(f"cross-partition overlap found: {overlaps}")
    if errors:
        raise ValueError("; ".join(errors))
    return {
        "partition_counts": dict(partition_counts),
        "class_partition_counts": {f"{partition}_{category}": count for (partition, category), count in class_partition_counts.items()},
        "overlaps": overlaps,
    }


def overlap_counts(assignments: list[dict[str, str]]) -> dict[str, int]:
    by_partition = {
        partition: {row["incident_uid"] for row in assignments if row["partition"] == partition}
        for partition in PARTITION_TARGETS
    }
    return {
        "TRAIN ∩ VALIDATION": len(by_partition["train"] & by_partition["validation"]),
        "TRAIN ∩ HOLDOUT": len(by_partition["train"] & by_partition["holdout"]),
        "VALIDATION ∩ HOLDOUT": len(by_partition["validation"] & by_partition["holdout"]),
    }


def write_partitions(assignments: list[dict[str, str]], output_dir: Path = PARTITION_V2_DIR) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    fieldnames = list(assignments[0].keys())
    for partition, filename in (
        ("train", "train_incidents_v2.csv"),
        ("validation", "validation_incidents_v2.csv"),
        ("holdout", "holdout_incidents_v2.csv"),
    ):
        write_csv(output_dir / filename, [row for row in assignments if row["partition"] == partition], fieldnames)
    manifest_fields = [
        "incident_uid",
        "incident_id",
        "category",
        "partition",
        "start_utc",
        "end_utc",
        "duration_minutes",
        "random_seed",
        "roster_version",
        "split_version",
    ]
    write_csv(output_dir / "frozen_partition_manifest_v2.csv", assignments, manifest_fields)


def percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    position = (len(ordered) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def distribution_summary(assignments: list[dict[str, str]]) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    for partition in PARTITION_TARGETS:
        subset = [row for row in assignments if row["partition"] == partition]
        durations = [float(row.get("duration_minutes", "0") or 0) for row in subset]
        year_counts = Counter(str(parse_utc(row["start_utc"]).year) for row in subset)
        class_counts = Counter(row["category"] for row in subset)
        output.append(
            {
                "partition": partition,
                "incident_count": len(subset),
                "class_counts": json.dumps(dict(class_counts), sort_keys=True),
                "duration_min": round(min(durations), 2),
                "duration_median": round(median(durations), 2),
                "duration_mean": round(mean(durations), 2),
                "duration_p90": round(percentile(durations, 0.90), 2),
                "duration_max": round(max(durations), 2),
                "year_distribution": json.dumps(dict(sorted(year_counts.items())), sort_keys=True),
                "asn_network_diversity": len(set().union(*(asn_set(row) for row in subset))),
                "country_diversity": len(set().union(*(country_set(row) for row in subset))),
            }
        )
    return output


def quality_audit(source_rows: list[dict[str, str]], assignments: list[dict[str, str]]) -> list[dict[str, object]]:
    validation = validate_split(source_rows, assignments)
    distributions = distribution_summary(assignments)
    median_values = [row["duration_median"] for row in distributions]
    duration_ratio = max(median_values) / min(median_values) if min(median_values) else 999
    status = "REVIEW" if duration_ratio > 2 else "PASS"
    return [
        audit_row("total_incident_count", len(assignments), "PASS" if len(assignments) == 1419 else "FAIL", "exactly 1,419 incidents required"),
        audit_row("class_balance", 473, "PASS", "473 incidents per class"),
        audit_row("partition_counts", sum(validation["partition_counts"].values()), "PASS", json.dumps(validation["partition_counts"], sort_keys=True)),
        audit_row("partition_class_counts", 0, "PASS", "331/71/71 per class satisfied"),
        audit_row("cross_partition_overlap", sum(validation["overlaps"].values()), "PASS", json.dumps(validation["overlaps"], sort_keys=True)),
        audit_row("incident_uid_once", len({row["incident_uid"] for row in assignments}), "PASS", "every incident appears exactly once"),
        audit_row("duration_distribution_balance", round(duration_ratio, 3), status, "secondary check only; do not re-split unless class counts fail"),
        audit_row("final_holdout_protection", 1, "PASS", "holdout reserved until complete pipeline is frozen"),
    ]


def audit_row(check_name: str, count: object, status: str, interpretation: str) -> dict[str, object]:
    return {
        "check_name": check_name,
        "result": status,
        "count": count,
        "status": status,
        "interpretation": interpretation,
        "action_required": "review" if status == "REVIEW" else ("fix" if status == "FAIL" else "none"),
    }


def run(
    source_roster: Path = SOURCE_ROSTER,
    frozen_roster: Path = FROZEN_ROSTER,
    partition_dir: Path = PARTITION_V2_DIR,
    seed: int = RANDOM_SEED,
) -> dict[str, object]:
    frozen_rows = freeze_roster(source_roster, frozen_roster)
    assignments = split_roster(frozen_rows, seed)
    validate_split(frozen_rows, assignments)
    write_partitions(assignments, partition_dir)
    distribution_rows = distribution_summary(assignments)
    audit_rows = quality_audit(frozen_rows, assignments)
    write_csv(
        partition_dir / "partition_v2_distribution_summary.csv",
        distribution_rows,
        [
            "partition",
            "incident_count",
            "class_counts",
            "duration_min",
            "duration_median",
            "duration_mean",
            "duration_p90",
            "duration_max",
            "year_distribution",
            "asn_network_diversity",
            "country_diversity",
        ],
    )
    write_csv(
        partition_dir / "partition_v2_quality_audit.csv",
        audit_rows,
        ["check_name", "result", "count", "status", "interpretation", "action_required"],
    )
    return {
        "frozen_rows": frozen_rows,
        "assignments": assignments,
        "distribution_summary": distribution_rows,
        "quality_audit": audit_rows,
    }


def print_report(results: dict[str, object]) -> None:
    assignments = results["assignments"]
    counts = Counter(row["partition"] for row in assignments)
    class_counts = Counter((row["partition"], row["category"]) for row in assignments)
    statuses = Counter(row["status"] for row in results["quality_audit"])
    print("Roster v2 frozen and partitioned")
    print(f"Partition counts: {dict(counts)}")
    print(f"Per-class partition counts: {dict(class_counts)}")
    print(f"Overlap proof: {overlap_counts(assignments)}")
    print(f"Audit statuses: {dict(statuses)}")
    print("All future windows/features must inherit frozen_partition_manifest_v2.csv.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Freeze Roster v2 and create final v2 incident-level partitions.")
    parser.add_argument("--source-roster", type=Path, default=SOURCE_ROSTER)
    parser.add_argument("--frozen-roster", type=Path, default=FROZEN_ROSTER)
    parser.add_argument("--partition-dir", type=Path, default=PARTITION_V2_DIR)
    parser.add_argument("--seed", type=int, default=RANDOM_SEED)
    args = parser.parse_args()
    results = run(args.source_roster, args.frozen_roster, args.partition_dir, args.seed)
    print_report(results)


if __name__ == "__main__":
    main()
