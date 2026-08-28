from __future__ import annotations

import argparse
import csv
import random
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


ROSTER_PATH = Path("cloudflare_incidents/balanced_incident_level_roster_473_each_leak_hijack_outage.csv")
PARTITION_DIR = Path("data/partitions")
RANDOM_SEED = 20260828
SPLIT_VERSION = "v1"
INCIDENT_UID_FIELD = "incident_uid"

EXPECTED_TOTAL = 1419
EXPECTED_PER_CLASS = 473
PARTITION_TARGETS = {
    "train": 331,
    "validation": 71,
    "holdout": 71,
}
CLASS_LABELS = ("Hijack", "Leak", "Outage")


class PartitionValidationError(ValueError):
    """Raised when the incident roster or frozen split fails validation."""


def load_roster(path: Path = ROSTER_PATH) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def parse_utc(value: str | None) -> datetime | None:
    if value is None or value == "":
        return None
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def incident_uid(row: dict[str, str]) -> str:
    return f"{row.get('category', '')}:{row.get('incident_id', '')}"


def validate_roster(rows: list[dict[str, str]]) -> dict[str, object]:
    ids = [row.get("incident_id", "") for row in rows]
    categories = [row.get("category", "") for row in rows]
    incident_uids = [incident_uid(row) for row in rows]
    missing_ids = [idx for idx, incident_id in enumerate(ids, start=2) if incident_id == ""]
    missing_categories = [idx for idx, category in enumerate(categories, start=2) if category == ""]
    source_id_collisions = [incident_id for incident_id, count in Counter(ids).items() if count > 1]
    duplicate_uids = [uid for uid, count in Counter(incident_uids).items() if count > 1]
    class_counts = Counter(categories)

    errors: list[str] = []
    if len(rows) != EXPECTED_TOTAL:
        errors.append(f"expected {EXPECTED_TOTAL} rows, found {len(rows)}")
    if len(set(incident_uids)) != EXPECTED_TOTAL:
        errors.append(f"expected {EXPECTED_TOTAL} unique incident UIDs, found {len(set(incident_uids))}")
    if missing_ids:
        errors.append(f"missing incident_id on CSV rows {missing_ids[:10]}")
    if missing_categories:
        errors.append(f"missing category on CSV rows {missing_categories[:10]}")
    if duplicate_uids:
        errors.append(f"duplicate incident UIDs found: {duplicate_uids[:10]}")
    for label in CLASS_LABELS:
        if class_counts[label] != EXPECTED_PER_CLASS:
            errors.append(f"expected {EXPECTED_PER_CLASS} {label} incidents, found {class_counts[label]}")

    invalid_timestamps: list[str] = []
    for row in rows:
        incident_id = row.get("incident_id", "")
        start_raw = row.get("start_utc", "")
        end_raw = row.get("end_utc", "")
        try:
            start = parse_utc(start_raw)
            end = parse_utc(end_raw)
        except ValueError as exc:
            invalid_timestamps.append(f"{incident_id}: {exc}")
            continue
        if start and end and end < start:
            invalid_timestamps.append(f"{incident_id}: end_utc precedes start_utc")
    if invalid_timestamps:
        errors.append(f"invalid timestamps: {invalid_timestamps[:10]}")

    if errors:
        raise PartitionValidationError("; ".join(errors))

    return {
        "row_count": len(rows),
        "unique_incident_ids": len(set(incident_uids)),
        "source_incident_id_collisions": source_id_collisions,
        "class_counts": dict(class_counts),
    }


def _first_jsonish_value(value: str | None) -> str:
    if not value:
        return "unknown"
    cleaned = value.strip()
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1].strip()
    cleaned = cleaned.replace('"', "").replace("'", "")
    first = cleaned.split(",")[0].strip()
    return first or "unknown"


def _number(value: str | None) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _duration_bucket(row: dict[str, str]) -> str:
    duration = _number(row.get("duration_minutes"))
    if duration is None:
        return "duration_unknown"
    if duration <= 30:
        return "duration_0_30"
    if duration <= 120:
        return "duration_31_120"
    if duration <= 720:
        return "duration_121_720"
    if duration <= 1440:
        return "duration_721_1440"
    return "duration_gt_1440"


def _prefix_bucket(row: dict[str, str]) -> str:
    prefix_count = _number(row.get("prefix_count"))
    if prefix_count is None:
        return "prefix_unknown"
    if prefix_count <= 1:
        return "prefix_0_1"
    if prefix_count <= 10:
        return "prefix_2_10"
    if prefix_count <= 100:
        return "prefix_11_100"
    return "prefix_gt_100"


def _asn_bucket(row: dict[str, str]) -> str:
    primary = row.get("primary_asn") or _first_jsonish_value(row.get("affected_asns"))
    asn = _number(primary)
    if asn is None:
        return "asn_unknown"
    if asn <= 65535:
        return "asn_16bit"
    return "asn_32bit"


def _year(row: dict[str, str]) -> str:
    timestamp = parse_utc(row.get("start_utc"))
    if timestamp:
        return str(timestamp.year)
    incident_date = row.get("incident_date", "")
    return incident_date[:4] if len(incident_date) >= 4 else "year_unknown"


def diversity_key(row: dict[str, str]) -> tuple[str, str, str, str, str]:
    return (
        _year(row),
        _duration_bucket(row),
        _asn_bucket(row),
        _first_jsonish_value(row.get("countries")),
        _prefix_bucket(row),
    )


def _assign_category(rows: list[dict[str, str]], seed: int) -> list[dict[str, str]]:
    rng = random.Random(seed)
    buckets: dict[tuple[str, str, str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        buckets[diversity_key(row)].append(row)

    bucket_items = list(buckets.items())
    rng.shuffle(bucket_items)
    for _, bucket_rows in bucket_items:
        rng.shuffle(bucket_rows)

    assignments: list[dict[str, str]] = []
    fill_counts = {partition: 0 for partition in PARTITION_TARGETS}
    active = True
    while active:
        active = False
        for _, bucket_rows in bucket_items:
            if not bucket_rows:
                continue
            active = True
            remaining_partitions = [
                partition
                for partition, target in PARTITION_TARGETS.items()
                if fill_counts[partition] < target
            ]
            if not remaining_partitions:
                break
            partition = min(
                remaining_partitions,
                key=lambda name: (fill_counts[name] / PARTITION_TARGETS[name], name),
            )
            row = dict(bucket_rows.pop())
            row[INCIDENT_UID_FIELD] = incident_uid(row)
            row["partition"] = partition
            assignments.append(row)
            fill_counts[partition] += 1

    if fill_counts != PARTITION_TARGETS:
        raise PartitionValidationError(f"partition target mismatch for class: {fill_counts}")
    return assignments


def split_incidents(rows: list[dict[str, str]], seed: int = RANDOM_SEED) -> list[dict[str, str]]:
    validate_roster(rows)
    assignments: list[dict[str, str]] = []
    by_category: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_category[row["category"]].append(row)

    for category in CLASS_LABELS:
        category_seed = seed + sum(ord(char) for char in category)
        assignments.extend(_assign_category(by_category[category], category_seed))

    return sorted(assignments, key=lambda row: (row["partition"], row["category"], row["start_utc"], row["incident_id"]))


def validate_split(assignments: list[dict[str, str]], source_rows: list[dict[str, str]]) -> dict[str, object]:
    source_ids = {incident_uid(row) for row in source_rows}
    assigned_ids = [row[INCIDENT_UID_FIELD] for row in assignments]
    partition_counts = Counter(row["partition"] for row in assignments)
    class_by_partition = Counter((row["partition"], row["category"]) for row in assignments)

    errors: list[str] = []
    if set(assigned_ids) != source_ids:
        errors.append("assigned incident IDs do not match source roster IDs")
    duplicate_assignments = [incident_id for incident_id, count in Counter(assigned_ids).items() if count > 1]
    if duplicate_assignments:
        errors.append(f"incidents assigned more than once: {duplicate_assignments[:10]}")
    expected_partition_counts = {
        partition: target * len(CLASS_LABELS) for partition, target in PARTITION_TARGETS.items()
    }
    if dict(partition_counts) != expected_partition_counts:
        errors.append(f"partition counts mismatch: {dict(partition_counts)}")
    for partition, target in PARTITION_TARGETS.items():
        for category in CLASS_LABELS:
            if class_by_partition[(partition, category)] != target:
                errors.append(
                    f"expected {target} {category} rows in {partition}, "
                    f"found {class_by_partition[(partition, category)]}"
                )
    if errors:
        raise PartitionValidationError("; ".join(errors))

    return {
        "partition_counts": dict(partition_counts),
        "class_by_partition": dict(class_by_partition),
        "total_assigned": len(assignments),
    }


def audit_diversity(assignments: list[dict[str, str]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for partition in PARTITION_TARGETS:
        partition_rows = [row for row in assignments if row["partition"] == partition]
        durations = [_number(row.get("duration_minutes")) for row in partition_rows]
        durations = [duration for duration in durations if duration is not None]
        rows.append(
            {
                "partition": partition,
                "incident_count": str(len(partition_rows)),
                "year_count": str(len({_year(row) for row in partition_rows})),
                "asn_bucket_count": str(len({_asn_bucket(row) for row in partition_rows})),
                "country_count": str(len({_first_jsonish_value(row.get("countries")) for row in partition_rows})),
                "prefix_bucket_count": str(len({_prefix_bucket(row) for row in partition_rows})),
                "median_duration_minutes": str(round(_median(durations), 2)) if durations else "",
            }
        )
    return rows


def _median(values: list[float]) -> float:
    ordered = sorted(values)
    midpoint = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[midpoint]
    return (ordered[midpoint - 1] + ordered[midpoint]) / 2


def manifest_rows(assignments: Iterable[dict[str, str]], seed: int = RANDOM_SEED) -> list[dict[str, str]]:
    manifest: list[dict[str, str]] = []
    for row in assignments:
        manifest.append(
            {
                "incident_uid": row[INCIDENT_UID_FIELD],
                "incident_id": row["incident_id"],
                "category": row["category"],
                "partition": row["partition"],
                "start_utc": row.get("start_utc", ""),
                "end_utc": row.get("end_utc", ""),
                "duration_minutes": row.get("duration_minutes", ""),
                "random_seed": str(seed),
                "split_version": SPLIT_VERSION,
            }
        )
    return sorted(manifest, key=lambda row: (row["partition"], row["category"], row["start_utc"], row["incident_id"]))


def write_outputs(assignments: list[dict[str, str]], output_dir: Path = PARTITION_DIR, seed: int = RANDOM_SEED) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    fieldnames = list(assignments[0].keys())
    for partition, filename in (
        ("train", "train_incidents.csv"),
        ("validation", "validation_incidents.csv"),
        ("holdout", "holdout_incidents.csv"),
    ):
        partition_rows = [row for row in assignments if row["partition"] == partition]
        _write_csv(output_dir / filename, partition_rows, fieldnames)

    manifest_fieldnames = [
        "incident_uid",
        "incident_id",
        "category",
        "partition",
        "start_utc",
        "end_utc",
        "duration_minutes",
        "random_seed",
        "split_version",
    ]
    _write_csv(output_dir / "frozen_partition_manifest.csv", manifest_rows(assignments, seed), manifest_fieldnames)


def _write_csv(path: Path, rows: list[dict[str, str]], fieldnames: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def overlap_report(assignments: list[dict[str, str]]) -> dict[str, int]:
    ids_by_partition = {
        partition: {row[INCIDENT_UID_FIELD] for row in assignments if row["partition"] == partition}
        for partition in PARTITION_TARGETS
    }
    return {
        "TRAIN ∩ VALIDATION": len(ids_by_partition["train"] & ids_by_partition["validation"]),
        "TRAIN ∩ HOLDOUT": len(ids_by_partition["train"] & ids_by_partition["holdout"]),
        "VALIDATION ∩ HOLDOUT": len(ids_by_partition["validation"] & ids_by_partition["holdout"]),
    }


def print_audit(assignments: list[dict[str, str]], source_rows: list[dict[str, str]]) -> None:
    validate_split(assignments, source_rows)
    print("PASS: roster validation and frozen partition checks succeeded")
    print("Partition counts:")
    for partition, count in Counter(row["partition"] for row in assignments).items():
        print(f"  {partition}: {count}")
    print("Per-class counts:")
    counts = Counter((row["partition"], row["category"]) for row in assignments)
    for partition in PARTITION_TARGETS:
        for category in CLASS_LABELS:
            print(f"  {partition} {category}: {counts[(partition, category)]}")
    print("Overlap checks:")
    for label, count in overlap_report(assignments).items():
        print(f"  {label} = {count} incidents")
    print("Diversity audit:")
    for row in audit_diversity(assignments):
        print(f"  {row}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Freeze incident-level train/validation/holdout partitions.")
    parser.add_argument("--roster", type=Path, default=ROSTER_PATH)
    parser.add_argument("--output-dir", type=Path, default=PARTITION_DIR)
    parser.add_argument("--seed", type=int, default=RANDOM_SEED)
    args = parser.parse_args()

    rows = load_roster(args.roster)
    validate_roster(rows)
    assignments = split_incidents(rows, seed=args.seed)
    validate_split(assignments, rows)
    write_outputs(assignments, args.output_dir, seed=args.seed)
    print_audit(assignments, rows)


if __name__ == "__main__":
    main()
