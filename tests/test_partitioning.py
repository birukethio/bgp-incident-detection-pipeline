from __future__ import annotations

import csv
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.partitioning import (  # noqa: E402
    CLASS_LABELS,
    PARTITION_TARGETS,
    RANDOM_SEED,
    incident_uid,
    load_roster,
    split_incidents,
    validate_split,
)


PARTITION_DIR = ROOT / "data/partitions"
ROSTER_PATH = ROOT / "cloudflare_incidents/balanced_incident_level_roster_473_each_leak_hijack_outage.csv"


def _read_partition(name: str) -> list[dict[str, str]]:
    with (PARTITION_DIR / f"{name}_incidents.csv").open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_no_cross_partition_incident_overlap() -> None:
    ids_by_partition = {
        partition: {row["incident_uid"] for row in _read_partition(partition)}
        for partition in PARTITION_TARGETS
    }

    assert ids_by_partition["train"].isdisjoint(ids_by_partition["validation"])
    assert ids_by_partition["train"].isdisjoint(ids_by_partition["holdout"])
    assert ids_by_partition["validation"].isdisjoint(ids_by_partition["holdout"])


def test_exact_expected_counts() -> None:
    for partition, per_class_target in PARTITION_TARGETS.items():
        rows = _read_partition(partition)
        assert len(rows) == per_class_target * len(CLASS_LABELS)
        class_counts = Counter(row["category"] for row in rows)
        assert class_counts == {category: per_class_target for category in CLASS_LABELS}


def test_each_incident_appears_once() -> None:
    source_rows = load_roster(ROSTER_PATH)
    partition_rows = []
    for partition in PARTITION_TARGETS:
        partition_rows.extend(_read_partition(partition))

    source_ids = {incident_uid(row) for row in source_rows}
    partition_ids = [row["incident_uid"] for row in partition_rows]

    assert len(partition_ids) == len(source_ids) == 1419
    assert set(partition_ids) == source_ids
    assert not [incident_id for incident_id, count in Counter(partition_ids).items() if count > 1]


def test_reproducibility_using_same_random_seed() -> None:
    source_rows = load_roster(ROSTER_PATH)
    first = split_incidents(source_rows, seed=RANDOM_SEED)
    second = split_incidents(source_rows, seed=RANDOM_SEED)

    first_assignment = [(row["incident_uid"], row["category"], row["partition"]) for row in first]
    second_assignment = [(row["incident_uid"], row["category"], row["partition"]) for row in second]

    assert first_assignment == second_assignment
    validate_split(first, source_rows)
