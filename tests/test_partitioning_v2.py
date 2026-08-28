from __future__ import annotations

import csv
import hashlib
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.partitioning_v2 import (  # noqa: E402
    CLASS_LABELS,
    FROZEN_ROSTER,
    PARTITION_TARGETS,
    PARTITION_V2_DIR,
    RANDOM_SEED,
    split_roster,
    validate_roster,
    validate_split,
)


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_partition(partition: str) -> list[dict[str, str]]:
    return _read_csv(ROOT / PARTITION_V2_DIR / f"{partition}_incidents_v2.csv")


def test_frozen_roster_contains_expected_incidents() -> None:
    rows = _read_csv(ROOT / FROZEN_ROSTER)

    assert len(rows) == 1419
    assert len({row["incident_uid"] for row in rows}) == 1419
    assert Counter(row["category"] for row in rows) == {"Hijack": 473, "Leak": 473, "Outage": 473}
    assert {row["roster_version"] for row in rows} == {"v2"}
    assert {row["roster_status"] for row in rows} == {"FROZEN"}
    validate_roster(rows)


def test_v2_partition_counts_and_class_balance() -> None:
    for partition, per_class_target in PARTITION_TARGETS.items():
        rows = _read_partition(partition)
        assert len(rows) == per_class_target * len(CLASS_LABELS)
        assert Counter(row["category"] for row in rows) == {
            category: per_class_target for category in CLASS_LABELS
        }


def test_no_cross_partition_overlap_and_each_incident_once() -> None:
    rows_by_partition = {
        partition: _read_partition(partition)
        for partition in PARTITION_TARGETS
    }
    ids_by_partition = {
        partition: {row["incident_uid"] for row in rows}
        for partition, rows in rows_by_partition.items()
    }
    all_partition_rows = [
        row
        for rows in rows_by_partition.values()
        for row in rows
    ]
    frozen_rows = _read_csv(ROOT / FROZEN_ROSTER)

    assert ids_by_partition["train"].isdisjoint(ids_by_partition["validation"])
    assert ids_by_partition["train"].isdisjoint(ids_by_partition["holdout"])
    assert ids_by_partition["validation"].isdisjoint(ids_by_partition["holdout"])
    assert len(all_partition_rows) == 1419
    assert set(row["incident_uid"] for row in all_partition_rows) == {
        row["incident_uid"] for row in frozen_rows
    }
    assert not [
        incident_uid
        for incident_uid, count in Counter(row["incident_uid"] for row in all_partition_rows).items()
        if count > 1
    ]
    validate_split(frozen_rows, all_partition_rows)


def test_reproducibility_with_seed_20260828() -> None:
    frozen_rows = _read_csv(ROOT / FROZEN_ROSTER)
    regenerated = split_roster(frozen_rows, seed=RANDOM_SEED)
    manifest = _read_csv(ROOT / PARTITION_V2_DIR / "frozen_partition_manifest_v2.csv")

    regenerated_assignments = {
        row["incident_uid"]: row["partition"]
        for row in regenerated
    }
    manifest_assignments = {
        row["incident_uid"]: row["partition"]
        for row in manifest
    }

    assert regenerated_assignments == manifest_assignments


def test_frozen_roster_is_not_changed_by_partitioning() -> None:
    frozen_path = ROOT / FROZEN_ROSTER
    before = _hash(frozen_path)
    frozen_rows = _read_csv(frozen_path)
    split_roster(frozen_rows, seed=RANDOM_SEED)
    after = _hash(frozen_path)

    assert before == after
