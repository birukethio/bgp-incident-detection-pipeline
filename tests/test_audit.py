from __future__ import annotations

import csv
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.audit import (  # noqa: E402
    PARTITION_FILES,
    file_hashes,
    partition_file_paths,
    possible_duplicates,
    run_audit,
)
from bgp_incident_detection.partitioning import CLASS_LABELS, PARTITION_TARGETS  # noqa: E402


PARTITION_DIR = ROOT / "data/partitions"


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _partition_rows() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for filename in PARTITION_FILES.values():
        rows.extend(_read_csv(PARTITION_DIR / filename))
    return rows


def test_audit_does_not_modify_frozen_partition_files() -> None:
    paths = partition_file_paths(PARTITION_DIR)
    before = file_hashes(paths)
    run_audit(PARTITION_DIR)
    after = file_hashes(paths)
    assert before == after


def test_duplicate_detection_does_not_silently_merge_records() -> None:
    rows = _partition_rows()
    before_count = len(rows)
    duplicate_pairs = possible_duplicates(rows)
    after_count = len(rows)

    assert before_count == after_count == 1419
    assert duplicate_pairs
    assert all(row["recommended_action"] == "manual_review_do_not_merge_automatically" for row in duplicate_pairs)


def test_partition_counts_remain_unchanged_after_audit() -> None:
    run_audit(PARTITION_DIR)
    rows = _partition_rows()
    partition_counts = Counter(row["partition"] for row in rows)
    class_partition_counts = Counter((row["partition"], row["category"]) for row in rows)

    assert partition_counts == {
        partition: target * len(CLASS_LABELS)
        for partition, target in PARTITION_TARGETS.items()
    }
    for partition, target in PARTITION_TARGETS.items():
        for category in CLASS_LABELS:
            assert class_partition_counts[(partition, category)] == target


def test_all_incidents_appear_in_quality_audit_output() -> None:
    run_audit(PARTITION_DIR)
    quality_rows = _read_csv(PARTITION_DIR / "incident_quality_audit_v1.csv")
    partition_uids = {row["incident_uid"] for row in _partition_rows()}
    quality_uids = [row["incident_uid"] for row in quality_rows]

    assert len(quality_rows) == 1419
    assert set(quality_uids) == partition_uids
    assert len(quality_uids) == len(set(quality_uids))
