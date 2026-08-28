from __future__ import annotations

import csv
import hashlib
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.resolve_roster_quality_questions import run_resolution  # noqa: E402


PARTITION_DIR = ROOT / "data/partitions"
REVIEW_DIR = ROOT / "data/review"


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_resolution_does_not_modify_frozen_manifest() -> None:
    manifest = PARTITION_DIR / "frozen_partition_manifest.csv"
    before = _hash(manifest)
    run_resolution(PARTITION_DIR, REVIEW_DIR)
    after = _hash(manifest)
    assert before == after


def test_timestamp_semantics_resolution_has_one_row_per_category() -> None:
    run_resolution(PARTITION_DIR, REVIEW_DIR)
    rows = _read_csv(REVIEW_DIR / "timestamp_semantics_resolution.csv")
    assert {row["category"] for row in rows} == {"Hijack", "Leak", "Outage"}
    assert len(rows) == 3


def test_duplicate_resolution_keeps_all_candidate_groups_as_recommendations() -> None:
    run_resolution(PARTITION_DIR, REVIEW_DIR)
    source_groups = _read_csv(REVIEW_DIR / "duplicate_candidate_groups.csv")
    resolved_groups = _read_csv(REVIEW_DIR / "duplicate_resolution_recommendations.csv")
    assert len(resolved_groups) == len(source_groups) == 120
    assert all(row["recommended_action"] for row in resolved_groups)


def test_incident_window_recommendations_cover_all_incidents() -> None:
    run_resolution(PARTITION_DIR, REVIEW_DIR)
    rows = _read_csv(REVIEW_DIR / "incident_window_resolution_recommendations.csv")
    assert len(rows) == 1419
    assert len({row["incident_uid"] for row in rows}) == 1419
