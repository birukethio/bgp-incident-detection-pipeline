from __future__ import annotations

import csv
import hashlib
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.review_triage import run_triage  # noqa: E402


PARTITION_DIR = ROOT / "data/partitions"
REVIEW_DIR = ROOT / "data/review"


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_triage_does_not_modify_frozen_partition_manifest() -> None:
    manifest = PARTITION_DIR / "frozen_partition_manifest.csv"
    before = _hash(manifest)
    run_triage(PARTITION_DIR, REVIEW_DIR)
    after = _hash(manifest)
    assert before == after


def test_triage_does_not_change_partition_counts_or_assignments() -> None:
    before = _read_csv(PARTITION_DIR / "frozen_partition_manifest.csv")
    run_triage(PARTITION_DIR, REVIEW_DIR)
    after = _read_csv(PARTITION_DIR / "frozen_partition_manifest.csv")

    assert before == after
    assert Counter(row["partition"] for row in after) == {"train": 993, "validation": 213, "holdout": 213}
    assert Counter((row["partition"], row["category"]) for row in after)[("train", "Hijack")] == 331
    assert Counter((row["partition"], row["category"]) for row in after)[("validation", "Leak")] == 71
    assert Counter((row["partition"], row["category"]) for row in after)[("holdout", "Outage")] == 71


def test_review_reason_output_covers_current_review_incidents() -> None:
    results = run_triage(PARTITION_DIR, REVIEW_DIR)
    reason_rows = _read_csv(REVIEW_DIR / "incident_review_reasons.csv")
    quality_rows = _read_csv(PARTITION_DIR / "incident_quality_audit_v1.csv")
    reviewed_uids = {row["incident_uid"] for row in quality_rows if row["quality_status"] == "REVIEW"}

    assert len(reason_rows) == 820
    assert {row["incident_uid"] for row in reason_rows} == reviewed_uids
    assert len(results["incident_review_reasons"]) == len(reason_rows)


def test_duplicate_pair_triage_preserves_candidate_pairs_without_merging() -> None:
    results = run_triage(PARTITION_DIR, REVIEW_DIR)
    original_pairs = _read_csv(PARTITION_DIR / "possible_duplicate_incidents.csv")
    triage_pairs = _read_csv(REVIEW_DIR / "duplicate_pair_triage.csv")

    assert len(triage_pairs) == len(original_pairs) == 389
    assert {row["recommended_action"] for row in triage_pairs} == {"manual_review_do_not_merge"}
    assert Counter(row["duplicate_triage"] for row in triage_pairs)
