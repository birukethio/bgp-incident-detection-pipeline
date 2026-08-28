from __future__ import annotations

import csv
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.build_roster_v2 import run_build  # noqa: E402


PARTITION_DIR = ROOT / "data/partitions"
REVIEW_DIR = ROOT / "data/review"
ROSTER_V2_DIR = ROOT / "data/roster_v2"


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_v2_build_does_not_modify_v1_frozen_manifest() -> None:
    manifest = PARTITION_DIR / "frozen_partition_manifest.csv"
    before = _hash(manifest)
    run_build(PARTITION_DIR, REVIEW_DIR, ROSTER_V2_DIR)
    after = _hash(manifest)
    assert before == after


def test_v2_roster_reaches_required_class_balance() -> None:
    run_build(PARTITION_DIR, REVIEW_DIR, ROSTER_V2_DIR)
    rows = _read_csv(ROSTER_V2_DIR / "balanced_incident_roster_v2.csv")
    assert len(rows) == 1419
    assert len({row["incident_uid"] for row in rows}) == 1419
    assert Counter(row["category"] for row in rows) == {"Hijack": 473, "Leak": 473, "Outage": 473}
    assert {row["roster_version"] for row in rows} == {"v2"}


def test_noncanonical_true_duplicates_are_excluded_from_v2() -> None:
    run_build(PARTITION_DIR, REVIEW_DIR, ROSTER_V2_DIR)
    plan = _read_csv(ROSTER_V2_DIR / "duplicate_canonicalization_plan.csv")
    v2_uids = {row["incident_uid"] for row in _read_csv(ROSTER_V2_DIR / "balanced_incident_roster_v2.csv")}
    excluded = set()
    canonicals = set()
    for row in plan:
        excluded.update(json.loads(row["records_to_exclude_from_v2"]))
        canonicals.add(row["canonical_incident_uid"])
    assert not (excluded & v2_uids)
    assert canonicals <= v2_uids


def test_replacements_match_duplicate_collapse_deficit() -> None:
    run_build(PARTITION_DIR, REVIEW_DIR, ROSTER_V2_DIR)
    replacements = _read_csv(ROSTER_V2_DIR / "replacement_incidents.csv")
    assert Counter(row["category"] for row in replacements) == {"Hijack": 30, "Leak": 57, "Outage": 9}
    assert len(replacements) == 96
