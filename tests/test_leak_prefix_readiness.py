from __future__ import annotations

import csv
import hashlib
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.resolve_leak_prefix_readiness import run_resolution  # noqa: E402


ROSTER_V2_DIR = ROOT / "data/roster_v2"
V2_ROSTER = ROSTER_V2_DIR / "balanced_incident_roster_v2.csv"


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_leak_prefix_resolution_does_not_modify_v2_roster() -> None:
    before = _hash(V2_ROSTER)
    run_resolution(V2_ROSTER, ROSTER_V2_DIR)
    after = _hash(V2_ROSTER)
    assert before == after


def test_leak_prefix_recovery_audit_has_one_row_per_v2_leak() -> None:
    run_resolution(V2_ROSTER, ROSTER_V2_DIR)
    rows = _read_csv(ROSTER_V2_DIR / "leak_prefix_recovery_audit.csv")
    assert len(rows) == 473
    assert {row["recovery_status"] for row in rows} == {"NOT_RECOVERABLE_FROM_LOCAL_CLOUDFLARE_ARTIFACTS"}


def test_freeze_readiness_recommends_freeze_without_changing_split() -> None:
    run_resolution(V2_ROSTER, ROSTER_V2_DIR)
    rows = _read_csv(ROSTER_V2_DIR / "roster_v2_freeze_readiness.csv")
    assert len(rows) == 1
    assert rows[0]["leak_prefix_disposition"] == "PASS_NOT_REQUIRED"
    assert rows[0]["remaining_blockers"] == "none"
    assert rows[0]["recommendation"] == "FREEZE"


def test_policy_document_exists_and_separates_labeling_from_feature_extraction() -> None:
    run_resolution(V2_ROSTER, ROSTER_V2_DIR)
    text = (ROSTER_V2_DIR / "leak_event_identification_policy_v1.md").read_text(encoding="utf-8")
    assert "Incident Identification" in text
    assert "Feature Extraction" in text
    assert "Ground-Truth Labeling" in text
    assert "Do not invent missing prefixes" in text
