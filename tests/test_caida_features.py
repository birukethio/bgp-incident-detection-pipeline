from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.caida_features import (  # noqa: E402
    CAIDA_FEATURE_NAMES,
    aggregate_rows,
    caida_snapshot_name,
    caida_snapshot_url,
    parse_as_path,
    relationship_sequence,
    selected_snapshot_for_window,
    valley_free_result,
)


def test_caida_snapshot_mapping_is_deterministic_monthly_serial2():
    dt = datetime(2025, 3, 31, 8, 47, tzinfo=timezone.utc)
    assert caida_snapshot_name(dt) == "20250301.as-rel2.txt.bz2"
    assert caida_snapshot_url(dt).endswith("/serial-2/20250301.as-rel2.txt.bz2")
    snapshot, url, reason = selected_snapshot_for_window("2025-03-31T08:47:02.000Z")
    assert snapshot == "20250301.as-rel2.txt.bz2"
    assert "serial-2" in url
    assert "same-month" in reason


def test_as_path_parser_collapses_prepending():
    assert parse_as_path("1 2 2 2 3 {4,5}") == ["1", "2", "3", "4", "5"]


def test_relationship_encoding_and_valley_free_logic():
    relationships = {
        ("1", "2"): "c2p",
        ("2", "3"): "p2p",
        ("3", "4"): "p2c",
        ("4", "5"): "p2c",
        ("3", "2"): "p2p",
        ("2", "1"): "p2c",
    }
    assert relationship_sequence("1 2 3 4", relationships) == ["c2p", "p2p", "p2c"]
    valid = valley_free_result("1 2 3 4 5", relationships)
    assert valid.violation_count == 0
    assert valid.unknown_transition_count == 0
    violation = valley_free_result("1 2 3 2 1", relationships)
    assert violation.violation_count > 0


def test_unknown_relationship_is_not_counted_valid_or_violation():
    result = valley_free_result("1 9 10", {})
    assert result.unknown_transition_count == 2
    assert result.violation_count == 0
    features = aggregate_rows([{"as_path": "1 9 10"}], {})
    assert features["caida_paths_with_unknown_relationship_count"] == 1
    assert features["caida_valley_free_valid_path_count"] == 0
    assert features["caida_valley_free_violation_path_count"] == 0


def test_no_path_state_is_distinct_from_unknown_relationship():
    features = aggregate_rows([{"as_path": ""}, {"as_path": "6453"}], {})
    assert features["caida_path_observation_count"] == 0
    assert features["caida_paths_with_no_as_path_count"] == 2
    assert features["caida_paths_with_unknown_relationship_count"] == 0


def test_recommended_caida_feature_count_is_exact():
    assert len(CAIDA_FEATURE_NAMES) == 14
    assert all(name.startswith("caida_") for name in CAIDA_FEATURE_NAMES)
