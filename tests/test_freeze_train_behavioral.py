from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES  # noqa: E402
from bgp_incident_detection.freeze_train_behavioral import (  # noqa: E402
    EXPECTED_CLASS_COUNTS,
    EXPECTED_FEATURE_COUNT,
    EXPECTED_INCIDENTS,
    EXPECTED_ROWS,
    add_freeze_metadata,
    assert_feature_values_unchanged,
    validate_source,
)


def test_validate_source_accepts_resolved_train_v2_corpus():
    df = pd.read_parquet(ROOT / "data/train_scale/train_incident_behavioral_features_v2.parquet")
    audit_rows = validate_source(df)
    assert len(df) == EXPECTED_ROWS
    assert df["incident_uid"].nunique() == EXPECTED_INCIDENTS
    assert df.groupby("category")["incident_uid"].nunique().to_dict() == EXPECTED_CLASS_COUNTS
    assert {row["status"] for row in audit_rows} == {"PASS"}


def test_freeze_metadata_does_not_change_existing_values():
    df = pd.DataFrame(
        {
            "incident_uid": ["Hijack:1"],
            "window_id": ["Hijack:1_20240101T000000Z"],
            "category": ["Hijack"],
            "partition": ["train"],
            "update_count": [5],
        }
    )
    frozen = add_freeze_metadata(df, "2026-08-31T00:00:00Z", "abc123")
    assert_feature_values_unchanged(df, frozen)
    assert frozen.loc[0, "train_corpus_version"] == "v1"
    assert frozen.loc[0, "corpus_status"] == "FROZEN"


def test_behavioral_feature_inventory_is_frozen_at_44():
    assert len(BEHAVIORAL_FEATURE_NAMES) == EXPECTED_FEATURE_COUNT == 44
    forbidden = {"sample_weight", "row_weight", "window_cap", "cap_strategy"}
    assert forbidden.isdisjoint(BEHAVIORAL_FEATURE_NAMES)
    assert not any(name.startswith(("caida_", "rpki_", "rov_")) for name in BEHAVIORAL_FEATURE_NAMES)
