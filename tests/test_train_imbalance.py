from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES  # noqa: E402
from bgp_incident_detection.train_imbalance import (  # noqa: E402
    BEHAVIORAL_FEATURE_COUNT,
    add_incident_weights,
    apply_cap,
    cap_rows_for_incident,
    compare_strategies,
    review_incidents,
)


def test_review_incidents_are_exactly_ten_train_reviews():
    rows = review_incidents()
    assert len(rows) == 10
    assert {row["status"] for row in rows} == {"REVIEW"}


def test_incident_weights_sum_equally_per_incident():
    df = pd.DataFrame({"incident_uid": ["a", "a", "b"], "category": ["Hijack", "Hijack", "Leak"]})
    weighted = add_incident_weights(df)
    totals = weighted.groupby("incident_uid")["row_weight"].sum().round(6).to_dict()
    assert totals == {"a": 1.0, "b": 1.0}


def test_cap_sampling_preserves_onset_middle_end():
    df = pd.DataFrame({"window_start": [f"2025-01-01T00:{i:02d}:00Z" for i in range(20)], "value": range(20)})
    sampled = cap_rows_for_incident(df, 5)
    values = set(sampled["value"])
    assert 0 in values
    assert 10 in values
    assert 19 in values


def test_apply_cap_retains_all_incidents_without_partition_moves():
    df = pd.DataFrame(
        {
            "incident_uid": ["a"] * 5 + ["b"] * 2,
            "window_start": list(range(5)) + list(range(2)),
            "partition": ["train"] * 7,
            "category": ["Hijack"] * 7,
        }
    )
    capped = apply_cap(df, 3)
    assert capped["incident_uid"].nunique() == 2
    assert set(capped["partition"]) == {"train"}
    assert len(capped) == 5


def test_strategy_comparison_uses_frozen_schema_and_percentile_caps():
    rows = compare_strategies()
    assert len(BEHAVIORAL_FEATURE_NAMES) == BEHAVIORAL_FEATURE_COUNT == 44
    cap_defs = {row["cap_definition"] for row in rows}
    assert {"global_p90", "global_p95", "global_p99"} <= cap_defs
    assert all("weight" not in BEHAVIORAL_FEATURE_NAMES for _ in [0])
