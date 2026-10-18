from __future__ import annotations

import pandas as pd

from bgp_incident_detection.k1_incident_stacking import (
    HIGH_CONFIDENCE_THRESHOLD,
    LOW_MARGIN_THRESHOLD,
    build_meta_frame,
    load_candidate_config,
    param_hash,
    simple_feature_names,
    temporal_feature_names,
    temporal_segment_positions,
)


def test_k1_uses_locked_phase_i2_xgboost_candidate() -> None:
    candidate = load_candidate_config()

    assert candidate["candidate_id"] == "XGB_REFINED_TRAIN_CANDIDATE"
    assert candidate["feature_count"] == 74
    assert candidate["selected_hyperparameters"]["n_estimators"] == 600
    assert candidate["selected_hyperparameters"]["max_depth"] == 6
    assert candidate["selected_hyperparameters"]["learning_rate"] == 0.125


def test_k1_predeclared_confidence_thresholds_are_fixed() -> None:
    assert LOW_MARGIN_THRESHOLD == 0.10
    assert HIGH_CONFIDENCE_THRESHOLD == 0.80


def test_temporal_segment_positions_are_deterministic() -> None:
    assert temporal_segment_positions(1) == ["EARLY"]
    assert temporal_segment_positions(2) == ["EARLY", "LATE"]
    assert temporal_segment_positions(5) == ["EARLY", "EARLY", "MIDDLE", "MIDDLE", "LATE"]


def test_build_meta_frame_creates_one_row_per_incident_and_preserves_fold() -> None:
    oof = pd.DataFrame(
        {
            "incident_uid": ["a", "a", "b", "b", "b"],
            "window_id": ["a1", "a2", "b1", "b2", "b3"],
            "window_start": pd.date_range("2025-01-01", periods=5, freq="5min").astype(str),
            "window_end": pd.date_range("2025-01-01 00:05", periods=5, freq="5min").astype(str),
            "temporal_status": ["ACTIVE"] * 5,
            "fold": [1, 1, 2, 2, 2],
            "true_class": ["HIJACK", "HIJACK", "LEAK", "LEAK", "LEAK"],
            "p_hijack": [0.8, 0.7, 0.2, 0.1, 0.2],
            "p_leak": [0.1, 0.2, 0.7, 0.8, 0.7],
            "p_outage": [0.1, 0.1, 0.1, 0.1, 0.1],
        }
    )
    structural = pd.DataFrame({"window_id": ["a1", "a2", "b1", "b2", "b3"], "raw_observation_count": [1, 0, 5, 5, 0]})

    meta = build_meta_frame(oof, structural)

    assert len(meta) == 2
    assert meta["incident_uid"].is_unique
    assert meta.set_index("incident_uid").loc["a", "fold"] == 1
    assert meta.set_index("incident_uid").loc["b", "window_count"] == 3
    assert "hijack_prob_mean" in meta.columns
    assert "early_hijack_prob_mean" in meta.columns


def test_simple_feature_set_excludes_temporal_trajectory_features() -> None:
    meta = pd.DataFrame(
        columns=[
            "incident_uid",
            "true_class",
            "fold",
            "window_count",
            "hijack_prob_mean",
            "early_hijack_prob_mean",
            "late_minus_early_hijack_prob_mean",
            "hijack_prob_linear_slope",
        ]
    )

    simple = simple_feature_names(meta)
    temporal = temporal_feature_names(meta)

    assert "window_count" in simple
    assert "hijack_prob_mean" in simple
    assert "early_hijack_prob_mean" not in simple
    assert "late_minus_early_hijack_prob_mean" not in simple
    assert "hijack_prob_linear_slope" not in simple
    assert "early_hijack_prob_mean" in temporal


def test_parameter_hash_is_order_invariant() -> None:
    assert param_hash({"a": 1, "b": 2}) == param_hash({"b": 2, "a": 1})
