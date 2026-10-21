from __future__ import annotations

import inspect
import json
import sys
from pathlib import Path

import pandas as pd
import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection import rf_refinement_stability as h2  # noqa: E402


def test_h2_scope_constants_are_locked():
    assert h2.FEATURE_VARIANT == "V4"
    assert h2.FEATURE_COUNT == 74
    assert h2.IMBALANCE_CONDITION == "I1"
    assert h2.ARCHITECTURE == "RF_MULTICLASS_STAGE2"
    assert h2.LOCAL_SEARCH_BUDGET == 25
    assert h2.RF_STABILITY_SEEDS == [20260828, 20260829, 20260830, 20260831, 20260901]


def test_local_candidates_include_phase_h_winner_and_respect_budget():
    candidates = h2.local_parameter_candidates(budget=8, seed=h2.LOCAL_SEARCH_SEED)

    assert len(candidates) == 8
    assert candidates[0] == h2.PHASE_H_WINNER
    assert all(candidate["bootstrap"] is False for candidate in candidates)
    assert len({h2.parameter_hash(candidate) for candidate in candidates}) == 8


def test_local_budget_cannot_exceed_25():
    with pytest.raises(ValueError):
        h2.local_parameter_candidates(budget=26)


def test_train_data_is_train_only_incident_only_and_same_grouped_folds():
    data = h2.load_stage2_train_data()

    assert set(data["partition"].astype(str)) == {"train"}
    assert set(data["label"].unique()) == set(h2.INCIDENT_LABELS)
    assert len(h2.FEATURES_BY_VARIANT["V4"]) == 74
    assert data.groupby("model_group_id")["fold"].nunique().max() == 1


def test_rf_pipeline_has_no_class_weight_and_seed_controls_rf_only():
    pipeline = h2.rf_pipeline(h2.PHASE_H_WINNER, rf_seed=20260831)
    model = pipeline.named_steps["model"]

    assert model.class_weight is None
    assert model.random_state == 20260831
    assert model.bootstrap is False


def test_incident_aggregation_is_mean_probability():
    scores = pd.DataFrame(
        {
            "candidate_id": ["c1", "c1"],
            "parameter_hash": ["h1", "h1"],
            "rf_seed": [20260828, 20260828],
            "incident_uid": ["i1", "i1"],
            "fold": [1, 1],
            "true_class": ["OUTAGE", "OUTAGE"],
            "p_hijack": [0.1, 0.3],
            "p_leak": [0.4, 0.2],
            "p_outage": [0.5, 0.5],
        }
    )
    aggregated = h2.aggregate_incident_scores(scores)

    assert aggregated["p_hijack"].iloc[0] == pytest.approx(0.2)
    assert aggregated["p_leak"].iloc[0] == pytest.approx(0.3)
    assert aggregated["p_outage"].iloc[0] == pytest.approx(0.5)


def test_refined_config_records_no_validation_holdout_and_xgboost_pending(tmp_path, monkeypatch):
    out = tmp_path / "candidate.yaml"
    monkeypatch.setattr(h2, "REFINED_CONFIG", out)
    selected = pd.Series(
        {
            "candidate_id": "PHASE_H_WINNER",
            "parameters_json": json.dumps(h2.PHASE_H_WINNER),
            "mean_incident_macro_f1": 0.78,
            "std_incident_macro_f1": 0.01,
            "mean_mrr": 0.88,
            "mean_top2": 0.93,
            "mean_top1": 0.78,
            "hijack_f1_mean": 0.72,
            "leak_f1_mean": 0.84,
            "outage_f1_mean": 0.79,
            "window_macro_f1_mean": 0.68,
            "mean_fit_time_seconds": 220.0,
        }
    )

    h2.write_refined_config(selected, "NO_MEANINGFUL_IMPROVEMENT", "KEEP_PHASE_H_RF")
    text = out.read_text(encoding="utf-8")

    assert "RF_REFINED_TRAIN_CANDIDATE" in text
    assert "validation_accessed: false" in text
    assert "final_holdout_accessed: false" in text
    assert "phase_i_xgboost_pending: true" in text


def test_no_validation_holdout_or_xgboost_training_paths_or_imports():
    source = inspect.getsource(h2).lower()

    assert "validation_incidents_v2.csv" not in source
    assert "holdout_incidents_v2.csv" not in source
    assert "import xgboost" not in source
    assert "xgbclassifier" not in source
