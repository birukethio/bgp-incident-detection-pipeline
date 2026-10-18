from __future__ import annotations

import inspect
import json
import sys
from pathlib import Path

import pandas as pd
import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection import xgboost_algorithm_comparison as phase_i  # noqa: E402


def test_phase_i_scope_constants_are_locked():
    assert phase_i.FEATURE_VARIANT == "V4"
    assert phase_i.FEATURE_COUNT == 74
    assert phase_i.IMBALANCE_CONDITION == "I1"
    assert phase_i.SEARCH_BUDGET == 40
    assert phase_i.SEARCH_SEED == 20260828
    assert phase_i.XGB_STABILITY_SEEDS == [20260828, 20260829, 20260830, 20260831, 20260901]
    assert phase_i.RF_COMPARATOR_ID == "RF_REFINED_TRAIN_CANDIDATE"
    assert phase_i.STAGE1_STATUS == "UNRESOLVED_EXPERIMENTAL_AUXILIARY"


def test_h2_rf_reference_is_the_required_comparator():
    assert phase_i.RF_REFINED_PARAMS["n_estimators"] == 1200
    assert phase_i.RF_REFINED_PARAMS["max_depth"] == 40
    assert phase_i.RF_REFINED_PARAMS["max_features"] == 0.3
    assert phase_i.RF_REFINED_PARAMS["min_samples_leaf"] == 6
    assert phase_i.RF_REFINED_PARAMS["min_samples_split"] == 6
    assert phase_i.RF_REFINED_PARAMS["bootstrap"] is False
    assert phase_i.RF_REFINED_PARAMS["criterion"] == "log_loss"
    assert phase_i.RF_REFINED_REFERENCE["incident_macro_f1"] == pytest.approx(0.784588)
    assert phase_i.RF_REFINED_REFERENCE["mrr"] == pytest.approx(0.882578)
    assert phase_i.RF_REFINED_REFERENCE["top2"] == pytest.approx(0.932931)
    assert phase_i.RF_REFINED_SOURCE_CANDIDATE_ID == "H2_LOCAL_001"


def test_rf_fold_reference_uses_h2_refined_candidate_when_available():
    folds = phase_i.rf_fold_reference()

    if folds.empty:
        pytest.skip("RF H2 fold artifact is not present in this test fixture")
    assert set(folds["fold"]) == {1, 2, 3, 4, 5}
    assert "incident_macro_f1" in folds.columns


def test_xgboost_environment_records_version_and_install_command():
    env = phase_i.xgboost_environment()

    assert list(env["package"]) == ["xgboost"]
    assert "python -m pip install xgboost" in env["installation_command"].iloc[0]
    assert "python_version" in env.columns
    assert "platform" in env.columns


def test_parameter_candidates_respect_fixed_budget_and_include_baseline():
    candidates = phase_i.parameter_candidates(search_budget=8, seed=phase_i.SEARCH_SEED)

    assert len(candidates) == 8
    assert candidates[0] == phase_i.BASELINE_PARAMS
    assert len({phase_i.parameter_hash(candidate) for candidate in candidates}) == 8


def test_search_budget_cannot_exceed_40():
    with pytest.raises(ValueError):
        phase_i.parameter_candidates(search_budget=41)


def test_train_data_is_train_only_incident_only_v4_and_same_grouped_folds():
    data = phase_i.load_stage2_train_data()

    assert set(data["partition"].astype(str)) == {"train"}
    assert set(data["label"].unique()) == set(phase_i.INCIDENT_LABELS)
    assert len(phase_i.FEATURES_BY_VARIANT["V4"]) == 74
    assert data.groupby("model_group_id")["fold"].nunique().max() == 1


def test_incident_aggregation_is_mean_probability():
    scores = pd.DataFrame(
        {
            "candidate_id": ["c1", "c1"],
            "parameter_hash": ["h1", "h1"],
            "xgb_seed": [20260828, 20260828],
            "incident_uid": ["i1", "i1"],
            "fold": [1, 1],
            "true_class": ["LEAK", "LEAK"],
            "p_hijack": [0.1, 0.3],
            "p_leak": [0.7, 0.5],
            "p_outage": [0.2, 0.2],
        }
    )
    aggregated = phase_i.aggregate_incident_scores(scores)

    assert aggregated["p_hijack"].iloc[0] == pytest.approx(0.2)
    assert aggregated["p_leak"].iloc[0] == pytest.approx(0.6)
    assert aggregated["p_outage"].iloc[0] == pytest.approx(0.2)


def test_label_codes_follow_incident_label_order():
    labels = pd.Series(["HIJACK", "LEAK", "OUTAGE"])

    assert phase_i.label_codes(labels).tolist() == [0, 1, 2]


def test_final_decision_prefers_rf_for_tiny_tie():
    comparison = pd.DataFrame(
        [
            {"algorithm": "RandomForest", "incident_macro_f1": 0.784, "mrr": 0.882, "top2": 0.933},
            {"algorithm": "XGBoost", "incident_macro_f1": 0.786, "mrr": 0.883, "top2": 0.932},
        ]
    )
    decision, _ = phase_i.final_decision(comparison)

    assert decision == "ALGORITHMS_EFFECTIVELY_TIED_PREFER_SIMPLER"


def test_no_validation_holdout_stage1_or_alternative_boosters():
    source = inspect.getsource(phase_i).lower()

    assert "validation_incidents_v2.csv" not in source
    assert "holdout_incidents_v2.csv" not in source
    assert "lightgbm" not in source
    assert "catboost" not in source
    assert "stage1_status" in source
