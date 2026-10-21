from __future__ import annotations

import inspect
import json
import sys
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection import rf_hyperparameter_optimization as rho  # noqa: E402


def test_parameter_candidates_are_fixed_budget_and_include_baseline():
    candidates = rho.parameter_candidates(search_budget=10, seed=rho.SEED)

    assert len(candidates) == 10
    assert candidates[0] == rho.BASELINE_PARAMS
    assert len({rho.parameter_hash(params) for params in candidates}) == 10


def test_train_data_is_incident_train_only_and_reuses_grouped_folds():
    data = rho.load_stage2_train_data()

    assert set(data["partition"].astype(str)) == {"train"}
    assert set(data["label"].unique()) == set(rho.INCIDENT_LABELS)
    assert len(rho.FEATURES_BY_VARIANT["V4"]) == 74
    assert data.groupby("model_group_id")["fold"].nunique().max() == 1


def test_rf_pipeline_keeps_i1_compatible_rf_constraints():
    params = {
        "n_estimators": 400,
        "max_depth": 20,
        "min_samples_split": 5,
        "min_samples_leaf": 2,
        "max_features": "log2",
        "bootstrap": True,
        "criterion": "entropy",
    }
    pipeline = rho.rf_pipeline(params)
    model = pipeline.named_steps["model"]

    assert model.n_estimators == 400
    assert model.max_depth == 20
    assert model.class_weight is None
    assert model.random_state == 20260828


def test_incident_aggregation_uses_mean_probabilities():
    scores = pd.DataFrame(
        {
            "candidate_id": ["c1", "c1"],
            "parameter_hash": ["h1", "h1"],
            "incident_uid": ["i1", "i1"],
            "fold": [1, 1],
            "true_class": ["LEAK", "LEAK"],
            "p_hijack": [0.1, 0.3],
            "p_leak": [0.6, 0.4],
            "p_outage": [0.3, 0.3],
        }
    )
    aggregated = rho.aggregate_incident_scores(scores)

    assert aggregated["p_hijack"].iloc[0] == 0.2
    assert aggregated["p_leak"].iloc[0] == 0.5


def test_candidate_config_records_tuned_candidate_without_overwriting_v1(tmp_path, monkeypatch):
    out = tmp_path / "candidate.yaml"
    monkeypatch.setattr(rho, "TUNED_CANDIDATE_CONFIG", out)
    row = pd.Series(
        {
            "parameters_json": json.dumps(rho.BASELINE_PARAMS),
            "incident_macro_f1": 0.7,
            "incident_mrr": 0.8,
            "incident_top2": 0.9,
            "incident_top1": 0.75,
            "incident_hijack_f1": 0.6,
            "incident_leak_f1": 0.8,
            "incident_outage_f1": 0.7,
            "window_macro_f1": 0.67,
            "incident_macro_f1_fold_std": 0.01,
            "fit_time_seconds": 1.2,
        }
    )

    rho.write_candidate_config(row)
    text = out.read_text(encoding="utf-8")

    assert "RF_TUNED_LOCK_CANDIDATE_V1" in text
    assert "TUNED_TRAIN_CV_CANDIDATE" in text
    assert "feature_variant: \"V4\"" in text
    assert "validation_accessed: false" in text


def test_validation_protocol_v2_preserves_primary_metrics_and_sealed_holdout(tmp_path, monkeypatch):
    out = tmp_path / "protocol.yaml"
    monkeypatch.setattr(rho, "VALIDATION_PROTOCOL_V2", out)

    rho.write_validation_protocol_v2()
    text = out.read_text(encoding="utf-8")

    assert "candidate_under_test: \"RF_TUNED_LOCK_CANDIDATE_V1\"" in text
    assert "incident_level_macro_f1" in text
    assert "incident_level_mrr" in text
    assert "incident_level_top2_accuracy" in text
    assert "final_holdout_status: \"SEALED\"" in text


def test_only_rf_hyperparameters_vary_in_search_space():
    expected = {"n_estimators", "max_depth", "min_samples_split", "min_samples_leaf", "max_features", "bootstrap", "criterion"}

    assert set(rho.PARAMETER_SPACE) == expected
    assert rho.FEATURE_VARIANT == "V4"
    assert rho.IMBALANCE_CONDITION == "I1"
    assert rho.ARCHITECTURE == "RF_MULTICLASS_STAGE2"


def test_no_validation_or_holdout_paths_are_loaded():
    source = inspect.getsource(rho).lower()

    assert "validation_incidents_v2.csv" not in source
    assert "holdout_incidents_v2.csv" not in source
    assert "final_holdout" in source
