from __future__ import annotations

import inspect
import json
import sys
from pathlib import Path

import pandas as pd
import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection import xgboost_refinement_stability as i2  # noqa: E402


def test_i2_scope_constants_are_locked():
    assert i2.FEATURE_VARIANT == "V4"
    assert i2.FEATURE_COUNT == 74
    assert i2.IMBALANCE_CONDITION == "I1"
    assert i2.LOCAL_SEARCH_BUDGET == 25
    assert i2.SEARCH_SEED == 20260828
    assert i2.XGB_STABILITY_SEEDS == [20260828, 20260829, 20260830, 20260831, 20260901]
    assert i2.STAGE1_STATUS == "UNRESOLVED_EXPERIMENTAL_AUXILIARY"


def test_phase_i_winner_params_are_included_first():
    candidates = i2.local_parameter_candidates(budget=8, seed=i2.SEARCH_SEED)

    assert len(candidates) == 8
    assert candidates[0] == i2.PHASE_I_WINNER_PARAMS
    assert len({i2.parameter_hash(candidate) for candidate in candidates}) == 8


def test_local_budget_cannot_exceed_25():
    with pytest.raises(ValueError):
        i2.local_parameter_candidates(budget=26)


def test_train_data_is_train_only_incident_only_v4_and_same_folds():
    data = i2.load_stage2_train_data()

    assert set(data["partition"].astype(str)) == {"train"}
    assert set(data["label"].unique()) == set(i2.INCIDENT_LABELS)
    assert len(i2.FEATURES_BY_VARIANT["V4"]) == 74
    assert data.groupby("model_group_id")["fold"].nunique().max() == 1


def test_paired_against_phase_i_uses_phase_i_winner_baseline():
    results = pd.DataFrame(
        [
            {
                "candidate_id": i2.PHASE_I_WINNER_ID,
                "parameter_hash": "h0",
                "incident_macro_f1": 0.8,
                "incident_mrr": 0.9,
                "incident_top1": 0.8,
                "incident_top2": 0.93,
                "incident_hijack_f1": 0.75,
                "incident_leak_f1": 0.85,
                "incident_outage_f1": 0.80,
                "window_macro_f1": 0.68,
            },
            {
                "candidate_id": "c1",
                "parameter_hash": "h1",
                "incident_macro_f1": 0.81,
                "incident_mrr": 0.91,
                "incident_top1": 0.81,
                "incident_top2": 0.94,
                "incident_hijack_f1": 0.76,
                "incident_leak_f1": 0.86,
                "incident_outage_f1": 0.81,
                "window_macro_f1": 0.69,
            },
        ]
    )
    folds = pd.DataFrame(
        {
            "candidate_id": [i2.PHASE_I_WINNER_ID, i2.PHASE_I_WINNER_ID, "c1", "c1"],
            "fold": [1, 2, 1, 2],
            "incident_macro_f1": [0.7, 0.9, 0.8, 0.91],
        }
    )
    paired = i2.paired_against_phase_i(results, folds)

    c1 = paired[paired["candidate_id"].eq("c1")].iloc[0]
    assert c1["incident_macro_f1_delta"] == pytest.approx(0.01)
    assert c1["folds_improved"] == 2


def test_deterministic_status_requires_full_sampling_and_zero_variance():
    params = dict(i2.PHASE_I_WINNER_PARAMS)

    assert i2.is_deterministic(params, 0.0)
    params["subsample"] = 0.9
    assert not i2.is_deterministic(params, 0.0)


def test_select_i2_prefers_phase_i_for_tiny_gain_or_class_damage():
    stability = pd.DataFrame(
        [
            {
                "candidate_id": i2.PHASE_I_WINNER_ID,
                "mean_incident_macro_f1": 0.800,
                "mean_mrr": 0.889,
                "mean_top2": 0.934,
                "mean_top1": 0.801,
                "hijack_f1_mean": 0.751,
                "leak_f1_mean": 0.849,
                "outage_f1_mean": 0.799,
                "std_incident_macro_f1": 0.0,
                "mean_fit_time_seconds": 20.0,
            },
            {
                "candidate_id": "local",
                "mean_incident_macro_f1": 0.802,
                "mean_mrr": 0.889,
                "mean_top2": 0.934,
                "mean_top1": 0.802,
                "hijack_f1_mean": 0.730,
                "leak_f1_mean": 0.860,
                "outage_f1_mean": 0.815,
                "std_incident_macro_f1": 0.0,
                "mean_fit_time_seconds": 25.0,
            },
        ]
    )
    selected, classification, recommendation = i2.select_i2_candidate(stability)

    assert selected["candidate_id"] == i2.PHASE_I_WINNER_ID
    assert classification == "NO_MEANINGFUL_IMPROVEMENT"
    assert recommendation == "KEEP_PHASE_I_XGB"


def test_no_validation_holdout_stage1_rf_retuning_or_feature_rework():
    source = inspect.getsource(i2).lower()

    assert "validation_incidents_v2.csv" not in source
    assert "holdout_incidents_v2.csv" not in source
    assert "stratifiedgroupkfold" not in source
    assert "randomforestclassifier(" not in source
    assert "stage1_status" in source
