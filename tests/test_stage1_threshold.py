from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection import stage1_threshold as st  # noqa: E402
from bgp_incident_detection.model_baselines import RF_HYPERPARAMETERS, SEED  # noqa: E402


def test_phase_e_uses_v4_only_with_74_features():
    assert len(st.FEATURES_BY_VARIANT["V4"]) == 74
    assert set(st.CALIBRATION_METHODS) == {"C0_NONE", "C1_SIGMOID", "C2_ISOTONIC"}


def test_stage1_data_is_train_only_and_reuses_existing_folds_when_available():
    data = st.load_stage1_data()

    assert len(data) == 68547
    assert set(data["partition"].astype(str)) == {"train"}
    assert data["fold"].nunique() == 5
    assert data.groupby("model_group_id")["fold"].nunique().max() == 1


def test_threshold_metrics_report_both_error_rates():
    frame = pd.DataFrame(
        {
            "true_label": ["NORMAL", "NORMAL", "INCIDENT", "INCIDENT"],
            "p_normal": [0.9, 0.2, 0.8, 0.1],
        }
    )
    metrics = st.stage1_metrics(frame, 0.5)

    assert metrics["normal_recall"] == 0.5
    assert metrics["incident_recall"] == 0.5
    assert metrics["false_normal_rate"] == 0.5
    assert metrics["false_incident_rate"] == 0.5


def test_select_threshold_requires_nonzero_recall_when_possible():
    sweep = pd.DataFrame(
        [
            {"calibration_method": "C0_NONE", "threshold": 0.1, "macro_f1": 0.7, "balanced_accuracy": 0.5, "normal_f1": 0.0, "normal_recall": 0.0, "incident_recall": 1.0},
            {"calibration_method": "C0_NONE", "threshold": 0.2, "macro_f1": 0.6, "balanced_accuracy": 0.6, "normal_f1": 0.4, "normal_recall": 0.5, "incident_recall": 0.7},
        ]
    )
    selected = st.select_threshold(sweep, "C0_NONE")

    assert selected["threshold"] == 0.2


def test_select_calibration_keeps_c0_when_calibration_gain_is_not_material():
    calibration = pd.DataFrame(
        [
            {"calibration_method": "C0_NONE", "brier_score": 0.0100, "log_loss": 0.05, "roc_auc": 0.70, "pr_auc_normal": 0.020},
            {"calibration_method": "C2_ISOTONIC", "brier_score": 0.00999, "log_loss": 0.04, "roc_auc": 0.69, "pr_auc_normal": 0.018},
        ]
    )
    sweep = pd.DataFrame(
        [
            {"calibration_method": "C0_NONE", "threshold": 0.1, "macro_f1": 0.51, "balanced_accuracy": 0.51, "normal_f1": 0.02, "normal_recall": 0.01, "incident_recall": 0.99},
            {"calibration_method": "C2_ISOTONIC", "threshold": 0.1, "macro_f1": 0.50, "balanced_accuracy": 0.50, "normal_f1": 0.01, "normal_recall": 0.01, "incident_recall": 0.99},
        ]
    )
    method, reason = st.select_calibration_method(calibration, sweep)

    assert method == "C0_NONE"
    assert "small Normal sample" in reason


def test_group_oof_uses_mean_probability_per_model_group():
    oof = pd.DataFrame(
        {
            "calibration_method": ["C0_NONE", "C0_NONE", "C0_NONE"],
            "model_group_id": ["g1", "g1", "g2"],
            "true_label": ["NORMAL", "NORMAL", "INCIDENT"],
            "fold": [1, 1, 2],
            "p_normal": [0.2, 0.6, 0.1],
            "p_incident": [0.8, 0.4, 0.9],
        }
    )
    grouped = st.group_oof(oof)

    assert grouped.loc[grouped["model_group_id"] == "g1", "p_normal"].iloc[0] == 0.4


def test_ece_score_is_bounded():
    y = np.array([1, 0, 1, 0])
    p = np.array([0.9, 0.1, 0.8, 0.2])
    score = st.ece_score(y, p)

    assert 0 <= score <= 1


def test_hyperparameters_and_stage1_rule_are_unchanged():
    assert RF_HYPERPARAMETERS["random_state"] == SEED
    assert RF_HYPERPARAMETERS["class_weight"] is None
    assert np.allclose(st.THRESHOLDS[:3], [0.01, 0.02, 0.03])


def test_no_validation_or_holdout_constants_are_used():
    assert not hasattr(st, "VALIDATION")
    assert not hasattr(st, "HOLDOUT")
