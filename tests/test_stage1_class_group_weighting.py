from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection import stage1_class_group_weighting as cg  # noqa: E402


def test_phase_e2_uses_v4_only():
    assert len(cg.FEATURES_BY_VARIANT["V4"]) == 74
    assert cg.WEIGHTING_CONDITIONS == ["W0_GROUP_ONLY", "W1_CLASS_GROUP_BALANCED"]


def test_w1_balances_classes_and_groups():
    train = pd.DataFrame(
        {
            "window_id": [f"w{i}" for i in range(10)],
            "model_group_id": ["a", "a", "a", "b", "b", "c", "c", "d", "d", "d"],
            "stage1_label": ["NORMAL", "NORMAL", "INCIDENT", "NORMAL", "INCIDENT", "INCIDENT", "INCIDENT", "INCIDENT", "INCIDENT", "INCIDENT"],
        }
    )
    weights = cg.w1_class_group_weights(train)
    train["weight"] = weights

    class_weights = train.groupby("stage1_label")["weight"].sum()
    assert np.isclose(class_weights["NORMAL"], class_weights["INCIDENT"])
    by_cell = train.groupby(["stage1_label", "model_group_id"])["weight"].sum()
    assert np.isclose(by_cell[("NORMAL", "a")], by_cell[("NORMAL", "b")])
    assert np.isclose(by_cell[("INCIDENT", "a")], by_cell[("INCIDENT", "b")])


def test_w0_group_only_can_leave_class_imbalance():
    train = pd.DataFrame(
        {
            "window_id": [f"w{i}" for i in range(6)],
            "model_group_id": ["a", "a", "a", "b", "b", "b"],
            "stage1_label": ["NORMAL", "INCIDENT", "INCIDENT", "INCIDENT", "INCIDENT", "INCIDENT"],
        }
    )
    weights = cg.group_aware_weights(train)
    train["weight"] = weights
    class_weights = train.groupby("stage1_label")["weight"].sum()

    assert class_weights["INCIDENT"] > class_weights["NORMAL"]


def test_weight_balance_audit_train_only_when_available():
    data = cg.load_stage1_data()
    audit = cg.weight_balance_audit(data)

    assert set(data["partition"].astype(str)) == {"train"}
    assert set(audit["weighting_condition"]) == set(cg.WEIGHTING_CONDITIONS)
    assert audit["fold"].nunique() == 5


def test_w1_audit_equalizes_total_class_weight_when_available():
    data = cg.load_stage1_data()
    audit = cg.weight_balance_audit(data)
    w1 = audit[audit["weighting_condition"] == "W1_CLASS_GROUP_BALANCED"]

    assert np.allclose(w1["total_effective_normal_sample_weight"], w1["total_effective_incident_sample_weight"])


def test_no_validation_holdout_or_oversampling_symbols():
    assert not hasattr(cg, "VALIDATION")
    assert not hasattr(cg, "HOLDOUT")
    assert not hasattr(cg, "SMOTE")
    assert not hasattr(cg, "oversample")
