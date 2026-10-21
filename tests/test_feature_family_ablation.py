from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection import feature_family_ablation as fam  # noqa: E402
from bgp_incident_detection.model_baselines import RF_HYPERPARAMETERS, SEED  # noqa: E402


def test_full_v4_has_exactly_74_features():
    inventory = fam.feature_family_inventory()
    variants = fam.ablation_variants(inventory)

    assert len(variants[fam.FULL_VARIANT]) == 74


def test_every_feature_has_one_primary_family():
    inventory = fam.feature_family_inventory()

    assert len(inventory) == 74
    assert not inventory["feature_name"].duplicated().any()
    assert inventory["feature_family"].notna().all()
    assert inventory.groupby("feature_name")["feature_family"].nunique().max() == 1


def test_required_family_counts_are_present():
    inventory = fam.feature_family_inventory()
    counts = inventory.groupby("feature_family")["feature_name"].count().to_dict()

    assert counts["caida_as_relationship"] == 14
    assert counts["rpki_rov"] == 16
    assert counts["announcement_update_activity"] >= 1
    assert counts["withdrawal_activity"] >= 1
    assert counts["as_path_instability_path_change"] >= 1
    assert counts["origin_change_moas_behavior"] >= 1


def test_removal_variants_have_correct_counts():
    inventory = fam.feature_family_inventory()
    variants = fam.ablation_variants(inventory)
    full_count = len(variants[fam.FULL_VARIANT])
    counts = inventory.groupby("feature_family")["feature_name"].count().to_dict()

    for family, family_count in counts.items():
        variant_id = f"FAM_V4_MINUS_{family.upper()}"
        assert len(variants[variant_id]) == full_count - family_count


def test_v4_data_reuses_identical_grouped_folds_when_available():
    if not fam.CV_ASSIGNMENTS.exists():
        return
    df = fam.load_variant("V4")
    assignments = fam.load_assignments(df)
    merged = df[["window_id", "model_group_id"]].merge(assignments, on="window_id", how="left", validate="one_to_one")

    assert assignments["fold"].nunique() == 5
    assert merged.groupby("model_group_id")["fold"].nunique().max() == 1


def test_v4_data_is_train_only_when_available():
    df = fam.load_variant("V4")

    assert set(df["partition"].astype(str)) == {"train"}
    assert len(df) == 68547


def test_i1_group_weights_equalize_group_influence():
    train = pd.DataFrame(
        {
            "window_id": ["a1", "a2", "b1", "c1", "c2", "c3"],
            "model_group_id": ["a", "a", "b", "c", "c", "c"],
        }
    )
    weights = fam.group_aware_weights(train)
    train["weight"] = weights

    assert np.allclose(train.groupby("model_group_id")["weight"].sum().to_numpy(), np.ones(3))


def test_hyperparameters_and_stage1_rule_are_unchanged():
    assert RF_HYPERPARAMETERS["random_state"] == SEED
    assert RF_HYPERPARAMETERS["class_weight"] is None
    row = fam.metric_row(
        "FAM_V4_FULL_RF_SINGLE",
        "RF_SINGLE",
        "NONE_FULL_V4",
        74,
        1,
        "window",
        "end_to_end",
        pd.DataFrame({"model_group_id": ["g1"]}),
        pd.DataFrame({"model_group_id": ["g2"]}),
        ["NORMAL", "HIJACK"],
        ["NORMAL", "LEAK"],
        pd.DataFrame({"NORMAL": [0.9, 0.1], "HIJACK": [0.1, 0.2], "LEAK": [0.0, 0.7], "OUTAGE": [0.0, 0.0]}),
        fam.CLASS_LABELS,
        0.1,
        0.01,
    )
    assert row["stage1_decision_rule"] == "default_argmax_probability"


def test_phase_d_has_no_threshold_tuning_or_shap_symbols():
    assert fam.I1_CONDITION == "I1"
    assert not hasattr(fam, "SHAP")
    assert not hasattr(fam, "threshold_grid")
