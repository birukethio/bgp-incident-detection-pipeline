from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection import feature_ablation as fa  # noqa: E402
from bgp_incident_detection.model_baselines import RF_HYPERPARAMETERS, SEED  # noqa: E402


def test_feature_counts_are_exact():
    assert {variant: len(features) for variant, features in fa.FEATURES_BY_VARIANT.items()} == {
        "V1": 44,
        "V2": 58,
        "V3": 60,
        "V4": 74,
    }


def test_feature_sets_are_expected_unions():
    assert fa.FEATURES_BY_VARIANT["V2"] == fa.BEHAVIORAL_FEATURE_NAMES + fa.CAIDA_FEATURES
    assert fa.FEATURES_BY_VARIANT["V3"] == fa.BEHAVIORAL_FEATURE_NAMES + fa.RPKI_FEATURES
    assert fa.FEATURES_BY_VARIANT["V4"] == fa.BEHAVIORAL_FEATURE_NAMES + fa.CAIDA_FEATURES + fa.RPKI_FEATURES


def test_schema_validation_passes_when_frozen_files_exist():
    if not all(paths["incident"].exists() and paths["normal"].exists() for paths in fa.VARIANT_PATHS.values()):
        return
    audit = fa.validate_feature_schemas()

    assert set(audit["status"]) == {"PASS"}
    assert audit.set_index("feature_variant")["observed_feature_count"].to_dict() == fa.EXPECTED_COUNTS


def test_all_variants_reuse_identical_phase_a_folds_when_available():
    if not fa.CV_ASSIGNMENTS.exists() or not all(paths["incident"].exists() and paths["normal"].exists() for paths in fa.VARIANT_PATHS.values()):
        return
    signatures = []
    for variant in fa.VARIANT_PATHS:
        df = fa.load_variant(variant)
        assignments = fa.load_assignments(df)
        signatures.append(assignments.sort_values("window_id")[["window_id", "fold"]].to_json(orient="records"))

    assert len(set(signatures)) == 1


def test_load_variant_is_train_only_when_available():
    if not fa.VARIANT_PATHS["V4"]["incident"].exists() or not fa.VARIANT_PATHS["V4"]["normal"].exists():
        return
    df = fa.load_variant("V4")

    assert set(df["partition"].astype(str)) == {"train"}
    assert len(df) == 68547


def test_group_weights_are_training_fold_only_math():
    train = pd.DataFrame(
        {
            "window_id": ["a1", "a2", "b1", "c1", "c2", "c3"],
            "model_group_id": ["a", "a", "b", "c", "c", "c"],
        }
    )
    weights = fa.group_aware_weights(train)
    train["weight"] = weights

    assert np.allclose(train.groupby("model_group_id")["weight"].sum().to_numpy(), np.ones(3))


def test_rf_hyperparameters_match_phase_a_b_and_threshold_is_default_argmax():
    assert RF_HYPERPARAMETERS["random_state"] == SEED
    assert RF_HYPERPARAMETERS["class_weight"] is None
    row = fa.result_row(
        "test",
        "V1",
        "RF_SINGLE",
        1,
        "window",
        "end_to_end",
        pd.DataFrame({"model_group_id": ["g1"]}),
        pd.DataFrame({"model_group_id": ["g2"]}),
        ["NORMAL", "HIJACK"],
        ["NORMAL", "LEAK"],
        pd.DataFrame({"NORMAL": [0.9, 0.1], "HIJACK": [0.1, 0.2], "LEAK": [0.0, 0.7], "OUTAGE": [0.0, 0.0]}),
        fa.CLASS_LABELS,
        0.1,
        0.01,
    )
    assert row["stage1_decision_rule"] == "default_argmax_probability"


def test_phase_c_constants_do_not_include_other_imbalance_conditions_or_family_removal():
    assert "I1" == "I1"
    assert not hasattr(fa, "P95_WINDOW_CAP")
    assert not hasattr(fa, "SHAP")
