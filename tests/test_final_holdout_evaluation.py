from pathlib import Path

import numpy as np
import pandas as pd

from bgp_incident_detection import final_holdout_evaluation as fhe


def test_preaccess_audit_is_pass_ready():
    audit = pd.read_csv(fhe.PREACCESS_AUDIT)
    assert set(audit["status"]) == {"PASS"}
    assert "final_second_level_hyperparameters" in set(audit["check"])
    assert "deployable_candidate_config" in set(audit["check"])


def test_holdout_partition_is_balanced_and_disjoint():
    train = pd.read_csv(fhe.TRAIN_INCIDENTS)
    validation = pd.read_csv(fhe.VALIDATION_INCIDENTS)
    holdout = pd.read_csv(fhe.HOLDOUT_INCIDENTS)
    assert len(holdout) == 213
    assert holdout["incident_uid"].nunique() == 213
    assert holdout["category"].value_counts().to_dict() == {"Hijack": 71, "Leak": 71, "Outage": 71}
    assert not set(holdout["incident_uid"]) & set(train["incident_uid"])
    assert not set(holdout["incident_uid"]) & set(validation["incident_uid"])
    assert set(holdout["partition"]) == {"holdout"}


def test_v4_and_k1_meta_schema_counts_are_frozen():
    assert len(fhe.FEATURES_BY_VARIANT["V4"]) == 74
    schema = fhe.load_yaml(fhe.META_SCHEMA_CONFIG)
    assert schema["status"] == "FROZEN"
    assert schema["feature_count"] == 74
    assert len(schema["feature_order"]) == 74


def test_bootstrap_ci_preserves_metrics_shape(tmp_path, monkeypatch):
    monkeypatch.setattr(fhe, "FINAL_HOLDOUT", tmp_path)
    frame = pd.DataFrame(
        {
            "incident_uid": [f"i{i}" for i in range(6)],
            "true_class": ["HIJACK", "HIJACK", "LEAK", "LEAK", "OUTAGE", "OUTAGE"],
            "p_hijack": [0.8, 0.7, 0.1, 0.1, 0.2, 0.2],
            "p_leak": [0.1, 0.2, 0.8, 0.7, 0.1, 0.2],
            "p_outage": [0.1, 0.1, 0.1, 0.2, 0.7, 0.6],
        }
    )
    out = fhe.bootstrap_ci(frame, replicates=20, seed=123)
    assert set(out["metric"]) == {"incident_macro_f1", "top1", "top2", "mrr"}
    assert np.isfinite(out["ci_lower_95"]).all()
    assert np.isfinite(out["ci_upper_95"]).all()


def test_multiclass_brier_zero_for_perfect_predictions():
    probs = pd.DataFrame({"HIJACK": [1.0, 0.0, 0.0], "LEAK": [0.0, 1.0, 0.0], "OUTAGE": [0.0, 0.0, 1.0]})
    assert fhe.multiclass_brier(["HIJACK", "LEAK", "OUTAGE"], probs) == 0.0


def test_final_holdout_module_does_not_authorize_alternative_models():
    text = Path(fhe.__file__).read_text()
    assert "KEEP_XGB_XGB_K1" in text
    assert "RF_REFINED_TRAIN_CANDIDATE" not in text
    assert "K1_FINAL_SECOND_LEVEL_XGB_V1" in text
    assert "40df040321ef" in text
