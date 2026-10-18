from __future__ import annotations

import ast
import inspect
import sys
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection import model_lock_planning as mlp  # noqa: E402


def test_selected_architecture_feature_variant_and_imbalance_are_locked():
    assert mlp.SELECTED_ARCHITECTURE == "multiclass Stage 2 Random Forest"
    assert mlp.SELECTED_DECISION == "KEEP_MULTICLASS_STAGE2"
    assert mlp.FEATURE_VARIANT == "V4"
    assert mlp.FEATURE_COUNT == 74
    assert mlp.IMBALANCE_TREATMENT == "I1 incident-aware weighting"


def test_stage1_status_is_unresolved_and_holdout_sealed():
    assert mlp.STAGE1_STATUS == "UNRESOLVED_EXPERIMENTAL_AUXILIARY"
    assert mlp.FINAL_HOLDOUT_STATUS == "SEALED"


def test_final_model_candidate_contains_v4_features_and_rf_parameters(tmp_path, monkeypatch):
    candidate = tmp_path / "candidate.yaml"
    monkeypatch.setattr(mlp, "FINAL_MODEL_CANDIDATE", candidate)

    mlp.write_final_model_candidate()
    text = candidate.read_text(encoding="utf-8")

    assert "RF_LOCK_CANDIDATE_V1" in text
    assert "feature_variant: \"V4\"" in text
    assert "feature_count: 74" in text
    assert "stage1_required_as_hard_gate: false" in text
    assert "random_state: 20260828" in text


def test_validation_protocol_predeclares_metrics_and_forbids_search(tmp_path, monkeypatch):
    protocol = tmp_path / "validation.yaml"
    monkeypatch.setattr(mlp, "VALIDATION_PROTOCOL", protocol)

    mlp.write_validation_protocol()
    text = protocol.read_text(encoding="utf-8")

    assert "validation_status: \"NOT_ACCESSED\"" in text
    assert "final_holdout_status: \"SEALED\"" in text
    assert "incident_level_macro_f1" in text
    assert "incident_level_mrr" in text
    assert "incident_level_top2_accuracy" in text
    assert "expert architectures" in text
    assert "Stage 1 thresholds" in text


def test_train_selection_summary_records_phase_f_selected_architecture():
    summary = mlp.build_train_selection_summary()
    selected = summary[
        summary["experiment_id"].eq("PHASEF_S2_BASE_V4_I1_RF_INCIDENT")
        & summary["status"].eq("SELECTED_ARCHITECTURE")
    ]

    assert len(selected) == 1
    row = selected.iloc[0]
    assert row["feature_variant"] == "V4"
    assert row["imbalance_condition"] == "I1"
    assert row["incident_group_macro_f1"] > 0.7
    assert row["mrr"] > 0.8


def test_readiness_audit_is_all_pass_after_protocol_written(tmp_path, monkeypatch):
    protocol = tmp_path / "validation.yaml"
    monkeypatch.setattr(mlp, "VALIDATION_PROTOCOL", protocol)
    mlp.write_validation_protocol()

    audit = mlp.build_readiness_audit()

    assert set(audit["status"]) == {"PASS"}
    assert "validation_not_accessed" in set(audit["check_name"])
    assert "holdout_not_accessed" in set(audit["check_name"])


def test_module_does_not_train_or_evaluate_models():
    tree = ast.parse(inspect.getsource(mlp))
    forbidden_calls = {"fit", "predict", "predict_proba", "StratifiedGroupKFold", "RandomForestClassifier"}
    calls = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                calls.add(node.func.attr)
            elif isinstance(node.func, ast.Name):
                calls.add(node.func.id)

    assert forbidden_calls.isdisjoint(calls)


def test_no_validation_or_holdout_data_paths_are_defined():
    source = inspect.getsource(mlp).lower()

    assert "data/partitions_v2/validation_incidents_v2.csv" not in source
    assert "data/partitions_v2/holdout_incidents_v2.csv" not in source
    assert "read_parquet" not in source
