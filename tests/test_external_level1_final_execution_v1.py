from pathlib import Path

import json
import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "external_validation" / "final_execution_v1"


def test_locked_cohort_and_predictions_match_exactly():
    cohort = pd.read_csv(OUT / "final_external_cohort_locked_v1.csv")
    predictions = pd.read_csv(OUT / "final_external_per_incident_predictions_v1.csv")
    assert len(cohort) == len(predictions) == 18
    assert cohort["external_id"].is_unique
    assert set(cohort["external_id"]) == set(predictions["external_id"])
    assert cohort["true_class"].value_counts().to_dict() == {"Outage": 10, "Leak": 5, "Hijack": 3}


def test_exact_v4_and_inference_yields_are_complete():
    schema = pd.read_csv(OUT / "final_external_v4_schema_audit_v1.csv")
    predictions = pd.read_csv(OUT / "final_external_per_incident_predictions_v1.csv")
    assert len(schema) == 18
    assert set(schema["status"]) == {"PASS"}
    assert set(schema["feature_count"]) == {74}
    assert len(predictions) == 18


def test_headline_metrics_match_preserved_predictions():
    metrics = json.loads((OUT / "final_external_metrics_v1.json").read_text())
    assert metrics["evaluable_n"] == 18
    assert abs(metrics["headline"]["macro_f1"] - 0.41269841269841273) < 1e-15
    assert metrics["headline"]["top1_accuracy"] == 10 / 18
    assert metrics["headline"]["top2_accuracy"] == 13 / 18
    assert metrics["top1_errors"] == 8
    assert metrics["top2_rescues"] == 3


def test_locked_manifest_preserves_scientific_boundary():
    manifest = json.loads((OUT / "final_external_cohort_lock_manifest_v1.json").read_text())
    assert manifest["level2_external_validation"] is False
    assert manifest["cohort_counts"] == {"total": 18, "Hijack": 3, "Leak": 5, "Outage": 10}
    assert "before reconstruction" in manifest["statement"]


def test_bootstrap_protocol_is_incident_level_and_predeclared():
    protocol = json.loads((OUT / "final_external_bootstrap_protocol_v1.json").read_text())
    assert protocol["fixed_before_metric_computation"] is True
    assert protocol["resampling_unit"] == "incident"
    assert protocol["bootstrap_iterations"] == 10000
    assert protocol["random_seed"] == 20260918
