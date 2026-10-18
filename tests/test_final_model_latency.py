from __future__ import annotations

from pathlib import Path

import pandas as pd
import yaml

from bgp_incident_detection import final_model_latency as fml


def test_stage1_tau_not_used_in_final_k1() -> None:
    stage1 = fml.stage1_results()
    assert set(stage1["tau_threshold_used_in_final_k1"]) == {"NO"}
    assert stage1.loc[stage1["phase"].eq("E"), "tau"].iloc[0] == 0.06
    assert stage1.loc[stage1["phase"].eq("E2"), "tau"].iloc[0] == 0.72
    assert bool(stage1.loc[stage1["phase"].eq("E"), "validation_loaded"].iloc[0]) is False
    assert bool(stage1.loc[stage1["phase"].eq("E"), "holdout_loaded"].iloc[0]) is False


def test_final_k1_model_identity_and_ranking_rule_unchanged() -> None:
    final = yaml.safe_load(Path("config/final_praxis_result_v1.yaml").read_text(encoding="utf-8"))
    deployable = yaml.safe_load(Path("config/k1_final_candidate_v1_1_deployable.yaml").read_text(encoding="utf-8"))
    assert final["second_level_parameter_hash"] == "40df040321ef"
    assert final["stage1_status"] == "UNRESOLVED_EXPERIMENTAL_AUXILIARY"
    assert deployable["ranking_rule"] == "descending P(Hijack), P(Leak), P(Outage)"
    assert deployable["first_level_inference_strategy"] == "CROSSFIT_ENSEMBLE_FIRST_LEVEL"
    assert deployable["validation_used"] is False
    assert deployable["final_holdout_accessed"] is False


def test_latency_benchmark_uses_train_only_fixture() -> None:
    latency, _ = fml.benchmark_latency(repetitions=3)
    assert set(latency["evidence_type"]) == {"MEASURED_TRAIN_FIXTURE"}
    assert (latency["train_fixture_incidents"] > 0).all()
    assert (latency["train_fixture_windows"] > 0).all()
    assert set(latency["included_in_operational_latency"]) == {"YES_AFTER_FEATURE_AVAILABILITY"}
    assert "Complete measured K1 computational path from probabilities to ranking" in set(latency["component"])


def test_phase_n_does_not_call_model_fit_or_holdout_evaluation() -> None:
    source = Path("src/bgp_incident_detection/final_model_latency.py").read_text(encoding="utf-8")
    assert ".fit(" not in source
    assert "predict_proba(" not in source
    assert "final_holdout_performance_summary" not in source
    assert "validation_confirmation_results" not in source


def test_phase_n_outputs_exist_after_run() -> None:
    summary = fml.run_phase_n(repetitions=3)
    assert summary["tau_used_in_final_k1"] == "NO"
    assert summary["stage1_status"] == "UNRESOLVED_EXPERIMENTAL_AUXILIARY"
    for path in [
        "docs/stage1_threshold_lineage_v1.md",
        "docs/stage1_threshold_results_v1.csv",
        "docs/model_runtime_history_v1.csv",
        "data/performance/final_k1_inference_latency_v1.csv",
        "docs/final_k1_latency_summary_v1.md",
        "docs/detection_vs_classification_scope_v1.md",
        "docs/professor_tau_and_latency_answers_v1.md",
        "docs/model_latency_table_v1.csv",
        "notebooks/57_tau_threshold_and_final_model_latency.ipynb",
    ]:
        assert Path(path).exists()
    table = pd.read_csv("docs/model_latency_table_v1.csv")
    assert "operational observation requirement" in set(table["component"])
