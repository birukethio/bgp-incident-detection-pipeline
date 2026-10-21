from __future__ import annotations

from pathlib import Path

import pandas as pd

from bgp_incident_detection import master_praxis_record as mpr


def test_final_praxis_title_and_authoritative_counts() -> None:
    values = mpr.final_values()
    assert values["title"] == "An Artificial Intelligence–Based Classification and Ranking System for Border Gateway Protocol Incidents in Enterprise Networks"
    assert values["train_incidents"] == 993
    assert values["validation_incidents"] == 213
    assert values["holdout_incidents"] == 213
    assert values["behavioral_features"] == 44
    assert values["caida_features"] == 14
    assert values["rpki_features"] == 16
    assert values["v4_features"] == 74
    assert values["train_behavioral_rows"] == 68031
    assert values["normal_windows"] == 516


def test_terminal_holdout_values_are_exact() -> None:
    values = mpr.final_values()
    assert values["final_macro_f1"] == 0.9201769450076779
    assert values["final_top1"] == 0.92018779342723
    assert values["final_top2"] == 0.9906103286384976
    assert values["final_mrr"] == 0.9585289514866979
    assert values["final_hijack_f1"] == 0.8776978417266187
    assert values["final_leak_f1"] == 0.9041095890410958
    assert values["final_outage_f1"] == 0.9787234042553191
    assert values["rank1"] == 196
    assert values["rank2"] == 15
    assert values["rank3"] == 2
    assert values["second_level_hash"] == "40df040321ef"


def test_phase_chronology_marks_validation_k1_and_holdout_correctly() -> None:
    phases = mpr.phases(mpr.final_values())
    order = {row["phase_id"]: row["sequence"] for row in phases}
    assert order["P13"] < order["P14"]
    assert order["P14"] < order["P15"] < order["P16"] < order["P17"] < order["P18"]
    k1 = next(row for row in phases if row["phase_id"] == "P14")
    validation = next(row for row in phases if row["phase_id"] == "P13")
    holdout = next(row for row in phases if row["phase_id"] == "P18")
    assert validation["validation_accessed"] is True
    assert "Post-Validation TRAIN development" in k1["notes_limitations"]
    assert holdout["holdout_accessed"] is True


def test_stage1_remains_auxiliary_unresolved() -> None:
    values = mpr.final_values()
    assert values["stage1_status"] == "UNRESOLVED_EXPERIMENTAL_AUXILIARY"
    stage1 = next(row for row in mpr.phases(values) if row["phase_id"] == "P9")
    assert stage1["primary_result"] == "UNRESOLVED_EXPERIMENTAL_AUXILIARY"


def test_phase_m_generation_outputs_without_model_execution() -> None:
    summary = mpr.run_phase_m()
    assert summary["phase_count"] == 19
    assert Path("docs/master_praxis_experimental_record_v1.csv").exists()
    assert Path("docs/MASTER_PRAXIS_EXPERIMENTAL_RECORD_INDEX_v1.md").exists()
    record = pd.read_csv("docs/master_praxis_experimental_record_v1.csv")
    assert len(record) == 19

    source = Path("src/bgp_incident_detection/master_praxis_record.py").read_text(encoding="utf-8")
    assert ".fit(" not in source
    assert "predict_proba(" not in source
    assert "XGBClassifier" not in source
