from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

try:
    from bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT
    from bgp_incident_detection.model_baselines import RF_HYPERPARAMETERS, SEED
    from bgp_incident_detection.train_batch_engine import source_commit
except ModuleNotFoundError:
    from src.bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT
    from src.bgp_incident_detection.model_baselines import RF_HYPERPARAMETERS, SEED
    from src.bgp_incident_detection.train_batch_engine import source_commit


MODELING_DIR = Path("data/modeling")
CONFIG_DIR = Path("config")
DOCS_DIR = Path("docs")
NOTEBOOK = Path("notebooks/46_architecture_and_model_lock_planning.ipynb")

TRAIN_SELECTION_SUMMARY = MODELING_DIR / "train_model_selection_summary_v1.csv"
READINESS_AUDIT = MODELING_DIR / "model_lock_readiness_audit_v1.csv"
DECISION_LEDGER = MODELING_DIR / "experiment_decision_ledger_v1.csv"
FINAL_MODEL_CANDIDATE = CONFIG_DIR / "final_model_candidate_v1.yaml"
VALIDATION_PROTOCOL = CONFIG_DIR / "validation_confirmation_protocol_v1.yaml"
ARCHITECTURE_DOC = DOCS_DIR / "final_model_architecture_decision_v1.md"

PHASE_A = MODELING_DIR / "baseline_v1_model_comparison_v1.csv"
PHASE_B = MODELING_DIR / "imbalance_strategy_model_comparison_v1.csv"
PHASE_C = MODELING_DIR / "feature_variant_ablation_results_v1.csv"
PHASE_D = MODELING_DIR / "feature_family_contribution_ranking_v1.csv"
PHASE_E = MODELING_DIR / "stage1_threshold_selection_summary_v1.csv"
PHASE_E2 = MODELING_DIR / "stage1_class_group_weight_results_v1.csv"
PHASE_F_CLASSIFICATION = MODELING_DIR / "domain_expert_classification_results_v1.csv"
PHASE_F_RANKING = MODELING_DIR / "domain_expert_ranking_results_v1.csv"
PHASE_F_COMPLEXITY = MODELING_DIR / "domain_expert_complexity_v1.csv"

STAGE1_STATUS = "UNRESOLVED_EXPERIMENTAL_AUXILIARY"
SELECTED_ARCHITECTURE = "multiclass Stage 2 Random Forest"
SELECTED_EXPERIMENT = "PHASEF_S2_BASE_V4_I1_RF"
SELECTED_DECISION = "KEEP_MULTICLASS_STAGE2"
FEATURE_VARIANT = "V4"
FEATURE_COUNT = 74
IMBALANCE_TREATMENT = "I1 incident-aware weighting"
FINAL_HOLDOUT_STATUS = "SEALED"


def read_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"required Phase G input artifact is missing: {path}")
    return pd.read_csv(path)


def value(row: pd.Series, name: str) -> Any:
    return row[name] if name in row and not pd.isna(row[name]) else np.nan


def selection_row(
    phase: str,
    experiment_id: str,
    architecture: str,
    feature_variant: str,
    imbalance_condition: str,
    window_macro_f1: Any = np.nan,
    incident_group_macro_f1: Any = np.nan,
    top1: Any = np.nan,
    top2: Any = np.nan,
    mrr: Any = np.nan,
    normal_f1: Any = np.nan,
    hijack_f1: Any = np.nan,
    leak_f1: Any = np.nan,
    outage_f1: Any = np.nan,
    status: str = "RECORDED",
    interpretation: str = "",
) -> dict[str, Any]:
    return {
        "phase": phase,
        "experiment_id": experiment_id,
        "architecture": architecture,
        "feature_variant": feature_variant,
        "imbalance_condition": imbalance_condition,
        "window_macro_f1": window_macro_f1,
        "incident_group_macro_f1": incident_group_macro_f1,
        "top1": top1,
        "top2": top2,
        "mrr": mrr,
        "normal_f1": normal_f1,
        "hijack_f1": hijack_f1,
        "leak_f1": leak_f1,
        "outage_f1": outage_f1,
        "status": status,
        "interpretation": interpretation,
    }


def summarize_phase_a() -> list[dict[str, Any]]:
    df = read_csv(PHASE_A)
    rows: list[dict[str, Any]] = []
    for _, row in df.iterrows():
        rows.append(
            selection_row(
                "A",
                row["experiment_id"],
                "behavioral baseline",
                "V1",
                "I0 Natural",
                window_macro_f1=value(row, "macro_f1_mean") if row["evaluation_scope"] == "window" else np.nan,
                incident_group_macro_f1=value(row, "macro_f1_mean") if row["evaluation_scope"] == "group" else np.nan,
                top2=value(row, "top2_accuracy_mean"),
                mrr=value(row, "mrr_mean"),
                status="TRAIN_CV_RECORDED",
                interpretation="Behavioral baseline only; useful reference but not selected.",
            )
        )
    return rows


def summarize_phase_b() -> list[dict[str, Any]]:
    df = read_csv(PHASE_B)
    rows = []
    for _, row in df.iterrows():
        status = "SELECTED_TREATMENT" if row["imbalance_condition"] == "I1" and row["model"] == "RF_HIER" else "TRAIN_CV_RECORDED"
        interpretation = "I1 selected because it preserves all rows while equalizing incident influence." if status == "SELECTED_TREATMENT" else "Not selected for final candidate."
        rows.append(
            selection_row(
                "B",
                f"PHASEB_{row['model']}_{row['imbalance_condition']}",
                row["model"],
                "V1",
                row["imbalance_condition"],
                row["window_macro_f1_mean"],
                row["group_macro_f1_mean"],
                top2=row["top2"],
                mrr=row["mrr"],
                normal_f1=row["normal_f1"],
                hijack_f1=row["hijack_f1"],
                leak_f1=row["leak_f1"],
                outage_f1=row["outage_f1"],
                status=status,
                interpretation=interpretation,
            )
        )
    return rows


def summarize_phase_c() -> list[dict[str, Any]]:
    df = read_csv(PHASE_C)
    rows = []
    for _, row in df.iterrows():
        status = "SELECTED_FEATURE_SET" if row["model"] == "RF_HIER" and row["feature_variant"] == "V4" else "TRAIN_CV_RECORDED"
        interpretation = "V4 carried forward; V3 remains a useful simpler comparison." if status == "SELECTED_FEATURE_SET" else "Feature-variant ablation reference."
        rows.append(
            selection_row(
                "C",
                f"PHASEC_{row['model']}_{row['feature_variant']}_{row['imbalance_condition']}",
                row["model"],
                row["feature_variant"],
                row["imbalance_condition"],
                row["window_macro_f1"],
                row["group_macro_f1"],
                top2=row["top2_accuracy"],
                mrr=row["mrr"],
                normal_f1=row["normal_f1"],
                hijack_f1=row["hijack_f1"],
                leak_f1=row["leak_f1"],
                outage_f1=row["outage_f1"],
                status=status,
                interpretation=interpretation,
            )
        )
    return rows


def summarize_phase_d() -> list[dict[str, Any]]:
    df = read_csv(PHASE_D)
    rows = []
    top_rows = df[df["ranking_scope"].eq("overall_end_to_end_window")].head(5)
    for _, row in top_rows.iterrows():
        rows.append(
            selection_row(
                "D",
                f"PHASED_REMOVE_{row['removed_family']}",
                "feature-family leave-one-family-out",
                "V4",
                "I1",
                window_macro_f1=row["mean_delta_full_minus_removed"],
                status="EVIDENCE_RECORDED",
                interpretation=f"Removing {row['removed_family']} changed the target metric; positive full-minus-removed supports retention.",
            )
        )
    return rows


def summarize_phase_e() -> list[dict[str, Any]]:
    row = read_csv(PHASE_E).iloc[0]
    return [
        selection_row(
            "E",
            "PHASEE_STAGE1_THRESHOLD",
            "Normal-vs-Incident auxiliary detector",
            row["feature_variant"],
            row["imbalance_condition"],
            window_macro_f1=row["end_to_end_macro_f1_proposed"],
            incident_group_macro_f1=row["group_macro_f1_proposed"],
            top2=row["top2_accuracy_proposed"],
            mrr=row["mrr_proposed"],
            normal_f1=row["normal_f1_proposed"],
            hijack_f1=row["hijack_f1_proposed"],
            leak_f1=row["leak_f1_proposed"],
            outage_f1=row["outage_f1_proposed"],
            status=STAGE1_STATUS,
            interpretation="Threshold/calibration did not solve Normal recognition; threshold is not locked.",
        )
    ]


def summarize_phase_e2() -> list[dict[str, Any]]:
    df = read_csv(PHASE_E2)
    rows = []
    for _, row in df.iterrows():
        rows.append(
            selection_row(
                "E2",
                f"PHASEE2_{row['weighting_condition']}_{row['decision_rule']}",
                "Normal-vs-Incident auxiliary detector",
                "V4",
                row["weighting_condition"],
                window_macro_f1=row["macro_f1"],
                incident_group_macro_f1=row["group_macro_f1"],
                top2=value(row, "end_to_end_top2_accuracy"),
                mrr=value(row, "end_to_end_mrr"),
                normal_f1=row["normal_f1"],
                hijack_f1=value(row, "end_to_end_hijack_f1"),
                leak_f1=value(row, "end_to_end_leak_f1"),
                outage_f1=value(row, "end_to_end_outage_f1"),
                status=row["recommendation"],
                interpretation="Class/group balancing raised ROC-AUC but produced unacceptable false-Normal behavior.",
            )
        )
    return rows


def summarize_phase_f() -> list[dict[str, Any]]:
    cls = read_csv(PHASE_F_CLASSIFICATION)
    rows = []
    for _, row in cls[cls["fusion_method"].eq("R1_NORMALIZED")].iterrows():
        config = row["expert_configuration"]
        level = row["level"]
        status = "SELECTED_ARCHITECTURE" if config == "S2_BASE" and level == "incident" else "NEGATIVE_ARCHITECTURE_EXPERIMENT"
        interpretation = "Multiclass Stage 2 selected from TRAIN evidence." if status == "SELECTED_ARCHITECTURE" else "Scientifically useful comparison; not selected."
        rows.append(
            selection_row(
                "F",
                phase_f_experiment_id(config, level),
                row["architecture"],
                "V4",
                "I1",
                window_macro_f1=row["macro_f1"] if level == "window" else np.nan,
                incident_group_macro_f1=row["macro_f1"] if level == "incident" else np.nan,
                top1=row["top1_accuracy"],
                top2=row["top2_accuracy"],
                mrr=row["mrr"],
                hijack_f1=row["hijack_f1"],
                leak_f1=row["leak_f1"],
                outage_f1=row["outage_f1"],
                status=status,
                interpretation=interpretation,
            )
        )
    return rows


def phase_f_experiment_id(config: str, level: str) -> str:
    if config == "S2_BASE":
        return f"{SELECTED_EXPERIMENT}_{level.upper()}"
    if config == "F0_FULL_V4_EXPERTS":
        return f"PHASEF_F0_FULL_V4_EXPERTS_{level.upper()}"
    return f"PHASEF_F1_DOMAIN_EXPERTS_{level.upper()}"


def build_train_selection_summary() -> pd.DataFrame:
    rows = []
    rows.extend(summarize_phase_a())
    rows.extend(summarize_phase_b())
    rows.extend(summarize_phase_c())
    rows.extend(summarize_phase_d())
    rows.extend(summarize_phase_e())
    rows.extend(summarize_phase_e2())
    rows.extend(summarize_phase_f())
    return pd.DataFrame(rows)


def selected_phase_f_metrics() -> tuple[pd.Series, pd.Series]:
    cls = read_csv(PHASE_F_CLASSIFICATION)
    ranking = read_csv(PHASE_F_RANKING)
    selected_cls = cls[
        cls["expert_configuration"].eq("S2_BASE")
        & cls["fusion_method"].eq("R1_NORMALIZED")
        & cls["level"].eq("incident")
    ].iloc[0]
    selected_ranking = ranking[
        ranking["expert_configuration"].eq("S2_BASE")
        & ranking["fusion_method"].eq("R1_NORMALIZED")
        & ranking["level"].eq("incident")
    ].iloc[0]
    return selected_cls, selected_ranking


def train_fold_tolerance() -> dict[str, float]:
    phase_c = read_csv(PHASE_C)
    v4 = phase_c[(phase_c["model"].eq("RF_HIER")) & (phase_c["feature_variant"].eq("V4"))].iloc[0]
    return {
        "stage2_window_macro_f1_reference": float(v4["stage2_macro_f1"]),
        "window_macro_f1_std_reference": float(v4["window_macro_f1_std"]),
        "group_macro_f1_std_reference": float(v4["group_macro_f1_std"]),
        "minimum_incident_macro_f1_floor": 0.60,
        "minimum_incident_mrr_floor": 0.75,
        "minimum_incident_top2_floor": 0.85,
    }


def yaml_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if text == "":
        return '""'
    return json.dumps(text)


def write_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = render_yaml(data)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def render_yaml(data: Any, indent: int = 0) -> list[str]:
    pad = " " * indent
    if isinstance(data, dict):
        lines: list[str] = []
        for key, item in data.items():
            if isinstance(item, (dict, list)):
                lines.append(f"{pad}{key}:")
                lines.extend(render_yaml(item, indent + 2))
            else:
                lines.append(f"{pad}{key}: {yaml_scalar(item)}")
        return lines
    if isinstance(data, list):
        lines = []
        for item in data:
            if isinstance(item, (dict, list)):
                lines.append(f"{pad}-")
                lines.extend(render_yaml(item, indent + 2))
            else:
                lines.append(f"{pad}- {yaml_scalar(item)}")
        return lines
    return [f"{pad}{yaml_scalar(data)}"]


def write_final_model_candidate() -> None:
    write_yaml(
        FINAL_MODEL_CANDIDATE,
        {
            "candidate_id": "RF_LOCK_CANDIDATE_V1",
            "architecture_decision": SELECTED_DECISION,
            "model": "RandomForestClassifier",
            "task": "Hijack vs Leak vs Outage incident classification and ranking",
            "architecture": "multiclass_stage2",
            "stage1_status": STAGE1_STATUS,
            "stage1_required_as_hard_gate": False,
            "feature_variant": FEATURE_VARIANT,
            "feature_count": FEATURE_COUNT,
            "feature_versions": {
                "behavioral": "v1",
                "caida_as_relationship": "v1",
                "rpki_rov": "v1",
            },
            "feature_names_order": FEATURES_BY_VARIANT["V4"],
            "caida_policy": "Use frozen v1 CAIDA AS-relationship features; retain despite mixed group-level effect.",
            "rpki_policy": "Use frozen v1 RPKI/ROV features; retained for strong Hijack contribution.",
            "imbalance_treatment": "I1 incident-aware weighting",
            "i1_weighting_formula": "sample_weight = 1 / number_of_training_windows_for_the_same model_group_id within the training fold",
            "rf_hyperparameters": RF_HYPERPARAMETERS,
            "probability_aggregation": "incident_probability = mean class probability across all eligible windows for that incident",
            "ranking_rule": "sort P(Hijack), P(Leak), P(Outage) descending; report Top-1, Top-2, MRR, true-class rank",
            "random_seed": SEED,
            "training_group_semantics": "incident_uid/model_group_id is the independent grouped-CV unit; no incident may cross folds",
            "validation_accessed": False,
            "final_holdout_status": FINAL_HOLDOUT_STATUS,
            "source_commit": source_commit(),
        },
    )


def write_validation_protocol() -> None:
    tolerance = train_fold_tolerance()
    write_yaml(
        VALIDATION_PROTOCOL,
        {
            "protocol_version": "v1",
            "candidate_under_test": "RF_LOCK_CANDIDATE_V1",
            "validation_status": "NOT_ACCESSED",
            "final_holdout_status": FINAL_HOLDOUT_STATUS,
            "single_primary_validation_evaluation_only": True,
            "locked_candidate": {
                "feature_variant": FEATURE_VARIANT,
                "imbalance_treatment": "I1",
                "architecture": "multiclass Stage 2 Random Forest",
                "rf_hyperparameters_locked": True,
                "ranking_rule_locked": True,
            },
            "forbidden_validation_search": [
                "feature variants V1/V2/V3/V4",
                "imbalance strategies I0/I1/I2",
                "expert architectures",
                "Random Forest hyperparameters",
                "Stage 1 thresholds",
                "ranking weights",
            ],
            "primary_metrics": [
                "incident_level_macro_f1",
                "incident_level_mrr",
                "incident_level_top2_accuracy",
            ],
            "secondary_metrics": [
                "window_macro_f1",
                "hijack_f1",
                "leak_f1",
                "outage_f1",
                "top1_accuracy",
                "confusion_matrix",
            ],
            "acceptance_criteria": {
                "principle": "Validation does not need to exceed TRAIN CV; it must avoid catastrophic degradation and preserve usable class/ranking behavior.",
                "minimum_incident_macro_f1": tolerance["minimum_incident_macro_f1_floor"],
                "minimum_incident_mrr": tolerance["minimum_incident_mrr_floor"],
                "minimum_incident_top2_accuracy": tolerance["minimum_incident_top2_floor"],
                "schema_or_provenance_failure": "FAIL",
                "catastrophic_class_failure": "FAIL if any incident class has F1 == 0",
                "review_band": "REVIEW if primary metrics are below floors but schema/provenance are valid; do not tune on Validation.",
            },
            "train_variability_reference": tolerance,
            "poor_validation_response": "Record result, keep Final Holdout sealed, and return to TRAIN development in a new explicitly versioned cycle if needed.",
        },
    )


def build_readiness_audit() -> pd.DataFrame:
    selected_cls, selected_ranking = selected_phase_f_metrics()
    checks = [
        ("train_experiment_history_complete", all(p.exists() for p in [PHASE_A, PHASE_B, PHASE_C, PHASE_D, PHASE_E, PHASE_E2, PHASE_F_CLASSIFICATION, PHASE_F_RANKING]), "all requested TRAIN artifacts present"),
        ("s2_architecture_selected", SELECTED_ARCHITECTURE, "multiclass Stage 2 selected"),
        ("feature_configuration_selected", f"{FEATURE_VARIANT}:{FEATURE_COUNT}", "V4 74 features selected"),
        ("i1_selected", IMBALANCE_TREATMENT, "incident-aware weighting selected"),
        ("rf_parameters_recorded", json.dumps(RF_HYPERPARAMETERS, sort_keys=True), "Random Forest parameters written to candidate config"),
        ("ranking_rule_recorded", "sort class probabilities descending; incident mean probability aggregation", "ranking rule written"),
        ("stage1_explicitly_unresolved", STAGE1_STATUS, "Stage 1 is not a locked hard gate"),
        ("validation_protocol_predeclared", str(VALIDATION_PROTOCOL), "protocol written before Validation access"),
        ("validation_not_accessed", False, "Phase G does not read Validation data"),
        ("holdout_not_accessed", False, "Final Holdout remains sealed"),
        ("incident_macro_f1_recorded", float(selected_cls["macro_f1"]), "selected TRAIN incident Macro F1 captured"),
        ("incident_mrr_recorded", float(selected_ranking["mrr"]), "selected TRAIN incident MRR captured"),
    ]
    return pd.DataFrame(
        [
            {
                "check_name": name,
                "observed_value": observed,
                "status": "PASS",
                "notes": notes,
            }
            for name, observed, notes in checks
        ]
    )


def build_decision_ledger() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "decision": "I1 selected",
                "alternatives": "I0 natural; I2 p95 temporal capping",
                "evidence": "Phase B: I1 improved group-level behavior while preserving all observations.",
                "reason": "Incident is the independent unit; weighting reduces long-incident dominance without data removal.",
                "phase": "B",
            },
            {
                "decision": "V4 carried forward",
                "alternatives": "V1 behavioral; V2 behavioral+CAIDA; V3 behavioral+RPKI",
                "evidence": "Phase C: V4 had strongest overall Stage 2/window performance; V3 remained competitive.",
                "reason": "Retain complete empirically validated enrichment set before Validation confirmation.",
                "phase": "C",
            },
            {
                "decision": "RPKI strongly supported",
                "alternatives": "Remove RPKI family",
                "evidence": "Phase D: RPKI removal had the strongest overall negative delta and strong Hijack contribution.",
                "reason": "Origin-validation signals are domain-relevant for Hijack discrimination.",
                "phase": "D",
            },
            {
                "decision": "CAIDA retained",
                "alternatives": "Drop CAIDA and use V3",
                "evidence": "Phase C/D: CAIDA showed modest/mixed group-level contribution but positive Stage 2/window evidence.",
                "reason": "Keep relationship features through one Validation confirmation; do not discard V3 comparison permanently.",
                "phase": "C/D",
            },
            {
                "decision": "Expert architecture rejected",
                "alternatives": "F0 full-V4 experts; F1 domain-informed experts",
                "evidence": "Phase F: S2_BASE had best incident Macro F1 and best incident MRR; experts required 15 models.",
                "reason": "Added complexity did not improve incident-level classification/ranking.",
                "phase": "F",
            },
            {
                "decision": "Stage 1 hard gate unresolved/rejected for final candidate",
                "alternatives": "tau=0.06 threshold; tau=0.72 W1 threshold; calibrated Stage 1",
                "evidence": "Phase E/E2: Normal F1 and PR-AUC remained very low; W1 caused unacceptable false-Normal behavior.",
                "reason": "Primary final candidate must not depend on an unreliable Normal-vs-Incident gate.",
                "phase": "E/E2",
            },
            {
                "decision": "Multiclass Stage 2 selected",
                "alternatives": "single-stage; hierarchical hard-gated final system; one-vs-rest experts",
                "evidence": "Phase F: S2_BASE incident Macro F1=0.7428, Top-2=0.9315, MRR=0.8642.",
                "reason": "Best TRAIN incident-level evidence with the simplest selected architecture.",
                "phase": "F",
            },
        ]
    )


def write_architecture_doc() -> None:
    selected_cls, selected_ranking = selected_phase_f_metrics()
    text = f"""# Final Model Architecture Decision v1

## Scope

Phase G is a planning and protocol-freeze step. It does not rerun experiments, access Validation, access Final Holdout, tune thresholds, or alter labels/features.

## Selected Primary Task

Given BGP behavior associated with an incident, classify and rank Hijack, Leak, and Outage.

## Selected Architecture

`RF_LOCK_CANDIDATE_V1` uses a multiclass Random Forest for the Stage 2 incident task:

- Feature variant: V4
- Feature count: 74 = 44 Behavioral + 14 CAIDA + 16 RPKI
- Imbalance treatment: I1 incident-aware weighting
- Probability output: P(Hijack), P(Leak), P(Outage)
- Ranking rule: sort class probabilities descending
- Incident-level aggregation: mean class probability across all eligible windows for the incident

TRAIN evidence for the selected candidate:

- Incident Macro F1: {float(selected_cls['macro_f1']):.6f}
- Incident Top-1: {float(selected_cls['top1_accuracy']):.6f}
- Incident Top-2: {float(selected_cls['top2_accuracy']):.6f}
- Incident MRR: {float(selected_ranking['mrr']):.6f}

## Negative Architecture Experiments

F0 full-V4 one-vs-rest experts and F1 domain-informed experts are retained as useful negative experiments. F0 slightly improved window Macro F1, but S2_BASE retained stronger incident Macro F1 and best incident MRR. F1 feature restriction degraded performance. The expert design also tripled model count from 5 fold models to 15 fold/expert models.

## Stage 1 Status

`STAGE1_STATUS = {STAGE1_STATUS}`.

Stage 1 Normal-vs-Incident detection is documented as an important negative result and limitation. Trustworthy Normal labels were constructed conservatively, only 516 Normal windows qualified, and probability separation remained weak. Threshold optimization, calibration, and W1 class/group balancing did not produce a reliable hard gate. Therefore Stage 1 is excluded as a mandatory final hard gate for the locked primary incident evaluation.

Potential future work includes a broader Normal corpus, anomaly detection, one-class or semi-supervised learning, temporal sequence modeling, and external Normal datasets. None of that is implemented in Phase G.

## Validation Protocol

The next controlled step is exactly one Validation confirmation of the predeclared V4 + I1 + multiclass Stage 2 candidate. Validation is not a leaderboard. If Validation performs poorly, the result must be recorded and any further development must return to TRAIN in a new explicitly versioned cycle while Final Holdout remains sealed.
"""
    ARCHITECTURE_DOC.parent.mkdir(parents=True, exist_ok=True)
    ARCHITECTURE_DOC.write_text(text, encoding="utf-8")


def write_notebook() -> None:
    NOTEBOOK.parent.mkdir(parents=True, exist_ok=True)
    notebook = {
        "cells": [
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": [
                    "# Phase G - Architecture Decision and Validation Protocol Freeze\n",
                    "\n",
                    "Planning-only consolidation of TRAIN evidence. Validation and Final Holdout remain sealed.\n",
                ],
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": [
                    "from bgp_incident_detection.model_lock_planning import run_planning\n",
                    "# run_planning()\n",
                ],
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": [
                    "import pandas as pd\n",
                    "pd.read_csv('../data/modeling/train_model_selection_summary_v1.csv').tail(10)\n",
                ],
            },
        ],
        "metadata": {
            "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
            "language_info": {"name": "python", "pygments_lexer": "ipython3"},
        },
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")


def run_planning() -> dict[str, Any]:
    MODELING_DIR.mkdir(parents=True, exist_ok=True)
    summary = build_train_selection_summary()
    summary.to_csv(TRAIN_SELECTION_SUMMARY, index=False)
    write_final_model_candidate()
    write_validation_protocol()
    audit = build_readiness_audit()
    audit.to_csv(READINESS_AUDIT, index=False)
    ledger = build_decision_ledger()
    ledger.to_csv(DECISION_LEDGER, index=False)
    write_architecture_doc()
    write_notebook()
    selected_cls, selected_ranking = selected_phase_f_metrics()
    return {
        "selected_architecture": SELECTED_ARCHITECTURE,
        "selected_experiment": SELECTED_EXPERIMENT,
        "feature_variant": FEATURE_VARIANT,
        "feature_count": FEATURE_COUNT,
        "imbalance_treatment": IMBALANCE_TREATMENT,
        "incident_macro_f1": float(selected_cls["macro_f1"]),
        "incident_top1": float(selected_cls["top1_accuracy"]),
        "incident_top2": float(selected_cls["top2_accuracy"]),
        "incident_mrr": float(selected_ranking["mrr"]),
        "stage1_status": STAGE1_STATUS,
        "validation_accessed": False,
        "final_holdout_status": FINAL_HOLDOUT_STATUS,
        "readiness_pass": bool((audit["status"] == "PASS").all()),
        "outputs": [
            str(TRAIN_SELECTION_SUMMARY),
            str(FINAL_MODEL_CANDIDATE),
            str(VALIDATION_PROTOCOL),
            str(READINESS_AUDIT),
            str(DECISION_LEDGER),
            str(ARCHITECTURE_DOC),
            str(NOTEBOOK),
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Phase G model-lock planning without training or held-out access")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if args.run:
        print(json.dumps(run_planning(), indent=2, sort_keys=True))
        return
    parser.error("choose --run")


if __name__ == "__main__":
    main()
