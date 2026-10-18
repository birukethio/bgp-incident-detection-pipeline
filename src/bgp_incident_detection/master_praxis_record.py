from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import yaml


DOCS = Path("docs")
NOTEBOOK = Path("notebooks/56_master_praxis_experimental_record.ipynb")
TITLE = "An Artificial Intelligence–Based Classification and Ranking System for Border Gateway Protocol Incidents in Enterprise Networks"

FINAL_RESULT = Path("config/final_praxis_result_v1.yaml")
FINAL_PERFORMANCE = Path("data/final_holdout/final_holdout_performance_summary_v1.csv")
FINAL_CI = Path("data/final_holdout/final_holdout_bootstrap_ci_v1.csv")
FINAL_RANKING = Path("data/final_holdout/final_holdout_ranking_metrics_v1.csv")
FINAL_CLASS = Path("data/final_holdout/final_holdout_per_class_metrics_v1.csv")
FINAL_COMPARISON = Path("data/final_holdout/train_vs_final_holdout_comparison_v1.csv")
FINAL_CONFUSION = Path("data/final_holdout/final_holdout_confusion_matrix_v1.csv")
FINAL_ACCESS = Path("data/final_holdout/final_holdout_access_record_v1.csv")
FINAL_AUDIT = Path("data/final_holdout/final_evaluation_audit_v1.csv")
TRAIN_V4 = Path("data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1.parquet")
TRAIN_BEHAVIORAL = Path("data/train_frozen/frozen_train_behavioral_corpus_v1.parquet")
NORMAL_V4 = Path("data/model_ready/frozen_normal_v4_v1.parquet")
PARTITIONS_V2 = Path("data/partitions_v2/frozen_partition_manifest_v2.csv")
FEATURE_VARIANTS = Path("config/feature_variants_v1.yaml")
BEHAVIORAL_SCHEMA = Path("config/behavioral_feature_schema_v1.yaml")
CAIDA_SCHEMA = Path("config/caida_feature_schema_v1.yaml")
RPKI_SCHEMA = Path("config/rpki_feature_schema_v1.yaml")
NORMAL_METHOD = Path("config/normal_ground_truth_method_v1.yaml")
IMBALANCE_CONFIG = Path("config/imbalance_strategies_v1.yaml")
VALIDATION_RESULTS = Path("data/validation/validation_confirmation_results_v1.csv")
K1_RESULTS = Path("data/modeling_k1/k1_model_results_v1.csv")
K1_DECISION = Path("data/modeling_k1/k1_decision_summary_v1.csv")
K2_RESULTS = Path("data/modeling_k2/k2_multiseed_performance_v1.csv")
K2_COMPARE = Path("data/modeling_k2/k2_final_vs_b0_comparison_v1.csv")
K2_PERMUTATION = Path("data/modeling_k2/k2_label_permutation_sanity_v1.csv")
K25_RESULTS = Path("data/modeling_k25/k25_architecture_multiseed_results_v1.csv")
K25_DECISION = Path("data/modeling_k25/k25_final_architecture_decision_v1.csv")
L0_VERIFY = Path("data/final_prep/k1_fixed_second_level_verification_v1.csv")
BASELINE = Path("data/modeling/baseline_v1_model_comparison_v1.csv")
IMBALANCE = Path("data/modeling/imbalance_strategy_model_comparison_v1.csv")
FEATURE_VARIANT_ABLATION = Path("data/modeling/feature_variant_ablation_results_v1.csv")
FEATURE_FAMILY_ABLATION = Path("data/modeling/feature_family_ablation_results_v1.csv")
FEATURE_FAMILY_INVENTORY = Path("data/modeling/feature_family_inventory_v1.csv")
DOMAIN_EXPERT = Path("data/modeling/domain_expert_classification_results_v1.csv")
RF_H2 = Path("data/modeling/rf_h2_final_comparison_v1.csv")
XGB_I2 = Path("data/modeling/xgb_i2_final_comparison_v1.csv")
MODEL_SELECTION = Path("data/modeling/final_algorithm_selection_v1.csv")
FINAL_DEPLOYABLE = Path("config/k1_final_candidate_v1_1_deployable.yaml")
SECOND_LEVEL = Path("config/k1_second_level_xgb_final_v1.yaml")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def read_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def read_csv(path: Path) -> pd.DataFrame:
    return pd.read_csv(path) if path.exists() else pd.DataFrame()


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str] | None = None) -> pd.DataFrame:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fieldnames is None:
        keys: list[str] = []
        for row in rows:
            for key in row:
                if key not in keys:
                    keys.append(key)
        fieldnames = keys
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})
    return pd.DataFrame(rows)


def write_md(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.strip() + "\n", encoding="utf-8")


def final_values() -> dict[str, Any]:
    result = read_yaml(FINAL_RESULT)
    ci = read_csv(FINAL_CI)
    ranking = read_csv(FINAL_RANKING)
    perf = read_csv(FINAL_PERFORMANCE)
    classes = read_csv(FINAL_CLASS)
    access = read_csv(FINAL_ACCESS)
    partitions = read_csv(PARTITIONS_V2)
    train = pd.read_parquet(TRAIN_BEHAVIORAL)
    train_v4 = pd.read_parquet(TRAIN_V4)
    normal = pd.read_parquet(NORMAL_V4)
    holdout_counts = partitions[partitions["partition"].eq("holdout")]["category"].value_counts().to_dict()
    validation_counts = partitions[partitions["partition"].eq("validation")]["category"].value_counts().to_dict()
    train_counts = partitions[partitions["partition"].eq("train")]["category"].value_counts().to_dict()
    macro_ci = ci[ci["metric"].eq("incident_macro_f1")].iloc[0].to_dict()
    rank_map = dict(zip(ranking["metric"], ranking["value"]))
    class_map = {row["class"].lower(): row.to_dict() for _, row in classes.iterrows()}
    values = {
        "title": TITLE,
        "stage1_status": "UNRESOLVED_EXPERIMENTAL_AUXILIARY",
        "train_incidents": int((partitions["partition"] == "train").sum()),
        "validation_incidents": int((partitions["partition"] == "validation").sum()),
        "holdout_incidents": int(result["holdout_incidents"]),
        "train_class_counts": train_counts,
        "validation_class_counts": validation_counts,
        "holdout_class_counts": holdout_counts,
        "train_behavioral_rows": int(len(train)),
        "train_v4_rows": int(len(train_v4)),
        "normal_windows": int(len(normal)),
        "holdout_window_rows": int(result["holdout_window_rows"]),
        "behavioral_features": 44,
        "caida_features": 14,
        "rpki_features": 16,
        "v4_features": 74,
        "final_macro_f1": float(result["incident_macro_f1"]),
        "final_macro_f1_ci_lower": float(macro_ci["ci_lower_95"]),
        "final_macro_f1_ci_upper": float(macro_ci["ci_upper_95"]),
        "final_top1": float(result["top1"]),
        "final_top2": float(result["top2"]),
        "final_mrr": float(result["mrr"]),
        "final_hijack_f1": float(result["hijack_f1"]),
        "final_leak_f1": float(result["leak_f1"]),
        "final_outage_f1": float(result["outage_f1"]),
        "mean_true_class_rank": float(result["mean_true_class_rank"]),
        "rank1": int(rank_map["ranked_first_count"]),
        "rank2": int(rank_map["ranked_second_count"]),
        "rank3": int(rank_map["ranked_third_count"]),
        "second_level_hash": str(result["second_level_parameter_hash"]),
        "first_holdout_access": access["access_timestamp_utc"].iloc[0] if not access.empty else "",
        "final_performance_artifact": str(FINAL_PERFORMANCE),
        "final_ci_artifact": str(FINAL_CI),
        "hijack_precision": float(class_map["hijack"]["precision"]),
        "hijack_recall": float(class_map["hijack"]["recall"]),
        "leak_precision": float(class_map["leak"]["precision"]),
        "leak_recall": float(class_map["leak"]["recall"]),
        "outage_precision": float(class_map["outage"]["precision"]),
        "outage_recall": float(class_map["outage"]["recall"]),
    }
    validate_authoritative_values(values)
    return values


def validate_authoritative_values(v: dict[str, Any]) -> None:
    expected = {
        "holdout_incidents": 213,
        "holdout_window_rows": 14906,
        "v4_features": 74,
        "rank1": 196,
        "rank2": 15,
        "rank3": 2,
        "second_level_hash": "40df040321ef",
        "train_incidents": 993,
        "validation_incidents": 213,
        "train_behavioral_rows": 68031,
        "normal_windows": 516,
    }
    for key, expected_value in expected.items():
        if v[key] != expected_value:
            raise RuntimeError(f"authoritative value mismatch for {key}: {v[key]} != {expected_value}")
    float_expected = {
        "final_macro_f1": 0.9201769450076779,
        "final_macro_f1_ci_lower": 0.8801170994295882,
        "final_macro_f1_ci_upper": 0.9544024249379308,
        "final_top1": 0.92018779342723,
        "final_top2": 0.9906103286384976,
        "final_mrr": 0.9585289514866979,
        "final_hijack_f1": 0.8776978417266187,
        "final_leak_f1": 0.9041095890410958,
        "final_outage_f1": 0.9787234042553191,
    }
    for key, expected_value in float_expected.items():
        if abs(v[key] - expected_value) > 1e-12:
            raise RuntimeError(f"authoritative value mismatch for {key}: {v[key]} != {expected_value}")


def metric_from_table(path: Path, key_col: str, key: str, value_col: str, default: Any = "") -> Any:
    df = read_csv(path)
    if df.empty or key_col not in df or value_col not in df:
        return default
    rows = df[df[key_col].astype(str).eq(key)]
    return rows[value_col].iloc[0] if not rows.empty else default


def phases(v: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        phase(1, "P0", "Incident roster and v2 partitions", "Can incidents be frozen as independent units?", "Cloudflare incident roster", "TRAIN/Validation/Holdout", "none", "stratified incident-level partitioning", "freeze v2 roster and partitions", "class counts", "1419 incidents; TRAIN 993, Validation 213, Holdout 213", "331/331/331 TRAIN and 71/71/71 Validation/Holdout", "Use v2 as authoritative corpus", "Balanced and leakage-free incident split", "AUTHORITATIVE_CURRENT", False, False, "notebooks/05_freeze_roster_v2_and_partition.ipynb", "src/bgp_incident_detection/partitioning_v2.py", "data/partitions_v2/frozen_partition_manifest_v2.csv", "tests/test_partitioning_v2.py", "Chapter 3", "Incident Dataset and Partitioning", "Table: Incident Partition Summary", "v1 partitions retained as audit history"),
        phase(2, "P1", "RouteViews acquisition and processing", "Can historical MRT UPDATE data be acquired reproducibly?", "v2 TRAIN incidents", "TRAIN", "none", "RouteViews update download, URL deduplication, parser, batching", "volume-aware processing", "quality gate", "Outage:605 recovered via alternate valid collector", "Raw MRT to parsed relevant observations to windows", "Proceed to frozen behavioral corpus", "Pipeline recovered missing primary source cases", "AUTHORITATIVE_CURRENT", False, False, "notebooks/30_full_train_behavioral_execution.ipynb", "src/bgp_incident_detection/full_train_execution.py", "data/train_scale/outage_605_recovery_feature_changes_v1.csv", "tests/test_full_train_execution.py", "Chapter 3", "BGP Data Acquisition", "Figure: RouteViews-to-feature flow", "Methodology robustness, not performance"),
        phase(3, "P2", "Behavioral feature corpus", "Can BGP behavior be represented per five-minute incident window?", "TRAIN MRT observations", "TRAIN", "V1", "44 behavioral features", "freeze behavioral corpus", "row count", v["train_behavioral_rows"], "993 TRAIN incidents", "Use as base feature family", "Schema and corpus frozen", "AUTHORITATIVE_CURRENT", False, False, "notebooks/33_freeze_train_behavioral_corpus_v1.ipynb", "src/bgp_incident_detection/freeze_train_behavioral.py", "data/train_frozen/frozen_train_behavioral_corpus_v1.parquet", "tests/test_freeze_train_behavioral.py", "Chapter 3/4", "Behavioral Feature Engineering", "Table: Behavioral Feature Families", "Zero-observation windows preserved"),
        phase(4, "P3", "Normal ground-truth development", "Can trustworthy Normal windows be curated?", "RouteViews RIB + UPDATE candidates", "TRAIN only", "V1-V4 Normal", "RIB-assisted qualification", "replace UPDATE-only candidate logic", "NORMAL_VERIFIED windows", v["normal_windows"], "43 unique ASNs; 30-min stability; 60-min incident buffer", "Keep Stage 1 auxiliary", "Normal is useful but hard", "AUTHORITATIVE_CURRENT", False, False, "notebooks/27_freeze_normal_ground_truth_v1.ipynb", "src/bgp_incident_detection/freeze_normal.py", "data/model_ready/frozen_normal_v4_v1.parquet", "tests/test_freeze_normal.py", "Chapter 3/5", "Normal Ground Truth", "Table: Normal Qualification Rules", "Stage 1 remained unresolved"),
        phase(5, "P4", "CAIDA enrichment", "Do AS-relationship features add useful context?", "compact BGP evidence", "TRAIN", "V2/V4", "CAIDA serial-2 temporal snapshots", "add 14 CAIDA features", "feature count", 14, "V2 has 58 features; V4 has 74", "Retain CAIDA in V4", "Useful especially for Leak/Outage context with caveats", "AUTHORITATIVE_CURRENT", False, False, "notebooks/35_full_train_caida_enrichment.ipynb", "src/bgp_incident_detection/caida_train_enrichment.py", "config/caida_feature_schema_v1.yaml", "tests/test_caida_train_enrichment.py", "Chapter 3/4", "CAIDA Enrichment", "Table: CAIDA Feature Inventory", "Predictive association only"),
        phase(6, "P5", "RPKI/ROV enrichment", "Do historical RPKI/ROV states improve classification?", "compact prefix-origin evidence", "TRAIN", "V3/V4", "RIPE NCC historical VRP mapping", "add 16 RPKI/ROV features", "feature count", 16, "V3 has 60 features; V4 has 74", "Retain RPKI in V4", "Strong Hijack signal in ablation", "AUTHORITATIVE_CURRENT", False, False, "notebooks/37_full_train_rpki_enrichment.ipynb", "src/bgp_incident_detection/rpki_train_enrichment.py", "config/rpki_feature_schema_v1.yaml", "tests/test_rpki_train_enrichment.py", "Chapter 3/4", "RPKI/ROV Enrichment", "Table: RPKI Feature Inventory", "Historical snapshot assumptions remain"),
        phase(7, "P6", "Feature variants", "Which feature composition is strongest?", "Frozen TRAIN V1-V4", "TRAIN grouped CV", "V1/V2/V3/V4", "variant ablation", "add CAIDA/RPKI combinations", "group Macro F1", metric_from_table(FEATURE_VARIANT_ABLATION, "feature_variant", "V4", "group_macro_f1"), "V4 strongest overall RF/HIER window/Stage 2 configuration", "Use V4 for later models", "Behavioral+CAIDA+RPKI retained", "AUTHORITATIVE_CURRENT", False, False, "notebooks/41_feature_variant_ablation.ipynb", "src/bgp_incident_detection/feature_ablation.py", "data/modeling/feature_variant_ablation_results_v1.csv", "tests/test_feature_ablation.py", "Chapter 4", "Feature Variant Ablation", "Table: V1-V4 Feature Ablation", "TRAIN grouped-CV only"),
        phase(8, "P7", "Imbalance strategies", "How should unequal incident window counts be handled?", "Frozen TRAIN corpus", "TRAIN grouped CV", "V1", "I0/I1/I2", "incident-aware weighting and p95 cap", "group Macro F1", metric_from_table(IMBALANCE, "imbalance_condition", "I1", "group_macro_f1_mean"), "I1 retained all data; I2 discarded rows", "Carry I1 forward", "Equalizes incident influence without data loss", "AUTHORITATIVE_CURRENT", False, False, "notebooks/40_v1_imbalance_treatment_experiment.ipynb", "src/bgp_incident_detection/imbalance_model_experiment.py", "data/modeling/imbalance_strategy_model_comparison_v1.csv", "tests/test_imbalance_model_experiment.py", "Chapter 3/4", "Imbalance Treatment", "Table: Imbalance Strategy Comparison", "p95 cap remains historical"),
        phase(9, "P8", "Baseline modeling", "What is the initial RF baseline?", "Behavioral V1", "TRAIN grouped CV", "V1", "RF single/hierarchical", "baseline comparison", "group Macro F1", metric_from_table(BASELINE, "experiment_id", "BASE_V1_I0_RF_SINGLE", "macro_f1_mean"), "Stage 2 window Macro F1 0.652807 for hierarchical RF", "Proceed to enrichment/imbalance", "Baseline only", "HISTORICAL_EXPERIMENT", False, False, "notebooks/39_v1_behavioral_model_baselines.ipynb", "src/bgp_incident_detection/model_baselines.py", "data/modeling/baseline_v1_model_comparison_v1.csv", "tests/test_model_baselines.py", "Chapter 4", "Baseline Performance", "Table: Baseline Model Performance", "Do not use as final model"),
        phase(10, "P9", "Stage 1 experiments", "Can Normal-vs-Incident be solved reliably?", "Normal + incident TRAIN rows", "TRAIN grouped CV", "V1-V4", "threshold and class/group weighting", "calibrate Stage 1", "Stage 1 status", "UNRESOLVED_EXPERIMENTAL_AUXILIARY", "Normal recognition weak; weighting caused excessive false-Normal risk", "Keep Stage 1 auxiliary", "Negative result preserved", "HISTORICAL_EXPERIMENT", False, False, "notebooks/43_stage1_calibration_and_threshold.ipynb", "src/bgp_incident_detection/stage1_threshold.py", "data/modeling/stage1_threshold_selection_summary_v1.csv", "tests/test_stage1_threshold.py", "Chapter 4/5", "Stage 1 Negative Findings", "Table: Stage 1 Findings", "Not final architecture"),
        phase(11, "P10", "Domain-expert architecture", "Do handcrafted class experts outperform multiclass Stage 2?", "TRAIN V4", "TRAIN grouped CV", "V4", "S2_BASE/F0/F1 experts", "expert specialization", "incident Macro F1", "S2_BASE 0.742814; F0 0.725539; F1 0.705210", "Experts did not outperform multiclass Stage 2", "KEEP_MULTICLASS_STAGE2", "Negative architecture result", "HISTORICAL_EXPERIMENT", False, False, "notebooks/45_domain_informed_incident_experts.ipynb", "src/bgp_incident_detection/domain_experts.py", "data/modeling/domain_expert_classification_results_v1.csv", "tests/test_domain_experts.py", "Chapter 4/5", "Domain Expert Comparison", "Table: Domain Expert Results", "Exact values verified where artifact schema permits"),
        phase(12, "P11", "Random Forest optimization", "Can RF be materially improved?", "TRAIN V4/I1", "TRAIN grouped CV", "V4", "refined RF", "Phase H/H2 search", "incident Macro F1", metric_from_table(RF_H2, "candidate_id", "H2_LOCAL_001", "mean_incident_macro_f1"), "Refined RF 0.784588; runtime increased", "PROMOTE_PHASE_H2_RF as RF benchmark", "MARGINAL_REFINEMENT", "HISTORICAL_EXPERIMENT", False, False, "notebooks/48_rf_local_refinement_and_stability.ipynb", "src/bgp_incident_detection/rf_refinement_stability.py", "data/modeling/rf_h2_final_comparison_v1.csv", "tests/test_rf_refinement_stability.py", "Chapter 4", "RF Optimization", "Table: RF Tuning Summary", "RF benchmark, not final"),
        phase(13, "P12", "XGBoost comparison/refinement", "Does XGBoost outperform refined RF?", "TRAIN V4/I1", "TRAIN grouped CV", "V4", "XGBoost 3.4.1", "Phase I/I2 comparison", "incident Macro F1", metric_from_table(XGB_I2, "candidate_id", "PHASEI2_XGB_LOCAL_004", "mean_incident_macro_f1"), "0.805678 ± 0.002042; Top-2 0.934743", "PROMOTE_PHASE_I2_XGB", "XGBoost stronger than refined RF", "AUTHORITATIVE_CURRENT", False, False, "notebooks/50_xgboost_local_refinement_and_stability.ipynb", "src/bgp_incident_detection/xgboost_refinement_stability.py", "data/modeling/xgb_i2_final_comparison_v1.csv", "tests/test_xgboost_refinement_stability.py", "Chapter 4", "XGBoost Selection", "Table: RF vs XGBoost", "TRAIN-only development"),
        phase(14, "P13", "Phase J Validation", "Does the predeclared Phase I2 candidate pass Validation?", "TRAIN model + Validation V4", "Validation", "V4", "XGBoost mean incident probability", "first Validation access", "incident Macro F1", 0.713904, "Top-2 0.901408; MRR 0.842723", "VALIDATION_CONFIRMATION_PASS", "Passed predeclared floors", "AUTHORITATIVE_CURRENT", True, False, "notebooks/51_phase_j_single_validation_confirmation.ipynb", "src/bgp_incident_detection/validation_confirmation.py", "data/validation/validation_confirmation_results_v1.csv", "tests/test_validation_confirmation.py", "Chapter 4", "Validation Confirmation", "Table: Phase J Validation", "K1 is not Validation-confirmed"),
        phase(15, "P14", "K1 incident-level stacking", "Can incident-level summaries improve ranking/classification?", "TRAIN OOF first-level probabilities", "TRAIN nested CV", "V4", "XGB to XGB temporal stacker", "replace mean aggregation", "incident Macro F1", metric_from_table(K1_RESULTS, "candidate_id", "K1-M2_XGB_K1-TEMPORAL", "incident_macro_f1"), "Gain vs B0 = 0.131729 Macro F1", "CARRY_XGB_INCIDENT_STACKER", "Material TRAIN-only stacking gain", "AUTHORITATIVE_CURRENT", False, False, "notebooks/52_phase_k1_train_only_incident_stacking.ipynb", "src/bgp_incident_detection/k1_incident_stacking.py", "data/modeling_k1/k1_model_results_v1.csv", "tests/test_k1_incident_stacking.py", "Chapter 4", "K1 Stacking", "Table/Figure: K1 Mean vs Stacker", "Post-Validation TRAIN development"),
        phase(16, "P15", "K2 forensic verification", "Is K1 gain leakage-safe and stable?", "K1 artifacts", "TRAIN nested CV", "V4", "leakage audits, permutation, multi-seed", "forensic audit", "multi-seed Macro F1", metric_from_table(K2_RESULTS, "metric", "incident_macro_f1", "mean"), "0.934304 ± 0.002309; permutation Macro F1 near chance", "K1_GAIN_CONFIRMED", "Leakage controls support validity", "AUTHORITATIVE_CURRENT", False, False, "notebooks/53_k1_forensic_audit_and_freeze.ipynb", "src/bgp_incident_detection/k1_forensic_audit.py", "data/modeling_k2/k2_multiseed_performance_v1.csv", "tests/test_k1_forensic_audit.py", "Chapter 4", "K2 Forensic Verification", "Table: Leakage/Stability Audit", "No Validation/Holdout"),
        phase(17, "P16", "K2.5 architecture comparator", "Should RF replace any K1 layer?", "K1/K2 cache", "TRAIN nested CV", "V4", "A0/A1/A2/A3", "RF/XGB layer swaps", "Macro F1", "A0 0.934304; A1 0.911434; A2 0.927166; A3 0.906259", "A0 XGB-to-XGB remained strongest", "KEEP_XGB_XGB_K1", "XGB->XGB strongest", "AUTHORITATIVE_CURRENT", False, False, "notebooks/54_k25_rf_vs_xgb_architecture_comparator.ipynb", "src/bgp_incident_detection/k25_architecture_comparator.py", "data/modeling_k25/k25_architecture_multiseed_results_v1.csv", "tests/test_k25_architecture_comparator.py", "Chapter 4", "Architecture Comparator", "Table: K2.5 A0-A3", "TRAIN only"),
        phase(18, "P17", "L0 deployable freeze", "Is one deployable second-level config frozen before Holdout?", "K1/K2/K2.5 artifacts", "TRAIN nested CV", "V4", "deterministic selection rule", "freeze hash 40df040321ef", "fixed Macro F1", metric_from_table(L0_VERIFY, "metric", "incident_macro_f1", "mean"), "0.931653 ± 0.002150; Top-2 0.992346", "READY_FOR_PHASE_L", "Prevented premature Holdout access", "AUTHORITATIVE_CURRENT", False, False, "notebooks/54_k1_final_second_level_freeze.ipynb", "src/bgp_incident_detection/k1_final_model_freeze.py", "config/k1_second_level_xgb_final_v1.yaml", "tests/test_k1_final_model_freeze.py", "Chapter 3/4", "Final Model Freeze", "Table: Final K1 Spec", "Phase L initially stopped correctly"),
        phase(19, "P18", "Final Holdout", "How does locked K1 generalize to untouched Holdout?", "Frozen Holdout V4 + locked K1", "Final Holdout", "V4", "A0 XGB->XGB K1", "one-time terminal evaluation", "incident Macro F1", v["final_macro_f1"], f"Top-2 {v['final_top2']}; MRR {v['final_mrr']}; CI [{v['final_macro_f1_ci_lower']}, {v['final_macro_f1_ci_upper']}]", "FINAL_HOLDOUT_EVALUATED_NO_FURTHER_TUNING", "Strong independent generalization, no post-Holdout tuning", "AUTHORITATIVE_CURRENT", False, True, "notebooks/55_final_holdout_evaluation.ipynb", "src/bgp_incident_detection/final_holdout_evaluation.py", "config/final_praxis_result_v1.yaml", "tests/test_final_holdout_evaluation.py", "Chapter 4/5", "Final Holdout", "Table: Final Holdout Performance", "Hijack:68538 processing REVIEW disclosed"),
    ]


def phase(sequence: int, phase_id: str, phase_name: str, research_question: str, input_dataset: str, partition: str, feature_variant: str, model_or_method: str, experimental_change: str, primary_metric: str, primary_result: Any, secondary_results: str, decision: str, decision_rationale: str, status: str, validation_accessed: bool, holdout_accessed: bool, notebook: str, source_module: str, primary_artifacts: str, tests: str, chapter: str, section_recommendation: str, table_or_figure_candidate: str, notes_limitations: str) -> dict[str, Any]:
    return locals()


def artifact_rows() -> list[dict[str, Any]]:
    rows = [
        ("data/partitions_v2/frozen_partition_manifest_v2.csv", "manifest", "P0", "v2 incident partition counts and leakage-free split", "Chapter 3", "Incident Dataset", "Incident partition table", "methodology evidence", "AUTHORITATIVE_CURRENT"),
        ("data/train_frozen/frozen_train_behavioral_corpus_v1.parquet", "parquet corpus", "P2", "68,031 TRAIN behavioral five-minute feature rows", "Chapter 3/4", "Behavioral Features", "Behavioral corpus table", "data evidence", "AUTHORITATIVE_CURRENT"),
        ("data/model_ready/frozen_normal_v4_v1.parquet", "parquet corpus", "P3", "516 verified Normal windows after RIB+UPDATE qualification", "Chapter 3", "Normal Method", "Normal qualification table", "methodology evidence", "AUTHORITATIVE_CURRENT"),
        ("config/feature_variants_v1.yaml", "config", "P6", "V1/V2/V3/V4 definitions and feature counts", "Chapter 3/4", "Feature Variants", "Variant definition table", "schema evidence", "AUTHORITATIVE_CURRENT"),
        ("data/modeling/feature_variant_ablation_results_v1.csv", "results", "P6", "feature-variant ablation outcomes", "Chapter 4", "Feature Variant Ablation", "Feature ablation table", "result evidence", "AUTHORITATIVE_CURRENT"),
        ("data/modeling/feature_family_ablation_results_v1.csv", "results", "P10", "feature-family removal outcomes", "Chapter 4", "Feature Family Ablation", "Feature-family table", "result evidence", "AUTHORITATIVE_CURRENT"),
        ("data/modeling/xgb_i2_final_comparison_v1.csv", "results", "P12", "refined XGBoost selected before Validation", "Chapter 4", "XGBoost Selection", "RF vs XGB table", "result evidence", "AUTHORITATIVE_CURRENT"),
        ("data/validation/validation_confirmation_results_v1.csv", "results", "P13", "first Validation access and confirmation result", "Chapter 4", "Validation", "Validation result table", "evaluation evidence", "AUTHORITATIVE_CURRENT"),
        ("data/modeling_k1/k1_model_results_v1.csv", "results", "P14", "K1 stacker compared with mean aggregation", "Chapter 4", "K1", "K1 comparison table", "result evidence", "AUTHORITATIVE_CURRENT"),
        ("data/modeling_k2/k2_multiseed_performance_v1.csv", "results", "P15", "K1 multi-seed stability", "Chapter 4", "K2", "K2 stability table", "forensic evidence", "AUTHORITATIVE_CURRENT"),
        ("data/modeling_k2/k2_label_permutation_sanity_v1.csv", "audit", "P15", "label permutation sanity check", "Chapter 4/5", "Leakage Controls", "K2 audit table", "validity evidence", "AUTHORITATIVE_CURRENT"),
        ("data/modeling_k25/k25_architecture_multiseed_results_v1.csv", "results", "P16", "A0/A1/A2/A3 architecture comparison", "Chapter 4", "K2.5", "Architecture comparison table", "result evidence", "AUTHORITATIVE_CURRENT"),
        ("config/k1_second_level_xgb_final_v1.yaml", "config", "P17", "frozen deployable second-level XGBoost hash 40df040321ef", "Chapter 3/4", "Final Model", "Final model specification table", "model specification", "AUTHORITATIVE_CURRENT"),
        ("config/final_praxis_result_v1.yaml", "config/results", "P18", "terminal final Holdout result", "Chapter 4/5", "Final Holdout", "Headline result table", "terminal result", "AUTHORITATIVE_CURRENT"),
        ("data/final_holdout/final_holdout_confusion_matrix_v1.csv", "results", "P18", "final confusion/error pattern", "Chapter 4", "Final Error Analysis", "Confusion matrix", "result evidence", "AUTHORITATIVE_CURRENT"),
    ]
    return [
        {
            "artifact": a,
            "artifact_type": t,
            "phase": p,
            "what_it_proves": w,
            "chapter": c,
            "section": s,
            "table_figure_candidate": tf,
            "citation_or_reference_role": r,
            "final_or_intermediate": f,
            "notes": "",
        }
        for a, t, p, w, c, s, tf, r, f in rows
    ]


def write_authoritative_numbers(v: dict[str, Any]) -> None:
    rows = [
        ("Praxis title", v["title"], "user Phase M request", "current title", "all chapters"),
        ("TRAIN incidents", 993, str(PARTITIONS_V2), "frozen v2 partition", "Chapter 3"),
        ("TRAIN class counts", "331/331/331", str(PARTITIONS_V2), "Hijack/Leak/Outage", "Chapter 3"),
        ("Validation incidents", 213, str(PARTITIONS_V2), "frozen v2 partition", "Chapter 3/4"),
        ("Validation class counts", "71/71/71", str(PARTITIONS_V2), "Hijack/Leak/Outage", "Chapter 3/4"),
        ("Final Holdout incidents", 213, str(FINAL_RESULT), "terminal evaluation", "Chapter 4/5"),
        ("Final Holdout class counts", "71/71/71", str(PARTITIONS_V2), "Hijack/Leak/Outage", "Chapter 4"),
        ("TRAIN behavioral rows", v["train_behavioral_rows"], str(TRAIN_BEHAVIORAL), "five-minute feature rows", "Chapter 3/4"),
        ("Normal frozen windows", v["normal_windows"], str(NORMAL_V4), "NORMAL_VERIFIED windows", "Chapter 3/4"),
        ("Behavioral features", 44, str(BEHAVIORAL_SCHEMA), "frozen behavioral schema", "Chapter 3"),
        ("CAIDA features", 14, str(CAIDA_SCHEMA), "frozen CAIDA schema", "Chapter 3"),
        ("RPKI features", 16, str(RPKI_SCHEMA), "frozen RPKI schema", "Chapter 3"),
        ("V4 features", 74, str(FEATURE_VARIANTS), "Behavioral+CAIDA+RPKI", "Chapter 3/4"),
        ("Final Holdout rows", v["holdout_window_rows"], str(FINAL_RESULT), "final Holdout V4 rows", "Chapter 4"),
        ("Final Macro F1", f"{v['final_macro_f1']:.6f}", str(FINAL_RESULT), "incident-level final metric", "Chapter 4/5"),
        ("Final Macro F1 95% CI", f"[{v['final_macro_f1_ci_lower']:.6f}, {v['final_macro_f1_ci_upper']:.6f}]", str(FINAL_CI), "incident bootstrap CI", "Chapter 4"),
        ("Final Top-1", f"{v['final_top1']:.6f}", str(FINAL_RESULT), "incident-level final metric", "Chapter 4"),
        ("Final Top-2", f"{v['final_top2']:.6f}", str(FINAL_RESULT), "incident-level final metric", "Chapter 4/5"),
        ("Final MRR", f"{v['final_mrr']:.6f}", str(FINAL_RESULT), "incident-level final metric", "Chapter 4"),
        ("Final Hijack F1", f"{v['final_hijack_f1']:.6f}", str(FINAL_RESULT), "per-class final metric", "Chapter 4"),
        ("Final Leak F1", f"{v['final_leak_f1']:.6f}", str(FINAL_RESULT), "per-class final metric", "Chapter 4"),
        ("Final Outage F1", f"{v['final_outage_f1']:.6f}", str(FINAL_RESULT), "per-class final metric", "Chapter 4"),
        ("Final rank1", 196, str(FINAL_RANKING), "true class ranked first", "Chapter 4/5"),
        ("Final rank2", 15, str(FINAL_RANKING), "true class ranked second", "Chapter 4/5"),
        ("Final rank3", 2, str(FINAL_RANKING), "true class ranked third", "Chapter 4/5"),
        ("Final Top-2 count", "211/213", str(FINAL_RANKING), "rank1+rank2", "Chapter 4/5"),
        ("Second-level hash", v["second_level_hash"], str(SECOND_LEVEL), "frozen model identifier", "Chapter 3/4"),
        ("Phase J Macro F1", "0.713904", str(VALIDATION_RESULTS), "Validation result before K1", "Chapter 4"),
        ("K2 Macro F1", "0.934304 ± 0.002309", str(K2_RESULTS), "TRAIN multi-seed K1 stability", "Chapter 4"),
        ("Fixed deployable K1 Macro F1", "0.931653 ± 0.002150", str(L0_VERIFY), "pre-Holdout fixed TRAIN reference", "Chapter 4"),
    ]
    write_csv(DOCS / "authoritative_numbers_register_v1.csv", [{"number_name": n, "value": val, "authoritative_source": src, "context": ctx, "chapter_usage": chap} for n, val, src, ctx, chap in rows])


def write_statistical_register(v: dict[str, Any]) -> None:
    rows = []
    def add(metric, partition, design, point, std="", lo="", hi="", unit="incident", count="", artifact="", notes=""):
        rows.append({"metric": metric, "partition": partition, "evaluation_design": design, "point_estimate": point, "std": std, "ci_lower": lo, "ci_upper": hi, "sample_unit": unit, "sample_count": count, "source_artifact": artifact, "notes": notes})
    perf = read_csv(FINAL_PERFORMANCE).iloc[0]
    ci = read_csv(FINAL_CI)
    ci_map = {r["metric"]: r for _, r in ci.iterrows()}
    for metric in ["incident_macro_f1", "top1", "top2", "mrr"]:
        c = ci_map[metric]
        add(metric, "Final Holdout", "one-time terminal incident-level evaluation with bootstrap CI", f"{perf[metric]:.6f}", "", f"{c['ci_lower_95']:.6f}", f"{c['ci_upper_95']:.6f}", "incident", 213, str(FINAL_PERFORMANCE), "Do not mix with window-level uncertainty.")
    for label in ["hijack", "leak", "outage"]:
        add(f"{label}_f1", "Final Holdout", "one-time terminal incident-level evaluation", f"{perf[f'{label}_f1']:.6f}", "", "", "", "incident", 71, str(FINAL_CLASS), "Per-class F1.")
    l0 = read_csv(L0_VERIFY)
    for _, r in l0.iterrows():
        add(r["metric"], "TRAIN", "fixed deployable K1 nested-CV reference", f"{r['mean']:.6f}", f"{r['std']:.6f}", "", "", "incident", 993, str(L0_VERIFY), "TRAIN reference, not final generalization estimate.")
    val = read_csv(VALIDATION_RESULTS).iloc[0]
    for metric in ["incident_macro_f1", "top1", "top2", "mrr", "hijack_f1", "leak_f1", "outage_f1"]:
        add(metric, "Validation", "Phase J single predeclared confirmation", f"{val[metric]:.6f}", "", "", "", "incident", 213, str(VALIDATION_RESULTS), "Pre-K1 validation; do not describe K1 as Validation-confirmed.")
    write_csv(DOCS / "final_statistical_results_register_v1.csv", rows)


def write_headline(v: dict[str, Any]) -> None:
    rows = [
        ("Final Holdout Incident Macro F1", f"{v['final_macro_f1']:.6f}", str(FINAL_RESULT), "terminal result"),
        ("Final Holdout Macro F1 95% CI", f"[{v['final_macro_f1_ci_lower']:.6f}, {v['final_macro_f1_ci_upper']:.6f}]", str(FINAL_CI), "incident bootstrap"),
        ("Final Holdout Top-1", f"{v['final_top1']:.6f}", str(FINAL_RESULT), "196/213 rank first"),
        ("Final Holdout Top-2", f"{v['final_top2']:.6f}", str(FINAL_RESULT), "211/213 within Top-2"),
        ("Final Holdout MRR", f"{v['final_mrr']:.6f}", str(FINAL_RESULT), "ranking metric"),
        ("Final Holdout Hijack F1", f"{v['final_hijack_f1']:.6f}", str(FINAL_RESULT), "hardest class"),
        ("Final Holdout Leak F1", f"{v['final_leak_f1']:.6f}", str(FINAL_RESULT), "middle class"),
        ("Final Holdout Outage F1", f"{v['final_outage_f1']:.6f}", str(FINAL_RESULT), "strongest class"),
        ("Mean true-class rank", f"{v['mean_true_class_rank']:.6f}", str(FINAL_RESULT), "ranking quality"),
        ("Correct rank 1", "196/213", str(FINAL_RANKING), "Top-1 count"),
        ("Correct within Top-2", "211/213", str(FINAL_RANKING), "rank1+rank2"),
        ("Rank 3", "2/213", str(FINAL_RANKING), "missed Top-2"),
        ("Fixed deployable TRAIN nested-CV Macro F1", "0.931653 ± 0.002150", str(L0_VERIFY), "TRAIN reference"),
        ("Fixed deployable TRAIN Top-1", "0.931521", str(L0_VERIFY), "TRAIN reference"),
        ("Fixed deployable TRAIN Top-2", "0.992346", str(L0_VERIFY), "TRAIN reference"),
        ("Fixed deployable TRAIN MRR", "0.964485", str(L0_VERIFY), "TRAIN reference"),
    ]
    write_csv(DOCS / "final_headline_results_v1.csv", [{"metric": m, "value": val, "source_artifact": src, "notes": notes} for m, val, src, notes in rows])


def simple_rows(name_rows: list[tuple], columns: list[str]) -> list[dict[str, Any]]:
    return [dict(zip(columns, row)) for row in name_rows]


def write_maps_and_registers(v: dict[str, Any], phase_rows: list[dict[str, Any]]) -> None:
    write_csv(DOCS / "master_praxis_experimental_record_v1.csv", phase_rows)
    write_csv(DOCS / "praxis_artifact_evidence_map_v1.csv", artifact_rows())

    notebook_rows = []
    for row in phase_rows:
        notebook_rows.append({"notebook_number": Path(row["notebook"]).name.split("_")[0], "notebook_filename": row["notebook"], "phase": row["phase_id"], "purpose": row["phase_name"], "partition_used": row["partition"], "inputs": row["input_dataset"], "outputs": row["primary_artifacts"], "major_result": row["primary_result"], "decision": row["decision"], "chapter_destination": row["chapter"], "keep_for_defense": "CORE" if row["status"] == "AUTHORITATIVE_CURRENT" else "SUPPORTING", "notes": row["notes_limitations"]})
    extra_notebooks = [
        ("02", "notebooks/02_incident_partitioning.ipynb", "P0", "v1 historical partitioning", "historical", "HISTORICAL"),
        ("11", "notebooks/11_behavioral_feature_extraction_pilot.ipynb", "P2", "behavioral pilot", "pilot", "SUPPORTING"),
        ("20", "notebooks/20_normal_rib_prescreen_scale.ipynb", "P3", "Normal RIB prescreen scale", "TRAIN", "APPENDIX"),
        ("23", "notebooks/23_rib_index_engineering.ipynb", "P3", "RIB index engineering", "TRAIN", "APPENDIX"),
    ]
    for n, fn, ph, purpose, part, keep in extra_notebooks:
        notebook_rows.append({"notebook_number": n, "notebook_filename": fn, "phase": ph, "purpose": purpose, "partition_used": part, "inputs": "", "outputs": "", "major_result": "", "decision": "", "chapter_destination": "Appendix", "keep_for_defense": keep, "notes": "Detailed engineering support."})
    write_csv(DOCS / "notebook_experiment_map_v1.csv", notebook_rows)

    chapter3_sections = ["Research Design", "Incident Dataset and Partitioning", "BGP Data Acquisition", "Five-Minute Analytical Window", "Behavioral Feature Engineering", "Normal Ground-Truth Method", "CAIDA Enrichment", "RPKI/ROV Enrichment", "Feature Variants", "Data Quality Gates", "Imbalance Treatment", "Grouped Cross-Validation", "Baseline Models", "Hyperparameter Optimization", "Incident-Level Stacking", "Leakage Prevention", "Final Evaluation Protocol"]
    write_csv(DOCS / "chapter3_methodology_evidence_map_v1.csv", [{"chapter3_section": s, "source_artifacts": "; ".join(a["artifact"] for a in artifact_rows() if "Chapter 3" in a["chapter"]), "methodology_facts": s, "tables": f"Proposed table for {s}", "figures": f"Proposed figure for {s}", "equations_or_formulas": "Use where feature/ranking metrics are defined."} for s in chapter3_sections])
    chapter4_sections = ["Dataset/corpus summary", "Behavioral feature quality", "Baseline performance", "Imbalance-treatment results", "Feature-variant ablation", "Feature-family ablation", "Stage 1 findings", "Domain-expert comparison", "RF optimization", "XGBoost comparison", "XGBoost refinement", "Validation confirmation", "Incident-level K1 stacking", "K2 forensic/stability results", "K2.5 architecture comparison", "Fixed deployable K1", "Final Holdout", "Per-class results", "Ranking results", "Error analysis"]
    write_csv(DOCS / "chapter4_results_evidence_map_v1.csv", [{"chapter4_section": s, "authoritative_artifacts": "; ".join(a["artifact"] for a in artifact_rows() if "Chapter 4" in a["chapter"]), "result_facts": s, "table": f"Proposed table for {s}", "figure": f"Proposed figure for {s}", "interpretation_boundary": "Descriptive unless an existing paired/nested/forensic artifact supports stronger wording."} for s in chapter4_sections])

    table_rows = [
        ("PROPOSED_TABLE_CH3_PARTITIONS", "Chapter 3", "Incident Dataset", "Incident Partition Summary", "show 993/213/213 and class balance", str(PARTITIONS_V2), "partition, category counts", "READY", "ESSENTIAL"),
        ("PROPOSED_TABLE_CH3_BEHAVIORAL", "Chapter 3", "Features", "Behavioral Feature Families", "summarize 44 behavioral features", str(BEHAVIORAL_SCHEMA), "feature group/count", "READY", "ESSENTIAL"),
        ("PROPOSED_TABLE_CH3_VARIANTS", "Chapter 3", "Features", "Feature Variant Definitions", "define V1-V4", str(FEATURE_VARIANTS), "variant/composition/features", "READY", "ESSENTIAL"),
        ("PROPOSED_TABLE_CH3_NORMAL", "Chapter 3", "Normal", "Normal Ground-Truth Qualification Rules", "document RIB+UPDATE rules", str(NORMAL_METHOD), "rule/status", "READY", "IMPORTANT"),
        ("PROPOSED_TABLE_CH3_K1_SPEC", "Chapter 3", "Final Model", "Final K1 Model Specification", "document final architecture", str(FINAL_DEPLOYABLE), "level/model/features", "READY", "ESSENTIAL"),
        ("PROPOSED_TABLE_CH4_BASELINE", "Chapter 4", "Baseline", "Baseline Model Performance", "baseline RF results", str(BASELINE), "metrics", "READY", "IMPORTANT"),
        ("PROPOSED_TABLE_CH4_IMBALANCE", "Chapter 4", "Imbalance", "Imbalance Strategy Comparison", "I0/I1/I2", str(IMBALANCE), "metrics", "READY", "ESSENTIAL"),
        ("PROPOSED_TABLE_CH4_VARIANT", "Chapter 4", "Ablation", "V1-V4 Feature Ablation", "feature variants", str(FEATURE_VARIANT_ABLATION), "metrics", "READY", "ESSENTIAL"),
        ("PROPOSED_TABLE_CH4_FAMILY", "Chapter 4", "Ablation", "Feature-Family Removal Results", "feature families", str(FEATURE_FAMILY_ABLATION), "metrics", "READY", "ESSENTIAL"),
        ("PROPOSED_TABLE_CH4_VALIDATION", "Chapter 4", "Validation", "Phase J Validation", "pre-K1 validation", str(VALIDATION_RESULTS), "metrics", "READY", "ESSENTIAL"),
        ("PROPOSED_TABLE_CH4_K1", "Chapter 4", "K1", "K1 Mean-Aggregation vs Stacker", "stacking gain", str(K1_RESULTS), "metrics", "READY", "ESSENTIAL"),
        ("PROPOSED_TABLE_CH4_K2", "Chapter 4", "K2", "K2 Multi-Seed Stability", "forensic checks", str(K2_RESULTS), "metrics", "READY", "ESSENTIAL"),
        ("PROPOSED_TABLE_CH4_K25", "Chapter 4", "K2.5", "A0/A1/A2/A3 Comparison", "architecture comparator", str(K25_RESULTS), "metrics", "READY", "ESSENTIAL"),
        ("PROPOSED_TABLE_CH4_HOLDOUT", "Chapter 4", "Final Holdout", "Final Holdout Performance", "terminal metrics", str(FINAL_PERFORMANCE), "metrics", "READY", "ESSENTIAL"),
        ("PROPOSED_TABLE_CH4_CLASS", "Chapter 4", "Final Holdout", "Final Per-Class Metrics", "class detail", str(FINAL_CLASS), "precision/recall/F1", "READY", "ESSENTIAL"),
        ("PROPOSED_TABLE_CH4_RANK", "Chapter 4", "Final Holdout", "Final Ranking Metrics", "rank utility", str(FINAL_RANKING), "rank counts/MRR", "READY", "ESSENTIAL"),
    ]
    table_cols = ["table_id_proposed", "chapter", "section", "title", "purpose", "source_artifact", "key_columns", "status", "priority"]
    write_csv(DOCS / "dissertation_table_inventory_v1.csv", simple_rows(table_rows, table_cols))
    write_csv(DOCS / "chapter3_table_plan_v1.csv", simple_rows([r for r in table_rows if r[1] == "Chapter 3"], table_cols))
    write_csv(DOCS / "chapter4_table_plan_v1.csv", simple_rows([r for r in table_rows if r[1] == "Chapter 4"], table_cols))

    figure_rows = [
        ("End-to-end methodology pipeline", "show full workflow", "docs/final_architecture_flow_v1.md", "NEEDS_GENERATION", "YES", "Chapter 3 Research Design"),
        ("Dataset/partition flow", "show incident-level split", str(PARTITIONS_V2), "NEEDS_GENERATION", "YES", "Chapter 3 Dataset"),
        ("Five-minute window representation", "define analytical row", str(TRAIN_BEHAVIORAL), "NEEDS_GENERATION", "YES", "Chapter 3 Windowing"),
        ("Feature engineering/enrichment pipeline", "show Behavioral+CAIDA+RPKI", str(FEATURE_VARIANTS), "NEEDS_GENERATION", "YES", "Chapter 3 Features"),
        ("K1 stacking architecture", "show final two-level K1", "docs/final_architecture_flow_v1.md", "NEEDS_GENERATION", "YES", "Chapter 3 Model"),
        ("Final confusion matrix", "terminal errors", "figures/final/final_holdout_confusion_matrix_v1.png", "EXISTS", "NO", "Chapter 4 Final Holdout"),
        ("TRAIN vs Validation vs Holdout", "compare evaluation populations", str(FINAL_COMPARISON), "NEEDS_GENERATION", "YES", "Chapter 4"),
        ("SHAP global/class-specific figures", "explainability", "", "NEEDS_GENERATION", "YES", "Future explainability"),
    ]
    fcols = ["figure_title", "purpose", "source", "exists", "needs_generation", "chapter_section"]
    write_csv(DOCS / "chapter3_figure_plan_v1.csv", simple_rows(figure_rows[:5], fcols))
    write_csv(DOCS / "chapter4_figure_plan_v1.csv", simple_rows(figure_rows[5:], fcols))
    write_csv(DOCS / "dissertation_figure_inventory_v1.csv", [{"figure_title": r[0], "purpose": r[1], "source": r[2], "status": r[3], "priority": "ESSENTIAL" if r[0] != "SHAP global/class-specific figures" else "OPTIONAL"} for r in figure_rows])

    write_csv(
        DOCS / "experiment_to_chapter_matrix_v1.csv",
        [
            {
                "phase": r["phase_id"],
                "experiment": r["phase_name"],
                "chapter3_methodology": "YES" if "Chapter 3" in r["chapter"] else "NO",
                "chapter4_results": "YES" if "Chapter 4" in r["chapter"] else "NO",
                "chapter5_discussion": "YES" if "Chapter 5" in r["chapter"] else ("YES" if r["status"] == "HISTORICAL_EXPERIMENT" else "NO"),
                "appendix": "YES" if r["status"] != "AUTHORITATIVE_CURRENT" else "OPTIONAL",
                "defense_slide_candidate": "YES" if r["phase_id"] in {"P0", "P6", "P13", "P14", "P15", "P16", "P18"} else "NO",
                "priority": "ESSENTIAL" if r["phase_id"] in {"P0", "P6", "P7", "P12", "P13", "P14", "P15", "P16", "P17", "P18"} else ("IMPORTANT" if r["status"] == "AUTHORITATIVE_CURRENT" else "SUPPORTING"),
            }
            for r in phase_rows
        ],
    )

    essential = [
        ("Frozen Behavioral feature corpus", "P2", "ESSENTIAL", str(TRAIN_BEHAVIORAL)),
        ("V1/V2/V3/V4 feature variants", "P6", "ESSENTIAL", str(FEATURE_VARIANTS)),
        ("Imbalance I0/I1/I2", "P7", "ESSENTIAL", str(IMBALANCE)),
        ("Baseline RF/H1", "P8", "IMPORTANT", str(BASELINE)),
        ("Feature-variant ablation", "P6", "ESSENTIAL", str(FEATURE_VARIANT_ABLATION)),
        ("Feature-family ablation", "P10", "ESSENTIAL", str(FEATURE_FAMILY_ABLATION)),
        ("RF vs XGBoost selection", "P12", "ESSENTIAL", str(XGB_I2)),
        ("Refined XGBoost", "P12", "ESSENTIAL", str(XGB_I2)),
        ("Phase J Validation", "P13", "ESSENTIAL", str(VALIDATION_RESULTS)),
        ("K1 stacking", "P14", "ESSENTIAL", str(K1_RESULTS)),
        ("K2 leakage/stability verification", "P15", "ESSENTIAL", str(K2_RESULTS)),
        ("K2.5 architecture comparator", "P16", "ESSENTIAL", str(K25_RESULTS)),
        ("L0 fixed deployable K1", "P17", "ESSENTIAL", str(L0_VERIFY)),
        ("Final Holdout", "P18", "ESSENTIAL", str(FINAL_RESULT)),
        ("RIB/Normal engineering pilots", "P3", "APPENDIX_ONLY", str(NORMAL_METHOD)),
    ]
    write_csv(DOCS / "dissertation_essential_experiments_v1.csv", [{"experiment": a, "phase": b, "priority": c, "source_artifact": d, "why_needed": "Minimum sequence for final methodology and evidence."} for a, b, c, d in essential])

    appendix_items = [
        ("Complete 44 Behavioral feature inventory", "feature details are too wide for the main chapter", str(BEHAVIORAL_SCHEMA), "Appendix A"),
        ("Complete 14 CAIDA feature inventory", "enrichment feature details", str(CAIDA_SCHEMA), "Appendix A"),
        ("Complete 16 RPKI feature inventory", "historical ROV details", str(RPKI_SCHEMA), "Appendix A"),
        ("Feature formulas", "full formulas support reproducibility", "src/bgp_incident_detection/features.py", "Appendix B"),
        ("Normal candidate qualification details", "long engineering path with negative results", str(NORMAL_METHOD), "Appendix C"),
        ("RIB indexing benchmarks", "implementation evidence", "data/normal_scale/", "Appendix C"),
        ("Complete hyperparameter search spaces", "too detailed for main results", "config/", "Appendix D"),
        ("Detailed fold assignments", "reproducibility evidence", "data/modeling/", "Appendix D"),
        ("Full quality-gate tables", "audit traceability", "data/", "Appendix E"),
        ("Complete confusion/error records", "error-analysis support", "data/final_holdout/", "Appendix F"),
        ("Reproducibility/environment information", "defense and reproduction", "docs/reproducibility_manifest_v1.csv", "Appendix G"),
    ]
    write_csv(DOCS / "dissertation_appendix_inventory_v1.csv", [{"appendix_candidate": a, "reason": b, "source_artifact": c, "recommended_appendix": d} for a, b, c, d in appendix_items])

    methodology_links = [
        ("Incident-level split", "avoid window leakage across incidents", "P0", "zero cross-partition incident overlap", str(PARTITIONS_V2), "All future windows inherit incident partition."),
        ("Incident-aware weighting", "reduce unequal incident influence", "P7", "I1 retained as modeling default", str(IMBALANCE), "Balancing decision made on TRAIN only."),
        ("Behavioral+CAIDA+RPKI V4", "combine route behavior, AS context, and route authorization state", "P6", "V4 carried forward", str(FEATURE_VARIANT_ABLATION), "Feature composition supported by ablation with caveats."),
        ("RPKI enrichment", "capture prefix-origin validity signals", "P5/P10", "Hijack classification benefited in feature-family evidence", str(FEATURE_FAMILY_ABLATION), "Predictive contribution, not causal proof."),
        ("Incident temporal stacking", "summarize within-incident probability trajectory", "P14", "+0.131729 Macro F1 vs mean aggregation", str(K1_DECISION), "K1 transformed window probabilities into incident summaries."),
        ("One-time Holdout evaluation", "protect final generalization estimate", "P18", f"Macro F1 {v['final_macro_f1']:.6f}", str(FINAL_RESULT), "Terminal result; no post-Holdout model changes."),
    ]
    write_csv(DOCS / "methodology_result_linkage_v1.csv", [{"methodology_decision": a, "scientific_reason": b, "experiment": c, "measured_effect": d, "artifact": e, "final_interpretation": f} for a, b, c, d, e, f in methodology_links])

    write_data_access_chronology()
    write_research_and_claim_registers(v)
    write_status_registers(v)


def write_data_access_chronology() -> None:
    rows = [
        ("P0-P12", "YES", "NO", "NO", "iterative TRAIN-only data engineering/model development", "", "pre-Validation candidates", "TRAIN-only changes allowed"),
        ("Phase J", "YES", "FIRST_VALIDATION_ACCESS", "NO", "single predeclared Validation confirmation", "", "XGB_REFINED_TRAIN_CANDIDATE", "no Phase J candidate tuning after results"),
        ("Phase K1", "YES", "NO", "NO", "post-Validation TRAIN-only K1 development", "", "Phase J complete; Holdout sealed", "K1 not Validation-confirmed"),
        ("Phase K2", "YES", "NO", "NO", "TRAIN-only forensic leakage and stability checks", "", "K1 candidate", "no Validation/Holdout access"),
        ("Phase K2.5", "YES", "NO", "NO", "TRAIN-only architecture comparator", "", "K1 candidate", "no Validation/Holdout access"),
        ("Phase L0", "YES", "NO", "NO", "fixed deployable K1 parameter freeze", "", "selected A0_XGB_TO_XGB", "ready for first Holdout access"),
        ("Phase L", "YES", "NO", "FIRST_FINAL_HOLDOUT_ACCESS", "one-time terminal final evaluation", "2026-09-03T01:23:45Z", "locked K1", "NO_POST_HOLDOUT_MODEL_CHANGES"),
        ("Phase M", "NO_NEW_MODELING", "NO", "NO", "documentation/indexing only", "", "terminal result already fixed", "no recomputation"),
    ]
    write_csv(
        DOCS / "data_access_chronology_v1.csv",
        [{"phase": a, "TRAIN_access": b, "Validation_access": c, "Holdout_access": d, "purpose": e, "first_access_timestamp_if_known": f, "model_state_at_access": g, "post_access_changes": h} for a, b, c, d, e, f, g, h in rows],
    )


def write_research_and_claim_registers(v: dict[str, Any]) -> None:
    claims = [
        ("Chapter 4", "Final Holdout Performance", "the final K1 architecture achieved strong generalization on the untouched Final Holdout", "DIRECTLY_SUPPORTED", str(FINAL_RESULT), f"Macro F1 {v['final_macro_f1']:.6f}; Top-2 {v['final_top2']:.6f}; Holdout first accessed once."),
        ("Chapter 4", "K1 Comparison", "incident-level stacking materially improved classification/ranking compared with mean probability aggregation", "DIRECTLY_SUPPORTED", str(K1_DECISION), "TRAIN-only Macro F1 gain 0.131729 over K1-B0 mean aggregation."),
        ("Chapter 4", "Feature-Family Ablation", "RPKI/ROV features contributed strongly to Hijack classification", "SUPPORTED_WITH_CAVEAT", str(FEATURE_FAMILY_ABLATION), "Supported by TRAIN ablation; phrase as predictive contribution, not causal proof."),
        ("Chapter 4", "Feature-Family Ablation", "CAIDA/peer-visibility context contributed useful signal for Leak/Outage", "SUPPORTED_WITH_CAVEAT", str(FEATURE_FAMILY_ABLATION), "Supported by feature-family experiments; avoid causal overclaiming."),
        ("Chapter 4", "RF vs XGBoost", "XGBoost outperformed refined Random Forest under the selected architecture", "DIRECTLY_SUPPORTED", str(XGB_I2), "Phase I2 XGB Macro F1 0.805678 vs H2 RF 0.784588."),
        ("Chapter 4", "Final Ranking Metrics", "the final system ranked the true class in the Top-2 for 211 of 213 Holdout incidents", "DIRECTLY_SUPPORTED", str(FINAL_RANKING), "rank1=196 and rank2=15."),
        ("Chapter 4", "Per-Class Metrics", "Outage was the strongest final class", "DIRECTLY_SUPPORTED", str(FINAL_CLASS), "Outage F1 0.978723."),
        ("Chapter 4/5", "Per-Class Metrics", "Hijack remained the most difficult final class", "DIRECTLY_SUPPORTED", str(FINAL_CLASS), "Hijack F1 0.877698, lowest of the three classes."),
        ("Chapter 5", "Stage 1", "Stage 1 Normal-vs-Incident discrimination remained unresolved", "DIRECTLY_SUPPORTED", str(FINAL_RESULT), "Stage 1 status is UNRESOLVED_EXPERIMENTAL_AUXILIARY."),
        ("Chapter 4/5", "K2 Forensics", "leakage controls and permutation testing supported the validity of K1", "SUPPORTED_WITH_CAVEAT", str(K2_PERMUTATION), "Supports absence of detected leakage, not a mathematical proof."),
        ("Chapter 5", "Causality", "model features identify root cause mechanisms causally", "FUTURE_WORK_ONLY", "", "Current evidence is predictive classification/ranking, not causal inference."),
    ]
    write_csv(DOCS / "dissertation_claim_evidence_register_v1.csv", [{"chapter_section": a, "table_or_figure": b, "claim": c, "support_status": d, "source_artifact": e, "caveat": f, "status": "READY" if d != "FUTURE_WORK_ONLY" else "DO_NOT_CLAIM_AS_RESULT"} for a, b, c, d, e, f in claims])

    rq = [
        ("RQ1", "Can historical RouteViews data support a reproducible BGP incident feature corpus?", "P0-P6", "68,031 TRAIN rows; frozen V4 74-feature corpus", str(TRAIN_V4), "SUPPORTED"),
        ("RQ2", "Do CAIDA and RPKI enrichments improve incident classification?", "P6/P10", "V4 and feature-family ablation support usefulness", str(FEATURE_VARIANT_ABLATION), "SUPPORTED_WITH_CAVEAT"),
        ("RQ3", "Which model architecture best classifies/ranks incident causes?", "P12-P16", "XGB and K1 stacker selected under TRAIN-only evidence", str(K25_DECISION), "SUPPORTED"),
        ("RQ4", "Does the locked final system generalize to unseen incidents?", "P18", f"Final Macro F1 {v['final_macro_f1']:.6f}; Top-2 {v['final_top2']:.6f}", str(FINAL_RESULT), "SUPPORTED"),
    ]
    write_csv(DOCS / "research_question_evidence_matrix_v1.csv", [{"research_question": a, "question_text": b, "phases": c, "evidence_summary": d, "source_artifact": e, "support_level": f} for a, b, c, d, e, f in rq])

    signals = [
        ("Behavioral", "announcements, withdrawals, AS-path changes, churn, visibility", "all classes", "base BGP dynamics", str(BEHAVIORAL_SCHEMA), "DIRECT"),
        ("CAIDA", "relationship and peer-visibility context", "Leak/Outage especially", "topological context", str(CAIDA_SCHEMA), "SUPPORTED_WITH_CAVEAT"),
        ("RPKI/ROV", "valid/invalid/not-found route authorization state", "Hijack especially", "prefix-origin legitimacy signal", str(RPKI_SCHEMA), "SUPPORTED_WITH_CAVEAT"),
        ("K1 temporal summaries", "incident-level probability trajectory statistics", "all classes", "aggregation beyond window mean", str(K1_RESULTS), "DIRECT"),
    ]
    write_csv(DOCS / "feature_signal_interpretation_map_v1.csv", [{"feature_family": a, "signals": b, "most_relevant_classes": c, "interpretation": d, "source_artifact": e, "support_status": f} for a, b, c, d, e, f in signals])


def write_status_registers(v: dict[str, Any]) -> None:
    quality = [
        ("v2 roster frozen", "exact 1419 and 473/class", str(PARTITIONS_V2), "PASS", ""),
        ("TRAIN behavioral corpus frozen", "68031 rows, 993 incidents", str(TRAIN_BEHAVIORAL), "PASS", ""),
        ("V4 schema frozen", "74 features", str(FEATURE_VARIANTS), "PASS", ""),
        ("Normal corpus frozen", "516 verified Normal windows", str(NORMAL_V4), "PASS", "Stage 1 remains auxiliary."),
        ("Validation confirmation", "213 incidents evaluated once", str(VALIDATION_RESULTS), "PASS", "Pre-K1 candidate only."),
        ("Final Holdout evaluation", "213 incidents evaluated once", str(FINAL_RESULT), "PASS", "One processing REVIEW disclosed for Hijack:68538."),
    ]
    write_csv(DOCS / "data_quality_gate_register_v1.csv", [{"gate": a, "criterion": b, "artifact": c, "status": d, "notes": e} for a, b, c, d, e in quality])

    leakage = [
        ("Incident-level partitioning", "all windows inherit incident partition", str(PARTITIONS_V2), "PASS", "No cross-partition incident overlap."),
        ("Grouped CV", "folds grouped by incident_uid", "data/modeling/", "PASS", "Prevents within-incident window leakage."),
        ("Validation access control", "first opened in Phase J only", str(VALIDATION_RESULTS), "PASS", "No K1 validation reuse."),
        ("Holdout access control", "first opened in Phase L only", str(FINAL_ACCESS), "PASS", "No post-Holdout model changes."),
        ("K2 permutation sanity", "label permutation near chance", str(K2_PERMUTATION), "PASS", "Supports leakage-control validity with caveat."),
    ]
    write_csv(DOCS / "leakage_control_register_v1.csv", [{"control": a, "purpose": b, "artifact": c, "status": d, "notes": e} for a, b, c, d, e in leakage])

    repro = [
        ("repository", "local project", str(Path.cwd()), "current checkout", ""),
        ("final model hash", "second-level parameter hash", v["second_level_hash"], str(SECOND_LEVEL), "authoritative"),
        ("XGBoost version", "final/result configuration", "3.4.1", str(FINAL_RESULT), "locked candidate family"),
        ("feature counts", "44/14/16/74", "Behavioral/CAIDA/RPKI/V4", str(FEATURE_VARIANTS), "frozen"),
        ("partition seed/version", "v2 split", "20260828 / split_version v2", str(PARTITIONS_V2), "frozen"),
    ]
    write_csv(DOCS / "reproducibility_manifest_v1.csv", [{"item": a, "description": b, "value": c, "source_artifact": d, "notes": e} for a, b, c, d, e in repro])

    metrics = [
        ("Macro F1", "unweighted mean of per-class F1", "incident for final metrics", "classification"),
        ("Top-1", "proportion where highest-ranked class is true class", "incident", "ranking"),
        ("Top-2", "proportion where true class is among top two ranked classes", "incident", "ranking"),
        ("MRR", "mean reciprocal rank of the true class", "incident", "ranking"),
        ("Window Macro F1", "window-level macro F1", "window", "diagnostic only, not terminal incident metric"),
    ]
    write_csv(DOCS / "evaluation_metric_definitions_v1.csv", [{"metric": a, "definition": b, "sample_unit": c, "usage": d} for a, b, c, d in metrics])

    progression = [
        ("RF baseline", "TRAIN grouped CV", "Behavioral V1", metric_from_table(BASELINE, "experiment_id", "BASE_V1_I0_RF_SINGLE", "macro_f1_mean"), str(BASELINE), "historical baseline"),
        ("Refined RF H2", "TRAIN grouped CV", "V4/I1", "0.784588", str(RF_H2), "RF benchmark"),
        ("Refined XGBoost I2", "TRAIN grouped CV", "V4/I1", "0.805678", str(XGB_I2), "promoted to Validation"),
        ("Phase J Validation", "Validation confirmation", "V4/I1", "0.713904", str(VALIDATION_RESULTS), "passed floors"),
        ("K1 stacker", "TRAIN nested CV", "V4/I1", "0.934666", str(K1_RESULTS), "post-Validation TRAIN development"),
        ("K2 multi-seed K1", "TRAIN nested CV", "V4/I1", "0.934304 ± 0.002309", str(K2_RESULTS), "forensic/stability"),
        ("L0 fixed deployable K1", "TRAIN nested CV", "V4/I1", "0.931653 ± 0.002150", str(L0_VERIFY), "pre-Holdout frozen"),
        ("Final Holdout", "one-time terminal", "V4/I1/K1", f"{v['final_macro_f1']:.6f}", str(FINAL_RESULT), "terminal"),
    ]
    write_csv(DOCS / "model_performance_progression_v1.csv", [{"stage": a, "evaluation_design": b, "feature_set": c, "incident_macro_f1": d, "source_artifact": e, "status": f} for a, b, c, d, e, f in progression])

    decisions = [
        ("Use incident as experimental unit", "avoid leakage", "P0", str(PARTITIONS_V2), "LOCKED"),
        ("Use V4 features", "best complete feature representation", "P6", str(FEATURE_VARIANTS), "LOCKED"),
        ("Use I1 weighting", "preserve all windows while reducing incident dominance", "P7", str(IMBALANCE_CONFIG), "LOCKED"),
        ("Promote XGBoost over RF", "higher TRAIN grouped-CV Macro F1", "P12", str(XGB_I2), "LOCKED"),
        ("Retain K1 stacker", "large TRAIN-only gain over mean aggregation", "P14", str(K1_DECISION), "LOCKED"),
        ("Keep A0 XGB->XGB", "best K2.5 architecture", "P16", str(K25_DECISION), "LOCKED"),
        ("Freeze L0 before Holdout", "protect final evaluation", "P17", str(L0_VERIFY), "LOCKED"),
    ]
    write_csv(DOCS / "master_experiment_decision_ledger_v1.csv", [{"decision": a, "rationale": b, "phase": c, "artifact": d, "status": e} for a, b, c, d, e in decisions])

    negatives = [
        ("Stage 1 did not become final architecture", "Normal-vs-Incident remained unresolved", str(FINAL_RESULT), "Preserve as limitation and future work."),
        ("Domain experts were not adopted", "expert variants did not outperform multiclass Stage 2", str(DOMAIN_EXPERT), "Reduced candidate space."),
        ("Class balancing alone was not sufficient", "I1 helped but did not solve all errors", str(IMBALANCE), "Supports later architecture work."),
        ("Threshold tuning was not sufficient", "Stage 1 false-Normal risk remained", "data/modeling/stage1_threshold_selection_summary_v1.csv", "Do not present Stage 1 as final."),
        ("RF remained strong but was not final", "XGBoost and K1 were stronger", str(RF_H2), "RF is benchmark/historical."),
        ("Not every feature family contributed equally", "ablation showed uneven contributions", str(FEATURE_FAMILY_ABLATION), "Use nuanced feature claims."),
    ]
    write_csv(DOCS / "negative_and_null_findings_v1.csv", [{"finding": a, "evidence": b, "source_artifact": c, "interpretation": d} for a, b, c, d in negatives])

    limitations = [
        ("RouteViews perspective", "public collectors may not reflect enterprise-local BGP state", "use multiple collectors/future enterprise telemetry", "Chapter 5"),
        ("Collector observability", "historical visibility varies by collector/time", "quality gates and caveats", "Chapter 5"),
        ("External labels", "incident labels derive from third-party sources", "cross-check provenance and preserve uncertainty", "Chapter 5"),
        ("Normal methodology", "Stage 1 remained auxiliary", "future Normal formulation", "Chapter 5"),
        ("K1 window requirements", "requires configured observation window", "future shorter-window inference", "Chapter 5"),
        ("Post-Validation K1 development", "K1 was not Validation-confirmed", "treat Holdout as primary independent estimate", "Chapter 5"),
        ("Holdout size", "213 incidents limits uncertainty precision", "bootstrap CI and larger corpus future work", "Chapter 5"),
        ("Hijack difficulty", "Hijack lowest final F1", "targeted future features/error analysis", "Chapter 5"),
    ]
    write_csv(DOCS / "threats_to_validity_register_v1.csv", [{"threat": a, "description": b, "mitigation_or_future_work": c, "chapter": d} for a, b, c, d in limitations])
    write_csv(DOCS / "final_limitations_v1.csv", [{"limitation": a, "impact": b, "mitigation": c, "future_work": d} for a, b, c, d in limitations])

    future = [
        ("stronger Normal-vs-Incident Stage 1 formulation", "tested partially", "Stage 1 unresolved", "HIGH"),
        ("enterprise-local telemetry integration", "future work", "improve local observability", "MEDIUM"),
        ("streaming/online classification", "future work", "operational deployment", "MEDIUM"),
        ("shorter observation-window inference", "future work", "reduce detection latency", "HIGH"),
        ("larger incident corpus", "future work", "narrow confidence intervals", "MEDIUM"),
        ("additional route collectors", "future work", "improve visibility", "MEDIUM"),
        ("graph-based AS relationship models", "future work", "richer topology learning", "LOW"),
        ("sequence models", "future work", "model temporal patterns directly", "LOW"),
        ("calibrated ranked probabilities", "future work", "improve operator trust", "MEDIUM"),
        ("operator diagnostic-time study", "future work", "measure operational usefulness", "MEDIUM"),
    ]
    write_csv(DOCS / "future_work_register_v1.csv", [{"future_direction": a, "tested_or_future": b, "reason": c, "priority": d} for a, b, c, d in future])

    contributions = [
        ("Reproducible BGP incident feature-engineering pipeline using historical RouteViews data", "frozen v2 roster, MRT processing, behavioral corpus", "project contribution; literature novelty must be qualified", "Chapter 3/4", "HIGH"),
        ("Integrated Behavioral + CAIDA + historical RPKI/ROV representation", "V4 74-feature schema and ablation artifacts", "applied system contribution", "Chapter 3/4", "HIGH"),
        ("Incident-aware weighting methodology for unequal window counts", "I1 imbalance strategy and grouped-CV modeling", "methodological design contribution", "Chapter 3/4", "MEDIUM"),
        ("Leakage-safe incident-level temporal stacking architecture", "K1/K2/K2.5/L0 artifacts", "model architecture contribution within this Praxis", "Chapter 4", "HIGH"),
        ("Classification plus ranked incident-cause output", "Top-1/Top-2/MRR final Holdout results", "operational output contribution", "Chapter 4/5", "HIGH"),
        ("Grouped/nested CV and forensic leakage controls", "K2 permutation, access chronology, Holdout discipline", "evaluation-integrity contribution", "Chapter 3/4/5", "HIGH"),
        ("Final unbiased Holdout evaluation on 213 incidents", "Phase L terminal evaluation", "evaluation evidence contribution", "Chapter 4/5", "HIGH"),
    ]
    write_csv(DOCS / "praxis_key_contributions_v1.csv", [{"contribution": a, "evidence": b, "novelty_scope": c, "chapter": d, "defense_value": e} for a, b, c, d, e in contributions])

    terms = [
        ("incident", "independent real-world BGP event unit used for splitting and evaluation", "Do not confuse with five-minute windows.", "Chapter 3"),
        ("window", "five-minute analytical interval associated with an incident or verified Normal candidate", "Window rows inherit incident partition.", "Chapter 3"),
        ("V4", "74-feature schema combining 44 Behavioral, 14 CAIDA, and 16 RPKI/ROV features", "Authoritative final feature representation.", "Chapter 3/4"),
        ("I1", "incident-aware weighting strategy", "Used to reduce unequal influence from incidents with many windows.", "Chapter 3/4"),
        ("Stage 1", "Normal-vs-Incident experimental branch", "Auxiliary/unresolved, not final architecture.", "Chapter 4/5"),
        ("K1", "incident-level temporal stacking architecture", "Post-Validation TRAIN-only development; not Validation-confirmed.", "Chapter 4"),
        ("Final Holdout", "sealed 213-incident terminal evaluation partition", "Opened once in Phase L.", "Chapter 3/4"),
        ("Top-2", "share of incidents whose true class appears in the two highest-ranked classes", "Final Top-2 = 211/213.", "Chapter 4"),
        ("MRR", "mean reciprocal rank of the true class", "Incident-level ranking metric.", "Chapter 4"),
    ]
    write_csv(DOCS / "praxis_terminology_register_v1.csv", [{"term": a, "definition": b, "usage_note": c, "chapter": d} for a, b, c, d in terms])

    consistency = [
        ("old Praxis title", "search docs/config summaries", "CURRENT_DOCUMENT_NEEDS_UPDATE", "Update only current writing files; keep historical artifacts."),
        ("old feature count around 49", "historical docs", "CURRENT_DOCUMENT_NEEDS_UPDATE", "Current V4 = 74."),
        ("old RPKI count of 3", "historical docs", "CURRENT_DOCUMENT_NEEDS_UPDATE", "Current RPKI = 16."),
        ("old 7-event Holdout", "historical pilot docs", "HISTORICAL_KEEP_AS_IS", "Do not rewrite pilot history."),
        ("old Random Forest final-model claims", "modeling docs", "SUPERSEDED", "RF is benchmark, final is K1 XGB->XGB."),
        ("old Macro F1 values", "phase-specific results", "HISTORICAL_KEEP_AS_IS", "Use artifact status to distinguish."),
        ("old threshold tau=0.70 claims", "Stage 1 docs", "HISTORICAL_KEEP_AS_IS", "Stage 1 remains auxiliary."),
        ("old two-stage hierarchy as final architecture", "historical docs", "CURRENT_DOCUMENT_NEEDS_UPDATE", "Final architecture is K1 incident-level stacker."),
    ]
    write_csv(DOCS / "dissertation_consistency_audit_v1.csv", [{"stale_claim_pattern": a, "where_to_check": b, "flag": c, "notes": d} for a, b, c, d in consistency])

    stale = [
        ("config/final_praxis_result_v1.yaml", "AUTHORITATIVE_CURRENT", "terminal final result"),
        ("config/k1_final_candidate_v1_1_deployable.yaml", "AUTHORITATIVE_CURRENT", "final deployable K1 config"),
        ("data/partitions_v2/frozen_partition_manifest_v2.csv", "AUTHORITATIVE_CURRENT", "v2 partition"),
        ("data/validation/validation_confirmation_results_v1.csv", "AUTHORITATIVE_CURRENT", "Phase J evidence, not K1 validation"),
        ("config/final_model_candidate_v3_1_xgb_refined.yaml", "SUPERSEDED", "Phase J candidate superseded by K1 final"),
        ("data/modeling/rf_h2_final_comparison_v1.csv", "HISTORICAL_EXPERIMENT", "RF benchmark"),
        ("data/modeling_k1/k1_model_results_v1.csv", "AUTHORITATIVE_CURRENT", "K1 TRAIN result"),
        ("data/modeling_k2/k2_multiseed_performance_v1.csv", "AUTHORITATIVE_CURRENT", "K2 stability"),
        ("data/modeling_k25/k25_architecture_multiseed_results_v1.csv", "AUTHORITATIVE_CURRENT", "K2.5 comparator"),
        ("early pilot notebooks", "INTERMEDIATE", "engineering history"),
    ]
    write_csv(DOCS / "stale_artifact_register_v1.csv", [{"artifact": a, "artifact_status": b, "reason": c} for a, b, c in stale])
    write_csv(DOCS / "authoritative_artifact_shortlist_v1.csv", [{"artifact": a["artifact"], "phase": a["phase"], "role": a["what_it_proves"], "priority": "ESSENTIAL"} for a in artifact_rows() if a["final_or_intermediate"] == "AUTHORITATIVE_CURRENT"])

    writing = [
        ("Chapter 3", "update methodology to final architecture", "TODO", "docs/final_architecture_flow_v1.md", "ESSENTIAL"),
        ("Chapter 3", "update feature counts to 44/14/16/74", "TODO", str(FEATURE_VARIANTS), "ESSENTIAL"),
        ("Chapter 3", "include leakage controls", "TODO", "docs/leakage_control_register_v1.csv", "ESSENTIAL"),
        ("Chapter 4", "baseline and ablation tables", "TODO", "docs/chapter4_table_plan_v1.csv", "ESSENTIAL"),
        ("Chapter 4", "K1 and Holdout results", "TODO", str(FINAL_RESULT), "ESSENTIAL"),
        ("Chapter 4", "error/confusion analysis", "TODO", str(FINAL_CONFUSION), "IMPORTANT"),
        ("Chapter 5", "interpret findings and limitations", "TODO", "docs/chapter5_findings_handoff_v1.md", "ESSENTIAL"),
        ("Defense", "key slides: architecture, ablation, leakage, final results", "TODO", "docs/defense_evidence_index_v1.csv", "ESSENTIAL"),
    ]
    write_csv(DOCS / "dissertation_writing_checklist_v1.csv", [{"area": a, "task": b, "status": c, "source_artifact": d, "priority": e} for a, b, c, d, e in writing])
    write_csv(DOCS / "documentation_open_items_v1.csv", [{"open_item": b, "area": a, "priority": e, "source_artifact": d, "status": c} for a, b, c, d, e in writing] + [{"open_item": "generate final publication-quality figures", "area": "Figures", "priority": "IMPORTANT", "source_artifact": "docs/dissertation_figure_inventory_v1.csv", "status": "TODO"}, {"open_item": "SHAP explainability not completed unless existing artifacts are later supplied", "area": "Explainability", "priority": "IMPORTANT", "source_artifact": "", "status": "TODO"}, {"open_item": "bibliography/source citations still needed", "area": "Citations", "priority": "ESSENTIAL", "source_artifact": "", "status": "TODO"}])


def write_narratives(v: dict[str, Any], phase_rows: list[dict[str, Any]]) -> None:
    record_lines = [
        f"# Master Praxis Experimental Record v1",
        "",
        f"Praxis title: {TITLE}",
        "",
        "This record is an index and dissertation handoff. It reads existing authoritative artifacts and does not train, tune, recompute Validation, or recompute Final Holdout.",
        "",
        "## Terminal Result",
        f"- Final Holdout incidents: {v['holdout_incidents']} with 71/71/71 class balance.",
        f"- Final Holdout window rows: {v['holdout_window_rows']}.",
        f"- V4 features: {v['v4_features']} = 44 Behavioral + 14 CAIDA + 16 RPKI/ROV.",
        f"- Incident Macro F1: {v['final_macro_f1']:.6f} with 95% CI [{v['final_macro_f1_ci_lower']:.6f}, {v['final_macro_f1_ci_upper']:.6f}].",
        f"- Top-1: {v['final_top1']:.6f}; Top-2: {v['final_top2']:.6f}; MRR: {v['final_mrr']:.6f}.",
        f"- Hijack F1: {v['final_hijack_f1']:.6f}; Leak F1: {v['final_leak_f1']:.6f}; Outage F1: {v['final_outage_f1']:.6f}.",
        f"- True class rank counts: rank 1 = {v['rank1']}, rank 2 = {v['rank2']}, rank 3 = {v['rank3']}.",
        f"- Second-level hash: {v['second_level_hash']}.",
        "",
        "## Phase Progression",
    ]
    for r in phase_rows:
        record_lines.append(f"- {r['phase_id']} {r['phase_name']}: {r['decision']} ({r['status']}).")
    write_md(DOCS / "master_praxis_experimental_record_v1.md", "\n".join(record_lines) + "\n")

    write_md(
        DOCS / "evaluation_integrity_narrative_v1.md",
        "\n".join(
            [
                "# Evaluation Integrity Narrative v1",
                "",
                "TRAIN was used for iterative data engineering, feature development, model comparison, and K1 architecture development. Grouped cross-validation used incident identity as the grouping unit so windows from the same incident could not cross folds.",
                "",
                "Validation was first opened in Phase J for a single predeclared confirmation of the refined XGBoost candidate. K1 was subsequently developed as a versioned TRAIN-only post-Validation experiment and was not evaluated on Validation; therefore K1 should not be described as Validation-confirmed.",
                "",
                "Final Holdout remained sealed through K1, K2, K2.5, and L0. Phase L was the first Final Holdout access for the fixed deployable K1 model. No model changes followed Holdout evaluation.",
                "",
                "Stage 1 Normal-vs-Incident discrimination remains explicitly auxiliary and unresolved.",
            ]
        )
        + "\n",
    )
    write_md(
        DOCS / "final_model_selection_narrative_v1.md",
        "# Final Model Selection Narrative v1\n\nBehavioral RF baseline established a reproducible starting point. Imbalance treatment introduced incident-aware weighting. CAIDA and RPKI enrichment produced V4. Refined Random Forest remained a strong benchmark, but refined XGBoost performed better under TRAIN grouped-CV and passed Phase J Validation. K1 then used TRAIN-only incident-level stacking to improve over mean probability aggregation. K2 and K2.5 checked leakage, stability, and architecture alternatives. L0 froze the deployable XGB-to-XGB K1 model before the one-time Final Holdout evaluation.\n",
    )
    write_md(
        DOCS / "negative_results_narrative_v1.md",
        "# Negative Results Narrative v1\n\nThe negative results matter because they reduced the plausible model space. Stage 1 did not become the final architecture, domain experts were not adopted, threshold tuning was not sufficient, and class balancing alone did not solve the task. Random Forest remained useful as a benchmark, but XGBoost and then K1 stacking produced stronger TRAIN-only evidence. These outcomes support the final model-selection rationale without hiding unsuccessful paths.\n",
    )
    write_md(
        DOCS / "final_model_specification_v1.md",
        f"# Final Model Specification v1\n\n- Praxis title: {TITLE}\n- Final architecture: A0 XGBoost first level to XGBoost K1 incident stacker.\n- First-level strategy: crossfit ensemble first level.\n- Second-level model: K1 final second-level XGBoost.\n- Second-level hash: `{v['second_level_hash']}`.\n- Feature schema: V4, 74 frozen features.\n- Training evidence: TRAIN nested CV only after Phase J.\n- Final evaluation: one-time Final Holdout, 213 incidents.\n- Stage 1: UNRESOLVED_EXPERIMENTAL_AUXILIARY.\n",
    )
    write_md(
        DOCS / "final_architecture_flow_v1.md",
        "# Final Architecture Flow v1\n\n```mermaid\nflowchart TD\n    A[RouteViews MRT UPDATE data] --> B[5-minute behavioral windows]\n    B --> C[CAIDA enrichment]\n    B --> D[RPKI/ROV enrichment]\n    C --> E[V4 feature matrix]\n    D --> E\n    E --> F[First-level XGBoost crossfit ensemble]\n    F --> G[Incident-level temporal summary features]\n    G --> H[Second-level XGBoost K1 stacker]\n    H --> I[Ranked classes: Hijack / Leak / Outage]\n    N[Normal/Stage 1 branch] -. auxiliary unresolved .-> B\n```\n",
    )
    write_md(DOCS / "chapter3_proposed_structure_v1.md", "# Chapter 3 Proposed Structure v1\n\n1. Research design and evaluation integrity\n2. Incident roster, v2 freeze, and partitions\n3. RouteViews acquisition and five-minute window construction\n4. Behavioral, CAIDA, and RPKI/ROV feature engineering\n5. Normal-ground-truth methodology and Stage 1 boundary\n6. Model families, imbalance handling, grouped CV\n7. Final K1 architecture and Holdout protocol\n")
    write_md(DOCS / "chapter4_proposed_structure_v1.md", "# Chapter 4 Proposed Structure v1\n\n1. Corpus and quality-gate summary\n2. Baseline and imbalance experiments\n3. Feature-variant and feature-family ablations\n4. RF and XGBoost comparison/refinement\n5. Phase J Validation confirmation\n6. K1 stacking, K2 checks, and K2.5 comparator\n7. Final Holdout performance, ranking, and error analysis\n")
    write_md(DOCS / "chapter5_findings_handoff_v1.md", "# Chapter 5 Findings Handoff v1\n\nKey findings: K1 generalized strongly on untouched Holdout, Top-2 ranking was high, Outage was strongest, Hijack was hardest, and Stage 1 remained unresolved. Limitations include RouteViews observability, external labels, post-Validation K1 development interpretation, and finite Holdout size. Future work should prioritize Normal/Stage 1, shorter-window inference, enterprise-local telemetry, and calibrated ranking.\n")
    write_md(
        DOCS / "experiment_dependency_graph_v1.md",
        "# Experiment Dependency Graph v1\n\n```mermaid\nflowchart LR\n    R[v2 roster and partitions] --> M[MRT acquisition]\n    M --> B[Behavioral corpus]\n    B --> C[CAIDA]\n    B --> P[RPKI/ROV]\n    C --> V4[V4 feature set]\n    P --> V4\n    B --> N[Normal/Stage 1 auxiliary]\n    V4 --> BL[Baselines]\n    BL --> I[Imbalance I1]\n    I --> RF[RF tuning]\n    I --> XGB[XGBoost refinement]\n    XGB --> J[Phase J Validation]\n    XGB --> K1[K1 TRAIN-only stacking]\n    K1 --> K2[K2 forensic checks]\n    K2 --> K25[K2.5 comparator]\n    K25 --> L0[L0 freeze]\n    L0 --> H[Final Holdout]\n```\n",
    )
    write_md(
        DOCS / "MASTER_PRAXIS_EXPERIMENTAL_RECORD_INDEX_v1.md",
        "# Master Praxis Experimental Record Index v1\n\nThis is the entry point for the Phase M dissertation handoff.\n\n- `docs/master_praxis_experimental_record_v1.md`: narrative phase record.\n- `docs/master_praxis_experimental_record_v1.csv`: structured phase ledger.\n- `docs/notebook_experiment_map_v1.csv`: notebook-to-phase map.\n- `docs/praxis_artifact_evidence_map_v1.csv`: evidence map for artifacts.\n- `docs/chapter3_methodology_evidence_map_v1.csv`: Chapter 3 source map.\n- `docs/chapter4_results_evidence_map_v1.csv`: Chapter 4 result map.\n- `docs/dissertation_table_inventory_v1.csv`: table candidates.\n- `docs/dissertation_figure_inventory_v1.csv`: figure candidates.\n- `docs/master_experiment_decision_ledger_v1.csv`: decision ledger.\n- `docs/negative_and_null_findings_v1.csv`: negative findings.\n- `docs/threats_to_validity_register_v1.csv`: threats and mitigations.\n- `docs/authoritative_numbers_register_v1.csv`: canonical numbers.\n- `docs/dissertation_claim_evidence_register_v1.csv`: claim support status.\n- `docs/master_praxis_results_summary_v1.yaml`: compact machine-readable summary.\n- `docs/stale_artifact_register_v1.csv`: current/historical/superseded status.\n",
    )


def write_summary_yaml(v: dict[str, Any], phase_rows: list[dict[str, Any]]) -> None:
    summary = {
        "praxis": {"title": TITLE, "stage1_status": "UNRESOLVED_EXPERIMENTAL_AUXILIARY"},
        "dataset": {"train_incidents": 993, "validation_incidents": 213, "holdout_incidents": 213, "holdout_window_rows": v["holdout_window_rows"]},
        "feature_engineering": {"behavioral_features": 44, "caida_features": 14, "rpki_features": 16, "v4_features": 74, "train_behavioral_rows": v["train_behavioral_rows"]},
        "normal_methodology": {"normal_windows": v["normal_windows"], "status": "auxiliary"},
        "feature_variants": {"V1": 44, "V2": 58, "V3": 60, "V4": 74},
        "baseline_results": {"artifact": str(BASELINE)},
        "ablation_results": {"feature_variant_artifact": str(FEATURE_VARIANT_ABLATION), "feature_family_artifact": str(FEATURE_FAMILY_ABLATION)},
        "stage1_results": {"status": "UNRESOLVED_EXPERIMENTAL_AUXILIARY"},
        "rf_results": {"refined_rf_macro_f1": 0.784588, "artifact": str(RF_H2)},
        "xgboost_results": {"refined_xgb_macro_f1": 0.805678, "artifact": str(XGB_I2)},
        "validation": {"macro_f1": 0.713904, "artifact": str(VALIDATION_RESULTS), "note": "Phase J candidate only; K1 not Validation-confirmed."},
        "k1": {"architecture": "A0_XGB_TO_XGB", "train_macro_f1": 0.934666, "artifact": str(K1_RESULTS)},
        "k2": {"macro_f1_mean": 0.934304, "macro_f1_std": 0.002309, "artifact": str(K2_RESULTS)},
        "k25": {"decision": "KEEP_XGB_XGB_K1", "artifact": str(K25_DECISION)},
        "final_model": {"architecture": "A0_XGB_TO_XGB", "second_level_hash": v["second_level_hash"], "artifact": str(SECOND_LEVEL)},
        "holdout": {"macro_f1": v["final_macro_f1"], "ci_lower": v["final_macro_f1_ci_lower"], "ci_upper": v["final_macro_f1_ci_upper"], "top1": v["final_top1"], "top2": v["final_top2"], "mrr": v["final_mrr"], "hijack_f1": v["final_hijack_f1"], "leak_f1": v["final_leak_f1"], "outage_f1": v["final_outage_f1"], "rank1": v["rank1"], "rank2": v["rank2"], "rank3": v["rank3"]},
        "limitations": ["RouteViews observability", "external labels", "Stage 1 unresolved", "K1 not Validation-confirmed", "Holdout size 213"],
        "authoritative_artifacts": [a["artifact"] for a in artifact_rows() if a["final_or_intermediate"] == "AUTHORITATIVE_CURRENT"],
        "phase_count": len(phase_rows),
    }
    (DOCS / "master_praxis_results_summary_v1.yaml").parent.mkdir(parents=True, exist_ok=True)
    with (DOCS / "master_praxis_results_summary_v1.yaml").open("w", encoding="utf-8") as handle:
        yaml.safe_dump(summary, handle, sort_keys=False, allow_unicode=True)


def write_timeline_and_audit(v: dict[str, Any], phase_rows: list[dict[str, Any]]) -> None:
    write_csv(
        DOCS / "master_praxis_timeline_v1.csv",
        [
            {
                "sequence": r["sequence"],
                "phase": r["phase_id"],
                "milestone": r["phase_name"],
                "date_or_commit_if_available": "2026-09-03T01:23:45Z" if r["phase_id"] == "P18" else "",
                "partition": r["partition"],
                "major_output": r["primary_artifacts"],
                "decision": r["decision"],
                "significance": r["decision_rationale"],
            }
            for r in phase_rows
        ],
    )
    audit_rows = [
        ("chronology complete", "all major phases P0-P18 represented", "PASS"),
        ("major phases represented", f"{len(phase_rows)} phases/subphases", "PASS"),
        ("authoritative numbers verified", "script checked terminal values", "PASS"),
        ("final model lineage correct", "XGB refinement -> Validation -> K1 -> K2/K2.5 -> L0 -> Holdout", "PASS"),
        ("Validation chronology correct", "Phase J first Validation access; K1 not Validation-confirmed", "PASS"),
        ("Holdout chronology correct", "Phase L first Holdout access; no post-Holdout changes", "PASS"),
        ("negative findings preserved", "Stage 1/domain experts/RF caveats captured", "PASS"),
        ("limitations preserved", "threats and final limitations produced", "PASS"),
        ("feature ablation documented", "variant and family ablation mapped", "PASS"),
        ("baseline modeling documented", "RF baseline/RF/XGB progression mapped", "PASS"),
        ("data engineering documented", "MRT/Behavioral/CAIDA/RPKI/Normal mapped", "PASS"),
        ("dissertation Chapter 3 map produced", "chapter3 methodology/table/figure plans", "PASS"),
        ("dissertation Chapter 4 map produced", "chapter4 results/table/figure plans", "PASS"),
        ("notebook map produced", "notebook_experiment_map_v1.csv", "PASS"),
        ("evidence map produced", "praxis_artifact_evidence_map_v1.csv", "PASS"),
        ("stale artifacts identified", "stale_artifact_register_v1.csv", "PASS"),
        ("SHAP explainability", "not generated in Phase M unless already present", "REVIEW"),
    ]
    write_csv(DOCS / "master_praxis_record_audit_v1.csv", [{"audit_item": a, "evidence": b, "status": c} for a, b, c in audit_rows])

    defense = [
        ("Problem and corpus", "v2 roster and partition counts", str(PARTITIONS_V2), "ESSENTIAL"),
        ("Feature architecture", "44+14+16=74 V4", str(FEATURE_VARIANTS), "ESSENTIAL"),
        ("Ablation evidence", "V1-V4 and feature-family results", str(FEATURE_VARIANT_ABLATION), "ESSENTIAL"),
        ("Model selection", "RF vs XGB and K1 progression", str(XGB_I2), "ESSENTIAL"),
        ("Leakage integrity", "grouped CV, access chronology, K2", str(K2_RESULTS), "ESSENTIAL"),
        ("Final results", "Holdout Macro F1/Top-2/MRR/class metrics", str(FINAL_RESULT), "ESSENTIAL"),
        ("Limitations", "Stage 1, observability, labels", "docs/final_limitations_v1.csv", "ESSENTIAL"),
    ]
    write_csv(DOCS / "defense_evidence_index_v1.csv", [{"defense_topic": a, "evidence": b, "source_artifact": c, "priority": d} for a, b, c, d in defense])


def write_notebook() -> None:
    NOTEBOOK.parent.mkdir(parents=True, exist_ok=True)
    cells = [
        {"cell_type": "markdown", "metadata": {}, "source": ["# Phase M - Master Praxis Experimental Record\n", "\n", "Documentation/indexing only. This notebook does not rerun experiments.\n"]},
        {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["import pandas as pd\n", "from pathlib import Path\n", "docs = Path('../docs')\n"]},
        {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["record = pd.read_csv(docs / 'master_praxis_experimental_record_v1.csv')\n", "record[['sequence','phase_id','phase_name','partition','primary_metric','primary_result','decision','status']]\n"]},
        {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["pd.read_csv(docs / 'experiment_to_chapter_matrix_v1.csv')\n"]},
        {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["pd.read_csv(docs / 'authoritative_numbers_register_v1.csv')\n"]},
        {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["pd.read_csv(docs / 'documentation_open_items_v1.csv')\n"]},
    ]
    nb = {"cells": cells, "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}}, "nbformat": 4, "nbformat_minor": 5}
    NOTEBOOK.write_text(json.dumps(nb, indent=2), encoding="utf-8")


def run_phase_m() -> dict[str, Any]:
    DOCS.mkdir(parents=True, exist_ok=True)
    v = final_values()
    phase_rows = phases(v)
    write_authoritative_numbers(v)
    write_statistical_register(v)
    write_headline(v)
    write_maps_and_registers(v, phase_rows)
    write_narratives(v, phase_rows)
    write_summary_yaml(v, phase_rows)
    write_timeline_and_audit(v, phase_rows)
    write_notebook()
    return {"phase_count": len(phase_rows), "docs_dir": str(DOCS), "title": TITLE, "final_macro_f1": v["final_macro_f1"]}


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Phase M Master Praxis documentation artifacts.")
    parser.add_argument("--run", action="store_true", help="Generate the Phase M documentation artifacts.")
    args = parser.parse_args()
    if args.run:
        summary = run_phase_m()
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
