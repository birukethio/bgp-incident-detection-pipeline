from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import average_precision_score, confusion_matrix, f1_score, precision_recall_fscore_support, roc_auc_score
from sklearn.pipeline import Pipeline

try:
    from bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT, load_assignments, load_variant
    from bgp_incident_detection.feature_family_ablation import feature_family_inventory
    from bgp_incident_detection.imbalance_model_experiment import group_aware_weights
    from bgp_incident_detection.model_baselines import (
        CLASS_LABELS,
        CV_ASSIGNMENTS,
        INCIDENT_LABELS,
        REGISTRY,
        RF_HYPERPARAMETERS,
        SEED,
        aggregate_group_predictions,
        class_prob_frame,
        macro_f1,
        mrr,
        per_class_f1,
        top2_accuracy,
    )
    from bgp_incident_detection.train_batch_engine import source_commit
except ModuleNotFoundError:
    from src.bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT, load_assignments, load_variant
    from src.bgp_incident_detection.feature_family_ablation import feature_family_inventory
    from src.bgp_incident_detection.imbalance_model_experiment import group_aware_weights
    from src.bgp_incident_detection.model_baselines import (
        CLASS_LABELS,
        CV_ASSIGNMENTS,
        INCIDENT_LABELS,
        REGISTRY,
        RF_HYPERPARAMETERS,
        SEED,
        aggregate_group_predictions,
        class_prob_frame,
        macro_f1,
        mrr,
        per_class_f1,
        top2_accuracy,
    )
    from src.bgp_incident_detection.train_batch_engine import source_commit


MODELING_DIR = Path("data/modeling")
MODEL_DIR = MODELING_DIR / "models/domain_experts_v1"
FEATURE_INVENTORY = MODELING_DIR / "domain_expert_feature_inventory_v1.csv"
OOF_SCORES = MODELING_DIR / "domain_expert_oof_scores_v1.parquet"
CLASSIFICATION_RESULTS = MODELING_DIR / "domain_expert_classification_results_v1.csv"
RANKING_RESULTS = MODELING_DIR / "domain_expert_ranking_results_v1.csv"
SPECIALIZATION = MODELING_DIR / "domain_expert_specialization_v1.csv"
PAIRED = MODELING_DIR / "domain_expert_paired_fold_comparison_v1.csv"
COMPLEXITY = MODELING_DIR / "domain_expert_complexity_v1.csv"
NOTEBOOK = Path("notebooks/45_domain_informed_incident_experts.ipynb")

CONFIGURATIONS = ["S2_BASE", "F0_FULL_V4_EXPERTS", "F1_DOMAIN_EXPERTS"]
FUSIONS = ["R0_DIRECT", "R1_NORMALIZED", "R2_SOFTMAX"]
F1_FAMILIES = {
    "HIJACK": {
        "announcement_update_activity",
        "prefix_dynamics",
        "origin_change_moas_behavior",
        "as_path_length_structure",
        "as_path_instability_path_change",
        "prepending_behavior",
        "rpki_rov",
    },
    "LEAK": {
        "announcement_update_activity",
        "prefix_dynamics",
        "peer_visibility_behavior",
        "as_path_length_structure",
        "as_path_instability_path_change",
        "prepending_behavior",
        "origin_change_moas_behavior",
        "caida_as_relationship",
    },
    "OUTAGE": {
        "announcement_update_activity",
        "withdrawal_activity",
        "prefix_dynamics",
        "peer_visibility_behavior",
        "caida_as_relationship",
    },
}


def rf_pipeline() -> Pipeline:
    return Pipeline(
        [
            ("imputer", SimpleImputer(strategy="median")),
            ("model", RandomForestClassifier(**RF_HYPERPARAMETERS)),
        ]
    )


def load_incident_data() -> pd.DataFrame:
    df = load_variant("V4")
    assignments = load_assignments(df)
    data = df.merge(assignments, on="window_id", how="left", validate="one_to_one")
    data = data[data["label"].isin(INCIDENT_LABELS)].copy()
    if set(data["partition"].astype(str)) != {"train"}:
        raise ValueError("Phase F must use TRAIN only")
    if data.groupby("model_group_id")["fold"].nunique().max() != 1:
        raise ValueError("incident model_group_id crosses folds")
    return data


def domain_expert_inventory() -> pd.DataFrame:
    inv = feature_family_inventory()
    full = set(FEATURES_BY_VARIANT["V4"])
    rows = []
    for expert in INCIDENT_LABELS:
        included_families = F1_FAMILIES[expert]
        for _, row in inv.iterrows():
            feature = row["feature_name"]
            family = row["feature_family"]
            included = family in included_families
            rows.append(
                {
                    "expert_name": f"E_{expert}",
                    "feature_name": feature,
                    "feature_family": family,
                    "included": included,
                    "prior_evidence": prior_evidence(expert, family),
                    "rationale": expert_rationale(expert, family, included),
                }
            )
    out = pd.DataFrame(rows)
    if set(out["feature_name"]) != full:
        raise ValueError("domain expert inventory must use frozen V4 features only")
    return out


def prior_evidence(expert: str, family: str) -> str:
    if expert == "HIJACK" and family == "rpki_rov":
        return "Phase D: RPKI removal had strongest Hijack F1 delta."
    if expert == "LEAK" and family in {"peer_visibility_behavior", "caida_as_relationship"}:
        return "Phase D: peer/visibility ranked highest for Leak; CAIDA was positive."
    if expert == "OUTAGE" and family == "caida_as_relationship":
        return "Phase D: CAIDA ranked highest for Outage F1."
    return "Included/excluded by predeclared domain family mapping before Phase F results."


def expert_rationale(expert: str, family: str, included: bool) -> str:
    if not included:
        return "Excluded from F1 domain-informed subset to test specialization; still available in F0."
    if expert == "HIJACK":
        return "Hijack expert emphasizes origin security, origin/MOAS, AS-path, prefix, and activity signals."
    if expert == "LEAK":
        return "Leak expert emphasizes peer visibility, path behavior, CAIDA relationships, prefix, and activity signals."
    return "Outage expert emphasizes activity, withdrawals, visibility, CAIDA relationships, and prefix dynamics."


def features_for_expert(expert: str, config: str, inventory: pd.DataFrame) -> list[str]:
    if config == "F0_FULL_V4_EXPERTS":
        return FEATURES_BY_VARIANT["V4"]
    if config == "F1_DOMAIN_EXPERTS":
        rows = inventory[(inventory["expert_name"] == f"E_{expert}") & (inventory["included"])]
        return rows["feature_name"].tolist()
    raise ValueError(f"expert feature request for unsupported config: {config}")


def fit_with_weights(train: pd.DataFrame, features: list[str], target: str) -> Pipeline:
    model = rf_pipeline()
    model.fit(train[features], train[target], model__sample_weight=group_aware_weights(train))
    return model


def train_s2_base(data: pd.DataFrame) -> tuple[pd.DataFrame, list[dict[str, object]]]:
    features = FEATURES_BY_VARIANT["V4"]
    rows = []
    complexity = []
    for fold in sorted(data["fold"].unique()):
        train = data[data["fold"] != fold].copy()
        test = data[data["fold"] == fold].copy()
        model = rf_pipeline()
        started = time.perf_counter()
        model.fit(train[features], train["label"], model__sample_weight=group_aware_weights(train))
        fit_time = time.perf_counter() - started
        started = time.perf_counter()
        probs = class_prob_frame(list(model.classes_), model.predict_proba(test[features]), INCIDENT_LABELS)
        inference_time = time.perf_counter() - started
        path = save_model(model, f"PHASEF_S2_BASE_V4_I1_RF_fold{fold}")
        complexity.append(complexity_row("S2_BASE", "S2_BASE", int(fold), 1, len(features), fit_time, inference_time, path))
        for pos, idx in enumerate(test.index):
            rows.append(
                score_row(
                    data.loc[idx],
                    "S2_BASE",
                    "S2_BASE",
                    "R1_NORMALIZED",
                    probs.iloc[pos]["HIJACK"],
                    probs.iloc[pos]["LEAK"],
                    probs.iloc[pos]["OUTAGE"],
                )
            )
    return pd.DataFrame(rows), complexity


def train_experts(data: pd.DataFrame, config: str, inventory: pd.DataFrame) -> tuple[pd.DataFrame, list[dict[str, object]], list[dict[str, object]]]:
    rows = []
    complexity = []
    specialization = []
    for fold in sorted(data["fold"].unique()):
        train = data[data["fold"] != fold].copy()
        test = data[data["fold"] == fold].copy()
        raw_scores = pd.DataFrame(index=test.index)
        for expert in INCIDENT_LABELS:
            target = f"is_{expert.lower()}"
            train[target] = np.where(train["label"] == expert, expert, f"NON_{expert}_INCIDENT")
            features = features_for_expert(expert, config, inventory)
            started = time.perf_counter()
            model = fit_with_weights(train, features, target)
            fit_time = time.perf_counter() - started
            started = time.perf_counter()
            probs = class_prob_frame(list(model.classes_), model.predict_proba(test[features]), [expert, f"NON_{expert}_INCIDENT"])
            inference_time = time.perf_counter() - started
            raw_scores[expert] = probs[expert].to_numpy()
            path = save_model(model, f"PHASEF_{config}_{expert}_fold{fold}")
            complexity.append(complexity_row(config, f"E_{expert}", int(fold), 1, len(features), fit_time, inference_time, path))
            y_true = (test["label"] == expert).astype(int)
            specialization.append(
                {
                    "expert_configuration": config,
                    "expert_name": f"E_{expert}",
                    "fold": int(fold),
                    "feature_count": len(features),
                    "auroc": float(roc_auc_score(y_true, raw_scores[expert])),
                    "pr_auc": float(average_precision_score(y_true, raw_scores[expert])),
                    "binary_f1_at_0_5": float(f1_score(y_true, raw_scores[expert] >= 0.5, zero_division=0)),
                }
            )
        for fusion in FUSIONS:
            fused = fuse_scores(raw_scores, fusion)
            for idx in test.index:
                rows.append(score_row(data.loc[idx], config, "ONE_VS_REST_EXPERTS", fusion, fused.loc[idx, "HIJACK"], fused.loc[idx, "LEAK"], fused.loc[idx, "OUTAGE"]))
    return pd.DataFrame(rows), complexity, specialization


def fuse_scores(scores: pd.DataFrame, fusion: str) -> pd.DataFrame:
    if fusion == "R0_DIRECT":
        return scores.copy()
    if fusion == "R1_NORMALIZED":
        total = scores.sum(axis=1).replace(0, np.nan)
        return scores.div(total, axis=0).fillna(1 / 3)
    if fusion == "R2_SOFTMAX":
        arr = scores.to_numpy()
        exp = np.exp(arr - arr.max(axis=1, keepdims=True))
        norm = exp / exp.sum(axis=1, keepdims=True)
        return pd.DataFrame(norm, index=scores.index, columns=scores.columns)
    raise ValueError(f"unknown fusion method: {fusion}")


def score_row(source: pd.Series, config: str, architecture: str, fusion: str, p_hijack: float, p_leak: float, p_outage: float) -> dict[str, object]:
    return {
        "window_id": source["window_id"],
        "incident_uid": source["incident_uid"],
        "true_class": source["label"],
        "fold": int(source["fold"]),
        "expert_configuration": config,
        "architecture": architecture,
        "fusion_method": fusion,
        "p_hijack": float(p_hijack),
        "p_leak": float(p_leak),
        "p_outage": float(p_outage),
    }


def ranked_frame(scores: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, row in scores.iterrows():
        pairs = sorted([(label, row[f"p_{label.lower()}"]) for label in INCIDENT_LABELS], key=lambda item: item[1], reverse=True)
        out = row.to_dict()
        for rank, (label, score) in enumerate(pairs, start=1):
            out[f"rank_{rank}_class"] = label
            out[f"rank_{rank}_score"] = float(score)
        out["predicted_class"] = pairs[0][0]
        out["true_class_rank"] = [label for label, _ in pairs].index(row["true_class"]) + 1
        rows.append(out)
    return pd.DataFrame(rows)


def aggregate_incident_scores(scores: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for keys, group in scores.groupby(["expert_configuration", "architecture", "fusion_method", "incident_uid"]):
        config, arch, fusion, incident_uid = keys
        rows.append(
            {
                "expert_configuration": config,
                "architecture": arch,
                "fusion_method": fusion,
                "incident_uid": incident_uid,
                "true_class": group["true_class"].iloc[0],
                "fold": int(group["fold"].iloc[0]),
                "p_hijack": float(group["p_hijack"].mean()),
                "p_leak": float(group["p_leak"].mean()),
                "p_outage": float(group["p_outage"].mean()),
            }
        )
    return pd.DataFrame(rows)


def classification_metrics(scores: pd.DataFrame, level: str) -> list[dict[str, object]]:
    ranked = ranked_frame(scores)
    rows = []
    for keys, group in ranked.groupby(["expert_configuration", "architecture", "fusion_method"]):
        config, arch, fusion = keys
        y_true = group["true_class"].tolist()
        y_pred = group["predicted_class"].tolist()
        probs = group[["p_hijack", "p_leak", "p_outage"]].copy()
        probs.columns = INCIDENT_LABELS
        row = {
            "expert_configuration": config,
            "architecture": arch,
            "fusion_method": fusion,
            "level": level,
            "row_count": len(group),
            "macro_f1": macro_f1(y_true, y_pred, INCIDENT_LABELS),
            "top1_accuracy": float((group["true_class"] == group["rank_1_class"]).mean()),
            "top2_accuracy": top2_accuracy(y_true, probs),
            "mrr": mrr(y_true, probs),
            "mean_true_class_rank": float(group["true_class_rank"].mean()),
            "confusion_matrix": json.dumps(confusion_matrix(y_true, y_pred, labels=INCIDENT_LABELS).tolist()),
        }
        row.update(per_class_f1(y_true, y_pred, INCIDENT_LABELS))
        rows.append(row)
    return rows


def ranking_metrics(scores: pd.DataFrame, level: str) -> list[dict[str, object]]:
    ranked = ranked_frame(scores)
    rows = []
    for keys, group in ranked.groupby(["expert_configuration", "architecture", "fusion_method"]):
        config, arch, fusion = keys
        probs = group[["p_hijack", "p_leak", "p_outage"]].copy()
        probs.columns = INCIDENT_LABELS
        row = {
            "expert_configuration": config,
            "architecture": arch,
            "fusion_method": fusion,
            "level": level,
            "top1_accuracy": float((group["true_class"] == group["rank_1_class"]).mean()),
            "top2_accuracy": top2_accuracy(group["true_class"].tolist(), probs),
            "mrr": mrr(group["true_class"].tolist(), probs),
            "mean_true_class_rank": float(group["true_class_rank"].mean()),
        }
        for label in INCIDENT_LABELS:
            subset = group[group["true_class"] == label]
            label_probs = subset[["p_hijack", "p_leak", "p_outage"]].copy()
            label_probs.columns = INCIDENT_LABELS
            row[f"{label.lower()}_mrr"] = mrr(subset["true_class"].tolist(), label_probs)
            row[f"{label.lower()}_mean_rank"] = float(subset["true_class_rank"].mean())
        rows.append(row)
    return rows


def paired_fold_comparison(scores: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for level, frame in [("window", scores), ("incident", aggregate_incident_scores(scores))]:
        ranked = ranked_frame(frame)
        for fold in sorted(ranked["fold"].unique()):
            fold_rows = ranked[ranked["fold"] == fold]
            metrics = {}
            for config in CONFIGURATIONS:
                subset = fold_rows[(fold_rows["expert_configuration"] == config) & (fold_rows["fusion_method"] == primary_fusion(config))]
                metrics[config] = fold_metrics(subset)
            for left, right in [("F0_FULL_V4_EXPERTS", "S2_BASE"), ("F1_DOMAIN_EXPERTS", "S2_BASE"), ("F1_DOMAIN_EXPERTS", "F0_FULL_V4_EXPERTS")]:
                row = {"level": level, "fold": int(fold), "comparison": f"{left}-{right}"}
                for metric in ["macro_f1", "hijack_f1", "leak_f1", "outage_f1", "top2_accuracy", "mrr"]:
                    row[f"{metric}_delta"] = metrics[left][metric] - metrics[right][metric]
                if level == "incident":
                    row["incident_level_mrr_delta"] = metrics[left]["mrr"] - metrics[right]["mrr"]
                rows.append(row)
    return pd.DataFrame(rows)


def primary_fusion(config: str) -> str:
    return "R1_NORMALIZED" if config == "S2_BASE" else "R1_NORMALIZED"


def fold_metrics(group: pd.DataFrame) -> dict[str, float]:
    y_true = group["true_class"].tolist()
    y_pred = group["predicted_class"].tolist()
    probs = group[["p_hijack", "p_leak", "p_outage"]].copy()
    probs.columns = INCIDENT_LABELS
    out = {
        "macro_f1": macro_f1(y_true, y_pred, INCIDENT_LABELS),
        "top2_accuracy": top2_accuracy(y_true, probs),
        "mrr": mrr(y_true, probs),
    }
    out.update({k: v for k, v in per_class_f1(y_true, y_pred, INCIDENT_LABELS).items() if k.endswith("_f1")})
    return out


def complexity_row(config: str, model_name: str, fold: int, trained_models: int, feature_count: int, fit_time: float, inference_time: float, path: Path) -> dict[str, object]:
    return {
        "expert_configuration": config,
        "model_name": model_name,
        "fold": fold,
        "trained_models": trained_models,
        "feature_count": feature_count,
        "fit_time": round(fit_time, 3),
        "inference_time": round(inference_time, 3),
        "serialized_model_size_bytes": path.stat().st_size if path.exists() else 0,
    }


def save_model(model: object, name: str) -> Path:
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    path = MODEL_DIR / f"{name}.joblib"
    joblib.dump(model, path)
    return path


def specialization_summary(rows: list[dict[str, object]], ranking: pd.DataFrame) -> pd.DataFrame:
    spec = pd.DataFrame(rows)
    if spec.empty:
        return spec
    summary = spec.groupby(["expert_configuration", "expert_name"]).agg(
        auroc=("auroc", "mean"),
        pr_auc=("pr_auc", "mean"),
        binary_f1=("binary_f1_at_0_5", "mean"),
        feature_count=("feature_count", "mean"),
    ).reset_index()
    impact_rows = ranking[(ranking["level"] == "window") & (ranking["fusion_method"] == "R1_NORMALIZED")]
    for _, row in summary.iterrows():
        config = row["expert_configuration"]
        class_name = row["expert_name"].replace("E_", "").lower()
        subset = impact_rows[impact_rows["expert_configuration"] == config]
        if not subset.empty:
            summary.loc[(summary["expert_configuration"] == config) & (summary["expert_name"] == row["expert_name"]), "ranking_impact_mrr"] = float(subset[f"{class_name}_mrr"].iloc[0])
    return summary


def update_registry() -> None:
    existing = pd.read_csv(REGISTRY, dtype=str).fillna("") if REGISTRY.exists() else pd.DataFrame()
    rows = [
        {"experiment_id": "PHASEF_S2_BASE_V4_I1_RF", "model": "RandomForestClassifier", "architecture": "multiclass-stage2", "feature_variant": "V4", "feature_count": "74", "imbalance_condition": "I1 Group-aware weighting", "cv_scheme": "Existing Phase A 5-fold grouped CV by model_group_id", "seed": str(SEED), "status": "COMPLETED", "result_artifact": str(CLASSIFICATION_RESULTS), "source_commit": source_commit()},
        {"experiment_id": "PHASEF_F0_FULL_V4_EXPERTS", "model": "RandomForestClassifier", "architecture": "one-vs-rest-experts", "feature_variant": "V4", "feature_count": "74 per expert", "imbalance_condition": "I1 Group-aware weighting", "cv_scheme": "Existing Phase A 5-fold grouped CV by model_group_id", "seed": str(SEED), "status": "COMPLETED", "result_artifact": str(CLASSIFICATION_RESULTS), "source_commit": source_commit()},
        {"experiment_id": "PHASEF_F1_DOMAIN_EXPERTS", "model": "RandomForestClassifier", "architecture": "domain-informed-one-vs-rest-experts", "feature_variant": "V4 family subsets", "feature_count": "per expert in inventory", "imbalance_condition": "I1 Group-aware weighting", "cv_scheme": "Existing Phase A 5-fold grouped CV by model_group_id", "seed": str(SEED), "status": "COMPLETED", "result_artifact": str(CLASSIFICATION_RESULTS), "source_commit": source_commit()},
    ]
    combined = pd.concat([existing, pd.DataFrame(rows)], ignore_index=True, sort=False) if len(existing) else pd.DataFrame(rows)
    combined = combined.drop_duplicates("experiment_id", keep="last")
    combined.to_csv(REGISTRY, index=False)


def write_notebook() -> None:
    NOTEBOOK.parent.mkdir(parents=True, exist_ok=True)
    notebook = {
        "cells": [
            {"cell_type": "markdown", "metadata": {}, "source": ["# Phase F - Domain-Informed Incident Experts\n", "\n", "TRAIN-only incident-classification and ranking experiment conditional on incident presence. Stage 1 remains unresolved.\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["from bgp_incident_detection.domain_experts import run_experiment\n", "# run_experiment()\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["import pandas as pd\n", "pd.read_csv('../data/modeling/domain_expert_classification_results_v1.csv')\n"]},
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")


def run_experiment() -> dict[str, object]:
    MODELING_DIR.mkdir(parents=True, exist_ok=True)
    data = load_incident_data()
    inventory = domain_expert_inventory()
    inventory.to_csv(FEATURE_INVENTORY, index=False)
    base_scores, base_complexity = train_s2_base(data)
    f0_scores, f0_complexity, f0_spec = train_experts(data, "F0_FULL_V4_EXPERTS", inventory)
    f1_scores, f1_complexity, f1_spec = train_experts(data, "F1_DOMAIN_EXPERTS", inventory)
    scores = pd.concat([base_scores, f0_scores, f1_scores], ignore_index=True)
    scores.to_parquet(OOF_SCORES, index=False)

    incident_scores = aggregate_incident_scores(scores)
    classification = pd.DataFrame(classification_metrics(scores, "window") + classification_metrics(incident_scores, "incident"))
    classification.to_csv(CLASSIFICATION_RESULTS, index=False)
    ranking = pd.DataFrame(ranking_metrics(scores, "window") + ranking_metrics(incident_scores, "incident"))
    ranking.to_csv(RANKING_RESULTS, index=False)
    specialization_summary(f0_spec + f1_spec, ranking).to_csv(SPECIALIZATION, index=False)
    paired_fold_comparison(scores).to_csv(PAIRED, index=False)
    pd.DataFrame(base_complexity + f0_complexity + f1_complexity).to_csv(COMPLEXITY, index=False)
    update_registry()
    write_notebook()
    primary = classification[(classification["level"] == "incident") & (classification["fusion_method"] == "R1_NORMALIZED")]
    best = primary.sort_values(["macro_f1", "mrr", "top2_accuracy"], ascending=False).iloc[0]
    recommendation = {
        "S2_BASE": "KEEP_MULTICLASS_STAGE2",
        "F0_FULL_V4_EXPERTS": "CARRY_FULL_V4_EXPERTS",
        "F1_DOMAIN_EXPERTS": "CARRY_DOMAIN_INFORMED_EXPERTS",
    }[best["expert_configuration"]]
    return {
        "incident_rows": len(data),
        "incident_groups": data["incident_uid"].nunique(),
        "folds_reused": str(CV_ASSIGNMENTS),
        "recommendation": recommendation,
        "best_incident_level_configuration": best["expert_configuration"],
        "best_incident_level_macro_f1": float(best["macro_f1"]),
        "stage1_status": "UNRESOLVED",
        "validation_loaded": False,
        "holdout_loaded": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Phase F TRAIN-only domain-informed expert architecture experiment")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if args.run:
        print(json.dumps(run_experiment(), indent=2, sort_keys=True))
        return
    parser.error("choose --run")


if __name__ == "__main__":
    main()
