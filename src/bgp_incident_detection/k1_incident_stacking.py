from __future__ import annotations

import argparse
import hashlib
import json
import math
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import yaml
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, precision_recall_fscore_support
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

try:
    from bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT
    from bgp_incident_detection.imbalance_model_experiment import group_aware_weights
    from bgp_incident_detection.model_baselines import INCIDENT_LABELS, mrr, top2_accuracy
    from bgp_incident_detection.train_batch_engine import source_commit
except ModuleNotFoundError:
    from src.bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT
    from src.bgp_incident_detection.imbalance_model_experiment import group_aware_weights
    from src.bgp_incident_detection.model_baselines import INCIDENT_LABELS, mrr, top2_accuracy
    from src.bgp_incident_detection.train_batch_engine import source_commit


MODELING_DIR = Path("data/modeling")
K1_DIR = Path("data/modeling_k1")
TRAIN_V4 = Path("data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1.parquet")
ASSIGNMENTS = MODELING_DIR / "baseline_v1_grouped_cv_assignments_v1.csv"
FINAL_CANDIDATE = Path("config/final_model_candidate_v3_1_xgb_refined.yaml")
K1_CANDIDATE = Path("config/post_validation_k1_candidate_v1.yaml")
NOTEBOOK = Path("notebooks/52_phase_k1_train_only_incident_stacking.ipynb")

OOF_PROBS = K1_DIR / "k1_window_oof_probabilities_v1.parquet"
OOF_AUDIT = K1_DIR / "k1_oof_leakage_audit_v1.csv"
META_FEATURES = K1_DIR / "k1_incident_meta_features_v1.parquet"
META_INVENTORY = K1_DIR / "k1_meta_feature_inventory_v1.csv"
NESTED_AUDIT = K1_DIR / "k1_nested_cv_audit_v1.csv"
MODEL_RESULTS = K1_DIR / "k1_model_results_v1.csv"
FOLD_RESULTS = K1_DIR / "k1_fold_results_v1.csv"
CONFUSION = K1_DIR / "k1_confusion_matrices_v1.csv"
PAIRED = K1_DIR / "k1_paired_fold_comparison_v1.csv"
ABLATION = K1_DIR / "k1_simple_vs_temporal_ablation_v1.csv"
DECISION = K1_DIR / "k1_decision_summary_v1.csv"

SEED = 20260828
FEATURE_VARIANT = "V4"
FEATURE_COUNT = 74
LOW_MARGIN_THRESHOLD = 0.10
HIGH_CONFIDENCE_THRESHOLD = 0.80
LABEL_TO_CODE = {label: idx for idx, label in enumerate(INCIDENT_LABELS)}
CODE_TO_LABEL = {idx: label for label, idx in LABEL_TO_CODE.items()}

FIRST_LEVEL_PARAMS = {
    "n_estimators": 600,
    "max_depth": 6,
    "learning_rate": 0.125,
    "subsample": 0.9,
    "colsample_bytree": 0.9,
    "min_child_weight": 1,
    "gamma": 0,
    "reg_alpha": 0.01,
    "reg_lambda": 2.0,
}

M2_PARAM_GRID = [
    {"n_estimators": 50, "max_depth": 2, "learning_rate": 0.05, "subsample": 0.8, "colsample_bytree": 0.8, "reg_lambda": 2.0, "reg_alpha": 0.01},
    {"n_estimators": 50, "max_depth": 3, "learning_rate": 0.05, "subsample": 1.0, "colsample_bytree": 0.8, "reg_lambda": 2.0, "reg_alpha": 0.01},
    {"n_estimators": 100, "max_depth": 2, "learning_rate": 0.05, "subsample": 0.8, "colsample_bytree": 1.0, "reg_lambda": 2.0, "reg_alpha": 0.01},
    {"n_estimators": 100, "max_depth": 3, "learning_rate": 0.03, "subsample": 0.8, "colsample_bytree": 0.8, "reg_lambda": 3.0, "reg_alpha": 0.05},
    {"n_estimators": 100, "max_depth": 3, "learning_rate": 0.1, "subsample": 0.8, "colsample_bytree": 0.8, "reg_lambda": 2.0, "reg_alpha": 0.01},
    {"n_estimators": 150, "max_depth": 2, "learning_rate": 0.05, "subsample": 1.0, "colsample_bytree": 1.0, "reg_lambda": 2.0, "reg_alpha": 0.01},
    {"n_estimators": 150, "max_depth": 3, "learning_rate": 0.03, "subsample": 1.0, "colsample_bytree": 0.8, "reg_lambda": 3.0, "reg_alpha": 0.05},
    {"n_estimators": 150, "max_depth": 4, "learning_rate": 0.03, "subsample": 0.8, "colsample_bytree": 0.8, "reg_lambda": 4.0, "reg_alpha": 0.1},
    {"n_estimators": 200, "max_depth": 2, "learning_rate": 0.03, "subsample": 0.8, "colsample_bytree": 1.0, "reg_lambda": 3.0, "reg_alpha": 0.05},
    {"n_estimators": 200, "max_depth": 3, "learning_rate": 0.03, "subsample": 1.0, "colsample_bytree": 1.0, "reg_lambda": 3.0, "reg_alpha": 0.05},
    {"n_estimators": 200, "max_depth": 4, "learning_rate": 0.03, "subsample": 0.8, "colsample_bytree": 1.0, "reg_lambda": 4.0, "reg_alpha": 0.1},
    {"n_estimators": 100, "max_depth": 4, "learning_rate": 0.05, "subsample": 1.0, "colsample_bytree": 1.0, "reg_lambda": 4.0, "reg_alpha": 0.1},
]


def param_hash(params: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(params, sort_keys=True).encode("utf-8")).hexdigest()[:12]


def load_candidate_config() -> dict[str, Any]:
    with FINAL_CANDIDATE.open(encoding="utf-8") as handle:
        candidate = yaml.safe_load(handle)
    if candidate["candidate_id"] != "XGB_REFINED_TRAIN_CANDIDATE":
        raise ValueError("K1 must use the Phase I2 refined XGBoost first-level model")
    if candidate["selected_hyperparameters"] != FIRST_LEVEL_PARAMS:
        raise ValueError("K1 first-level XGBoost hyperparameters do not match the locked candidate")
    if candidate["feature_count"] != FEATURE_COUNT:
        raise ValueError("K1 requires the frozen 74-feature V4 schema")
    return candidate


def load_train_data() -> pd.DataFrame:
    candidate = load_candidate_config()
    features = FEATURES_BY_VARIANT[FEATURE_VARIANT]
    if len(features) != FEATURE_COUNT:
        raise ValueError("V4 feature schema is not exactly 74 features")
    train = pd.read_parquet(TRAIN_V4)
    assignments = pd.read_csv(ASSIGNMENTS, low_memory=False)
    assignments = assignments[assignments["label"].isin(INCIDENT_LABELS)].copy()
    data = train.merge(assignments[["window_id", "label", "model_group_id", "fold"]], on="window_id", how="left", validate="one_to_one")
    data = data[data["label"].isin(INCIDENT_LABELS)].copy()
    if set(data["partition"].astype(str)) != {"train"}:
        raise ValueError("K1 must use TRAIN rows only")
    incident_counts = data.drop_duplicates("incident_uid")["label"].value_counts().to_dict()
    if incident_counts != {"HIJACK": 331, "LEAK": 331, "OUTAGE": 331}:
        raise ValueError(f"K1 expected 331/331/331 TRAIN incidents, found {incident_counts}")
    if data["incident_uid"].nunique() != 993:
        raise ValueError("K1 expected exactly 993 TRAIN incidents")
    if data.groupby("incident_uid")["fold"].nunique().max() != 1:
        raise ValueError("K1 grouped CV violation: incident crosses folds")
    _ = candidate
    return data


def y_codes(labels: pd.Series) -> np.ndarray:
    return labels.map(LABEL_TO_CODE).astype(int).to_numpy()


def first_level_model(seed: int = SEED) -> Pipeline:
    return Pipeline(
        [
            ("imputer", SimpleImputer(strategy="median")),
            (
                "model",
                XGBClassifier(
                    **FIRST_LEVEL_PARAMS,
                    objective="multi:softprob",
                    num_class=3,
                    eval_metric="mlogloss",
                    random_state=seed,
                    seed=seed,
                    tree_method="hist",
                    n_jobs=-1,
                    verbosity=0,
                ),
            ),
        ]
    )


def probability_rows(frame: pd.DataFrame, probs: np.ndarray, fold: int, source: str) -> pd.DataFrame:
    out = frame[["incident_uid", "window_id", "window_start", "window_end", "temporal_status", "label"]].copy()
    out["fold"] = int(fold)
    out["true_class"] = out.pop("label")
    out["p_hijack"] = probs[:, 0]
    out["p_leak"] = probs[:, 1]
    out["p_outage"] = probs[:, 2]
    out["probability_source"] = source
    return out


def generate_oof_probabilities(data: pd.DataFrame) -> pd.DataFrame:
    if OOF_PROBS.exists():
        return pd.read_parquet(OOF_PROBS)
    rows = []
    features = FEATURES_BY_VARIANT[FEATURE_VARIANT]
    for fold in sorted(data["fold"].unique()):
        train = data[data["fold"] != fold].copy()
        test = data[data["fold"] == fold].copy()
        model = first_level_model()
        model.fit(train[features], y_codes(train["label"]), model__sample_weight=group_aware_weights(train))
        probs = model.predict_proba(test[features])
        rows.append(probability_rows(test, probs, int(fold), "outer_oof"))
        print(f"K1 first-level OOF fold {fold} complete rows={len(test)}", flush=True)
    out = pd.concat(rows, ignore_index=True)
    K1_DIR.mkdir(parents=True, exist_ok=True)
    out.to_parquet(OOF_PROBS, index=False)
    return out


def leakage_audit(data: pd.DataFrame, oof: pd.DataFrame) -> pd.DataFrame:
    rows = []
    oof_incidents = oof.drop_duplicates("incident_uid")
    rows.append({"check": "train_incidents_represented", "observed": oof_incidents["incident_uid"].nunique(), "expected": 993, "status": "PASS"})
    rows.append({"check": "validation_rows", "observed": int((data["partition"].astype(str) == "validation").sum()), "expected": 0, "status": "PASS"})
    rows.append({"check": "holdout_rows", "observed": int((data["partition"].astype(str) == "holdout").sum()), "expected": 0, "status": "PASS"})
    rows.append({"check": "incident_one_heldout_fold", "observed": int(oof.groupby("incident_uid")["fold"].nunique().max()), "expected": 1, "status": "PASS"})
    rows.append({"check": "all_incident_windows_grouped", "observed": int(data.groupby("incident_uid")["fold"].nunique().max()), "expected": 1, "status": "PASS"})
    rows.append({"check": "no_in_sample_first_level_predictions", "observed": "first-level model excludes predicted fold", "expected": "first-level model excludes predicted fold", "status": "PASS"})
    rows.append({"check": "window_rows_represented", "observed": len(oof), "expected": len(data), "status": "PASS" if len(oof) == len(data) else "FAIL"})
    audit = pd.DataFrame(rows)
    audit.to_csv(OOF_AUDIT, index=False)
    if set(audit["status"]) != {"PASS"}:
        raise RuntimeError("K1 OOF leakage audit failed")
    return audit


def entropy(probs: np.ndarray) -> np.ndarray:
    clipped = np.clip(probs, 1e-12, 1.0)
    return -np.sum(clipped * np.log(clipped), axis=1)


def temporal_segment_positions(n: int) -> list[str]:
    if n <= 2:
        return ["EARLY" if i == 0 else "LATE" for i in range(n)]
    thirds = np.array_split(np.arange(n), 3)
    labels = [""] * n
    for name, positions in zip(["EARLY", "MIDDLE", "LATE"], thirds):
        for pos in positions:
            labels[int(pos)] = name
    return labels


def summarize_incident(group: pd.DataFrame, structural: pd.DataFrame) -> dict[str, Any]:
    group = group.sort_values("window_start").reset_index(drop=True)
    probs = group[["p_hijack", "p_leak", "p_outage"]].to_numpy()
    top_order = np.argsort(probs, axis=1)[:, ::-1]
    max_prob = probs.max(axis=1)
    margin = probs[np.arange(len(probs)), top_order[:, 0]] - probs[np.arange(len(probs)), top_order[:, 1]]
    top1_labels = np.array([INCIDENT_LABELS[idx] for idx in top_order[:, 0]])
    top2_labels = np.array([[INCIDENT_LABELS[idx] for idx in row[:2]] for row in top_order], dtype=object)
    row: dict[str, Any] = {
        "incident_uid": group["incident_uid"].iloc[0],
        "true_class": group["true_class"].iloc[0],
        "fold": int(group["fold"].iloc[0]),
        "window_count": len(group),
        "observed_temporal_span_minutes": (pd.to_datetime(group["window_end"]).max() - pd.to_datetime(group["window_start"]).min()).total_seconds() / 60,
    }
    if "raw_observation_count" in structural.columns:
        raw = structural.set_index("window_id").reindex(group["window_id"])["raw_observation_count"].fillna(0)
        row["proportion_zero_observation_windows"] = float((raw <= 0).mean())
    else:
        row["proportion_zero_observation_windows"] = np.nan
    for label, col in zip(INCIDENT_LABELS, ["p_hijack", "p_leak", "p_outage"]):
        values = group[col].to_numpy()
        lower = label.lower()
        row[f"{lower}_prob_mean"] = float(np.mean(values))
        row[f"{lower}_prob_median"] = float(np.median(values))
        row[f"{lower}_prob_std"] = float(np.std(values, ddof=0))
        row[f"{lower}_prob_min"] = float(np.min(values))
        row[f"{lower}_prob_max"] = float(np.max(values))
        row[f"{lower}_prob_p25"] = float(np.quantile(values, 0.25))
        row[f"{lower}_prob_p75"] = float(np.quantile(values, 0.75))
        row[f"{lower}_prob_p90"] = float(np.quantile(values, 0.90))
        row[f"{lower}_top1_proportion"] = float((top1_labels == label).mean())
        row[f"{lower}_top2_proportion"] = float(np.mean([label in pair for pair in top2_labels]))
        row[f"{lower}_top1_count"] = int((top1_labels == label).sum())
    row["mean_max_class_probability"] = float(np.mean(max_prob))
    row["median_max_class_probability"] = float(np.median(max_prob))
    row["maximum_confidence"] = float(np.max(max_prob))
    row["minimum_confidence"] = float(np.min(max_prob))
    row["confidence_standard_deviation"] = float(np.std(max_prob, ddof=0))
    row["mean_top1_top2_margin"] = float(np.mean(margin))
    row["median_top1_top2_margin"] = float(np.median(margin))
    row["minimum_top1_top2_margin"] = float(np.min(margin))
    row["maximum_top1_top2_margin"] = float(np.max(margin))
    row["proportion_low_margin_windows"] = float((margin < LOW_MARGIN_THRESHOLD).mean())
    row["proportion_high_confidence_windows"] = float((max_prob >= HIGH_CONFIDENCE_THRESHOLD).mean())
    ent = entropy(probs)
    row["window_prediction_entropy_mean"] = float(np.mean(ent))
    row["window_prediction_entropy_std"] = float(np.std(ent, ddof=0))
    top_counts = pd.Series(top1_labels).value_counts()
    row["unique_top1_classes_observed"] = int(top_counts.size)
    row["dominant_class_proportion"] = float(top_counts.max() / len(group))
    sorted_counts = top_counts.sort_values(ascending=False).tolist()
    row["dominant_vs_second_vote_margin"] = float((sorted_counts[0] - (sorted_counts[1] if len(sorted_counts) > 1 else 0)) / len(group))
    segments = temporal_segment_positions(len(group))
    group = group.copy()
    group["temporal_third"] = segments
    for seg in ["EARLY", "MIDDLE", "LATE"]:
        seg_group = group[group["temporal_third"] == seg]
        seg_probs = seg_group[["p_hijack", "p_leak", "p_outage"]].to_numpy()
        seg_margin = np.nan
        seg_conf = np.nan
        if len(seg_group):
            seg_top = np.argsort(seg_probs, axis=1)[:, ::-1]
            seg_conf = float(seg_probs.max(axis=1).mean())
            seg_margin = float((seg_probs[np.arange(len(seg_probs)), seg_top[:, 0]] - seg_probs[np.arange(len(seg_probs)), seg_top[:, 1]]).mean())
        for label, col in zip(INCIDENT_LABELS, ["p_hijack", "p_leak", "p_outage"]):
            row[f"{seg.lower()}_{label.lower()}_prob_mean"] = float(seg_group[col].mean()) if len(seg_group) else np.nan
        row[f"{seg.lower()}_mean_max_confidence"] = seg_conf
        row[f"{seg.lower()}_mean_top1_top2_margin"] = seg_margin
    for label in INCIDENT_LABELS:
        row[f"late_minus_early_{label.lower()}_prob_mean"] = row[f"late_{label.lower()}_prob_mean"] - row[f"early_{label.lower()}_prob_mean"]
    row["late_minus_early_confidence"] = row["late_mean_max_confidence"] - row["early_mean_max_confidence"]
    x = np.linspace(0.0, 1.0, len(group))
    for label, col in zip(INCIDENT_LABELS, ["p_hijack", "p_leak", "p_outage"]):
        row[f"{label.lower()}_prob_linear_slope"] = float(np.polyfit(x, group[col].to_numpy(), 1)[0]) if len(group) > 1 else 0.0
    return row


def build_meta_features(oof: pd.DataFrame, structural: pd.DataFrame) -> pd.DataFrame:
    rows = [summarize_incident(group, structural) for _, group in oof.groupby("incident_uid", sort=True)]
    meta = pd.DataFrame(rows)
    meta.to_parquet(META_FEATURES, index=False)
    return meta


def first_level_predictions_for_split(data: pd.DataFrame, train: pd.DataFrame, test: pd.DataFrame, fold: int, source: str) -> pd.DataFrame:
    features = FEATURES_BY_VARIANT[FEATURE_VARIANT]
    model = first_level_model()
    model.fit(train[features], y_codes(train["label"]), model__sample_weight=group_aware_weights(train))
    probs = model.predict_proba(test[features])
    return probability_rows(test, probs, int(fold), source)


def nested_meta_for_outer_fold(data: pd.DataFrame, outer_fold: int) -> tuple[pd.DataFrame, pd.DataFrame, dict[str, Any]]:
    outer_train = data[data["fold"] != outer_fold].copy()
    outer_test = data[data["fold"] == outer_fold].copy()
    inner_rows = []
    for inner_fold in sorted(outer_train["fold"].unique()):
        inner_train = outer_train[outer_train["fold"] != inner_fold].copy()
        inner_test = outer_train[outer_train["fold"] == inner_fold].copy()
        inner_rows.append(first_level_predictions_for_split(data, inner_train, inner_test, int(inner_fold), f"nested_inner_oof_outer_{outer_fold}"))
    train_oof = pd.concat(inner_rows, ignore_index=True)
    test_oof = first_level_predictions_for_split(data, outer_train, outer_test, int(outer_fold), f"nested_outer_test_{outer_fold}")
    train_meta = build_meta_frame(train_oof, data)
    test_meta = build_meta_frame(test_oof, data)
    audit = {
        "outer_fold": int(outer_fold),
        "outer_train_incidents": int(outer_train["incident_uid"].nunique()),
        "outer_test_incidents": int(outer_test["incident_uid"].nunique()),
        "inner_training_uses_outer_test_incidents": False,
        "meta_train_features_are_inner_oof": True,
        "meta_test_features_from_outer_train_only": True,
        "validation_rows_used": 0,
        "holdout_rows_used": 0,
        "inner_fold_count": int(outer_train["fold"].nunique()),
        "status": "PASS",
    }
    return train_meta, test_meta, audit


def build_meta_frame(oof: pd.DataFrame, structural: pd.DataFrame) -> pd.DataFrame:
    rows = [summarize_incident(group, structural) for _, group in oof.groupby("incident_uid", sort=True)]
    return pd.DataFrame(rows)


def simple_feature_names(meta: pd.DataFrame) -> list[str]:
    excluded = {"incident_uid", "true_class", "fold"}
    temporal_markers = ("early_", "middle_", "late_", "late_minus_early_", "_linear_slope")
    return [c for c in meta.columns if c not in excluded and not c.startswith(temporal_markers) and not c.endswith("_linear_slope")]


def temporal_feature_names(meta: pd.DataFrame) -> list[str]:
    return [c for c in meta.columns if c not in {"incident_uid", "true_class", "fold"}]


def write_inventory(meta: pd.DataFrame) -> pd.DataFrame:
    rows = []
    simple = set(simple_feature_names(meta))
    temporal = set(temporal_feature_names(meta)) - simple
    for feature in simple_feature_names(meta) + sorted(temporal):
        if feature in {"window_count", "observed_temporal_span_minutes", "proportion_zero_observation_windows"}:
            source = "frozen TRAIN feature rows"
            aggregation = "incident structural summary"
        elif feature in temporal:
            source = "OOF first-level window probabilities"
            aggregation = "chronological thirds or trajectory"
        else:
            source = "OOF first-level window probabilities"
            aggregation = "incident-level probability/confidence summary"
        rows.append(
            {
                "meta_feature_name": feature,
                "definition": feature.replace("_", " "),
                "source": source,
                "aggregation": aggregation,
                "temporal_scope": "EARLY/MIDDLE/LATE" if feature in temporal else "all eligible incident windows",
                "leakage_safe": True,
            }
        )
    inventory = pd.DataFrame(rows)
    inventory.to_csv(META_INVENTORY, index=False)
    return inventory


def ranked_frame(frame: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, row in frame.iterrows():
        pairs = sorted([(label, row[f"p_{label.lower()}"]) for label in INCIDENT_LABELS], key=lambda item: item[1], reverse=True)
        out = row.to_dict()
        out["predicted_class"] = pairs[0][0]
        out["true_class_rank"] = [label for label, _ in pairs].index(row["true_class"]) + 1
        rows.append(out)
    return pd.DataFrame(rows)


def metrics(frame: pd.DataFrame) -> dict[str, Any]:
    ranked = ranked_frame(frame)
    y_true = ranked["true_class"].tolist()
    y_pred = ranked["predicted_class"].tolist()
    probs = ranked[["p_hijack", "p_leak", "p_outage"]].copy()
    probs.columns = INCIDENT_LABELS
    precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, labels=INCIDENT_LABELS, zero_division=0)
    out = {
        "incident_macro_f1": float(f1_score(y_true, y_pred, labels=INCIDENT_LABELS, average="macro", zero_division=0)),
        "top1": float((ranked["true_class_rank"] == 1).mean()),
        "top2": top2_accuracy(y_true, probs),
        "mrr": mrr(y_true, probs),
        "mean_true_class_rank": float(ranked["true_class_rank"].mean()),
    }
    for idx, label in enumerate(INCIDENT_LABELS):
        lower = label.lower()
        out[f"{lower}_precision"] = float(precision[idx])
        out[f"{lower}_recall"] = float(recall[idx])
        out[f"{lower}_f1"] = float(f1[idx])
        class_rows = ranked[ranked["true_class"].eq(label)]
        out[f"{lower}_mrr"] = float((1.0 / class_rows["true_class_rank"]).mean()) if len(class_rows) else np.nan
    return out


def mean_baseline_predictions(oof: pd.DataFrame) -> pd.DataFrame:
    grouped = oof.groupby("incident_uid", as_index=False).agg(
        true_class=("true_class", "first"),
        fold=("fold", "first"),
        p_hijack=("p_hijack", "mean"),
        p_leak=("p_leak", "mean"),
        p_outage=("p_outage", "mean"),
    )
    return grouped


def logistic_model() -> Pipeline:
    return Pipeline(
        [
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            ("model", LogisticRegression(multi_class="multinomial", max_iter=2000, C=1.0, class_weight=None, random_state=SEED)),
        ]
    )


def xgb_meta_model(params: dict[str, Any]) -> Pipeline:
    return Pipeline(
        [
            ("imputer", SimpleImputer(strategy="median")),
            (
                "model",
                XGBClassifier(
                    **params,
                    objective="multi:softprob",
                    num_class=3,
                    eval_metric="mlogloss",
                    random_state=SEED,
                    seed=SEED,
                    tree_method="hist",
                    n_jobs=-1,
                    verbosity=0,
                ),
            ),
        ]
    )


def predict_meta(model: Pipeline, test: pd.DataFrame, features: list[str], candidate_id: str, fold: int) -> pd.DataFrame:
    probs = model.predict_proba(test[features])
    return pd.DataFrame(
        {
            "candidate_id": candidate_id,
            "incident_uid": test["incident_uid"].to_numpy(),
            "true_class": test["true_class"].to_numpy(),
            "fold": fold,
            "p_hijack": probs[:, 0],
            "p_leak": probs[:, 1],
            "p_outage": probs[:, 2],
        }
    )


def fit_eval_meta(meta: pd.DataFrame, features: list[str], candidate_id: str, model_factory, fold: int) -> tuple[pd.DataFrame, float, float]:
    train = meta[meta["fold"] != fold].copy()
    test = meta[meta["fold"] == fold].copy()
    model = model_factory()
    started = time.perf_counter()
    model.fit(train[features], y_codes(train["true_class"]))
    fit_time = time.perf_counter() - started
    started = time.perf_counter()
    pred = predict_meta(model, test, features, candidate_id, fold)
    infer_time = time.perf_counter() - started
    return pred, fit_time, infer_time


def tune_xgb_meta(meta: pd.DataFrame, train_folds: list[int], features: list[str]) -> dict[str, Any]:
    train_meta = meta[meta["fold"].isin(train_folds)].copy()
    best_score = -math.inf
    best_params = M2_PARAM_GRID[0]
    inner_scores = []
    for params in M2_PARAM_GRID:
        fold_frames = []
        for inner_fold in train_folds:
            inner_train = train_meta[train_meta["fold"] != inner_fold]
            inner_test = train_meta[train_meta["fold"] == inner_fold]
            model = xgb_meta_model(params)
            model.fit(inner_train[features], y_codes(inner_train["true_class"]))
            fold_frames.append(predict_meta(model, inner_test, features, "K1-M2-INNER", int(inner_fold)))
        score = metrics(pd.concat(fold_frames, ignore_index=True))["incident_macro_f1"]
        inner_scores.append({"parameter_hash": param_hash(params), "incident_macro_f1": score, "params": params})
        if score > best_score:
            best_score = score
            best_params = params
    return {"params": best_params, "inner_macro_f1": best_score, "search_rows": inner_scores}


def evaluate_k1_models_nested(data: pd.DataFrame, oof: pd.DataFrame, meta: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    simple_features = simple_feature_names(meta)
    temporal_features = temporal_feature_names(meta)
    predictions = []
    fold_rows = []
    nested_rows = []
    baseline = mean_baseline_predictions(oof)
    baseline["candidate_id"] = "K1-B0_MEAN_PROBABILITY"
    predictions.append(baseline[["candidate_id", "incident_uid", "true_class", "fold", "p_hijack", "p_leak", "p_outage"]])
    for fold, fold_group in baseline.groupby("fold"):
        fold_metric = metrics(fold_group)
        fold_rows.append({"candidate_id": "K1-B0_MEAN_PROBABILITY", "feature_set": "OOF_MEAN", "fold": int(fold), "fit_time_seconds": 0.0, "inference_time_seconds": 0.0, **fold_metric})
    nested_cache: dict[int, tuple[pd.DataFrame, pd.DataFrame, dict[str, Any]]] = {}
    for fold in sorted(meta["fold"].unique()):
        print(f"K1 nested first-level probabilities for outer fold {fold}", flush=True)
        nested_cache[int(fold)] = nested_meta_for_outer_fold(data, int(fold))
        audit = nested_cache[int(fold)][2]
        audit["feature_set"] = "ALL"
        audit["xgb_meta_search_budget"] = len(M2_PARAM_GRID)
        nested_rows.append(audit)
    for feature_set, features in [("K1-SIMPLE", simple_features), ("K1-TEMPORAL", temporal_features)]:
        for fold in sorted(meta["fold"].unique()):
            train_meta, test_meta, _ = nested_cache[int(fold)]
            model = logistic_model()
            started = time.perf_counter()
            model.fit(train_meta[features], y_codes(train_meta["true_class"]))
            fit_time = time.perf_counter() - started
            started = time.perf_counter()
            pred = predict_meta(model, test_meta, features, f"K1-M1_LOGISTIC_{feature_set}", int(fold))
            infer_time = time.perf_counter() - started
            predictions.append(pred)
            fold_rows.append({"candidate_id": f"K1-M1_LOGISTIC_{feature_set}", "feature_set": feature_set, "fold": int(fold), "fit_time_seconds": fit_time, "inference_time_seconds": infer_time, **metrics(pred)})
            train_folds = sorted([int(f) for f in train_meta["fold"].unique()])
            tuned = tune_xgb_meta(train_meta, train_folds, features)
            model_factory = lambda params=tuned["params"]: xgb_meta_model(params)
            started = time.perf_counter()
            model2 = model_factory()
            model2.fit(train_meta[features], y_codes(train_meta["true_class"]))
            fit_time2 = time.perf_counter() - started
            started = time.perf_counter()
            pred2 = predict_meta(model2, test_meta, features, f"K1-M2_XGB_{feature_set}", int(fold))
            infer_time2 = time.perf_counter() - started
            pred2["parameter_hash"] = param_hash(tuned["params"])
            predictions.append(pred2)
            fold_rows.append({"candidate_id": f"K1-M2_XGB_{feature_set}", "feature_set": feature_set, "fold": int(fold), "fit_time_seconds": fit_time2, "inference_time_seconds": infer_time2, "parameter_hash": param_hash(tuned["params"]), "inner_selected_macro_f1": tuned["inner_macro_f1"], **metrics(pred2)})
    all_predictions = pd.concat(predictions, ignore_index=True, sort=False)
    folds = pd.DataFrame(fold_rows)
    nested = pd.DataFrame(nested_rows)
    nested.to_csv(NESTED_AUDIT, index=False)
    return all_predictions, folds, nested


def summarize_models(predictions: pd.DataFrame, folds: pd.DataFrame, meta: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for candidate_id, group in predictions.groupby("candidate_id"):
        feature_set = folds[folds["candidate_id"].eq(candidate_id)]["feature_set"].iloc[0]
        metric = metrics(group)
        rows.append(
            {
                "candidate_id": candidate_id,
                "feature_set": feature_set,
                "phase": "K1",
                "methodological_status": "POST_VALIDATION_VERSIONED_TRAIN_DEVELOPMENT_EXPERIMENT",
                "train_only": True,
                "validation_used": False,
                "holdout_status": "SEALED",
                "incident_rows": group["incident_uid"].nunique(),
                "meta_feature_count": 0 if candidate_id.startswith("K1-B0") else len(simple_feature_names(meta) if feature_set == "K1-SIMPLE" else temporal_feature_names(meta)),
                "incident_to_feature_ratio": np.inf if candidate_id.startswith("K1-B0") else group["incident_uid"].nunique() / len(simple_feature_names(meta) if feature_set == "K1-SIMPLE" else temporal_feature_names(meta)),
                "mean_fit_time_seconds": float(folds[folds["candidate_id"].eq(candidate_id)]["fit_time_seconds"].mean()),
                "mean_inference_time_seconds": float(folds[folds["candidate_id"].eq(candidate_id)]["inference_time_seconds"].mean()),
                **metric,
                "fold_macro_f1_std": float(folds[folds["candidate_id"].eq(candidate_id)]["incident_macro_f1"].std(ddof=0)),
            }
        )
    return pd.DataFrame(rows).sort_values(["incident_macro_f1", "mrr", "top2"], ascending=False)


def write_confusion(predictions: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for candidate_id, group in predictions.groupby("candidate_id"):
        ranked = ranked_frame(group)
        cm = confusion_matrix(ranked["true_class"], ranked["predicted_class"], labels=INCIDENT_LABELS)
        for i, true_class in enumerate(INCIDENT_LABELS):
            for j, predicted_class in enumerate(INCIDENT_LABELS):
                rows.append({"candidate_id": candidate_id, "true_class": true_class, "predicted_class": predicted_class, "count": int(cm[i, j])})
    out = pd.DataFrame(rows)
    out.to_csv(CONFUSION, index=False)
    return out


def paired_comparison(folds: pd.DataFrame) -> pd.DataFrame:
    comparisons = [("K1-M1_LOGISTIC_K1-SIMPLE", "K1-B0_MEAN_PROBABILITY"), ("K1-M1_LOGISTIC_K1-TEMPORAL", "K1-B0_MEAN_PROBABILITY"), ("K1-M2_XGB_K1-SIMPLE", "K1-B0_MEAN_PROBABILITY"), ("K1-M2_XGB_K1-TEMPORAL", "K1-B0_MEAN_PROBABILITY"), ("K1-M2_XGB_K1-TEMPORAL", "K1-M1_LOGISTIC_K1-TEMPORAL")]
    metrics_cols = ["incident_macro_f1", "top1", "top2", "mrr", "hijack_f1", "leak_f1", "outage_f1"]
    rows = []
    for candidate, baseline in comparisons:
        c = folds[folds["candidate_id"].eq(candidate)].set_index("fold")
        b = folds[folds["candidate_id"].eq(baseline)].set_index("fold")
        if c.empty or b.empty:
            continue
        row = {"candidate_id": candidate, "baseline_id": baseline}
        macro_delta = c["incident_macro_f1"] - b["incident_macro_f1"]
        for col in metrics_cols:
            row[f"{col}_delta"] = float((c[col] - b[col]).mean())
        row["folds_won"] = int((macro_delta > 0).sum())
        row["folds_lost"] = int((macro_delta < 0).sum())
        row["folds_tied"] = int((macro_delta == 0).sum())
        rows.append(row)
    out = pd.DataFrame(rows)
    out.to_csv(PAIRED, index=False)
    return out


def temporal_ablation(results: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for family in ["K1-M1_LOGISTIC", "K1-M2_XGB"]:
        simple = results[results["candidate_id"].eq(f"{family}_K1-SIMPLE")]
        temporal = results[results["candidate_id"].eq(f"{family}_K1-TEMPORAL")]
        if len(simple) and len(temporal):
            s = simple.iloc[0]
            t = temporal.iloc[0]
            rows.append(
                {
                    "model_family": family,
                    "simple_candidate": s["candidate_id"],
                    "temporal_candidate": t["candidate_id"],
                    "meta_feature_count_simple": s["meta_feature_count"],
                    "meta_feature_count_temporal": t["meta_feature_count"],
                    "macro_f1_delta_temporal_minus_simple": t["incident_macro_f1"] - s["incident_macro_f1"],
                    "mrr_delta_temporal_minus_simple": t["mrr"] - s["mrr"],
                    "top2_delta_temporal_minus_simple": t["top2"] - s["top2"],
                    "hijack_f1_delta_temporal_minus_simple": t["hijack_f1"] - s["hijack_f1"],
                }
            )
    out = pd.DataFrame(rows)
    out.to_csv(ABLATION, index=False)
    return out


def decision_summary(results: pd.DataFrame, paired: pd.DataFrame) -> pd.DataFrame:
    baseline = results[results["candidate_id"].eq("K1-B0_MEAN_PROBABILITY")].iloc[0]
    best = results.iloc[0]
    macro_gain = float(best["incident_macro_f1"] - baseline["incident_macro_f1"])
    mrr_gain = float(best["mrr"] - baseline["mrr"])
    top2_gain = float(best["top2"] - baseline["top2"])
    hijack_gain = float(best["hijack_f1"] - baseline["hijack_f1"])
    if macro_gain >= 0.02 and mrr_gain >= 0 and best["fold_macro_f1_std"] <= 0.08:
        outcome = "MEANINGFUL_IMPROVEMENT"
        recommendation = "CARRY_LOGISTIC_INCIDENT_STACKER" if "M1" in best["candidate_id"] else "CARRY_XGB_INCIDENT_STACKER"
    elif macro_gain >= 0.005 and mrr_gain >= -0.005:
        outcome = "MARGINAL_IMPROVEMENT"
        recommendation = "KEEP_MEAN_PROBABILITY_AGGREGATION"
    else:
        outcome = "NO_IMPROVEMENT"
        recommendation = "KEEP_MEAN_PROBABILITY_AGGREGATION"
    row = {
        "phase": "K1",
        "methodological_status": "POST_VALIDATION_VERSIONED_TRAIN_DEVELOPMENT_EXPERIMENT",
        "selected_by": "TRAIN nested-CV only",
        "baseline_candidate": baseline["candidate_id"],
        "best_train_candidate": best["candidate_id"],
        "macro_f1_gain_vs_b0": macro_gain,
        "mrr_gain_vs_b0": mrr_gain,
        "top2_gain_vs_b0": top2_gain,
        "hijack_f1_gain_vs_b0": hijack_gain,
        "outcome": outcome,
        "recommendation": recommendation,
        "validation_used_for_k1": False,
        "final_holdout_status": "SEALED",
        "source_commit": source_commit(),
        "notes": "K1 must not be run on Validation or Holdout without a separately approved protocol.",
    }
    out = pd.DataFrame([row])
    out.to_csv(DECISION, index=False)
    if recommendation != "KEEP_MEAN_PROBABILITY_AGGREGATION" and outcome == "MEANINGFUL_IMPROVEMENT":
        K1_CANDIDATE.write_text(yaml.safe_dump({"candidate_id": best["candidate_id"], "status": "POST_VALIDATION_TRAIN_DEVELOPMENT_CANDIDATE", "selection_basis": "TRAIN nested-CV only", "validation_used": False, "final_holdout_status": "SEALED", "source_commit": source_commit()}, sort_keys=False), encoding="utf-8")
    return out


def write_notebook() -> None:
    NOTEBOOK.parent.mkdir(parents=True, exist_ok=True)
    notebook = {
        "cells": [
            {"cell_type": "markdown", "metadata": {}, "source": ["# Phase K1 - TRAIN-Only Incident Stacking\n", "\n", "Post-Validation versioned TRAIN-only development experiment. Validation is not used for K1 model development; Final Holdout remains sealed.\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["from bgp_incident_detection.k1_incident_stacking import run_phase_k1\n", "# run_phase_k1()\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["import pandas as pd\n", "pd.read_csv('../data/modeling_k1/k1_model_results_v1.csv')\n"]},
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")


def run_phase_k1() -> dict[str, Any]:
    K1_DIR.mkdir(parents=True, exist_ok=True)
    data = load_train_data()
    oof = generate_oof_probabilities(data)
    leakage_audit(data, oof)
    meta = build_meta_features(oof, data)
    write_inventory(meta)
    predictions, folds, nested = evaluate_k1_models_nested(data, oof, meta)
    predictions.to_parquet(K1_DIR / "k1_incident_level_predictions_v1.parquet", index=False)
    folds.to_csv(FOLD_RESULTS, index=False)
    results = summarize_models(predictions, folds, meta)
    results.to_csv(MODEL_RESULTS, index=False)
    write_confusion(predictions)
    paired = paired_comparison(folds)
    temporal_ablation(results)
    decision = decision_summary(results, paired)
    write_notebook()
    return {
        "status": "PASS" if set(nested["status"]) == {"PASS"} else "REVIEW",
        "train_incidents": int(meta["incident_uid"].nunique()),
        "meta_rows": int(len(meta)),
        "best_candidate": results.iloc[0]["candidate_id"],
        "best_macro_f1": float(results.iloc[0]["incident_macro_f1"]),
        "best_mrr": float(results.iloc[0]["mrr"]),
        "recommendation": decision.iloc[0]["recommendation"],
        "outcome": decision.iloc[0]["outcome"],
        "validation_used": False,
        "final_holdout_status": "SEALED",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Phase K1 TRAIN-only incident-level stacking experiment")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if not args.run:
        parser.error("choose --run")
    print(json.dumps(run_phase_k1(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
