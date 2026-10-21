from __future__ import annotations

import argparse
import json
import time
from collections import Counter, defaultdict
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline

try:
    from bgp_incident_detection.audit import write_csv
    from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES
    from bgp_incident_detection.train_batch_engine import source_commit
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import write_csv
    from src.bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES
    from src.bgp_incident_detection.train_batch_engine import source_commit


MODEL_READY_DIR = Path("data/model_ready")
MODELING_DIR = Path("data/modeling")
MODEL_DIR = MODELING_DIR / "models/baseline_v1"
NORMAL_V1 = MODEL_READY_DIR / "frozen_normal_v1_v1.parquet"
INCIDENT_V1 = Path("data/train_frozen/frozen_train_behavioral_corpus_v1.parquet")
STAGE1_MANIFEST = MODEL_READY_DIR / "stage1_v1_development_manifest_v1.csv"
STAGE2_MANIFEST = MODEL_READY_DIR / "stage2_v1_development_manifest_v1.csv"
CV_ASSIGNMENTS = MODELING_DIR / "baseline_v1_grouped_cv_assignments_v1.csv"
FOLD_RESULTS = MODELING_DIR / "baseline_v1_fold_results_v1.csv"
MODEL_COMPARISON = MODELING_DIR / "baseline_v1_model_comparison_v1.csv"
REGISTRY = MODELING_DIR / "model_experiment_registry_v1.csv"
NOTEBOOK = Path("notebooks/39_v1_behavioral_model_baselines.ipynb")

SEED = 20260828
N_SPLITS = 5
CLASS_LABELS = ["NORMAL", "HIJACK", "LEAK", "OUTAGE"]
INCIDENT_LABELS = ["HIJACK", "LEAK", "OUTAGE"]
RF_HYPERPARAMETERS = {
    "n_estimators": 200,
    "max_depth": None,
    "min_samples_split": 2,
    "min_samples_leaf": 1,
    "max_features": "sqrt",
    "class_weight": None,
    "random_state": SEED,
    "n_jobs": -1,
}
XGB_HYPERPARAMETERS = {
    "n_estimators": 200,
    "max_depth": 6,
    "learning_rate": 0.05,
    "subsample": 0.9,
    "colsample_bytree": 0.9,
    "objective": "multi:softprob",
    "random_state": SEED,
}


def xgboost_available() -> bool:
    try:
        import xgboost  # noqa: F401
    except Exception:
        return False
    return True


def normalize_category(value: object) -> str:
    text = str(value or "").upper()
    if text == "HIJACK":
        return "HIJACK"
    if text == "LEAK":
        return "LEAK"
    if text == "OUTAGE":
        return "OUTAGE"
    if text == "NORMAL":
        return "NORMAL"
    return text


def load_v1_dataset() -> pd.DataFrame:
    normal = pd.read_parquet(NORMAL_V1)
    incident = pd.read_parquet(INCIDENT_V1)
    normal_rows = normal[["window_id", "candidate_period_id", "associated_incident_uid", "category", "partition"] + BEHAVIORAL_FEATURE_NAMES].copy()
    normal_rows["incident_uid"] = ""
    normal_rows["control_uid"] = normal_rows["candidate_period_id"]
    normal_rows["label"] = "NORMAL"
    normal_rows["group_id"] = normal_rows["candidate_period_id"]
    normal_rows["model_group_id"] = normal_rows["associated_incident_uid"]

    incident_rows = incident[["window_id", "incident_uid", "category", "partition"] + BEHAVIORAL_FEATURE_NAMES].copy()
    incident_rows["control_uid"] = ""
    incident_rows["label"] = incident_rows["category"].map(normalize_category)
    incident_rows["group_id"] = incident_rows["incident_uid"]
    incident_rows["model_group_id"] = incident_rows["incident_uid"]
    incident_rows["candidate_period_id"] = ""
    incident_rows["associated_incident_uid"] = ""

    df = pd.concat([normal_rows, incident_rows], ignore_index=True, sort=False)
    if len(normal_rows) != 516:
        raise ValueError(f"expected 516 Normal rows, found {len(normal_rows)}")
    if len(incident_rows) != 68031:
        raise ValueError(f"expected 68,031 incident rows, found {len(incident_rows)}")
    if set(df["partition"].astype(str)) != {"train"}:
        raise ValueError("baseline dataset must be TRAIN only")
    if any(feature not in df.columns for feature in BEHAVIORAL_FEATURE_NAMES):
        raise ValueError("V1 baseline dataset must contain exactly the 44 behavioral features")
    extra_forbidden = [column for column in df.columns if column.startswith("caida_") or column.startswith("rpki_")]
    if extra_forbidden:
        raise ValueError(f"V1 baseline must not include CAIDA/RPKI features: {extra_forbidden}")
    return df


def group_labels(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for model_group_id, group in df.groupby("model_group_id"):
        counts = Counter(group["label"])
        primary = counts.most_common(1)[0][0]
        rows.append({"model_group_id": model_group_id, "stratify_label": primary, "rows": len(group), "labels": json.dumps(dict(counts), sort_keys=True)})
    return pd.DataFrame(rows)


def create_grouped_folds(df: pd.DataFrame, seed: int = SEED) -> pd.DataFrame:
    groups_df = group_labels(df).sort_values("model_group_id").reset_index(drop=True)
    splitter = StratifiedGroupKFold(n_splits=N_SPLITS, shuffle=True, random_state=seed)
    folds = {}
    X = np.zeros(len(groups_df))
    y = groups_df["stratify_label"]
    groups = groups_df["model_group_id"]
    for fold, (_, test_idx) in enumerate(splitter.split(X, y, groups), start=1):
        for idx in test_idx:
            folds[groups_df.loc[idx, "model_group_id"]] = fold
    rows = []
    for _, row in df.iterrows():
        rows.append(
            {
                "window_id": row["window_id"],
                "incident_uid": row.get("incident_uid", ""),
                "control_uid": row.get("control_uid", ""),
                "label": row["label"],
                "category": normalize_category(row["category"]),
                "group_id": row["group_id"],
                "model_group_id": row["model_group_id"],
                "fold": folds[row["model_group_id"]],
                "cv_seed": seed,
                "feature_variant": "V1",
                "imbalance_condition": "I0",
            }
        )
    assignments = pd.DataFrame(rows)
    if assignments.groupby("model_group_id")["fold"].nunique().max() != 1:
        raise RuntimeError("a model_group_id crosses folds")
    CV_ASSIGNMENTS.parent.mkdir(parents=True, exist_ok=True)
    assignments.to_csv(CV_ASSIGNMENTS, index=False)
    return assignments


def fold_distribution(assignments: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for fold, group in assignments.groupby("fold"):
        rows.append(
            {
                "fold": fold,
                "rows": len(group),
                "model_groups": group["model_group_id"].nunique(),
                "normal_rows": int((group["label"] == "NORMAL").sum()),
                "hijack_rows": int((group["label"] == "HIJACK").sum()),
                "leak_rows": int((group["label"] == "LEAK").sum()),
                "outage_rows": int((group["label"] == "OUTAGE").sum()),
            }
        )
    return pd.DataFrame(rows)


def rf_pipeline(binary: bool = False) -> Pipeline:
    return Pipeline(
        [
            ("imputer", SimpleImputer(strategy="median")),
            ("model", RandomForestClassifier(**RF_HYPERPARAMETERS)),
        ]
    )


def class_prob_frame(labels: list[str], probs: np.ndarray, columns: list[str]) -> pd.DataFrame:
    frame = pd.DataFrame(0.0, index=np.arange(len(probs)), columns=columns)
    for index, label in enumerate(labels):
        frame[label] = probs[:, index]
    return frame


def top2_accuracy(y_true: list[str], probs: pd.DataFrame) -> float:
    labels = list(probs.columns)
    score = 0
    arr = probs.to_numpy()
    for true, row in zip(y_true, arr):
        top = [labels[idx] for idx in np.argsort(row)[-2:]]
        score += int(true in top)
    return score / len(y_true) if y_true else float("nan")


def mrr(y_true: list[str], probs: pd.DataFrame) -> float:
    labels = list(probs.columns)
    total = 0.0
    arr = probs.to_numpy()
    for true, row in zip(y_true, arr):
        order = [labels[idx] for idx in np.argsort(row)[::-1]]
        total += 1.0 / (order.index(true) + 1)
    return total / len(y_true) if y_true else float("nan")


def macro_f1(y_true: list[str], y_pred: list[str], labels: list[str]) -> float:
    return float(f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0))


def per_class_f1(y_true: list[str], y_pred: list[str], labels: list[str]) -> dict[str, float]:
    precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, labels=labels, zero_division=0)
    output = {}
    for label, p, r, f in zip(labels, precision, recall, f1):
        output[f"{label.lower()}_precision"] = float(p)
        output[f"{label.lower()}_recall"] = float(r)
        output[f"{label.lower()}_f1"] = float(f)
    return output


def aggregate_group_predictions(predictions: pd.DataFrame, labels: list[str]) -> tuple[list[str], list[str], pd.DataFrame]:
    prob_cols = [f"prob_{label}" for label in labels]
    grouped = predictions.groupby("group_id")
    y_true = grouped["true_label"].agg(lambda values: values.iloc[0]).tolist()
    probs = grouped[prob_cols].mean()
    probs.columns = labels
    y_pred = probs.idxmax(axis=1).tolist()
    return y_true, y_pred, probs


def common_result(model_name: str, fold: int, train: pd.DataFrame, test: pd.DataFrame, train_seconds: float, infer_seconds: float, scope: str, y_true: list[str], y_pred: list[str], probs: pd.DataFrame, labels: list[str]) -> dict[str, object]:
    result = {
        "experiment_id": model_name,
        "fold": fold,
        "evaluation_scope": scope,
        "train_groups": train["model_group_id"].nunique(),
        "test_groups": test["model_group_id"].nunique(),
        "train_rows": len(train),
        "test_rows": len(test),
        "macro_f1": macro_f1(y_true, y_pred, labels),
        "top2_accuracy": top2_accuracy(y_true, probs) if len(labels) > 2 else "",
        "mrr": mrr(y_true, probs),
        "train_seconds": round(train_seconds, 3),
        "inference_seconds": round(infer_seconds, 3),
        "confusion_matrix": json.dumps(confusion_matrix(y_true, y_pred, labels=labels).tolist()),
        "hyperparameters": json.dumps(RF_HYPERPARAMETERS, sort_keys=True),
        "notes": "",
    }
    result.update(per_class_f1(y_true, y_pred, labels))
    return result


def fit_single_rf(df: pd.DataFrame, assignments: pd.DataFrame) -> list[dict[str, object]]:
    rows = []
    data = df.merge(assignments[["window_id", "fold"]], on="window_id", how="left", validate="one_to_one")
    for fold in sorted(data["fold"].unique()):
        train = data[data["fold"] != fold]
        test = data[data["fold"] == fold]
        model = rf_pipeline()
        started = time.perf_counter()
        model.fit(train[BEHAVIORAL_FEATURE_NAMES], train["label"])
        train_seconds = time.perf_counter() - started
        started = time.perf_counter()
        probs_raw = model.predict_proba(test[BEHAVIORAL_FEATURE_NAMES])
        infer_seconds = time.perf_counter() - started
        probs = class_prob_frame(list(model.classes_), probs_raw, CLASS_LABELS)
        y_pred = probs.idxmax(axis=1).tolist()
        y_true = test["label"].tolist()
        rows.append(common_result("BASE_V1_I0_RF_SINGLE", int(fold), train, test, train_seconds, infer_seconds, "window", y_true, y_pred, probs, CLASS_LABELS))
        predictions = test[["window_id", "group_id"]].copy()
        predictions["true_label"] = y_true
        for label in CLASS_LABELS:
            predictions[f"prob_{label}"] = probs[label].to_numpy()
        gy_true, gy_pred, gprobs = aggregate_group_predictions(predictions, CLASS_LABELS)
        rows.append(common_result("BASE_V1_I0_RF_SINGLE", int(fold), train, test, train_seconds, infer_seconds, "group", gy_true, gy_pred, gprobs, CLASS_LABELS))
        save_model(model, "BASE_V1_I0_RF_SINGLE", int(fold), RF_HYPERPARAMETERS)
    return rows


def fit_hierarchical_rf(df: pd.DataFrame, assignments: pd.DataFrame) -> list[dict[str, object]]:
    rows = []
    data = df.merge(assignments[["window_id", "fold"]], on="window_id", how="left", validate="one_to_one")
    for fold in sorted(data["fold"].unique()):
        train = data[data["fold"] != fold].copy()
        test = data[data["fold"] == fold].copy()
        train["stage1_label"] = np.where(train["label"] == "NORMAL", "NORMAL", "INCIDENT")
        test["stage1_label"] = np.where(test["label"] == "NORMAL", "NORMAL", "INCIDENT")
        stage1 = rf_pipeline(binary=True)
        stage2 = rf_pipeline()
        started = time.perf_counter()
        stage1.fit(train[BEHAVIORAL_FEATURE_NAMES], train["stage1_label"])
        incident_train = train[train["label"].isin(INCIDENT_LABELS)]
        stage2.fit(incident_train[BEHAVIORAL_FEATURE_NAMES], incident_train["label"])
        train_seconds = time.perf_counter() - started
        started = time.perf_counter()
        stage1_probs = class_prob_frame(list(stage1.classes_), stage1.predict_proba(test[BEHAVIORAL_FEATURE_NAMES]), ["NORMAL", "INCIDENT"])
        stage1_probs.index = test.index
        stage2_probs = class_prob_frame(list(stage2.classes_), stage2.predict_proba(test[BEHAVIORAL_FEATURE_NAMES]), INCIDENT_LABELS)
        stage2_probs.index = test.index
        infer_seconds = time.perf_counter() - started

        stage1_pred = stage1_probs.idxmax(axis=1).tolist()
        rows.append(stage1_result(int(fold), train, test, train_seconds, infer_seconds, test["stage1_label"].tolist(), stage1_pred, stage1_probs, "window"))

        incident_test = test[test["label"].isin(INCIDENT_LABELS)].copy()
        incident_stage2_probs = stage2_probs.loc[incident_test.index].reset_index(drop=True)
        stage2_pred = incident_stage2_probs.idxmax(axis=1).tolist()
        rows.append(common_result("BASE_V1_I0_RF_HIER_STAGE2", int(fold), incident_train, incident_test, train_seconds, infer_seconds, "window", incident_test["label"].tolist(), stage2_pred, incident_stage2_probs, INCIDENT_LABELS))

        end_probs = pd.DataFrame({"NORMAL": stage1_probs["NORMAL"]})
        for label in INCIDENT_LABELS:
            end_probs[label] = stage1_probs["INCIDENT"] * stage2_probs[label]
        end_pred = end_probs.idxmax(axis=1).tolist()
        rows.append(common_result("BASE_V1_I0_RF_HIER", int(fold), train, test, train_seconds, infer_seconds, "window", test["label"].tolist(), end_pred, end_probs, CLASS_LABELS))

        predictions = test[["window_id", "group_id"]].copy()
        predictions["true_label"] = test["label"].tolist()
        for label in CLASS_LABELS:
            predictions[f"prob_{label}"] = end_probs[label].to_numpy()
        gy_true, gy_pred, gprobs = aggregate_group_predictions(predictions, CLASS_LABELS)
        rows.append(common_result("BASE_V1_I0_RF_HIER", int(fold), train, test, train_seconds, infer_seconds, "group", gy_true, gy_pred, gprobs, CLASS_LABELS))
        save_model({"stage1": stage1, "stage2": stage2}, "BASE_V1_I0_RF_HIER", int(fold), RF_HYPERPARAMETERS)
    return rows


def stage1_result(fold: int, train: pd.DataFrame, test: pd.DataFrame, train_seconds: float, infer_seconds: float, y_true: list[str], y_pred: list[str], probs: pd.DataFrame, scope: str) -> dict[str, object]:
    row = common_result("BASE_V1_I0_RF_HIER_STAGE1", fold, train, test, train_seconds, infer_seconds, scope, y_true, y_pred, probs, ["NORMAL", "INCIDENT"])
    try:
        row["roc_auc"] = float(roc_auc_score([1 if y == "INCIDENT" else 0 for y in y_true], probs["INCIDENT"]))
        row["pr_auc"] = float(average_precision_score([1 if y == "INCIDENT" else 0 for y in y_true], probs["INCIDENT"]))
        row["brier_score"] = float(brier_score_loss([1 if y == "INCIDENT" else 0 for y in y_true], probs["INCIDENT"]))
    except ValueError:
        row["roc_auc"] = ""
        row["pr_auc"] = ""
        row["brier_score"] = ""
    return row


def save_model(model: object, experiment_id: str, fold: int, hyperparameters: dict[str, object]) -> None:
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    path = MODEL_DIR / f"{experiment_id}_fold{fold}.joblib"
    joblib.dump(model, path)
    metadata = {
        "model_name": experiment_id,
        "feature_variant": "V1",
        "imbalance_condition": "I0",
        "fold": fold,
        "seed": SEED,
        "hyperparameters": hyperparameters,
        "feature_names": BEHAVIORAL_FEATURE_NAMES,
        "training_timestamp": pd.Timestamp.utcnow().isoformat(),
        "source_commit": source_commit(),
        "production_model": False,
    }
    (MODEL_DIR / f"{experiment_id}_fold{fold}.metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def summarize_results(fold_results: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for (experiment_id, scope), group in fold_results.groupby(["experiment_id", "evaluation_scope"]):
        if experiment_id.endswith("_STAGE1") or experiment_id.endswith("_STAGE2"):
            pass
        metric_cols = ["macro_f1", "top2_accuracy", "mrr", "train_seconds", "inference_seconds"]
        output = {"experiment_id": experiment_id, "evaluation_scope": scope, "folds": group["fold"].nunique()}
        for metric in metric_cols:
            values = pd.to_numeric(group[metric], errors="coerce").dropna()
            output[f"{metric}_mean"] = values.mean() if len(values) else ""
            output[f"{metric}_std"] = values.std(ddof=1) if len(values) > 1 else ""
        output["notes"] = "TRAIN grouped-CV baseline; not final model selection"
        rows.append(output)
    return pd.DataFrame(rows).sort_values(["evaluation_scope", "experiment_id"])


def write_registry(xgb_status: str) -> None:
    rows = [
        {"experiment_id": "BASE_V1_I0_RF_SINGLE", "model": "RandomForestClassifier", "architecture": "single-stage", "feature_variant": "V1", "feature_count": 44, "imbalance_condition": "I0 Natural", "cv_scheme": "5-fold StratifiedGroupKFold by model_group_id", "seed": SEED, "status": "COMPLETED", "result_artifact": str(MODEL_COMPARISON)},
        {"experiment_id": "BASE_V1_I0_XGB_SINGLE", "model": "XGBoost", "architecture": "single-stage", "feature_variant": "V1", "feature_count": 44, "imbalance_condition": "I0 Natural", "cv_scheme": "5-fold StratifiedGroupKFold by model_group_id", "seed": SEED, "status": xgb_status, "result_artifact": str(MODEL_COMPARISON) if xgb_status == "COMPLETED" else "xgboost_not_installed"},
        {"experiment_id": "BASE_V1_I0_RF_HIER", "model": "RandomForestClassifier", "architecture": "hierarchical", "feature_variant": "V1", "feature_count": 44, "imbalance_condition": "I0 Natural", "cv_scheme": "5-fold StratifiedGroupKFold by model_group_id", "seed": SEED, "status": "COMPLETED", "result_artifact": str(MODEL_COMPARISON)},
    ]
    write_csv(REGISTRY, rows, ["experiment_id", "model", "architecture", "feature_variant", "feature_count", "imbalance_condition", "cv_scheme", "seed", "status", "result_artifact"])


def write_notebook() -> None:
    NOTEBOOK.parent.mkdir(parents=True, exist_ok=True)
    notebook = {
        "cells": [
            {"cell_type": "markdown", "metadata": {}, "source": ["# V1 Behavioral Baseline Modeling\n", "\n", "TRAIN-only V1/I0 baselines using grouped CV. No CAIDA/RPKI, weighting, p95 cap, ablation, SHAP, threshold tuning, or Holdout access.\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["from bgp_incident_detection.model_baselines import run_baselines\n", "# run_baselines()\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["import pandas as pd\n", "pd.read_csv('../data/modeling/baseline_v1_model_comparison_v1.csv')\n"]},
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")


def prepare_summary() -> dict[str, object]:
    df = load_v1_dataset()
    assignments = create_grouped_folds(df)
    distribution = fold_distribution(assignments)
    return {
        "stage1_rows": len(df),
        "stage1_label_counts": dict(Counter(df["label"].map(lambda value: "INCIDENT" if value != "NORMAL" else "NORMAL"))),
        "stage2_rows": int((df["label"] != "NORMAL").sum()),
        "stage2_label_counts": dict(Counter(df.loc[df["label"] != "NORMAL", "label"])),
        "model_groups": df["model_group_id"].nunique(),
        "group_ids": df["group_id"].nunique(),
        "fold_distribution": distribution.to_dict(orient="records"),
        "rf_hyperparameters": RF_HYPERPARAMETERS,
        "xgb_available": xgboost_available(),
        "xgb_hyperparameters": XGB_HYPERPARAMETERS,
        "holdout_loaded": False,
    }


def run_baselines() -> dict[str, object]:
    df = load_v1_dataset()
    assignments = create_grouped_folds(df)
    results = []
    results.extend(fit_single_rf(df, assignments))
    xgb_status = "UNAVAILABLE_XGBOOST_NOT_INSTALLED"
    if xgboost_available():
        xgb_status = "NOT_RUN_IN_THIS_BASELINE_RUN"
    results.extend(fit_hierarchical_rf(df, assignments))
    fold_results = pd.DataFrame(results)
    MODELING_DIR.mkdir(parents=True, exist_ok=True)
    fold_results.to_csv(FOLD_RESULTS, index=False)
    comparison = summarize_results(fold_results)
    comparison.to_csv(MODEL_COMPARISON, index=False)
    write_registry(xgb_status)
    write_notebook()
    return {
        "stage1_rows": len(df),
        "stage2_rows": int((df["label"] != "NORMAL").sum()),
        "model_groups": df["model_group_id"].nunique(),
        "group_ids": df["group_id"].nunique(),
        "folds": N_SPLITS,
        "xgboost_status": xgb_status,
        "fold_results": str(FOLD_RESULTS),
        "model_comparison": str(MODEL_COMPARISON),
        "registry": str(REGISTRY),
        "cv_assignments": str(CV_ASSIGNMENTS),
        "holdout_loaded": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run V1/I0 behavioral grouped-CV model baselines")
    parser.add_argument("--prepare-summary", action="store_true")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if args.prepare_summary:
        print(json.dumps(prepare_summary(), indent=2, sort_keys=True))
        return
    if args.run:
        print(json.dumps(run_baselines(), indent=2, sort_keys=True))
        return
    parser.error("choose --prepare-summary or --run")


if __name__ == "__main__":
    main()
