from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import sklearn
import xgboost
import yaml
from sklearn.impute import SimpleImputer
from sklearn.metrics import f1_score
from sklearn.pipeline import Pipeline
from xgboost import XGBClassifier

try:
    from bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT
    from bgp_incident_detection.imbalance_model_experiment import group_aware_weights
    from bgp_incident_detection.model_baselines import INCIDENT_LABELS
    from bgp_incident_detection.train_batch_engine import source_commit
except ModuleNotFoundError:
    from src.bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT
    from src.bgp_incident_detection.imbalance_model_experiment import group_aware_weights
    from src.bgp_incident_detection.model_baselines import INCIDENT_LABELS
    from src.bgp_incident_detection.train_batch_engine import source_commit


ROOT = Path(".")
OUT_DIR = ROOT / "data" / "tti_pilot"
MODEL_DIR = OUT_DIR / "reconstructed_level1_v1"
TRAIN_V4 = ROOT / "data" / "train_frozen" / "frozen_train_v4_behavioral_caida_rpki_v1.parquet"
ASSIGNMENTS = ROOT / "data" / "modeling" / "baseline_v1_grouped_cv_assignments_v1.csv"
REFERENCE_OOF = ROOT / "data" / "modeling_k1" / "k1_window_oof_probabilities_v1.parquet"
FINAL_CANDIDATE = ROOT / "config" / "final_model_candidate_v3_1_xgb_refined.yaml"

SEED = 20260828
FEATURE_VARIANT = "V4"
EXPECTED_FEATURE_COUNT = 74
LABEL_TO_CODE = {label: idx for idx, label in enumerate(INCIDENT_LABELS)}
PROBABILITY_COLUMNS = ["p_hijack", "p_leak", "p_outage"]
REFERENCE_KEYS = ["incident_uid", "window_id", "fold"]

BASE_XGB_PARAMS: dict[str, Any] = {
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

EQUIVALENCE_CRITERIA = {
    "predicted_class_agreement_min": 1.0,
    "max_abs_probability_difference_max": 1e-6,
    "mean_abs_probability_difference_max": 1e-8,
    "median_abs_probability_difference_max": 1e-8,
    "per_class_probability_correlation_min": 0.999999999,
    "incident_macro_f1_abs_difference_max": 1e-8,
}


@dataclass(frozen=True)
class Candidate:
    candidate_id: str
    tree_method: str | None
    n_jobs: int
    rationale: str


CANDIDATES = [
    Candidate("hist_njobs_minus1", "hist", -1, "Matches src/bgp_incident_detection/k1_incident_stacking.py:first_level_model."),
    Candidate("hist_njobs_1", "hist", 1, "Same historical tree_method with single-thread deterministic execution."),
    Candidate("default_auto_njobs_minus1", None, -1, "Historically plausible XGBoost default when helper does not set tree_method."),
    Candidate("exact_njobs_1", "exact", 1, "Historically plausible CPU exact-tree fallback; tested only against fingerprint."),
    Candidate("approx_njobs_1", "approx", 1, "Historically plausible CPU approximate-tree fallback; tested only against fingerprint."),
]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def load_candidate_config() -> dict[str, Any]:
    with FINAL_CANDIDATE.open(encoding="utf-8") as handle:
        config = yaml.safe_load(handle)
    expected = config.get("selected_hyperparameters", {})
    if expected != BASE_XGB_PARAMS:
        raise ValueError(f"Locked XGBoost parameters disagree with recovered specification: {expected}")
    if int(config.get("feature_count")) != EXPECTED_FEATURE_COUNT:
        raise ValueError("Locked candidate does not declare the frozen 74-feature V4 schema.")
    return config


def load_train_frame() -> tuple[pd.DataFrame, list[str]]:
    _ = load_candidate_config()
    features = list(FEATURES_BY_VARIANT[FEATURE_VARIANT])
    if len(features) != EXPECTED_FEATURE_COUNT:
        raise ValueError(f"Expected {EXPECTED_FEATURE_COUNT} V4 features; got {len(features)}.")
    train = pd.read_parquet(TRAIN_V4)
    assignments = pd.read_csv(ASSIGNMENTS, low_memory=False)
    assignments = assignments[assignments["label"].isin(INCIDENT_LABELS)].copy()
    data = train.merge(
        assignments[["window_id", "label", "model_group_id", "fold"]],
        on="window_id",
        how="left",
        validate="one_to_one",
    )
    data = data[data["label"].isin(INCIDENT_LABELS)].copy()
    data["fold"] = data["fold"].astype(int)
    if set(data["partition"].astype(str)) != {"train"}:
        raise ValueError("Reconstruction must use TRAIN rows only.")
    if data["incident_uid"].nunique() != 993:
        raise ValueError("Expected exactly 993 TRAIN incidents.")
    incident_counts = data.drop_duplicates("incident_uid")["label"].value_counts().to_dict()
    if incident_counts != {"HIJACK": 331, "LEAK": 331, "OUTAGE": 331}:
        raise ValueError(f"Expected 331/331/331 TRAIN incident balance; got {incident_counts}.")
    if data.groupby("incident_uid")["fold"].nunique().max() != 1:
        raise ValueError("Grouped fold violation: an incident crosses folds.")
    missing = [feature for feature in features if feature not in data.columns]
    if missing:
        raise ValueError(f"Missing V4 feature columns: {missing}")
    return data, features


def y_codes(labels: pd.Series) -> np.ndarray:
    return labels.map(LABEL_TO_CODE).astype(int).to_numpy()


def model_for_candidate(candidate: Candidate) -> Pipeline:
    model_params = {
        **BASE_XGB_PARAMS,
        "objective": "multi:softprob",
        "num_class": 3,
        "eval_metric": "mlogloss",
        "random_state": SEED,
        "seed": SEED,
        "n_jobs": candidate.n_jobs,
        "verbosity": 0,
    }
    if candidate.tree_method is not None:
        model_params["tree_method"] = candidate.tree_method
    return Pipeline(
        [
            ("imputer", SimpleImputer(strategy="median")),
            ("model", XGBClassifier(**model_params)),
        ]
    )


def reconstruct_candidate(data: pd.DataFrame, features: list[str], candidate: Candidate) -> tuple[pd.DataFrame, dict[int, Pipeline]]:
    frames = []
    models = {}
    for fold in sorted(data["fold"].unique()):
        print(f"Reconstructing candidate={candidate.candidate_id} fold={fold}", flush=True)
        train = data[data["fold"] != fold].copy()
        test = data[data["fold"] == fold].copy()
        model = model_for_candidate(candidate)
        model.fit(train[features], y_codes(train["label"]), model__sample_weight=group_aware_weights(train))
        probs = model.predict_proba(test[features])
        frame = test[["incident_uid", "window_id", "fold", "label"]].copy()
        frame["true_class"] = frame.pop("label")
        frame["p_hijack_reconstructed"] = probs[:, 0]
        frame["p_leak_reconstructed"] = probs[:, 1]
        frame["p_outage_reconstructed"] = probs[:, 2]
        frames.append(frame)
        models[int(fold)] = model
        print(f"Compared candidate={candidate.candidate_id} fold={fold} heldout_rows={len(test)}", flush=True)
    return pd.concat(frames, ignore_index=True), models


def compare_to_reference(reconstructed: pd.DataFrame, reference: pd.DataFrame, candidate: Candidate) -> dict[str, Any]:
    ref = reference[REFERENCE_KEYS + ["true_class"] + PROBABILITY_COLUMNS].copy()
    merged = ref.merge(reconstructed, on=REFERENCE_KEYS + ["true_class"], how="inner", validate="one_to_one")
    if len(merged) != len(reference) or len(merged) != len(reconstructed):
        raise ValueError(f"Fingerprint comparison row mismatch for {candidate.candidate_id}.")

    ref_probs = merged[PROBABILITY_COLUMNS].to_numpy()
    rec_probs = merged[["p_hijack_reconstructed", "p_leak_reconstructed", "p_outage_reconstructed"]].to_numpy()
    abs_diff = np.abs(ref_probs - rec_probs)
    ref_pred = ref_probs.argmax(axis=1)
    rec_pred = rec_probs.argmax(axis=1)
    labels = y_codes(merged["true_class"])
    correlations: dict[str, float] = {}
    for ref_col, rec_col in zip(PROBABILITY_COLUMNS, ["p_hijack_reconstructed", "p_leak_reconstructed", "p_outage_reconstructed"]):
        if merged[ref_col].nunique() <= 1 or merged[rec_col].nunique() <= 1:
            correlations[ref_col] = float("nan")
        else:
            correlations[ref_col] = float(np.corrcoef(merged[ref_col], merged[rec_col])[0, 1])
    ref_f1 = float(f1_score(labels, ref_pred, average="macro"))
    rec_f1 = float(f1_score(labels, rec_pred, average="macro"))
    class_agreement = float((ref_pred == rec_pred).mean())
    min_corr = min(v for v in correlations.values() if not np.isnan(v))
    passes = (
        class_agreement >= EQUIVALENCE_CRITERIA["predicted_class_agreement_min"]
        and float(abs_diff.max()) <= EQUIVALENCE_CRITERIA["max_abs_probability_difference_max"]
        and float(abs_diff.mean()) <= EQUIVALENCE_CRITERIA["mean_abs_probability_difference_max"]
        and float(np.median(abs_diff)) <= EQUIVALENCE_CRITERIA["median_abs_probability_difference_max"]
        and min_corr >= EQUIVALENCE_CRITERIA["per_class_probability_correlation_min"]
        and abs(ref_f1 - rec_f1) <= EQUIVALENCE_CRITERIA["incident_macro_f1_abs_difference_max"]
    )
    return {
        "candidate_id": candidate.candidate_id,
        "tree_method": candidate.tree_method or "XGBOOST_DEFAULT",
        "n_jobs": candidate.n_jobs,
        "predictions_compared": len(merged),
        "predicted_class_agreement": class_agreement,
        "max_abs_probability_difference": float(abs_diff.max()),
        "mean_abs_probability_difference": float(abs_diff.mean()),
        "median_abs_probability_difference": float(np.median(abs_diff)),
        "p_hijack_correlation": correlations["p_hijack"],
        "p_leak_correlation": correlations["p_leak"],
        "p_outage_correlation": correlations["p_outage"],
        "reference_window_macro_f1": ref_f1,
        "reconstructed_window_macro_f1": rec_f1,
        "window_macro_f1_difference": rec_f1 - ref_f1,
        "equivalence_status": "PASS" if passes else "FAIL",
        "selection_basis": "probability fingerprint only; no outcome-based tuning or TTI scoring",
    }


def write_equivalence_criteria() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Level-1 Equivalence Criteria v2",
        "",
        "These tolerances were fixed before computing the final reconstruction comparison.",
        "",
        "| Criterion | Tolerance |",
        "|---|---:|",
    ]
    for key, value in EQUIVALENCE_CRITERIA.items():
        lines.append(f"| `{key}` | `{value}` |")
    lines.extend(
        [
            "",
            "Primary equivalence evidence is probability-level reproduction against preserved TRAIN OOF fingerprints.",
            "Similar aggregate Macro F1 alone is not sufficient for acceptance.",
            "The reconstruction may serialize models only after one candidate passes these criteria.",
        ]
    )
    (OUT_DIR / "level1_equivalence_criteria_v2.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def environment_rows(selected_tree_method: str | None = None) -> list[dict[str, Any]]:
    return [
        {"item": "python_version", "value": sys.version.replace("\n", " "), "source": "runtime"},
        {"item": "python_executable", "value": sys.executable, "source": "runtime"},
        {"item": "platform", "value": platform.platform(), "source": "runtime"},
        {"item": "xgboost_version", "value": xgboost.__version__, "source": "runtime/config"},
        {"item": "sklearn_version", "value": sklearn.__version__, "source": "runtime"},
        {"item": "numpy_version", "value": np.__version__, "source": "runtime"},
        {"item": "pandas_version", "value": pd.__version__, "source": "runtime"},
        {"item": "tree_method_selected", "value": selected_tree_method or "UNSELECTED_AT_START", "source": "fingerprint_equivalence"},
        {"item": "random_seed", "value": SEED, "source": "config/final_model_candidate_v3_1_xgb_refined.yaml"},
        {"item": "feature_count", "value": EXPECTED_FEATURE_COUNT, "source": "config/feature_variants_v1.yaml"},
        {"item": "class_order", "value": json.dumps(INCIDENT_LABELS), "source": "src/bgp_incident_detection/model_baselines.py"},
    ]


def serialize_models(models: dict[int, Pipeline], selected: Candidate, data: pd.DataFrame, features: list[str]) -> dict[str, str]:
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    checksums: dict[str, str] = {}
    schema_path = MODEL_DIR / "feature_schema_v4.json"
    schema_path.write_text(json.dumps(features, indent=2) + "\n", encoding="utf-8")
    checksums[str(schema_path)] = sha256_file(schema_path)

    for fold, model in sorted(models.items()):
        path = MODEL_DIR / f"level1_xgb_fold_{fold}_{selected.candidate_id}.joblib"
        joblib.dump(model, path, compress=3)
        checksums[str(path)] = sha256_file(path)
        meta = {
            "fold": fold,
            "candidate_id": selected.candidate_id,
            "tree_method": selected.tree_method or "XGBOOST_DEFAULT",
            "n_jobs": selected.n_jobs,
            "seed": SEED,
            "training_incident_count": int(data.loc[data["fold"] != fold, "incident_uid"].nunique()),
            "heldout_incident_count": int(data.loc[data["fold"] == fold, "incident_uid"].nunique()),
            "train_dataset_sha256": sha256_file(TRAIN_V4),
            "assignment_sha256": sha256_file(ASSIGNMENTS),
            "feature_schema_path": str(schema_path),
            "hyperparameters": BASE_XGB_PARAMS,
            "environment": {row["item"]: row["value"] for row in environment_rows(selected.tree_method or "XGBOOST_DEFAULT")},
            "model_sha256": checksums[str(path)],
        }
        meta_path = MODEL_DIR / f"level1_xgb_fold_{fold}_{selected.candidate_id}.metadata.json"
        meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        checksums[str(meta_path)] = sha256_file(meta_path)

    checksum_path = MODEL_DIR / "sha256_checksums.json"
    checksum_path.write_text(json.dumps(checksums, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return checksums


def write_ensemble_manifest(selected: Candidate, checksums: dict[str, str] | None, status: str) -> None:
    manifest = {
        "manifest_id": "level1_ensemble_manifest_v2",
        "status": status,
        "model_family": "five-model cross-fit XGBoost Level-1 ensemble",
        "candidate_id": selected.candidate_id if selected else None,
        "tree_method": (selected.tree_method or "XGBOOST_DEFAULT") if selected else None,
        "random_seed": SEED,
        "class_order": INCIDENT_LABELS,
        "feature_schema": "V4 74-feature Behavioral + CAIDA + RPKI/ROV frozen order",
        "inference_combination_rule": "arithmetic mean of class probabilities across the five fold-specific Level-1 models",
        "model_directory": str(MODEL_DIR) if checksums else None,
        "checksums": checksums or {},
        "validation_accessed": False,
        "final_holdout_accessed": False,
        "tti_scored": False,
        "source_commit": source_commit(),
    }
    (OUT_DIR / "level1_ensemble_manifest_v2.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_execution_docs(selected: Candidate | None, disposition: str, comparisons: list[dict[str, Any]]) -> None:
    best_text = "No candidate passed equivalence."
    if selected is not None:
        best_text = f"Selected `{selected.candidate_id}` using probability-fingerprint equivalence only."
    execution = [
        "# Level-1 Reconstruction Execution v2",
        "",
        "Scope: TRAIN-only reconstruction and probability-fingerprint verification.",
        "",
        "- Validation accessed/recomputed: NO",
        "- Final Holdout accessed/recomputed: NO",
        "- TTI scoring performed: NO",
        "- Hyperparameter tuning/search performed: NO",
        "- Frozen primary Praxis artifacts modified: NO",
        "",
        "Historically plausible candidates were reconstructed only to resolve the `tree_method` ambiguity. Selection used preserved TRAIN probability fingerprints, not Macro F1 or TTI performance.",
        "",
        best_text,
        "",
        f"Disposition: `{disposition}`",
    ]
    (OUT_DIR / "level1_reconstruction_execution_v2.md").write_text("\n".join(execution) + "\n", encoding="utf-8")

    verification = [
        "# Level-1 Reconstruction Verification v2",
        "",
        "The preserved reference fingerprint is `data/modeling_k1/k1_window_oof_probabilities_v1.parquet`.",
        "One compared row represents one TRAIN five-minute window with preserved OOF Level-1 probabilities.",
        "",
        f"Candidates evaluated: {len(comparisons)}",
        f"Passing candidates: {sum(1 for row in comparisons if row['equivalence_status'] == 'PASS')}",
        "",
        "If more than one candidate passed, the historically documented K1 helper implementation is preferred while recording numerical equivalence.",
        "",
        f"Disposition: `{disposition}`",
    ]
    (OUT_DIR / "level1_reconstruction_verification_v2.md").write_text("\n".join(verification) + "\n", encoding="utf-8")


def run(candidate_ids: set[str] | None = None) -> str:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write_equivalence_criteria()
    data, features = load_train_frame()
    reference = pd.read_parquet(REFERENCE_OOF)
    if len(reference) != len(data):
        raise ValueError("Reference OOF fingerprint row count does not match TRAIN V4 row count.")

    candidate_rows = []
    comparison_rows = []
    model_cache: dict[str, dict[int, Pipeline]] = {}
    selected_candidates = [candidate for candidate in CANDIDATES if candidate_ids is None or candidate.candidate_id in candidate_ids]
    if not selected_candidates:
        raise ValueError(f"No reconstruction candidates matched {sorted(candidate_ids or [])}")

    for candidate in selected_candidates:
        reconstructed, models = reconstruct_candidate(data, features, candidate)
        comparison = compare_to_reference(reconstructed, reference, candidate)
        comparison_rows.append(comparison)
        model_cache[candidate.candidate_id] = models
        candidate_rows.append(
            {
                "candidate_id": candidate.candidate_id,
                "tree_method": candidate.tree_method or "XGBOOST_DEFAULT",
                "n_jobs": candidate.n_jobs,
                "rationale": candidate.rationale,
                "status": comparison["equivalence_status"],
            }
        )

    write_csv(OUT_DIR / "level1_reconstruction_candidates_v2.csv", candidate_rows)
    write_csv(OUT_DIR / "level1_probability_equivalence_v2.csv", comparison_rows)

    passing = [row for row in comparison_rows if row["equivalence_status"] == "PASS"]
    selected_candidate = None
    checksums = None
    if passing:
        preferred_order = {candidate.candidate_id: idx for idx, candidate in enumerate(CANDIDATES)}
        passing = sorted(passing, key=lambda row: preferred_order[row["candidate_id"]])
        selected_candidate = next(candidate for candidate in CANDIDATES if candidate.candidate_id == passing[0]["candidate_id"])
        checksums = serialize_models(model_cache[selected_candidate.candidate_id], selected_candidate, data, features)
        disposition = "RECONSTRUCTED_LEVEL1_EQUIVALENCE_PASS"
    else:
        disposition = "RECONSTRUCTED_LEVEL1_EQUIVALENCE_FAIL"

    write_csv(OUT_DIR / "level1_environment_manifest_v2.csv", environment_rows((selected_candidate.tree_method or "XGBOOST_DEFAULT") if selected_candidate else None))
    write_ensemble_manifest(selected_candidate, checksums, disposition)
    write_execution_docs(selected_candidate, disposition, comparison_rows)
    return disposition


def main() -> None:
    parser = argparse.ArgumentParser(description="Reconstruct TRAIN-only Level-1 XGBoost ensemble and verify probability equivalence.")
    parser.add_argument(
        "--candidate",
        action="append",
        dest="candidates",
        help="Candidate ID to run. May be supplied multiple times. Defaults to all candidates.",
    )
    args = parser.parse_args()
    print(run(set(args.candidates) if args.candidates else None))


if __name__ == "__main__":
    main()
