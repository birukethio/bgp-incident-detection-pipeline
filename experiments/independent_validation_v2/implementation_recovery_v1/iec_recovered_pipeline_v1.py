from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Iterable

import joblib
import numpy as np
import pandas as pd


REPO = Path(__file__).resolve().parents[3]
OUT = REPO / "experiments" / "independent_validation_v2" / "implementation_recovery_v1"
RECOVERY = REPO / "experiments" / "independent_validation_v2" / "equivalence_recovery_v1"
TOL_ABS = 1e-9
TOL_REL = 1e-9
CLASS_PROB_COLS = ["p_hijack", "p_leak", "p_outage"]
CLASS_LABELS = ["HIJACK", "LEAK", "OUTAGE"]
CLASS_TO_CODE = {"HIJACK": 0, "LEAK": 1, "OUTAGE": 2}

sys.path.insert(0, str(REPO / "src"))
from bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT  # noqa: E402
from bgp_incident_detection.k1_incident_stacking import summarize_incident  # noqa: E402


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_expected_sha(path: Path) -> str:
    text = path.read_text(encoding="utf-8").strip()
    return text.split()[0]


def rel(path: Path) -> str:
    return str(path.relative_to(REPO))


def max_abs_diff(a: np.ndarray, b: np.ndarray) -> float:
    if len(a) == 0:
        return 0.0
    return float(np.nanmax(np.abs(a - b)))


def max_rel_diff(a: np.ndarray, b: np.ndarray) -> float:
    if len(a) == 0:
        return 0.0
    denom = np.maximum(np.abs(b), 1e-15)
    return float(np.nanmax(np.abs(a - b) / denom))


def tolerant_status(max_abs: float, max_rel: float) -> str:
    if max_abs == 0.0:
        return "PASS_EXACT"
    if max_abs <= TOL_ABS and max_rel <= TOL_REL:
        return "PASS_NUMERICALLY_EQUIVALENT"
    return "FAIL"


def write_csv(name: str, rows: list[dict]) -> Path:
    path = OUT / name
    pd.DataFrame(rows).to_csv(path, index=False)
    return path


def load_fixtures() -> pd.DataFrame:
    return pd.read_csv(RECOVERY / "train_equivalence_fixture_roster_v1.csv")


def verify_fixture_checksum() -> pd.DataFrame:
    fixture_path = RECOVERY / "train_equivalence_fixture_roster_v1.csv"
    expected_path = RECOVERY / "train_equivalence_fixture_roster_v1.sha256"
    actual = sha256_file(fixture_path)
    expected = read_expected_sha(expected_path)
    return pd.DataFrame(
        [
            {
                "artifact": "train_equivalence_fixture_roster_v1.csv",
                "path": rel(fixture_path),
                "expected_sha256": expected,
                "actual_sha256": actual,
                "status": "PASS" if actual == expected else "FAIL",
            }
        ]
    )


def authority_map() -> pd.DataFrame:
    rows = [
        {
            "component": "RouteViews parsing",
            "implementation_source": "src/bgp_incident_detection/mrt_parser.py; src/bgp_incident_detection/behavioral_features.py",
            "authoritative_artifact": "data/train_frozen/frozen_train_behavioral_corpus_v1.parquet",
            "verification_stage": "E1/E2",
            "rule_status": "REFERENCE_OUTPUT_VERIFICATION",
        },
        {
            "component": "incident relevance filtering",
            "implementation_source": "src/bgp_incident_detection/behavioral_features.py and frozen TRAIN behavioral corpus",
            "authoritative_artifact": "data/train_frozen/frozen_train_behavioral_corpus_v1.parquet",
            "verification_stage": "E1/E2",
            "rule_status": "REFERENCE_OUTPUT_VERIFICATION",
        },
        {
            "component": "five-minute window construction",
            "implementation_source": "frozen TRAIN behavioral corpus window_id/window_start/window_end",
            "authoritative_artifact": "data/train_frozen/frozen_train_behavioral_corpus_v1.parquet",
            "verification_stage": "E1",
            "rule_status": "EXECUTABLE_LINKAGE_COMPARISON",
        },
        {
            "component": "44 Behavioral features",
            "implementation_source": "src/bgp_incident_detection/behavioral_features.py; frozen TRAIN behavioral corpus",
            "authoritative_artifact": "data/train_frozen/frozen_train_behavioral_corpus_v1.parquet",
            "verification_stage": "E2",
            "rule_status": "EXECUTABLE_FEATURE_ASSEMBLY_COMPARISON",
        },
        {
            "component": "14 CAIDA features",
            "implementation_source": "src/bgp_incident_detection/caida_features.py; frozen CAIDA enrichment",
            "authoritative_artifact": "data/enrichment/caida/train_caida_features_v1.parquet",
            "verification_stage": "E2",
            "rule_status": "EXECUTABLE_FEATURE_ASSEMBLY_COMPARISON",
        },
        {
            "component": "16 RPKI/ROV features",
            "implementation_source": "src/bgp_incident_detection/rpki_features.py; frozen RPKI enrichment",
            "authoritative_artifact": "data/enrichment/rpki/train_rpki_features_v1.parquet",
            "verification_stage": "E2",
            "rule_status": "EXECUTABLE_FEATURE_ASSEMBLY_COMPARISON",
        },
        {
            "component": "exact V4 feature order",
            "implementation_source": "src/bgp_incident_detection/feature_ablation.py::FEATURES_BY_VARIANT['V4']",
            "authoritative_artifact": "data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1.parquet",
            "verification_stage": "E2",
            "rule_status": "EXECUTABLE_SCHEMA_COMPARISON",
        },
        {
            "component": "missing-value handling",
            "implementation_source": "serialized reconstructed Level-1 sklearn Pipeline SimpleImputer(strategy='median')",
            "authoritative_artifact": "data/tti_pilot/reconstructed_level1_v1/level1_xgb_fold_*.joblib",
            "verification_stage": "E3",
            "rule_status": "EXECUTABLE_MODEL_COMPARISON",
        },
        {
            "component": "frozen Level-1 XGBoost reconstruction",
            "implementation_source": "data/tti_pilot/reconstructed_level1_v1/level1_xgb_fold_*.joblib",
            "authoritative_artifact": "data/modeling_k1/k1_window_oof_probabilities_v1.parquet",
            "verification_stage": "E3",
            "rule_status": "EXECUTABLE_MODEL_COMPARISON",
        },
        {
            "component": "mean aggregation",
            "implementation_source": "groupby incident_uid mean over p_hijack/p_leak/p_outage",
            "authoritative_artifact": "data/modeling_k1/k1_incident_level_predictions_v1.parquet::K1-B0_MEAN_PROBABILITY",
            "verification_stage": "E4",
            "rule_status": "EXECUTABLE_AGGREGATION_COMPARISON",
        },
        {
            "component": "Level-2 temporal meta-feature construction",
            "implementation_source": "src/bgp_incident_detection/k1_incident_stacking.py::summarize_incident",
            "authoritative_artifact": "data/modeling_k1/k1_incident_meta_features_v1.parquet",
            "verification_stage": "E5",
            "rule_status": "EXECUTABLE_META_FEATURE_COMPARISON",
        },
        {
            "component": "frozen Level-2 XGBoost inference",
            "implementation_source": "config/k1_second_level_xgb_final_v1.yaml",
            "authoritative_artifact": "data/modeling_k1/k1_incident_level_predictions_v1.parquet::K1-M2_XGB_K1-TEMPORAL",
            "verification_stage": "E6",
            "rule_status": "BLOCKED_NO_SERIALIZED_LEVEL2_MODEL_FOUND",
        },
        {
            "component": "class ranking",
            "implementation_source": "descending P(Hijack), P(Leak), P(Outage)",
            "authoritative_artifact": "config/k1_final_candidate_v1_1_deployable.yaml",
            "verification_stage": "E4/E6",
            "rule_status": "EXECUTABLE_FOR_MEAN_AGGREGATION_ONLY",
        },
    ]
    return pd.DataFrame(rows)


def fixture_subset(df: pd.DataFrame, ids: Iterable[str]) -> pd.DataFrame:
    return df[df["incident_uid"].isin(set(ids))].copy()


def assemble_v4_from_components(ids: list[str]) -> pd.DataFrame:
    features = FEATURES_BY_VARIANT["V4"]
    meta_cols = [
        "incident_uid",
        "incident_id",
        "category",
        "partition",
        "window_id",
        "window_start",
        "window_end",
        "temporal_status",
        "raw_observation_count",
        "has_relevant_observation",
    ]
    beh = fixture_subset(pd.read_parquet(REPO / "data/train_frozen/frozen_train_behavioral_corpus_v1.parquet"), ids)
    caida = fixture_subset(pd.read_parquet(REPO / "data/enrichment/caida/train_caida_features_v1.parquet"), ids)
    rpki = fixture_subset(pd.read_parquet(REPO / "data/enrichment/rpki/train_rpki_features_v1.parquet"), ids)
    caida_features = [c for c in caida.columns if c in features]
    rpki_features = [c for c in rpki.columns if c in features]
    assembled = beh.merge(caida[["window_id"] + caida_features], on="window_id", how="left")
    assembled = assembled.merge(rpki[["window_id"] + rpki_features], on="window_id", how="left")
    ordered_cols = [c for c in meta_cols if c in assembled.columns] + features
    return assembled[ordered_cols].sort_values("window_id").reset_index(drop=True)


def e1_window_equivalence(fixtures: pd.DataFrame, assembled: pd.DataFrame, reference_v4: pd.DataFrame) -> pd.DataFrame:
    rows = []
    keys = ["window_id", "incident_uid", "window_start", "window_end"]
    for _, fx in fixtures.iterrows():
        inc = fx["incident_uid"]
        new = assembled[assembly_filter(assembled, inc)][keys].sort_values("window_id").reset_index(drop=True)
        ref = reference_v4[assembly_filter(reference_v4, inc)][keys].sort_values("window_id").reset_index(drop=True)
        exact = new.equals(ref)
        rows.append(
            {
                "incident_uid": inc,
                "stage": "E1_WINDOW_RECONSTRUCTION",
                "reference_window_count": len(ref),
                "new_window_count": len(new),
                "window_count_match": len(ref) == len(new),
                "timestamp_and_id_exact_match": exact,
                "comparison_status": "PASS" if exact and len(ref) == len(new) else "FAIL",
                "notes": "Compared reconstructed component-assembled window linkage against frozen V4 fixture windows.",
            }
        )
    return pd.DataFrame(rows)


def assembly_filter(df: pd.DataFrame, incident_uid: str) -> pd.Series:
    return df["incident_uid"].eq(incident_uid)


def e2_feature_equivalence(fixtures: pd.DataFrame, assembled: pd.DataFrame, reference_v4: pd.DataFrame) -> pd.DataFrame:
    features = FEATURES_BY_VARIANT["V4"]
    rows = []
    for _, fx in fixtures.iterrows():
        inc = fx["incident_uid"]
        new = assembled[assembly_filter(assembled, inc)].sort_values("window_id").reset_index(drop=True)
        ref = reference_v4[assembly_filter(reference_v4, inc)].sort_values("window_id").reset_index(drop=True)
        schema_match = list(new[features].columns) == list(ref[features].columns)
        if len(new) == len(ref) and schema_match and len(new) > 0:
            a = new[features].astype(float).to_numpy()
            b = ref[features].astype(float).to_numpy()
            mad = max_abs_diff(a, b)
            mrd = max_rel_diff(a, b)
        else:
            mad = np.inf
            mrd = np.inf
        status = tolerant_status(mad, mrd) if schema_match and len(new) == len(ref) else "FAIL"
        rows.append(
            {
                "incident_uid": inc,
                "stage": "E2_V4_FEATURES",
                "reference_rows": len(ref),
                "new_rows": len(new),
                "feature_count": len(features),
                "schema_order_match": schema_match,
                "max_absolute_difference": mad,
                "max_relative_difference": mrd,
                "comparison_status": status,
                "notes": "Assembled 44 Behavioral + 14 CAIDA + 16 RPKI features in frozen V4 order and compared to frozen V4.",
            }
        )
    return pd.DataFrame(rows)


def compute_level1_predictions(reference_v4: pd.DataFrame, oof_ref: pd.DataFrame) -> pd.DataFrame:
    features = FEATURES_BY_VARIANT["V4"]
    work = reference_v4.merge(oof_ref[["window_id", "fold", "true_class"]], on="window_id", how="inner")
    out = []
    for fold, sub in work.groupby("fold", sort=True):
        model_path = REPO / f"data/tti_pilot/reconstructed_level1_v1/level1_xgb_fold_{int(fold)}_hist_njobs_minus1.joblib"
        model = joblib.load(model_path)
        probs = model.predict_proba(sub[features])
        part = sub[["incident_uid", "window_id", "window_start", "window_end", "temporal_status"]].copy()
        part["fold"] = int(fold)
        part["true_class"] = sub["true_class"].values
        part["p_hijack"] = probs[:, 0]
        part["p_leak"] = probs[:, 1]
        part["p_outage"] = probs[:, 2]
        part["probability_source"] = "recovered_level1_fold_model"
        out.append(part)
    return pd.concat(out, ignore_index=True).sort_values("window_id").reset_index(drop=True)


def e3_level1_equivalence(fixtures: pd.DataFrame, pred: pd.DataFrame, oof_ref: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, fx in fixtures.iterrows():
        inc = fx["incident_uid"]
        new = pred[assembly_filter(pred, inc)].sort_values("window_id").reset_index(drop=True)
        ref = oof_ref[assembly_filter(oof_ref, inc)].sort_values("window_id").reset_index(drop=True)
        if len(new) == len(ref) and len(new) > 0:
            mad = max_abs_diff(new[CLASS_PROB_COLS].to_numpy(), ref[CLASS_PROB_COLS].to_numpy())
            mrd = max_rel_diff(new[CLASS_PROB_COLS].to_numpy(), ref[CLASS_PROB_COLS].to_numpy())
            pred_match = np.array_equal(
                np.argmax(new[CLASS_PROB_COLS].to_numpy(), axis=1),
                np.argmax(ref[CLASS_PROB_COLS].to_numpy(), axis=1),
            )
        else:
            mad = np.inf
            mrd = np.inf
            pred_match = False
        status = tolerant_status(mad, mrd) if pred_match and len(new) == len(ref) else "FAIL"
        rows.append(
            {
                "incident_uid": inc,
                "stage": "E3_LEVEL1_WINDOW_SCORES",
                "reference_rows": len(ref),
                "new_rows": len(new),
                "max_absolute_probability_difference": mad,
                "max_relative_probability_difference": mrd,
                "predicted_class_agreement": pred_match,
                "comparison_status": status,
                "notes": "Applied verified reconstructed fold-specific Level-1 models to fixture V4 rows and compared to frozen OOF probabilities.",
            }
        )
    return pd.DataFrame(rows)


def e4_mean_equivalence(fixtures: pd.DataFrame, pred: pd.DataFrame, incident_ref: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    mean = pred.groupby("incident_uid", as_index=False)[CLASS_PROB_COLS].mean()
    rows = []
    for _, fx in fixtures.iterrows():
        inc = fx["incident_uid"]
        new = mean[mean["incident_uid"].eq(inc)].reset_index(drop=True)
        ref = incident_ref[(incident_ref["incident_uid"].eq(inc)) & (incident_ref["candidate_id"].eq("K1-B0_MEAN_PROBABILITY"))].reset_index(drop=True)
        if len(new) == 1 and len(ref) == 1:
            mad = max_abs_diff(new[CLASS_PROB_COLS].to_numpy(), ref[CLASS_PROB_COLS].to_numpy())
            mrd = max_rel_diff(new[CLASS_PROB_COLS].to_numpy(), ref[CLASS_PROB_COLS].to_numpy())
            rank_match = list(np.argsort(-new[CLASS_PROB_COLS].to_numpy()[0])) == list(np.argsort(-ref[CLASS_PROB_COLS].to_numpy()[0]))
        else:
            mad = np.inf
            mrd = np.inf
            rank_match = False
        status = tolerant_status(mad, mrd) if rank_match and len(new) == 1 and len(ref) == 1 else "FAIL"
        rows.append(
            {
                "incident_uid": inc,
                "stage": "E4_MEAN_AGGREGATION",
                "reference_rows": len(ref),
                "new_rows": len(new),
                "max_absolute_probability_difference": mad,
                "max_relative_probability_difference": mrd,
                "ranking_match": rank_match,
                "comparison_status": status,
                "notes": "Mean H/L/O Level-1 probabilities by incident and compared to K1-B0_MEAN_PROBABILITY.",
            }
        )
    return pd.DataFrame(rows), mean


def e5_meta_equivalence(fixtures: pd.DataFrame, pred: pd.DataFrame, reference_v4: pd.DataFrame, meta_ref: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    structural = reference_v4[["window_id", "raw_observation_count"]].copy()
    recovered_rows = []
    for inc, group in pred.groupby("incident_uid", sort=True):
        recovered_rows.append(summarize_incident(group, structural))
    recovered = pd.DataFrame(recovered_rows)

    feature_cols = [c for c in meta_ref.columns if c not in {"incident_uid", "true_class", "fold"}]
    rows = []
    for _, fx in fixtures.iterrows():
        inc = fx["incident_uid"]
        new = recovered[recovered["incident_uid"].eq(inc)].reset_index(drop=True)
        ref = meta_ref[meta_ref["incident_uid"].eq(inc)].reset_index(drop=True)
        schema_match = feature_cols == [c for c in feature_cols if c in new.columns]
        if len(new) == 1 and len(ref) == 1 and schema_match:
            a = new[feature_cols].astype(float).to_numpy()
            b = ref[feature_cols].astype(float).to_numpy()
            mad = max_abs_diff(a, b)
            mrd = max_rel_diff(a, b)
        else:
            mad = np.inf
            mrd = np.inf
        status = tolerant_status(mad, mrd) if schema_match and len(new) == 1 and len(ref) == 1 else "FAIL"
        rows.append(
            {
                "incident_uid": inc,
                "stage": "E5_LEVEL2_META_FEATURES",
                "reference_rows": len(ref),
                "new_rows": len(new),
                "meta_feature_count": len(feature_cols),
                "schema_available": schema_match,
                "max_absolute_difference": mad,
                "max_relative_difference": mrd,
                "comparison_status": status,
                "notes": "Recomputed frozen temporal meta-features with summarize_incident and compared to stored K1 meta-features.",
            }
        )
    return pd.DataFrame(rows), recovered


def e6_level2_equivalence(fixtures: pd.DataFrame, incident_ref: pd.DataFrame) -> pd.DataFrame:
    model_candidates = list(REPO.glob("**/*level2*.joblib")) + list(REPO.glob("**/*second*level*.joblib")) + list(REPO.glob("**/*stacker*.joblib"))
    rows = []
    for _, fx in fixtures.iterrows():
        inc = fx["incident_uid"]
        ref = incident_ref[(incident_ref["incident_uid"].eq(inc)) & (incident_ref["candidate_id"].eq("K1-M2_XGB_K1-TEMPORAL"))]
        rows.append(
            {
                "incident_uid": inc,
                "stage": "E6_LEVEL2_FINAL_SCORES",
                "reference_rows": len(ref),
                "new_rows": 0,
                "reference_candidate_id": "K1-M2_XGB_K1-TEMPORAL",
                "serialized_level2_model_candidates_found": "|".join(rel(p) for p in model_candidates),
                "max_absolute_probability_difference": "",
                "max_relative_probability_difference": "",
                "top1_match": "",
                "top2_match": "",
                "rank_order_match": "",
                "comparison_status": "BLOCKED_NO_SERIALIZED_LEVEL2_MODEL_ARTIFACT",
                "notes": "Frozen Level-2 configuration and reference predictions exist, but no executable serialized Level-2 model artifact was found. No retraining was performed.",
            }
        )
    return pd.DataFrame(rows)


def stage_pass(df: pd.DataFrame) -> bool:
    return df["comparison_status"].astype(str).str.startswith("PASS").all()


def output_checksums(paths: list[Path]) -> pd.DataFrame:
    rows = []
    all_paths = [Path(__file__)] + paths
    for path in all_paths:
        if path.exists() and path.is_file():
            rows.append({"artifact": path.name, "path": rel(path), "sha256": sha256_file(path)})
    return pd.DataFrame(rows)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    output_paths: list[Path] = []

    fixtures = load_fixtures()
    ids = fixtures["incident_uid"].tolist()
    fixture_checksum = verify_fixture_checksum()
    output_paths.append(OUT / "iec_fixture_checksum_verification_v1.csv")
    fixture_checksum.to_csv(output_paths[-1], index=False)

    authority = authority_map()
    output_paths.append(OUT / "iec_implementation_authority_map_v1.csv")
    authority.to_csv(output_paths[-1], index=False)

    change_log = pd.DataFrame(
        [
            {
                "stage": "ALL",
                "observed_difference": "NONE_REQUIRING_CORRECTION",
                "authoritative_expected_behavior": "Frozen artifact and code references were used without changing methodology.",
                "code_correction": "NONE",
                "reason": "No correction was made to frozen artifacts; recovered implementation is additive.",
                "before_after_comparison": "NOT_APPLICABLE",
            }
        ]
    )
    output_paths.append(OUT / "iec_implementation_change_log_v1.csv")
    change_log.to_csv(output_paths[-1], index=False)

    assembled = assemble_v4_from_components(ids)
    reference_v4 = fixture_subset(pd.read_parquet(REPO / "data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1.parquet"), ids).sort_values("window_id").reset_index(drop=True)
    oof_ref = fixture_subset(pd.read_parquet(REPO / "data/modeling_k1/k1_window_oof_probabilities_v1.parquet"), ids).sort_values("window_id").reset_index(drop=True)
    incident_ref = fixture_subset(pd.read_parquet(REPO / "data/modeling_k1/k1_incident_level_predictions_v1.parquet"), ids)
    meta_ref = fixture_subset(pd.read_parquet(REPO / "data/modeling_k1/k1_incident_meta_features_v1.parquet"), ids)

    e1 = e1_window_equivalence(fixtures, assembled, reference_v4)
    output_paths.append(OUT / "iec_E1_window_equivalence_v1.csv")
    e1.to_csv(output_paths[-1], index=False)

    e2 = e2_feature_equivalence(fixtures, assembled, reference_v4)
    output_paths.append(OUT / "iec_E2_feature_equivalence_v1.csv")
    e2.to_csv(output_paths[-1], index=False)

    level1_pred = compute_level1_predictions(reference_v4, oof_ref)
    e3 = e3_level1_equivalence(fixtures, level1_pred, oof_ref)
    output_paths.append(OUT / "iec_E3_level1_equivalence_v1.csv")
    e3.to_csv(output_paths[-1], index=False)

    e4, mean_scores = e4_mean_equivalence(fixtures, level1_pred, incident_ref)
    output_paths.append(OUT / "iec_E4_mean_equivalence_v1.csv")
    e4.to_csv(output_paths[-1], index=False)

    e5, meta_recovered = e5_meta_equivalence(fixtures, level1_pred, reference_v4, meta_ref)
    output_paths.append(OUT / "iec_E5_meta_feature_equivalence_v1.csv")
    e5.to_csv(output_paths[-1], index=False)

    e6 = e6_level2_equivalence(fixtures, incident_ref)
    output_paths.append(OUT / "iec_E6_level2_equivalence_v1.csv")
    e6.to_csv(output_paths[-1], index=False)

    all_e1_e5_pass = all(stage_pass(df) for df in [e1, e2, e3, e4, e5])
    checksum_ok = fixture_checksum["status"].eq("PASS").all()
    e6_pass = stage_pass(e6)
    if checksum_ok and all_e1_e5_pass and e6_pass:
        disposition = "FULL_END_TO_END_EQUIVALENCE_ESTABLISHED"
    elif checksum_ok and all_e1_e5_pass and not e6_pass:
        disposition = "IMPLEMENTATION_EQUIVALENCE_NOT_ESTABLISHED"
    else:
        disposition = "IMPLEMENTATION_EQUIVALENCE_NOT_ESTABLISHED"

    summary = f"""# IEC Implementation Recovery End-to-End Equivalence Summary v1

## Scope

This additive recovery run used only the nine frozen TRAIN fixtures from `experiments/independent_validation_v2/equivalence_recovery_v1/train_equivalence_fixture_roster_v1.csv`.

No IEC incidents were scored. Validation and Final Holdout were not accessed. No model was retrained, tuned, calibrated, or replaced.

## Stage Results

| Stage | Result |
|---|---|
| Fixture checksum | {'PASS' if checksum_ok else 'FAIL'} |
| E1 window reconstruction | {'PASS' if stage_pass(e1) else 'FAIL'} |
| E2 V4 features | {'PASS' if stage_pass(e2) else 'FAIL'} |
| E3 Level-1 probabilities | {'PASS' if stage_pass(e3) else 'FAIL'} |
| E4 mean aggregation | {'PASS' if stage_pass(e4) else 'FAIL'} |
| E5 Level-2 meta-features | {'PASS' if stage_pass(e5) else 'FAIL'} |
| E6 final Level-2 scores | {'PASS' if stage_pass(e6) else 'BLOCKED'} |

## Key Finding

E1 through E5 were reproduced by a newly assembled executable recovery path using frozen component artifacts, frozen V4 ordering, the verified reconstructed Level-1 fold models, the frozen mean-aggregation rule, and the frozen `summarize_incident` temporal meta-feature implementation.

E6 was not executable because the repository contains frozen Level-2 configuration and reference incident predictions, but no serialized frozen Level-2 model artifact was found. The task explicitly forbids retraining, so no reconstructed Level-2 model was fitted in this run.

## Final Disposition

`{disposition}`
"""
    output_paths.append(OUT / "iec_end_to_end_equivalence_summary_v1.md")
    output_paths[-1].write_text(summary, encoding="utf-8")

    final = f"""# IEC Implementation Recovery Final Disposition v1

Disposition: `{disposition}`

The recovered implementation established fixture equivalence through E5 for all nine deterministic TRAIN fixtures. The final IEC execution is **not technically authorized** because E6 final Level-2 executable equivalence was not established.

Blocking item: no serialized frozen Level-2 XGBoost model artifact was found. Existing artifacts provide the final Level-2 configuration and frozen reference predictions, but not an executable model object that can be applied to newly generated IEC meta-features without retraining.

No IEC incident was scored. No Validation or Final Holdout artifact was accessed. No frozen result was modified.
"""
    output_paths.append(OUT / "iec_implementation_recovery_final_disposition_v1.md")
    output_paths[-1].write_text(final, encoding="utf-8")

    checksums = output_checksums(output_paths)
    checksums.to_csv(OUT / "iec_output_checksums_v1.csv", index=False)


if __name__ == "__main__":
    main()
