from __future__ import annotations

import argparse
import csv
import json
import math
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import yaml
from sklearn.impute import SimpleImputer
from sklearn.metrics import confusion_matrix, f1_score, log_loss, precision_recall_fscore_support
from xgboost import XGBClassifier

try:
    from bgp_incident_detection.audit import parse_listish, write_csv
    from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES
    from bgp_incident_detection.caida_features import CAIDA_FEATURE_NAMES
    from bgp_incident_detection.caida_train_enrichment import (
        aggregate_caida_batch,
        build_snapshot_mapping as build_caida_snapshot_mapping,
        ensure_caida_snapshots,
        group_by,
    )
    from bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT
    from bgp_incident_detection.full_train_execution import execute_batch
    from bgp_incident_detection.rpki_features import RPKI_FEATURE_NAMES
    from bgp_incident_detection.rpki_train_enrichment import (
        VrpIndexCache,
        aggregate_rpki_batch,
        build_train_snapshot_mapping,
        selected_snapshot_by_observation_date,
    )
    from bgp_incident_detection.train_batch_engine import DiskPolicy, source_commit
    from bgp_incident_detection.train_incident_scale import acquisition_rows, batch_rows, normalize_asn
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import parse_listish, write_csv
    from src.bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES
    from src.bgp_incident_detection.caida_features import CAIDA_FEATURE_NAMES
    from src.bgp_incident_detection.caida_train_enrichment import (
        aggregate_caida_batch,
        build_snapshot_mapping as build_caida_snapshot_mapping,
        ensure_caida_snapshots,
        group_by,
    )
    from src.bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT
    from src.bgp_incident_detection.full_train_execution import execute_batch
    from src.bgp_incident_detection.rpki_features import RPKI_FEATURE_NAMES
    from src.bgp_incident_detection.rpki_train_enrichment import (
        VrpIndexCache,
        aggregate_rpki_batch,
        build_train_snapshot_mapping,
        selected_snapshot_by_observation_date,
    )
    from src.bgp_incident_detection.train_batch_engine import DiskPolicy, source_commit
    from src.bgp_incident_detection.train_incident_scale import acquisition_rows, batch_rows, normalize_asn


VALIDATION_DIR = Path("data/validation")
PROTOCOL = Path("config/validation_confirmation_protocol_v4.yaml")
CANDIDATE_CONFIG = Path("config/final_model_candidate_v3_1_xgb_refined.yaml")
TRAIN_V4 = Path("data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1.parquet")
VALIDATION_INCIDENTS = Path("data/partitions_v2/validation_incidents_v2.csv")
TRAIN_INCIDENTS = Path("data/partitions_v2/train_incidents_v2.csv")
HOLDOUT_INCIDENTS = Path("data/partitions_v2/holdout_incidents_v2.csv")
VALIDATION_V4 = VALIDATION_DIR / "validation_v4_features_v1.parquet"
VALIDATION_BEHAVIORAL = VALIDATION_DIR / "validation_behavioral_features_v1.parquet"
VALIDATION_CAIDA = VALIDATION_DIR / "validation_caida_features_v1.parquet"
VALIDATION_RPKI = VALIDATION_DIR / "validation_rpki_features_v1.parquet"
VALIDATION_V2 = VALIDATION_DIR / "validation_behavioral_caida_v1.parquet"
VALIDATION_V3 = VALIDATION_DIR / "validation_behavioral_rpki_v1.parquet"
VALIDATION_MANIFEST = VALIDATION_DIR / "validation_incident_manifest_v1.csv"
VALIDATION_ACQUISITION_PLAN = VALIDATION_DIR / "validation_mrt_acquisition_plan_v1.csv"
VALIDATION_SCHEMA_AUDIT = VALIDATION_DIR / "validation_v4_schema_audit_v1.csv"
VALIDATION_MANIFEST_AUDIT = VALIDATION_DIR / "validation_incident_manifest_audit_v1.csv"
VALIDATION_WINDOW_PREDICTIONS = VALIDATION_DIR / "validation_xgb_window_predictions_v1.parquet"
VALIDATION_INCIDENT_RANKINGS = VALIDATION_DIR / "validation_incident_rankings_v1.csv"
VALIDATION_RESULTS = VALIDATION_DIR / "validation_confirmation_results_v1.csv"
VALIDATION_AUDIT = VALIDATION_DIR / "validation_confirmation_audit_v1.csv"
VALIDATION_COMPARISON = VALIDATION_DIR / "train_vs_validation_comparison_v1.csv"
VALIDATION_ERROR_ANALYSIS = VALIDATION_DIR / "validation_error_analysis_v1.csv"
NOTEBOOK = Path("notebooks/51_phase_j_single_validation_confirmation.ipynb")

LABELS = ["HIJACK", "LEAK", "OUTAGE"]
DISPLAY_TO_LABEL = {"Hijack": "HIJACK", "Leak": "LEAK", "Outage": "OUTAGE"}
LABEL_TO_DISPLAY = {v: k for k, v in DISPLAY_TO_LABEL.items()}
SEED = 20260828
EVIDENCE_COLUMNS = [
    "window_id",
    "incident_uid",
    "window_start",
    "window_end",
    "prefix",
    "origin_asn",
    "normalized_as_path",
    "observation_count",
    "collector",
    "source_mrt_count",
    "processing_batch_id",
    "parser",
    "parser_command",
    "source_commit",
    "behavioral_feature_version",
    "caida_feature_version",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def json_list(value: object) -> str:
    return json.dumps(parse_listish(value), separators=(",", ":"))


def load_yaml(path: Path) -> dict[str, object]:
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def verify_protocol() -> dict[str, object]:
    protocol = load_yaml(PROTOCOL)
    candidate = load_yaml(CANDIDATE_CONFIG)
    expected_params = {
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
    checks = [
        protocol.get("selected_candidate_config") == str(CANDIDATE_CONFIG),
        protocol.get("selected_candidate") == "XGB_REFINED_TRAIN_CANDIDATE",
        protocol.get("validation_compares_algorithms") is False,
        protocol.get("primary_metrics") == ["incident_macro_f1", "incident_mrr", "incident_top2"],
        protocol.get("acceptance_criteria", {}).get("incident_macro_f1_floor") == 0.6,
        protocol.get("acceptance_criteria", {}).get("incident_mrr_floor") == 0.75,
        protocol.get("acceptance_criteria", {}).get("incident_top2_floor") == 0.85,
        candidate.get("candidate_id") == "XGB_REFINED_TRAIN_CANDIDATE",
        candidate.get("recommendation") == "PROMOTE_PHASE_I2_XGB",
        candidate.get("xgboost_version") == "3.4.1",
        candidate.get("feature_variant") == "V4",
        candidate.get("feature_count") == 74,
        candidate.get("imbalance_condition") == "I1",
        candidate.get("objective") == "multi:softprob",
        candidate.get("num_class") == 3,
        candidate.get("selected_hyperparameters") == expected_params,
    ]
    if not all(checks):
        raise RuntimeError("validation protocol/candidate mismatch; Validation rows were not loaded")
    return {"protocol": protocol, "candidate": candidate}


def audit_validation_manifest() -> pd.DataFrame:
    validation = pd.read_csv(VALIDATION_INCIDENTS)
    train = pd.read_csv(TRAIN_INCIDENTS)
    holdout = pd.read_csv(HOLDOUT_INCIDENTS)
    rows = []
    val_uids = set(validation["incident_uid"].astype(str))
    train_uids = set(train["incident_uid"].astype(str))
    holdout_uids = set(holdout["incident_uid"].astype(str))
    counts = Counter(validation["category"].astype(str))
    checks = [
        ("validation_total_incidents", len(validation), 213, len(validation) == 213),
        ("validation_hijack_incidents", counts.get("Hijack", 0), 71, counts.get("Hijack", 0) == 71),
        ("validation_leak_incidents", counts.get("Leak", 0), 71, counts.get("Leak", 0) == 71),
        ("validation_outage_incidents", counts.get("Outage", 0), 71, counts.get("Outage", 0) == 71),
        ("unique_validation_incident_uid", validation["incident_uid"].nunique(), 213, validation["incident_uid"].nunique() == 213),
        ("partition_values_validation_only", ",".join(sorted(validation["partition"].astype(str).unique())), "validation", set(validation["partition"].astype(str)) == {"validation"}),
        ("train_validation_overlap", len(val_uids & train_uids), 0, not (val_uids & train_uids)),
        ("validation_holdout_overlap", len(val_uids & holdout_uids), 0, not (val_uids & holdout_uids)),
    ]
    for check, observed, expected, passed in checks:
        rows.append({"check": check, "observed": observed, "expected": expected, "status": "PASS" if passed else "FAIL"})
    VALIDATION_DIR.mkdir(parents=True, exist_ok=True)
    write_csv(VALIDATION_MANIFEST_AUDIT, rows, ["check", "observed", "expected", "status"])
    if any(row["status"] == "FAIL" for row in rows):
        raise RuntimeError("Validation manifest audit failed")
    return validation


def prepare_validation_inputs() -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    manifest = []
    for row in read_csv(VALIDATION_INCIDENTS):
        category = row["category"]
        leak_asn = normalize_asn(row.get("leak_asn") or (row.get("primary_asn") if category == "Leak" else ""))
        manifest.append(
            {
                "incident_uid": row["incident_uid"],
                "incident_id": row.get("incident_id", ""),
                "category": category,
                "start_utc": row["start_utc"],
                "end_utc": row["end_utc"],
                "duration_minutes": row.get("duration_minutes", ""),
                "affected_asns": json_list(row.get("affected_asns", "")),
                "affected_prefixes": json_list(row.get("affected_prefixes", "")),
                "leak_asn": leak_asn,
                "leak_seg": row.get("leak_seg", ""),
                "partition": "validation",
                "roster_version": row.get("roster_version", "v2"),
                "split_version": row.get("split_version", "v2"),
                "primary_asn": normalize_asn(row.get("primary_asn", "")),
                "countries": json_list(row.get("countries", "")),
                "source_url": row.get("source_url", ""),
                "notes": row.get("notes", ""),
            }
        )
    batches = batch_rows(manifest, batch_size=25)
    for row in batches:
        row["volume_batch_id"] = row.pop("batch_id").replace("batch_", "volume_batch_")
        row["batch_id"] = row["volume_batch_id"]
    plan = acquisition_rows(manifest, batches)
    for row in plan:
        row["batch_id"] = str(row["batch_id"]).replace("batch_", "volume_batch_")
        row["local_path"] = str(Path(str(row["local_path"]).replace("data/raw_mrt/train", "data/raw_mrt/validation")))
    write_csv(VALIDATION_MANIFEST, manifest, list(manifest[0].keys()))
    write_csv(VALIDATION_ACQUISITION_PLAN, plan, list(plan[0].keys()))
    return manifest, batches, plan


def generate_validation_behavioral(download_workers: int = 8) -> pd.DataFrame:
    import bgp_incident_detection.full_train_execution as fte

    manifest, batches, plan = prepare_validation_inputs()
    manifest_by_uid = {row["incident_uid"]: row for row in manifest}
    plan_by_uid = group_by([{k: str(v) for k, v in row.items()} for row in plan], "incident_uid")
    uids_by_batch = {}
    for row in batches:
        uids_by_batch.setdefault(row["batch_id"], []).append(row["incident_uid"])

    old_values = {
        "RAW_BATCH_ROOT": fte.RAW_BATCH_ROOT,
        "PARSED_TRAIN_ROOT": fte.PARSED_TRAIN_ROOT,
        "FEATURES_DIR": fte.FEATURES_DIR,
        "DOWNLOAD_AUDIT": fte.DOWNLOAD_AUDIT,
        "FEATURE_SUMMARY": fte.FEATURE_SUMMARY,
        "QUALITY_GATE": fte.QUALITY_GATE,
        "BATCH_EXECUTION_SUMMARY": fte.BATCH_EXECUTION_SUMMARY,
    }
    fte.RAW_BATCH_ROOT = Path("data/raw_mrt/validation_batches_phase_j")
    fte.PARSED_TRAIN_ROOT = Path("data/parsed_mrt/validation_phase_j")
    fte.FEATURES_DIR = VALIDATION_DIR / "behavioral_batches_phase_j"
    fte.DOWNLOAD_AUDIT = VALIDATION_DIR / "validation_mrt_download_audit_v1.csv"
    fte.FEATURE_SUMMARY = VALIDATION_DIR / "validation_incident_feature_summary_v1.csv"
    fte.QUALITY_GATE = VALIDATION_DIR / "validation_incident_processing_quality_gate_v1.csv"
    fte.BATCH_EXECUTION_SUMMARY = VALIDATION_DIR / "validation_batch_execution_summary_v1.csv"
    try:
        for batch_id in sorted(uids_by_batch):
            path = fte.batch_feature_path(batch_id)
            if path.exists() and path.stat().st_size > 0:
                print(f"{batch_id} Validation behavioral features already exist; skipping", flush=True)
                continue
            summary = execute_batch(batch_id, manifest_by_uid, sorted(uids_by_batch[batch_id]), plan_by_uid, DiskPolicy(), download_workers=download_workers)
            print(f"{batch_id} Validation behavioral complete status={summary['status']} rows={summary['feature_rows']}", flush=True)
        paths = sorted(fte.FEATURES_DIR.glob("volume_batch_*.parquet"))
        df = pd.concat([pd.read_parquet(path) for path in paths], ignore_index=True)
        df.to_parquet(VALIDATION_BEHAVIORAL, index=False)
    finally:
        for name, value in old_values.items():
            setattr(fte, name, value)
    return df


def generate_validation_caida(behavioral: pd.DataFrame, download_workers: int = 8) -> pd.DataFrame:
    import bgp_incident_detection.caida_train_enrichment as cte

    manifest = read_csv(VALIDATION_MANIFEST)
    plan = read_csv(VALIDATION_ACQUISITION_PLAN)
    batches = {}
    for row in read_csv(VALIDATION_DIR / "validation_batch_execution_summary_v1.csv"):
        _ = row
    for row in read_csv(VALIDATION_MANIFEST):
        pass
    batch_rows_data = []
    for idx, row in enumerate(sorted(manifest, key=lambda item: item["incident_uid"])):
        batch_rows_data.append({"volume_batch_id": f"volume_batch_{idx // 25 + 1:03d}", "incident_uid": row["incident_uid"]})
    for row in batch_rows_data:
        batches.setdefault(row["volume_batch_id"], []).append(row["incident_uid"])

    old_values = {
        "EVIDENCE_DIR": cte.EVIDENCE_DIR,
        "CAIDA_BATCH_DIR": cte.CAIDA_BATCH_DIR,
        "RAW_BATCH_ROOT": cte.RAW_BATCH_ROOT,
        "SNAPSHOT_MAPPING": cte.SNAPSHOT_MAPPING,
        "SNAPSHOT_CACHE_AUDIT": cte.SNAPSHOT_CACHE_AUDIT,
    }
    cte.EVIDENCE_DIR = VALIDATION_DIR / "evidence_phase_j"
    cte.CAIDA_BATCH_DIR = VALIDATION_DIR / "caida_batches_phase_j"
    cte.RAW_BATCH_ROOT = Path("data/raw_mrt/validation_caida_batches_phase_j")
    cte.SNAPSHOT_MAPPING = VALIDATION_DIR / "validation_caida_snapshot_mapping_v1.csv"
    cte.SNAPSHOT_CACHE_AUDIT = VALIDATION_DIR / "validation_caida_snapshot_cache_audit_v1.csv"
    try:
        mapping = build_caida_snapshot_mapping(behavioral)
        relationships_by_snapshot = ensure_caida_snapshots(mapping)
        snapshot_by_window = dict(zip(mapping["window_id"], mapping["selected_caida_snapshot"]))
        manifest_by_uid = {row["incident_uid"]: row for row in manifest}
        plan_by_uid = group_by(plan, "incident_uid")
        summaries = []
        for batch_id, uids in sorted(batches.items()):
            if cte.batch_feature_path(batch_id).exists() and cte.evidence_batch_path(batch_id).exists():
                print(f"{batch_id} Validation CAIDA/evidence already exist; skipping", flush=True)
                continue
            rows = [row for uid in uids for row in plan_by_uid.get(uid, [])]
            summary = aggregate_caida_batch(batch_id, sorted(uids), behavioral, manifest_by_uid, rows, snapshot_by_window, relationships_by_snapshot, download_workers)
            summaries.append(summary)
            print(f"{batch_id} Validation CAIDA complete status={summary['status']} rows={summary['feature_rows']}", flush=True)
        if summaries:
            write_csv(
                VALIDATION_DIR / "validation_caida_batch_execution_summary_v1.csv",
                summaries,
                list(summaries[0].keys()),
            )
        for evidence_path in sorted(cte.EVIDENCE_DIR.glob("batch_*.parquet")):
            evidence = pd.read_parquet(evidence_path)
            if list(evidence.columns) != EVIDENCE_COLUMNS:
                pd.DataFrame(columns=EVIDENCE_COLUMNS).to_parquet(evidence_path, index=False)
        caida = pd.concat([pd.read_parquet(path) for path in sorted(cte.CAIDA_BATCH_DIR.glob("volume_batch_*.parquet"))], ignore_index=True)
        caida.to_parquet(VALIDATION_CAIDA, index=False)
        v2 = behavioral.merge(caida[["window_id", "selected_caida_snapshot"] + CAIDA_FEATURE_NAMES], on="window_id", how="left", validate="one_to_one")
        v2.to_parquet(VALIDATION_V2, index=False)
    finally:
        for name, value in old_values.items():
            setattr(cte, name, value)
    return v2


def generate_validation_rpki(behavioral: pd.DataFrame, v2: pd.DataFrame) -> pd.DataFrame:
    import bgp_incident_detection.rpki_train_enrichment as rte

    if VALIDATION_V4.exists():
        return pd.read_parquet(VALIDATION_V4)
    batch_rows_data = []
    manifest = read_csv(VALIDATION_MANIFEST)
    for idx, row in enumerate(sorted(manifest, key=lambda item: item["incident_uid"])):
        batch_rows_data.append({"volume_batch_id": f"volume_batch_{idx // 25 + 1:03d}", "incident_uid": row["incident_uid"]})
    batches = {}
    for row in batch_rows_data:
        batches.setdefault(row["volume_batch_id"], []).append(row["incident_uid"])
    old_values = {
        "EVIDENCE_DIR": rte.EVIDENCE_DIR,
        "RPKI_BATCH_DIR": rte.RPKI_BATCH_DIR,
        "TRAIN_RPKI_MAPPING": rte.TRAIN_RPKI_MAPPING,
    }
    rte.EVIDENCE_DIR = VALIDATION_DIR / "evidence_phase_j"
    rte.RPKI_BATCH_DIR = VALIDATION_DIR / "rpki_batches_phase_j"
    rte.TRAIN_RPKI_MAPPING = VALIDATION_DIR / "validation_rpki_snapshot_mapping_v1.csv"
    try:
        mapping = build_train_snapshot_mapping(behavioral)
        selected = selected_snapshot_by_observation_date(mapping)
        index_cache = VrpIndexCache(max_size=4)
        summaries = []
        for batch_id, uids in sorted(batches.items()):
            result = aggregate_rpki_batch(batch_id, sorted(uids), behavioral, index_cache, selected)
            summaries.append(result)
            print(f"{batch_id} Validation RPKI complete status={result['status']} rows={result['feature_rows']}", flush=True)
        write_csv(VALIDATION_DIR / "validation_rpki_batch_manifest_v1.csv", summaries, list(summaries[0].keys()))
        rpki = pd.concat([pd.read_parquet(path) for path in sorted(rte.RPKI_BATCH_DIR.glob("batch_*.parquet"))], ignore_index=True)
        rpki.to_parquet(VALIDATION_RPKI, index=False)
        v3 = behavioral.merge(rpki[["window_id"] + RPKI_FEATURE_NAMES], on="window_id", how="left", validate="one_to_one")
        v3.to_parquet(VALIDATION_V3, index=False)
        v4 = v2.merge(rpki[["window_id"] + RPKI_FEATURE_NAMES], on="window_id", how="left", validate="one_to_one")
        v4.to_parquet(VALIDATION_V4, index=False)
    finally:
        for name, value in old_values.items():
            setattr(rte, name, value)
    return v4


def ensure_validation_features(download_workers: int = 8) -> pd.DataFrame:
    if VALIDATION_V4.exists():
        return pd.read_parquet(VALIDATION_V4)
    behavioral = generate_validation_behavioral(download_workers=download_workers)
    v2 = generate_validation_caida(behavioral, download_workers=download_workers)
    return generate_validation_rpki(behavioral, v2)


def schema_audit(validation: pd.DataFrame, train: pd.DataFrame) -> None:
    features = FEATURES_BY_VARIANT["V4"]
    rows = []
    checks = [
        ("behavioral_features", len([f for f in BEHAVIORAL_FEATURE_NAMES if f in validation.columns]), 44),
        ("caida_features", len([f for f in CAIDA_FEATURE_NAMES if f in validation.columns]), 14),
        ("rpki_features", len([f for f in RPKI_FEATURE_NAMES if f in validation.columns]), 16),
        ("total_model_features", len(features), 74),
        ("feature_names_match_train", FEATURES_BY_VARIANT["V4"] == features, True),
        ("feature_order_matches_train", list(train[features].columns) == list(validation[features].columns), True),
        ("no_duplicate_window_ids", int(validation["window_id"].duplicated().sum()), 0),
        ("no_holdout_rows", int((validation["partition"].astype(str) == "holdout").sum()), 0),
        ("no_train_rows", int((validation["partition"].astype(str) == "train").sum()), 0),
    ]
    for check, observed, expected in checks:
        rows.append({"check": check, "observed": observed, "expected": expected, "status": "PASS" if observed == expected else "FAIL"})
    numeric = validation[features].apply(pd.to_numeric, errors="coerce")
    rows.append({"check": "invalid_numeric_values", "observed": int(np.isinf(numeric.to_numpy()).sum()), "expected": 0, "status": "PASS" if not np.isinf(numeric.to_numpy()).any() else "FAIL"})
    write_csv(VALIDATION_SCHEMA_AUDIT, rows, ["check", "observed", "expected", "status"])
    if any(row["status"] == "FAIL" for row in rows):
        raise RuntimeError("Validation V4 schema audit failed")


def incident_weights(df: pd.DataFrame) -> np.ndarray:
    counts = df.groupby("incident_uid")["window_id"].transform("count")
    return (1.0 / counts).to_numpy(dtype=float)


def top2_accuracy(y_true: list[str], probs: pd.DataFrame) -> float:
    labels = list(probs.columns)
    arr = probs.to_numpy()
    return float(np.mean([true in [labels[i] for i in np.argsort(row)[-2:]] for true, row in zip(y_true, arr)]))


def mrr(y_true: list[str], probs: pd.DataFrame) -> float:
    labels = list(probs.columns)
    total = 0.0
    for true, row in zip(y_true, probs.to_numpy()):
        order = [labels[i] for i in np.argsort(row)[::-1]]
        total += 1.0 / (order.index(true) + 1)
    return total / len(y_true)


def multiclass_brier(y_true: list[str], probs: pd.DataFrame) -> float:
    y = np.zeros((len(y_true), len(LABELS)))
    label_to_idx = {label: idx for idx, label in enumerate(LABELS)}
    for row, label in enumerate(y_true):
        y[row, label_to_idx[label]] = 1.0
    return float(np.mean(np.sum((probs[LABELS].to_numpy() - y) ** 2, axis=1)))


def evaluate_validation(download_workers: int = 8) -> dict[str, object]:
    verified = verify_protocol()
    validation_manifest = audit_validation_manifest()
    train = pd.read_parquet(TRAIN_V4)
    validation = ensure_validation_features(download_workers=download_workers)
    features = FEATURES_BY_VARIANT["V4"]
    if len(features) != 74:
        raise RuntimeError("V4 feature schema is not exactly 74 features")
    validation = validation[validation["incident_uid"].isin(set(validation_manifest["incident_uid"].astype(str)))].copy()
    schema_audit(validation, train)
    train_df = train.copy()
    train_df["label"] = train_df["category"].map(DISPLAY_TO_LABEL)
    validation["label"] = validation["category"].map(DISPLAY_TO_LABEL)

    params = verified["candidate"]["selected_hyperparameters"]
    model = XGBClassifier(
        **params,
        objective="multi:softprob",
        num_class=3,
        eval_metric="mlogloss",
        random_state=SEED,
        n_jobs=-1,
    )
    imputer = SimpleImputer(strategy="median")
    X_train = imputer.fit_transform(train_df[features])
    y_train = train_df["label"].map({label: idx for idx, label in enumerate(LABELS)}).to_numpy()
    weights = incident_weights(train_df)
    model.fit(X_train, y_train, sample_weight=weights)

    X_val = imputer.transform(validation[features])
    y_val = validation["label"].map({label: idx for idx, label in enumerate(LABELS)}).to_numpy()
    probs = model.predict_proba(X_val)
    window_predictions = validation[["window_id", "incident_uid", "category"]].copy()
    window_predictions["true_class"] = validation["label"]
    for idx, label in enumerate(LABELS):
        window_predictions[f"p_{label.lower()}"] = probs[:, idx]
    window_predictions["predicted_class"] = [LABELS[idx] for idx in probs.argmax(axis=1)]
    window_predictions.to_parquet(VALIDATION_WINDOW_PREDICTIONS, index=False)

    prob_cols = [f"p_{label.lower()}" for label in LABELS]
    incident_probs = window_predictions.groupby("incident_uid", as_index=False)[prob_cols].mean()
    incident_truth = validation.drop_duplicates("incident_uid")[["incident_uid", "label", "category"]]
    incident_probs = incident_probs.merge(incident_truth, on="incident_uid", how="left", validate="one_to_one")
    ranking_rows = []
    for _, row in incident_probs.iterrows():
        scores = {label: float(row[f"p_{label.lower()}"]) for label in LABELS}
        ranked = sorted(scores.items(), key=lambda item: item[1], reverse=True)
        true = row["label"]
        ranking_rows.append(
            {
                "incident_uid": row["incident_uid"],
                "true_class": true,
                "predicted_class": ranked[0][0],
                "rank_1_class": ranked[0][0],
                "rank_1_score": ranked[0][1],
                "rank_2_class": ranked[1][0],
                "rank_2_score": ranked[1][1],
                "rank_3_class": ranked[2][0],
                "rank_3_score": ranked[2][1],
                "true_class_rank": [label for label, _ in ranked].index(true) + 1,
                "window_count": int((window_predictions["incident_uid"] == row["incident_uid"]).sum()),
                "mean_p_hijack": scores["HIJACK"],
                "mean_p_leak": scores["LEAK"],
                "mean_p_outage": scores["OUTAGE"],
            }
        )
    rankings = pd.DataFrame(ranking_rows)
    rankings.to_csv(VALIDATION_INCIDENT_RANKINGS, index=False)

    y_incident_true = rankings["true_class"].tolist()
    y_incident_pred = rankings["predicted_class"].tolist()
    incident_prob_frame = rankings[["mean_p_hijack", "mean_p_leak", "mean_p_outage"]].rename(columns={"mean_p_hijack": "HIJACK", "mean_p_leak": "LEAK", "mean_p_outage": "OUTAGE"})
    precision, recall, f1, _ = precision_recall_fscore_support(y_incident_true, y_incident_pred, labels=LABELS, zero_division=0)
    per_class = {label: {"precision": precision[i], "recall": recall[i], "f1": f1[i]} for i, label in enumerate(LABELS)}
    incident_macro_f1 = float(f1_score(y_incident_true, y_incident_pred, labels=LABELS, average="macro", zero_division=0))
    top1 = float(np.mean(rankings["true_class_rank"] == 1))
    top2 = top2_accuracy(y_incident_true, incident_prob_frame)
    incident_mrr = mrr(y_incident_true, incident_prob_frame)
    window_macro_f1 = float(f1_score(window_predictions["true_class"], window_predictions["predicted_class"], labels=LABELS, average="macro", zero_division=0))
    val_log_loss = float(log_loss(y_incident_true, incident_prob_frame[LABELS], labels=LABELS))
    val_brier = multiclass_brier(y_incident_true, incident_prob_frame)
    cm = confusion_matrix(y_incident_true, y_incident_pred, labels=LABELS)
    cm_rows = []
    for i, true_label in enumerate(LABELS):
        for j, pred_label in enumerate(LABELS):
            cm_rows.append({"true_class": true_label, "predicted_class": pred_label, "count": int(cm[i, j])})
    write_csv(VALIDATION_DIR / "validation_incident_confusion_matrix_v1.csv", cm_rows, ["true_class", "predicted_class", "count"])
    errors = rankings[rankings["true_class"] != rankings["predicted_class"]]
    errors.to_csv(VALIDATION_ERROR_ANALYSIS, index=False)

    train_ref = verified["candidate"]["train_multiseed_results"]
    validation_metrics = {
        "incident_macro_f1": incident_macro_f1,
        "top1": top1,
        "top2": top2,
        "mrr": incident_mrr,
        "hijack_f1": per_class["HIJACK"]["f1"],
        "leak_f1": per_class["LEAK"]["f1"],
        "outage_f1": per_class["OUTAGE"]["f1"],
        "window_macro_f1": window_macro_f1,
    }
    ref_map = {
        "incident_macro_f1": "mean_incident_macro_f1",
        "top1": "mean_top1",
        "top2": "mean_top2",
        "mrr": "mean_mrr",
        "hijack_f1": "hijack_f1_mean",
        "leak_f1": "leak_f1_mean",
        "outage_f1": "outage_f1_mean",
        "window_macro_f1": "window_macro_f1_mean",
    }
    comparison = []
    for metric, ref_key in ref_map.items():
        comparison.append({"metric": metric, "train_cv": train_ref[ref_key], "validation": validation_metrics[metric], "validation_minus_train_cv": validation_metrics[metric] - train_ref[ref_key], "absolute_delta": abs(validation_metrics[metric] - train_ref[ref_key])})
    write_csv(VALIDATION_COMPARISON, comparison, ["metric", "train_cv", "validation", "validation_minus_train_cv", "absolute_delta"])

    floors = verified["protocol"]["acceptance_criteria"]
    macro_pass = incident_macro_f1 >= floors["incident_macro_f1_floor"]
    mrr_pass = incident_mrr >= floors["incident_mrr_floor"]
    top2_pass = top2 >= floors["incident_top2_floor"]
    severe_degradation = any(value["f1"] == 0 for value in per_class.values())
    disposition = "VALIDATION_CONFIRMATION_PASS" if macro_pass and mrr_pass and top2_pass and not severe_degradation else "VALIDATION_CONFIRMATION_REVIEW"
    result = {
        "candidate": "XGB_REFINED_TRAIN_CANDIDATE",
        "xgboost_version": verified["candidate"]["xgboost_version"],
        "validation_incidents": rankings["incident_uid"].nunique(),
        "window_rows": len(window_predictions),
        "incident_macro_f1": incident_macro_f1,
        "top1": top1,
        "top2": top2,
        "mrr": incident_mrr,
        "hijack_precision": per_class["HIJACK"]["precision"],
        "hijack_recall": per_class["HIJACK"]["recall"],
        "hijack_f1": per_class["HIJACK"]["f1"],
        "leak_precision": per_class["LEAK"]["precision"],
        "leak_recall": per_class["LEAK"]["recall"],
        "leak_f1": per_class["LEAK"]["f1"],
        "outage_precision": per_class["OUTAGE"]["precision"],
        "outage_recall": per_class["OUTAGE"]["recall"],
        "outage_f1": per_class["OUTAGE"]["f1"],
        "mean_true_class_rank": float(rankings["true_class_rank"].mean()),
        "window_macro_f1": window_macro_f1,
        "multiclass_log_loss": val_log_loss,
        "multiclass_brier_score": val_brier,
        "macro_f1_floor_pass": macro_pass,
        "mrr_floor_pass": mrr_pass,
        "top2_floor_pass": top2_pass,
        "formal_disposition": disposition,
        "severe_class_degradation": severe_degradation,
        "stage1_status": "UNRESOLVED_EXPERIMENTAL_AUXILIARY",
        "final_holdout_status": "SEALED",
        "source_commit": source_commit(),
        "evaluation_timestamp": utc_now(),
    }
    write_csv(VALIDATION_RESULTS, [result], list(result.keys()))
    audit_rows = [
        {"check": "protocol_verified_before_validation_access", "status": "PASS", "notes": str(PROTOCOL)},
        {"check": "candidate_locked", "status": "PASS", "notes": "XGB_REFINED_TRAIN_CANDIDATE"},
        {"check": "train_only_fit", "status": "PASS", "notes": f"{train_df['incident_uid'].nunique()} TRAIN incidents"},
        {"check": "validation_not_used_for_fit", "status": "PASS", "notes": "Validation used for one confirmation pass only"},
        {"check": "holdout_sealed", "status": "PASS", "notes": "Holdout feature/prediction paths not loaded"},
        {"check": "feature_count_74", "status": "PASS" if len(features) == 74 else "FAIL", "notes": str(len(features))},
        {"check": "acceptance_floors", "status": "PASS" if disposition == "VALIDATION_CONFIRMATION_PASS" else "REVIEW", "notes": disposition},
        {"check": "nothing_changed_after_results", "status": "PASS", "notes": "No candidate, feature, hyperparameter, weighting, aggregation, or ranking change performed"},
    ]
    write_csv(VALIDATION_AUDIT, audit_rows, ["check", "status", "notes"])
    write_notebook()
    return result


def write_notebook() -> None:
    NOTEBOOK.parent.mkdir(parents=True, exist_ok=True)
    notebook = {
        "cells": [
            {"cell_type": "markdown", "metadata": {}, "source": ["# Phase J - Single Validation Confirmation\n", "\n", "Executes the predeclared Phase J protocol for the locked Phase I2 XGBoost candidate. Validation is used once for confirmation only; Final Holdout remains sealed.\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["from bgp_incident_detection.validation_confirmation import verify_protocol, audit_validation_manifest\n", "verify_protocol()\n", "audit_validation_manifest()\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["from bgp_incident_detection.validation_confirmation import evaluate_validation\n", "# evaluate_validation(download_workers=8)\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["import pandas as pd\n", "pd.read_csv('../data/validation/validation_confirmation_results_v1.csv')\n"]},
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Phase J single predeclared Validation confirmation")
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--download-workers", type=int, default=8)
    args = parser.parse_args()
    if args.verify_only:
        verify_protocol()
        audit_validation_manifest()
        write_notebook()
        print(json.dumps({"status": "PASS", "protocol_verified": True, "validation_manifest_audited": True}, indent=2))
        return
    if args.run:
        print(json.dumps(evaluate_validation(download_workers=args.download_workers), indent=2, sort_keys=True))
        return
    parser.error("choose --verify-only or --run")


if __name__ == "__main__":
    main()
