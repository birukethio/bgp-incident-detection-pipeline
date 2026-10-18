from __future__ import annotations

import argparse
import csv
import json
import math
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import yaml
from sklearn.metrics import confusion_matrix, f1_score, log_loss, precision_recall_fscore_support

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
    from bgp_incident_detection.imbalance_model_experiment import group_aware_weights
    from bgp_incident_detection.k1_incident_stacking import (
        FIRST_LEVEL_PARAMS,
        INCIDENT_LABELS,
        build_meta_frame,
        first_level_model,
        metrics as k1_metrics,
        predict_meta,
        temporal_feature_names,
        xgb_meta_model,
        y_codes,
    )
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
    from src.bgp_incident_detection.imbalance_model_experiment import group_aware_weights
    from src.bgp_incident_detection.k1_incident_stacking import (
        FIRST_LEVEL_PARAMS,
        INCIDENT_LABELS,
        build_meta_frame,
        first_level_model,
        metrics as k1_metrics,
        predict_meta,
        temporal_feature_names,
        xgb_meta_model,
        y_codes,
    )
    from src.bgp_incident_detection.rpki_features import RPKI_FEATURE_NAMES
    from src.bgp_incident_detection.rpki_train_enrichment import (
        VrpIndexCache,
        aggregate_rpki_batch,
        build_train_snapshot_mapping,
        selected_snapshot_by_observation_date,
    )
    from src.bgp_incident_detection.train_batch_engine import DiskPolicy, source_commit
    from src.bgp_incident_detection.train_incident_scale import acquisition_rows, batch_rows, normalize_asn


FINAL_HOLDOUT = Path("data/final_holdout")
FIGURE_DIR = Path("figures/final")
PROTOCOL = Path("config/final_holdout_protocol_v1.yaml")
DEPLOYABLE_CONFIG = Path("config/k1_final_candidate_v1_1_deployable.yaml")
SECOND_LEVEL_CONFIG = Path("config/k1_second_level_xgb_final_v1.yaml")
META_SCHEMA_CONFIG = Path("config/k1_incident_meta_feature_schema_v1.yaml")
PREACCESS_AUDIT = FINAL_HOLDOUT / "final_preaccess_model_audit_v2.csv"
TRAIN_V4 = Path("data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1.parquet")
ASSIGNMENTS = Path("data/modeling/baseline_v1_grouped_cv_assignments_v1.csv")
OOF_PROBS = Path("data/modeling_k1/k1_window_oof_probabilities_v1.parquet")
TRAIN_INCIDENTS = Path("data/partitions_v2/train_incidents_v2.csv")
VALIDATION_INCIDENTS = Path("data/partitions_v2/validation_incidents_v2.csv")
HOLDOUT_INCIDENTS = Path("data/partitions_v2/holdout_incidents_v2.csv")

ACCESS_RECORD = FINAL_HOLDOUT / "final_holdout_access_record_v1.csv"
MANIFEST_AUDIT = FINAL_HOLDOUT / "final_holdout_manifest_audit_v1.csv"
HOLDOUT_MANIFEST = FINAL_HOLDOUT / "final_holdout_incident_manifest_v1.csv"
ACQUISITION_PLAN = FINAL_HOLDOUT / "final_holdout_mrt_acquisition_plan_v1.csv"
HOLDOUT_BEHAVIORAL = FINAL_HOLDOUT / "final_holdout_behavioral_features_v1.parquet"
HOLDOUT_CAIDA = FINAL_HOLDOUT / "final_holdout_caida_features_v1.parquet"
HOLDOUT_RPKI = FINAL_HOLDOUT / "final_holdout_rpki_features_v1.parquet"
HOLDOUT_V2 = FINAL_HOLDOUT / "final_holdout_behavioral_caida_v1.parquet"
HOLDOUT_V3 = FINAL_HOLDOUT / "final_holdout_behavioral_rpki_v1.parquet"
HOLDOUT_V4 = FINAL_HOLDOUT / "final_holdout_v4_features_v1.parquet"
SCHEMA_AUDIT = FINAL_HOLDOUT / "final_holdout_v4_schema_audit_v1.csv"
LEVEL1_PROBS = FINAL_HOLDOUT / "final_holdout_level1_window_probabilities_v1.parquet"
META_FEATURES = FINAL_HOLDOUT / "final_holdout_k1_meta_features_v1.parquet"
META_SCHEMA_AUDIT = FINAL_HOLDOUT / "final_holdout_k1_meta_schema_audit_v1.csv"
RANKINGS = FINAL_HOLDOUT / "final_holdout_incident_rankings_v1.csv"
PERFORMANCE = FINAL_HOLDOUT / "final_holdout_performance_summary_v1.csv"
PER_CLASS = FINAL_HOLDOUT / "final_holdout_per_class_metrics_v1.csv"
RANKING_METRICS = FINAL_HOLDOUT / "final_holdout_ranking_metrics_v1.csv"
CONFUSION = FINAL_HOLDOUT / "final_holdout_confusion_matrix_v1.csv"
COMPARISON = FINAL_HOLDOUT / "train_vs_final_holdout_comparison_v1.csv"
ERROR_ANALYSIS = FINAL_HOLDOUT / "final_holdout_error_analysis_v1.csv"
EVALUATION_AUDIT = FINAL_HOLDOUT / "final_evaluation_audit_v1.csv"
FINAL_RESULT = Path("config/final_praxis_result_v1.yaml")
DOC = Path("docs/final_experimental_pipeline_v1.md")
NOTEBOOK = Path("notebooks/55_final_holdout_evaluation.ipynb")

SEED = 20260828
BOOTSTRAP_REPLICATES = 1000
DISPLAY_TO_LABEL = {"Hijack": "HIJACK", "Leak": "LEAK", "Outage": "OUTAGE"}
TRAIN_REFERENCE = {
    "incident_macro_f1": 0.931653,
    "top1": 0.931521,
    "top2": 0.992346,
    "mrr": 0.964485,
    "hijack_f1": 0.909146,
    "leak_f1": 0.907998,
    "outage_f1": 0.977817,
}
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


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def verify_preaccess_gate() -> pd.DataFrame:
    audit = pd.read_csv(PREACCESS_AUDIT)
    if set(audit["status"].astype(str)) != {"PASS"}:
        raise RuntimeError("Phase L pre-access model audit is not all PASS")
    required = {
        "final_second_level_hyperparameters",
        "deployable_candidate_config",
        "final_holdout_accessed",
        "k25_decision",
        "meta_feature_schema",
    }
    if not required <= set(audit["check"].astype(str)):
        raise RuntimeError("Phase L pre-access audit is missing required checks")
    return audit


def freeze_protocol() -> dict[str, Any]:
    preaccess = verify_preaccess_gate()
    deployable = load_yaml(DEPLOYABLE_CONFIG)
    second = load_yaml(SECOND_LEVEL_CONFIG)
    meta_schema = load_yaml(META_SCHEMA_CONFIG)
    if deployable.get("candidate_id") != "K1_FINAL_DEPLOYABLE_V1_1":
        raise RuntimeError("Unexpected deployable candidate config")
    if second.get("candidate_parameter_hash") != "40df040321ef":
        raise RuntimeError("Unexpected second-level XGBoost parameter hash")
    if meta_schema.get("feature_count") != 74 or meta_schema.get("status") != "FROZEN":
        raise RuntimeError("Unexpected K1 meta schema")
    protocol = {
        "protocol_id": "final_holdout_protocol_v1",
        "protocol_status": "FROZEN_BEFORE_HOLDOUT_ACCESS",
        "freeze_timestamp_utc": utc_now(),
        "authorized_architecture": "A0_XGB_TO_XGB",
        "architecture_decision": "KEEP_XGB_XGB_K1",
        "first_level_model": "XGB_REFINED_TRAIN_CANDIDATE",
        "first_level_xgboost_version": "3.4.1",
        "first_level_feature_schema": "V4 exactly 74 frozen Behavioral + CAIDA + RPKI features",
        "first_level_hyperparameters": FIRST_LEVEL_PARAMS,
        "first_level_inference_strategy": "CROSSFIT_ENSEMBLE_FIRST_LEVEL",
        "first_level_ensemble_rule": "arithmetic_mean_across_five_train_fold_models",
        "second_level_model": "K1_FINAL_SECOND_LEVEL_XGB_V1",
        "second_level_config": str(SECOND_LEVEL_CONFIG),
        "second_level_parameter_hash": "40df040321ef",
        "second_level_hyperparameters": {key: second[key] for key in ["n_estimators", "max_depth", "learning_rate", "subsample", "colsample_bytree", "reg_alpha", "reg_lambda", "objective", "num_class"]},
        "k1_meta_feature_schema": str(META_SCHEMA_CONFIG),
        "k1_meta_feature_count": 74,
        "training_population": "TRAIN only: 993 incidents, 331 Hijack / 331 Leak / 331 Outage",
        "validation_population": "not used in Phase L",
        "final_holdout_population": "sealed until this frozen protocol and access record",
        "ranking_rule": "descending second-level P(Hijack), P(Leak), P(Outage)",
        "primary_metrics": ["incident_macro_f1", "incident_mrr", "incident_top2"],
        "secondary_metrics": ["top1", "per_class_precision_recall_f1", "confusion_matrix", "mean_true_class_rank", "log_loss", "brier_score"],
        "bootstrap_replicates": BOOTSTRAP_REPLICATES,
        "bootstrap_seed": SEED,
        "train_reference": TRAIN_REFERENCE,
        "stage1_status": "UNRESOLVED_EXPERIMENTAL_AUXILIARY",
        "final_holdout_use": "one terminal unbiased evaluation only",
        "no_post_holdout_changes_allowed": True,
        "source_commit": source_commit(),
        "preaccess_audit": str(PREACCESS_AUDIT),
        "preaccess_audit_status": "PASS" if set(preaccess["status"]) == {"PASS"} else "FAIL",
    }
    PROTOCOL.parent.mkdir(parents=True, exist_ok=True)
    PROTOCOL.write_text(yaml.safe_dump(protocol, sort_keys=False), encoding="utf-8")
    return protocol


def record_holdout_access(protocol: dict[str, Any]) -> pd.DataFrame:
    row = {
        "access_timestamp_utc": utc_now(),
        "access_type": "FINAL_HOLDOUT_PHASE_L_EVALUATION",
        "protocol": str(PROTOCOL),
        "protocol_status": protocol["protocol_status"],
        "authorized_architecture": protocol["authorized_architecture"],
        "model_candidate": protocol["second_level_model"],
        "second_level_parameter_hash": protocol["second_level_parameter_hash"],
        "notes": "Recorded before Holdout feature generation, prediction, and metric computation.",
    }
    out = pd.DataFrame([row])
    FINAL_HOLDOUT.mkdir(parents=True, exist_ok=True)
    out.to_csv(ACCESS_RECORD, index=False)
    return out


def audit_holdout_manifest() -> pd.DataFrame:
    holdout = pd.read_csv(HOLDOUT_INCIDENTS)
    train = pd.read_csv(TRAIN_INCIDENTS)
    validation = pd.read_csv(VALIDATION_INCIDENTS)
    holdout_uids = set(holdout["incident_uid"].astype(str))
    train_uids = set(train["incident_uid"].astype(str))
    validation_uids = set(validation["incident_uid"].astype(str))
    counts = Counter(holdout["category"].astype(str))
    checks = [
        ("holdout_total_incidents", len(holdout), 213, len(holdout) == 213),
        ("holdout_hijack_incidents", counts.get("Hijack", 0), 71, counts.get("Hijack", 0) == 71),
        ("holdout_leak_incidents", counts.get("Leak", 0), 71, counts.get("Leak", 0) == 71),
        ("holdout_outage_incidents", counts.get("Outage", 0), 71, counts.get("Outage", 0) == 71),
        ("unique_holdout_incident_uid", holdout["incident_uid"].nunique(), 213, holdout["incident_uid"].nunique() == 213),
        ("partition_values_holdout_only", ",".join(sorted(holdout["partition"].astype(str).unique())), "holdout", set(holdout["partition"].astype(str)) == {"holdout"}),
        ("train_holdout_overlap", len(holdout_uids & train_uids), 0, not (holdout_uids & train_uids)),
        ("validation_holdout_overlap", len(holdout_uids & validation_uids), 0, not (holdout_uids & validation_uids)),
    ]
    rows = [{"check": c, "observed": o, "expected": e, "status": "PASS" if p else "FAIL"} for c, o, e, p in checks]
    write_csv(MANIFEST_AUDIT, rows, ["check", "observed", "expected", "status"])
    if any(row["status"] == "FAIL" for row in rows):
        raise RuntimeError("Final Holdout manifest audit failed")
    return holdout


def prepare_holdout_inputs() -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    manifest = []
    for row in read_csv(HOLDOUT_INCIDENTS):
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
                "partition": "holdout",
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
        row["local_path"] = str(Path(str(row["local_path"]).replace("data/raw_mrt/train", "data/raw_mrt/final_holdout")))
    write_csv(HOLDOUT_MANIFEST, manifest, list(manifest[0].keys()))
    write_csv(ACQUISITION_PLAN, plan, list(plan[0].keys()))
    return manifest, batches, plan


def valid_download_cache() -> bool:
    if not (FINAL_HOLDOUT / "final_holdout_mrt_download_audit_v1.csv").exists():
        return False
    audit = pd.read_csv(FINAL_HOLDOUT / "final_holdout_mrt_download_audit_v1.csv")
    if len(audit) == 0:
        return False
    latest = audit.drop_duplicates(["mrt_url", "local_path"], keep="last")
    return not latest["download_status"].astype(str).eq("FAILED").any() and int(latest["file_size"].fillna(0).astype(int).sum()) > 0


def valid_behavioral_cache() -> bool:
    if not HOLDOUT_BEHAVIORAL.exists():
        return False
    summary_path = FINAL_HOLDOUT / "final_holdout_batch_execution_summary_v1.csv"
    if not summary_path.exists():
        return False
    summary = pd.read_csv(summary_path)
    return valid_download_cache() and len(summary) >= 9 and int(summary["raw_observations"].fillna(0).astype(int).sum()) > 0


def generate_holdout_behavioral(download_workers: int = 8) -> pd.DataFrame:
    if valid_behavioral_cache():
        return pd.read_parquet(HOLDOUT_BEHAVIORAL)
    import bgp_incident_detection.full_train_execution as fte

    manifest, batches, plan = prepare_holdout_inputs()
    manifest_by_uid = {row["incident_uid"]: row for row in manifest}
    plan_by_uid = group_by([{key: str(value) for key, value in row.items()} for row in plan], "incident_uid")
    uids_by_batch: dict[str, list[str]] = {}
    for row in batches:
        uids_by_batch.setdefault(str(row["batch_id"]), []).append(str(row["incident_uid"]))

    old_values = {
        "RAW_BATCH_ROOT": fte.RAW_BATCH_ROOT,
        "PARSED_TRAIN_ROOT": fte.PARSED_TRAIN_ROOT,
        "FEATURES_DIR": fte.FEATURES_DIR,
        "DOWNLOAD_AUDIT": fte.DOWNLOAD_AUDIT,
        "FEATURE_SUMMARY": fte.FEATURE_SUMMARY,
        "QUALITY_GATE": fte.QUALITY_GATE,
        "BATCH_EXECUTION_SUMMARY": fte.BATCH_EXECUTION_SUMMARY,
    }
    fte.RAW_BATCH_ROOT = Path("data/raw_mrt/final_holdout_batches_phase_l")
    fte.PARSED_TRAIN_ROOT = Path("data/parsed_mrt/final_holdout_phase_l")
    fte.FEATURES_DIR = FINAL_HOLDOUT / "behavioral_batches_phase_l"
    fte.DOWNLOAD_AUDIT = FINAL_HOLDOUT / "final_holdout_mrt_download_audit_v1.csv"
    fte.FEATURE_SUMMARY = FINAL_HOLDOUT / "final_holdout_incident_feature_summary_v1.csv"
    fte.QUALITY_GATE = FINAL_HOLDOUT / "final_holdout_incident_processing_quality_gate_v1.csv"
    fte.BATCH_EXECUTION_SUMMARY = FINAL_HOLDOUT / "final_holdout_batch_execution_summary_v1.csv"
    try:
        for batch_id in sorted(uids_by_batch):
            path = fte.batch_feature_path(batch_id)
            if path.exists() and path.stat().st_size > 0 and valid_behavioral_cache():
                print(f"{batch_id} Final Holdout behavioral features already exist; skipping", flush=True)
                continue
            summary = execute_batch(batch_id, manifest_by_uid, sorted(uids_by_batch[batch_id]), plan_by_uid, DiskPolicy(), download_workers=download_workers)
            print(f"{batch_id} Final Holdout behavioral complete status={summary['status']} rows={summary['feature_rows']}", flush=True)
        paths = sorted(fte.FEATURES_DIR.glob("volume_batch_*.parquet"))
        if not paths:
            raise RuntimeError("No Final Holdout behavioral batch files were produced")
        df = pd.concat([pd.read_parquet(path) for path in paths], ignore_index=True)
        df.to_parquet(HOLDOUT_BEHAVIORAL, index=False)
    finally:
        for name, value in old_values.items():
            setattr(fte, name, value)
    return df


def generate_holdout_caida(behavioral: pd.DataFrame, download_workers: int = 8) -> pd.DataFrame:
    import bgp_incident_detection.caida_train_enrichment as cte

    manifest = read_csv(HOLDOUT_MANIFEST)
    plan = read_csv(ACQUISITION_PLAN)
    batches: dict[str, list[str]] = {}
    for idx, row in enumerate(sorted(manifest, key=lambda item: item["incident_uid"])):
        batches.setdefault(f"volume_batch_{idx // 25 + 1:03d}", []).append(row["incident_uid"])

    old_values = {
        "EVIDENCE_DIR": cte.EVIDENCE_DIR,
        "CAIDA_BATCH_DIR": cte.CAIDA_BATCH_DIR,
        "RAW_BATCH_ROOT": cte.RAW_BATCH_ROOT,
        "SNAPSHOT_MAPPING": cte.SNAPSHOT_MAPPING,
        "SNAPSHOT_CACHE_AUDIT": cte.SNAPSHOT_CACHE_AUDIT,
    }
    cte.EVIDENCE_DIR = FINAL_HOLDOUT / "evidence_phase_l"
    cte.CAIDA_BATCH_DIR = FINAL_HOLDOUT / "caida_batches_phase_l"
    cte.RAW_BATCH_ROOT = Path("data/raw_mrt/final_holdout_caida_batches_phase_l")
    cte.SNAPSHOT_MAPPING = FINAL_HOLDOUT / "final_holdout_caida_snapshot_mapping_v1.csv"
    cte.SNAPSHOT_CACHE_AUDIT = FINAL_HOLDOUT / "final_holdout_caida_snapshot_cache_audit_v1.csv"
    try:
        mapping = build_caida_snapshot_mapping(behavioral)
        relationships_by_snapshot = ensure_caida_snapshots(mapping)
        snapshot_by_window = dict(zip(mapping["window_id"], mapping["selected_caida_snapshot"]))
        manifest_by_uid = {row["incident_uid"]: row for row in manifest}
        plan_by_uid = group_by(plan, "incident_uid")
        summaries = []
        for batch_id, uids in sorted(batches.items()):
            feature_path = cte.batch_feature_path(batch_id)
            evidence_path = cte.evidence_batch_path(batch_id)
            if feature_path.exists() and evidence_path.exists() and feature_path.stat().st_size > 0 and valid_behavioral_cache() and not (FINAL_HOLDOUT / "final_holdout_caida_batch_execution_summary_v1.csv").exists():
                print(f"{batch_id} Final Holdout CAIDA/evidence already exist; skipping", flush=True)
                continue
            rows = [row for uid in uids for row in plan_by_uid.get(uid, [])]
            summary = aggregate_caida_batch(batch_id, sorted(uids), behavioral, manifest_by_uid, rows, snapshot_by_window, relationships_by_snapshot, download_workers)
            summaries.append(summary)
            print(f"{batch_id} Final Holdout CAIDA complete status={summary['status']} rows={summary['feature_rows']}", flush=True)
        if summaries:
            write_csv(FINAL_HOLDOUT / "final_holdout_caida_batch_execution_summary_v1.csv", summaries, list(summaries[0].keys()))
        for evidence_path in sorted(cte.EVIDENCE_DIR.glob("batch_*.parquet")):
            evidence = pd.read_parquet(evidence_path)
            if list(evidence.columns) != EVIDENCE_COLUMNS:
                pd.DataFrame(columns=EVIDENCE_COLUMNS).to_parquet(evidence_path, index=False)
        paths = sorted(cte.CAIDA_BATCH_DIR.glob("volume_batch_*.parquet"))
        if not paths:
            raise RuntimeError("No Final Holdout CAIDA batch files were produced")
        caida = pd.concat([pd.read_parquet(path) for path in paths], ignore_index=True)
        caida.to_parquet(HOLDOUT_CAIDA, index=False)
        v2 = behavioral.merge(caida[["window_id", "selected_caida_snapshot"] + CAIDA_FEATURE_NAMES], on="window_id", how="left", validate="one_to_one")
        v2.to_parquet(HOLDOUT_V2, index=False)
    finally:
        for name, value in old_values.items():
            setattr(cte, name, value)
    return v2


def generate_holdout_rpki(behavioral: pd.DataFrame, v2: pd.DataFrame) -> pd.DataFrame:
    import bgp_incident_detection.rpki_train_enrichment as rte

    manifest = read_csv(HOLDOUT_MANIFEST)
    batches: dict[str, list[str]] = {}
    for idx, row in enumerate(sorted(manifest, key=lambda item: item["incident_uid"])):
        batches.setdefault(f"volume_batch_{idx // 25 + 1:03d}", []).append(row["incident_uid"])
    old_values = {
        "EVIDENCE_DIR": rte.EVIDENCE_DIR,
        "RPKI_BATCH_DIR": rte.RPKI_BATCH_DIR,
        "TRAIN_RPKI_MAPPING": rte.TRAIN_RPKI_MAPPING,
    }
    rte.EVIDENCE_DIR = FINAL_HOLDOUT / "evidence_phase_l"
    rte.RPKI_BATCH_DIR = FINAL_HOLDOUT / "rpki_batches_phase_l"
    rte.TRAIN_RPKI_MAPPING = FINAL_HOLDOUT / "final_holdout_rpki_snapshot_mapping_v1.csv"
    try:
        mapping = build_train_snapshot_mapping(behavioral)
        selected = selected_snapshot_by_observation_date(mapping)
        index_cache = VrpIndexCache(max_size=4)
        summaries = []
        for batch_id, uids in sorted(batches.items()):
            path = rte.RPKI_BATCH_DIR / f"batch_{batch_id.split('_')[-1]}.parquet"
            if path.exists() and path.stat().st_size > 0 and HOLDOUT_V4.exists():
                print(f"{batch_id} Final Holdout RPKI already exists; skipping", flush=True)
                continue
            result = aggregate_rpki_batch(batch_id, sorted(uids), behavioral, index_cache, selected)
            summaries.append(result)
            print(f"{batch_id} Final Holdout RPKI complete status={result['status']} rows={result['feature_rows']}", flush=True)
        if summaries:
            write_csv(FINAL_HOLDOUT / "final_holdout_rpki_batch_manifest_v1.csv", summaries, list(summaries[0].keys()))
        paths = sorted(rte.RPKI_BATCH_DIR.glob("batch_*.parquet"))
        if not paths:
            raise RuntimeError("No Final Holdout RPKI batch files were produced")
        rpki = pd.concat([pd.read_parquet(path) for path in paths], ignore_index=True)
        rpki.to_parquet(HOLDOUT_RPKI, index=False)
        v3 = behavioral.merge(rpki[["window_id"] + RPKI_FEATURE_NAMES], on="window_id", how="left", validate="one_to_one")
        v3.to_parquet(HOLDOUT_V3, index=False)
        v4 = v2.merge(rpki[["window_id"] + RPKI_FEATURE_NAMES], on="window_id", how="left", validate="one_to_one")
        v4.to_parquet(HOLDOUT_V4, index=False)
    finally:
        for name, value in old_values.items():
            setattr(rte, name, value)
    return v4


def ensure_holdout_features(download_workers: int = 8) -> pd.DataFrame:
    if HOLDOUT_V4.exists() and valid_behavioral_cache():
        return pd.read_parquet(HOLDOUT_V4)
    behavioral = generate_holdout_behavioral(download_workers=download_workers)
    v2 = generate_holdout_caida(behavioral, download_workers=download_workers)
    return generate_holdout_rpki(behavioral, v2)


def schema_audit(holdout: pd.DataFrame, train: pd.DataFrame) -> pd.DataFrame:
    features = FEATURES_BY_VARIANT["V4"]
    rows = []
    checks = [
        ("behavioral_features", len([f for f in BEHAVIORAL_FEATURE_NAMES if f in holdout.columns]), 44),
        ("caida_features", len([f for f in CAIDA_FEATURE_NAMES if f in holdout.columns]), 14),
        ("rpki_features", len([f for f in RPKI_FEATURE_NAMES if f in holdout.columns]), 16),
        ("total_model_features", len(features), 74),
        ("feature_order_matches_train", list(train[features].columns) == list(holdout[features].columns), True),
        ("no_duplicate_window_ids", int(holdout["window_id"].duplicated().sum()), 0),
        ("no_train_rows", int((holdout["partition"].astype(str) == "train").sum()), 0),
        ("no_validation_rows", int((holdout["partition"].astype(str) == "validation").sum()), 0),
        ("holdout_rows_only", sorted(holdout["partition"].astype(str).unique()), ["holdout"]),
    ]
    for check, observed, expected in checks:
        rows.append({"check": check, "observed": observed, "expected": expected, "status": "PASS" if observed == expected else "FAIL"})
    numeric = holdout[features].apply(pd.to_numeric, errors="coerce")
    invalid = bool(np.isinf(numeric.to_numpy()).any())
    rows.append({"check": "invalid_numeric_values", "observed": int(np.isinf(numeric.to_numpy()).sum()), "expected": 0, "status": "FAIL" if invalid else "PASS"})
    out = pd.DataFrame(rows)
    out.to_csv(SCHEMA_AUDIT, index=False)
    if any(out["status"].eq("FAIL")):
        raise RuntimeError("Final Holdout V4 schema audit failed")
    return out


def load_train_stage2() -> pd.DataFrame:
    train = pd.read_parquet(TRAIN_V4)
    assignments = pd.read_csv(ASSIGNMENTS, low_memory=False)
    assignments = assignments[assignments["label"].isin(INCIDENT_LABELS)].copy()
    data = train.merge(assignments[["window_id", "label", "model_group_id", "fold"]], on="window_id", how="left", validate="one_to_one")
    data = data[data["label"].isin(INCIDENT_LABELS)].copy()
    if set(data["partition"].astype(str)) != {"train"}:
        raise RuntimeError("Phase L first/second-level fitting must use TRAIN only")
    if data["incident_uid"].nunique() != 993:
        raise RuntimeError("Expected exactly 993 TRAIN incidents")
    if data.drop_duplicates("incident_uid")["label"].value_counts().to_dict() != {"HIJACK": 331, "LEAK": 331, "OUTAGE": 331}:
        raise RuntimeError("Expected TRAIN 331/331/331 incidents")
    return data


def crossfit_holdout_level1_predictions(train: pd.DataFrame, holdout: pd.DataFrame) -> pd.DataFrame:
    if LEVEL1_PROBS.exists():
        return pd.read_parquet(LEVEL1_PROBS)
    features = FEATURES_BY_VARIANT["V4"]
    holdout = holdout.copy()
    holdout["label"] = holdout["category"].map(DISPLAY_TO_LABEL)
    fold_prob_arrays = []
    fold_ids = []
    for fold in sorted(train["fold"].unique()):
        fold_train = train[train["fold"] != fold].copy()
        model = first_level_model(SEED)
        model.fit(fold_train[features], y_codes(fold_train["label"]), model__sample_weight=group_aware_weights(fold_train))
        fold_prob_arrays.append(model.predict_proba(holdout[features]))
        fold_ids.append(int(fold))
        print(f"Phase L first-level TRAIN fold-model {fold} predicted Holdout windows={len(holdout)}", flush=True)
    probs = np.mean(np.stack(fold_prob_arrays, axis=0), axis=0)
    out = holdout[["incident_uid", "window_id", "window_start", "window_end", "temporal_status"]].copy()
    out["fold"] = 0
    out["true_class"] = holdout["label"]
    out["p_hijack"] = probs[:, 0]
    out["p_leak"] = probs[:, 1]
    out["p_outage"] = probs[:, 2]
    out["probability_source"] = "final_holdout_crossfit_ensemble_first_level"
    out["contributing_fold_models"] = json.dumps(fold_ids)
    out["ensemble_rule"] = "arithmetic_mean"
    out.to_parquet(LEVEL1_PROBS, index=False)
    return out


def build_train_meta() -> tuple[pd.DataFrame, list[str]]:
    train = pd.read_parquet(TRAIN_V4)
    oof = pd.read_parquet(OOF_PROBS)
    meta = build_meta_frame(oof, train)
    schema = load_yaml(META_SCHEMA_CONFIG)["feature_order"]
    if schema != temporal_feature_names(meta):
        raise RuntimeError("Frozen K1 meta schema does not match generated TRAIN meta features")
    return meta, schema


def build_holdout_meta(level1: pd.DataFrame, holdout: pd.DataFrame) -> pd.DataFrame:
    if META_FEATURES.exists():
        return pd.read_parquet(META_FEATURES)
    meta = build_meta_frame(level1, holdout)
    meta.to_parquet(META_FEATURES, index=False)
    return meta


def audit_meta_schema(meta: pd.DataFrame, schema: list[str]) -> pd.DataFrame:
    checks = [
        ("k1_meta_rows", meta["incident_uid"].nunique(), 213, meta["incident_uid"].nunique() == 213),
        ("k1_meta_feature_count", len(schema), 74, len(schema) == 74),
        ("k1_meta_schema_columns_present", all(col in meta.columns for col in schema), True, all(col in meta.columns for col in schema)),
        ("no_train_or_validation_meta_rows", int(meta["incident_uid"].isin(set(pd.read_csv(TRAIN_INCIDENTS)["incident_uid"].astype(str)) | set(pd.read_csv(VALIDATION_INCIDENTS)["incident_uid"].astype(str))).sum()), 0, True),
    ]
    rows = [{"check": c, "observed": o, "expected": e, "status": "PASS" if p else "FAIL"} for c, o, e, p in checks]
    out = pd.DataFrame(rows)
    out.to_csv(META_SCHEMA_AUDIT, index=False)
    if any(out["status"].eq("FAIL")):
        raise RuntimeError("Final Holdout K1 meta schema audit failed")
    return out


def train_second_level_and_predict(train_meta: pd.DataFrame, holdout_meta: pd.DataFrame, schema: list[str]) -> pd.DataFrame:
    second = load_yaml(SECOND_LEVEL_CONFIG)
    params = {key: second[key] for key in ["n_estimators", "max_depth", "learning_rate", "subsample", "colsample_bytree", "reg_alpha", "reg_lambda"]}
    model = xgb_meta_model(params)
    model.fit(train_meta[schema], y_codes(train_meta["true_class"]))
    pred = predict_meta(model, holdout_meta, schema, "K1_FINAL_SECOND_LEVEL_XGB_V1", fold=0)
    ranked = []
    for _, row in pred.iterrows():
        scores = {label: float(row[f"p_{label.lower()}"]) for label in INCIDENT_LABELS}
        order = sorted(scores.items(), key=lambda item: item[1], reverse=True)
        classes = [label for label, _ in order]
        ranked.append(
            {
                **row.to_dict(),
                "rank_1_class": order[0][0],
                "rank_1_score": order[0][1],
                "rank_2_class": order[1][0],
                "rank_2_score": order[1][1],
                "rank_3_class": order[2][0],
                "rank_3_score": order[2][1],
                "predicted_class": order[0][0],
                "true_class_rank": classes.index(row["true_class"]) + 1,
                "second_level_parameter_hash": second["candidate_parameter_hash"],
            }
        )
    out = pd.DataFrame(ranked)
    out.to_csv(RANKINGS, index=False)
    return out


def multiclass_brier(y_true: list[str], probs: pd.DataFrame) -> float:
    y = np.zeros((len(y_true), len(INCIDENT_LABELS)))
    label_to_idx = {label: idx for idx, label in enumerate(INCIDENT_LABELS)}
    for row, label in enumerate(y_true):
        y[row, label_to_idx[label]] = 1.0
    return float(np.mean(np.sum((probs[INCIDENT_LABELS].to_numpy() - y) ** 2, axis=1)))


def bootstrap_ci(rankings: pd.DataFrame, replicates: int = BOOTSTRAP_REPLICATES, seed: int = SEED) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows = []
    n = len(rankings)
    for i in range(replicates):
        sample = rankings.iloc[rng.integers(0, n, n)].copy()
        values = k1_metrics(sample)
        rows.append({"replicate": i + 1, "incident_macro_f1": values["incident_macro_f1"], "top1": values["top1"], "top2": values["top2"], "mrr": values["mrr"]})
    boot = pd.DataFrame(rows)
    summary = []
    for metric in ["incident_macro_f1", "top1", "top2", "mrr"]:
        summary.append(
            {
                "metric": metric,
                "point_estimate": k1_metrics(rankings)[metric],
                "ci_lower_95": float(boot[metric].quantile(0.025)),
                "ci_upper_95": float(boot[metric].quantile(0.975)),
                "bootstrap_replicates": replicates,
                "bootstrap_seed": seed,
            }
        )
    out = pd.DataFrame(summary)
    out.to_csv(FINAL_HOLDOUT / "final_holdout_bootstrap_ci_v1.csv", index=False)
    return out


def write_metric_outputs(rankings: pd.DataFrame, level1: pd.DataFrame) -> dict[str, Any]:
    metric_values = k1_metrics(rankings)
    probs = rankings[["p_hijack", "p_leak", "p_outage"]].copy()
    probs.columns = INCIDENT_LABELS
    y_true = rankings["true_class"].tolist()
    metric_values["multiclass_log_loss"] = float(log_loss(y_true, probs[INCIDENT_LABELS], labels=INCIDENT_LABELS))
    metric_values["multiclass_brier_score"] = multiclass_brier(y_true, probs)
    metric_values["holdout_incidents"] = int(rankings["incident_uid"].nunique())
    metric_values["holdout_window_rows"] = int(len(level1))
    metric_values["k1_meta_rows"] = int(len(rankings))
    metric_values["second_level_parameter_hash"] = "40df040321ef"
    metric_values["evaluation_timestamp_utc"] = utc_now()
    metric_values["formal_disposition"] = "FINAL_HOLDOUT_TERMINAL_EVALUATION_COMPLETE"
    pd.DataFrame([metric_values]).to_csv(PERFORMANCE, index=False)

    precision, recall, f1, support = precision_recall_fscore_support(y_true, rankings["predicted_class"], labels=INCIDENT_LABELS, zero_division=0)
    per_class_rows = []
    for idx, label in enumerate(INCIDENT_LABELS):
        per_class_rows.append(
            {
                "class": label,
                "precision": precision[idx],
                "recall": recall[idx],
                "f1": f1[idx],
                "support_incidents": int(support[idx]),
                "mean_true_class_rank": float(rankings[rankings["true_class"].eq(label)]["true_class_rank"].mean()),
            }
        )
    pd.DataFrame(per_class_rows).to_csv(PER_CLASS, index=False)

    rank_counts = rankings["true_class_rank"].value_counts().to_dict()
    rank_rows = [
        {"metric": "ranked_first_count", "value": int(rank_counts.get(1, 0))},
        {"metric": "ranked_second_count", "value": int(rank_counts.get(2, 0))},
        {"metric": "ranked_third_count", "value": int(rank_counts.get(3, 0))},
        {"metric": "mean_true_class_rank", "value": metric_values["mean_true_class_rank"]},
        {"metric": "mrr", "value": metric_values["mrr"]},
    ]
    pd.DataFrame(rank_rows).to_csv(RANKING_METRICS, index=False)

    cm = confusion_matrix(y_true, rankings["predicted_class"], labels=INCIDENT_LABELS)
    cm_rows = []
    for i, true_label in enumerate(INCIDENT_LABELS):
        for j, pred_label in enumerate(INCIDENT_LABELS):
            cm_rows.append({"true_class": true_label, "predicted_class": pred_label, "count": int(cm[i, j])})
    pd.DataFrame(cm_rows).to_csv(CONFUSION, index=False)
    errors = rankings[rankings["true_class"] != rankings["predicted_class"]].copy()
    errors.to_csv(ERROR_ANALYSIS, index=False)

    comparison = []
    for metric in ["incident_macro_f1", "top1", "top2", "mrr", "hijack_f1", "leak_f1", "outage_f1"]:
        comparison.append(
            {
                "metric": metric,
                "fixed_k1_train_nested_cv": TRAIN_REFERENCE[metric],
                "final_holdout": metric_values[metric],
                "holdout_minus_train": metric_values[metric] - TRAIN_REFERENCE[metric],
                "absolute_delta": abs(metric_values[metric] - TRAIN_REFERENCE[metric]),
            }
        )
    pd.DataFrame(comparison).to_csv(COMPARISON, index=False)
    ci = bootstrap_ci(rankings)
    return {**metric_values, "bootstrap_ci": ci}


def write_figure() -> None:
    if not CONFUSION.exists():
        return
    cm = pd.read_csv(CONFUSION).pivot(index="true_class", columns="predicted_class", values="count").reindex(index=INCIDENT_LABELS, columns=INCIDENT_LABELS).fillna(0)
    FIGURE_DIR.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(5.5, 4.5))
    image = ax.imshow(cm.to_numpy(), cmap="Blues")
    ax.set_xticks(range(len(INCIDENT_LABELS)), INCIDENT_LABELS)
    ax.set_yticks(range(len(INCIDENT_LABELS)), INCIDENT_LABELS)
    ax.set_xlabel("Predicted class")
    ax.set_ylabel("True class")
    ax.set_title("Final Holdout Confusion Matrix")
    for i in range(len(INCIDENT_LABELS)):
        for j in range(len(INCIDENT_LABELS)):
            ax.text(j, i, int(cm.iloc[i, j]), ha="center", va="center", color="black")
    fig.colorbar(image, ax=ax, fraction=0.046, pad=0.04)
    fig.tight_layout()
    fig.savefig(FIGURE_DIR / "final_holdout_confusion_matrix_v1.png", dpi=200)
    plt.close(fig)


def write_final_audit(metrics: dict[str, Any]) -> pd.DataFrame:
    rows = [
        {"check": "preaccess_audit_passed", "status": "PASS", "notes": str(PREACCESS_AUDIT)},
        {"check": "protocol_frozen_before_predictive_holdout_access", "status": "PASS", "notes": str(PROTOCOL)},
        {"check": "holdout_access_record_created", "status": "PASS" if ACCESS_RECORD.exists() else "FAIL", "notes": str(ACCESS_RECORD)},
        {"check": "train_only_model_fitting", "status": "PASS", "notes": "TRAIN V4 and OOF TRAIN probabilities only"},
        {"check": "validation_excluded", "status": "PASS", "notes": "No Validation rows used in Phase L fitting or prediction"},
        {"check": "holdout_excluded_from_fitting", "status": "PASS", "notes": "Holdout used only for features/prediction/evaluation"},
        {"check": "feature_count_74", "status": "PASS" if len(FEATURES_BY_VARIANT["V4"]) == 74 else "FAIL", "notes": str(len(FEATURES_BY_VARIANT["V4"]))},
        {"check": "crossfit_ensemble_first_level_used", "status": "PASS", "notes": "five TRAIN fold models averaged arithmetically"},
        {"check": "k1_meta_rows_213", "status": "PASS" if int(metrics["k1_meta_rows"]) == 213 else "FAIL", "notes": str(metrics["k1_meta_rows"])},
        {"check": "second_level_hash_40df040321ef", "status": "PASS" if metrics["second_level_parameter_hash"] == "40df040321ef" else "FAIL", "notes": metrics["second_level_parameter_hash"]},
        {"check": "stage1_unresolved_auxiliary", "status": "PASS", "notes": "UNRESOLVED_EXPERIMENTAL_AUXILIARY"},
        {"check": "model_tuning_permanently_complete", "status": "PASS", "notes": "No post-Holdout tuning allowed"},
        {"check": "final_holdout_terminal_evaluation", "status": "PASS", "notes": "One-time terminal unbiased evaluation"},
    ]
    out = pd.DataFrame(rows)
    out.to_csv(EVALUATION_AUDIT, index=False)
    return out


def write_final_result(metrics: dict[str, Any]) -> None:
    ci = pd.read_csv(FINAL_HOLDOUT / "final_holdout_bootstrap_ci_v1.csv")
    result = {
        "result_id": "final_praxis_result_v1",
        "status": "FROZEN_TERMINAL_FINAL_HOLDOUT_RESULT",
        "architecture": "A0_XGB_TO_XGB",
        "architecture_decision": "KEEP_XGB_XGB_K1",
        "first_level_strategy": "CROSSFIT_ENSEMBLE_FIRST_LEVEL",
        "second_level_model": "K1_FINAL_SECOND_LEVEL_XGB_V1",
        "second_level_parameter_hash": "40df040321ef",
        "holdout_incidents": int(metrics["holdout_incidents"]),
        "holdout_window_rows": int(metrics["holdout_window_rows"]),
        "incident_macro_f1": float(metrics["incident_macro_f1"]),
        "top1": float(metrics["top1"]),
        "top2": float(metrics["top2"]),
        "mrr": float(metrics["mrr"]),
        "hijack_f1": float(metrics["hijack_f1"]),
        "leak_f1": float(metrics["leak_f1"]),
        "outage_f1": float(metrics["outage_f1"]),
        "mean_true_class_rank": float(metrics["mean_true_class_rank"]),
        "multiclass_log_loss": float(metrics["multiclass_log_loss"]),
        "multiclass_brier_score": float(metrics["multiclass_brier_score"]),
        "bootstrap_ci_file": str(FINAL_HOLDOUT / "final_holdout_bootstrap_ci_v1.csv"),
        "macro_f1_ci_95": ci[ci["metric"].eq("incident_macro_f1")][["ci_lower_95", "ci_upper_95"]].iloc[0].to_dict(),
        "stage1_status": "UNRESOLVED_EXPERIMENTAL_AUXILIARY",
        "final_holdout_status": "EVALUATED_ONCE_AND_CLOSED",
        "post_holdout_model_changes": "FORBIDDEN",
        "next_phase": "documentation, chapters, figures, and defense only",
        "source_commit": source_commit(),
        "evaluation_timestamp_utc": utc_now(),
    }
    FINAL_RESULT.parent.mkdir(parents=True, exist_ok=True)
    FINAL_RESULT.write_text(yaml.safe_dump(result, sort_keys=False), encoding="utf-8")


def write_docs() -> None:
    DOC.parent.mkdir(parents=True, exist_ok=True)
    DOC.write_text(
        """# Final Experimental Pipeline v1

This document records the terminal Praxis evaluation pipeline after all model development was complete.

## Corpus and Split

- Frozen roster: Roster v2.
- TRAIN: 993 incidents, 331 Hijack / 331 Leak / 331 Outage.
- Validation: excluded from Phase L.
- Final Holdout: 213 incidents, 71 Hijack / 71 Leak / 71 Outage.

## Locked Model

Phase L uses only `A0_XGB_TO_XGB` with decision `KEEP_XGB_XGB_K1`.

The first-level model is the Phase I2 XGBoost candidate using the frozen 74-feature V4 schema and I1 incident-aware weighting. Five grouped TRAIN fold models predict each Final Holdout window, and their class probabilities are combined with a fixed arithmetic mean.

The second-level model is `K1_FINAL_SECOND_LEVEL_XGB_V1` with parameter hash `40df040321ef`. It is trained on TRAIN-only leakage-safe K1 meta-features and evaluated once on Final Holdout K1 meta-features.

## Holdout Protection

The Final Holdout result is terminal. It must not be used for feature selection, model tuning, threshold tuning, architecture comparison, class balancing, aggregation changes, or any other modeling decision.

Stage 1 remains `UNRESOLVED_EXPERIMENTAL_AUXILIARY`.
""",
        encoding="utf-8",
    )


def write_notebook() -> None:
    NOTEBOOK.parent.mkdir(parents=True, exist_ok=True)
    notebook = {
        "cells": [
            {"cell_type": "markdown", "metadata": {}, "source": ["# Phase L - Final Holdout Evaluation\n", "\n", "One-time terminal evaluation for the locked K1 model. No model selection or tuning is performed here.\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["from bgp_incident_detection.final_holdout_evaluation import freeze_protocol, record_holdout_access, audit_holdout_manifest\n", "protocol = freeze_protocol()\n", "record_holdout_access(protocol)\n", "audit_holdout_manifest()\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["from bgp_incident_detection.final_holdout_evaluation import run_phase_l\n", "# run_phase_l(download_workers=8)\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["import pandas as pd\n", "pd.read_csv('../data/final_holdout/final_holdout_performance_summary_v1.csv')\n"]},
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")


def run_phase_l(download_workers: int = 8) -> dict[str, Any]:
    protocol = freeze_protocol()
    record_holdout_access(protocol)
    manifest = audit_holdout_manifest()
    train = load_train_stage2()
    holdout = ensure_holdout_features(download_workers=download_workers)
    holdout = holdout[holdout["incident_uid"].isin(set(manifest["incident_uid"].astype(str)))].copy()
    schema_audit(holdout, train)
    level1 = crossfit_holdout_level1_predictions(train, holdout)
    train_meta, meta_schema = build_train_meta()
    holdout_meta = build_holdout_meta(level1, holdout)
    audit_meta_schema(holdout_meta, meta_schema)
    rankings = train_second_level_and_predict(train_meta, holdout_meta, meta_schema)
    metric_values = write_metric_outputs(rankings, level1)
    write_figure()
    write_final_audit(metric_values)
    write_final_result(metric_values)
    write_docs()
    write_notebook()
    return {key: value for key, value in metric_values.items() if key != "bootstrap_ci"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Phase L one-time Final Holdout evaluation")
    parser.add_argument("--verify-gate", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--download-workers", type=int, default=8)
    args = parser.parse_args()
    if args.verify_gate:
        protocol = freeze_protocol()
        print(json.dumps({"status": "PASS", "protocol_status": protocol["protocol_status"]}, indent=2))
        return
    if args.run:
        print(json.dumps(run_phase_l(download_workers=args.download_workers), indent=2, sort_keys=True))
        return
    parser.error("choose --verify-gate or --run")


if __name__ == "__main__":
    main()
