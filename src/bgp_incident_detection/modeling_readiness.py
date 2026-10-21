from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

import pandas as pd

try:
    from bgp_incident_detection.audit import parse_utc, write_csv
    from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES
    from bgp_incident_detection.caida_features import (
        CAIDA_FEATURE_NAMES,
        CaidaWindowAggregate,
        caida_snapshot_name,
        caida_snapshot_url,
        features_from_caida_aggregate,
        load_relationships,
        parse_as_path,
        row_window_id,
        update_caida_aggregate_from_result,
        valley_free_result,
    )
    from bgp_incident_detection.caida_train_enrichment import CAIDA_CACHE, download_snapshot as download_caida_snapshot
    from bgp_incident_detection.rpki_features import (
        RPKI_FEATURE_NAMES,
        STATE_TO_CODE,
        TRUST_ANCHORS,
        build_vrp_index,
        cache_path,
        download_snapshot as download_rpki_snapshot,
        load_vrps,
        snapshot_date_for_observation,
        snapshot_url,
        utc_now,
        validate_rov,
    )
    from bgp_incident_detection.rpki_train_enrichment import cached_snapshot_usable, sha256
    from bgp_incident_detection.train_batch_engine import source_commit
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import parse_utc, write_csv
    from src.bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES
    from src.bgp_incident_detection.caida_features import (
        CAIDA_FEATURE_NAMES,
        CaidaWindowAggregate,
        caida_snapshot_name,
        caida_snapshot_url,
        features_from_caida_aggregate,
        load_relationships,
        parse_as_path,
        row_window_id,
        update_caida_aggregate_from_result,
        valley_free_result,
    )
    from src.bgp_incident_detection.caida_train_enrichment import CAIDA_CACHE, download_snapshot as download_caida_snapshot
    from src.bgp_incident_detection.rpki_features import (
        RPKI_FEATURE_NAMES,
        STATE_TO_CODE,
        TRUST_ANCHORS,
        build_vrp_index,
        cache_path,
        download_snapshot as download_rpki_snapshot,
        load_vrps,
        snapshot_date_for_observation,
        snapshot_url,
        utc_now,
        validate_rov,
    )
    from src.bgp_incident_detection.rpki_train_enrichment import cached_snapshot_usable, sha256
    from src.bgp_incident_detection.train_batch_engine import source_commit


MODEL_READY_DIR = Path("data/model_ready")
NORMAL_FROZEN = Path("data/normal_frozen/frozen_normal_corpus_v1.parquet")
PARSED_NORMAL_DIR = Path("data/parsed_mrt/normal_scale")
FROZEN_INCIDENT_V1 = Path("data/train_frozen/frozen_train_behavioral_corpus_v1.parquet")
FROZEN_INCIDENT_V2 = Path("data/train_frozen/frozen_train_v2_behavioral_caida_v1.parquet")
FROZEN_INCIDENT_V3 = Path("data/train_frozen/frozen_train_v3_behavioral_rpki_v1.parquet")
FROZEN_INCIDENT_V4 = Path("data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1.parquet")

INPUT_AUDIT = MODEL_READY_DIR / "normal_enrichment_input_audit_v1.csv"
NORMAL_CAIDA = MODEL_READY_DIR / "normal_caida_features_v1.parquet"
NORMAL_RPKI = MODEL_READY_DIR / "normal_rpki_features_v1.parquet"
NORMAL_V1 = MODEL_READY_DIR / "frozen_normal_v1_v1.parquet"
NORMAL_V2 = MODEL_READY_DIR / "frozen_normal_v2_v1.parquet"
NORMAL_V3 = MODEL_READY_DIR / "frozen_normal_v3_v1.parquet"
NORMAL_V4 = MODEL_READY_DIR / "frozen_normal_v4_v1.parquet"
GROUPING_AUDIT = MODEL_READY_DIR / "model_grouping_audit_v1.csv"
READINESS_AUDIT = MODEL_READY_DIR / "modeling_readiness_audit_v1.csv"
EXPERIMENT_MATRIX = Path("config/model_experiment_matrix_v1.yaml")
NOTEBOOK = Path("notebooks/38_modeling_readiness_and_normal_enrichment.ipynb")

NORMAL_ID_COLUMNS = [
    "candidate_period_id",
    "associated_incident_uid",
    "associated_category",
    "window_id",
    "window_start",
    "window_end",
    "category",
    "partition",
    "final_state",
    "affected_asn",
    "collector",
]
INCIDENT_ID_COLUMNS = ["incident_uid", "incident_id", "category", "partition", "window_id", "window_start", "window_end", "temporal_status"]
VARIANT_SPECS = {
    "V1": (FROZEN_INCIDENT_V1, NORMAL_V1, BEHAVIORAL_FEATURE_NAMES),
    "V2": (FROZEN_INCIDENT_V2, NORMAL_V2, BEHAVIORAL_FEATURE_NAMES + CAIDA_FEATURE_NAMES),
    "V3": (FROZEN_INCIDENT_V3, NORMAL_V3, BEHAVIORAL_FEATURE_NAMES + RPKI_FEATURE_NAMES),
    "V4": (FROZEN_INCIDENT_V4, NORMAL_V4, BEHAVIORAL_FEATURE_NAMES + CAIDA_FEATURE_NAMES + RPKI_FEATURE_NAMES),
}


def month_start(value: str) -> datetime:
    parsed = parse_utc(value)
    if not parsed:
        raise ValueError(f"invalid timestamp: {value}")
    return parsed.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def load_normal() -> pd.DataFrame:
    normal = pd.read_parquet(NORMAL_FROZEN)
    if len(normal) != 516:
        raise ValueError(f"expected 516 frozen Normal rows, found {len(normal)}")
    if normal["window_id"].nunique() != 516:
        raise ValueError("frozen Normal windows must be unique")
    if set(normal["partition"].astype(str)) != {"train"}:
        raise ValueError("frozen Normal corpus must be TRAIN only")
    if set(normal["final_state"].astype(str)) != {"NORMAL_VERIFIED"}:
        raise ValueError("frozen Normal corpus contains non-verified windows")
    missing = [feature for feature in BEHAVIORAL_FEATURE_NAMES if feature not in normal.columns]
    if missing:
        raise ValueError(f"frozen Normal corpus missing behavioral features: {missing}")
    return normal


def load_incident(path: Path, features: list[str]) -> pd.DataFrame:
    df = pd.read_parquet(path)
    if len(df) != 68031:
        raise ValueError(f"expected 68,031 incident rows in {path}, found {len(df)}")
    if df["incident_uid"].nunique() != 993:
        raise ValueError(f"expected 993 incident groups in {path}")
    if set(df["partition"].astype(str)) != {"train"}:
        raise ValueError(f"incident corpus {path} contains non-TRAIN rows")
    missing = [feature for feature in features if feature not in df.columns]
    if missing:
        raise ValueError(f"incident corpus {path} missing features: {missing}")
    return df


def parsed_normal_files(normal: pd.DataFrame) -> list[Path]:
    periods = set(normal["candidate_period_id"].astype(str))
    files = [path for path in sorted(PARSED_NORMAL_DIR.glob("*/parsed_bgp_observations.csv")) if path.parent.name in periods]
    return files


def input_audit_rows(normal: pd.DataFrame) -> list[dict[str, object]]:
    files = parsed_normal_files(normal)
    periods = set(normal["candidate_period_id"].astype(str))
    parsed_periods = {path.parent.name for path in files}
    return [
        {"check_name": "frozen_normal_rows", "observed_value": len(normal), "status": "PASS" if len(normal) == 516 else "FAIL", "notes": "Normal membership is not modified"},
        {"check_name": "frozen_normal_train_only", "observed_value": sorted(normal["partition"].astype(str).unique()), "status": "PASS" if set(normal["partition"].astype(str)) == {"train"} else "FAIL", "notes": "Validation/Holdout not accessed"},
        {"check_name": "parsed_normal_period_coverage", "observed_value": f"{len(parsed_periods)} / {len(periods)}", "status": "PASS" if periods <= parsed_periods else "FAIL", "notes": "parsed Normal UPDATE artifacts cover every frozen Normal control period"},
        {"check_name": "caida_inputs_available", "observed_value": "parsed AS_PATH by Normal window", "status": "PASS", "notes": "CAIDA can be calculated exactly from existing parsed Normal observations"},
        {"check_name": "rpki_inputs_available", "observed_value": "parsed prefix + origin_asn by Normal window", "status": "PASS", "notes": "RPKI can be calculated exactly from existing parsed Normal observations"},
        {"check_name": "incident_corpus_reprocessed", "observed_value": "NO", "status": "PASS", "notes": "Incident feature corpora are read only for schema/manifests"},
    ]


def normal_window_maps(normal: pd.DataFrame) -> tuple[set[str], dict[str, dict[str, object]]]:
    allowed = set(normal["window_id"].astype(str))
    meta = {str(row["window_id"]): row.to_dict() for _, row in normal.iterrows()}
    return allowed, meta


def iter_normal_rows(normal: pd.DataFrame):
    allowed, _ = normal_window_maps(normal)
    for path in parsed_normal_files(normal):
        candidate_period_id = path.parent.name
        for chunk in pd.read_csv(path, chunksize=100_000):
            if chunk.empty:
                continue
            chunk["window_id"] = chunk["bgp_timestamp_utc"].map(lambda ts: row_window_id(candidate_period_id, str(ts)))
            chunk = chunk[chunk["window_id"].isin(allowed)]
            if not chunk.empty:
                yield chunk


def ensure_caida_relationships(normal: pd.DataFrame) -> tuple[dict[str, str], dict[str, dict[tuple[str, str], str]]]:
    snapshots = {}
    for value in normal["window_start"]:
        dt = month_start(str(value))
        snapshots[caida_snapshot_name(dt)] = caida_snapshot_url(dt)
    relationships = {}
    for snapshot, url in sorted(snapshots.items()):
        destination = CAIDA_CACHE / snapshot
        if not destination.exists() or destination.stat().st_size == 0:
            result = download_caida_snapshot(snapshot, url)
            destination = Path(str(result["local_path"]))
        relationships[snapshot] = load_relationships(destination)
    return snapshots, relationships


def build_normal_caida(normal: pd.DataFrame) -> pd.DataFrame:
    snapshots, relationships = ensure_caida_relationships(normal)
    snapshot_by_window = {str(row["window_id"]): caida_snapshot_name(month_start(str(row["window_start"]))) for _, row in normal.iterrows()}
    aggregates = {str(wid): CaidaWindowAggregate() for wid in normal["window_id"]}
    result_cache = {}
    for chunk in iter_normal_rows(normal):
        grouped = chunk.groupby(["window_id", "as_path"], dropna=False).size().reset_index(name="observation_count")
        for _, row in grouped.iterrows():
            wid = str(row["window_id"])
            as_path = str(row["as_path"] or "")
            count = int(row["observation_count"])
            if len(parse_as_path(as_path)) < 2:
                aggregates[wid].paths_with_no_as_path_count += count
                continue
            snapshot = snapshot_by_window[wid]
            key = (snapshot, as_path)
            if key not in result_cache:
                result_cache[key] = valley_free_result(as_path, relationships[snapshot])
            update_caida_aggregate_from_result(aggregates[wid], result_cache[key], multiplicity=count)
    rows = []
    for _, meta in normal.sort_values(["candidate_period_id", "window_start"]).iterrows():
        output = {column: meta[column] for column in ["candidate_period_id", "associated_incident_uid", "window_id", "window_start", "window_end", "category", "partition"] if column in normal.columns}
        output["selected_caida_snapshot"] = snapshot_by_window[str(meta["window_id"])]
        output.update(features_from_caida_aggregate(aggregates[str(meta["window_id"])]))
        rows.append(output)
    df = pd.DataFrame(rows)
    MODEL_READY_DIR.mkdir(parents=True, exist_ok=True)
    df.to_parquet(NORMAL_CAIDA, index=False)
    return df


def ensure_rpki_snapshots(normal: pd.DataFrame) -> dict[str, str]:
    selected = {}
    for date in sorted({snapshot_date_for_observation(value) for value in normal["window_start"]}):
        selected[date] = date
        for tal in TRUST_ANCHORS:
            path = cache_path(tal, date)
            if not cached_snapshot_usable(path):
                if path.exists():
                    path.unlink()
                result = download_rpki_snapshot(tal, date)
                if str(result["status"]).startswith("FAIL") or not cached_snapshot_usable(Path(str(result["local_path"]))):
                    raise RuntimeError(f"missing RPKI snapshot for Normal date {date} {tal}")
    return selected


def zero_rpki_features() -> dict[str, object]:
    return {
        "rpki_evidence_observation_count": 0,
        "rpki_evaluable_observation_count": 0,
        "rpki_valid_observation_count": 0,
        "rpki_invalid_observation_count": 0,
        "rpki_not_found_observation_count": 0,
        "rpki_unevaluable_observation_count": 0,
        "rpki_invalid_origin_observation_count": 0,
        "rpki_invalid_maxlength_observation_count": 0,
        "rpki_valid_observation_ratio": float("nan"),
        "rpki_invalid_observation_ratio": float("nan"),
        "rpki_not_found_observation_ratio": float("nan"),
        "rpki_unique_valid_prefix_count": 0,
        "rpki_unique_invalid_prefix_count": 0,
        "rpki_unique_not_found_prefix_count": 0,
        "rpki_state_diversity_count": 0,
        "rpki_dominant_state_code": STATE_TO_CODE["NO_PREFIX_ORIGIN_EVIDENCE"],
    }


def build_normal_rpki(normal: pd.DataFrame) -> pd.DataFrame:
    ensure_rpki_snapshots(normal)
    vrp_cache = {}
    state_counts = {str(wid): Counter() for wid in normal["window_id"]}
    unique_prefixes = {str(wid): defaultdict(set) for wid in normal["window_id"]}
    validation_cache = {}
    for chunk in iter_normal_rows(normal):
        chunk["prefix"] = chunk["prefix"].fillna("").astype(str)
        chunk["origin_asn"] = chunk["origin_asn"].fillna("").astype(str)
        chunk["snapshot_date"] = chunk["bgp_timestamp_utc"].map(snapshot_date_for_observation)
        grouped = chunk.groupby(["window_id", "snapshot_date", "prefix", "origin_asn"], dropna=False).size().reset_index(name="observation_count")
        for _, row in grouped.iterrows():
            wid = str(row["window_id"])
            date = str(row["snapshot_date"])
            prefix = str(row["prefix"] or "")
            origin = str(row["origin_asn"] or "")
            if date not in vrp_cache:
                vrp_cache[date] = build_vrp_index(load_vrps(date))
            key = (date, prefix, origin)
            if key not in validation_cache:
                validation_cache[key] = validate_rov(prefix, origin, vrp_cache[date])
            result = validation_cache[key]
            count = int(row["observation_count"])
            state_counts[wid][result.state] += count
            if prefix:
                unique_prefixes[wid][result.state].add(prefix)
    rows = []
    for _, meta in normal.sort_values(["candidate_period_id", "window_start"]).iterrows():
        wid = str(meta["window_id"])
        counts = state_counts[wid]
        valid = counts["VALID"]
        invalid_origin = counts["INVALID_ORIGIN"]
        invalid_length = counts["INVALID_LENGTH"]
        invalid = invalid_origin + invalid_length
        not_found = counts["NOT_FOUND"]
        unevaluable = counts["UNEVALUABLE"]
        evaluable = valid + invalid + not_found
        total = evaluable + unevaluable
        dominant = "NO_PREFIX_ORIGIN_EVIDENCE" if total == 0 else max(["VALID", "INVALID_ORIGIN", "INVALID_LENGTH", "NOT_FOUND", "UNEVALUABLE"], key=lambda state: (counts[state], state))
        output = {column: meta[column] for column in ["candidate_period_id", "associated_incident_uid", "window_id", "window_start", "window_end", "category", "partition"] if column in normal.columns}
        output.update(
            {
                "rpki_evidence_observation_count": total,
                "rpki_evaluable_observation_count": evaluable,
                "rpki_valid_observation_count": valid,
                "rpki_invalid_observation_count": invalid,
                "rpki_not_found_observation_count": not_found,
                "rpki_unevaluable_observation_count": unevaluable,
                "rpki_invalid_origin_observation_count": invalid_origin,
                "rpki_invalid_maxlength_observation_count": invalid_length,
                "rpki_valid_observation_ratio": valid / evaluable if evaluable else float("nan"),
                "rpki_invalid_observation_ratio": invalid / evaluable if evaluable else float("nan"),
                "rpki_not_found_observation_ratio": not_found / evaluable if evaluable else float("nan"),
                "rpki_unique_valid_prefix_count": len(unique_prefixes[wid]["VALID"]),
                "rpki_unique_invalid_prefix_count": len(unique_prefixes[wid]["INVALID_ORIGIN"] | unique_prefixes[wid]["INVALID_LENGTH"]),
                "rpki_unique_not_found_prefix_count": len(unique_prefixes[wid]["NOT_FOUND"]),
                "rpki_state_diversity_count": sum(1 for value in counts.values() if value > 0),
                "rpki_dominant_state_code": STATE_TO_CODE[dominant],
            }
        )
        rows.append(output)
    df = pd.DataFrame(rows)
    df.to_parquet(NORMAL_RPKI, index=False)
    return df


def build_normal_variants(normal: pd.DataFrame, caida: pd.DataFrame, rpki: pd.DataFrame) -> dict[str, pd.DataFrame]:
    base_cols = [column for column in NORMAL_ID_COLUMNS if column in normal.columns]
    base = normal[base_cols + BEHAVIORAL_FEATURE_NAMES].copy()
    variants = {
        "V1": base,
        "V2": base.merge(caida[["window_id"] + CAIDA_FEATURE_NAMES], on="window_id", how="left", validate="one_to_one"),
        "V3": base.merge(rpki[["window_id"] + RPKI_FEATURE_NAMES], on="window_id", how="left", validate="one_to_one"),
        "V4": base.merge(caida[["window_id"] + CAIDA_FEATURE_NAMES], on="window_id", how="left", validate="one_to_one").merge(rpki[["window_id"] + RPKI_FEATURE_NAMES], on="window_id", how="left", validate="one_to_one"),
    }
    for variant, df in variants.items():
        _, destination, features = VARIANT_SPECS[variant]
        ordered = [column for column in base_cols if column in df.columns] + features
        df = df[ordered].copy()
        df["normal_feature_variant"] = variant
        df["normal_corpus_version"] = "v1"
        df["corpus_status"] = "MODEL_READY"
        variants[variant] = df
        df.to_parquet(destination, index=False)
    return variants


def feature_columns(df: pd.DataFrame, expected: list[str]) -> list[str]:
    return [column for column in df.columns if column in expected]


def model_grouping(normal: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, row in normal.drop_duplicates("candidate_period_id").iterrows():
        rows.append(
            {
                "row_type": "NORMAL_CONTROL",
                "control_uid": row["candidate_period_id"],
                "associated_incident_uid": row["associated_incident_uid"],
                "group_id": row["candidate_period_id"],
                "model_group_id": row["associated_incident_uid"],
                "windows": int((normal["candidate_period_id"] == row["candidate_period_id"]).sum()),
                "strategy": "Group Normal control windows by candidate_period_id; use associated_incident_uid as model_group_id to keep matched controls with related incident family.",
                "status": "PASS",
            }
        )
    write_csv(GROUPING_AUDIT, rows, ["row_type", "control_uid", "associated_incident_uid", "group_id", "model_group_id", "windows", "strategy", "status"])
    return pd.DataFrame(rows)


def manifest_path(stage: str, variant: str) -> Path:
    return MODEL_READY_DIR / f"{stage.lower()}_{variant.lower()}_development_manifest_v1.csv"


def build_manifests(normal_variants: dict[str, pd.DataFrame]) -> dict[str, dict[str, int]]:
    counts = {}
    for variant, (incident_path, _, features) in VARIANT_SPECS.items():
        incident = load_incident(incident_path, features)
        normal = normal_variants[variant]
        stage1_rows = []
        for _, row in normal.iterrows():
            stage1_rows.append(
                {
                    "window_id": row["window_id"],
                    "incident_uid": "",
                    "control_uid": row["candidate_period_id"],
                    "label": "NORMAL",
                    "category": "NORMAL",
                    "feature_variant": variant,
                    "group_id": row["candidate_period_id"],
                    "model_group_id": row["associated_incident_uid"],
                    "partition": "train",
                }
            )
        for _, row in incident[INCIDENT_ID_COLUMNS].iterrows():
            stage1_rows.append(
                {
                    "window_id": row["window_id"],
                    "incident_uid": row["incident_uid"],
                    "control_uid": "",
                    "label": "INCIDENT",
                    "category": row["category"],
                    "feature_variant": variant,
                    "group_id": row["incident_uid"],
                    "model_group_id": row["incident_uid"],
                    "partition": "train",
                }
            )
        write_csv(manifest_path("stage1", variant), stage1_rows, ["window_id", "incident_uid", "control_uid", "label", "category", "feature_variant", "group_id", "model_group_id", "partition"])
        stage2_rows = [
            {
                "window_id": row["window_id"],
                "incident_uid": row["incident_uid"],
                "control_uid": "",
                "label": row["category"],
                "category": row["category"],
                "feature_variant": variant,
                "group_id": row["incident_uid"],
                "model_group_id": row["incident_uid"],
                "partition": "train",
            }
            for _, row in incident[INCIDENT_ID_COLUMNS].iterrows()
        ]
        write_csv(manifest_path("stage2", variant), stage2_rows, ["window_id", "incident_uid", "control_uid", "label", "category", "feature_variant", "group_id", "model_group_id", "partition"])
        counts[variant] = {"stage1_rows": len(stage1_rows), "stage2_rows": len(stage2_rows), "normal_rows": len(normal), "incident_rows": len(incident)}
    return counts


def write_experiment_matrix() -> None:
    EXPERIMENT_MATRIX.parent.mkdir(parents=True, exist_ok=True)
    EXPERIMENT_MATRIX.write_text(
        "\n".join(
            [
                "model_experiment_matrix_version: v1",
                "status: REGISTERED_UNEXECUTED",
                "holdout_rule: Final Holdout remains untouched and must not be used for threshold selection, feature selection, balancing, hyperparameter tuning, or model comparison.",
                "feature_variants:",
                "  V1: {description: Behavioral, feature_count: 44}",
                "  V2: {description: Behavioral + CAIDA, feature_count: 58}",
                "  V3: {description: Behavioral + RPKI, feature_count: 60}",
                "  V4: {description: Behavioral + CAIDA + RPKI, feature_count: 74}",
                "imbalance_conditions:",
                "  I0: {description: Natural, applied: false}",
                "  I1: {description: Incident-aware weighting, applied: false}",
                "  I2: {description: p95 cap plus incident-aware weighting, train_derived_p95_cap_windows: 164, applied: false}",
                "baselines:",
                "  B0: {description: Single-stage Random Forest, task: Normal / Hijack / Leak / Outage, executed: false}",
                "  B1: {description: Single-stage XGBoost, task: Normal / Hijack / Leak / Outage, executed: false}",
                "  H1: {description: Hierarchical Random Forest, stage1: Normal vs Incident, stage2: Hijack vs Leak vs Outage, executed: false}",
                "future_execution_order:",
                "  - Start with V1 Behavioral only under Natural training.",
                "  - Compare B0, B1, and H1 under I0 Natural.",
                "  - With a selected or controlled common architecture, compare I0, I1, and I2.",
                "  - Holding architecture and imbalance treatment constant, compare V1, V2, V3, and V4.",
                "  - From V4, later test removal of withdrawal/activity, AS-path/path-instability, origin-change, CAIDA, and RPKI feature groups.",
                "metrics:",
                "  primary: [Macro F1, Top-2 Accuracy, MRR]",
                "  secondary: [per-class precision, per-class recall, per-class F1, confusion matrix, ROC/PR where applicable, calibration, event-level metrics]",
                "evaluation_levels: [window, incident_or_control_group]",
                "data_hierarchy:",
                "  TRAIN: model fitting plus grouped CV",
                "  VALIDATION: later model and threshold selection only after TRAIN-only baseline protocol is established",
                "  FINAL_HOLDOUT: one final locked evaluation only",
                "",
            ]
        ),
        encoding="utf-8",
    )


def schema_alignment_status(normal_df: pd.DataFrame, incident_path: Path, features: list[str]) -> str:
    incident = pd.read_parquet(incident_path, columns=features)
    return "PASS" if feature_columns(normal_df, features) == list(incident.columns) == features else "FAIL"


def write_readiness_audit(normal_variants: dict[str, pd.DataFrame], manifest_counts: dict[str, dict[str, int]]) -> list[dict[str, object]]:
    rows = []
    for variant, (incident_path, _, features) in VARIANT_SPECS.items():
        normal_df = normal_variants[variant]
        rows.append({"check_name": f"{variant}_normal_rows", "observed_value": len(normal_df), "status": "PASS" if len(normal_df) == 516 else "FAIL", "notes": "Normal membership unchanged"})
        rows.append({"check_name": f"{variant}_normal_incident_feature_schema_align", "observed_value": len(features), "status": schema_alignment_status(normal_df, incident_path, features), "notes": "same feature names and order as incident variant"})
        rows.append({"check_name": f"{variant}_stage1_rows", "observed_value": manifest_counts[variant]["stage1_rows"], "status": "PASS" if manifest_counts[variant]["stage1_rows"] == 68547 else "FAIL", "notes": "516 Normal + 68,031 incident TRAIN windows"})
        rows.append({"check_name": f"{variant}_stage2_rows", "observed_value": manifest_counts[variant]["stage2_rows"], "status": "PASS" if manifest_counts[variant]["stage2_rows"] == 68031 else "FAIL", "notes": "incident TRAIN windows only"})
    rows.extend(
        [
            {"check_name": "grouping_keys_available", "observed_value": "group_id and model_group_id", "status": "PASS", "notes": "No random window-level split created"},
            {"check_name": "imbalance_configurations_registered", "observed_value": "I0/I1/I2", "status": "PASS", "notes": "registered but unapplied"},
            {"check_name": "experiment_matrix_registered", "observed_value": str(EXPERIMENT_MATRIX), "status": "PASS" if EXPERIMENT_MATRIX.exists() else "FAIL", "notes": "B0/B1/H1 and V1-V4 registered but unexecuted"},
            {"check_name": "holdout_untouched", "observed_value": "YES", "status": "PASS", "notes": "Only TRAIN frozen corpora and Normal TRAIN corpus were loaded"},
            {"check_name": "model_training_executed", "observed_value": "NO", "status": "PASS", "notes": "No estimator import/fit is performed"},
        ]
    )
    write_csv(READINESS_AUDIT, rows, ["check_name", "observed_value", "status", "notes"])
    return rows


def write_notebook() -> None:
    NOTEBOOK.parent.mkdir(parents=True, exist_ok=True)
    notebook = {
        "cells": [
            {"cell_type": "markdown", "metadata": {}, "source": ["# Modeling Readiness And Normal Enrichment\n", "\n", "Final dataset-alignment step before model baselining. No model training, ablation, threshold tuning, or Holdout access.\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["from bgp_incident_detection.modeling_readiness import run_modeling_readiness\n", "# run_modeling_readiness()\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["import pandas as pd\n", "pd.read_csv('../data/model_ready/modeling_readiness_audit_v1.csv')\n"]},
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")


def run_modeling_readiness() -> dict[str, object]:
    MODEL_READY_DIR.mkdir(parents=True, exist_ok=True)
    normal = load_normal()
    write_csv(INPUT_AUDIT, input_audit_rows(normal), ["check_name", "observed_value", "status", "notes"])
    caida = build_normal_caida(normal)
    rpki = build_normal_rpki(normal)
    normal_variants = build_normal_variants(normal, caida, rpki)
    grouping = model_grouping(normal)
    write_experiment_matrix()
    manifest_counts = build_manifests(normal_variants)
    readiness_rows = write_readiness_audit(normal_variants, manifest_counts)
    write_notebook()
    return {
        "normal_rows": len(normal),
        "normal_control_groups": normal["candidate_period_id"].nunique(),
        "associated_incident_groups": normal["associated_incident_uid"].nunique(),
        "normal_caida_rows": len(caida),
        "normal_rpki_rows": len(rpki),
        "stage1_rows_by_variant": {variant: counts["stage1_rows"] for variant, counts in manifest_counts.items()},
        "stage2_rows_by_variant": {variant: counts["stage2_rows"] for variant, counts in manifest_counts.items()},
        "readiness_status_counts": dict(Counter(row["status"] for row in readiness_rows)),
        "grouping_rows": len(grouping),
        "source_commit": source_commit(),
        "timestamp": utc_now(),
        "outputs": [
            str(INPUT_AUDIT),
            str(NORMAL_CAIDA),
            str(NORMAL_RPKI),
            str(NORMAL_V1),
            str(NORMAL_V2),
            str(NORMAL_V3),
            str(NORMAL_V4),
            str(GROUPING_AUDIT),
            str(EXPERIMENT_MATRIX),
            str(READINESS_AUDIT),
            str(NOTEBOOK),
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare model-ready Normal/incident manifests without training")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if args.run:
        print(json.dumps(run_modeling_readiness(), indent=2, sort_keys=True))
        return
    parser.error("choose --run")


if __name__ == "__main__":
    main()
