from __future__ import annotations

import argparse
import csv
import hashlib
import json
import lzma
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, f1_score, precision_recall_fscore_support

try:
    from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES, WindowAggregate, features_from_aggregate, update_aggregate
    from bgp_incident_detection.caida_features import CAIDA_FEATURE_NAMES, CaidaWindowAggregate, download_snapshot as download_caida_snapshot, features_from_caida_aggregate, load_relationships, selected_snapshot_for_window, update_caida_aggregate
    from bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT
    from bgp_incident_detection.rpki_features import RPKI_FEATURE_NAMES, STATE_TO_CODE, TRUST_ANCHORS, build_vrp_index, cache_path, download_snapshot, load_vrps_for_file, validate_rov
    from bgp_incident_detection.rpki_train_enrichment import selected_snapshot_by_observation_date
except ModuleNotFoundError:
    from src.bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES, WindowAggregate, features_from_aggregate, update_aggregate
    from src.bgp_incident_detection.caida_features import CAIDA_FEATURE_NAMES, CaidaWindowAggregate, download_snapshot as download_caida_snapshot, features_from_caida_aggregate, load_relationships, selected_snapshot_for_window, update_caida_aggregate
    from src.bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT
    from src.bgp_incident_detection.rpki_features import RPKI_FEATURE_NAMES, STATE_TO_CODE, TRUST_ANCHORS, build_vrp_index, cache_path, download_snapshot, load_vrps_for_file, validate_rov
    from src.bgp_incident_detection.rpki_train_enrichment import selected_snapshot_by_observation_date


OUT_DIR = Path("data/tti_extended_horizon_analysis_v1")
FIGURE_DIR = OUT_DIR / "figures"
TRAIN_EVIDENCE_DIR = Path("data/tti_timestamped_train_v1/evidence")
VALIDATION_EVIDENCE_DIR = Path("data/tti_validation_confirmation_v1/timestamped_evidence")
TRAIN_COHORT = Path("data/tti_train_full_v2_1/tti_train_evaluable_cohort_v2_1.csv")
TRAIN_COVERAGE = Path("data/tti_extended_horizon_feasibility_v1/tti_extended_horizon_coverage_v1.csv")
VALIDATION_EVAL = Path("data/tti_validation_confirmation_v1/tti_validation_evaluability_audit_v1.csv")
TRAIN_RPKI_MAPPING = Path("data/enrichment/rpki/train_rpki_snapshot_mapping_v1.csv")
MODEL_DIR = Path("data/tti_pilot/reconstructed_level1_v1")
SCHEMA = MODEL_DIR / "feature_schema_v4.json"

EXTENDED_V4 = OUT_DIR / "tti_extended_horizon_v4_features_v1.parquet"
COMPATIBILITY = OUT_DIR / "tti_extended_horizon_compatibility_audit_v1.csv"
LEAKAGE = OUT_DIR / "tti_extended_horizon_leakage_audit_v1.csv"
PREDICTIONS = OUT_DIR / "tti_extended_horizon_predictions_v1.csv"
METRICS = OUT_DIR / "tti_extended_horizon_metrics_v1.csv"
PER_CLASS = OUT_DIR / "tti_extended_horizon_per_class_metrics_v1.csv"
CONFUSION = OUT_DIR / "tti_extended_horizon_confusion_matrices_v1.csv"
BOOTSTRAP = OUT_DIR / "tti_extended_horizon_bootstrap_ci_v1.csv"
TRAJECTORIES = OUT_DIR / "tti_extended_prediction_trajectories_v1.csv"
STABILITY = OUT_DIR / "tti_extended_horizon_stability_analysis_v1.csv"
TRAIN_COVERAGE_OUT = OUT_DIR / "tti_extended_train_coverage_analysis_v1.csv"
CURVE_TABLE = OUT_DIR / "tti_extended_temporal_curve_table_v1.csv"
INTERPRETATION = OUT_DIR / "tti_extended_horizon_exploratory_interpretation_v1.md"
FIGURE_PNG = FIGURE_DIR / "figure_tti_extended_temporal_curve_v1.png"
FIGURE_PDF = FIGURE_DIR / "figure_tti_extended_temporal_curve_v1.pdf"
FIGURE_JPG = FIGURE_DIR / "figure_tti_extended_temporal_curve_v1_highres_chart_only.jpg"

CONFIRMATORY_TRAIN_METRICS = Path("data/tti_train_scoring_v1/tti_train_horizon_metrics_v1.csv")
CONFIRMATORY_VALIDATION_METRICS = Path("data/tti_validation_confirmation_v1/tti_validation_horizon_metrics_v1.csv")
CONFIRMATORY_TRAIN_PRED = Path("data/tti_train_scoring_v1/tti_train_predictions_v1.csv")
CONFIRMATORY_VALIDATION_PRED = Path("data/tti_validation_confirmation_v1/tti_validation_predictions_v1.csv")

LABELS = ["HIJACK", "LEAK", "OUTAGE"]
DISPLAY = {"HIJACK": "Hijack", "LEAK": "Leak", "OUTAGE": "Outage"}
DISPLAY_LABELS = [DISPLAY[label] for label in LABELS]
EXTENDED_HORIZONS = [600, 900]
ALL_HORIZONS = [30, 60, 120, 300, 600, 900]
BOOTSTRAP_SEED = 20260828
BOOTSTRAP_ITERATIONS = 2000
EXPERIMENT_SCOPE = "POST-HOC EXPLORATORY / SENSITIVITY TEMPORAL-CURVE ANALYSIS"
INTERPRETATION_BOUNDARY = (
    "The 600- and 900-second checkpoints were added after the pre-specified Validation TTI results had been observed. "
    "They are therefore exploratory sensitivity analyses and are not part of the terminal confirmatory TTI evaluation."
)


def as_text(value: object) -> str:
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError):
        pass
    return str(value).strip()


def format_utc(value: pd.Timestamp) -> str:
    return pd.Timestamp(value).tz_convert("UTC").isoformat(timespec="milliseconds").replace("+00:00", "Z")


def evidence_path(scope: str, uid: str) -> Path:
    directory = TRAIN_EVIDENCE_DIR if scope == "TRAIN" else VALIDATION_EVIDENCE_DIR
    return directory / f"{uid.replace(':', '_')}.parquet"


def load_evidence(scope: str, uid: str, columns: list[str] | None = None) -> pd.DataFrame:
    df = pd.read_parquet(evidence_path(scope, uid), columns=columns)
    df["bgp_timestamp_utc"] = pd.to_datetime(df["bgp_timestamp_utc"], utc=True, errors="coerce")
    return df.dropna(subset=["bgp_timestamp_utc"]).sort_values("bgp_timestamp_utc").reset_index(drop=True)


def load_cohorts() -> pd.DataFrame:
    train = pd.read_csv(TRAIN_COHORT, low_memory=False)
    train = train[train["tti_evaluable_status"].eq("TTI_EVALUABLE")].copy()
    train["scope"] = "TRAIN"
    train["tti_status"] = "TTI_EVALUABLE"
    train = train[["scope", "incident_uid", "incident_id", "category", "partition", "selected_onset_utc", "tti_status"]]

    validation = pd.read_csv(VALIDATION_EVAL, low_memory=False)
    validation = validation[validation["tti_status"].eq("TTI_EVALUABLE")].copy()
    validation["scope"] = "Validation"
    validation = validation[["scope", "incident_uid", "incident_id", "category", "partition", "selected_onset_utc", "tti_status"]]
    return pd.concat([train, validation], ignore_index=True)


def build_horizon_manifest(cohort: pd.DataFrame) -> pd.DataFrame:
    coverage = pd.read_csv(TRAIN_COVERAGE, low_memory=False)
    coverage = coverage[coverage["scope"].isin(["TRAIN", "Validation"])].copy()
    coverage_lookup = coverage.set_index(["scope", "incident_uid"])
    rows: list[dict[str, Any]] = []
    for row in cohort.itertuples(index=False):
        onset = pd.to_datetime(row.selected_onset_utc, utc=True, errors="raise")
        cov = coverage_lookup.loc[(row.scope, row.incident_uid)]
        for horizon in EXTENDED_HORIZONS:
            covered = bool(cov[f"coverage_{horizon}s"])
            cutoff = onset + pd.Timedelta(seconds=horizon)
            if not covered:
                rows.append(
                    {
                        "scope": row.scope,
                        "incident_uid": row.incident_uid,
                        "incident_id": row.incident_id,
                        "category": row.category,
                        "partition": row.partition,
                        "horizon_seconds": horizon,
                        "selected_onset_utc": format_utc(onset),
                        "horizon_cutoff_utc": format_utc(cutoff),
                        "observation_count_in_horizon": 0,
                        "max_bgp_timestamp_utc": "",
                        "extended_horizon_status": "NOT_EVALUABLE_INSUFFICIENT_TEMPORAL_COVERAGE",
                    }
                )
                continue
            ev = load_evidence(row.scope, row.incident_uid, columns=["bgp_timestamp_utc"])
            mask = (ev["bgp_timestamp_utc"] >= onset) & (ev["bgp_timestamp_utc"] <= cutoff)
            count = int(mask.sum())
            max_ts = ev.loc[mask, "bgp_timestamp_utc"].max() if count else pd.NaT
            rows.append(
                {
                    "scope": row.scope,
                    "incident_uid": row.incident_uid,
                    "incident_id": row.incident_id,
                    "category": row.category,
                    "partition": row.partition,
                    "horizon_seconds": horizon,
                    "selected_onset_utc": format_utc(onset),
                    "horizon_cutoff_utc": format_utc(cutoff),
                    "observation_count_in_horizon": count,
                    "max_bgp_timestamp_utc": format_utc(max_ts) if pd.notna(max_ts) else "",
                    "extended_horizon_status": "EVALUABLE",
                }
            )
    out = pd.DataFrame(rows).sort_values(["scope", "category", "incident_uid", "horizon_seconds"]).reset_index(drop=True)
    out.to_csv(OUT_DIR / "tti_extended_horizon_manifest_v1.csv", index=False)
    return out


def rpki_snapshot_usable(snapshot_date: str) -> bool:
    for tal in TRUST_ANCHORS:
        path = cache_path(tal, snapshot_date)
        if not path.exists() or path.stat().st_size <= 0:
            return False
        try:
            with lzma.open(path, "rt", encoding="utf-8", errors="replace") as handle:
                handle.readline()
        except (lzma.LZMAError, EOFError, OSError):
            return False
    return True


def ensure_rpki_snapshot(snapshot_date: str) -> bool:
    if rpki_snapshot_usable(snapshot_date):
        return True
    for tal in TRUST_ANCHORS:
        result = download_snapshot(tal, snapshot_date)
        if not str(result.get("status", "")).startswith(("CACHED", "DOWNLOADED")):
            return False
    return rpki_snapshot_usable(snapshot_date)


def selected_rpki_snapshot(onset: pd.Timestamp, mapping: dict[str, str]) -> str:
    date = onset.strftime("%Y-%m-%d")
    if date in mapping:
        return mapping[date]
    parsed = onset.normalize()
    for days_back in range(0, 31):
        candidate = (parsed - pd.Timedelta(days=days_back)).date().isoformat()
        if ensure_rpki_snapshot(candidate):
            return candidate
    raise RuntimeError(f"Missing usable RPKI snapshot for {date}")


def zero_rpki_features() -> dict[str, Any]:
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


def validate_keys_for_snapshot(snapshot_date: str, keys: pd.DataFrame) -> pd.DataFrame:
    vrps = []
    for tal in TRUST_ANCHORS:
        path = cache_path(tal, snapshot_date)
        if not path.exists() or path.stat().st_size <= 0:
            raise FileNotFoundError(f"Missing cached RPKI snapshot: {path}")
        vrps.extend(load_vrps_for_file(path, tal))
    index = build_vrp_index(vrps)
    rows = []
    for row in keys.itertuples(index=False):
        result = validate_rov(row.prefix, row.origin_asn, index)
        rows.append({"snapshot_date": snapshot_date, "prefix": row.prefix, "origin_asn": row.origin_asn, "rpki_state": result.state})
    return pd.DataFrame(rows)


def rpki_features_from_counts(horizon: pd.DataFrame, counts: pd.DataFrame, mapping: dict[str, str]) -> pd.DataFrame:
    key_cols = ["scope", "incident_uid", "incident_id", "category", "partition", "horizon_seconds", "selected_onset_utc", "horizon_cutoff_utc", "observation_count_in_horizon"]
    if not len(counts):
        return pd.DataFrame([{**{col: getattr(row, col) for col in key_cols}, **zero_rpki_features()} for row in horizon.itertuples(index=False)])
    counts = counts.copy()
    unique_onsets = counts["selected_onset_utc"].drop_duplicates()
    snapshot_lookup = {
        onset_utc: selected_rpki_snapshot(pd.to_datetime(onset_utc, utc=True), mapping)
        for onset_utc in unique_onsets
    }
    counts["snapshot_date"] = counts["selected_onset_utc"].map(snapshot_lookup)
    unique_keys = counts[["snapshot_date", "prefix", "origin_asn"]].drop_duplicates(ignore_index=True)
    grouped_keys = [(str(snapshot), keys.copy()) for snapshot, keys in unique_keys.groupby("snapshot_date", sort=True)]
    lookup_parts: dict[str, pd.DataFrame] = {}
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = {executor.submit(validate_keys_for_snapshot, snapshot, keys): (snapshot, len(keys)) for snapshot, keys in grouped_keys}
        done = 0
        for future in as_completed(futures):
            snapshot, key_count = futures[future]
            lookup_parts[snapshot] = future.result()
            done += 1
            print(f"Extended RPKI snapshot {snapshot} ({done}/{len(futures)}) keys={key_count}", flush=True)
    lookup = pd.concat([lookup_parts[snapshot] for snapshot, _ in grouped_keys], ignore_index=True)
    enriched = counts.merge(lookup, on=["snapshot_date", "prefix", "origin_asn"], how="left", validate="many_to_one")
    grouped = {key: group for key, group in enriched.groupby(key_cols, dropna=False)}
    rows = []
    for meta in horizon.itertuples(index=False):
        output = {col: getattr(meta, col) for col in key_cols}
        group = grouped.get(tuple(output[col] for col in key_cols))
        if group is None or not len(group):
            output.update(zero_rpki_features())
            rows.append(output)
            continue
        state_counts = group.groupby("rpki_state")["observation_count"].sum().to_dict()
        valid = int(state_counts.get("VALID", 0))
        invalid_origin = int(state_counts.get("INVALID_ORIGIN", 0))
        invalid_length = int(state_counts.get("INVALID_LENGTH", 0))
        invalid = invalid_origin + invalid_length
        not_found = int(state_counts.get("NOT_FOUND", 0))
        unevaluable = int(state_counts.get("UNEVALUABLE", 0))
        evaluable = valid + invalid + not_found
        total = evaluable + unevaluable
        dominant = "NO_PREFIX_ORIGIN_EVIDENCE" if total == 0 else max(["VALID", "INVALID_ORIGIN", "INVALID_LENGTH", "NOT_FOUND", "UNEVALUABLE"], key=lambda state: (state_counts.get(state, 0), state))
        features = zero_rpki_features()
        features.update(
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
                "rpki_unique_valid_prefix_count": int(group[group["rpki_state"].eq("VALID")]["prefix"].nunique()),
                "rpki_unique_invalid_prefix_count": int(group[group["rpki_state"].isin(["INVALID_ORIGIN", "INVALID_LENGTH"])]["prefix"].nunique()),
                "rpki_unique_not_found_prefix_count": int(group[group["rpki_state"].eq("NOT_FOUND")]["prefix"].nunique()),
                "rpki_state_diversity_count": int(sum(1 for state in ["VALID", "INVALID_ORIGIN", "INVALID_LENGTH", "NOT_FOUND", "UNEVALUABLE"] if state_counts.get(state, 0) > 0)),
                "rpki_dominant_state_code": STATE_TO_CODE[dominant],
            }
        )
        output.update(features)
        rows.append(output)
    return pd.DataFrame(rows)


def build_extended_features(manifest: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    mapping = selected_snapshot_by_observation_date(pd.read_csv(TRAIN_RPKI_MAPPING, low_memory=False))
    caida_cache: dict[str, Any] = {}
    rows: list[dict[str, Any]] = []
    rpki_count_parts: list[pd.DataFrame] = []
    evaluable = manifest[manifest["extended_horizon_status"].eq("EVALUABLE")].copy()
    processed = 0
    for (_scope, _uid), incident_rows in evaluable.groupby(["scope", "incident_uid"], sort=True):
        ev = load_evidence(_scope, _uid)
        for meta in incident_rows.itertuples(index=False):
            onset = pd.to_datetime(meta.selected_onset_utc, utc=True)
            cutoff = pd.to_datetime(meta.horizon_cutoff_utc, utc=True)
            subset = ev[(ev["bgp_timestamp_utc"] >= onset) & (ev["bgp_timestamp_utc"] <= cutoff)].copy()
            aggregate = WindowAggregate()
            caida_aggregate = CaidaWindowAggregate()
            caida_snapshot, caida_url, _ = selected_snapshot_for_window(meta.selected_onset_utc)
            if caida_snapshot not in caida_cache:
                caida_cache[caida_snapshot] = load_relationships(download_caida_snapshot(caida_snapshot, caida_url))
            for record in subset.to_dict("records"):
                update_aggregate(aggregate, record)
                update_caida_aggregate(caida_aggregate, record, caida_cache[caida_snapshot])
            row = {
                "scope": meta.scope,
                "incident_uid": meta.incident_uid,
                "incident_id": meta.incident_id,
                "category": meta.category,
                "partition": meta.partition,
                "horizon_seconds": int(meta.horizon_seconds),
                "selected_onset_utc": meta.selected_onset_utc,
                "horizon_cutoff_utc": meta.horizon_cutoff_utc,
                "observation_count_in_horizon": int(len(subset)),
            }
            row.update(features_from_aggregate(aggregate))
            row.update(features_from_caida_aggregate(caida_aggregate))
            rows.append(row)
            if len(subset):
                keyed = subset.assign(prefix=subset["prefix"].map(as_text), origin_asn=subset["origin_asn"].map(as_text)).groupby(["prefix", "origin_asn"], dropna=False).size().reset_index(name="observation_count")
                for col, value in reversed(list(row.items())[:9]):
                    keyed.insert(0, col, value)
                rpki_count_parts.append(keyed)
            processed += 1
            if processed % 100 == 0 or processed == len(evaluable):
                print(f"Extended Behavioral/CAIDA features {processed}/{len(evaluable)}", flush=True)
    base = pd.DataFrame(rows)
    counts = pd.concat(rpki_count_parts, ignore_index=True) if rpki_count_parts else pd.DataFrame()
    horizon_for_rpki = base[["scope", "incident_uid", "incident_id", "category", "partition", "horizon_seconds", "selected_onset_utc", "horizon_cutoff_utc", "observation_count_in_horizon"]].copy()
    rpki = rpki_features_from_counts(horizon_for_rpki, counts, mapping)
    merge_keys = ["scope", "incident_uid", "incident_id", "category", "partition", "horizon_seconds", "selected_onset_utc", "horizon_cutoff_utc", "observation_count_in_horizon"]
    features = base.merge(rpki[merge_keys + RPKI_FEATURE_NAMES], on=merge_keys, how="left", validate="one_to_one")
    feature_order = FEATURES_BY_VARIANT["V4"]
    v4 = features[merge_keys + feature_order].sort_values(["scope", "category", "incident_uid", "horizon_seconds"]).reset_index(drop=True)
    behavioral = features[merge_keys + BEHAVIORAL_FEATURE_NAMES]
    caida = features[merge_keys + CAIDA_FEATURE_NAMES]
    return v4, behavioral, caida, rpki


def write_audits(v4: pd.DataFrame, manifest: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    feature_order = FEATURES_BY_VARIANT["V4"]
    observed_order = [col for col in v4.columns if col in feature_order]
    comp_rows = []
    for i, feature in enumerate(feature_order):
        series = pd.to_numeric(v4[feature], errors="coerce")
        inf_count = int(np.isinf(series.to_numpy(dtype=float, na_value=np.nan)).sum())
        comp_rows.append({"feature_order": i + 1, "feature_name": feature, "present": feature in v4.columns, "expected_order_matches": observed_order[i] == feature, "inf_count": inf_count, "status": "PASS" if feature in v4.columns and observed_order[i] == feature and inf_count == 0 else "FAIL"})
    comp = pd.DataFrame(comp_rows)
    comp.to_csv(COMPATIBILITY, index=False)
    leak_rows = []
    for row in manifest[manifest["extended_horizon_status"].eq("EVALUABLE")].itertuples(index=False):
        cutoff = pd.to_datetime(row.horizon_cutoff_utc, utc=True)
        max_ts = pd.to_datetime(row.max_bgp_timestamp_utc, utc=True, errors="coerce") if as_text(row.max_bgp_timestamp_utc) else pd.NaT
        ok = int(row.observation_count_in_horizon) == 0 or (pd.notna(max_ts) and max_ts <= cutoff)
        leak_rows.append({"scope": row.scope, "incident_uid": row.incident_uid, "horizon_seconds": row.horizon_seconds, "horizon_cutoff_utc": row.horizon_cutoff_utc, "max_bgp_timestamp_utc": row.max_bgp_timestamp_utc, "status": "PASS" if ok else "FAIL"})
    leak = pd.DataFrame(leak_rows)
    leak.to_csv(LEAKAGE, index=False)
    return comp, leak


def load_models() -> list[Any]:
    return [joblib.load(MODEL_DIR / f"level1_xgb_fold_{fold}_hist_njobs_minus1.joblib") for fold in [1, 2, 3, 4, 5]]


def normalize_class(value: object) -> str:
    text = str(value).strip().upper()
    if text not in LABELS:
        raise ValueError(f"Unexpected class label: {value!r}")
    return text


def score(v4: pd.DataFrame) -> pd.DataFrame:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8")) if SCHEMA.suffix == ".json" else FEATURES_BY_VARIANT["V4"]
    if not isinstance(schema, list):
        schema = FEATURES_BY_VARIANT["V4"]
    models = load_models()
    probs = np.stack([model.predict_proba(v4[schema]) for model in models], axis=0).mean(axis=0)
    out = v4[["scope", "incident_uid", "incident_id", "category", "partition", "horizon_seconds", "selected_onset_utc", "horizon_cutoff_utc", "observation_count_in_horizon"]].copy()
    out["true_class"] = out["category"].map(lambda x: DISPLAY[normalize_class(x)])
    out["hijack_probability"] = probs[:, 0]
    out["leak_probability"] = probs[:, 1]
    out["outage_probability"] = probs[:, 2]
    out["predicted_top1_class"] = [DISPLAY[LABELS[i]] for i in probs.argmax(axis=1)]
    out["true_class_rank"] = [int(np.where(np.argsort(row)[::-1] == LABELS.index(normalize_class(cls)))[0][0] + 1) for cls, row in zip(out["true_class"], probs)]
    out["top1_correct"] = out["predicted_top1_class"].eq(out["true_class"])
    out["top2_correct"] = out["true_class_rank"].le(2)
    out["experiment_scope"] = EXPERIMENT_SCOPE
    out["interpretation_boundary"] = INTERPRETATION_BOUNDARY
    return out


def bootstrap_macro_f1(group: pd.DataFrame) -> dict[str, float]:
    rng = np.random.default_rng(BOOTSTRAP_SEED + int(group["horizon_seconds"].iloc[0]) + (0 if group["scope"].iloc[0] == "TRAIN" else 10000))
    ids = group["incident_uid"].to_numpy()
    true = group.set_index("incident_uid")["true_class"]
    pred = group.set_index("incident_uid")["predicted_top1_class"]
    values = []
    for _ in range(BOOTSTRAP_ITERATIONS):
        sample = rng.choice(ids, size=len(ids), replace=True)
        values.append(f1_score(true.loc[sample], pred.loc[sample], labels=DISPLAY_LABELS, average="macro", zero_division=0))
    arr = np.asarray(values)
    return {"macro_f1_ci_lower": float(np.quantile(arr, 0.025)), "macro_f1_ci_upper": float(np.quantile(arr, 0.975)), "macro_f1_bootstrap_mean": float(arr.mean()), "macro_f1_bootstrap_std": float(arr.std(ddof=1))}


def metric_outputs(pred: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    metric_rows = []
    per_rows = []
    conf_rows = []
    boot_rows = []
    for (scope, horizon), group in pred.groupby(["scope", "horizon_seconds"], sort=True):
        y_true = group["true_class"]
        y_pred = group["predicted_top1_class"]
        precision, recall, f1, support = precision_recall_fscore_support(y_true, y_pred, labels=DISPLAY_LABELS, zero_division=0)
        boot = bootstrap_macro_f1(group)
        metric_rows.append({"scope": scope, "horizon_seconds": horizon, "n_incidents": len(group), "analysis_type": "POST_HOC_EXPLORATORY" if horizon in EXTENDED_HORIZONS else "PRE_SPECIFIED_CONFIRMATORY_REFERENCE", "macro_f1": f1_score(y_true, y_pred, labels=DISPLAY_LABELS, average="macro", zero_division=0), **{k: boot[k] for k in ["macro_f1_ci_lower", "macro_f1_ci_upper"]}, "top1_accuracy": group["top1_correct"].mean(), "top2_accuracy": group["top2_correct"].mean(), "mrr": (1.0 / group["true_class_rank"]).mean()})
        boot_rows.append({"scope": scope, "horizon_seconds": horizon, "n_incidents": len(group), "bootstrap_iterations": BOOTSTRAP_ITERATIONS, **boot, "sample_unit": "incident"})
        matrix = confusion_matrix(y_true, y_pred, labels=DISPLAY_LABELS)
        for i, cls in enumerate(DISPLAY_LABELS):
            per_rows.append({"scope": scope, "horizon_seconds": horizon, "class": cls, "precision": precision[i], "recall": recall[i], "f1": f1[i], "support": int(support[i])})
            for j, pred_cls in enumerate(DISPLAY_LABELS):
                conf_rows.append({"scope": scope, "horizon_seconds": horizon, "true_class": cls, "predicted_class": pred_cls, "count": int(matrix[i, j])})
    return pd.DataFrame(metric_rows), pd.DataFrame(per_rows), pd.DataFrame(conf_rows), pd.DataFrame(boot_rows)


def write_trajectories_and_stability(pred: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    confirm = pd.concat([pd.read_csv(CONFIRMATORY_TRAIN_PRED), pd.read_csv(CONFIRMATORY_VALIDATION_PRED)], ignore_index=True)
    confirm["scope"] = np.where(confirm["partition"].astype(str).str.lower().eq("train"), "TRAIN", "Validation")
    cols = ["scope", "incident_uid", "incident_id", "true_class", "horizon_seconds", "predicted_top1_class", "true_class_rank", "top1_correct", "top2_correct"]
    combined = pd.concat([confirm[cols], pred[cols]], ignore_index=True)
    combined = combined[combined["horizon_seconds"].isin(ALL_HORIZONS)].sort_values(["scope", "incident_uid", "horizon_seconds"])
    traj_rows = []
    stab_rows = []
    for (scope, uid), group in combined.groupby(["scope", "incident_uid"], sort=True):
        horizons = group["horizon_seconds"].astype(int).tolist()
        top1 = group["top1_correct"].astype(bool).tolist()
        stable = None
        for idx, horizon in enumerate(horizons):
            if all(top1[idx:]):
                stable = horizon
                break
        confirm_group = group[group["horizon_seconds"].le(300)]
        ext_group = group[group["horizon_seconds"].isin(EXTENDED_HORIZONS)]
        unstable_by_300 = not bool(confirm_group["top1_correct"].iloc[-1]) or any(confirm_group["top1_correct"].astype(bool) & ~confirm_group["top1_correct"].astype(bool).cummin())
        becomes_stable_extended = stable in EXTENDED_HORIZONS
        traj_rows.append({"scope": scope, "incident_uid": uid, "incident_id": group["incident_id"].iloc[0], "true_class": group["true_class"].iloc[0], "top1_trajectory": " -> ".join(f"{int(r.horizon_seconds)}s:{r.predicted_top1_class}" for r in group.itertuples(index=False)), "rank_trajectory": " -> ".join(f"{int(r.horizon_seconds)}s:rank{int(r.true_class_rank)}" for r in group.itertuples(index=False)), "extended_stable_correct_checkpoint": f"<={stable}s" if stable else "NOT_STABLE_WITHIN_900S", "unstable_or_incorrect_by_300s": bool(unstable_by_300), "becomes_stable_correct_at_600_or_900": bool(becomes_stable_extended)})
        stab_rows.append({"scope": scope, "incident_uid": uid, "true_class": group["true_class"].iloc[0], "stable_checkpoint_30_to_900": f"<={stable}s" if stable else "NOT_STABLE_WITHIN_900S", "unstable_or_incorrect_by_300s": bool(unstable_by_300), "becomes_stable_correct_at_600_or_900": bool(becomes_stable_extended), "top1_600_correct": bool(ext_group[ext_group["horizon_seconds"].eq(600)]["top1_correct"].iloc[0]) if len(ext_group[ext_group["horizon_seconds"].eq(600)]) else False, "top1_900_correct": bool(ext_group[ext_group["horizon_seconds"].eq(900)]["top1_correct"].iloc[0]) if len(ext_group[ext_group["horizon_seconds"].eq(900)]) else False})
    trajectories = pd.DataFrame(traj_rows)
    stability = pd.DataFrame(stab_rows)
    trajectories.to_csv(TRAJECTORIES, index=False)
    stability.to_csv(STABILITY, index=False)
    return trajectories, stability


def combined_curve(metrics: pd.DataFrame) -> pd.DataFrame:
    train = pd.read_csv(CONFIRMATORY_TRAIN_METRICS)
    train["scope"] = "TRAIN"
    val = pd.read_csv(CONFIRMATORY_VALIDATION_METRICS)
    val["scope"] = "Validation"
    base = pd.concat([train, val], ignore_index=True)
    base["analysis_type"] = "PRE_SPECIFIED_CONFIRMATORY_REFERENCE"
    curve = pd.concat([base[["scope", "horizon_seconds", "n_incidents", "analysis_type", "macro_f1", "top1_accuracy", "top2_accuracy", "mrr"]], metrics[["scope", "horizon_seconds", "n_incidents", "analysis_type", "macro_f1", "top1_accuracy", "top2_accuracy", "mrr"]]], ignore_index=True)
    curve = curve.sort_values(["scope", "horizon_seconds"]).reset_index(drop=True)
    curve.to_csv(CURVE_TABLE, index=False)
    return curve


def write_figures(curve: pd.DataFrame) -> None:
    FIGURE_DIR.mkdir(parents=True, exist_ok=True)
    metrics = [("macro_f1", "Macro F1"), ("top1_accuracy", "Top-1"), ("top2_accuracy", "Top-2"), ("mrr", "MRR")]
    fig, axes = plt.subplots(2, 2, figsize=(11, 7), sharex=True)
    for ax, (col, label) in zip(axes.ravel(), metrics):
        for scope, sdf in curve.groupby("scope"):
            ax.plot(sdf["horizon_seconds"], sdf[col], marker="o", linewidth=2, label=scope)
        ax.axvspan(0, 300, color="#dbeafe", alpha=0.35, label="pre-specified" if col == "macro_f1" else None)
        ax.axvspan(300, 900, color="#fef3c7", alpha=0.35, label="post-hoc exploratory" if col == "macro_f1" else None)
        ax.axvline(300, color="#6b7280", linestyle="--", linewidth=1)
        ax.set_title(label)
        ax.set_ylim(0.65, 1.0)
        ax.grid(True, alpha=0.25)
    handles, labels = axes[0, 0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=4, frameon=False)
    fig.supxlabel("Cumulative observation horizon after selected onset (seconds)")
    fig.supylabel("Incident-level metric")
    fig.tight_layout(rect=(0, 0, 1, 0.92))
    fig.savefig(FIGURE_PNG, dpi=220)
    fig.savefig(FIGURE_PDF)
    fig.savefig(FIGURE_JPG, dpi=420)
    plt.close(fig)


def write_interpretation(metrics: pd.DataFrame, curve: pd.DataFrame, stability: pd.DataFrame, manifest: pd.DataFrame, started: float) -> str:
    val_ext = metrics[metrics["scope"].eq("Validation")].sort_values("horizon_seconds")
    train_ext = metrics[metrics["scope"].eq("TRAIN")].sort_values("horizon_seconds")
    val_300 = curve[(curve["scope"].eq("Validation")) & (curve["horizon_seconds"].eq(300))].iloc[0]
    val_900 = curve[(curve["scope"].eq("Validation")) & (curve["horizon_seconds"].eq(900))].iloc[0]
    train_300 = curve[(curve["scope"].eq("TRAIN")) & (curve["horizon_seconds"].eq(300))].iloc[0]
    train_900 = curve[(curve["scope"].eq("TRAIN")) & (curve["horizon_seconds"].eq(900))].iloc[0]
    train_cov = manifest[manifest["scope"].eq("TRAIN")].groupby("horizon_seconds")["extended_horizon_status"].value_counts().unstack(fill_value=0)
    validation_cov = manifest[manifest["scope"].eq("Validation")].groupby("horizon_seconds")["extended_horizon_status"].value_counts().unstack(fill_value=0)
    stable_summary = stability.groupby("scope")["becomes_stable_correct_at_600_or_900"].sum().to_dict()
    lines = [
        "# Extended Horizon Exploratory Interpretation v1",
        "",
        f"**{EXPERIMENT_SCOPE}**",
        "",
        INTERPRETATION_BOUNDARY,
        "",
        "No Final Holdout access occurred. No Level-1 model retraining, tuning, calibration, optimization, or modification occurred. Feature definitions, onset methodology, CAIDA/RPKI mapping, class order, and V4 schema were preserved.",
        "",
        "## Coverage",
        "",
        "TRAIN extended-horizon coverage:",
        "",
        train_cov.to_markdown(),
        "",
        "Validation extended-horizon coverage:",
        "",
        validation_cov.to_markdown(),
        "",
        "## 600/900 Metrics",
        "",
        metrics.sort_values(["scope", "horizon_seconds"])[["scope", "horizon_seconds", "n_incidents", "macro_f1", "macro_f1_ci_lower", "macro_f1_ci_upper", "top1_accuracy", "top2_accuracy", "mrr"]].to_markdown(index=False),
        "",
        "## Descriptive Temporal-Curve Finding",
        "",
        f"- Validation Macro F1 moved from 300s={val_300['macro_f1']:.6f} to 900s={val_900['macro_f1']:.6f}.",
        f"- TRAIN Macro F1 moved from 300s={train_300['macro_f1']:.6f} to 900s={train_900['macro_f1']:.6f}.",
        "- This exploratory curve should be interpreted descriptively only; it must not be used to select a new optimal TTI horizon or redefine the confirmatory TTI checkpoint.",
        f"- Incidents becoming stable-correct only at 600s/900s: {stable_summary}.",
        "",
        "## Files",
        "",
        f"- V4 features: `{EXTENDED_V4}`",
        f"- predictions: `{PREDICTIONS}`",
        f"- metrics: `{METRICS}`",
        f"- combined curve table: `{CURVE_TABLE}`",
        f"- figure PNG/PDF/JPG: `{FIGURE_PNG}`, `{FIGURE_PDF}`, `{FIGURE_JPG}`",
        "",
        f"Elapsed seconds: {time.time() - started:.3f}",
        "",
        "Disposition: `EXTENDED_HORIZON_EXPLORATORY_ANALYSIS_COMPLETE`",
    ]
    INTERPRETATION.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return "EXTENDED_HORIZON_EXPLORATORY_ANALYSIS_COMPLETE"


def run() -> str:
    started = time.time()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    cohort = load_cohorts()
    manifest = build_horizon_manifest(cohort)
    manifest[manifest["scope"].eq("TRAIN")].to_csv(TRAIN_COVERAGE_OUT, index=False)
    v4, behavioral, caida, rpki = build_extended_features(manifest)
    behavioral.to_parquet(OUT_DIR / "tti_extended_horizon_behavioral_v1.parquet", index=False)
    caida.to_parquet(OUT_DIR / "tti_extended_horizon_caida_v1.parquet", index=False)
    rpki.to_parquet(OUT_DIR / "tti_extended_horizon_rpki_v1.parquet", index=False)
    v4.to_parquet(EXTENDED_V4, index=False)
    comp, leak = write_audits(v4, manifest)
    if not comp["status"].eq("PASS").all() or not leak["status"].eq("PASS").all():
        write_interpretation(pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), manifest, started)
        return "EXTENDED_HORIZON_EXPLORATORY_ANALYSIS_REQUIRES_REVIEW"
    pred = score(v4)
    pred.to_csv(PREDICTIONS, index=False)
    metrics, per_class, confusion, boot = metric_outputs(pred)
    metrics.to_csv(METRICS, index=False)
    per_class.to_csv(PER_CLASS, index=False)
    confusion.to_csv(CONFUSION, index=False)
    boot.to_csv(BOOTSTRAP, index=False)
    _, stability = write_trajectories_and_stability(pred)
    curve = combined_curve(metrics)
    write_figures(curve)
    return write_interpretation(metrics, curve, stability, manifest, started)


def main() -> None:
    parser = argparse.ArgumentParser(description="Post-hoc exploratory extended-horizon TTI analysis at 600 and 900 seconds.")
    parser.parse_args()
    print(run())


if __name__ == "__main__":
    main()
