from __future__ import annotations

import argparse
import csv
import hashlib
import json
import lzma
import re
import shutil
import subprocess
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import timedelta
from pathlib import Path
from typing import Any

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, f1_score, precision_recall_fscore_support

try:
    from bgp_incident_detection.audit import parse_listish, parse_utc
    from bgp_incident_detection.behavioral_features import WindowAggregate, features_from_aggregate, update_aggregate
    from bgp_incident_detection.caida_features import CAIDA_FEATURE_NAMES, download_snapshot as download_caida_snapshot, load_relationships, selected_snapshot_for_window, update_caida_aggregate
    from bgp_incident_detection.caida_features import CaidaWindowAggregate, features_from_caida_aggregate
    from bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT
    from bgp_incident_detection.mrt_parser import parse_as_path, parse_as_path_set, parse_bgpdump_line
    from bgp_incident_detection.rpki_features import RPKI_FEATURE_NAMES, STATE_TO_CODE, TRUST_ANCHORS, build_vrp_index, cache_path, download_snapshot, load_vrps_for_file, validate_rov
    from bgp_incident_detection.rpki_train_enrichment import selected_snapshot_by_observation_date
    from bgp_incident_detection.train_incident_scale import compression_ok, copy_or_download, relevance_targets, relevant_with_targets
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import parse_listish, parse_utc
    from src.bgp_incident_detection.behavioral_features import WindowAggregate, features_from_aggregate, update_aggregate
    from src.bgp_incident_detection.caida_features import CAIDA_FEATURE_NAMES, download_snapshot as download_caida_snapshot, load_relationships, selected_snapshot_for_window, update_caida_aggregate
    from src.bgp_incident_detection.caida_features import CaidaWindowAggregate, features_from_caida_aggregate
    from src.bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT
    from src.bgp_incident_detection.mrt_parser import parse_as_path, parse_as_path_set, parse_bgpdump_line
    from src.bgp_incident_detection.rpki_features import RPKI_FEATURE_NAMES, STATE_TO_CODE, TRUST_ANCHORS, build_vrp_index, cache_path, download_snapshot, load_vrps_for_file, validate_rov
    from src.bgp_incident_detection.rpki_train_enrichment import selected_snapshot_by_observation_date
    from src.bgp_incident_detection.train_incident_scale import compression_ok, copy_or_download, relevance_targets, relevant_with_targets


OUT_DIR = Path("data/tti_validation_confirmation_v1")
EVIDENCE_DIR = OUT_DIR / "timestamped_evidence"
RAW_CACHE = OUT_DIR / "raw_mrt_cache"
FIGURE_DIR = OUT_DIR / "figures"
PROTOCOL_MANIFEST = Path("data/tti_train_scoring_v1/tti_frozen_protocol_manifest_v1.json")
VALIDATION_INCIDENTS = Path("data/partitions_v2/validation_incidents_v2.csv")
VALIDATION_MANIFEST_SOURCE = Path("data/validation/validation_incident_manifest_v1.csv")
VALIDATION_ACQUISITION_PLAN = Path("data/validation/validation_mrt_acquisition_plan_v1.csv")
TRAIN_RPKI_MAPPING = Path("data/enrichment/rpki/train_rpki_snapshot_mapping_v1.csv")
TRAIN_METRICS = Path("data/tti_train_scoring_v1/tti_train_horizon_metrics_v1.csv")
TRAIN_CUMULATIVE = Path("data/tti_train_scoring_v1/tti_train_cumulative_identification_v1.csv")
TRAIN_STABILITY = Path("data/tti_train_scoring_v1/tti_train_stability_v1.csv")
MODEL_DIR = Path("data/tti_pilot/reconstructed_level1_v1")
SCHEMA = MODEL_DIR / "feature_schema_v4.json"
ENSEMBLE_MANIFEST = Path("data/tti_pilot/level1_ensemble_manifest_v2.json")

PROTOCOL_VERIFY = OUT_DIR / "tti_validation_protocol_hash_verification_v1.csv"
ROSTER_OUT = OUT_DIR / "tti_validation_incident_roster_v1.csv"
EVALUABILITY = OUT_DIR / "tti_validation_evaluability_audit_v1.csv"
EVIDENCE_MANIFEST = OUT_DIR / "tti_validation_timestamped_evidence_manifest_v1.csv"
HORIZON_MANIFEST = OUT_DIR / "tti_validation_horizon_manifest_v1.csv"
V4_COMPAT = OUT_DIR / "tti_validation_v4_compatibility_audit_v1.csv"
LEAKAGE = OUT_DIR / "tti_validation_leakage_audit_v1.csv"
PREDICTIONS = OUT_DIR / "tti_validation_predictions_v1.csv"
HORIZON_METRICS = OUT_DIR / "tti_validation_horizon_metrics_v1.csv"
PER_CLASS_METRICS = OUT_DIR / "tti_validation_per_class_metrics_v1.csv"
CONFUSION = OUT_DIR / "tti_validation_confusion_matrices_v1.csv"
CHECKPOINTS = OUT_DIR / "tti_validation_checkpoint_tti_v1.csv"
CUMULATIVE = OUT_DIR / "tti_validation_cumulative_identification_v1.csv"
TRAJECTORIES = OUT_DIR / "tti_validation_prediction_trajectories_v1.csv"
STABILITY = OUT_DIR / "tti_validation_stability_v1.csv"
BOOTSTRAP = OUT_DIR / "tti_validation_bootstrap_ci_v1.csv"
COMPARISON = OUT_DIR / "tti_train_vs_validation_tti_comparison_v1.csv"
SUMMARY = OUT_DIR / "tti_validation_confirmation_summary_v1.md"
HORIZON_V4 = OUT_DIR / "tti_validation_horizon_v4_v1.parquet"
RPKI_SNAPSHOT_AUDIT = OUT_DIR / "tti_validation_rpki_snapshot_mapping_audit_v1.csv"

LABELS = ["HIJACK", "LEAK", "OUTAGE"]
DISPLAY = {"HIJACK": "Hijack", "LEAK": "Leak", "OUTAGE": "Outage"}
DISPLAY_LABELS = [DISPLAY[label] for label in LABELS]
PROB_COLS = ["hijack_probability", "leak_probability", "outage_probability"]
HORIZONS = [30, 60, 120, 300]
BOOTSTRAP_SEED = 20260828
BOOTSTRAP_ITERATIONS = 2000
EXPERIMENT_LABEL = "ONE-TIME INDEPENDENT VALIDATION OF RETROSPECTIVE EARLY CLASSIFICATION / ROUTEVIEWS-OBSERVABLE CHECKPOINT TTI"
USER_AGENT = "bgp-incident-detection-pipeline/0.1"
DOWNLOAD_WORKERS = 8

EVIDENCE_FIELDS = [
    "incident_uid",
    "incident_id",
    "category",
    "partition",
    "source_mrt_filename",
    "collector",
    "bgp_timestamp_utc",
    "peer_ip",
    "peer_asn",
    "message_update_type",
    "announcement_or_withdrawal",
    "prefix",
    "as_path",
    "origin_asn",
    "next_hop",
    "communities",
    "med",
    "local_pref",
    "atomic_aggregate",
    "aggregator",
    "normalized_as_path",
]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fields is None:
        fields = list(rows[0].keys()) if rows else []
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def as_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and np.isnan(value):
        return ""
    return str(value).strip()


def clean_incident_record(incident: dict[str, Any]) -> dict[str, Any]:
    cleaned = {}
    for key, value in incident.items():
        cleaned[key] = as_text(value)
    cleaned["partition"] = "validation"
    return cleaned


def normalize_class(value: Any) -> str:
    text = str(value).strip().upper()
    if text not in LABELS:
        raise ValueError(f"Unexpected class label: {value!r}")
    return text


def format_utc(value: pd.Timestamp) -> str:
    return pd.Timestamp(value).tz_convert("UTC").isoformat(timespec="milliseconds").replace("+00:00", "Z")


def evidence_path(uid: str) -> Path:
    return EVIDENCE_DIR / f"{uid.replace(':', '_')}.parquet"


def cache_path_for_url(url: str) -> Path:
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:24]
    return RAW_CACHE / f"{digest}_{Path(url).name}"


def verify_protocol_hashes() -> None:
    obj = json.loads(PROTOCOL_MANIFEST.read_text())
    rows = []
    failures = []
    for artifact in obj["artifact_hashes"]:
        path = Path(artifact["path"])
        actual = sha256(path) if path.exists() else ""
        ok = path.exists() and actual == artifact["sha256"]
        rows.append(
            {
                "role": artifact["role"],
                "path": artifact["path"],
                "expected_sha256": artifact["sha256"],
                "actual_sha256": actual,
                "status": "PASS" if ok else "FAIL",
            }
        )
        if not ok:
            failures.append(artifact["path"])
    write_csv(PROTOCOL_VERIFY, rows, ["role", "path", "expected_sha256", "actual_sha256", "status"])
    if failures:
        raise RuntimeError(f"Frozen protocol hash verification failed: {failures[:10]}")


def normalize_asn(value: object) -> str:
    text = as_text(value).upper()
    if text.startswith("AS"):
        text = text[2:]
    if text.endswith(".0"):
        text = text[:-2]
    return text if text.isdigit() else ""


def load_validation_manifest() -> pd.DataFrame:
    validation = pd.read_csv(VALIDATION_INCIDENTS, low_memory=False)
    counts = validation["category"].value_counts().to_dict()
    if len(validation) != 213 or counts != {"Hijack": 71, "Leak": 71, "Outage": 71}:
        raise RuntimeError(f"Unexpected Validation partition counts: total={len(validation)} counts={counts}")
    if set(validation["partition"].astype(str).str.lower()) != {"validation"}:
        raise RuntimeError("Validation incident roster contains non-validation rows.")
    manifest = pd.read_csv(VALIDATION_MANIFEST_SOURCE, low_memory=False)
    if len(manifest) != 213:
        raise RuntimeError("Existing Validation manifest is not 213 incidents.")
    manifest.to_csv(ROSTER_OUT, index=False)
    return manifest


def load_validation_plan() -> pd.DataFrame:
    plan = pd.read_csv(VALIDATION_ACQUISITION_PLAN, low_memory=False)
    if plan["incident_uid"].nunique() != 213:
        raise RuntimeError("Validation acquisition plan does not cover 213 incidents.")
    return plan


def download_url(row: pd.Series) -> dict[str, Any]:
    url = str(row["mrt_url"])
    destination = cache_path_for_url(url)
    download_row = row.to_dict()
    download_row["local_path"] = str(destination)
    RAW_CACHE.mkdir(parents=True, exist_ok=True)
    return copy_or_download({key: str(value) for key, value in download_row.items()})


def compile_target_regex(targets: set[str]) -> re.Pattern[str] | None:
    cleaned = sorted({str(target) for target in targets if str(target)}, key=len, reverse=True)
    if not cleaned:
        return None
    return re.compile("|".join(re.escape(target) for target in cleaned))


def download_incident_files(unique_plan: pd.DataFrame, workers: int = DOWNLOAD_WORKERS) -> list[dict[str, Any]]:
    plan_rows = [row for _, row in unique_plan.iterrows()]
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, int(workers))) as executor:
        future_to_index = {executor.submit(download_url, row): index for index, row in enumerate(plan_rows)}
        for future in as_completed(future_to_index):
            index = future_to_index[future]
            try:
                result = future.result()
            except Exception as exc:  # pragma: no cover - network failures are environment-specific
                row = plan_rows[index]
                result = {
                    "mrt_url": str(row.get("mrt_url", "")),
                    "mrt_timestamp": str(row.get("mrt_timestamp", "")),
                    "collector": str(row.get("collector", "")),
                    "local_path": str(cache_path_for_url(str(row.get("mrt_url", "")))),
                    "download_status": "ERROR",
                    "notes": str(exc),
                }
            result["_input_order"] = index
            if "mrt_timestamp" not in result:
                result["mrt_timestamp"] = str(plan_rows[index].get("mrt_timestamp", ""))
            if "collector" not in result:
                result["collector"] = str(plan_rows[index].get("collector", ""))
            results.append(result)
    return sorted(results, key=lambda item: (str(item.get("mrt_timestamp", "")), int(item.get("_input_order", 0))))


def parse_incident(incident: dict[str, Any], plan_rows: pd.DataFrame) -> dict[str, Any]:
    incident = clean_incident_record(incident)
    uid = str(incident["incident_uid"])
    if evidence_path(uid).exists() and evidence_path(uid).stat().st_size > 0:
        frame = pd.read_parquet(evidence_path(uid))
        return {
            "incident_uid": uid,
            "incident_id": incident.get("incident_id", ""),
            "category": incident["category"],
            "partition": "validation",
            "processing_status": "TIMESTAMP_EVIDENCE_PASS" if len(frame) else "INSUFFICIENT_EVIDENCE",
            "review_reason": "",
            "mrt_files_processed": int(plan_rows["mrt_url"].nunique()),
            "mrt_files_downloaded_or_reused": int(plan_rows["mrt_url"].nunique()),
            "raw_records_inspected": "",
            "relevant_observations_retained": len(frame),
            "earliest_retained_timestamp": frame["bgp_timestamp_utc"].min() if len(frame) else "",
            "latest_retained_timestamp": frame["bgp_timestamp_utc"].max() if len(frame) else "",
            "evidence_path": str(evidence_path(uid)),
            "evidence_size_bytes": evidence_path(uid).stat().st_size,
        }

    target_asns, target_prefixes, leak_seg = relevance_targets(incident)
    rows = []
    raw_records = 0
    malformed = 0
    timestamp_errors = 0
    unique_plan = plan_rows.drop_duplicates("mrt_url").sort_values("mrt_timestamp")
    plan_by_url = {str(row["mrt_url"]): row for _, row in unique_plan.iterrows()}
    download_results = download_incident_files(unique_plan)
    for result in download_results:
        if str(result.get("download_status")) not in {"200", "CACHED", "REUSED_FROM_PILOT"}:
            continue
        path = Path(str(result["local_path"]))
        if not compression_ok(path):
            continue
        plan_row = plan_by_url.get(str(result.get("mrt_url", "")))
        collector = str(plan_row["collector"]) if plan_row is not None else str(result.get("collector", ""))
        process = subprocess.Popen(["bgpdump", "-q", "-m", str(path)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert process.stdout is not None
        for line in process.stdout:
            parts = line.rstrip("\n").split("|")
            if len(parts) < 6:
                malformed += 1
                continue
            raw_records += 1
            parsed = parse_bgpdump_line(line, uid, path, collector)
            if not parsed:
                malformed += 1
                continue
            if not relevant_with_targets(parsed, target_asns, target_prefixes, leak_seg):
                continue
            if not parse_utc(parsed["bgp_timestamp_utc"]):
                timestamp_errors += 1
                continue
            rows.append(
                {
                    "incident_uid": uid,
                    "incident_id": incident.get("incident_id", ""),
                    "category": incident["category"],
                    "partition": "validation",
                    "source_mrt_filename": parsed.get("source_mrt_filename", ""),
                    "collector": parsed.get("collector", ""),
                    "bgp_timestamp_utc": parsed.get("bgp_timestamp_utc", ""),
                    "peer_ip": parsed.get("peer_ip", ""),
                    "peer_asn": parsed.get("peer_asn", ""),
                    "message_update_type": parsed.get("message_update_type", ""),
                    "announcement_or_withdrawal": parsed.get("announcement_or_withdrawal", ""),
                    "prefix": parsed.get("prefix", ""),
                    "as_path": parsed.get("as_path", ""),
                    "origin_asn": parsed.get("origin_asn", ""),
                    "next_hop": parsed.get("next_hop", ""),
                    "communities": parsed.get("communities", ""),
                    "med": parsed.get("med", ""),
                    "local_pref": parsed.get("local_pref", ""),
                    "atomic_aggregate": parsed.get("atomic_aggregate", ""),
                    "aggregator": parsed.get("aggregator", ""),
                    "normalized_as_path": " ".join(parse_as_path(parsed.get("as_path", ""))),
                }
            )
        _ = process.stderr.read() if process.stderr else ""
        process.wait()
    if rows:
        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        pd.DataFrame(rows, columns=EVIDENCE_FIELDS).to_parquet(evidence_path(uid), index=False)
    ok_downloads = sum(1 for row in download_results if str(row.get("download_status")) in {"200", "CACHED", "REUSED_FROM_PILOT"})
    if rows:
        status = "TIMESTAMP_EVIDENCE_PASS"
        reason = ""
    elif ok_downloads == 0:
        status = "RETRY_REQUIRED_DOWNLOAD_CONTEXT"
        reason = "no usable MRT files were downloaded/reused in this execution context"
    else:
        status = "INSUFFICIENT_EVIDENCE"
        reason = "no incident-relevant timestamped observations retained"
    timestamps = [row["bgp_timestamp_utc"] for row in rows]
    return {
        "incident_uid": uid,
        "incident_id": incident.get("incident_id", ""),
        "category": incident["category"],
        "partition": "validation",
        "processing_status": status,
        "review_reason": reason,
        "mrt_files_processed": int(unique_plan["mrt_url"].nunique()),
        "mrt_files_downloaded_or_reused": ok_downloads,
        "raw_records_inspected": raw_records,
        "relevant_observations_retained": len(rows),
        "earliest_retained_timestamp": min(timestamps) if timestamps else "",
        "latest_retained_timestamp": max(timestamps) if timestamps else "",
        "malformed_records": malformed,
        "timestamp_errors": timestamp_errors,
        "evidence_path": str(evidence_path(uid)) if rows else "",
        "evidence_size_bytes": evidence_path(uid).stat().st_size if rows and evidence_path(uid).exists() else 0,
    }


def reconstruct_timestamped_evidence(manifest: pd.DataFrame, plan: pd.DataFrame) -> pd.DataFrame:
    rows = []
    by_uid = {uid: group.copy() for uid, group in plan.groupby("incident_uid")}
    for index, incident in enumerate(manifest.sort_values(["category", "incident_uid"]).to_dict("records"), start=1):
        uid = str(incident["incident_uid"])
        result = parse_incident(incident, by_uid[uid])
        rows.append(result)
        if index % 10 == 0 or index == len(manifest):
            pd.DataFrame(rows).to_csv(EVIDENCE_MANIFEST, index=False)
            print(f"Validation timestamp evidence processed {index}/{len(manifest)} incidents", flush=True)
    frame = pd.DataFrame(rows)
    frame.to_csv(EVIDENCE_MANIFEST, index=False)
    return frame


def load_evidence(uid: str) -> pd.DataFrame:
    path = evidence_path(uid)
    if not path.exists() or path.stat().st_size <= 0:
        return pd.DataFrame(columns=EVIDENCE_FIELDS)
    df = pd.read_parquet(path)
    df["bgp_timestamp_utc"] = pd.to_datetime(df["bgp_timestamp_utc"], utc=True, errors="coerce")
    return df


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


def load_rpki_mapping() -> dict[str, str]:
    return selected_snapshot_by_observation_date(pd.read_csv(TRAIN_RPKI_MAPPING, low_memory=False))


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


def rpki_snapshot_for_onset(onset: pd.Timestamp, mapping: dict[str, str], audit_rows: list[dict[str, Any]]) -> str:
    date = onset.strftime("%Y-%m-%d")
    selected = mapping.get(date)
    if selected:
        audit_rows.append({"observation_date": date, "selected_rpki_snapshot": selected, "mapping_source": "TRAIN_RPKI_MAPPING", "fallback_used": "NO", "status": "PASS"})
        return selected
    parsed = onset.date()
    for days_back in range(0, 31):
        candidate = (parsed - timedelta(days=days_back)).isoformat()
        if ensure_rpki_snapshot(candidate):
            audit_rows.append(
                {
                    "observation_date": date,
                    "selected_rpki_snapshot": candidate,
                    "mapping_source": "VALIDATION_EXACT_OR_NEAREST_EARLIER_SNAPSHOT_USING_FROZEN_POLICY",
                    "fallback_used": "NO" if days_back == 0 else "YES",
                    "days_back": days_back,
                    "status": "PASS",
                }
            )
            return candidate
    audit_rows.append({"observation_date": date, "selected_rpki_snapshot": "", "mapping_source": "VALIDATION_EXACT_OR_NEAREST_EARLIER_SNAPSHOT_USING_FROZEN_POLICY", "fallback_used": "YES", "days_back": "", "status": "FAIL"})
    raise RuntimeError(f"Missing usable exact or nearest-earlier RPKI snapshot for {date}")


def load_vrps(snapshot_date: str):
    vrps = []
    for tal in TRUST_ANCHORS:
        path = cache_path(tal, snapshot_date)
        if not path.exists() or path.stat().st_size <= 0:
            raise FileNotFoundError(f"Missing RPKI snapshot {path}")
        vrps.extend(load_vrps_for_file(path, tal))
    return build_vrp_index(vrps)


def rpki_features(rows: pd.DataFrame, vrp_index: Any) -> dict[str, Any]:
    if not len(rows):
        return zero_rpki_features()
    state_counts: Counter[str] = Counter()
    valid_prefixes = set()
    invalid_prefixes = set()
    not_found_prefixes = set()
    for row in rows.itertuples(index=False):
        result = validate_rov(row.prefix, row.origin_asn, vrp_index)
        state_counts[result.state] += 1
        if result.state == "VALID":
            valid_prefixes.add(row.prefix)
        elif result.state in {"INVALID_ORIGIN", "INVALID_LENGTH"}:
            invalid_prefixes.add(row.prefix)
        elif result.state == "NOT_FOUND":
            not_found_prefixes.add(row.prefix)
    valid = state_counts["VALID"]
    invalid_origin = state_counts["INVALID_ORIGIN"]
    invalid_length = state_counts["INVALID_LENGTH"]
    invalid = invalid_origin + invalid_length
    not_found = state_counts["NOT_FOUND"]
    unevaluable = state_counts["UNEVALUABLE"]
    evaluable = valid + invalid + not_found
    total = evaluable + unevaluable
    dominant = "NO_PREFIX_ORIGIN_EVIDENCE" if total == 0 else max(["VALID", "INVALID_ORIGIN", "INVALID_LENGTH", "NOT_FOUND", "UNEVALUABLE"], key=lambda s: (state_counts[s], s))
    features = zero_rpki_features()
    features.update(
        {
            "rpki_evidence_observation_count": int(total),
            "rpki_evaluable_observation_count": int(evaluable),
            "rpki_valid_observation_count": int(valid),
            "rpki_invalid_observation_count": int(invalid),
            "rpki_not_found_observation_count": int(not_found),
            "rpki_unevaluable_observation_count": int(unevaluable),
            "rpki_invalid_origin_observation_count": int(invalid_origin),
            "rpki_invalid_maxlength_observation_count": int(invalid_length),
            "rpki_valid_observation_ratio": valid / evaluable if evaluable else float("nan"),
            "rpki_invalid_observation_ratio": invalid / evaluable if evaluable else float("nan"),
            "rpki_not_found_observation_ratio": not_found / evaluable if evaluable else float("nan"),
            "rpki_unique_valid_prefix_count": len(valid_prefixes),
            "rpki_unique_invalid_prefix_count": len(invalid_prefixes),
            "rpki_unique_not_found_prefix_count": len(not_found_prefixes),
            "rpki_state_diversity_count": sum(1 for s in ["VALID", "INVALID_ORIGIN", "INVALID_LENGTH", "NOT_FOUND", "UNEVALUABLE"] if state_counts[s] > 0),
            "rpki_dominant_state_code": STATE_TO_CODE[dominant],
        }
    )
    return features


def collect_validation_prefix_origin_counts(horizon: pd.DataFrame) -> pd.DataFrame:
    rows: list[pd.DataFrame] = []
    for index, (uid, group) in enumerate(horizon.groupby("incident_uid", sort=True), start=1):
        selected = pd.to_datetime(group["selected_onset_utc"].iloc[0], utc=True, errors="raise")
        max_cutoff = pd.to_datetime(group["horizon_cutoff_utc"].max(), utc=True, errors="raise")
        evidence = load_evidence(uid)
        if not len(evidence):
            continue
        evidence = evidence[(evidence["bgp_timestamp_utc"] >= selected) & (evidence["bgp_timestamp_utc"] <= max_cutoff)].copy()
        if not len(evidence):
            continue
        evidence["prefix"] = evidence["prefix"].map(as_text)
        evidence["origin_asn"] = evidence["origin_asn"].map(as_text)
        for meta in group.sort_values("horizon_seconds").itertuples(index=False):
            cutoff = pd.to_datetime(meta.horizon_cutoff_utc, utc=True, errors="raise")
            subset = evidence[evidence["bgp_timestamp_utc"] <= cutoff]
            if not len(subset):
                continue
            keyed = subset.groupby(["prefix", "origin_asn"], dropna=False).size().reset_index(name="observation_count")
            keyed.insert(0, "incident_uid", meta.incident_uid)
            keyed.insert(1, "incident_id", meta.incident_id)
            keyed.insert(2, "category", meta.category)
            keyed.insert(3, "partition", meta.partition)
            keyed.insert(4, "horizon_seconds", int(meta.horizon_seconds))
            keyed.insert(5, "selected_onset_utc", meta.selected_onset_utc)
            keyed.insert(6, "horizon_cutoff_utc", meta.horizon_cutoff_utc)
            keyed.insert(7, "observation_count_in_horizon", int(meta.observation_count_in_horizon))
            rows.append(keyed)
        if index % 25 == 0 or index == horizon["incident_uid"].nunique():
            print(f"Collected Validation RPKI horizon keys for {index}/{horizon['incident_uid'].nunique()} incidents", flush=True)
    if not rows:
        return pd.DataFrame(columns=["incident_uid", "incident_id", "category", "partition", "horizon_seconds", "selected_onset_utc", "horizon_cutoff_utc", "observation_count_in_horizon", "prefix", "origin_asn", "observation_count"])
    return pd.concat(rows, ignore_index=True)


def add_validation_snapshot_dates(counts: pd.DataFrame, mapping: dict[str, str], audit_rows: list[dict[str, Any]]) -> pd.DataFrame:
    counts = counts.copy()
    selected_dates: dict[str, str] = {}
    for value in sorted(set(counts["selected_onset_utc"].astype(str))):
        onset = pd.to_datetime(value, utc=True, errors="raise")
        selected_dates[value] = rpki_snapshot_for_onset(onset, mapping, audit_rows)
    counts["snapshot_date"] = counts["selected_onset_utc"].astype(str).map(selected_dates)
    return counts


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
        rows.append({"snapshot_date": snapshot_date, "prefix": row.prefix, "origin_asn": row.origin_asn, "rpki_state": result.state, "covering_vrp_count": result.covering_vrp_count})
    return pd.DataFrame(rows)


def rpki_features_from_enriched_counts(horizon: pd.DataFrame, enriched: pd.DataFrame) -> pd.DataFrame:
    key_cols = ["incident_uid", "incident_id", "category", "partition", "horizon_seconds", "selected_onset_utc", "horizon_cutoff_utc", "observation_count_in_horizon"]
    rows: list[dict[str, Any]] = []
    grouped = {key: group for key, group in enriched.groupby(key_cols, dropna=False)} if len(enriched) else {}
    for meta in horizon.sort_values(["incident_uid", "horizon_seconds"]).itertuples(index=False):
        key = tuple(getattr(meta, col) for col in key_cols)
        group = grouped.get(key)
        output = {col: getattr(meta, col) for col in key_cols}
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
                "rpki_evidence_observation_count": int(total),
                "rpki_evaluable_observation_count": int(evaluable),
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


def optimized_validation_rpki(horizon: pd.DataFrame, mapping: dict[str, str], audit_rows: list[dict[str, Any]]) -> pd.DataFrame:
    counts = collect_validation_prefix_origin_counts(horizon)
    if not len(counts):
        return rpki_features_from_enriched_counts(horizon, pd.DataFrame())
    counts = add_validation_snapshot_dates(counts, mapping, audit_rows)
    unique_keys = counts[["snapshot_date", "prefix", "origin_asn"]].drop_duplicates(ignore_index=True)
    grouped_keys = [(str(snapshot_date), keys.copy()) for snapshot_date, keys in unique_keys.groupby("snapshot_date", sort=True)]
    lookup_parts_by_date: dict[str, pd.DataFrame] = {}
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = {executor.submit(validate_keys_for_snapshot, snapshot_date, keys): (snapshot_date, len(keys)) for snapshot_date, keys in grouped_keys}
        completed = 0
        for future in as_completed(futures):
            snapshot_date, key_count = futures[future]
            lookup_parts_by_date[snapshot_date] = future.result()
            completed += 1
            print(f"Validation RPKI validated snapshot {snapshot_date} ({completed}/{len(futures)}) with {key_count} unique prefix-origin keys", flush=True)
    lookup = pd.concat([lookup_parts_by_date[snapshot_date] for snapshot_date, _ in grouped_keys], ignore_index=True)
    enriched = counts.merge(lookup, on=["snapshot_date", "prefix", "origin_asn"], how="left", validate="many_to_one")
    return rpki_features_from_enriched_counts(horizon, enriched)


def build_horizon_features(manifest: pd.DataFrame, evidence_manifest: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    rows = []
    evaluability = []
    mapping = load_rpki_mapping()
    caida_cache: dict[str, dict[tuple[str, str], str]] = {}
    rpki_cache: dict[str, Any] = {}
    rpki_audit_rows: list[dict[str, Any]] = []
    for incident in manifest.to_dict("records"):
        uid = str(incident["incident_uid"])
        ev = load_evidence(uid)
        start = pd.to_datetime(incident["start_utc"], utc=True, errors="raise")
        if not len(ev):
            evaluability.append({**incident, "tti_status": "TTI_NOT_EVALUABLE_INSUFFICIENT_ROUTEVIEWS_EVIDENCE", "selected_onset_utc": "", "notes": "no retained incident-relevant timestamped observations"})
            continue
        post = ev[ev["bgp_timestamp_utc"] >= start].copy()
        if not len(post):
            evaluability.append({**incident, "tti_status": "TTI_NOT_EVALUABLE_ONSET_UNRESOLVED", "selected_onset_utc": "", "notes": "retained incident-relevant observations exist only before documented start"})
            continue
        onset = post["bgp_timestamp_utc"].min()
        evaluability.append({**incident, "tti_status": "TTI_EVALUABLE", "selected_onset_utc": format_utc(onset), "notes": ""})
        caida_snapshot, caida_url, _ = selected_snapshot_for_window(format_utc(onset))
        if caida_snapshot not in caida_cache:
            caida_cache[caida_snapshot] = load_relationships(download_caida_snapshot(caida_snapshot, caida_url))
        for horizon in HORIZONS:
            cutoff = onset + pd.Timedelta(seconds=horizon)
            subset = post[(post["bgp_timestamp_utc"] >= onset) & (post["bgp_timestamp_utc"] <= cutoff)].copy()
            aggregate = WindowAggregate()
            caida_aggregate = CaidaWindowAggregate()
            for record in subset.to_dict("records"):
                update_aggregate(aggregate, record)
                update_caida_aggregate(caida_aggregate, record, caida_cache[caida_snapshot])
            behavioral = features_from_aggregate(aggregate)
            caida = features_from_caida_aggregate(caida_aggregate)
            max_ts = subset["bgp_timestamp_utc"].max() if len(subset) else pd.NaT
            row = {
                "incident_uid": uid,
                "incident_id": incident.get("incident_id", ""),
                "category": incident["category"],
                "partition": "validation",
                "horizon_seconds": horizon,
                "selected_onset_utc": format_utc(onset),
                "horizon_cutoff_utc": format_utc(cutoff),
                "observation_count_in_horizon": int(len(subset)),
                "max_bgp_timestamp_utc": format_utc(max_ts) if pd.notna(max_ts) else "",
            }
            row.update(behavioral)
            row.update(caida)
            rows.append(row)
    eval_df = pd.DataFrame(evaluability)
    feature_df = pd.DataFrame(rows)
    horizon = feature_df[["incident_uid", "incident_id", "category", "partition", "horizon_seconds", "selected_onset_utc", "horizon_cutoff_utc", "observation_count_in_horizon", "max_bgp_timestamp_utc"]].copy() if len(feature_df) else pd.DataFrame()
    if len(feature_df):
        rpki_df = optimized_validation_rpki(horizon, mapping, rpki_audit_rows)
        merge_keys = ["incident_uid", "incident_id", "category", "partition", "horizon_seconds", "selected_onset_utc", "horizon_cutoff_utc", "observation_count_in_horizon"]
        feature_df = feature_df.merge(rpki_df[merge_keys + RPKI_FEATURE_NAMES], on=merge_keys, how="left", validate="one_to_one")
    if rpki_audit_rows:
        pd.DataFrame(rpki_audit_rows).drop_duplicates().to_csv(RPKI_SNAPSHOT_AUDIT, index=False)
    return eval_df, horizon, feature_df


def write_gates(feature_df: pd.DataFrame, horizon: pd.DataFrame, feature_schema: list[str]) -> None:
    rows = []
    for feature in feature_schema:
        rows.append(
            {
                "feature_name": feature,
                "present": feature in feature_df.columns,
                "status": "PASS" if feature in feature_df.columns else "FAIL",
            }
        )
    write_csv(V4_COMPAT, rows, ["feature_name", "present", "status"])
    leak_rows = []
    for row in horizon.itertuples(index=False):
        cutoff = pd.to_datetime(row.horizon_cutoff_utc, utc=True)
        max_ts = pd.to_datetime(row.max_bgp_timestamp_utc, utc=True, errors="coerce") if as_text(row.max_bgp_timestamp_utc) else pd.NaT
        ok = int(row.observation_count_in_horizon) == 0 or (pd.notna(max_ts) and max_ts <= cutoff)
        leak_rows.append(
            {
                "incident_uid": row.incident_uid,
                "horizon_seconds": row.horizon_seconds,
                "horizon_cutoff_utc": row.horizon_cutoff_utc,
                "max_bgp_timestamp_utc": row.max_bgp_timestamp_utc,
                "status": "PASS" if ok else "FAIL",
            }
        )
    write_csv(LEAKAGE, leak_rows, ["incident_uid", "horizon_seconds", "horizon_cutoff_utc", "max_bgp_timestamp_utc", "status"])


def load_models() -> list[Any]:
    return [joblib.load(MODEL_DIR / f"level1_xgb_fold_{fold}_hist_njobs_minus1.joblib") for fold in [1, 2, 3, 4, 5]]


def rank_for_true_class(true_class: str, probabilities: np.ndarray) -> int:
    order = np.argsort(probabilities)[::-1]
    true_index = LABELS.index(normalize_class(true_class))
    return int(np.where(order == true_index)[0][0] + 1)


def top_order(probabilities: np.ndarray) -> str:
    return " > ".join(DISPLAY[LABELS[index]] for index in np.argsort(probabilities)[::-1])


def score(feature_df: pd.DataFrame, feature_schema: list[str]) -> pd.DataFrame:
    models = load_models()
    probs = np.stack([model.predict_proba(feature_df[feature_schema]) for model in models], axis=0).mean(axis=0)
    out = feature_df[["incident_id", "incident_uid", "category", "partition", "horizon_seconds", "selected_onset_utc", "horizon_cutoff_utc", "observation_count_in_horizon"]].copy()
    out["true_class"] = out["category"].map(lambda x: DISPLAY[normalize_class(x)])
    out["hijack_probability"] = probs[:, 0]
    out["leak_probability"] = probs[:, 1]
    out["outage_probability"] = probs[:, 2]
    out["predicted_top1_class"] = [DISPLAY[LABELS[i]] for i in probs.argmax(axis=1)]
    out["top2_ordering"] = [top_order(row) for row in probs]
    out["true_class_rank"] = [rank_for_true_class(cls, row) for cls, row in zip(out["true_class"], probs)]
    out["top1_correct"] = out["predicted_top1_class"].eq(out["true_class"])
    out["top2_correct"] = out["true_class_rank"].le(2)
    out["experiment_scope"] = EXPERIMENT_LABEL
    return out


def bootstrap_macro_f1(group: pd.DataFrame) -> dict[str, float]:
    rng = np.random.default_rng(BOOTSTRAP_SEED + int(group["horizon_seconds"].iloc[0]))
    ids = group["incident_uid"].to_numpy()
    true = group.set_index("incident_uid")["true_class"]
    pred = group.set_index("incident_uid")["predicted_top1_class"]
    values = []
    for _ in range(BOOTSTRAP_ITERATIONS):
        sample = rng.choice(ids, size=len(ids), replace=True)
        values.append(f1_score(true.loc[sample], pred.loc[sample], labels=DISPLAY_LABELS, average="macro", zero_division=0))
    arr = np.asarray(values)
    return {
        "macro_f1_ci_lower": float(np.quantile(arr, 0.025)),
        "macro_f1_ci_upper": float(np.quantile(arr, 0.975)),
        "macro_f1_bootstrap_mean": float(arr.mean()),
        "macro_f1_bootstrap_std": float(arr.std(ddof=1)),
    }


def metric_outputs(pred: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    metric_rows = []
    per_rows = []
    boot_rows = []
    conf_rows = []
    for horizon, group in pred.groupby("horizon_seconds", sort=True):
        y_true = group["true_class"]
        y_pred = group["predicted_top1_class"]
        precision, recall, f1, support = precision_recall_fscore_support(y_true, y_pred, labels=DISPLAY_LABELS, zero_division=0)
        boot = bootstrap_macro_f1(group)
        boot_rows.append({"horizon_seconds": int(horizon), "n_incidents": len(group), "bootstrap_iterations": BOOTSTRAP_ITERATIONS, **boot, "sample_unit": "incident"})
        metric_rows.append(
            {
                "horizon_seconds": int(horizon),
                "n_incidents": len(group),
                "macro_f1": f1_score(y_true, y_pred, labels=DISPLAY_LABELS, average="macro", zero_division=0),
                "macro_f1_ci_lower": boot["macro_f1_ci_lower"],
                "macro_f1_ci_upper": boot["macro_f1_ci_upper"],
                "top1_accuracy": group["top1_correct"].mean(),
                "top2_accuracy": group["top2_correct"].mean(),
                "mrr": (1.0 / group["true_class_rank"]).mean(),
            }
        )
        matrix = confusion_matrix(y_true, y_pred, labels=DISPLAY_LABELS)
        for i, cls in enumerate(DISPLAY_LABELS):
            per_rows.append({"horizon_seconds": int(horizon), "class": cls, "precision": precision[i], "recall": recall[i], "f1": f1[i], "support": int(support[i])})
            for j, pred_cls in enumerate(DISPLAY_LABELS):
                conf_rows.append({"horizon_seconds": int(horizon), "true_class": cls, "predicted_class": pred_cls, "count": int(matrix[i, j])})
    return pd.DataFrame(metric_rows), pd.DataFrame(per_rows), pd.DataFrame(conf_rows), pd.DataFrame(boot_rows)


def checkpoint_label(value: int | None) -> str:
    return f"<={value}s" if value is not None else "NOT_IDENTIFIED_WITHIN_300S"


def horizon_sort_key(label: str) -> int:
    return {"<=30s": 0, "<=60s": 1, "<=120s": 2, "<=300s": 3, "NOT_IDENTIFIED_WITHIN_300S": 4}[label]


def checkpoint_outputs(pred: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    rows = []
    traj = []
    for uid, group in pred.sort_values("horizon_seconds").groupby("incident_uid", sort=True):
        horizons = group["horizon_seconds"].astype(int).tolist()
        top1 = group["top1_correct"].astype(bool).tolist()
        top2 = group["top2_correct"].astype(bool).tolist()
        top1_cp = next((h for h, ok in zip(horizons, top1) if ok), None)
        top2_cp = next((h for h, ok in zip(horizons, top2) if ok), None)
        stable = None
        for idx, horizon in enumerate(horizons):
            if all(top1[idx:]):
                stable = horizon
                break
        rows.append(
            {
                "incident_id": group["incident_id"].iloc[0],
                "incident_uid": uid,
                "true_class": group["true_class"].iloc[0],
                "top1_tti_checkpoint": checkpoint_label(top1_cp),
                "top2_tti_checkpoint": checkpoint_label(top2_cp),
                "stable_correct_checkpoint": checkpoint_label(stable),
                "top1_correct_then_later_incorrect": any(top1[i] and not all(top1[i:]) for i in range(len(top1))),
                "top2_correct_then_later_incorrect": any(top2[i] and not all(top2[i:]) for i in range(len(top2))),
            }
        )
        traj.append(
            {
                "incident_id": group["incident_id"].iloc[0],
                "incident_uid": uid,
                "true_class": group["true_class"].iloc[0],
                "top1_trajectory": " -> ".join(f"{int(r.horizon_seconds)}s:{r.predicted_top1_class}" for r in group.itertuples(index=False)),
                "top2_rank_trajectory": " -> ".join(f"{int(r.horizon_seconds)}s:rank{int(r.true_class_rank)}" for r in group.itertuples(index=False)),
            }
        )
    check = pd.DataFrame(rows)
    cumulative_rows = []
    for mode, col in [("Top-1", "top1_tti_checkpoint"), ("Top-2", "top2_tti_checkpoint")]:
        for label in ["<=30s", "<=60s", "<=120s", "<=300s", "NOT_IDENTIFIED_WITHIN_300S"]:
            count = int(check[col].eq(label).sum()) if label == "NOT_IDENTIFIED_WITHIN_300S" else int(check[col].map(horizon_sort_key).le(horizon_sort_key(label)).sum())
            cumulative_rows.append({"identification_type": mode, "checkpoint": label, "count": count, "percent": count / len(check), "denominator": len(check)})
    stability_rows = []
    counts = check["stable_correct_checkpoint"].value_counts().to_dict()
    for label in ["<=30s", "<=60s", "<=120s", "<=300s", "NOT_IDENTIFIED_WITHIN_300S"]:
        count = int(counts.get(label, 0))
        stability_rows.append({"stable_correct_checkpoint": label, "count": count, "percent": count / len(check), "denominator": len(check)})
    stability_rows.append({"stable_correct_checkpoint": "BECOMES_TOP1_CORRECT_THEN_LATER_INCORRECT", "count": int(check["top1_correct_then_later_incorrect"].sum()), "percent": check["top1_correct_then_later_incorrect"].mean(), "denominator": len(check)})
    return check, pd.DataFrame(cumulative_rows), pd.DataFrame(traj), pd.DataFrame(stability_rows)


def compare_train_validation(metrics: pd.DataFrame, cumulative: pd.DataFrame, stability: pd.DataFrame) -> pd.DataFrame:
    rows = []
    train_metrics = pd.read_csv(TRAIN_METRICS)
    for _, val in metrics.iterrows():
        train = train_metrics[train_metrics["horizon_seconds"].eq(val["horizon_seconds"])].iloc[0]
        for metric in ["macro_f1", "top1_accuracy", "top2_accuracy", "mrr"]:
            rows.append({"comparison": "horizon_metric", "horizon_seconds": int(val["horizon_seconds"]), "metric": metric, "train": float(train[metric]), "validation": float(val[metric]), "delta_validation_minus_train": float(val[metric] - train[metric])})
    train_cum = pd.read_csv(TRAIN_CUMULATIVE)
    for _, val in cumulative.iterrows():
        train = train_cum[(train_cum["identification_type"].eq(val["identification_type"])) & (train_cum["checkpoint"].eq(val["checkpoint"]))].iloc[0]
        rows.append({"comparison": "cumulative_identification", "horizon_seconds": "", "metric": f"{val['identification_type']} {val['checkpoint']}", "train": float(train["percent"]), "validation": float(val["percent"]), "delta_validation_minus_train": float(val["percent"] - train["percent"])})
    train_stab = pd.read_csv(TRAIN_STABILITY)
    for _, val in stability.iterrows():
        match = train_stab[train_stab["stable_correct_checkpoint"].eq(val["stable_correct_checkpoint"])]
        if len(match):
            train = match.iloc[0]
            rows.append({"comparison": "stability", "horizon_seconds": "", "metric": val["stable_correct_checkpoint"], "train": float(train["percent"]), "validation": float(val["percent"]), "delta_validation_minus_train": float(val["percent"] - train["percent"])})
    return pd.DataFrame(rows)


def save_figures(metrics: pd.DataFrame, cumulative: pd.DataFrame, comparison: pd.DataFrame) -> None:
    FIGURE_DIR.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(8.2, 4.6))
    x = np.arange(len(HORIZONS))
    for metric, label in [("macro_f1", "Macro F1"), ("top2_accuracy", "Top-2"), ("mrr", "MRR")]:
        y = metrics.sort_values("horizon_seconds")[metric].to_numpy()
        ax.plot(x, y, marker="o", label=label)
    ax.set_xticks(x)
    ax.set_xticklabels([f"{h}s" for h in HORIZONS])
    ax.set_ylim(0, 1.05)
    ax.grid(axis="y", alpha=0.25)
    ax.legend(frameon=False)
    fig.savefig(FIGURE_DIR / "figure_validation_tti_performance_by_horizon_v1.png", dpi=300, bbox_inches="tight")
    fig.savefig(FIGURE_DIR / "figure_validation_tti_performance_by_horizon_v1.pdf", dpi=300, bbox_inches="tight")
    fig.savefig(FIGURE_DIR / "figure_validation_tti_performance_by_horizon_v1_highres_chart_only.jpg", dpi=600, bbox_inches="tight", pil_kwargs={"quality": 95})
    plt.close(fig)

    top1 = cumulative[cumulative["identification_type"].eq("Top-1") & ~cumulative["checkpoint"].eq("NOT_IDENTIFIED_WITHIN_300S")]
    fig, ax = plt.subplots(figsize=(7.0, 4.2))
    bars = ax.bar(top1["checkpoint"], top1["percent"])
    for bar, count, pct in zip(bars, top1["count"], top1["percent"]):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.015, f"{int(count)}\n{pct:.1%}", ha="center", fontsize=8)
    ax.set_ylim(0, 1.05)
    ax.grid(axis="y", alpha=0.25)
    fig.savefig(FIGURE_DIR / "figure_validation_tti_cumulative_top1_v1.png", dpi=300, bbox_inches="tight")
    fig.savefig(FIGURE_DIR / "figure_validation_tti_cumulative_top1_v1.pdf", dpi=300, bbox_inches="tight")
    fig.savefig(FIGURE_DIR / "figure_validation_tti_cumulative_top1_v1_highres_chart_only.jpg", dpi=600, bbox_inches="tight", pil_kwargs={"quality": 95})
    plt.close(fig)


def write_summary(metrics: pd.DataFrame, cumulative: pd.DataFrame, evaluability: pd.DataFrame, comparison: pd.DataFrame, disposition: str) -> None:
    eval_counts = evaluability["tti_status"].value_counts().to_dict()
    lines = [
        "# Validation TTI Confirmation Summary v1",
        "",
        f"**{EXPERIMENT_LABEL}**",
        "",
        "- Frozen protocol hash verification: PASS",
        "- Validation incidents processed: 213",
        f"- TTI evaluability status counts: {json.dumps(eval_counts, sort_keys=True)}",
        "- Final Holdout accessed/recomputed/analyzed for TTI: NO",
        "- Model retrained/tuned/calibrated/modified: NO",
        "- Existing Final Holdout metrics remain authoritative: Macro F1 = 0.920177; Top-2 = 0.990610; MRR = 0.958529",
        "",
        "## Horizon Metrics",
        "",
        metrics.to_markdown(index=False),
        "",
        "## Cumulative Identification",
        "",
        cumulative.to_markdown(index=False),
        "",
        "## TRAIN vs Validation Deltas",
        "",
        comparison.to_markdown(index=False),
        "",
        f"Decision: {disposition}",
    ]
    SUMMARY.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run() -> str:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    verify_protocol_hashes()
    manifest = load_validation_manifest()
    plan = load_validation_plan()
    evidence_manifest = reconstruct_timestamped_evidence(manifest, plan)
    if evidence_manifest["processing_status"].eq("RETRY_REQUIRED_DOWNLOAD_CONTEXT").all():
        evidence_manifest.to_csv(EVALUABILITY, index=False)
        write_summary(
            pd.DataFrame(),
            pd.DataFrame(),
            evidence_manifest.rename(columns={"processing_status": "tti_status"}),
            pd.DataFrame(),
            "VALIDATION_TTI_CONFIRMATION_REQUIRES_REVIEW",
        )
        return "VALIDATION_TTI_CONFIRMATION_REQUIRES_REVIEW"
    evaluability, horizon, feature_df = build_horizon_features(manifest, evidence_manifest)
    evaluability.to_csv(EVALUABILITY, index=False)
    horizon.to_csv(HORIZON_MANIFEST, index=False)
    feature_schema = json.loads(SCHEMA.read_text())
    if len(feature_schema) != 74:
        raise RuntimeError("Frozen V4 schema is not 74 features.")
    feature_df = feature_df[["incident_uid", "incident_id", "category", "partition", "horizon_seconds", "selected_onset_utc", "horizon_cutoff_utc", "observation_count_in_horizon", "max_bgp_timestamp_utc"] + feature_schema].sort_values(["incident_uid", "horizon_seconds"]).reset_index(drop=True)
    feature_df.to_parquet(HORIZON_V4, index=False)
    write_gates(feature_df, horizon, feature_schema)
    if not len(feature_df) or set(pd.read_csv(V4_COMPAT)["status"]) != {"PASS"} or set(pd.read_csv(LEAKAGE)["status"]) != {"PASS"}:
        raise RuntimeError("Validation TTI feature gates failed.")
    predictions = score(feature_df, feature_schema)
    metrics, per_class, confusion, bootstrap = metric_outputs(predictions)
    checkpoints, cumulative, trajectories, stability = checkpoint_outputs(predictions)
    comparison = compare_train_validation(metrics, cumulative, stability)
    predictions.to_csv(PREDICTIONS, index=False)
    metrics.to_csv(HORIZON_METRICS, index=False)
    per_class.to_csv(PER_CLASS_METRICS, index=False)
    confusion.to_csv(CONFUSION, index=False)
    checkpoints.to_csv(CHECKPOINTS, index=False)
    cumulative.to_csv(CUMULATIVE, index=False)
    trajectories.to_csv(TRAJECTORIES, index=False)
    stability.to_csv(STABILITY, index=False)
    bootstrap.to_csv(BOOTSTRAP, index=False)
    comparison.to_csv(COMPARISON, index=False)
    save_figures(metrics, cumulative, comparison)
    status_ok = (
        manifest["incident_uid"].nunique() == 213
        and predictions["partition"].astype(str).str.lower().eq("validation").all()
        and predictions["incident_uid"].nunique() == feature_df["incident_uid"].nunique()
        and np.allclose(predictions[PROB_COLS].sum(axis=1).to_numpy(), 1.0, atol=1e-6)
    )
    disposition = "VALIDATION_TTI_CONFIRMATION_COMPLETE" if status_ok else "VALIDATION_TTI_CONFIRMATION_REQUIRES_REVIEW"
    write_summary(metrics, cumulative, evaluability, comparison, disposition)
    return disposition


def main() -> None:
    parser = argparse.ArgumentParser(description="Run one-time Validation TTI confirmation under the frozen protocol.")
    parser.parse_args()
    print(run())


if __name__ == "__main__":
    main()
