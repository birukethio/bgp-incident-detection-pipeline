from __future__ import annotations

import argparse
import csv
import json
import math
import shutil
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

try:
    from bgp_incident_detection.audit import write_csv
    from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES
    from bgp_incident_detection.behavioral_features import WindowAggregate, features_from_aggregate, update_aggregate
    from bgp_incident_detection.audit import parse_utc
    from bgp_incident_detection.mrt_parser import parse_as_path_set, parse_bgpdump_line
    from bgp_incident_detection.train_batch_engine import DiskPolicy, VOLUME_BATCH_PLAN, free_bytes, required_free_bytes, source_commit
    from bgp_incident_detection.train_incident_scale import (
        ACQUISITION_PLAN,
        BEHAVIORAL_FEATURE_COUNT,
        DOWNLOAD_AUDIT,
        FEATURE_QUALITY,
        FEATURE_SUMMARY,
        FEATURES_PARQUET,
        MANIFEST,
        QUALITY_GATE,
        TRAIN_SCALE_DIR,
        compression_ok,
        copy_or_download,
        load_csv,
        relevance_targets,
        relevant_with_targets,
        temporal_windows,
    )
    from bgp_incident_detection.windows import floor_to_five_minutes, format_utc, window_id
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import write_csv
    from src.bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES
    from src.bgp_incident_detection.behavioral_features import WindowAggregate, features_from_aggregate, update_aggregate
    from src.bgp_incident_detection.audit import parse_utc
    from src.bgp_incident_detection.mrt_parser import parse_as_path_set, parse_bgpdump_line
    from src.bgp_incident_detection.train_batch_engine import DiskPolicy, VOLUME_BATCH_PLAN, free_bytes, required_free_bytes, source_commit
    from src.bgp_incident_detection.train_incident_scale import (
        ACQUISITION_PLAN,
        BEHAVIORAL_FEATURE_COUNT,
        DOWNLOAD_AUDIT,
        FEATURE_QUALITY,
        FEATURE_SUMMARY,
        FEATURES_PARQUET,
        MANIFEST,
        QUALITY_GATE,
        TRAIN_SCALE_DIR,
        compression_ok,
        copy_or_download,
        load_csv,
        relevance_targets,
        relevant_with_targets,
        temporal_windows,
    )
    from src.bgp_incident_detection.windows import floor_to_five_minutes, format_utc, window_id


FEATURES_DIR = TRAIN_SCALE_DIR / "features_v1"
RAW_BATCH_ROOT = Path("data/raw_mrt/train_batches")
PARSED_TRAIN_ROOT = Path("data/parsed_mrt/train")
BATCH_EXECUTION_SUMMARY = TRAIN_SCALE_DIR / "train_batch_execution_summary_v1.csv"
WINDOW_IMBALANCE = TRAIN_SCALE_DIR / "train_window_imbalance_analysis_v1.csv"
BEHAVIORAL_CORPUS_AUDIT = TRAIN_SCALE_DIR / "train_behavioral_corpus_audit_v1.csv"
NOTEBOOK = Path("notebooks/30_full_train_behavioral_execution.ipynb")

DOWNLOAD_AUDIT_FIELDS = [
    "batch_id",
    "incident_uid",
    "category",
    "mrt_url",
    "local_path",
    "download_status",
    "file_size",
    "checksum",
    "download_seconds",
]

FEATURE_SUMMARY_FIELDS = [
    "incident_uid",
    "category",
    "duration_minutes",
    "raw_mrt_files",
    "raw_bgp_observations",
    "relevant_observations",
    "active_5min_windows",
    "unknown_5min_windows",
    "pre_context_windows",
    "post_context_windows",
    "zero_observation_windows",
    "total_feature_rows",
    "processing_status",
]

QUALITY_FIELDS = ["incident_uid", "category", "status", "review_reasons", "elapsed_seconds"]
BATCH_FIELDS = [
    "batch_id",
    "incident_count",
    "PASS",
    "REVIEW",
    "FAIL",
    "unique_mrt_files",
    "download_bytes",
    "raw_observations",
    "relevant_observations",
    "feature_rows",
    "elapsed_seconds",
    "peak_disk_bytes",
    "disk_recovered_bytes",
    "status",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def read_existing(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def validate_train_manifest(rows: list[dict[str, str]]) -> None:
    counts = Counter(row.get("category", "") for row in rows)
    if len(rows) != 993 or counts != {"Hijack": 331, "Leak": 331, "Outage": 331}:
        raise ValueError(f"unexpected TRAIN manifest counts: total={len(rows)} counts={dict(counts)}")
    if {row.get("partition") for row in rows} != {"train"}:
        raise ValueError("TRAIN manifest contains non-train incidents")


def group_by(rows: list[dict[str, str]], key: str) -> dict[str, list[dict[str, str]]]:
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[row[key]].append(row)
    return grouped


def safe_batch_path(batch_id: str, url: str) -> Path:
    return RAW_BATCH_ROOT / batch_id / Path(url).name


def batch_feature_path(batch_id: str) -> Path:
    return FEATURES_DIR / f"{batch_id}.parquet"


def batch_ids_from_plan(volume_rows: list[dict[str, str]]) -> list[str]:
    return sorted({row["volume_batch_id"] for row in volume_rows})


def existing_completed_batches() -> set[str]:
    completed = set()
    for row in read_existing(BATCH_EXECUTION_SUMMARY):
        if row.get("status") == "VERIFIED":
            path = batch_feature_path(row["batch_id"])
            if path.exists() and path.stat().st_size > 0:
                completed.add(row["batch_id"])
    return completed


def shared_download_rows(batch_id: str, assignment_rows: list[dict[str, str]], workers: int = 8) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    by_url: dict[str, dict[str, str]] = {}
    for row in assignment_rows:
        by_url.setdefault(row["mrt_url"], row)
    unique_download_inputs = []
    for url, row in sorted(by_url.items()):
        download_row = dict(row)
        download_row["batch_id"] = batch_id
        download_row["local_path"] = str(safe_batch_path(batch_id, url))
        unique_download_inputs.append(download_row)

    unique_downloads = []
    completed = 0
    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        futures = {executor.submit(copy_or_download, row): row for row in unique_download_inputs}
        for future in as_completed(futures):
            unique_downloads.append(future.result())
            completed += 1
            if completed == len(unique_download_inputs) or completed % 100 == 0:
                print(f"{batch_id} downloaded/cached {completed} / {len(unique_download_inputs)} unique MRT files", flush=True)

    status_by_url = {row["mrt_url"]: row for row in unique_downloads}
    expanded = []
    for row in assignment_rows:
        status = status_by_url[row["mrt_url"]]
        expanded_row = dict(row)
        expanded_row.update(
            {
                "batch_id": batch_id,
                "local_path": status["local_path"],
                "download_status": status["download_status"],
                "file_size": status["file_size"],
                "checksum": status["checksum"],
                "download_seconds": status["download_seconds"],
            }
        )
        expanded.append(expanded_row)
    return unique_downloads, expanded


def clean_batch_artifacts(batch_id: str, incident_uids: list[str]) -> int:
    recovered = 0
    raw_dir = RAW_BATCH_ROOT / batch_id
    if raw_dir.exists():
        recovered += directory_size(raw_dir)
        shutil.rmtree(raw_dir)
    for uid in incident_uids:
        parsed_dir = PARSED_TRAIN_ROOT / uid.replace(":", "_")
        if parsed_dir.exists():
            recovered += directory_size(parsed_dir)
            shutil.rmtree(parsed_dir)
    return recovered


def directory_size(path: Path) -> int:
    if not path.exists():
        return 0
    if path.is_file():
        return path.stat().st_size
    return sum(member.stat().st_size for member in path.rglob("*") if member.is_file())


def status_for_incident(downloads: list[dict[str, object]], parse_failures: int, relevant_observations: int, feature_rows: int) -> tuple[str, list[str]]:
    reasons = []
    download_ok = bool(downloads) and all(row.get("download_status") in {"200", "CACHED", "REUSED_FROM_PILOT"} for row in downloads)
    if not download_ok:
        reasons.append("download/integrity problem")
    if parse_failures:
        reasons.append("parser failure")
    if relevant_observations == 0:
        reasons.append("no relevant observations")
    if feature_rows == 0:
        reasons.append("unexpected empty output")
    status = "PASS" if not reasons else "REVIEW"
    if not downloads or parse_failures > 0 or feature_rows == 0:
        status = "FAIL" if "unexpected empty output" in reasons else "REVIEW"
    return status, reasons


def empty_stats() -> dict[str, object]:
    return {
        "raw_mrt_files": 0,
        "raw_bgp_observations": 0,
        "relevant_observations": 0,
        "parse_failures": 0,
        "malformed_records": 0,
        "missing_peer_asn": 0,
        "missing_prefix": 0,
        "malformed_as_path": 0,
        "matching_asns": set(),
        "matching_prefixes": set(),
    }


def parse_batch_once(
    batch_id: str,
    manifest_by_uid: dict[str, dict[str, str]],
    batch_uids: list[str],
    expanded_rows: list[dict[str, object]],
) -> tuple[dict[str, list[dict[str, object]]], dict[str, dict[str, object]]]:
    windows_by_uid = {uid: temporal_windows(manifest_by_uid[uid]) for uid in batch_uids}
    aggregates_by_uid = {
        uid: {wid: WindowAggregate() for wid in windows_by_uid[uid]}
        for uid in batch_uids
    }
    raw_window_counts = {uid: Counter() for uid in batch_uids}
    targets = {}
    for uid in batch_uids:
        target_asns, target_prefixes, leak_seg = relevance_targets(manifest_by_uid[uid])
        targets[uid] = {
            "target_asns": target_asns,
            "target_prefixes": target_prefixes,
            "leak_seg": leak_seg,
            "text_targets": target_asns | target_prefixes,
        }
    stats_by_uid = {uid: empty_stats() for uid in batch_uids}
    rows_by_url = group_by([{key: str(value) for key, value in row.items()} for row in expanded_rows], "mrt_url")
    downloaded_by_url = {}
    for url, group in rows_by_url.items():
        downloaded_by_url[url] = group[0]
        for row in group:
            stats_by_uid[row["incident_uid"]]["raw_mrt_files"] = int(stats_by_uid[row["incident_uid"]]["raw_mrt_files"]) + 1

    writer_handles = {}
    writers = {}
    parsed_fields = [
        "incident_uid",
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
        "raw_bgpdump_line",
    ]
    try:
        for uid in batch_uids:
            parsed_path = PARSED_TRAIN_ROOT / uid.replace(":", "_") / "parsed_relevant_bgp_observations.csv"
            parsed_path.parent.mkdir(parents=True, exist_ok=True)
            handle = parsed_path.open("w", newline="", encoding="utf-8")
            writer = csv.DictWriter(handle, fieldnames=parsed_fields)
            writer.writeheader()
            writer_handles[uid] = handle
            writers[uid] = writer

        import subprocess

        for file_index, (url, download_row) in enumerate(sorted(downloaded_by_url.items()), start=1):
            if download_row.get("download_status") not in {"200", "CACHED", "REUSED_FROM_PILOT"}:
                for row in rows_by_url[url]:
                    stats_by_uid[row["incident_uid"]]["parse_failures"] = int(stats_by_uid[row["incident_uid"]]["parse_failures"]) + 1
                continue
            path = Path(str(download_row["local_path"]))
            candidate_uids = sorted({row["incident_uid"] for row in rows_by_url[url]})
            process = subprocess.Popen(["bgpdump", "-q", "-m", str(path)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            assert process.stdout is not None
            for line in process.stdout:
                parts = line.rstrip("\n").split("|")
                if len(parts) < 6:
                    for uid in candidate_uids:
                        stats_by_uid[uid]["malformed_records"] = int(stats_by_uid[uid]["malformed_records"]) + 1
                    continue
                try:
                    raw_ts = datetime.fromtimestamp(float(parts[1]), tz=timezone.utc)
                    raw_slot = floor_to_five_minutes(raw_ts)
                except (ValueError, OverflowError):
                    for uid in candidate_uids:
                        stats_by_uid[uid]["malformed_records"] = int(stats_by_uid[uid]["malformed_records"]) + 1
                    continue
                for uid in candidate_uids:
                    stats_by_uid[uid]["raw_bgp_observations"] = int(stats_by_uid[uid]["raw_bgp_observations"]) + 1
                    raw_wid = window_id(uid, raw_slot)
                    if raw_wid in windows_by_uid[uid]:
                        raw_window_counts[uid][raw_wid] += 1
                    text_targets = targets[uid]["text_targets"]
                    if text_targets and not any(str(target) in line for target in text_targets):
                        continue
                    parsed = parse_bgpdump_line(line, uid, path, str(download_row["collector"]))
                    if not parsed:
                        stats_by_uid[uid]["malformed_records"] = int(stats_by_uid[uid]["malformed_records"]) + 1
                        continue
                    if not relevant_with_targets(parsed, targets[uid]["target_asns"], targets[uid]["target_prefixes"], targets[uid]["leak_seg"]):
                        continue
                    writers[uid].writerow(parsed)
                    stats_by_uid[uid]["relevant_observations"] = int(stats_by_uid[uid]["relevant_observations"]) + 1
                    if not parsed["peer_asn"]:
                        stats_by_uid[uid]["missing_peer_asn"] = int(stats_by_uid[uid]["missing_peer_asn"]) + 1
                    if not parsed["prefix"]:
                        stats_by_uid[uid]["missing_prefix"] = int(stats_by_uid[uid]["missing_prefix"]) + 1
                    if parsed["announcement_or_withdrawal"] == "announcement" and not parsed["as_path"]:
                        stats_by_uid[uid]["malformed_as_path"] = int(stats_by_uid[uid]["malformed_as_path"]) + 1
                    stats_by_uid[uid]["matching_prefixes"].add(parsed["prefix"])
                    stats_by_uid[uid]["matching_asns"].update(parse_as_path_set(parsed["as_path"]))
                    if parsed["peer_asn"]:
                        stats_by_uid[uid]["matching_asns"].add(parsed["peer_asn"])
                    if parsed["origin_asn"]:
                        stats_by_uid[uid]["matching_asns"].add(parsed["origin_asn"])
                    parsed_ts = parse_utc(parsed["bgp_timestamp_utc"])
                    if parsed_ts:
                        wid = window_id(uid, floor_to_five_minutes(parsed_ts))
                        if wid in aggregates_by_uid[uid]:
                            update_aggregate(aggregates_by_uid[uid][wid], parsed)
            stderr = process.stderr.read() if process.stderr else ""
            if process.wait() != 0:
                for uid in candidate_uids:
                    stats_by_uid[uid]["parse_failures"] = int(stats_by_uid[uid]["parse_failures"]) + 1
                if stderr:
                    print(stderr, flush=True)
            if file_index == len(downloaded_by_url) or file_index % 100 == 0:
                print(f"{batch_id} parsed {file_index} / {len(downloaded_by_url)} unique MRT files once", flush=True)
    finally:
        for handle in writer_handles.values():
            handle.close()

    features_by_uid = {}
    for uid in batch_uids:
        incident = manifest_by_uid[uid]
        features = []
        for wid, meta in sorted(windows_by_uid[uid].items(), key=lambda item: item[1]["window_start"]):
            feature_values = features_from_aggregate(aggregates_by_uid[uid][wid])
            row = {
                "incident_uid": uid,
                "incident_id": incident["incident_id"],
                "category": incident["category"],
                "partition": incident["partition"],
                "window_id": wid,
                "window_start": format_utc(meta["window_start"]),
                "window_end": format_utc(meta["window_end"]),
                "temporal_status": meta["temporal_status"],
                "behavioral_feature_version": "v1",
                "behavioral_feature_count": BEHAVIORAL_FEATURE_COUNT,
                "raw_observation_count": raw_window_counts[uid].get(wid, 0),
                "has_relevant_observation": feature_values["update_count"] > 0,
            }
            row.update(feature_values)
            features.append(row)
        features_by_uid[uid] = features
    return features_by_uid, stats_by_uid


def execute_batch(batch_id: str, manifest_by_uid: dict[str, dict[str, str]], batch_uids: list[str], plan_by_uid: dict[str, list[dict[str, str]]], policy: DiskPolicy, download_workers: int = 8) -> dict[str, object]:
    batch_start = time.perf_counter()
    batch_rows = [row for uid in batch_uids for row in plan_by_uid.get(uid, [])]
    unique_urls = {row["mrt_url"]: int(row.get("estimated_content_length") or 0) for row in batch_rows}
    estimated_compressed = sum(unique_urls.values())
    required = required_free_bytes(estimated_compressed, policy)
    available = free_bytes(Path("."))
    if available <= required:
        raise RuntimeError(f"disk safety check failed for {batch_id}: available={available} required={required}")

    peak_disk = directory_size(RAW_BATCH_ROOT / batch_id)
    unique_downloads, expanded_rows = shared_download_rows(batch_id, batch_rows, workers=download_workers)
    peak_disk = max(peak_disk, directory_size(RAW_BATCH_ROOT / batch_id))
    expanded_by_uid = group_by([{key: str(value) for key, value in row.items()} for row in expanded_rows], "incident_uid")

    features_by_uid, stats_by_uid = parse_batch_once(batch_id, manifest_by_uid, batch_uids, expanded_rows)
    all_features: list[dict[str, object]] = []
    incident_summaries: list[dict[str, object]] = []
    quality_rows: list[dict[str, object]] = []
    for uid in batch_uids:
        incident_start = time.perf_counter()
        incident = manifest_by_uid[uid]
        downloads = expanded_by_uid.get(uid, [])
        features = features_by_uid[uid]
        stats = stats_by_uid[uid]
        all_features.extend(features)
        active = sum(row["temporal_status"] == "INCIDENT_ACTIVE" for row in features)
        pre = sum(row["temporal_status"] == "PRE_CONTEXT" for row in features)
        post = sum(row["temporal_status"] == "POST_CONTEXT" for row in features)
        zero_windows = sum(int(row.get("update_count") or 0) == 0 for row in features)
        status, reasons = status_for_incident(downloads, int(stats["parse_failures"]), int(stats["relevant_observations"]), len(features))
        incident_summaries.append(
            {
                "incident_uid": uid,
                "category": incident["category"],
                "duration_minutes": incident.get("duration_minutes", ""),
                "raw_mrt_files": len(downloads),
                "raw_bgp_observations": stats["raw_bgp_observations"],
                "relevant_observations": stats["relevant_observations"],
                "active_5min_windows": active,
                "unknown_5min_windows": 0,
                "pre_context_windows": pre,
                "post_context_windows": post,
                "zero_observation_windows": zero_windows,
                "total_feature_rows": len(features),
                "processing_status": status,
            }
        )
        quality_rows.append(
            {
                "incident_uid": uid,
                "category": incident["category"],
                "status": status,
                "review_reasons": ";".join(reasons),
                "elapsed_seconds": round(time.perf_counter() - incident_start, 3),
            }
        )
        print(
            f"{batch_id} {uid} status={status} files={len(downloads)} raw={stats['raw_bgp_observations']} "
            f"relevant={stats['relevant_observations']} feature_rows={len(features)}",
            flush=True,
        )

    if all_features:
        FEATURES_DIR.mkdir(parents=True, exist_ok=True)
        df = pd.DataFrame(all_features)
        expected_columns = set(BEHAVIORAL_FEATURE_NAMES)
        if len(BEHAVIORAL_FEATURE_NAMES) != BEHAVIORAL_FEATURE_COUNT or not expected_columns <= set(df.columns):
            raise RuntimeError(f"feature schema mismatch in {batch_id}")
        if df.duplicated(["incident_uid", "window_id"]).any():
            raise RuntimeError(f"duplicate incident_uid/window_id rows in {batch_id}")
        df.to_parquet(batch_feature_path(batch_id), index=False)

    recovered = clean_batch_artifacts(batch_id, batch_uids)
    quality_counts = Counter(row["status"] for row in quality_rows)
    status = "VERIFIED" if quality_counts.get("FAIL", 0) == 0 else "FAIL"
    batch_summary = {
        "batch_id": batch_id,
        "incident_count": len(batch_uids),
        "PASS": quality_counts.get("PASS", 0),
        "REVIEW": quality_counts.get("REVIEW", 0),
        "FAIL": quality_counts.get("FAIL", 0),
        "unique_mrt_files": len(unique_downloads),
        "download_bytes": sum(int(row.get("file_size") or 0) for row in unique_downloads),
        "raw_observations": sum(int(row["raw_bgp_observations"]) for row in incident_summaries),
        "relevant_observations": sum(int(row["relevant_observations"]) for row in incident_summaries),
        "feature_rows": sum(int(row["total_feature_rows"]) for row in incident_summaries),
        "elapsed_seconds": round(time.perf_counter() - batch_start, 3),
        "peak_disk_bytes": peak_disk,
        "disk_recovered_bytes": recovered,
        "status": status,
    }
    append_rows(DOWNLOAD_AUDIT, download_audit_rows(unique_downloads), DOWNLOAD_AUDIT_FIELDS)
    append_rows(FEATURE_SUMMARY, incident_summaries, FEATURE_SUMMARY_FIELDS)
    append_rows(QUALITY_GATE, quality_rows, QUALITY_FIELDS)
    append_rows(BATCH_EXECUTION_SUMMARY, [batch_summary], BATCH_FIELDS)
    return batch_summary


def download_audit_rows(download_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    return [
        {
            "batch_id": row.get("batch_id", ""),
            "incident_uid": row.get("incident_uid", ""),
            "category": row.get("category", ""),
            "mrt_url": row.get("mrt_url", ""),
            "local_path": row.get("local_path", ""),
            "download_status": row.get("download_status", ""),
            "file_size": row.get("file_size", 0),
            "checksum": row.get("checksum", ""),
            "download_seconds": row.get("download_seconds", 0),
        }
        for row in download_rows
    ]


def append_rows(path: Path, rows: list[dict[str, object]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    exists = path.exists() and path.stat().st_size > 0
    with path.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        if not exists:
            writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def reset_outputs() -> None:
    for path in [DOWNLOAD_AUDIT, FEATURE_SUMMARY, QUALITY_GATE, BATCH_EXECUTION_SUMMARY, WINDOW_IMBALANCE, FEATURE_QUALITY, BEHAVIORAL_CORPUS_AUDIT, FEATURES_PARQUET]:
        if path.exists():
            path.unlink()
    if FEATURES_DIR.exists():
        shutil.rmtree(FEATURES_DIR)
    if PARSED_TRAIN_ROOT.exists():
        shutil.rmtree(PARSED_TRAIN_ROOT)


def combine_batch_features() -> pd.DataFrame:
    paths = sorted(FEATURES_DIR.glob("volume_batch_*.parquet"))
    if not paths:
        raise RuntimeError("no batch feature outputs found")
    frames = [pd.read_parquet(path) for path in paths]
    df = pd.concat(frames, ignore_index=True)
    if df.duplicated(["incident_uid", "window_id"]).any():
        raise RuntimeError("duplicate incident_uid/window_id rows in combined TRAIN corpus")
    FEATURES_PARQUET.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(FEATURES_PARQUET, index=False)
    return df


def percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    pos = (len(ordered) - 1) * q
    lo = math.floor(pos)
    hi = min(math.ceil(pos), len(ordered) - 1)
    if lo == hi:
        return float(ordered[lo])
    return float(ordered[lo] + (ordered[hi] - ordered[lo]) * (pos - lo))


def write_imbalance(summary_rows: list[dict[str, str]]) -> None:
    rows = []
    for category in ("Hijack", "Leak", "Outage", "ALL"):
        group = summary_rows if category == "ALL" else [row for row in summary_rows if row["category"] == category]
        values = [float(row["total_feature_rows"]) for row in group]
        total = sum(values)
        for level, pct in [("top_1_percent", 0.01), ("top_5_percent", 0.05), ("top_10_percent", 0.10)]:
            n = max(1, math.ceil(len(values) * pct)) if values else 0
            contribution = sum(sorted(values, reverse=True)[:n])
            rows.append({"category": category, "metric": level, "value": round(contribution / total * 100, 3) if total else 0, "notes": f"top {n} incidents"})
        rows.extend(
            [
                {"category": category, "metric": "min_rows_per_incident", "value": min(values) if values else 0, "notes": ""},
                {"category": category, "metric": "median_rows_per_incident", "value": percentile(values, 0.50), "notes": ""},
                {"category": category, "metric": "mean_rows_per_incident", "value": round(sum(values) / len(values), 3) if values else 0, "notes": ""},
                {"category": category, "metric": "p75_rows_per_incident", "value": percentile(values, 0.75), "notes": ""},
                {"category": category, "metric": "p90_rows_per_incident", "value": percentile(values, 0.90), "notes": ""},
                {"category": category, "metric": "p95_rows_per_incident", "value": percentile(values, 0.95), "notes": ""},
                {"category": category, "metric": "p99_rows_per_incident", "value": percentile(values, 0.99), "notes": ""},
                {"category": category, "metric": "max_rows_per_incident", "value": max(values) if values else 0, "notes": ""},
                {"category": category, "metric": "total_feature_rows", "value": total, "notes": ""},
            ]
        )
    write_csv(WINDOW_IMBALANCE, rows, ["category", "metric", "value", "notes"])


def write_feature_quality(df: pd.DataFrame) -> None:
    rows = []
    row_count = len(df)
    for feature in BEHAVIORAL_FEATURE_NAMES:
        series = pd.to_numeric(df[feature], errors="coerce") if feature in df else pd.Series(dtype=float)
        missing_count = int(series.isna().sum()) if len(series) else 0
        zero_count = int((series == 0).sum()) if len(series) else 0
        unique_values = int(series.nunique(dropna=True)) if len(series) else 0
        invalid = int(series.apply(lambda value: isinstance(value, float) and math.isinf(value)).sum()) if len(series) else 0
        sparse = row_count > 0 and zero_count / row_count >= 0.95
        rows.append(
            {
                "feature": feature,
                "missing_count": missing_count,
                "missing_rate": round(missing_count / row_count * 100, 3) if row_count else 0,
                "zero_count": zero_count,
                "zero_rate": round(zero_count / row_count * 100, 3) if row_count else 0,
                "min": series.min(skipna=True) if len(series) else "",
                "median": series.median(skipna=True) if len(series) else "",
                "mean": series.mean(skipna=True) if len(series) else "",
                "p95": series.quantile(0.95) if len(series) else "",
                "max": series.max(skipna=True) if len(series) else "",
                "number_unique": unique_values,
                "constant": str(unique_values <= 1),
                "sparse": str(sparse),
                "invalid": invalid,
            }
        )
    write_csv(
        FEATURE_QUALITY,
        rows,
        ["feature", "missing_count", "missing_rate", "zero_count", "zero_rate", "min", "median", "mean", "p95", "max", "number_unique", "constant", "sparse", "invalid"],
    )


def write_corpus_audit(df: pd.DataFrame, manifest_rows: list[dict[str, str]], quality_rows: list[dict[str, str]]) -> dict[str, object]:
    qcounts = Counter(row["status"] for row in quality_rows)
    duplicate_windows = int(df.duplicated(["incident_uid", "window_id"]).sum()) if len(df) else 0
    partitions = set(df["partition"].dropna().astype(str)) if len(df) and "partition" in df else set()
    schema_count = len([feature for feature in BEHAVIORAL_FEATURE_NAMES if feature in df.columns])
    class_rows = Counter(df["category"]) if len(df) else Counter()
    status = "PASS"
    notes = []
    if len({row["incident_uid"] for row in quality_rows}) != 993:
        status = "FAIL"
        notes.append("not all TRAIN incidents processed")
    if duplicate_windows:
        status = "FAIL"
        notes.append("duplicate window IDs detected")
    if schema_count != BEHAVIORAL_FEATURE_COUNT:
        status = "FAIL"
        notes.append("behavioral feature schema count mismatch")
    if partitions - {"train"}:
        status = "FAIL"
        notes.append("Validation/Holdout contamination detected")
    if qcounts.get("REVIEW", 0):
        status = "REVIEW" if status == "PASS" else status
        notes.append("some incidents require review")
    row = {
        "expected_incidents": len(manifest_rows),
        "processed_incidents": len({row["incident_uid"] for row in quality_rows}),
        "PASS": qcounts.get("PASS", 0),
        "REVIEW": qcounts.get("REVIEW", 0),
        "FAIL": qcounts.get("FAIL", 0),
        "total_feature_rows": len(df),
        "hijack_feature_rows": class_rows.get("Hijack", 0),
        "leak_feature_rows": class_rows.get("Leak", 0),
        "outage_feature_rows": class_rows.get("Outage", 0),
        "duplicate_window_ids": duplicate_windows,
        "schema_count": schema_count,
        "validation_contamination": str("validation" in partitions),
        "holdout_contamination": str("holdout" in partitions),
        "overall_status": status,
        "notes": ";".join(notes),
        "source_commit": source_commit(),
        "audit_timestamp": utc_now(),
    }
    write_csv(
        BEHAVIORAL_CORPUS_AUDIT,
        [row],
        [
            "expected_incidents",
            "processed_incidents",
            "PASS",
            "REVIEW",
            "FAIL",
            "total_feature_rows",
            "hijack_feature_rows",
            "leak_feature_rows",
            "outage_feature_rows",
            "duplicate_window_ids",
            "schema_count",
            "validation_contamination",
            "holdout_contamination",
            "overall_status",
            "notes",
            "source_commit",
            "audit_timestamp",
        ],
    )
    return row


def write_notebook() -> None:
    NOTEBOOK.parent.mkdir(parents=True, exist_ok=True)
    notebook = {
        "cells": [
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": [
                    "# Full TRAIN Behavioral Execution\n",
                    "\n",
                    "Executes the frozen 993-incident TRAIN-only behavioral feature pipeline using volume-aware batches. Validation and Holdout remain untouched. No Normal labels, CAIDA/RPKI, model training, window caps, weighting, downsampling, or oversampling are introduced.\n",
                ],
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": [
                    "from bgp_incident_detection.full_train_execution import preflight_summary\n",
                    "preflight_summary()\n",
                ],
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": [
                    "from bgp_incident_detection.full_train_execution import run_full_train\n",
                    "# run_full_train(resume=True)  # Downloads/parses TRAIN RouteViews MRT files batch-by-batch.\n",
                ],
            },
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")


def preflight_summary() -> dict[str, object]:
    manifest = load_csv(MANIFEST)
    validate_train_manifest(manifest)
    volume = load_csv(VOLUME_BATCH_PLAN)
    plan = load_csv(ACQUISITION_PLAN)
    batch_ids = batch_ids_from_plan(volume)
    first_batch = batch_ids[0]
    first_rows = [row for row in volume if row["volume_batch_id"] == first_batch]
    by_volume_uid = group_by(volume, "incident_uid")
    plan_by_uid = group_by(plan, "incident_uid")
    batch_requirements = []
    for batch_id in batch_ids:
        uids = [row["incident_uid"] for row in volume if row["volume_batch_id"] == batch_id]
        urls = {row["mrt_url"]: int(row.get("estimated_content_length") or 0) for uid in uids for row in plan_by_uid.get(uid, [])}
        compressed = sum(urls.values())
        batch_requirements.append({"batch_id": batch_id, "required_free_bytes": required_free_bytes(compressed), "estimated_compressed_bytes": compressed, "incident_count": len(uids)})
    largest = max(batch_requirements, key=lambda row: row["required_free_bytes"])
    return {
        "train_incidents": len(manifest),
        "train_counts": dict(Counter(row["category"] for row in manifest)),
        "volume_aware_batch_count": len(batch_ids),
        "largest_batch": largest,
        "current_free_bytes": free_bytes(Path(".")),
        "first_batch_id": first_batch,
        "first_batch_incident_count": len(first_rows),
        "first_batch_class_composition": dict(Counter(row["category"] for row in first_rows)),
        "first_batch_estimated_compressed_bytes": sum(int(row.get("estimated_compressed_bytes") or 0) for row in first_rows),
        "incident_membership_rows": len(by_volume_uid),
    }


def run_full_train(resume: bool = True, max_batches: int | None = None, reset: bool = False, download_workers: int = 8) -> dict[str, object]:
    if reset:
        reset_outputs()
    write_notebook()
    manifest = load_csv(MANIFEST)
    validate_train_manifest(manifest)
    volume = load_csv(VOLUME_BATCH_PLAN)
    plan = load_csv(ACQUISITION_PLAN)
    manifest_by_uid = {row["incident_uid"]: row for row in manifest}
    plan_by_uid = group_by(plan, "incident_uid")
    uids_by_batch = {
        batch_id: [row["incident_uid"] for row in sorted(group, key=lambda item: item["incident_uid"])]
        for batch_id, group in group_by(volume, "volume_batch_id").items()
    }
    completed = existing_completed_batches() if resume else set()
    batch_ids = batch_ids_from_plan(volume)
    if max_batches is not None:
        batch_ids = batch_ids[:max_batches]
    for batch_id in batch_ids:
        if batch_id in completed:
            print(f"{batch_id} already VERIFIED; skipping", flush=True)
            continue
        summary = execute_batch(batch_id, manifest_by_uid, uids_by_batch[batch_id], plan_by_uid, DiskPolicy(), download_workers=download_workers)
        print(f"{batch_id} complete status={summary['status']} feature_rows={summary['feature_rows']}", flush=True)
        if summary["status"] == "FAIL":
            raise RuntimeError(f"stopping after methodological/data FAIL in {batch_id}")

    df = combine_batch_features()
    summary_rows = read_existing(FEATURE_SUMMARY)
    quality_rows = read_existing(QUALITY_GATE)
    write_imbalance(summary_rows)
    write_feature_quality(df)
    corpus = write_corpus_audit(df, manifest, quality_rows)
    return {
        "incidents_completed": len({row["incident_uid"] for row in quality_rows}),
        "quality_counts": dict(Counter(row["status"] for row in quality_rows)),
        "unique_mrt_files_processed": len({row["mrt_url"] for row in read_existing(DOWNLOAD_AUDIT)}),
        "compressed_mrt_bytes_processed": sum(int(row.get("file_size") or 0) for row in read_existing(DOWNLOAD_AUDIT)),
        "raw_prefix_level_observations": sum(int(row["raw_bgp_observations"]) for row in summary_rows),
        "incident_relevant_observations": sum(int(row["relevant_observations"]) for row in summary_rows),
        "feature_rows": len(df),
        "feature_rows_by_class": dict(Counter(df["category"])),
        "corpus_audit_status": corpus["overall_status"],
        "outputs": [
            str(FEATURES_PARQUET),
            str(FEATURE_SUMMARY),
            str(QUALITY_GATE),
            str(BATCH_EXECUTION_SUMMARY),
            str(WINDOW_IMBALANCE),
            str(FEATURE_QUALITY),
            str(BEHAVIORAL_CORPUS_AUDIT),
            str(NOTEBOOK),
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Execute the full frozen TRAIN behavioral feature pipeline")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--no-resume", action="store_true")
    parser.add_argument("--reset", action="store_true")
    parser.add_argument("--max-batches", type=int)
    parser.add_argument("--download-workers", type=int, default=8)
    args = parser.parse_args()
    if args.preflight:
        print(json.dumps(preflight_summary(), indent=2, sort_keys=True))
        return
    if args.run:
        print(json.dumps(run_full_train(resume=not args.no_resume, max_batches=args.max_batches, reset=args.reset, download_workers=args.download_workers), indent=2, sort_keys=True))
        return
    parser.error("choose --preflight or --run")


if __name__ == "__main__":
    main()
