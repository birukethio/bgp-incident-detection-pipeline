from __future__ import annotations

import argparse
import hashlib
import csv
import json
import math
import shutil
import subprocess
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

try:
    from bgp_incident_detection.audit import parse_utc
    from bgp_incident_detection.mrt_parser import parse_as_path, parse_as_path_set, parse_bgpdump_line
    from bgp_incident_detection.train_incident_scale import (
        ACQUISITION_PLAN,
        MANIFEST,
        compression_ok,
        copy_or_download,
        load_csv,
        relevance_targets,
        relevant_with_targets,
    )
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import parse_utc
    from src.bgp_incident_detection.mrt_parser import parse_as_path, parse_as_path_set, parse_bgpdump_line
    from src.bgp_incident_detection.train_incident_scale import (
        ACQUISITION_PLAN,
        MANIFEST,
        compression_ok,
        copy_or_download,
        load_csv,
        relevance_targets,
        relevant_with_targets,
    )


OUT_DIR = Path("data/tti_timestamped_train_v1")
EVIDENCE_DIR = OUT_DIR / "evidence"
RAW_TEMP_DIR = OUT_DIR / "raw_mrt_temp"
RAW_CACHE_DIR = RAW_TEMP_DIR / "shared_cache"
MANIFEST_OUT = OUT_DIR / "tti_timestamped_train_manifest_v1.csv"
BATCH_STATUS = OUT_DIR / "tti_timestamped_train_batch_status_v1.csv"
QUALITY = OUT_DIR / "tti_timestamped_train_quality_v1.csv"
FAILURES = OUT_DIR / "tti_timestamped_train_failures_v1.csv"
SUMMARY = OUT_DIR / "tti_timestamped_train_summary_v1.md"
METHOD = OUT_DIR / "tti_timestamped_train_methodology_v1.md"
DEPENDENCY_MAP = OUT_DIR / "tti_mrt_dependency_map_v1.csv"
CACHE_EVENTS = OUT_DIR / "tti_mrt_cache_events_v1.csv"
STATUS_HISTORY = OUT_DIR / "tti_timestamped_train_status_history_v1.csv"

MIN_FREE_BYTES = 10 * 1024**3

PILOT_EVIDENCE = Path("data/tti_pilot/tti_timestamped_evidence_v1.csv")
COMPACT_MANIFEST = Path("data/enrichment/evidence/train_evidence_manifest_v1.csv")
COMPACT_SAMPLE = Path("data/enrichment/evidence/train_v1/batch_001.parquet")
PREVIOUS_BATCH_SUMMARY = Path("data/train_scale/train_batch_execution_summary_v1.csv")

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


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def safe_name(incident_uid: str) -> str:
    return incident_uid.replace(":", "_").replace("/", "_")


def evidence_path(incident_uid: str) -> Path:
    return EVIDENCE_DIR / f"{safe_name(incident_uid)}.parquet"


def cache_path_for_url(url: str) -> Path:
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:24]
    return RAW_CACHE_DIR / f"{digest}_{Path(url).name}"


def free_bytes() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    return shutil.disk_usage(OUT_DIR).free


def enforce_disk_safety() -> None:
    current = free_bytes()
    if current < MIN_FREE_BYTES:
        raise RuntimeError(f"free disk below safety threshold: {current} < {MIN_FREE_BYTES}")


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fields is None:
        fields = list(rows[0].keys()) if rows else []
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def update_csv_row(path: Path, key: str, value: str, update: dict[str, Any], fields: list[str]) -> None:
    rows = read_csv(path)
    found = False
    for row in rows:
        if row.get(key) == value:
            row.update({field: str(update.get(field, row.get(field, ""))) for field in fields})
            found = True
            break
    if not found:
        rows.append({field: str(update.get(field, "")) for field in fields})
    write_csv(path, rows, fields)


def append_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    exists = path.exists() and path.stat().st_size > 0
    with path.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        if not exists:
            writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def append_status_history(incident_uid: str, previous_status: str, new_status: str, reason: str) -> None:
    append_csv(
        STATUS_HISTORY,
        [
            {
                "timestamp_utc": utc_now(),
                "incident_uid": incident_uid,
                "previous_status": previous_status,
                "new_status": new_status,
                "reason": reason,
            }
        ],
        ["timestamp_utc", "incident_uid", "previous_status", "new_status", "reason"],
    )


def load_train_inputs() -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    manifest = load_csv(MANIFEST)
    plan = load_csv(ACQUISITION_PLAN)
    counts = Counter(row.get("category", "") for row in manifest)
    if len(manifest) != 993 or counts != {"Hijack": 331, "Leak": 331, "Outage": 331}:
        raise ValueError(f"Unexpected TRAIN manifest: total={len(manifest)} counts={dict(counts)}")
    if {row.get("partition") for row in manifest} != {"train"}:
        raise ValueError("TRAIN manifest contains non-TRAIN rows.")
    plan_uids = {row.get("incident_uid") for row in plan}
    missing = [row["incident_uid"] for row in manifest if row["incident_uid"] not in plan_uids]
    if missing:
        raise ValueError(f"Missing acquisition plan for incidents: {missing[:10]}")
    return manifest, plan


def group_by(rows: list[dict[str, str]], key: str) -> dict[str, list[dict[str, str]]]:
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[row[key]].append(row)
    return grouped


def clean_downloads(download_rows: list[dict[str, Any]]) -> int:
    recovered = 0
    for row in download_rows:
        path = Path(str(row.get("local_path", "")))
        try:
            if path.exists() and path.is_file():
                recovered += path.stat().st_size
                path.unlink()
        except OSError:
            continue
    return recovered


def temp_local_path(incident_uid: str, source_name: str) -> str:
    return str(RAW_TEMP_DIR / safe_name(incident_uid) / source_name)


def write_dependency_map(plan: list[dict[str, str]], active_uids: set[str]) -> dict[str, set[str]]:
    by_url: dict[str, set[str]] = defaultdict(set)
    bytes_by_url: dict[str, str] = {}
    collector_by_url: dict[str, str] = {}
    timestamp_by_url: dict[str, str] = {}
    for row in plan:
        uid = row["incident_uid"]
        if uid not in active_uids:
            continue
        url = row["mrt_url"]
        by_url[url].add(uid)
        bytes_by_url[url] = row.get("estimated_content_length", "")
        collector_by_url[url] = row.get("collector", "")
        timestamp_by_url[url] = row.get("mrt_timestamp", "")
    rows = [
        {
            "mrt_url": url,
            "collector": collector_by_url.get(url, ""),
            "mrt_timestamp": timestamp_by_url.get(url, ""),
            "dependent_incident_count": len(uids),
            "dependent_incident_uids": json.dumps(sorted(uids), separators=(",", ":")),
            "estimated_content_length": bytes_by_url.get(url, ""),
            "cache_path": str(cache_path_for_url(url)),
        }
        for url, uids in sorted(by_url.items())
    ]
    write_csv(
        DEPENDENCY_MAP,
        rows,
        [
            "mrt_url",
            "collector",
            "mrt_timestamp",
            "dependent_incident_count",
            "dependent_incident_uids",
            "estimated_content_length",
            "cache_path",
        ],
    )
    return by_url


def verify_evidence_artifact(path: Path, expected_rows: int) -> tuple[bool, str]:
    if expected_rows <= 0:
        return False, "no retained rows to verify"
    if not path.exists() or path.stat().st_size <= 0:
        return False, "missing or zero-byte parquet"
    try:
        frame = pd.read_parquet(path)
    except Exception as error:  # pragma: no cover - defensive for corrupted parquet readers
        return False, f"parquet read failed: {error}"
    if len(frame) != expected_rows:
        return False, f"row-count mismatch: expected {expected_rows}, found {len(frame)}"
    missing = [field for field in EVIDENCE_FIELDS if field not in frame.columns]
    if missing:
        return False, f"missing columns: {missing}"
    if set(frame["partition"].astype(str)) != {"train"}:
        return False, "non-TRAIN partition detected"
    return True, ""


def estimate() -> dict[str, Any]:
    manifest, plan = load_train_inputs()
    previous = pd.read_csv(PREVIOUS_BATCH_SUMMARY)
    compact = pd.read_csv(COMPACT_MANIFEST)
    compact_sample = pd.read_parquet(COMPACT_SAMPLE)
    pilot_rows = len(pd.read_csv(PILOT_EVIDENCE, usecols=["incident_uid"]))
    pilot_bytes = PILOT_EVIDENCE.stat().st_size
    pilot_parquet = Path("/private/tmp/tti_pilot_timestamped_evidence_test.parquet")
    if not pilot_parquet.exists():
        pd.read_csv(PILOT_EVIDENCE, low_memory=False).to_parquet(pilot_parquet, index=False)
    unique_urls = {row["mrt_url"] for row in plan}
    relevant = int(previous["relevant_observations"].sum())
    projected_csv = int(relevant * (pilot_bytes / pilot_rows))
    projected_parquet = int(relevant * (pilot_parquet.stat().st_size / pilot_rows))
    estimated_download = int(sum(int(row.get("estimated_content_length") or 0) for row in plan))
    return {
        "expected_train_incidents": len(manifest),
        "class_counts": dict(Counter(row["category"] for row in manifest)),
        "planned_file_assignments": len(plan),
        "unique_mrt_urls": len(unique_urls),
        "estimated_download_bytes": estimated_download,
        "previous_unique_mrt_files": int(previous["unique_mrt_files"].sum()),
        "previous_raw_observations": int(previous["raw_observations"].sum()),
        "previous_relevant_observations": relevant,
        "previous_runtime_seconds": float(previous["elapsed_seconds"].sum()),
        "previous_runtime_hours": float(previous["elapsed_seconds"].sum() / 3600),
        "previous_max_batch_download_bytes": int(previous["download_bytes"].max()),
        "pilot_timestamped_rows": pilot_rows,
        "pilot_timestamped_csv_bytes": pilot_bytes,
        "pilot_timestamped_parquet_bytes": pilot_parquet.stat().st_size,
        "projected_timestamped_csv_bytes": projected_csv,
        "projected_timestamped_parquet_bytes": projected_parquet,
        "compact_evidence_rows": int(compact["evidence_rows"].sum()),
        "compact_evidence_has_observation_timestamp": "bgp_timestamp_utc" in compact_sample.columns or "observation_timestamp" in compact_sample.columns,
        "storage_assessment": "REASONABLE_WITH_BATCH_PROCESSING_AND_PARQUET",
        "runtime_assessment": "LONG_RUNNING_REQUIRES_RESUMABLE_EXECUTION",
    }


def write_preflight_summary(info: dict[str, Any], disposition: str) -> None:
    lines = [
        "# TTI Timestamped TRAIN Evidence Summary v1",
        "",
        "This is an additive TRAIN-only evidence reconstruction gate. It does not score TTI rows, retrain models, or touch Validation/Final Holdout artifacts.",
        "",
        "## Preflight Estimate",
        "",
        f"- Expected TRAIN incidents: {info['expected_train_incidents']}",
        f"- Class counts: {json.dumps(info['class_counts'], sort_keys=True)}",
        f"- Planned MRT assignments: {info['planned_file_assignments']}",
        f"- Unique MRT URLs: {info['unique_mrt_urls']}",
        f"- Estimated compressed MRT transfer: {info['estimated_download_bytes'] / 1024**3:.3f} GiB",
        f"- Previous raw BGP observations inspected: {info['previous_raw_observations']:,}",
        f"- Previous relevant observations retained: {info['previous_relevant_observations']:,}",
        f"- Previous full TRAIN runtime: {info['previous_runtime_hours']:.3f} hours",
        f"- Projected timestamped Parquet size: {info['projected_timestamped_parquet_bytes'] / 1024**3:.3f} GiB",
        f"- Projected timestamped CSV size: {info['projected_timestamped_csv_bytes'] / 1024**3:.3f} GiB",
        "",
        "## Gate Finding",
        "",
        "Storage is reasonable only if processed batch-by-batch and stored as partitioned Parquet. Runtime and network/parse volume are long-running, so the script is resumable and records incident-level status.",
        "",
        f"{disposition}",
    ]
    SUMMARY.parent.mkdir(parents=True, exist_ok=True)
    SUMMARY.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_methodology() -> None:
    lines = [
        "# TTI Timestamped TRAIN Evidence Methodology v1",
        "",
        "Purpose: reconstruct timestamp-preserving incident-relevant RouteViews evidence for the complete 993-incident TRAIN partition.",
        "",
        "Scope limits: TRAIN only; no Validation or Final Holdout access; no model scoring; no model retraining; no modification of the primary five-minute evidence store.",
        "",
        "The reconstruction reuses the existing TRAIN acquisition plan, RouteViews collector/url handling, `bgpdump -q -m` parser logic, and incident relevance predicates from the original behavioral feature pipeline. Unlike the compact enrichment evidence store, this layer preserves `bgp_timestamp_utc` at observation grain so later 30/60/120/300-second horizon construction can assert no future observations were used.",
        "",
        "Output grain: one row per retained incident-relevant BGP observation. Files are partitioned by incident as Parquet under `data/tti_timestamped_train_v1/evidence/`.",
    ]
    METHOD.parent.mkdir(parents=True, exist_ok=True)
    METHOD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def completed_incidents() -> set[str]:
    rows = read_csv(MANIFEST_OUT)
    return {row["incident_uid"] for row in rows if row.get("processing_status") == "TIMESTAMP_EVIDENCE_PASS" and evidence_path(row["incident_uid"]).exists()}


def parse_incident(incident: dict[str, str], plan_rows: list[dict[str, str]], keep_raw: bool = False) -> dict[str, Any]:
    start_time = time.perf_counter()
    uid = incident["incident_uid"]
    target_asns, target_prefixes, leak_seg = relevance_targets(incident)
    text_targets = target_asns | target_prefixes
    rows: list[dict[str, Any]] = []
    raw_records = 0
    parse_failures = 0
    malformed = 0
    timestamp_errors = 0
    missing_prefix = 0
    missing_peer = 0
    downloaded_rows = []
    earliest = None
    latest = None
    url_seen = set()
    disk_pause = False
    disk_pause_reason = ""
    for plan_row in sorted(plan_rows, key=lambda row: row["mrt_timestamp"]):
        try:
            enforce_disk_safety()
        except RuntimeError as error:
            disk_pause = True
            disk_pause_reason = str(error)
            break
        url = plan_row["mrt_url"]
        if url in url_seen:
            continue
        url_seen.add(url)
        download_input = dict(plan_row)
        download_input["local_path"] = str(cache_path_for_url(url))
        result = copy_or_download(download_input)
        result["cache_scope"] = "shared_url_cache"
        result["cache_path"] = download_input["local_path"]
        downloaded_rows.append(result)
        status = str(result.get("download_status", ""))
        if status not in {"200", "CACHED", "REUSED_FROM_PILOT"}:
            continue
        path = Path(str(result["local_path"]))
        if not compression_ok(path):
            parse_failures += 1
            continue
        process = subprocess.Popen(["bgpdump", "-q", "-m", str(path)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert process.stdout is not None
        for line in process.stdout:
            parts = line.rstrip("\n").split("|")
            if len(parts) < 6:
                malformed += 1
                continue
            raw_records += 1
            try:
                _ = datetime.fromtimestamp(float(parts[1]), tz=timezone.utc)
            except (ValueError, OverflowError):
                timestamp_errors += 1
                continue
            if text_targets and not any(str(target) in line for target in text_targets):
                continue
            parsed = parse_bgpdump_line(line, uid, path, str(plan_row["collector"]))
            if not parsed:
                malformed += 1
                continue
            if not relevant_with_targets(parsed, target_asns, target_prefixes, leak_seg):
                continue
            ts = parse_utc(parsed["bgp_timestamp_utc"])
            if not ts:
                timestamp_errors += 1
                continue
            if earliest is None or ts < earliest:
                earliest = ts
            if latest is None or ts > latest:
                latest = ts
            if not parsed.get("peer_asn"):
                missing_peer += 1
            if not parsed.get("prefix"):
                missing_prefix += 1
            rows.append(
                {
                    "incident_uid": uid,
                    "incident_id": incident.get("incident_id", ""),
                    "category": incident["category"],
                    "partition": incident.get("partition", "train"),
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
        stderr = process.stderr.read() if process.stderr else ""
        if process.wait() != 0:
            parse_failures += 1
            if stderr:
                print(stderr, flush=True)
    evidence_ok = False
    evidence_reason = ""
    if rows:
        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        pd.DataFrame(rows, columns=EVIDENCE_FIELDS).to_parquet(evidence_path(uid), index=False)
        evidence_ok, evidence_reason = verify_evidence_artifact(evidence_path(uid), len(rows))
    if not keep_raw:
        pass
    status = "TIMESTAMP_EVIDENCE_PASS"
    reason = ""
    if disk_pause:
        status = "DISK_SAFETY_PAUSE"
        reason = disk_pause_reason
    elif parse_failures:
        status = "PARSER_FAILURE"
        reason = "one or more MRT files failed parser/compression checks"
    elif not downloaded_rows or not any(str(row.get("download_status")) in {"200", "CACHED", "REUSED_FROM_PILOT"} for row in downloaded_rows):
        status = "RETRY_REQUIRED_DOWNLOAD_CONTEXT"
        reason = "no usable MRT files were downloaded/reused in this execution context"
    elif not rows:
        status = "INSUFFICIENT_EVIDENCE"
        reason = "no incident-relevant timestamped observations retained"
    elif timestamp_errors:
        status = "REVIEW_REQUIRED"
        reason = "timestamp parse errors observed"
    elif not evidence_ok:
        status = "PARQUET_VERIFICATION_FAILURE"
        reason = evidence_reason
    return {
        "incident_uid": uid,
        "incident_id": incident.get("incident_id", ""),
        "category": incident["category"],
        "partition": incident.get("partition", "train"),
        "processing_status": status,
        "review_reason": reason,
        "mrt_files_processed": len({row.get("mrt_url") for row in downloaded_rows}),
        "mrt_files_downloaded_or_reused": sum(1 for row in downloaded_rows if str(row.get("download_status")) in {"200", "CACHED", "REUSED_FROM_PILOT"}),
        "raw_records_inspected": raw_records,
        "relevant_observations_retained": len(rows),
        "earliest_retained_timestamp": earliest.isoformat(timespec="milliseconds").replace("+00:00", "Z") if earliest else "",
        "latest_retained_timestamp": latest.isoformat(timespec="milliseconds").replace("+00:00", "Z") if latest else "",
        "timestamp_errors": timestamp_errors,
        "malformed_records": malformed,
        "missing_prefix_observations": missing_prefix,
        "missing_peer_asn_observations": missing_peer,
        "evidence_path": str(evidence_path(uid)) if rows else "",
        "evidence_size_bytes": evidence_path(uid).stat().st_size if rows and evidence_path(uid).exists() else 0,
        "elapsed_seconds": round(time.perf_counter() - start_time, 3),
        "download_rows": downloaded_rows,
    }


def initialize_outputs(manifest: list[dict[str, str]], info: dict[str, Any]) -> None:
    write_methodology()
    write_preflight_summary(info, "FULL_TRAIN_TIMESTAMPED_EVIDENCE_REQUIRES_REVIEW")
    if not MANIFEST_OUT.exists():
        rows = []
        for row in manifest:
            rows.append(
                {
                    "incident_uid": row["incident_uid"],
                    "incident_id": row.get("incident_id", ""),
                    "category": row["category"],
                    "partition": row.get("partition", ""),
                    "processing_status": "NOT_STARTED",
                    "review_reason": "",
                    "mrt_files_processed": 0,
                    "raw_records_inspected": 0,
                    "relevant_observations_retained": 0,
                    "earliest_retained_timestamp": "",
                    "latest_retained_timestamp": "",
                    "evidence_path": "",
                }
            )
        write_csv(MANIFEST_OUT, rows)
    quality_fields = [
        "incident_uid",
        "incident_id",
        "category",
        "partition",
        "processing_status",
        "review_reason",
        "mrt_files_processed",
        "mrt_files_downloaded_or_reused",
        "raw_records_inspected",
        "relevant_observations_retained",
        "earliest_retained_timestamp",
        "latest_retained_timestamp",
        "timestamp_errors",
        "malformed_records",
        "missing_prefix_observations",
        "missing_peer_asn_observations",
        "evidence_path",
        "evidence_size_bytes",
        "elapsed_seconds",
    ]
    if not QUALITY.exists():
        quality_rows = []
        for row in manifest:
            quality_rows.append(
                {
                    "incident_uid": row["incident_uid"],
                    "incident_id": row.get("incident_id", ""),
                    "category": row["category"],
                    "partition": row.get("partition", ""),
                    "processing_status": "NOT_STARTED",
                    "review_reason": "long-running reconstruction not launched in estimate/preflight gate",
                    "mrt_files_processed": 0,
                    "mrt_files_downloaded_or_reused": 0,
                    "raw_records_inspected": 0,
                    "relevant_observations_retained": 0,
                    "earliest_retained_timestamp": "",
                    "latest_retained_timestamp": "",
                    "timestamp_errors": 0,
                    "malformed_records": 0,
                    "missing_prefix_observations": 0,
                    "missing_peer_asn_observations": 0,
                    "evidence_path": "",
                    "evidence_size_bytes": 0,
                    "elapsed_seconds": 0,
                }
            )
        write_csv(QUALITY, quality_rows, quality_fields)
    if not FAILURES.exists():
        write_csv(FAILURES, [], quality_fields)


QUALITY_FIELDS = [
    "incident_uid",
    "incident_id",
    "category",
    "partition",
    "processing_status",
    "review_reason",
    "mrt_files_processed",
    "mrt_files_downloaded_or_reused",
    "raw_records_inspected",
    "relevant_observations_retained",
    "earliest_retained_timestamp",
    "latest_retained_timestamp",
    "timestamp_errors",
    "malformed_records",
    "missing_prefix_observations",
    "missing_peer_asn_observations",
    "evidence_path",
    "evidence_size_bytes",
    "elapsed_seconds",
]

MANIFEST_FIELDS = [
    "incident_uid",
    "incident_id",
    "category",
    "partition",
    "processing_status",
    "review_reason",
    "mrt_files_processed",
    "raw_records_inspected",
    "relevant_observations_retained",
    "earliest_retained_timestamp",
    "latest_retained_timestamp",
    "evidence_path",
]

CACHE_EVENT_FIELDS = [
    "timestamp_utc",
    "incident_uid",
    "mrt_url",
    "cache_path",
    "download_status",
    "file_size",
    "checksum",
    "remaining_dependent_incidents",
    "cache_event",
    "notes",
]


def cache_event(
    incident_uid: str,
    row: dict[str, Any],
    remaining: int,
    event: str,
    notes: str = "",
) -> dict[str, Any]:
    return {
        "timestamp_utc": utc_now(),
        "incident_uid": incident_uid,
        "mrt_url": row.get("mrt_url", ""),
        "cache_path": row.get("cache_path") or row.get("local_path", ""),
        "download_status": row.get("download_status", ""),
        "file_size": row.get("file_size", ""),
        "checksum": row.get("checksum", ""),
        "remaining_dependent_incidents": remaining,
        "cache_event": event,
        "notes": notes,
    }


def release_cache_for_incident(
    incident_uid: str,
    download_rows: list[dict[str, Any]],
    remaining_by_url: dict[str, int],
    keep_raw: bool = False,
) -> tuple[int, list[dict[str, Any]]]:
    events: list[dict[str, Any]] = []
    released_bytes = 0
    seen = set()
    for row in download_rows:
        url = str(row.get("mrt_url", ""))
        if not url or url in seen:
            continue
        seen.add(url)
        remaining_by_url[url] = max(0, remaining_by_url.get(url, 0) - 1)
        remaining = remaining_by_url[url]
        events.append(cache_event(incident_uid, row, remaining, "REFERENCE_RELEASED"))
        path = Path(str(row.get("cache_path") or row.get("local_path", "")))
        if keep_raw or remaining > 0:
            continue
        try:
            if path.exists() and path.is_file() and RAW_CACHE_DIR in path.parents:
                size = path.stat().st_size
                path.unlink()
                released_bytes += size
                events.append(cache_event(incident_uid, row, remaining, "TEMP_CACHE_DELETED", f"released_bytes={size}"))
        except OSError as error:
            events.append(cache_event(incident_uid, row, remaining, "TEMP_CACHE_DELETE_FAILED", str(error)))
    return released_bytes, events


def reclassify_false_mrt_unavailable(plan: list[dict[str, str]]) -> int:
    if not QUALITY.exists():
        return 0
    plan_by_uid = group_by(plan, "incident_uid")
    rows = read_csv(QUALITY)
    changed = 0
    for row in rows:
        if row.get("processing_status") != "MRT_UNAVAILABLE":
            continue
        downloaded = int(float(row.get("mrt_files_downloaded_or_reused") or 0))
        raw = int(float(row.get("raw_records_inspected") or 0))
        incident_plan = plan_by_uid.get(row.get("incident_uid", ""), [])
        remotely_available = bool(incident_plan) and all(
            str(item.get("remote_available")) == "True" and str(item.get("status_code")) == "200" for item in incident_plan
        )
        if downloaded == 0 and raw == 0 and remotely_available:
            append_status_history(
                row["incident_uid"],
                "MRT_UNAVAILABLE",
                "RETRY_REQUIRED_DOWNLOAD_CONTEXT",
                "remote availability was HTTP 200; no file was downloaded/reused during interrupted or sandboxed execution",
            )
            row["processing_status"] = "RETRY_REQUIRED_DOWNLOAD_CONTEXT"
            row["review_reason"] = "remote HTTP 200 in acquisition plan; retry required in valid download context"
            changed += 1
    if changed:
        write_csv(QUALITY, rows, QUALITY_FIELDS)
        manifest_rows = read_csv(MANIFEST_OUT)
        status_by_uid = {row["incident_uid"]: row for row in rows}
        for row in manifest_rows:
            update = status_by_uid.get(row["incident_uid"])
            if update and row.get("processing_status") == "MRT_UNAVAILABLE":
                row["processing_status"] = update["processing_status"]
                row["review_reason"] = update["review_reason"]
        write_csv(MANIFEST_OUT, manifest_rows, MANIFEST_FIELDS)
    return changed


def ordered_todo(manifest: list[dict[str, str]], plan_by_uid: dict[str, list[dict[str, str]]], done: set[str]) -> list[dict[str, str]]:
    pending = [row for row in manifest if row["incident_uid"] not in done]
    url_counts = Counter()
    for incident in pending:
        urls = {row["mrt_url"] for row in plan_by_uid.get(incident["incident_uid"], [])}
        url_counts.update(urls)

    def sort_key(incident: dict[str, str]) -> tuple[str, int, int, str]:
        rows = plan_by_uid.get(incident["incident_uid"], [])
        batch_id = min((row.get("batch_id", "") for row in rows), default="")
        shared_files = sum(1 for row in {item["mrt_url"]: item for item in rows}.values() if url_counts[row["mrt_url"]] > 1)
        file_count = len({row["mrt_url"] for row in rows})
        return (batch_id, -shared_files, file_count, incident["incident_uid"])

    return sorted(pending, key=sort_key)


def execute(max_incidents: int | None = None, keep_raw: bool = False) -> str:
    info = estimate()
    manifest, plan = load_train_inputs()
    initialize_outputs(manifest, info)
    reclassified = reclassify_false_mrt_unavailable(plan)
    plan_by_uid = group_by(plan, "incident_uid")
    done = completed_incidents()
    todo_all = ordered_todo(manifest, plan_by_uid, done)
    todo = todo_all
    if max_incidents is not None:
        todo = todo[:max_incidents]
    active_uids = {row["incident_uid"] for row in todo_all}
    dependency_by_url = write_dependency_map(plan, active_uids)
    remaining_by_url = {url: len(uids) for url, uids in dependency_by_url.items()}
    quality_rows = []
    failure_rows = []
    start = time.perf_counter()
    peak_temp_bytes = 0
    min_free = free_bytes()
    released_bytes_total = 0
    cache_events_total = 0
    stopped_for_disk = False
    for index, incident in enumerate(todo, start=1):
        try:
            enforce_disk_safety()
        except RuntimeError as error:
            append_status_history(incident["incident_uid"], "NOT_STARTED", "DISK_SAFETY_PAUSE", str(error))
            stopped_for_disk = True
            break
        result = parse_incident(incident, plan_by_uid[incident["incident_uid"]], keep_raw=keep_raw)
        quality_rows.append(result)
        download_rows = result.pop("download_rows", [])
        update_csv_row(QUALITY, "incident_uid", result["incident_uid"], result, QUALITY_FIELDS)
        update_csv_row(
            MANIFEST_OUT,
            "incident_uid",
            result["incident_uid"],
            {
                "incident_uid": result["incident_uid"],
                "incident_id": result["incident_id"],
                "category": result["category"],
                "partition": result["partition"],
                "processing_status": result["processing_status"],
                "review_reason": result["review_reason"],
                "mrt_files_processed": result["mrt_files_processed"],
                "raw_records_inspected": result["raw_records_inspected"],
                "relevant_observations_retained": result["relevant_observations_retained"],
                "earliest_retained_timestamp": result["earliest_retained_timestamp"],
                "latest_retained_timestamp": result["latest_retained_timestamp"],
                "evidence_path": result["evidence_path"],
            },
            MANIFEST_FIELDS,
        )
        if RAW_CACHE_DIR.exists():
            peak_temp_bytes = max(peak_temp_bytes, sum(path.stat().st_size for path in RAW_CACHE_DIR.glob("*") if path.is_file()))
        released_bytes, cache_events = release_cache_for_incident(result["incident_uid"], download_rows, remaining_by_url, keep_raw=keep_raw)
        released_bytes_total += released_bytes
        cache_events_total += len(cache_events)
        if cache_events:
            append_csv(CACHE_EVENTS, cache_events, CACHE_EVENT_FIELDS)
        min_free = min(min_free, free_bytes())
        print(
            f"{index}/{len(todo)} {result['incident_uid']} status={result['processing_status']} "
            f"raw={result['raw_records_inspected']} relevant={result['relevant_observations_retained']} "
            f"elapsed={result['elapsed_seconds']}s",
            flush=True,
        )
        if result["processing_status"] == "DISK_SAFETY_PAUSE":
            stopped_for_disk = True
            break
    all_quality = read_csv(QUALITY)
    failures = [row for row in all_quality if row.get("processing_status") not in {"TIMESTAMP_EVIDENCE_PASS", "NOT_STARTED"}]
    write_csv(FAILURES, failures, QUALITY_FIELDS)
    status_counts = Counter(row.get("processing_status", "") for row in all_quality)
    evidence_size = sum(path.stat().st_size for path in EVIDENCE_DIR.glob("*.parquet")) if EVIDENCE_DIR.exists() else 0
    batch_row = {
        "batch_run_id": utc_now(),
        "incidents_attempted_this_run": len(todo),
        "total_incidents_with_status": len({row["incident_uid"] for row in all_quality}),
        "timestamp_evidence_pass": status_counts.get("TIMESTAMP_EVIDENCE_PASS", 0),
        "retry_required": status_counts.get("RETRY_REQUIRED", 0) + status_counts.get("RETRY_REQUIRED_DOWNLOAD_CONTEXT", 0),
        "insufficient_evidence": status_counts.get("INSUFFICIENT_EVIDENCE", 0),
        "mrt_unavailable": status_counts.get("MRT_UNAVAILABLE", 0),
        "parser_failure": status_counts.get("PARSER_FAILURE", 0),
        "review_required": status_counts.get("REVIEW_REQUIRED", 0) + status_counts.get("PARQUET_VERIFICATION_FAILURE", 0) + status_counts.get("DISK_SAFETY_PAUSE", 0),
        "total_raw_records_inspected": sum(int(float(row.get("raw_records_inspected") or 0)) for row in all_quality),
        "total_relevant_observations_retained": sum(int(float(row.get("relevant_observations_retained") or 0)) for row in all_quality),
        "evidence_size_bytes": evidence_size,
        "elapsed_seconds_this_run": round(time.perf_counter() - start, 3),
        "status": "DISK_SAFETY_PAUSE" if stopped_for_disk else ("RUN_COMPLETE" if len(todo) else "NOTHING_TO_DO"),
        "false_mrt_unavailable_reclassified": reclassified,
        "cache_events_recorded": cache_events_total,
        "temp_cache_released_bytes": released_bytes_total,
        "peak_temp_cache_bytes": peak_temp_bytes,
        "minimum_free_bytes_observed": min_free,
    }
    previous_batch_rows = read_csv(BATCH_STATUS)
    write_csv(BATCH_STATUS, previous_batch_rows + [batch_row], list(batch_row.keys()))
    disposition = "FULL_TRAIN_TIMESTAMPED_EVIDENCE_READY" if status_counts.get("TIMESTAMP_EVIDENCE_PASS", 0) == 993 else "FULL_TRAIN_TIMESTAMPED_EVIDENCE_REQUIRES_REVIEW"
    write_preflight_summary({**info, "runtime_this_run": batch_row["elapsed_seconds_this_run"]}, disposition)
    return disposition


def main() -> None:
    parser = argparse.ArgumentParser(description="Reconstruct full TRAIN timestamp-preserving TTI evidence.")
    parser.add_argument("--estimate-only", action="store_true")
    parser.add_argument("--max-incidents", type=int, default=None)
    parser.add_argument("--keep-raw", action="store_true")
    args = parser.parse_args()
    info = estimate()
    if args.estimate_only:
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        write_methodology()
        write_preflight_summary(info, "FULL_TRAIN_TIMESTAMPED_EVIDENCE_REQUIRES_REVIEW")
        print(json.dumps(info, indent=2, sort_keys=True))
        print("FULL_TRAIN_TIMESTAMPED_EVIDENCE_REQUIRES_REVIEW")
        return
    print(execute(max_incidents=args.max_incidents, keep_raw=args.keep_raw))


if __name__ == "__main__":
    main()
