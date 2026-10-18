from __future__ import annotations

import argparse
import csv
import json
import math
import shutil
import subprocess
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

try:
    from bgp_incident_detection.audit import write_csv
    from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES
    from bgp_incident_detection.train_incident_scale import (
        ACQUISITION_PLAN,
        ACQUISITION_SUMMARY,
        BEHAVIORAL_FEATURE_COUNT,
        BATCHES,
        FEATURES_PARQUET,
        MANIFEST,
        QUALITY_GATE,
        TRAIN_SCALE_DIR,
        compression_ok,
        copy_or_download,
        parse_and_feature_incident,
        prepare,
    )
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import write_csv
    from src.bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES
    from src.bgp_incident_detection.train_incident_scale import (
        ACQUISITION_PLAN,
        ACQUISITION_SUMMARY,
        BEHAVIORAL_FEATURE_COUNT,
        BATCHES,
        FEATURES_PARQUET,
        MANIFEST,
        QUALITY_GATE,
        TRAIN_SCALE_DIR,
        compression_ok,
        copy_or_download,
        parse_and_feature_incident,
        prepare,
    )


STORAGE_CONFIG = Path("config/storage_config_v1.yaml")
STORAGE_PLAN = TRAIN_SCALE_DIR / "train_batch_storage_plan_v1.csv"
VOLUME_BATCH_PLAN = TRAIN_SCALE_DIR / "train_volume_aware_batch_plan_v1.csv"
URL_DEDUP_SUMMARY = TRAIN_SCALE_DIR / "train_mrt_url_dedup_savings_v1.csv"
BENCHMARK_SUMMARY = TRAIN_SCALE_DIR / "train_small_batch_benchmark_v1.csv"
BENCHMARK_FEATURES = TRAIN_SCALE_DIR / "features" / "train_small_benchmark_features_v1.parquet"
BENCHMARK_QUALITY = TRAIN_SCALE_DIR / "train_small_batch_quality_gate_v1.csv"
NOTEBOOK = Path("notebooks/29_train_storage_and_batch_architecture.ipynb")

STATUS_VALUES = ["PLANNED", "DOWNLOADING", "DOWNLOADED", "PARSING", "FEATURED", "VERIFIED", "CLEANED", "REVIEW", "FAIL"]
DEFAULT_TARGET_MRT_BYTES_PER_BATCH = 2 * 1024 * 1024 * 1024
DEFAULT_PARSER_TEMP_FACTOR = 1.25
DEFAULT_FEATURE_OUTPUT_FACTOR = 0.02
DEFAULT_SAFETY_RESERVE_BYTES = 5 * 1024 * 1024 * 1024


@dataclass(frozen=True)
class DiskPolicy:
    target_mrt_bytes_per_batch: int = DEFAULT_TARGET_MRT_BYTES_PER_BATCH
    parser_temp_factor: float = DEFAULT_PARSER_TEMP_FACTOR
    feature_output_factor: float = DEFAULT_FEATURE_OUTPUT_FACTOR
    safety_reserve_bytes: int = DEFAULT_SAFETY_RESERVE_BYTES


def load_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def source_commit() -> str:
    try:
        result = subprocess.run(["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True)
        return result.stdout.strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        return "UNKNOWN"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def free_bytes(path: Path) -> int:
    probe = path
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    return shutil.disk_usage(probe).free


def required_free_bytes(compressed_bytes: int, policy: DiskPolicy = DiskPolicy()) -> int:
    return int(
        compressed_bytes
        + compressed_bytes * policy.parser_temp_factor
        + compressed_bytes * policy.feature_output_factor
        + policy.safety_reserve_bytes
    )


def storage_rows(policy: DiskPolicy = DiskPolicy()) -> list[dict[str, object]]:
    if not ACQUISITION_SUMMARY.exists():
        prepare(check_remote=False)
    summary = load_csv(ACQUISITION_SUMMARY)
    plan = load_csv(ACQUISITION_PLAN)
    url_size_by_batch: dict[str, dict[str, int]] = defaultdict(dict)
    for row in plan:
        url_size_by_batch[row["batch_id"]].setdefault(row["mrt_url"], int(row.get("estimated_content_length") or 0))
    rows = []
    available = free_bytes(Path("."))
    for batch_id, group in group_by([row for row in summary if row["summary_level"] == "incident"], "batch_id").items():
        compressed = sum(url_size_by_batch.get(batch_id, {}).values())
        peak_temp = int(compressed * policy.parser_temp_factor)
        feature_bytes = int(compressed * policy.feature_output_factor)
        required = required_free_bytes(compressed, policy)
        largest = max(group, key=lambda row: int(float(row.get("estimated_compressed_bytes") or 0)))
        rows.append(
            {
                "batch_id": batch_id,
                "incident_count": len(group),
                "unique_mrt_files": len(url_size_by_batch.get(batch_id, {})),
                "estimated_compressed_bytes": compressed,
                "estimated_peak_temp_bytes": peak_temp,
                "estimated_feature_bytes": feature_bytes,
                "required_free_bytes": required,
                "current_free_bytes": available,
                "safe_to_run": str(available > required),
                "largest_incident": largest["incident_uid"],
                "largest_incident_estimated_bytes": int(float(largest.get("estimated_compressed_bytes") or 0)),
            }
        )
    write_csv(
        STORAGE_PLAN,
        rows,
        [
            "batch_id",
            "incident_count",
            "unique_mrt_files",
            "estimated_compressed_bytes",
            "estimated_peak_temp_bytes",
            "estimated_feature_bytes",
            "required_free_bytes",
            "current_free_bytes",
            "safe_to_run",
            "largest_incident",
            "largest_incident_estimated_bytes",
        ],
    )
    return rows


def volume_aware_batches(policy: DiskPolicy = DiskPolicy()) -> list[dict[str, object]]:
    if not ACQUISITION_SUMMARY.exists():
        prepare(check_remote=False)
    incidents = [row for row in load_csv(ACQUISITION_SUMMARY) if row["summary_level"] == "incident"]
    by_class = {
        category: sorted(
            [row for row in incidents if row["category"] == category],
            key=lambda row: (int(float(row.get("estimated_compressed_bytes") or 0)), row["incident_uid"]),
            reverse=True,
        )
        for category in ("Hijack", "Leak", "Outage")
    }
    queue = []
    while any(by_class.values()):
        for category in ("Outage", "Hijack", "Leak"):
            if by_class[category]:
                queue.append(by_class[category].pop(0))
    rows = []
    batch_id = 1
    batch_bytes = 0
    batch_incidents = 0
    for row in queue:
        size = int(float(row.get("estimated_compressed_bytes") or 0))
        if batch_incidents and batch_bytes + size > policy.target_mrt_bytes_per_batch:
            batch_id += 1
            batch_bytes = 0
            batch_incidents = 0
        rows.append(
            {
                "volume_batch_id": f"volume_batch_{batch_id:03d}",
                "incident_uid": row["incident_uid"],
                "category": row["category"],
                "original_batch_id": row["batch_id"],
                "estimated_compressed_bytes": size,
                "planned_file_count": row["planned_file_count"],
                "processing_status": "PLANNED",
            }
        )
        batch_bytes += size
        batch_incidents += 1
    write_csv(
        VOLUME_BATCH_PLAN,
        rows,
        ["volume_batch_id", "incident_uid", "category", "original_batch_id", "estimated_compressed_bytes", "planned_file_count", "processing_status"],
    )
    return rows


def dedup_savings_rows() -> list[dict[str, object]]:
    plan = load_csv(ACQUISITION_PLAN)
    assignment_bytes = sum(int(row.get("estimated_content_length") or 0) for row in plan)
    by_url = {}
    for row in plan:
        by_url.setdefault(row["mrt_url"], int(row.get("estimated_content_length") or 0))
    unique_bytes = sum(by_url.values())
    rows = [
        {
            "scope": "full_train_plan",
            "file_assignments": len(plan),
            "unique_urls": len(by_url),
            "assignment_bytes": assignment_bytes,
            "unique_url_bytes": unique_bytes,
            "saved_file_downloads": len(plan) - len(by_url),
            "saved_bytes_if_url_cached_once": assignment_bytes - unique_bytes,
            "saved_percent": round((1 - unique_bytes / assignment_bytes) * 100, 3) if assignment_bytes else 0,
        }
    ]
    write_csv(URL_DEDUP_SUMMARY, rows, ["scope", "file_assignments", "unique_urls", "assignment_bytes", "unique_url_bytes", "saved_file_downloads", "saved_bytes_if_url_cached_once", "saved_percent"])
    return rows


def ensure_planning_inputs() -> None:
    if not MANIFEST.exists() or not BATCHES.exists() or not ACQUISITION_PLAN.exists() or not ACQUISITION_SUMMARY.exists():
        prepare(check_remote=False)


def group_by(rows: list[dict[str, object]], key: str) -> dict[str, list[dict[str, object]]]:
    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        grouped[str(row[key])].append(row)
    return grouped


def selected_benchmark_incidents(limit: int = 3) -> list[str]:
    pilot_rows = [row for row in load_csv(Path("data/pilot/mrt_pilot_incidents_v1.csv")) if row.get("partition") == "train"]
    train = {row["incident_uid"] for row in load_csv(MANIFEST)}
    selected = []
    for category in ("Hijack", "Leak", "Outage"):
        for row in pilot_rows:
            if row["category"] == category and row["incident_uid"] in train and row["incident_uid"] not in selected:
                selected.append(row["incident_uid"])
                break
    for row in pilot_rows:
        if len(selected) >= limit:
            break
        if row["incident_uid"] in train and row["incident_uid"] not in selected:
            selected.append(row["incident_uid"])
    if len(selected) >= limit:
        return selected[:limit]
    return [row["incident_uid"] for row in load_csv(MANIFEST)[:limit]]


def benchmark_plan_rows(incident_uids: list[str]) -> list[dict[str, str]]:
    pilot_manifest = load_csv(Path("data/pilot/mrt_pilot_download_manifest_v1.csv"))
    rows = [row for row in pilot_manifest if row["incident_uid"] in set(incident_uids)]
    output = []
    for row in rows:
        local_path = Path(row["local_path"])
        output.append(
            {
                "batch_id": "small_benchmark_001",
                "incident_uid": row["incident_uid"],
                "category": row["category"],
                "active_segment_id": row["active_segment_id"],
                "segment_start": row["segment_start"],
                "segment_end": row["segment_end"],
                "temporal_status": "INCIDENT_ACTIVE",
                "collection_start": row["collection_start"],
                "collection_end": row["collection_end"],
                "collector": row["routeviews_collector"],
                "mrt_timestamp": row["mrt_timestamp"],
                "mrt_url": row["mrt_url"],
                "local_path": f"data/raw_mrt/train_batches/small_benchmark_001/{row['incident_uid'].replace(':', '_')}/{local_path.name}",
                "pilot_reuse_path": row["local_path"],
                "remote_available": "True",
                "status_code": "cached",
                "estimated_content_length": local_path.stat().st_size if local_path.exists() else 0,
                "notes": "small benchmark reuses existing TRAIN pilot MRT file",
            }
        )
    return output


def run_small_benchmark(limit: int = 3, cleanup: bool = True) -> dict[str, object]:
    if not MANIFEST.exists():
        prepare(check_remote=False)
    manifest = {row["incident_uid"]: row for row in load_csv(MANIFEST)}
    selected = selected_benchmark_incidents(limit)
    plan = benchmark_plan_rows(selected)
    if not plan:
        raise ValueError("no reusable pilot MRT files found for benchmark")
    compressed_input = sum(int(row.get("estimated_content_length") or 0) for row in plan)
    required = required_free_bytes(compressed_input, DiskPolicy(safety_reserve_bytes=1024 * 1024))
    available_before = free_bytes(Path("."))
    if available_before <= required:
        raise RuntimeError(f"disk gate failed: available={available_before} required={required}")

    start = time.perf_counter()
    all_features = []
    quality_rows = []
    download_rows = []
    parsed_temp_size_before = directory_size(Path("data/parsed_mrt/train_batches_temp"))
    raw_size_before = directory_size(Path("data/raw_mrt/train_batches"))
    for uid in selected:
        incident = manifest[uid]
        incident_plan = [row for row in plan if row["incident_uid"] == uid]
        downloads = [copy_or_download(row) for row in incident_plan]
        download_rows.extend(downloads)
        features, stats = parse_and_feature_incident(incident, downloads)
        all_features.extend(features)
        status = "VERIFIED" if features and all(row["download_status"] in {"200", "CACHED", "REUSED_FROM_PILOT"} for row in downloads) else "REVIEW"
        quality_rows.append(
            {
                "benchmark_batch_id": "small_benchmark_001",
                "incident_uid": uid,
                "category": incident["category"],
                "status": status,
                "mrt_files": len(downloads),
                "raw_bgp_observations": stats.raw_bgp_observations,
                "relevant_observations": stats.relevant_observations,
                "feature_rows": len(features),
                "parser_version": "bgpdump 1.6.2",
                "source_commit": source_commit(),
            }
        )

    BENCHMARK_FEATURES.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(all_features).to_parquet(BENCHMARK_FEATURES, index=False)
    write_csv(BENCHMARK_QUALITY, quality_rows, ["benchmark_batch_id", "incident_uid", "category", "status", "mrt_files", "raw_bgp_observations", "relevant_observations", "feature_rows", "parser_version", "source_commit"])
    raw_size_after_feature = directory_size(Path("data/raw_mrt/train_batches"))
    parsed_size_after_feature = directory_size(Path("data/parsed_mrt/train"))
    recovered = 0
    if cleanup:
        benchmark_raw = Path("data/raw_mrt/train_batches/small_benchmark_001")
        if benchmark_raw.exists():
            recovered += directory_size(benchmark_raw)
            shutil.rmtree(benchmark_raw)
        for uid in selected:
            parsed_dir = Path("data/parsed_mrt/train") / uid.replace(":", "_")
            if parsed_dir.exists():
                recovered += directory_size(parsed_dir)
                shutil.rmtree(parsed_dir)
    raw_size_after_cleanup = directory_size(Path("data/raw_mrt/train_batches"))
    rows = [
        {
            "benchmark_batch_id": "small_benchmark_001",
            "incident_count": len(selected),
            "incident_uids": json.dumps(selected, separators=(",", ":")),
            "compressed_mrt_input_bytes": compressed_input,
            "estimated_required_free_bytes": required,
            "available_free_bytes_before": available_before,
            "feature_output_bytes": BENCHMARK_FEATURES.stat().st_size,
            "raw_batch_size_before": raw_size_before,
            "raw_batch_size_after_feature": raw_size_after_feature,
            "raw_batch_size_after_cleanup": raw_size_after_cleanup,
            "parsed_temp_size_before": parsed_temp_size_before,
            "parsed_temp_size_after_feature": parsed_size_after_feature,
            "disk_recovered_after_cleanup": recovered,
            "feature_rows": len(all_features),
            "quality_counts": json.dumps(dict(Counter(row["status"] for row in quality_rows)), separators=(",", ":")),
            "elapsed_seconds": round(time.perf_counter() - start, 3),
            "streaming_parse_feasible": "True",
            "cleanup_performed": str(cleanup),
        }
    ]
    write_csv(
        BENCHMARK_SUMMARY,
        rows,
        [
            "benchmark_batch_id",
            "incident_count",
            "incident_uids",
            "compressed_mrt_input_bytes",
            "estimated_required_free_bytes",
            "available_free_bytes_before",
            "feature_output_bytes",
            "raw_batch_size_before",
            "raw_batch_size_after_feature",
            "raw_batch_size_after_cleanup",
            "parsed_temp_size_before",
            "parsed_temp_size_after_feature",
            "disk_recovered_after_cleanup",
            "feature_rows",
            "quality_counts",
            "elapsed_seconds",
            "streaming_parse_feasible",
            "cleanup_performed",
        ],
    )
    return rows[0]


def directory_size(path: Path) -> int:
    if not path.exists():
        return 0
    if path.is_file():
        return path.stat().st_size
    return sum(member.stat().st_size for member in path.rglob("*") if member.is_file())


def write_notebook() -> None:
    NOTEBOOK.parent.mkdir(parents=True, exist_ok=True)
    nb = {
        "cells": [
            {"cell_type": "markdown", "metadata": {}, "source": ["# TRAIN Batch Storage Architecture\n", "\n", "Resource-aware batch design for the frozen TRAIN incident-side behavioral pipeline. This notebook does not change labels, windows, features, or splits.\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["from bgp_incident_detection.train_batch_engine import build_plans\n", "build_plans()\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["from bgp_incident_detection.train_batch_engine import run_small_benchmark\n", "run_small_benchmark(limit=3)\n"]},
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(nb, indent=2) + "\n", encoding="utf-8")


def build_plans() -> dict[str, object]:
    ensure_planning_inputs()
    storage = storage_rows()
    volume = volume_aware_batches()
    dedup = dedup_savings_rows()
    write_notebook()
    old_all_at_once_compressed = int(dedup[0]["unique_url_bytes"])
    old_required = required_free_bytes(old_all_at_once_compressed)
    max_batch_required = max(int(row["required_free_bytes"]) for row in storage) if storage else 0
    max_volume_batch_bytes = max(sum(int(row["estimated_compressed_bytes"]) for row in group) for group in group_by(volume, "volume_batch_id").values()) if volume else 0
    return {
        "old_all_at_once_compressed_bytes": old_all_at_once_compressed,
        "old_all_at_once_peak_required_bytes": old_required,
        "existing_50_incident_batches": len(storage),
        "existing_50_batch_max_required_bytes": max_batch_required,
        "existing_50_batch_safe_count": sum(row["safe_to_run"] == "True" for row in storage),
        "volume_aware_batch_count": len({row["volume_batch_id"] for row in volume}),
        "volume_aware_max_compressed_bytes": max_volume_batch_bytes,
        "url_dedup_saved_file_downloads": dedup[0]["saved_file_downloads"],
        "url_dedup_saved_bytes": dedup[0]["saved_bytes_if_url_cached_once"],
        "outputs": [str(STORAGE_PLAN), str(VOLUME_BATCH_PLAN), str(URL_DEDUP_SUMMARY), str(NOTEBOOK)],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build disk-efficient TRAIN batch architecture and benchmark")
    parser.add_argument("--plan", action="store_true")
    parser.add_argument("--benchmark", action="store_true")
    parser.add_argument("--benchmark-limit", type=int, default=3)
    args = parser.parse_args()
    if args.plan:
        print(json.dumps(build_plans(), indent=2, sort_keys=True))
    elif args.benchmark:
        print(json.dumps(run_small_benchmark(limit=args.benchmark_limit), indent=2, sort_keys=True))
    else:
        parser.error("choose --plan or --benchmark")


if __name__ == "__main__":
    main()
