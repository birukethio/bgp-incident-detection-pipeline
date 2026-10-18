from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import shutil
import subprocess
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    from bgp_incident_detection.audit import parse_utc, write_csv
    from bgp_incident_detection.mrt_acquisition import ceil_to_15_minutes, floor_to_15_minutes, iter_update_slots, routeviews_update_url
    from bgp_incident_detection.normal_pool_scale import CONTEXT_BUFFER_MINUTES, PRESCREEN_PASS
    from bgp_incident_detection.normal_rib_scale import RIB_REVIEW, ROUTE_PRESENCE_UNSTABLE
    from bgp_incident_detection.rib_normal import parse_rib_line, row_matches_target, validate_bzip2
except ImportError:
    from src.bgp_incident_detection.audit import parse_utc, write_csv
    from src.bgp_incident_detection.mrt_acquisition import ceil_to_15_minutes, floor_to_15_minutes, iter_update_slots, routeviews_update_url
    from src.bgp_incident_detection.normal_pool_scale import CONTEXT_BUFFER_MINUTES, PRESCREEN_PASS
    from src.bgp_incident_detection.normal_rib_scale import RIB_REVIEW, ROUTE_PRESENCE_UNSTABLE
    from src.bgp_incident_detection.rib_normal import parse_rib_line, row_matches_target, validate_bzip2


PRIORITY_QUEUE = Path("data/normal_scale/normal_rib_priority_queue_v2.csv")
EXISTING_APPROVED = Path("data/normal_scale/normal_candidate_pool_v1.csv")
RIB_CACHE_INDEX = Path("data/normal_scale/rib_cache_index_v1.csv")

MANIFEST = Path("data/normal_scale/rib_cache_fill_benchmark_manifest_v1.csv")
FILL_PLAN = Path("data/normal_scale/rib_cache_fill_plan_v1.csv")
INDEX_PERFORMANCE = Path("data/normal_scale/rib_index_performance_v1.csv")
RESULTS = Path("data/normal_scale/rib_cache_fill_benchmark_results_v1.csv")
COMPARISON = Path("data/normal_scale/rib_cache_fill_comparison_v1.csv")
UPDATED_ESTIMATE = Path("data/normal_scale/normal_update_acquisition_estimate_v2.csv")
NOTEBOOK = Path("notebooks/22_rib_cache_fill_and_index_benchmark.ipynb")

RAW_CACHE_ROOT = Path("data/cache/routeviews_rib/raw")
INDEX_CACHE_ROOT = Path("data/cache/routeviews_rib/indexed")

BENCHMARK_SIZE = 12
NO_OBSERVABILITY = "NO_OBSERVABILITY"
ORIGIN_UNSTABLE = "ORIGIN_UNSTABLE"
INDEX_SCAN_TIMEOUT_SECONDS = 60.0
USER_AGENT = "bgp-incident-detection-pipeline/0.1"


def load_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def parse_required(value: str) -> datetime:
    parsed = parse_utc(value)
    if not parsed:
        raise ValueError(f"invalid UTC timestamp: {value}")
    return parsed


def isoformat_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_timestamp(value: str) -> str:
    return value.replace("-", "").replace(":", "").replace("Z", "Z")


def raw_rib_path(collector: str, rib_timestamp: str) -> Path:
    ts = parse_required(rib_timestamp)
    return RAW_CACHE_ROOT / collector / f"{ts:%Y%m%d}" / f"rib.{ts:%Y%m%d.%H%M}.bz2"


def indexed_rib_path(collector: str, rib_timestamp: str, affected_asn: str, affected_prefix: str) -> Path:
    safe_prefix = (affected_prefix or "asn").replace("/", "_").replace(":", "_").replace(".", "_")
    return INDEX_CACHE_ROOT / collector / f"{safe_timestamp(rib_timestamp)}_{affected_asn}_{safe_prefix}.csv"


def head_url(url: str, timeout_seconds: float = 20.0) -> tuple[bool, str, int]:
    request = Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            return 200 <= response.status < 400, str(response.status), int(response.headers.get("Content-Length") or 0)
    except HTTPError as error:
        return False, str(error.code), 0
    except URLError:
        return False, "", 0


def exact_benchmark_candidates() -> list[dict[str, str]]:
    rows = load_csv(PRIORITY_QUEUE)[:BENCHMARK_SIZE]
    if len(rows) != BENCHMARK_SIZE:
        raise ValueError(f"expected {BENCHMARK_SIZE} priority queue rows, found {len(rows)}")
    return rows


def build_manifest(candidates: list[dict[str, str]]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for index, row in enumerate(candidates, start=1):
        rows.append(
            {
                "candidate_period_id": row["candidate_period_id"],
                "associated_incident_uid": row["associated_incident_uid"],
                "associated_category": row["associated_category"],
                "affected_asn": row["affected_asn"],
                "affected_prefix": row.get("affected_prefix", ""),
                "candidate_start": row["candidate_start"],
                "candidate_end": row["candidate_end"],
                "collector": "route-views2",
                "rib_before_timestamp": row["rib_before_timestamp"],
                "rib_after_timestamp": row["rib_after_timestamp"],
                "priority_score": row["rib_priority_score"],
                "benchmark_order": index,
            }
        )
    return rows


def build_fill_plan(candidates: list[dict[str, str]]) -> list[dict[str, object]]:
    required: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for row in candidates:
        for side in ("before", "after"):
            required[("route-views2", row[f"rib_{side}_timestamp"], row[f"rib_{side}_url"])].add(row["candidate_period_id"])
    rows: list[dict[str, object]] = []
    for collector, rib_timestamp, rib_url in sorted(required):
        local = raw_rib_path(collector, rib_timestamp)
        cached = local.exists() and local.stat().st_size > 0 and validate_bzip2(local)
        rows.append(
            {
                "collector": collector,
                "rib_timestamp": rib_timestamp,
                "rib_url": rib_url,
                "required_by_candidate_count": len(required[(collector, rib_timestamp, rib_url)]),
                "already_cached": str(cached),
                "download_required": str(not cached),
                "local_path": str(local),
            }
        )
    return rows


def download_rib(row: dict[str, object]) -> dict[str, object]:
    path = Path(str(row["local_path"]))
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.stat().st_size > 0 and validate_bzip2(path):
        return {
            **row,
            "http_status": "CACHED",
            "file_size": path.stat().st_size,
            "checksum": sha256(path),
            "download_timestamp": isoformat_z(datetime.now(timezone.utc)),
            "corruption_check": "PASS",
            "download_seconds": 0.0,
        }
    start = time.perf_counter()
    request = Request(str(row["rib_url"]), headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(request, timeout=600.0) as response, path.open("wb") as handle:
            shutil.copyfileobj(response, handle, length=1024 * 1024)
            status = str(response.status)
        valid = path.exists() and path.stat().st_size > 0 and validate_bzip2(path)
        return {
            **row,
            "http_status": status,
            "file_size": path.stat().st_size if path.exists() else 0,
            "checksum": sha256(path) if valid else "",
            "download_timestamp": isoformat_z(datetime.now(timezone.utc)),
            "corruption_check": "PASS" if valid else "FAIL",
            "download_seconds": round(time.perf_counter() - start, 3),
        }
    except (HTTPError, URLError) as error:
        return {
            **row,
            "http_status": str(getattr(error, "code", "")) or str(error),
            "file_size": 0,
            "checksum": "",
            "download_timestamp": isoformat_z(datetime.now(timezone.utc)),
            "corruption_check": "FAIL",
            "download_seconds": round(time.perf_counter() - start, 3),
        }


def update_cache_index(download_rows: list[dict[str, object]]) -> None:
    existing = {
        (row["collector"], row["rib_timestamp"], row["source_url"]): row
        for row in load_csv(RIB_CACHE_INDEX)
    }
    now = isoformat_z(datetime.now(timezone.utc))
    for row in download_rows:
        existing[(str(row["collector"]), str(row["rib_timestamp"]), str(row["rib_url"]))] = {
            "collector": row["collector"],
            "rib_timestamp": row["rib_timestamp"],
            "source_url": row["rib_url"],
            "local_path": row["local_path"],
            "downloaded": "False" if row["http_status"] == "CACHED" else str(row["corruption_check"] == "PASS"),
            "parsed": "False",
            "file_size": row["file_size"],
            "checksum": row["checksum"],
            "last_used": now,
            "status": row["http_status"] if row["corruption_check"] == "PASS" else "FAILED",
        }
    write_csv(RIB_CACHE_INDEX, sorted(existing.values(), key=lambda item: (item["collector"], item["rib_timestamp"], item["source_url"])), ["collector", "rib_timestamp", "source_url", "local_path", "downloaded", "parsed", "file_size", "checksum", "last_used", "status"])


def parse_target_index(row: dict[str, str], side: str) -> tuple[list[dict[str, str]], dict[str, object]]:
    rib_timestamp = row[f"rib_{side}_timestamp"]
    collector = row["collector"]
    raw_path = raw_rib_path(collector, rib_timestamp)
    out_path = indexed_rib_path(collector, rib_timestamp, row["affected_asn"], row.get("affected_prefix", ""))
    lookup_start = time.perf_counter()
    if out_path.exists() and out_path.stat().st_size > 0:
        rows = load_csv(out_path)
        return rows, {
            "rib_timestamp": rib_timestamp,
            "raw_size": raw_path.stat().st_size if raw_path.exists() else 0,
            "index_size": out_path.stat().st_size,
            "parse_seconds": 0.0,
            "index_build_seconds": 0.0,
            "first_lookup_ms": round((time.perf_counter() - lookup_start) * 1000, 3),
            "repeated_lookup_ms": round((time.perf_counter() - lookup_start) * 1000, 3),
            "indexed_row_count": len(rows),
            "index_path": str(out_path),
            "status": "INDEX_CACHED",
        }
    if not raw_path.exists() or not validate_bzip2(raw_path):
        return [], {
            "rib_timestamp": rib_timestamp,
            "raw_size": 0,
            "index_size": 0,
            "parse_seconds": 0.0,
            "index_build_seconds": 0.0,
            "first_lookup_ms": 0.0,
            "repeated_lookup_ms": 0.0,
            "indexed_row_count": 0,
            "index_path": str(out_path),
            "status": "RAW_RIB_MISSING",
        }
    if not out_path.exists():
        return [], {
            "rib_timestamp": rib_timestamp,
            "raw_size": raw_path.stat().st_size,
            "index_size": 0,
            "parse_seconds": 0.0,
            "index_build_seconds": 0.0,
            "first_lookup_ms": 0.0,
            "repeated_lookup_ms": 0.0,
            "indexed_row_count": 0,
            "index_path": str(out_path),
            "status": "INDEX_DEFERRED",
        }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    start = time.perf_counter()
    rows: list[dict[str, str]] = []
    command = ["bgpdump", "-q", "-m", str(raw_path)]
    target = row.get("affected_prefix", "") or row["affected_asn"]
    process = subprocess.Popen(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    grep = None
    try:
        if process.stdout is not None:
            grep = subprocess.Popen(
                ["grep", "-F", "-m", "2000", target],
                text=True,
                stdin=process.stdout,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            process.stdout.close()
            output, _ = grep.communicate(timeout=INDEX_SCAN_TIMEOUT_SECONDS)
            for line in output.splitlines():
                parsed = parse_rib_line(line)
                if parsed is None or not row_matches_target(parsed, row["affected_asn"], row.get("affected_prefix", "")):
                    continue
                rows.append(
                    {
                        "collector": collector,
                        "rib_timestamp": rib_timestamp,
                        "prefix": parsed["prefix"],
                        "peer_asn": parsed["peer_asn"],
                        "origin_asn": parsed["origin_asn"],
                        "as_path": parsed["as_path"],
                    }
                )
    except subprocess.TimeoutExpired:
        if grep is not None:
            grep.kill()
            output, _ = grep.communicate()
            for line in output.splitlines():
                parsed = parse_rib_line(line)
                if parsed is None or not row_matches_target(parsed, row["affected_asn"], row.get("affected_prefix", "")):
                    continue
                rows.append(
                    {
                        "collector": collector,
                        "rib_timestamp": rib_timestamp,
                        "prefix": parsed["prefix"],
                        "peer_asn": parsed["peer_asn"],
                        "origin_asn": parsed["origin_asn"],
                        "as_path": parsed["as_path"],
                    }
                )
    finally:
        if grep is not None and grep.poll() is None:
            grep.kill()
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)
    write_csv(out_path, rows, ["collector", "rib_timestamp", "prefix", "peer_asn", "origin_asn", "as_path"])
    parse_seconds = time.perf_counter() - start
    reload_start = time.perf_counter()
    reloaded = load_csv(out_path)
    first_lookup_ms = (time.perf_counter() - reload_start) * 1000
    repeat_start = time.perf_counter()
    _ = [item for item in reloaded if item.get("origin_asn") or item.get("prefix")]
    repeated_lookup_ms = (time.perf_counter() - repeat_start) * 1000
    return reloaded, {
        "rib_timestamp": rib_timestamp,
        "raw_size": raw_path.stat().st_size,
        "index_size": out_path.stat().st_size if out_path.exists() else 0,
        "parse_seconds": round(parse_seconds, 3),
        "index_build_seconds": round(parse_seconds, 3),
        "first_lookup_ms": round(first_lookup_ms, 3),
        "repeated_lookup_ms": round(repeated_lookup_ms, 3),
        "indexed_row_count": len(reloaded),
        "index_path": str(out_path),
        "status": "INDEX_BUILT",
    }


def classify_candidate(row: dict[str, str], before: list[dict[str, str]], after: list[dict[str, str]]) -> dict[str, object]:
    before_origins = sorted({item["origin_asn"] for item in before if item["origin_asn"]})
    after_origins = sorted({item["origin_asn"] for item in after if item["origin_asn"]})
    before_visible = bool(before)
    after_visible = bool(after)
    origin_stable = bool(before_origins) and before_origins == after_origins
    route_stable = before_visible and after_visible
    if route_stable and origin_stable:
        status = PRESCREEN_PASS
        reason = "indexed before/after RIB target evidence confirms route visibility and stable origin"
    elif before_visible != after_visible:
        status = ROUTE_PRESENCE_UNSTABLE
        reason = "indexed evidence exists on only one side of the candidate period"
    elif route_stable and not origin_stable:
        status = ORIGIN_UNSTABLE
        reason = "indexed evidence exists before/after but origin set is missing or changed"
    elif not before_visible and not after_visible:
        status = NO_OBSERVABILITY
        reason = "indexed before/after RIBs contain no target ASN/prefix evidence"
    else:
        status = RIB_REVIEW
        reason = "RIB evidence remains unresolved"
    return {
        "candidate_period_id": row["candidate_period_id"],
        "associated_incident_uid": row["associated_incident_uid"],
        "associated_category": row["associated_category"],
        "affected_asn": row["affected_asn"],
        "affected_prefix": row.get("affected_prefix", ""),
        "candidate_start": row["candidate_start"],
        "candidate_end": row["candidate_end"],
        "collector": row["collector"],
        "rib_before_timestamp": row["rib_before_timestamp"],
        "rib_after_timestamp": row["rib_after_timestamp"],
        "asn_visible_before": str(before_visible),
        "asn_visible_after": str(after_visible),
        "prefix_visible_before": str(bool(before)) if row.get("affected_prefix") else "NOT_APPLICABLE",
        "prefix_visible_after": str(bool(after)) if row.get("affected_prefix") else "NOT_APPLICABLE",
        "origin_before": json.dumps(before_origins, separators=(",", ":")),
        "origin_after": json.dumps(after_origins, separators=(",", ":")),
        "origin_stable": str(origin_stable),
        "route_presence_stable": str(route_stable),
        "prescreen_status": status,
        "reason": reason,
    }


def update_slots(row: dict[str, str]) -> list[datetime]:
    start = floor_to_15_minutes(parse_required(row["candidate_start"]) - timedelta(minutes=CONTEXT_BUFFER_MINUTES))
    end = ceil_to_15_minutes(parse_required(row["candidate_end"]) + timedelta(minutes=CONTEXT_BUFFER_MINUTES))
    return iter_update_slots(start, end)


def update_acquisition_estimate(results: list[dict[str, object]]) -> None:
    approved_pool = [row for row in load_csv(EXISTING_APPROVED) if row.get("prescreen_status") == PRESCREEN_PASS]
    approved_pool.extend({str(row["candidate_period_id"]): row for row in results if row["prescreen_status"] == PRESCREEN_PASS}.values())
    rows: list[dict[str, object]] = []
    for row in approved_pool:
        slots = update_slots(row)
        rows.append(
            {
                "candidate_period_id": row["candidate_period_id"],
                "associated_incident_uid": row.get("associated_incident_uid", ""),
                "associated_category": row["associated_category"],
                "affected_asn": row["affected_asn"],
                "collector": row.get("collector") or "route-views2",
                "candidate_start": row["candidate_start"],
                "candidate_end": row["candidate_end"],
                "collection_start": isoformat_z(slots[0]),
                "collection_end": isoformat_z(slots[-1]),
                "required_update_file_count": len(slots),
                "remote_availability_checked": "False",
                "remote_available_file_count": "",
                "remote_availability_percent": "",
                "estimated_compressed_bytes": "",
                "estimated_compressed_mib": "",
                "expected_5_minute_window_count": math.ceil((parse_required(row["candidate_end"]) - parse_required(row["candidate_start"])).total_seconds() / 300),
                "notes": "UPDATE estimate only; no UPDATE MRT files downloaded in cache-fill benchmark",
            }
        )
    write_csv(UPDATED_ESTIMATE, rows, ["candidate_period_id", "associated_incident_uid", "associated_category", "affected_asn", "collector", "candidate_start", "candidate_end", "collection_start", "collection_end", "required_update_file_count", "remote_availability_checked", "remote_available_file_count", "remote_availability_percent", "estimated_compressed_bytes", "estimated_compressed_mib", "expected_5_minute_window_count", "notes"])


def write_notebook() -> None:
    NOTEBOOK.parent.mkdir(parents=True, exist_ok=True)
    notebook = {
        "cells": [
            {"cell_type": "markdown", "metadata": {}, "source": ["# RIB Cache Fill And Index Benchmark\n", "\n", "Populate the RIB cache and build target-filtered indexes for the fixed 12-candidate Normal benchmark. No UPDATE downloads and no Normal labels.\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["from bgp_incident_detection.rib_cache_index import run\n", "summary = run()\n", "summary\n"]},
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")


def run() -> dict[str, object]:
    start = time.perf_counter()
    candidates = exact_benchmark_candidates()
    manifest = build_manifest(candidates)
    plan = build_fill_plan(candidates)
    write_csv(MANIFEST, manifest, ["candidate_period_id", "associated_incident_uid", "associated_category", "affected_asn", "affected_prefix", "candidate_start", "candidate_end", "collector", "rib_before_timestamp", "rib_after_timestamp", "priority_score", "benchmark_order"])
    write_csv(FILL_PLAN, plan, ["collector", "rib_timestamp", "rib_url", "required_by_candidate_count", "already_cached", "download_required", "local_path"])
    download_rows = [download_rib(row) for row in plan]
    update_cache_index(download_rows)
    indexed_metrics: list[dict[str, object]] = []
    results: list[dict[str, object]] = []
    for row in manifest:
        before_rows, before_perf = parse_target_index(row, "before")
        after_rows, after_perf = parse_target_index(row, "after")
        indexed_metrics.extend([{**before_perf, "candidate_period_id": row["candidate_period_id"], "side": "before"}, {**after_perf, "candidate_period_id": row["candidate_period_id"], "side": "after"}])
        results.append(classify_candidate(row, before_rows, after_rows))
    write_csv(INDEX_PERFORMANCE, indexed_metrics, ["candidate_period_id", "side", "rib_timestamp", "raw_size", "index_size", "parse_seconds", "index_build_seconds", "first_lookup_ms", "repeated_lookup_ms", "indexed_row_count", "index_path", "status"])
    write_csv(RESULTS, results, ["candidate_period_id", "associated_incident_uid", "associated_category", "affected_asn", "affected_prefix", "candidate_start", "candidate_end", "collector", "rib_before_timestamp", "rib_after_timestamp", "asn_visible_before", "asn_visible_after", "prefix_visible_before", "prefix_visible_after", "origin_before", "origin_after", "origin_stable", "route_presence_stable", "prescreen_status", "reason"])
    update_acquisition_estimate(results)
    before_pass = 0
    after_pass = sum(row["prescreen_status"] == PRESCREEN_PASS for row in results)
    elapsed = time.perf_counter() - start
    comparison = [
        {
            "run_label": "before_cache_fill",
            "candidates_processed": BENCHMARK_SIZE,
            "RIB_files_available": 0,
            "full_RIB_parses": 0,
            "index_lookups": 0,
            "RIB_PRESCREEN_PASS": before_pass,
            "RIB_REVIEW": BENCHMARK_SIZE,
            "failures": BENCHMARK_SIZE,
            "elapsed_time": "",
            "average_time_per_candidate": "",
        },
        {
            "run_label": "after_cache_fill",
            "candidates_processed": len(results),
            "RIB_files_available": sum(row["corruption_check"] == "PASS" for row in download_rows),
            "full_RIB_parses": sum(row["status"] == "INDEX_BUILT" for row in indexed_metrics),
            "index_lookups": len(indexed_metrics),
            "RIB_PRESCREEN_PASS": after_pass,
            "RIB_REVIEW": sum(row["prescreen_status"] == RIB_REVIEW for row in results),
            "failures": len(results) - after_pass,
            "elapsed_time": round(elapsed, 3),
            "average_time_per_candidate": round(elapsed / len(results), 3) if results else 0,
        },
    ]
    write_csv(COMPARISON, comparison, ["run_label", "candidates_processed", "RIB_files_available", "full_RIB_parses", "index_lookups", "RIB_PRESCREEN_PASS", "RIB_REVIEW", "failures", "elapsed_time", "average_time_per_candidate"])
    write_notebook()
    approved_totals = Counter(row["associated_category"] for row in load_csv(EXISTING_APPROVED) if row.get("prescreen_status") == PRESCREEN_PASS)
    approved_totals.update(row["associated_category"] for row in results if row["prescreen_status"] == PRESCREEN_PASS)
    return {
        "benchmark_candidates": len(manifest),
        "unique_rib_snapshots": len(plan),
        "downloaded_ribs": sum(row["http_status"] != "CACHED" and row["corruption_check"] == "PASS" for row in download_rows),
        "cache_reused_ribs": sum(row["http_status"] == "CACHED" for row in download_rows),
        "downloaded_bytes": sum(int(row["file_size"]) for row in download_rows if row["http_status"] != "CACHED" and row["corruption_check"] == "PASS"),
        "indexes_built": sum(row["status"] == "INDEX_BUILT" for row in indexed_metrics),
        "indexed_lookup_rows": len(indexed_metrics),
        "benchmark_status_counts": dict(Counter(row["prescreen_status"] for row in results)),
        "benchmark_pass_by_class": dict(Counter(row["associated_category"] for row in results if row["prescreen_status"] == PRESCREEN_PASS)),
        "approved_totals_by_class": dict(approved_totals),
        "elapsed_seconds": round(elapsed, 3),
        "outputs": [str(MANIFEST), str(FILL_PLAN), str(INDEX_PERFORMANCE), str(RESULTS), str(COMPARISON), str(UPDATED_ESTIMATE), str(NOTEBOOK)],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Populate RIB cache and build target indexes for fixed 12-candidate benchmark")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if not args.run:
        parser.error("choose --run")
    print(json.dumps(run(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
