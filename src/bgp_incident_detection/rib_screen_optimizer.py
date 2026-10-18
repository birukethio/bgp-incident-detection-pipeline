from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
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
    from bgp_incident_detection.mrt_parser import origin_asn_from_path, parse_as_path_set
    from bgp_incident_detection.normal_pool_scale import (
        CONTEXT_BUFFER_MINUTES,
        EXCLUSION_BUFFER_MINUTES,
        MIN_DURATION_MINUTES,
        NORMAL_CANDIDATE_POOL,
        PRESCREEN_PASS,
        REVIEW,
    )
    from bgp_incident_detection.normal_rib_scale import (
        EXPANDED_RESULTS,
        RIB_CACHE_INDEX,
        RIB_REVIEW,
        ROUTE_PRESENCE_UNSTABLE,
        UPDATE_ESTIMATE_V2,
        local_rib_path,
        rib_url_for,
    )
    from bgp_incident_detection.rib_normal import nearest_ribs, parse_rib_line, row_matches_target, validate_bzip2
except ImportError:
    from src.bgp_incident_detection.audit import parse_utc, write_csv
    from src.bgp_incident_detection.mrt_acquisition import ceil_to_15_minutes, floor_to_15_minutes, iter_update_slots, routeviews_update_url
    from src.bgp_incident_detection.mrt_parser import origin_asn_from_path, parse_as_path_set
    from src.bgp_incident_detection.normal_pool_scale import (
        CONTEXT_BUFFER_MINUTES,
        EXCLUSION_BUFFER_MINUTES,
        MIN_DURATION_MINUTES,
        NORMAL_CANDIDATE_POOL,
        PRESCREEN_PASS,
        REVIEW,
    )
    from src.bgp_incident_detection.normal_rib_scale import (
        EXPANDED_RESULTS,
        RIB_CACHE_INDEX,
        RIB_REVIEW,
        ROUTE_PRESENCE_UNSTABLE,
        UPDATE_ESTIMATE_V2,
        local_rib_path,
        rib_url_for,
    )
    from src.bgp_incident_detection.rib_normal import nearest_ribs, parse_rib_line, row_matches_target, validate_bzip2


FAILURE_DIAGNOSIS = Path("data/normal_scale/rib_screen_failure_diagnosis_v1.csv")
PRIORITY_QUEUE = Path("data/normal_scale/normal_rib_priority_queue_v2.csv")
CACHE_PERFORMANCE = Path("data/normal_scale/rib_cache_performance_v1.csv")
OPTIMIZATION_COMPARISON = Path("data/normal_scale/rib_screening_optimization_comparison_v1.csv")
NOTEBOOK = Path("notebooks/21_normal_rib_screening_optimization.ipynb")
INDEX_ROOT = Path("data/cache/routeviews_rib_index")

NO_OBSERVABILITY = "NO_OBSERVABILITY"
ORIGIN_UNSTABLE = "ORIGIN_UNSTABLE"
BENCHMARK_BATCH_SIZE = 12
MAX_RIB_CANDIDATES_PER_ASN = 3
INDEX_TIMEOUT_SECONDS = 20


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


def head_url(url: str, timeout_seconds: float = 10.0) -> tuple[bool, str, int, float]:
    start = time.perf_counter()
    request = Request(url, method="HEAD", headers={"User-Agent": "bgp-incident-detection-pipeline/0.1"})
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            return 200 <= response.status < 400, str(response.status), int(response.headers.get("Content-Length") or 0), time.perf_counter() - start
    except HTTPError as error:
        return False, str(error.code), 0, time.perf_counter() - start
    except URLError:
        return False, "", 0, time.perf_counter() - start


def summarize_failure_rows(rows: list[dict[str, str]]) -> list[dict[str, object]]:
    output = []
    for row in rows:
        status = row["prescreen_status"]
        before_visible = row["asn_visible_before"] == "True"
        after_visible = row["asn_visible_after"] == "True"
        if status == ROUTE_PRESENCE_UNSTABLE:
            reason = "ASN/route was visible on only one side of the candidate interval."
        elif status == RIB_REVIEW:
            reason = "RIB snapshot was available but target visibility/origin evidence remained unresolved or parsing timed out."
        else:
            reason = row.get("reason", "")
        output.append(
            {
                "candidate_period_id": row["candidate_period_id"],
                "associated_category": row["associated_category"],
                "affected_asn": row["affected_asn"],
                "collector": row["collector"],
                "asn_visible_before": row["asn_visible_before"],
                "asn_visible_after": row["asn_visible_after"],
                "prefix_visible_before": row["prefix_visible_before"],
                "prefix_visible_after": row["prefix_visible_after"],
                "origin_before": row["origin_before"],
                "origin_after": row["origin_after"],
                "route_presence_before": str(before_visible),
                "route_presence_after": str(after_visible),
                "status": status,
                "exact_failure_reason": reason,
            }
        )
    return output


def nearest_pair(row: dict[str, str]) -> tuple[datetime, datetime]:
    start = parse_required(row["candidate_start"])
    end = parse_required(row["candidate_end"])
    before_hour = start.hour - (start.hour % 2)
    before = start.replace(hour=before_hour, minute=0, second=0, microsecond=0)
    after_hour = end.hour if end.minute == 0 and end.second == 0 and end.microsecond == 0 else end.hour + 1
    if after_hour % 2:
        after_hour += 1
    after = end.replace(minute=0, second=0, microsecond=0)
    after = after + timedelta(hours=after_hour - end.hour)
    return before, after


def priority_components(row: dict[str, str], prior_pass_asns: set[str], cache_urls: set[str], screened_counts: Counter[str]) -> dict[str, object]:
    before, after = nearest_pair(row)
    before_url = rib_url_for("route-views2", before)
    after_url = rib_url_for("route-views2", after)
    before_cached = before_url in cache_urls or local_rib_path("route-views2", before).exists()
    after_cached = after_url in cache_urls or local_rib_path("route-views2", after).exists()
    exact_prefix = bool(row.get("affected_prefix"))
    offset = abs(int(float(row.get("days_from_incident") or 0)))
    same_asn_prior_pass = row["affected_asn"] in prior_pass_asns
    score = 0
    score += 25 if same_asn_prior_pass else 0
    score += 20 if before_cached else 0
    score += 20 if after_cached else 0
    score += 10 if exact_prefix else 0
    score += 8 if offset <= 3 else (4 if offset <= 14 else 1)
    score += {"Outage": 18, "Hijack": 10, "Leak": 8}.get(row["associated_category"], 0)
    score -= screened_counts[row["affected_asn"]] * 5
    return {
        "rib_priority_score": score,
        "component_same_asn_prior_pass": str(same_asn_prior_pass),
        "component_rib_before_cached": str(before_cached),
        "component_rib_after_cached": str(after_cached),
        "component_exact_prefix_known": str(exact_prefix),
        "component_offset_score": 8 if offset <= 3 else (4 if offset <= 14 else 1),
        "component_class_deficit_score": {"Outage": 18, "Hijack": 10, "Leak": 8}.get(row["associated_category"], 0),
        "rib_before_timestamp": isoformat_z(before),
        "rib_after_timestamp": isoformat_z(after),
        "rib_before_url": before_url,
        "rib_after_url": after_url,
    }


def build_priority_queue(pool: list[dict[str, str]], expanded: list[dict[str, str]], max_per_asn: int) -> list[dict[str, object]]:
    completed = {row["candidate_period_id"] for row in expanded}
    prior_pass_asns = {row["affected_asn"] for row in pool if row.get("prescreen_status") == PRESCREEN_PASS}
    cache_urls = {row["source_url"] for row in load_csv(RIB_CACHE_INDEX)}
    raw_candidates = [
        row for row in pool
        if row.get("prescreen_status") == REVIEW
        and row.get("partition") == "train"
        and row.get("known_incident_overlap") == "False"
        and row.get("affected_asn")
        and row.get("candidate_period_id") not in completed
        and float(row.get("duration_minutes") or 0) >= MIN_DURATION_MINUTES
    ]
    per_asn: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in raw_candidates:
        if len(per_asn[row["affected_asn"]]) >= max_per_asn:
            continue
        comp = priority_components(row, prior_pass_asns, cache_urls, Counter({row["affected_asn"]: len(per_asn[row["affected_asn"]])}))
        enriched = dict(row)
        enriched.update(comp)
        per_asn[row["affected_asn"]].append(enriched)
    for values in per_asn.values():
        values.sort(key=lambda row: (-int(row["rib_priority_score"]), abs(int(float(row.get("days_from_incident") or 0))), row["candidate_period_id"]))
    queue = []
    for depth in range(max_per_asn):
        by_class: dict[str, list[dict[str, object]]] = defaultdict(list)
        for asn, values in per_asn.items():
            if depth < len(values):
                by_class[values[depth]["associated_category"]].append(values[depth])
        for category in ("Outage", "Hijack", "Leak"):
            by_class[category].sort(key=lambda row: (-int(row["rib_priority_score"]), row["affected_asn"], row["candidate_period_id"]))
        while any(by_class.values()):
            for category in ("Outage", "Hijack", "Leak"):
                if by_class[category]:
                    queue.append(by_class[category].pop(0))
    return queue


def index_path(collector: str, rib_timestamp: str, affected_asn: str, affected_prefix: str) -> Path:
    safe_prefix = (affected_prefix or "asn").replace("/", "_").replace(":", "_").replace(".", "_")
    safe_ts = rib_timestamp.replace(":", "").replace("-", "")
    return INDEX_ROOT / collector / f"{safe_ts}_{affected_asn}_{safe_prefix}.csv"


def target_index_from_rib(rib_path: Path, collector: str, rib_timestamp: str, affected_asn: str, affected_prefix: str) -> tuple[list[dict[str, str]], dict[str, object]]:
    out = index_path(collector, rib_timestamp, affected_asn, affected_prefix)
    start = time.perf_counter()
    cache_hit = out.exists() and out.stat().st_size > 0
    if cache_hit:
        return load_csv(out), {"cache_hit": True, "full_parse_required": False, "index_build_seconds": 0.0, "lookup_seconds": 0.0, "index_path": str(out)}
    out.parent.mkdir(parents=True, exist_ok=True)
    command = ["bgpdump", "-q", "-m", str(rib_path)]
    process = subprocess.Popen(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    rows: list[dict[str, str]] = []
    deadline = time.monotonic() + INDEX_TIMEOUT_SECONDS
    try:
        if process.stdout is not None:
            for line in process.stdout:
                if time.monotonic() > deadline:
                    break
                if affected_prefix and affected_prefix not in line:
                    continue
                if not affected_prefix and affected_asn not in line:
                    continue
                parsed = parse_rib_line(line)
                if not parsed or not row_matches_target(parsed, affected_asn, affected_prefix):
                    continue
                rows.append(
                    {
                        "rib_timestamp": rib_timestamp,
                        "collector": collector,
                        "prefix": parsed["prefix"],
                        "origin_asn": parsed["origin_asn"],
                        "peer_asn": parsed["peer_asn"],
                        "as_path": parsed["as_path"],
                    }
                )
                if len(rows) >= 1000:
                    break
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)
    write_csv(out, rows, ["rib_timestamp", "collector", "prefix", "origin_asn", "peer_asn", "as_path"])
    return rows, {"cache_hit": False, "full_parse_required": True, "index_build_seconds": round(time.perf_counter() - start, 3), "lookup_seconds": 0.0, "index_path": str(out)}


def rib_path_for_cached_url(url: str) -> Path | None:
    for row in load_csv(RIB_CACHE_INDEX):
        if row["source_url"] == url and Path(row["local_path"]).exists():
            return Path(row["local_path"])
    return None


def inspect_candidate_with_index(row: dict[str, object]) -> tuple[dict[str, object], list[dict[str, object]]]:
    collector = "route-views2"
    perf_rows = []
    before_url = str(row["rib_before_url"])
    after_url = str(row["rib_after_url"])
    states = []
    for side, url, ts in (("before", before_url, str(row["rib_before_timestamp"])), ("after", after_url, str(row["rib_after_timestamp"]))):
        rib_path = rib_path_for_cached_url(url)
        if not rib_path or not rib_path.exists() or not validate_bzip2(rib_path):
            ok, status, size, elapsed = head_url(url)
            perf_rows.append(
                {
                    "candidate_period_id": row["candidate_period_id"],
                    "collector": collector,
                    "rib_timestamp": ts,
                    "source_url": url,
                    "rib_file_cached": "False",
                    "index_cached": "False",
                    "rib_head_available": str(ok),
                    "rib_head_status": status,
                    "rib_file_size": size,
                    "download_time_seconds": 0.0,
                    "first_parse_index_time_seconds": 0.0,
                    "repeated_lookup_time_seconds": round(elapsed, 3),
                    "cache_hit_count": 0,
                    "cache_miss_count": 1,
                    "full_parses_required": 0,
                    "rib_files_reused": 0,
                    "status": "RIB_FILE_NOT_CACHED",
                }
            )
            states.append((side, []))
            continue
        indexed, perf = target_index_from_rib(rib_path, collector, ts, str(row["affected_asn"]), str(row.get("affected_prefix", "")))
        perf_rows.append(
            {
                "candidate_period_id": row["candidate_period_id"],
                "collector": collector,
                "rib_timestamp": ts,
                "source_url": url,
                "rib_file_cached": "True",
                "index_cached": str(perf["cache_hit"]),
                "rib_head_available": "True",
                "rib_head_status": "CACHED",
                "rib_file_size": rib_path.stat().st_size,
                "download_time_seconds": 0.0,
                "first_parse_index_time_seconds": perf["index_build_seconds"],
                "repeated_lookup_time_seconds": perf["lookup_seconds"],
                "cache_hit_count": 1 if perf["cache_hit"] else 0,
                "cache_miss_count": 0 if perf["cache_hit"] else 1,
                "full_parses_required": 0 if perf["cache_hit"] else 1,
                "rib_files_reused": 1,
                "status": "INDEX_READY",
            }
        )
        states.append((side, indexed))
    before = states[0][1]
    after = states[1][1]
    before_origins = sorted({r["origin_asn"] for r in before if r["origin_asn"]})
    after_origins = sorted({r["origin_asn"] for r in after if r["origin_asn"]})
    before_visible = bool(before)
    after_visible = bool(after)
    origin_stable = bool(before_origins) and before_origins == after_origins
    route_stable = before_visible and after_visible
    if route_stable and origin_stable:
        status = PRESCREEN_PASS
        reason = "cached/indexed RIB lookup confirms before/after visibility and stable origin"
    elif before_visible != after_visible:
        status = ROUTE_PRESENCE_UNSTABLE
        reason = "indexed lookup found route on only one side"
    elif route_stable and not origin_stable:
        status = ORIGIN_UNSTABLE
        reason = "indexed lookup found route visibility but unstable or missing origin"
    elif any(p["status"] == "RIB_FILE_NOT_CACHED" for p in perf_rows):
        status = RIB_REVIEW
        reason = "required RIB file not cached; HEAD checked but full download intentionally avoided in optimizer benchmark"
    else:
        status = NO_OBSERVABILITY
        reason = "indexed lookup found no target evidence in before/after RIBs"
    result = {
        "candidate_period_id": row["candidate_period_id"],
        "associated_category": row["associated_category"],
        "affected_asn": row["affected_asn"],
        "affected_prefix": row.get("affected_prefix", ""),
        "collector": collector,
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
    return result, perf_rows


def acquisition_estimate(rows: list[dict[str, str]]) -> list[dict[str, object]]:
    output = []
    for row in rows:
        if row.get("prescreen_status") != PRESCREEN_PASS:
            continue
        start = floor_to_15_minutes(parse_required(row["candidate_start"]) - timedelta(minutes=CONTEXT_BUFFER_MINUTES))
        end = ceil_to_15_minutes(parse_required(row["candidate_end"]) + timedelta(minutes=CONTEXT_BUFFER_MINUTES))
        slots = iter_update_slots(start, end)
        total_bytes = 0
        available = 0
        for slot in slots:
            ok, _, size, _ = head_url(routeviews_update_url(slot, row.get("collector") or "route-views2"))
            available += int(ok)
            total_bytes += size if ok else 0
        output.append(
            {
                "candidate_period_id": row["candidate_period_id"],
                "associated_incident_uid": row.get("associated_incident_uid", ""),
                "associated_category": row["associated_category"],
                "affected_asn": row["affected_asn"],
                "collector": row.get("collector") or "route-views2",
                "candidate_start": row["candidate_start"],
                "candidate_end": row["candidate_end"],
                "collection_start": isoformat_z(start),
                "collection_end": isoformat_z(end),
                "required_update_file_count": len(slots),
                "remote_availability_checked": "True",
                "remote_available_file_count": available,
                "remote_availability_percent": round(100 * available / len(slots), 3),
                "estimated_compressed_bytes": total_bytes,
                "estimated_compressed_mib": round(total_bytes / 1024 / 1024, 3),
                "expected_5_minute_window_count": math.ceil((parse_required(row["candidate_end"]) - parse_required(row["candidate_start"])).total_seconds() / 300),
                "notes": "UPDATE HEAD estimate only; no UPDATE MRT files downloaded",
            }
        )
    return output


def write_notebook() -> None:
    NOTEBOOK.parent.mkdir(parents=True, exist_ok=True)
    nb = {
        "cells": [
            {"cell_type": "markdown", "metadata": {}, "source": ["# RIB Screening Optimization\n", "\n", "Diagnose prior failures, build an explainable priority queue, and benchmark cached/indexed RIB lookup without UPDATE downloads.\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["from bgp_incident_detection.rib_screen_optimizer import run\n", "summary = run(benchmark_batch_size=12, refresh_update_estimate=False)\n", "summary\n"]},
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(nb, indent=2) + "\n", encoding="utf-8")


def run(benchmark_batch_size: int = BENCHMARK_BATCH_SIZE, refresh_update_estimate: bool = True) -> dict[str, object]:
    start = time.perf_counter()
    pool = load_csv(NORMAL_CANDIDATE_POOL)
    expanded = load_csv(EXPANDED_RESULTS)
    diagnosis = summarize_failure_rows(expanded)
    write_csv(FAILURE_DIAGNOSIS, diagnosis, ["candidate_period_id", "associated_category", "affected_asn", "collector", "asn_visible_before", "asn_visible_after", "prefix_visible_before", "prefix_visible_after", "origin_before", "origin_after", "route_presence_before", "route_presence_after", "status", "exact_failure_reason"])
    queue = build_priority_queue(pool, expanded, MAX_RIB_CANDIDATES_PER_ASN)
    write_csv(PRIORITY_QUEUE, queue, ["candidate_period_id", "associated_incident_uid", "associated_category", "partition", "affected_asn", "affected_prefix", "candidate_start", "candidate_end", "duration_minutes", "days_from_incident", "rib_priority_score", "component_same_asn_prior_pass", "component_rib_before_cached", "component_rib_after_cached", "component_exact_prefix_known", "component_offset_score", "component_class_deficit_score", "rib_before_timestamp", "rib_after_timestamp", "rib_before_url", "rib_after_url"])
    batch = []
    by_class: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in queue:
        by_class[row["associated_category"]].append(row)
    for category in ("Hijack", "Leak", "Outage"):
        batch.extend(by_class[category][: benchmark_batch_size // 3])
    batch = batch[:benchmark_batch_size]
    results = []
    perf_rows = []
    for row in batch:
        result, perf = inspect_candidate_with_index(row)
        result["associated_incident_uid"] = row["associated_incident_uid"]
        result["candidate_start"] = row["candidate_start"]
        result["candidate_end"] = row["candidate_end"]
        results.append(result)
        perf_rows.extend(perf)
    write_csv(CACHE_PERFORMANCE, perf_rows, ["candidate_period_id", "collector", "rib_timestamp", "source_url", "rib_file_cached", "index_cached", "rib_head_available", "rib_head_status", "rib_file_size", "download_time_seconds", "first_parse_index_time_seconds", "repeated_lookup_time_seconds", "cache_hit_count", "cache_miss_count", "full_parses_required", "rib_files_reused", "status"])
    all_pass_candidates = [row for row in pool if row.get("prescreen_status") == PRESCREEN_PASS] + [row for row in results if row.get("prescreen_status") == PRESCREEN_PASS]
    if refresh_update_estimate:
        estimate = acquisition_estimate([dict(row) for row in all_pass_candidates])
        write_csv(UPDATE_ESTIMATE_V2, estimate, ["candidate_period_id", "associated_incident_uid", "associated_category", "affected_asn", "collector", "candidate_start", "candidate_end", "collection_start", "collection_end", "required_update_file_count", "remote_availability_checked", "remote_available_file_count", "remote_availability_percent", "estimated_compressed_bytes", "estimated_compressed_mib", "expected_5_minute_window_count", "notes"])
    else:
        estimate = load_csv(UPDATE_ESTIMATE_V2)
    previous_counts = Counter(row["prescreen_status"] for row in expanded)
    optimized_counts = Counter(row["prescreen_status"] for row in results)
    comparison = [
        {
            "run_label": "previous_screening",
            "candidates_processed": len(expanded),
            "elapsed_time_seconds": "",
            "average_time_per_candidate": "",
            "unique_rib_files": len({(row.get("collector", ""), row.get("rib_before_timestamp", "")) for row in expanded} | {(row.get("collector", ""), row.get("rib_after_timestamp", "")) for row in expanded}),
            "cache_hits": "",
            "full_parses_required": "",
            "RIB_PRESCREEN_PASS": previous_counts[PRESCREEN_PASS],
            "RIB_REVIEW": previous_counts[RIB_REVIEW],
            "failure_count": len(expanded) - previous_counts[PRESCREEN_PASS],
        },
        {
            "run_label": "optimized_benchmark_screening",
            "candidates_processed": len(results),
            "elapsed_time_seconds": round(time.perf_counter() - start, 3),
            "average_time_per_candidate": round((time.perf_counter() - start) / len(results), 3) if results else 0,
            "unique_rib_files": len({(row["collector"], row["rib_timestamp"]) for row in perf_rows}),
            "cache_hits": sum(int(row["cache_hit_count"]) for row in perf_rows),
            "full_parses_required": sum(int(row["full_parses_required"]) for row in perf_rows),
            "RIB_PRESCREEN_PASS": optimized_counts[PRESCREEN_PASS],
            "RIB_REVIEW": optimized_counts[RIB_REVIEW],
            "failure_count": len(results) - optimized_counts[PRESCREEN_PASS],
        },
    ]
    write_csv(OPTIMIZATION_COMPARISON, comparison, ["run_label", "candidates_processed", "elapsed_time_seconds", "average_time_per_candidate", "unique_rib_files", "cache_hits", "full_parses_required", "RIB_PRESCREEN_PASS", "RIB_REVIEW", "failure_count"])
    write_notebook()
    return {
        "failure_diagnosis_rows": len(diagnosis),
        "priority_queue_rows": len(queue),
        "benchmark_processed": len(results),
        "benchmark_status_counts": dict(optimized_counts),
        "benchmark_pass_by_class": dict(Counter(row["associated_category"] for row in results if row["prescreen_status"] == PRESCREEN_PASS)),
        "approved_pool_by_class": dict(Counter(row["associated_category"] for row in all_pass_candidates)),
        "cache_performance_rows": len(perf_rows),
        "full_parses_required": sum(int(row["full_parses_required"]) for row in perf_rows),
        "cache_hits": sum(int(row["cache_hit_count"]) for row in perf_rows),
        "update_estimate_rows": len(estimate),
        "outputs": [str(FAILURE_DIAGNOSIS), str(PRIORITY_QUEUE), str(CACHE_PERFORMANCE), str(OPTIMIZATION_COMPARISON), str(UPDATE_ESTIMATE_V2), str(NOTEBOOK)],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Optimize TRAIN-only Normal RIB screening priority and indexing")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--benchmark-batch-size", type=int, default=BENCHMARK_BATCH_SIZE)
    parser.add_argument("--skip-update-estimate-refresh", action="store_true")
    args = parser.parse_args()
    if not args.run:
        parser.error("choose --run")
    print(json.dumps(run(args.benchmark_batch_size, refresh_update_estimate=not args.skip_update_estimate_refresh), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
