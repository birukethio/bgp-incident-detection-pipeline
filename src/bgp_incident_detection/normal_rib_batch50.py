from __future__ import annotations

import argparse
import csv
import json
import math
import sqlite3
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from statistics import median
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    from bgp_incident_detection.audit import parse_utc, write_csv
    from bgp_incident_detection.mrt_acquisition import ceil_to_15_minutes, floor_to_15_minutes, iter_update_slots, routeviews_update_url
    from bgp_incident_detection.normal_pool_scale import CONTEXT_BUFFER_MINUTES, EXCLUSION_BUFFER_MINUTES, MIN_DURATION_MINUTES, PRESCREEN_PASS
    from bgp_incident_detection.normal_rib_scale import RIB_REVIEW, ROUTE_PRESENCE_UNSTABLE
    from bgp_incident_detection.rib_cache_index import NO_OBSERVABILITY, ORIGIN_UNSTABLE
    from bgp_incident_detection.rib_index_engine import DB_PATH, lookup_asn, lookup_prefix
    from bgp_incident_detection.rib_normal import validate_bzip2
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import parse_utc, write_csv
    from src.bgp_incident_detection.mrt_acquisition import ceil_to_15_minutes, floor_to_15_minutes, iter_update_slots, routeviews_update_url
    from src.bgp_incident_detection.normal_pool_scale import CONTEXT_BUFFER_MINUTES, EXCLUSION_BUFFER_MINUTES, MIN_DURATION_MINUTES, PRESCREEN_PASS
    from src.bgp_incident_detection.normal_rib_scale import RIB_REVIEW, ROUTE_PRESENCE_UNSTABLE
    from src.bgp_incident_detection.rib_cache_index import NO_OBSERVABILITY, ORIGIN_UNSTABLE
    from src.bgp_incident_detection.rib_index_engine import DB_PATH, lookup_asn, lookup_prefix
    from src.bgp_incident_detection.rib_normal import validate_bzip2


PRIORITY_QUEUE = Path("data/normal_scale/normal_rib_priority_queue_v2.csv")
EXISTING_APPROVED_POOL = Path("data/normal_scale/normal_candidate_pool_v1.csv")
EXISTING_APPROVED_ESTIMATE = Path("data/normal_scale/normal_update_acquisition_estimate_v2.csv")
PREVIOUS_SCREEN_OUTPUTS = [
    Path("data/normal_scale/normal_rib_prescreen_expanded_v1.csv"),
    Path("data/normal_scale/rib_cache_fill_benchmark_results_v1.csv"),
    Path("data/normal_scale/rib_indexed_lookup_benchmark_v1.csv"),
]
RIB_CACHE_INDEX = Path("data/normal_scale/rib_cache_index_v1.csv")

FILL_PLAN = Path("data/normal_scale/normal_50_candidate_rib_fill_plan_v1.csv")
PRESCREEN_50 = Path("data/normal_scale/normal_rib_prescreen_50_v1.csv")
APPROVED_POOL_V2 = Path("data/normal_scale/normal_rib_approved_pool_v2.csv")
UPDATE_ESTIMATE_V3 = Path("data/normal_scale/normal_approved_update_acquisition_estimate_v3.csv")
PERFORMANCE = Path("data/normal_scale/normal_rib_50_performance_v1.csv")
NOTEBOOK = Path("notebooks/24_normal_rib_prescreen_50.ipynb")

BATCH_SIZE = 50
TARGET_CLASS_COUNTS = {"Hijack": 17, "Leak": 17, "Outage": 16}
RIB_DATA_REQUIRED = "RIB_DATA_REQUIRED"
KNOWN_INCIDENT_OVERLAP = "KNOWN_INCIDENT_OVERLAP"
INELIGIBLE_DURATION = "INELIGIBLE_DURATION"
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


def previously_screened_ids() -> set[str]:
    ids: set[str] = set()
    for path in PREVIOUS_SCREEN_OUTPUTS:
        for row in load_csv(path):
            if row.get("candidate_period_id"):
                ids.add(row["candidate_period_id"])
    return ids


def select_next_50(queue_rows: list[dict[str, str]], batch_size: int = BATCH_SIZE) -> list[dict[str, str]]:
    screened = previously_screened_ids()
    eligible = [
        row for row in queue_rows
        if row.get("partition") == "train"
        and row.get("candidate_period_id") not in screened
        and row.get("associated_category") in TARGET_CLASS_COUNTS
        and row.get("affected_asn")
    ]
    selected: list[dict[str, str]] = []
    selected_ids: set[str] = set()
    counts: Counter[str] = Counter()
    asn_counts: Counter[str] = Counter()

    def try_add(row: dict[str, str], prefer_unique_asn: bool) -> None:
        if len(selected) >= batch_size:
            return
        category = row["associated_category"]
        if counts[category] >= TARGET_CLASS_COUNTS[category]:
            return
        if row["candidate_period_id"] in selected_ids:
            return
        if asn_counts[row["affected_asn"]] >= 3:
            return
        if prefer_unique_asn and asn_counts[row["affected_asn"]] > 0:
            return
        selected.append(row)
        selected_ids.add(row["candidate_period_id"])
        counts[category] += 1
        asn_counts[row["affected_asn"]] += 1

    for row in eligible:
        try_add(row, prefer_unique_asn=True)
    for row in eligible:
        try_add(row, prefer_unique_asn=False)
    return selected


def cached_ribs() -> set[tuple[str, str]]:
    rows = set()
    for row in load_csv(RIB_CACHE_INDEX):
        collector = row.get("collector") or "route-views2"
        ts = row.get("rib_timestamp", "")
        path = Path(row.get("local_path", ""))
        if ts and path.exists() and path.stat().st_size > 0 and validate_bzip2(path):
            rows.add((collector, ts))
    for path in Path("data/cache/routeviews_rib").glob("**/rib.*.bz2"):
        if path.exists() and path.stat().st_size > 0:
            try:
                parts = path.name.split(".")
                parsed = datetime.strptime(f"{parts[1]}{parts[2]}", "%Y%m%d%H%M").replace(tzinfo=timezone.utc)
            except (ValueError, IndexError):
                continue
            rows.add(("route-views2", isoformat_z(parsed)))
    return rows


def indexed_ribs(conn: sqlite3.Connection) -> set[tuple[str, str]]:
    try:
        return {
            (row[0], row[1])
            for row in conn.execute("SELECT collector, rib_timestamp FROM rib_index_metadata WHERE index_status = 'INDEXED'")
        }
    except sqlite3.OperationalError:
        return set()


def build_fill_plan(selected: list[dict[str, str]], cached: set[tuple[str, str]], indexed: set[tuple[str, str]]) -> list[dict[str, object]]:
    required: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for row in selected:
        collector = row.get("collector") or "route-views2"
        for side in ("before", "after"):
            ts = row[f"rib_{side}_timestamp"]
            url = row[f"rib_{side}_url"]
            required[(collector, ts, url)].add(row["candidate_period_id"])
    output = []
    for collector, ts, url in sorted(required):
        key = (collector, ts)
        already_cached = key in cached
        already_indexed = key in indexed
        output.append(
            {
                "collector": collector,
                "rib_timestamp": ts,
                "rib_url": url,
                "candidate_count": len(required[(collector, ts, url)]),
                "already_cached": str(already_cached),
                "already_indexed": str(already_indexed),
                "download_required": str(not already_cached),
            }
        )
    return output


def classify_from_index(candidate: dict[str, str], before: list[dict[str, str]], after: list[dict[str, str]]) -> dict[str, object]:
    duration = float(candidate.get("duration_minutes") or 0)
    if not duration and candidate.get("candidate_start") and candidate.get("candidate_end"):
        duration = (parse_required(candidate["candidate_end"]) - parse_required(candidate["candidate_start"])).total_seconds() / 60
    if duration < MIN_DURATION_MINUTES:
        status = INELIGIBLE_DURATION
        reason = "candidate duration is below the preserved 30-minute minimum"
    elif candidate.get("known_incident_overlap") == "True":
        status = KNOWN_INCIDENT_OVERLAP
        reason = "candidate overlaps a known incident or exclusion buffer"
    else:
        before_origins = sorted({row["origin_asn"] for row in before if row["origin_asn"]})
        after_origins = sorted({row["origin_asn"] for row in after if row["origin_asn"]})
        before_visible = bool(before)
        after_visible = bool(after)
        origin_stable = bool(before_origins) and before_origins == after_origins
        route_stable = before_visible and after_visible
        if route_stable and origin_stable:
            status = PRESCREEN_PASS
            reason = "indexed before/after RIB evidence confirms route visibility and stable origin"
        elif before_visible != after_visible:
            status = ROUTE_PRESENCE_UNSTABLE
            reason = "indexed RIB evidence exists on only one side of the candidate period"
        elif route_stable and not origin_stable:
            status = ORIGIN_UNSTABLE
            reason = "indexed RIB evidence exists before/after but origin set changed"
        elif not before_visible and not after_visible:
            status = NO_OBSERVABILITY
            reason = "complete indexed RIB evidence found no target ASN/prefix visibility"
        else:
            status = RIB_REVIEW
            reason = "indexed RIB evidence remains unresolved"
        return {
            "asn_visible_before": str(before_visible),
            "asn_visible_after": str(after_visible),
            "prefix_visible_before": str(bool(before)) if candidate.get("affected_prefix") else "NOT_APPLICABLE",
            "prefix_visible_after": str(bool(after)) if candidate.get("affected_prefix") else "NOT_APPLICABLE",
            "origin_before": json.dumps(before_origins, separators=(",", ":")),
            "origin_after": json.dumps(after_origins, separators=(",", ":")),
            "origin_stable": str(origin_stable),
            "route_presence_stable": str(route_stable),
            "prescreen_status": status,
            "reason": reason,
        }
    return {
        "asn_visible_before": "False",
        "asn_visible_after": "False",
        "prefix_visible_before": "False" if candidate.get("affected_prefix") else "NOT_APPLICABLE",
        "prefix_visible_after": "False" if candidate.get("affected_prefix") else "NOT_APPLICABLE",
        "origin_before": "[]",
        "origin_after": "[]",
        "origin_stable": "False",
        "route_presence_stable": "False",
        "prescreen_status": status,
        "reason": reason,
    }


def screen_candidate(conn: sqlite3.Connection, candidate: dict[str, str], indexed: set[tuple[str, str]]) -> tuple[dict[str, object], list[float], dict[str, int]]:
    collector = candidate.get("collector") or "route-views2"
    before_key = (collector, candidate["rib_before_timestamp"])
    after_key = (collector, candidate["rib_after_timestamp"])
    metrics = {"indexed_lookups": 0, "index_hits": 0, "cache_hits": 0}
    lookup_times: list[float] = []
    if before_key not in indexed or after_key not in indexed:
        return (
            {
                "asn_visible_before": "False",
                "asn_visible_after": "False",
                "prefix_visible_before": "False" if candidate.get("affected_prefix") else "NOT_APPLICABLE",
                "prefix_visible_after": "False" if candidate.get("affected_prefix") else "NOT_APPLICABLE",
                "origin_before": "[]",
                "origin_after": "[]",
                "origin_stable": "False",
                "route_presence_stable": "False",
                "prescreen_status": RIB_DATA_REQUIRED,
                "reason": "one or both required RIB snapshots are not yet available in the persistent index",
            },
            lookup_times,
            metrics,
        )
    states = {}
    for side in ("before", "after"):
        ts = candidate[f"rib_{side}_timestamp"]
        if candidate.get("affected_prefix"):
            rows, elapsed = lookup_prefix(conn, collector, ts, candidate["affected_prefix"])
        else:
            rows, elapsed = lookup_asn(conn, collector, ts, candidate["affected_asn"])
        states[side] = rows
        lookup_times.append(elapsed)
        metrics["indexed_lookups"] += 1
        metrics["index_hits"] += 1
        metrics["cache_hits"] += 1
    return classify_from_index(candidate, states["before"], states["after"]), lookup_times, metrics


def prescreen_rows(selected: list[dict[str, str]], conn: sqlite3.Connection, indexed: set[tuple[str, str]]) -> tuple[list[dict[str, object]], list[float], Counter[str]]:
    rows = []
    timings: list[float] = []
    perf_counts: Counter[str] = Counter()
    for candidate in selected:
        result, lookup_times, metrics = screen_candidate(conn, candidate, indexed)
        timings.extend(lookup_times)
        perf_counts.update(metrics)
        row = {
            "candidate_period_id": candidate["candidate_period_id"],
            "associated_incident_uid": candidate["associated_incident_uid"],
            "associated_category": candidate["associated_category"],
            "affected_asn": candidate["affected_asn"],
            "affected_prefix": candidate.get("affected_prefix", ""),
            "candidate_start": candidate["candidate_start"],
            "candidate_end": candidate["candidate_end"],
            "collector": candidate.get("collector") or "route-views2",
            "rib_before_timestamp": candidate["rib_before_timestamp"],
            "rib_after_timestamp": candidate["rib_after_timestamp"],
            **result,
        }
        rows.append(row)
    return rows, timings, perf_counts


def base_approved_pool() -> list[dict[str, object]]:
    pool_rows = {
        row["candidate_period_id"]: dict(row)
        for row in load_csv(EXISTING_APPROVED_POOL)
        if row.get("prescreen_status") == PRESCREEN_PASS
    }
    for row in load_csv(EXISTING_APPROVED_ESTIMATE):
        candidate_id = row.get("candidate_period_id", "")
        if candidate_id and candidate_id not in pool_rows:
            pool_rows[candidate_id] = {
                "candidate_period_id": candidate_id,
                "associated_incident_uid": row.get("associated_incident_uid", ""),
                "associated_category": row.get("associated_category", ""),
                "partition": "train",
                "affected_asn": row.get("affected_asn", ""),
                "affected_prefix": "",
                "candidate_start": row.get("candidate_start", ""),
                "candidate_end": row.get("candidate_end", ""),
                "duration_minutes": "",
                "collector": row.get("collector", "route-views2"),
                "prescreen_status": PRESCREEN_PASS,
                "selection_reason": "carried forward from existing approved update acquisition estimate",
            }
    return list(pool_rows.values())


def combine_approved(new_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    by_id = {row["candidate_period_id"]: row for row in base_approved_pool()}
    for row in new_rows:
        if row.get("prescreen_status") == PRESCREEN_PASS:
            enriched = dict(row)
            enriched["partition"] = "train"
            enriched["selection_reason"] = row.get("reason", "")
            by_id[row["candidate_period_id"]] = enriched
    return sorted(by_id.values(), key=lambda row: (row.get("associated_category", ""), row.get("affected_asn", ""), row["candidate_period_id"]))


def head_url(url: str, timeout_seconds: float = 10.0) -> tuple[bool, str, int]:
    request = Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            return 200 <= response.status < 400, str(response.status), int(response.headers.get("Content-Length") or 0)
    except HTTPError as error:
        return False, str(error.code), 0
    except URLError:
        return False, "", 0


def update_slots(row: dict[str, object]) -> list[datetime]:
    start = floor_to_15_minutes(parse_required(str(row["candidate_start"])) - timedelta(minutes=CONTEXT_BUFFER_MINUTES))
    end = ceil_to_15_minutes(parse_required(str(row["candidate_end"])) + timedelta(minutes=CONTEXT_BUFFER_MINUTES))
    return iter_update_slots(start, end)


def build_update_estimate(approved_rows: list[dict[str, object]], newly_passing_ids: set[str], check_remote_for_new: bool = True) -> list[dict[str, object]]:
    output = []
    previous = {row["candidate_period_id"]: row for row in load_csv(EXISTING_APPROVED_ESTIMATE)}
    for row in approved_rows:
        if not row.get("candidate_start") or not row.get("candidate_end"):
            continue
        slots = update_slots(row)
        check_remote = check_remote_for_new and row["candidate_period_id"] in newly_passing_ids
        available = 0
        total_bytes = 0
        if check_remote:
            for slot in slots:
                ok, _, size = head_url(routeviews_update_url(slot, str(row.get("collector") or "route-views2")))
                available += int(ok)
                total_bytes += size if ok else 0
        prior = previous.get(row["candidate_period_id"], {})
        output.append(
            {
                "candidate_period_id": row["candidate_period_id"],
                "associated_incident_uid": row.get("associated_incident_uid", ""),
                "associated_category": row.get("associated_category", ""),
                "affected_asn": row.get("affected_asn", ""),
                "collector": row.get("collector") or "route-views2",
                "candidate_start": row.get("candidate_start", ""),
                "candidate_end": row.get("candidate_end", ""),
                "collection_start": isoformat_z(slots[0]),
                "collection_end": isoformat_z(slots[-1]),
                "required_update_file_count": len(slots),
                "remote_availability_checked": str(check_remote or prior.get("remote_availability_checked") == "True"),
                "remote_available_file_count": available if check_remote else prior.get("remote_available_file_count", ""),
                "remote_availability_percent": round(100 * available / len(slots), 3) if check_remote and slots else prior.get("remote_availability_percent", ""),
                "estimated_compressed_bytes": total_bytes if check_remote else prior.get("estimated_compressed_bytes", ""),
                "estimated_compressed_mib": round(total_bytes / 1024 / 1024, 3) if check_remote else prior.get("estimated_compressed_mib", ""),
                "expected_5_minute_window_count": math.ceil((parse_required(str(row["candidate_end"])) - parse_required(str(row["candidate_start"]))).total_seconds() / 300),
                "notes": "UPDATE HEAD estimate only for newly approved rows; no UPDATE MRT files downloaded",
            }
        )
    return output


def year_distribution(rows: list[dict[str, object]]) -> dict[str, int]:
    values = Counter()
    for row in rows:
        try:
            values[str(parse_required(str(row["candidate_start"])).year)] += 1
        except Exception:
            values["UNKNOWN"] += 1
    return dict(values)


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round((pct / 100) * (len(ordered) - 1))))
    return ordered[index]


def write_performance(rows: list[dict[str, object]], timings: list[float], perf_counts: Counter[str], fill_plan: list[dict[str, object]], approved: list[dict[str, object]], start: float) -> None:
    status_counts = Counter(row["prescreen_status"] for row in rows)
    approved_by_class = Counter(row.get("associated_category", "") for row in approved)
    update_estimate = load_csv(UPDATE_ESTIMATE_V3)
    performance_rows = [
        {
            "metric": "selected_candidates",
            "value": len(rows),
            "notes": json.dumps(dict(Counter(row["associated_category"] for row in rows)), separators=(",", ":")),
        },
        {"metric": "indexed_lookups_performed", "value": perf_counts["indexed_lookups"], "notes": ""},
        {"metric": "cache_hits", "value": perf_counts["cache_hits"], "notes": ""},
        {"metric": "index_hits", "value": perf_counts["index_hits"], "notes": ""},
        {"metric": "rib_data_required_candidates", "value": status_counts[RIB_DATA_REQUIRED], "notes": ""},
        {"metric": "median_lookup_time_ms", "value": round(median(timings), 3) if timings else 0, "notes": ""},
        {"metric": "p95_lookup_time_ms", "value": round(percentile(timings, 95), 3), "notes": ""},
        {"metric": "total_screening_runtime_seconds", "value": round(time.perf_counter() - start, 3), "notes": ""},
        {"metric": "required_rib_snapshots", "value": len(fill_plan), "notes": ""},
        {"metric": "already_indexed_rib_snapshots", "value": sum(row["already_indexed"] == "True" for row in fill_plan), "notes": ""},
        {"metric": "rib_snapshots_requiring_cache_fill_or_index", "value": sum(row["already_indexed"] != "True" for row in fill_plan), "notes": ""},
        {"metric": "prescreen_status_counts", "value": len(rows), "notes": json.dumps(dict(status_counts), separators=(",", ":"))},
        {"metric": "approved_pool_by_class", "value": len(approved), "notes": json.dumps(dict(approved_by_class), separators=(",", ":"))},
        {"metric": "approved_unique_asns", "value": len({row.get("affected_asn", "") for row in approved if row.get("affected_asn")}), "notes": ""},
        {"metric": "approved_pool_year_distribution", "value": len(approved), "notes": json.dumps(year_distribution(approved), separators=(",", ":"))},
        {"metric": "approved_update_file_count", "value": sum(int(row.get("required_update_file_count") or 0) for row in update_estimate), "notes": ""},
        {"metric": "approved_expected_5_minute_windows", "value": sum(int(row.get("expected_5_minute_window_count") or 0) for row in update_estimate), "notes": ""},
        {"metric": "exclusion_buffer_minutes_preserved", "value": EXCLUSION_BUFFER_MINUTES, "notes": ""},
        {"metric": "minimum_duration_minutes_preserved", "value": MIN_DURATION_MINUTES, "notes": ""},
    ]
    write_csv(PERFORMANCE, performance_rows, ["metric", "value", "notes"])


def write_notebook() -> None:
    NOTEBOOK.parent.mkdir(parents=True, exist_ok=True)
    notebook = {
        "cells": [
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": [
                    "# TRAIN-only Normal RIB Prescreen: 50 Candidates\n",
                    "\n",
                    "Run the next 50 TRAIN-only candidates through the persistent RIB index. Missing RIB/index evidence is recorded as `RIB_DATA_REQUIRED`, not `NO_OBSERVABILITY`. No UPDATE MRT files are downloaded and no Normal labels are created.\n",
                ],
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": ["from bgp_incident_detection.normal_rib_batch50 import run\n", "summary = run(check_remote_for_new=False)\n", "summary\n"],
            },
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")


def run(check_remote_for_new: bool = True) -> dict[str, object]:
    start = time.perf_counter()
    queue_rows = load_csv(PRIORITY_QUEUE)
    selected = select_next_50(queue_rows)
    conn = sqlite3.connect(DB_PATH)
    cached = cached_ribs()
    indexed = indexed_ribs(conn)
    fill_plan = build_fill_plan(selected, cached, indexed)
    prescreened, timings, perf_counts = prescreen_rows(selected, conn, indexed)
    conn.close()
    newly_passing_ids = {row["candidate_period_id"] for row in prescreened if row["prescreen_status"] == PRESCREEN_PASS}
    approved = combine_approved(prescreened)
    update_estimate = build_update_estimate(approved, newly_passing_ids, check_remote_for_new=check_remote_for_new)
    write_csv(FILL_PLAN, fill_plan, ["collector", "rib_timestamp", "rib_url", "candidate_count", "already_cached", "already_indexed", "download_required"])
    write_csv(PRESCREEN_50, prescreened, ["candidate_period_id", "associated_incident_uid", "associated_category", "affected_asn", "affected_prefix", "candidate_start", "candidate_end", "collector", "rib_before_timestamp", "rib_after_timestamp", "asn_visible_before", "asn_visible_after", "prefix_visible_before", "prefix_visible_after", "origin_before", "origin_after", "origin_stable", "route_presence_stable", "prescreen_status", "reason"])
    write_csv(APPROVED_POOL_V2, approved, ["candidate_period_id", "associated_incident_uid", "associated_category", "partition", "affected_asn", "affected_prefix", "candidate_start", "candidate_end", "duration_minutes", "days_from_incident", "collector", "rib_visible_before", "rib_visible_after", "origin_stable", "route_presence_stable", "known_incident_overlap", "prescreen_status", "selection_reason", "rib_before_timestamp", "rib_after_timestamp", "prefix_visible_before", "prefix_visible_after", "source_provenance", "selection_year", "selection_duration_bucket", "selection_country"])
    write_csv(UPDATE_ESTIMATE_V3, update_estimate, ["candidate_period_id", "associated_incident_uid", "associated_category", "affected_asn", "collector", "candidate_start", "candidate_end", "collection_start", "collection_end", "required_update_file_count", "remote_availability_checked", "remote_available_file_count", "remote_availability_percent", "estimated_compressed_bytes", "estimated_compressed_mib", "expected_5_minute_window_count", "notes"])
    write_performance(prescreened, timings, perf_counts, fill_plan, approved, start)
    write_notebook()
    approved_asn_counts = Counter(row.get("affected_asn", "") for row in approved if row.get("affected_asn"))
    return {
        "selected_candidates": len(selected),
        "selected_class_distribution": dict(Counter(row["associated_category"] for row in selected)),
        "required_rib_snapshots": len(fill_plan),
        "already_indexed_rib_snapshots": sum(row["already_indexed"] == "True" for row in fill_plan),
        "rib_snapshots_requiring_cache_fill_or_index": sum(row["already_indexed"] != "True" for row in fill_plan),
        "prescreen_status_counts": dict(Counter(row["prescreen_status"] for row in prescreened)),
        "pass_by_class": dict(Counter(row["associated_category"] for row in prescreened if row["prescreen_status"] == PRESCREEN_PASS)),
        "approved_pool_by_class": dict(Counter(row.get("associated_category", "") for row in approved)),
        "approved_unique_asns": len(approved_asn_counts),
        "approved_max_candidates_per_asn": max(approved_asn_counts.values()) if approved_asn_counts else 0,
        "approved_update_file_count": sum(int(row.get("required_update_file_count") or 0) for row in update_estimate),
        "approved_expected_5_minute_windows": sum(int(row.get("expected_5_minute_window_count") or 0) for row in update_estimate),
        "median_lookup_ms": round(median(timings), 3) if timings else 0,
        "p95_lookup_ms": round(percentile(timings, 95), 3),
        "elapsed_seconds": round(time.perf_counter() - start, 3),
        "outputs": [str(FILL_PLAN), str(PRESCREEN_50), str(APPROVED_POOL_V2), str(UPDATE_ESTIMATE_V3), str(PERFORMANCE), str(NOTEBOOK)],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the next 50 TRAIN-only Normal RIB prescreen candidates using the persistent index")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--skip-remote-update-head", action="store_true")
    args = parser.parse_args()
    if not args.run:
        parser.error("choose --run")
    print(json.dumps(run(check_remote_for_new=not args.skip_remote_update_head), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
