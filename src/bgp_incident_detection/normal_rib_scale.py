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
    from bgp_incident_detection.mrt_parser import origin_asn_from_path
    from bgp_incident_detection.normal_rib_prescreen import COLLECTOR_SEQUENCE
    from bgp_incident_detection.normal_pool_scale import (
        CONTEXT_BUFFER_MINUTES,
        EXCLUSION_BUFFER_MINUTES,
        INELIGIBLE_DURATION,
        KNOWN_INCIDENT_OVERLAP,
        MIN_DURATION_MINUTES,
        NO_OBSERVABILITY,
        NORMAL_CANDIDATE_POOL,
        ORIGIN_UNSTABLE,
        PRESCREEN_PASS,
        REVIEW,
    )
    from bgp_incident_detection.rib_normal import RibState, compact_set, nearest_ribs, parse_rib_line, routeviews_rib_url, row_matches_target, top_paths, validate_bzip2
except ImportError:
    from src.bgp_incident_detection.audit import parse_utc, write_csv
    from src.bgp_incident_detection.mrt_acquisition import ceil_to_15_minutes, floor_to_15_minutes, iter_update_slots, routeviews_update_url
    from src.bgp_incident_detection.mrt_parser import origin_asn_from_path
    from src.bgp_incident_detection.normal_rib_prescreen import COLLECTOR_SEQUENCE
    from src.bgp_incident_detection.normal_pool_scale import (
        CONTEXT_BUFFER_MINUTES,
        EXCLUSION_BUFFER_MINUTES,
        INELIGIBLE_DURATION,
        KNOWN_INCIDENT_OVERLAP,
        MIN_DURATION_MINUTES,
        NO_OBSERVABILITY,
        NORMAL_CANDIDATE_POOL,
        OUTPUT_DIR as NORMAL_SCALE_DIR,
        ORIGIN_UNSTABLE,
        PRESCREEN_PASS,
        REVIEW,
    )
    from src.bgp_incident_detection.rib_normal import RibState, compact_set, nearest_ribs, parse_rib_line, routeviews_rib_url, row_matches_target, top_paths, validate_bzip2


CACHE_ROOT = Path("data/cache/routeviews_rib")
RIB_CACHE_INDEX = Path("data/normal_scale/rib_cache_index_v1.csv")
EXPANDED_RESULTS = Path("data/normal_scale/normal_rib_prescreen_expanded_v1.csv")
EXPANDED_SUMMARY = Path("data/normal_scale/normal_rib_prescreen_expanded_summary_v1.csv")
UPDATE_ESTIMATE_V2 = Path("data/normal_scale/normal_update_acquisition_estimate_v2.csv")
NOTEBOOK = Path("notebooks/20_normal_rib_prescreen_scale.ipynb")

ROUTE_PRESENCE_UNSTABLE = "ROUTE_PRESENCE_UNSTABLE"
RIB_REVIEW = "RIB_REVIEW"
TARGET_PASS_PER_CLASS = 10
DEFAULT_BATCH_SIZE = 25
DEFAULT_MAX_RIB_CANDIDATES_PER_ASN = 3
DEFAULT_MAX_COLLECTORS_PER_CANDIDATE = 2
RIB_SCAN_TIMEOUT_SECONDS = 6.0


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


def checksum(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def local_rib_path(collector: str, rib_timestamp: datetime) -> Path:
    return CACHE_ROOT / collector / f"{rib_timestamp.year}.{rib_timestamp.month:02d}" / f"rib.{rib_timestamp:%Y%m%d.%H%M}.bz2"


def cache_key(collector: str, rib_timestamp: datetime, source_url: str) -> str:
    return f"{collector}|{isoformat_z(rib_timestamp)}|{source_url}"


def load_cache_index() -> dict[str, dict[str, str]]:
    rows = load_csv(RIB_CACHE_INDEX)
    return {cache_key(row["collector"], parse_required(row["rib_timestamp"]), row["source_url"]): row for row in rows}


def write_cache_index(index: dict[str, dict[str, str]]) -> None:
    fields = ["collector", "rib_timestamp", "source_url", "local_path", "downloaded", "parsed", "file_size", "checksum", "last_used", "status"]
    write_csv(RIB_CACHE_INDEX, sorted(index.values(), key=lambda row: (row["collector"], row["rib_timestamp"])), fields)


def rib_url_for(collector: str, rib_timestamp: datetime) -> str:
    if collector == "route-views2":
        return routeviews_rib_url(rib_timestamp, collector)
    return f"https://archive.routeviews.org/{collector}/bgpdata/{rib_timestamp.year}.{rib_timestamp.month:02d}/RIBS/rib.{rib_timestamp:%Y%m%d.%H%M}.bz2"


def download_or_reuse_rib(collector: str, rib_timestamp: datetime, index: dict[str, dict[str, str]]) -> tuple[bool, Path, str, bool]:
    url = rib_url_for(collector, rib_timestamp)
    path = local_rib_path(collector, rib_timestamp)
    key = cache_key(collector, rib_timestamp, url)
    now = isoformat_z(datetime.now(timezone.utc))
    cached = path.exists() and path.stat().st_size > 0 and validate_bzip2(path)
    if cached:
        index[key] = {
            "collector": collector,
            "rib_timestamp": isoformat_z(rib_timestamp),
            "source_url": url,
            "local_path": str(path),
            "downloaded": "False",
            "parsed": "True",
            "file_size": str(path.stat().st_size),
            "checksum": checksum(path),
            "last_used": now,
            "status": "CACHED",
        }
        return True, path, "CACHED", True
    path.parent.mkdir(parents=True, exist_ok=True)
    request = Request(url, headers={"User-Agent": "bgp-incident-detection-pipeline/0.1"})
    try:
        with urlopen(request, timeout=240.0) as response:
            path.write_bytes(response.read())
        ok = path.exists() and path.stat().st_size > 0 and validate_bzip2(path)
        index[key] = {
            "collector": collector,
            "rib_timestamp": isoformat_z(rib_timestamp),
            "source_url": url,
            "local_path": str(path),
            "downloaded": "True",
            "parsed": str(ok),
            "file_size": str(path.stat().st_size if path.exists() else 0),
            "checksum": checksum(path) if ok else "",
            "last_used": now,
            "status": str(response.status) if ok else "INVALID_BZIP2",
        }
        return ok, path, index[key]["status"], False
    except (HTTPError, URLError) as error:
        index[key] = {
            "collector": collector,
            "rib_timestamp": isoformat_z(rib_timestamp),
            "source_url": url,
            "local_path": str(path),
            "downloaded": "False",
            "parsed": "False",
            "file_size": "0",
            "checksum": "",
            "last_used": now,
            "status": str(getattr(error, "code", "")) or str(error),
        }
        return False, path, index[key]["status"], False


def inspect_rib_quick(path: Path, affected_asn: str, affected_prefix: str) -> RibState:
    try:
        return inspect_rib_quick_mrtparse(path, affected_asn, affected_prefix)
    except Exception:
        state = RibState()
        state.scan_timed_out = True
        return state


def as_path_from_attributes(path_attributes: list[dict[str, object]]) -> str:
    values: list[str] = []
    for attr in path_attributes:
        attr_type = attr.get("type", {})
        if not isinstance(attr_type, dict) or "2" not in attr_type:
            continue
        for segment in attr.get("value", []):
            if isinstance(segment, dict):
                values.extend(str(value) for value in segment.get("value", []))
    return " ".join(values)


def inspect_rib_quick_mrtparse(path: Path, affected_asn: str, affected_prefix: str) -> RibState:
    import mrtparse

    state = RibState()
    peers: dict[int, dict[str, str]] = {}
    deadline = time.monotonic() + RIB_SCAN_TIMEOUT_SECONDS
    for record in mrtparse.Reader(str(path)):
        if time.monotonic() > deadline:
            state.scan_timed_out = True
            break
        data = record.data
        if "peer_entries" in data:
            peers = {
                index: {"peer_ip": str(peer.get("peer_ip", "")), "peer_asn": str(peer.get("peer_as", ""))}
                for index, peer in enumerate(data.get("peer_entries", []))
            }
            continue
        prefix = str(data.get("prefix", ""))
        if not prefix:
            continue
        if affected_prefix and prefix != affected_prefix:
            continue
        for entry in data.get("rib_entries", []):
            as_path = as_path_from_attributes(entry.get("path_attributes", []))
            origin = origin_asn_from_path(as_path)
            peer = peers.get(int(entry.get("peer_index", -1)), {})
            parsed = {
                "prefix": prefix,
                "peer_asn": peer.get("peer_asn", ""),
                "peer_ip": peer.get("peer_ip", ""),
                "as_path": as_path,
                "origin_asn": origin,
            }
            if not row_matches_target(parsed, affected_asn, affected_prefix):
                continue
            state.route_present = True
            state.matched_rows += 1
            state.prefixes.add(prefix)
            if origin:
                state.origins.add(origin)
            if as_path:
                state.paths[as_path] += 1
            if parsed["peer_asn"]:
                state.peer_asns.add(parsed["peer_asn"])
            if state.matched_rows >= 800:
                return state
    return state


def inspect_rib_quick_bgpdump(path: Path, affected_asn: str, affected_prefix: str) -> RibState:
    state = RibState()
    command = ["bgpdump", "-q", "-m", str(path)]
    grep_terms = [term for term in [affected_prefix, affected_asn] if term]
    process = subprocess.Popen(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if process.stdout is None:
        return state
    deadline = time.monotonic() + 18.0
    try:
        for line in process.stdout:
            if time.monotonic() > deadline:
                state.scan_timed_out = True
                break
            if grep_terms and not any(term in line for term in grep_terms):
                continue
            parsed = parse_rib_line(line)
            if parsed is None or not row_matches_target(parsed, affected_asn, affected_prefix):
                continue
            state.route_present = True
            state.matched_rows += 1
            state.prefixes.add(parsed["prefix"])
            if parsed["origin_asn"]:
                state.origins.add(parsed["origin_asn"])
            if parsed["as_path"]:
                state.paths[parsed["as_path"]] += 1
            if parsed["peer_asn"]:
                state.peer_asns.add(parsed["peer_asn"])
            if state.matched_rows >= 800:
                break
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5.0)
    return state


def duration_ok(row: dict[str, str]) -> bool:
    try:
        return float(row.get("duration_minutes") or 0) >= MIN_DURATION_MINUTES
    except ValueError:
        return False


def existing_pass_counts(pool_rows: list[dict[str, str]], expanded_rows: list[dict[str, str]]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for row in pool_rows:
        if row.get("prescreen_status") == PRESCREEN_PASS:
            counts[row["associated_category"]] += 1
    for row in expanded_rows:
        if row.get("prescreen_status") == PRESCREEN_PASS:
            counts[row["associated_category"]] += 1
    return counts


def prioritized_queue(pool_rows: list[dict[str, str]], expanded_rows: list[dict[str, str]], max_per_asn: int) -> list[dict[str, str]]:
    completed = {row["candidate_period_id"] for row in expanded_rows}
    counts_by_asn: Counter[str] = Counter()
    candidates: list[dict[str, str]] = []
    for row in pool_rows:
        if row.get("candidate_period_id") in completed:
            continue
        if row.get("prescreen_status") != REVIEW:
            continue
        if row.get("partition") != "train":
            continue
        if row.get("known_incident_overlap") == "True":
            continue
        if not duration_ok(row):
            continue
        if not row.get("affected_asn"):
            continue
        if counts_by_asn[row["affected_asn"]] >= max_per_asn:
            continue
        counts_by_asn[row["affected_asn"]] += 1
        candidates.append(row)
    by_category: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in candidates:
        by_category[row["associated_category"]].append(row)
    for category in by_category:
        by_category[category].sort(
            key=lambda row: (
                counts_by_asn[row["affected_asn"]],
                abs(int(float(row.get("days_from_incident") or 0))),
                row["affected_asn"],
                row["candidate_period_id"],
            )
        )
    output: list[dict[str, str]] = []
    while any(by_category.values()):
        for category in ("Outage", "Leak", "Hijack"):
            if by_category[category]:
                output.append(by_category[category].pop(0))
    return output


def nearest_rib_pair(start: datetime, end: datetime) -> tuple[datetime, datetime]:
    before, after, _ = nearest_ribs(start, end, "route-views2")
    return before, after


def classify_states(before: RibState, after: RibState, affected_prefix: str) -> tuple[str, str, bool, bool]:
    visible_before = before.route_present
    visible_after = after.route_present
    route_stable = visible_before and visible_after
    prefix_stable = True if not affected_prefix else affected_prefix in before.prefixes and affected_prefix in after.prefixes
    origin_stable = bool(before.origins) and before.origins == after.origins
    if route_stable and prefix_stable and origin_stable:
        return PRESCREEN_PASS, "before/after RIBs show route presence and stable origin", origin_stable, route_stable
    if visible_before != visible_after:
        return ROUTE_PRESENCE_UNSTABLE, "route present on only one side of candidate period", origin_stable, route_stable
    if route_stable and not origin_stable:
        return ORIGIN_UNSTABLE, "route is visible but origin set is missing or changed", origin_stable, route_stable
    if before.scan_timed_out or after.scan_timed_out:
        return RIB_REVIEW, "RIB scan timed out", origin_stable, route_stable
    return NO_OBSERVABILITY, "no collector produced adequate before/after observability", origin_stable, route_stable


def screen_candidate(row: dict[str, str], index: dict[str, dict[str, str]], max_collectors: int = DEFAULT_MAX_COLLECTORS_PER_CANDIDATE) -> dict[str, object]:
    if not duration_ok(row):
        return base_result(row, "", "", "", "", False, False, RibState(), RibState(), INELIGIBLE_DURATION, "duration below 30 minutes")
    if row.get("known_incident_overlap") == "True":
        return base_result(row, "", "", "", "", False, False, RibState(), RibState(), KNOWN_INCIDENT_OVERLAP, "known incident overlap")
    start = parse_required(row["candidate_start"])
    end = parse_required(row["candidate_end"])
    before_ts, after_ts = nearest_rib_pair(start, end)
    best_reason = "no collector checked"
    for collector in COLLECTOR_SEQUENCE[:max_collectors]:
        before_ok, before_path, before_status, before_cached = download_or_reuse_rib(collector, before_ts, index)
        after_ok, after_path, after_status, after_cached = download_or_reuse_rib(collector, after_ts, index)
        if not before_ok or not after_ok:
            best_reason = f"{collector}: before_status={before_status}; after_status={after_status}"
            continue
        before_state = inspect_rib_quick(before_path, row["affected_asn"], row.get("affected_prefix", ""))
        after_state = inspect_rib_quick(after_path, row["affected_asn"], row.get("affected_prefix", ""))
        status, reason, origin_stable, route_stable = classify_states(before_state, after_state, row.get("affected_prefix", ""))
        reason = f"{collector}: {reason}"
        if status == PRESCREEN_PASS:
            return base_result(row, collector, isoformat_z(before_ts), isoformat_z(after_ts), str(before_cached), str(after_cached), origin_stable, route_stable, before_state, after_state, status, reason)
        best_reason = reason
        if status in {ORIGIN_UNSTABLE, ROUTE_PRESENCE_UNSTABLE, RIB_REVIEW}:
            return base_result(row, collector, isoformat_z(before_ts), isoformat_z(after_ts), str(before_cached), str(after_cached), origin_stable, route_stable, before_state, after_state, status, reason)
    return base_result(row, "", isoformat_z(before_ts), isoformat_z(after_ts), "False", "False", False, False, RibState(), RibState(), NO_OBSERVABILITY, best_reason)


def base_result(
    row: dict[str, str],
    collector: str,
    before_ts: str,
    after_ts: str,
    before_cached: str,
    after_cached: str,
    origin_stable: bool,
    route_stable: bool,
    before_state: RibState,
    after_state: RibState,
    status: str,
    reason: str,
) -> dict[str, object]:
    affected_prefix = row.get("affected_prefix", "")
    return {
        "candidate_period_id": row["candidate_period_id"],
        "associated_incident_uid": row["associated_incident_uid"],
        "associated_category": row["associated_category"],
        "affected_asn": row["affected_asn"],
        "affected_prefix": affected_prefix,
        "candidate_start": row["candidate_start"],
        "candidate_end": row["candidate_end"],
        "collector": collector,
        "rib_before_timestamp": before_ts,
        "rib_after_timestamp": after_ts,
        "rib_before_cached": before_cached,
        "rib_after_cached": after_cached,
        "asn_visible_before": str(before_state.route_present),
        "asn_visible_after": str(after_state.route_present),
        "prefix_visible_before": str(affected_prefix in before_state.prefixes) if affected_prefix else "NOT_APPLICABLE",
        "prefix_visible_after": str(affected_prefix in after_state.prefixes) if affected_prefix else "NOT_APPLICABLE",
        "origin_before": compact_set(before_state.origins),
        "origin_after": compact_set(after_state.origins),
        "origin_stable": str(origin_stable),
        "route_presence_stable": str(route_stable),
        "prescreen_status": status,
        "reason": reason,
    }


RESULT_FIELDS = [
    "candidate_period_id",
    "associated_incident_uid",
    "associated_category",
    "affected_asn",
    "affected_prefix",
    "candidate_start",
    "candidate_end",
    "collector",
    "rib_before_timestamp",
    "rib_after_timestamp",
    "rib_before_cached",
    "rib_after_cached",
    "asn_visible_before",
    "asn_visible_after",
    "prefix_visible_before",
    "prefix_visible_after",
    "origin_before",
    "origin_after",
    "origin_stable",
    "route_presence_stable",
    "prescreen_status",
    "reason",
]


def summary_rows(rows: list[dict[str, str]]) -> list[dict[str, object]]:
    output = []
    for category in ("Hijack", "Leak", "Outage"):
        cat_rows = [row for row in rows if row["associated_category"] == category]
        counts = Counter(row["prescreen_status"] for row in cat_rows)
        pass_count = counts[PRESCREEN_PASS]
        dominant = Counter(row["affected_asn"] for row in cat_rows if row["prescreen_status"] == PRESCREEN_PASS).most_common(1)
        output.append(
            {
                "associated_category": category,
                "candidates_screened": len(cat_rows),
                "unique_asns": len({row["affected_asn"] for row in cat_rows if row["affected_asn"]}),
                "RIB_PRESCREEN_PASS": pass_count,
                "NO_OBSERVABILITY": counts[NO_OBSERVABILITY],
                "ORIGIN_UNSTABLE": counts[ORIGIN_UNSTABLE],
                "ROUTE_PRESENCE_UNSTABLE": counts[ROUTE_PRESENCE_UNSTABLE],
                "RIB_REVIEW": counts[RIB_REVIEW],
                "other_failures": len(cat_rows) - pass_count - counts[NO_OBSERVABILITY] - counts[ORIGIN_UNSTABLE] - counts[ROUTE_PRESENCE_UNSTABLE] - counts[RIB_REVIEW],
                "pass_percentage": round(100 * pass_count / len(cat_rows), 3) if cat_rows else 0,
                "dominant_pass_asn": dominant[0][0] if dominant else "",
                "dominant_pass_asn_count": dominant[0][1] if dominant else 0,
                "dominance_review": "REVIEW" if dominant and pass_count and dominant[0][1] / pass_count > 0.5 else "PASS",
            }
        )
    return output


def update_slots(row: dict[str, str]) -> list[datetime]:
    start = floor_to_15_minutes(parse_required(row["candidate_start"]) - timedelta(minutes=CONTEXT_BUFFER_MINUTES))
    end = ceil_to_15_minutes(parse_required(row["candidate_end"]) + timedelta(minutes=CONTEXT_BUFFER_MINUTES))
    return iter_update_slots(start, end)


def head_url(url: str, timeout_seconds: float = 10.0) -> tuple[bool, str, int]:
    request = Request(url, method="HEAD", headers={"User-Agent": "bgp-incident-detection-pipeline/0.1"})
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            return 200 <= response.status < 400, str(response.status), int(response.headers.get("Content-Length") or 0)
    except HTTPError as error:
        return False, str(error.code), 0
    except URLError:
        return False, "", 0


def acquisition_estimate_rows(pool_rows: list[dict[str, str]], expanded_rows: list[dict[str, str]], verify_heads: bool) -> list[dict[str, object]]:
    by_id: dict[str, dict[str, str]] = {}
    for row in pool_rows:
        if row.get("prescreen_status") == PRESCREEN_PASS:
            by_id[row["candidate_period_id"]] = row
    for row in expanded_rows:
        if row.get("prescreen_status") == PRESCREEN_PASS:
            by_id[row["candidate_period_id"]] = row
    output = []
    for row in sorted(by_id.values(), key=lambda value: value["candidate_period_id"]):
        slots = update_slots(row)
        available = 0
        total_bytes = 0
        for slot in slots:
            if verify_heads:
                ok, _, size = head_url(routeviews_update_url(slot, row.get("collector") or "route-views2"))
                available += int(ok)
                total_bytes += size if ok else 0
        output.append(
            {
                "candidate_period_id": row["candidate_period_id"],
                "associated_incident_uid": row["associated_incident_uid"],
                "associated_category": row["associated_category"],
                "affected_asn": row["affected_asn"],
                "collector": row.get("collector") or "route-views2",
                "candidate_start": row["candidate_start"],
                "candidate_end": row["candidate_end"],
                "collection_start": isoformat_z(slots[0]),
                "collection_end": isoformat_z(slots[-1]),
                "required_update_file_count": len(slots),
                "remote_availability_checked": str(verify_heads),
                "remote_available_file_count": available if verify_heads else "",
                "remote_availability_percent": round(100 * available / len(slots), 3) if verify_heads else "",
                "estimated_compressed_bytes": total_bytes if verify_heads else "",
                "estimated_compressed_mib": round(total_bytes / 1024 / 1024, 3) if verify_heads else "",
                "expected_5_minute_window_count": math.ceil((parse_required(row["candidate_end"]) - parse_required(row["candidate_start"])).total_seconds() / 300),
                "notes": "UPDATE HEAD estimate only; no UPDATE MRT files downloaded",
            }
        )
    return output


def write_notebook() -> None:
    NOTEBOOK.parent.mkdir(parents=True, exist_ok=True)
    nb = {
        "cells": [
            {"cell_type": "markdown", "metadata": {}, "source": ["# Normal RIB Prescreen Scale\n", "\n", "Batched, resumable TRAIN-only RIB pre-screen expansion. No UPDATE downloads and no Normal labels.\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["from bgp_incident_detection.normal_rib_scale import run\n", "summary = run(batch_size=25, max_rib_candidates_per_asn=3, verify_update_heads=True)\n", "summary\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["import pandas as pd\n", "display(pd.read_csv('data/normal_scale/normal_rib_prescreen_expanded_summary_v1.csv'))\n", "display(pd.read_csv('data/normal_scale/normal_update_acquisition_estimate_v2.csv').head())\n"]},
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(nb, indent=2) + "\n", encoding="utf-8")


def stop_condition(pool_rows: list[dict[str, str]], expanded_rows: list[dict[str, str]], queue: list[dict[str, str]]) -> str:
    counts = existing_pass_counts(pool_rows, expanded_rows)
    if all(counts[category] >= TARGET_PASS_PER_CLASS for category in ("Hijack", "Leak", "Outage")):
        return "TARGET_PASS_COUNTS_REACHED"
    if not queue:
        return "PRIORITIZED_QUEUE_EXHAUSTED"
    return "BATCH_LIMIT_REACHED"


def run(
    batch_size: int = DEFAULT_BATCH_SIZE,
    max_rib_candidates_per_asn: int = DEFAULT_MAX_RIB_CANDIDATES_PER_ASN,
    max_collectors_per_candidate: int = DEFAULT_MAX_COLLECTORS_PER_CANDIDATE,
    force: bool = False,
    verify_update_heads: bool = True,
) -> dict[str, object]:
    pool_rows = load_csv(NORMAL_CANDIDATE_POOL)
    existing_results = [] if force else load_csv(EXPANDED_RESULTS)
    queue_before_cap = [
        row for row in pool_rows
        if row.get("prescreen_status") == REVIEW
        and row.get("partition") == "train"
        and row.get("known_incident_overlap") == "False"
        and duration_ok(row)
        and row.get("affected_asn")
    ]
    queue = prioritized_queue(pool_rows, existing_results, max_rib_candidates_per_asn)
    batch = queue[:batch_size]
    index = load_cache_index()
    new_results: list[dict[str, object]] = []
    for row in batch:
        new_results.append(screen_candidate(row, index, max_collectors=max_collectors_per_candidate))
        write_csv(EXPANDED_RESULTS, existing_results + new_results, RESULT_FIELDS)
        write_cache_index(index)
    all_results = existing_results + new_results
    write_csv(EXPANDED_RESULTS, all_results, RESULT_FIELDS)
    write_cache_index(index)
    write_csv(
        EXPANDED_SUMMARY,
        summary_rows([dict(row) for row in all_results]),
        [
            "associated_category",
            "candidates_screened",
            "unique_asns",
            "RIB_PRESCREEN_PASS",
            "NO_OBSERVABILITY",
            "ORIGIN_UNSTABLE",
            "ROUTE_PRESENCE_UNSTABLE",
            "RIB_REVIEW",
            "other_failures",
            "pass_percentage",
            "dominant_pass_asn",
            "dominant_pass_asn_count",
            "dominance_review",
        ],
    )
    estimate = acquisition_estimate_rows(pool_rows, [dict(row) for row in all_results], verify_update_heads)
    write_csv(
        UPDATE_ESTIMATE_V2,
        estimate,
        [
            "candidate_period_id",
            "associated_incident_uid",
            "associated_category",
            "affected_asn",
            "collector",
            "candidate_start",
            "candidate_end",
            "collection_start",
            "collection_end",
            "required_update_file_count",
            "remote_availability_checked",
            "remote_available_file_count",
            "remote_availability_percent",
            "estimated_compressed_bytes",
            "estimated_compressed_mib",
            "expected_5_minute_window_count",
            "notes",
        ],
    )
    write_notebook()
    pass_counts = existing_pass_counts(pool_rows, [dict(row) for row in all_results])
    statuses = Counter(row["prescreen_status"] for row in all_results)
    return {
        "queue_before_cap": len(queue_before_cap),
        "queue_after_cap_and_resume_filter": len(queue),
        "batch_size": batch_size,
        "max_collectors_per_candidate": max_collectors_per_candidate,
        "screened_this_run": len(new_results),
        "screened_total": len(all_results),
        "status_counts_total": dict(statuses),
        "available_rib_pass_counts_including_prior_pool": dict(pass_counts),
        "stop_condition": stop_condition(pool_rows, [dict(row) for row in all_results], prioritized_queue(pool_rows, [dict(row) for row in all_results], max_rib_candidates_per_asn)),
        "update_estimate_rows": len(estimate),
        "estimated_update_files": sum(int(row["required_update_file_count"]) for row in estimate),
        "estimated_5_minute_windows": sum(int(row["expected_5_minute_window_count"]) for row in estimate),
        "outputs": [str(EXPANDED_RESULTS), str(EXPANDED_SUMMARY), str(UPDATE_ESTIMATE_V2), str(RIB_CACHE_INDEX), str(NOTEBOOK)],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Expand TRAIN-only Normal RIB pre-screen using resumable cache")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--max-rib-candidates-per-asn", type=int, default=DEFAULT_MAX_RIB_CANDIDATES_PER_ASN)
    parser.add_argument("--max-collectors-per-candidate", type=int, default=DEFAULT_MAX_COLLECTORS_PER_CANDIDATE)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--skip-update-heads", action="store_true")
    args = parser.parse_args()
    if not args.run:
        parser.error("choose --run")
    print(
        json.dumps(
            run(
                batch_size=args.batch_size,
                max_rib_candidates_per_asn=args.max_rib_candidates_per_asn,
                max_collectors_per_candidate=args.max_collectors_per_candidate,
                force=args.force,
                verify_update_heads=not args.skip_update_heads,
            ),
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
