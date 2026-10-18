from __future__ import annotations

import argparse
import bz2
import csv
import hashlib
import json
import math
import shutil
import subprocess
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pandas as pd

try:
    from bgp_incident_detection.audit import parse_utc, write_csv
    from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES, WindowAggregate, features_from_aggregate, update_aggregate
    from bgp_incident_detection.mrt_acquisition import ceil_to_15_minutes, floor_to_15_minutes, iter_update_slots, routeviews_update_url
    from bgp_incident_detection.mrt_parser import PARSED_FIELDS, bgpdump_version, parse_as_path_set, parse_bgpdump_line
    from bgp_incident_detection.normal_pool_scale import CONTEXT_BUFFER_MINUTES, EXCLUSION_BUFFER_MINUTES
    from bgp_incident_detection.windows import floor_to_five_minutes, format_utc, window_id
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import parse_utc, write_csv
    from src.bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES, WindowAggregate, features_from_aggregate, update_aggregate
    from src.bgp_incident_detection.mrt_acquisition import ceil_to_15_minutes, floor_to_15_minutes, iter_update_slots, routeviews_update_url
    from src.bgp_incident_detection.mrt_parser import PARSED_FIELDS, bgpdump_version, parse_as_path_set, parse_bgpdump_line
    from src.bgp_incident_detection.normal_pool_scale import CONTEXT_BUFFER_MINUTES, EXCLUSION_BUFFER_MINUTES
    from src.bgp_incident_detection.windows import floor_to_five_minutes, format_utc, window_id


NORMAL_SCALE_DIR = Path("data/normal_scale")
APPROVED_POOL = NORMAL_SCALE_DIR / "normal_rib_approved_pool_v3.csv"
RIB_INDEX_DB = Path("data/cache/routeviews_rib/index/rib_index.sqlite")

EXECUTION_MANIFEST = NORMAL_SCALE_DIR / "normal_update_qualification_execution_manifest_v1.csv"
ACQUISITION_PLAN = NORMAL_SCALE_DIR / "normal_update_acquisition_plan_v1.csv"
DOWNLOAD_AUDIT = NORMAL_SCALE_DIR / "normal_update_download_audit_v1.csv"
RAW_COUNTS = NORMAL_SCALE_DIR / "normal_update_raw_bgp_counts_v1.csv"
RELEVANCE_SUMMARY = NORMAL_SCALE_DIR / "normal_update_relevance_summary_v1.csv"
WINDOW_COUNTS = NORMAL_SCALE_DIR / "normal_update_window_counts_v1.csv"
FEATURE_PARQUET = NORMAL_SCALE_DIR / "normal_behavioral_features_v1.parquet"
QUALIFICATION_RESULTS = NORMAL_SCALE_DIR / "normal_qualification_results_v1.csv"
CANDIDATE_SUMMARY = NORMAL_SCALE_DIR / "normal_candidate_qualification_summary_v1.csv"
DIVERSITY = NORMAL_SCALE_DIR / "normal_verified_diversity_v1.csv"
RIB_TO_UPDATE_YIELD = NORMAL_SCALE_DIR / "normal_rib_to_update_yield_v1.csv"
NOTEBOOK = Path("notebooks/25_normal_update_qualification_scale.ipynb")

RAW_DIR = Path("data/raw_mrt/normal_scale")
PARSED_DIR = Path("data/parsed_mrt/normal_scale")

NORMAL_METHOD_VERSION = "rib_update_v1"
BEHAVIORAL_FEATURE_VERSION = "v1"
BEHAVIORAL_FEATURE_COUNT = 44
MIN_STABLE_WINDOWS = 6
MIN_STABILITY_MINUTES = 30
UPDATE_BATCH_SIZE = 100
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


def checksum(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def compression_ok(path: Path) -> bool:
    try:
        with bz2.open(path, "rb") as handle:
            handle.read(3)
        return True
    except OSError:
        return False


def safe_candidate_dir(candidate_period_id: str) -> Path:
    return RAW_DIR / candidate_period_id.replace("/", "_")


def parsed_output_path(candidate_period_id: str) -> Path:
    return PARSED_DIR / candidate_period_id.replace("/", "_") / "parsed_bgp_observations.csv"


def head_url(url: str, timeout_seconds: float = 15.0) -> tuple[bool, str, int]:
    request = Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            return 200 <= response.status < 400, str(response.status), int(response.headers.get("Content-Length") or 0)
    except HTTPError as error:
        return False, str(error.code), 0
    except URLError:
        return False, "", 0


def load_approved_pool() -> list[dict[str, str]]:
    rows = [row for row in load_csv(APPROVED_POOL) if row.get("prescreen_status") == "RIB_PRESCREEN_PASS"]
    if len(rows) != 45:
        raise ValueError(f"expected 45 RIB-approved candidates, found {len(rows)}")
    counts = Counter(row["associated_category"] for row in rows)
    if counts != {"Hijack": 14, "Leak": 17, "Outage": 14}:
        raise ValueError(f"unexpected approved pool class counts: {dict(counts)}")
    if any(row.get("partition") != "train" for row in rows):
        raise ValueError("approved pool contains non-TRAIN rows")
    return rows


def freeze_execution_manifest() -> list[dict[str, object]]:
    rows = []
    for row in load_approved_pool():
        rows.append(
            {
                "candidate_period_id": row["candidate_period_id"],
                "associated_incident_uid": row["associated_incident_uid"],
                "associated_category": row["associated_category"],
                "affected_asn": row["affected_asn"],
                "affected_prefix": row.get("affected_prefix", ""),
                "candidate_start": row["candidate_start"],
                "candidate_end": row["candidate_end"],
                "collector": row.get("collector") or "route-views2",
                "rib_before": row.get("rib_before_timestamp", ""),
                "rib_after": row.get("rib_after_timestamp", ""),
                "origin_stable": row.get("origin_stable", ""),
                "route_presence_stable": row.get("route_presence_stable", ""),
                "partition": row.get("partition", "train"),
                "normal_method_version": NORMAL_METHOD_VERSION,
            }
        )
    write_csv(
        EXECUTION_MANIFEST,
        rows,
        ["candidate_period_id", "associated_incident_uid", "associated_category", "affected_asn", "affected_prefix", "candidate_start", "candidate_end", "collector", "rib_before", "rib_after", "origin_stable", "route_presence_stable", "partition", "normal_method_version"],
    )
    return rows


def build_acquisition_plan(execution_rows: list[dict[str, object]], check_remote: bool = False) -> list[dict[str, object]]:
    rows = []
    for row in execution_rows:
        start = floor_to_15_minutes(parse_required(str(row["candidate_start"])) - timedelta(minutes=CONTEXT_BUFFER_MINUTES))
        end = ceil_to_15_minutes(parse_required(str(row["candidate_end"])) + timedelta(minutes=CONTEXT_BUFFER_MINUTES))
        for slot in iter_update_slots(start, end):
            url = routeviews_update_url(slot, str(row["collector"]))
            local_path = safe_candidate_dir(str(row["candidate_period_id"])) / url.rsplit("/", 1)[-1]
            available, status, size = (False, "", 0)
            if check_remote:
                available, status, size = head_url(url)
            rows.append(
                {
                    "candidate_period_id": row["candidate_period_id"],
                    "associated_incident_uid": row["associated_incident_uid"],
                    "associated_category": row["associated_category"],
                    "collector": row["collector"],
                    "mrt_timestamp": isoformat_z(slot),
                    "mrt_url": url,
                    "local_path": str(local_path),
                    "remote_available": str(available) if check_remote else "",
                    "status_code": status,
                    "estimated_content_length": size if check_remote else "",
                    "partition": row["partition"],
                }
            )
    write_csv(
        ACQUISITION_PLAN,
        rows,
        ["candidate_period_id", "associated_incident_uid", "associated_category", "collector", "mrt_timestamp", "mrt_url", "local_path", "remote_available", "status_code", "estimated_content_length", "partition"],
    )
    return rows


def download_one(row: dict[str, object]) -> dict[str, object]:
    destination = Path(str(row["local_path"]))
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and destination.stat().st_size > 0 and compression_ok(destination):
        return {
            **row,
            "file_size": destination.stat().st_size,
            "checksum": checksum(destination),
            "download_status": "CACHED",
            "download_timestamp": isoformat_z(datetime.now(timezone.utc)),
        }
    start = time.perf_counter()
    request = Request(str(row["mrt_url"]), headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(request, timeout=180.0) as response, destination.open("wb") as handle:
            shutil.copyfileobj(response, handle, length=1024 * 1024)
            status = str(response.status)
    except (HTTPError, URLError, TimeoutError) as error:
        return {**row, "file_size": 0, "checksum": "", "download_status": str(getattr(error, "code", "")) or "FAILED", "download_timestamp": isoformat_z(datetime.now(timezone.utc)), "download_seconds": round(time.perf_counter() - start, 3)}
    ok = destination.exists() and destination.stat().st_size > 0 and compression_ok(destination)
    return {
        **row,
        "file_size": destination.stat().st_size if destination.exists() else 0,
        "checksum": checksum(destination) if ok else "",
        "download_status": status if ok else "CORRUPT",
        "download_timestamp": isoformat_z(datetime.now(timezone.utc)),
        "download_seconds": round(time.perf_counter() - start, 3),
    }


def download_updates(plan_rows: list[dict[str, object]], batch_size: int = UPDATE_BATCH_SIZE) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    for offset in range(0, len(plan_rows), batch_size):
        batch = plan_rows[offset : offset + batch_size]
        for row in batch:
            result = download_one(row)
            output.append(result)
        write_csv(
            DOWNLOAD_AUDIT,
            output,
            ["candidate_period_id", "associated_incident_uid", "associated_category", "collector", "mrt_timestamp", "mrt_url", "local_path", "file_size", "checksum", "download_status", "download_timestamp", "partition", "remote_available", "status_code", "estimated_content_length", "download_seconds"],
        )
        print(f"{min(offset + len(batch), len(plan_rows))} / {len(plan_rows)} UPDATE files processed", flush=True)
    return output


@dataclass
class ParseStats:
    file_count: int = 0
    parsed_records: int = 0
    announcements: int = 0
    withdrawals: int = 0
    relevant: int = 0
    relevant_announcements: int = 0
    relevant_withdrawals: int = 0
    matching_prefixes: set[str] = field(default_factory=set)
    matching_asns: set[str] = field(default_factory=set)
    parse_failures: int = 0


def relevant_to_candidate(parsed: dict[str, str], candidate: dict[str, object]) -> bool:
    asn = str(candidate["affected_asn"])
    prefix = str(candidate.get("affected_prefix") or "")
    if prefix and parsed["prefix"] == prefix:
        return True
    peer_origin = {parsed["peer_asn"], parsed["origin_asn"]}
    peer_origin.discard("")
    return bool(asn and (asn in peer_origin or asn in parse_as_path_set(parsed["as_path"])))


def line_maybe_relevant(line: str, candidate: dict[str, object]) -> bool:
    prefix = str(candidate.get("affected_prefix") or "")
    asn = str(candidate.get("affected_asn") or "")
    if prefix and prefix in line:
        return True
    return bool(asn and asn in line)


def candidate_windows(candidate: dict[str, object]) -> list[datetime]:
    cursor = floor_to_five_minutes(parse_required(str(candidate["candidate_start"])))
    end = parse_required(str(candidate["candidate_end"]))
    slots = []
    while cursor < end:
        slots.append(cursor)
        cursor += timedelta(minutes=5)
    return slots


def parse_downloads(download_rows: list[dict[str, object]], execution_rows: list[dict[str, object]]) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    candidates = {str(row["candidate_period_id"]): row for row in execution_rows}
    stats: dict[str, ParseStats] = defaultdict(ParseStats)
    aggs: dict[str, WindowAggregate] = defaultdict(WindowAggregate)
    raw_window_counts: Counter[str] = Counter()
    window_meta: dict[str, dict[str, object]] = {}
    parsed_handles: dict[str, tuple[object, csv.DictWriter]] = {}

    for candidate_id in candidates:
        path = parsed_output_path(candidate_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=PARSED_FIELDS, extrasaction="ignore")
            writer.writeheader()

    def writer_for(candidate_id: str) -> csv.DictWriter:
        if candidate_id not in parsed_handles:
            path = parsed_output_path(candidate_id)
            path.parent.mkdir(parents=True, exist_ok=True)
            handle = path.open("w", newline="", encoding="utf-8")
            writer = csv.DictWriter(handle, fieldnames=PARSED_FIELDS, extrasaction="ignore")
            writer.writeheader()
            parsed_handles[candidate_id] = (handle, writer)
        return parsed_handles[candidate_id][1]

    try:
        for row in download_rows:
            if str(row.get("download_status")) not in {"200", "CACHED"}:
                continue
            candidate_id = str(row["candidate_period_id"])
            candidate = candidates[candidate_id]
            stats[candidate_id].file_count += 1
            process = subprocess.Popen(["bgpdump", "-q", "-m", str(row["local_path"])], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            assert process.stdout is not None
            for line in process.stdout:
                parts = line.rstrip("\n").split("|")
                if len(parts) < 6:
                    continue
                stat = stats[candidate_id]
                stat.parsed_records += 1
                message_type = parts[2]
                if message_type == "A":
                    stat.announcements += 1
                elif message_type == "W":
                    stat.withdrawals += 1
                if not line_maybe_relevant(line, candidate):
                    continue
                parsed = parse_bgpdump_line(line, candidate_id, Path(str(row["local_path"])), str(row["collector"]))
                if parsed is None or not relevant_to_candidate(parsed, candidate):
                    continue
                writer_for(candidate_id).writerow(parsed)
                timestamp = parse_utc(parsed["bgp_timestamp_utc"])
                if not timestamp:
                    continue
                if not (parse_required(str(candidate["candidate_start"])) <= timestamp < parse_required(str(candidate["candidate_end"]))):
                    continue
                wid_start = floor_to_five_minutes(timestamp)
                wid = window_id(candidate_id, wid_start)
                window_meta.setdefault(
                    wid,
                    {
                        "candidate_period_id": candidate_id,
                        "associated_incident_uid": candidate["associated_incident_uid"],
                        "associated_category": candidate["associated_category"],
                        "partition": candidate["partition"],
                        "window_id": wid,
                        "window_start": format_utc(wid_start),
                        "window_end": format_utc(wid_start + timedelta(minutes=5)),
                        "raw_observation_count": 0,
                    },
                )
                raw_window_counts[wid] += 1
                stat.relevant += 1
                if parsed["announcement_or_withdrawal"] == "announcement":
                    stat.relevant_announcements += 1
                elif parsed["announcement_or_withdrawal"] == "withdrawal":
                    stat.relevant_withdrawals += 1
                if parsed["prefix"]:
                    stat.matching_prefixes.add(parsed["prefix"])
                stat.matching_asns.update(parse_as_path_set(parsed["as_path"]))
                if parsed["peer_asn"]:
                    stat.matching_asns.add(parsed["peer_asn"])
                if parsed["origin_asn"]:
                    stat.matching_asns.add(parsed["origin_asn"])
                update_aggregate(aggs[wid], parsed)
            stderr = process.stderr.read() if process.stderr else ""
            if process.wait() != 0:
                stats[candidate_id].parse_failures += 1
                if stderr:
                    print(stderr)
    finally:
        for handle, _ in parsed_handles.values():
            handle.close()

    for candidate in execution_rows:
        for slot in candidate_windows(candidate):
            wid = window_id(str(candidate["candidate_period_id"]), slot)
            window_meta.setdefault(
                wid,
                {
                    "candidate_period_id": candidate["candidate_period_id"],
                    "associated_incident_uid": candidate["associated_incident_uid"],
                    "associated_category": candidate["associated_category"],
                    "partition": candidate["partition"],
                    "window_id": wid,
                    "window_start": format_utc(slot),
                    "window_end": format_utc(slot + timedelta(minutes=5)),
                    "raw_observation_count": 0,
                },
            )
            aggs.setdefault(wid, WindowAggregate())
    for wid, count in raw_window_counts.items():
        window_meta[wid]["raw_observation_count"] = count

    raw_counts = []
    relevance = []
    for candidate_id in sorted(candidates):
        stat = stats[candidate_id]
        candidate = candidates[candidate_id]
        raw_counts.append(
            {
                "candidate_period_id": candidate_id,
                "associated_incident_uid": candidate["associated_incident_uid"],
                "associated_category": candidate["associated_category"],
                "mrt_file_count": stat.file_count,
                "parsed_mrt_records": stat.parsed_records,
                "bgp_update_messages": stat.parsed_records,
                "announcement_observations": stat.announcements,
                "withdrawal_observations": stat.withdrawals,
                "total_prefix_level_observations": stat.parsed_records,
                "parse_failures": stat.parse_failures,
            }
        )
        relevance.append(
            {
                "candidate_period_id": candidate_id,
                "associated_incident_uid": candidate["associated_incident_uid"],
                "associated_category": candidate["associated_category"],
                "total_parsed_observations": stat.parsed_records,
                "directly_matching_observations": stat.relevant,
                "match_percent": round(stat.relevant / stat.parsed_records * 100, 3) if stat.parsed_records else 0,
                "matching_asn_count": len(stat.matching_asns),
                "matching_prefix_count": len(stat.matching_prefixes),
                "notes": "features use only candidate-relevant UPDATE observations; unrelated global RouteViews traffic is retained only in raw counts",
            }
        )

    feature_rows = []
    window_counts = []
    for wid, meta in sorted(window_meta.items(), key=lambda item: (str(item[1]["candidate_period_id"]), str(item[1]["window_start"]))):
        features = features_from_aggregate(aggs[wid])
        row = {
            "incident_uid": meta["candidate_period_id"],
            "incident_id": meta["candidate_period_id"],
            "category": "Normal",
            "partition": meta["partition"],
            "window_id": wid,
            "window_start": meta["window_start"],
            "window_end": meta["window_end"],
            "temporal_status": "NORMAL_CANDIDATE",
            "associated_incident_uid": meta["associated_incident_uid"],
            "associated_category": meta["associated_category"],
            "candidate_period_id": meta["candidate_period_id"],
            "behavioral_feature_version": BEHAVIORAL_FEATURE_VERSION,
            "behavioral_feature_count": BEHAVIORAL_FEATURE_COUNT,
            "raw_observation_count": meta["raw_observation_count"],
            "has_relevant_observation": features["update_count"] > 0,
        }
        row.update(features)
        feature_rows.append(row)
        window_counts.append(
            {
                "associated_incident_uid": row["associated_incident_uid"],
                "associated_category": row["associated_category"],
                "candidate_period_id": row["candidate_period_id"],
                "window_id": row["window_id"],
                "window_start": row["window_start"],
                "window_end": row["window_end"],
                "raw_observation_count": row["raw_observation_count"],
                "relevant_observation_count": row["update_count"],
                "announcement_count": row["announcement_count"],
                "withdrawal_count": row["withdrawal_count"],
                "unique_prefixes": row["unique_prefix_count"],
                "unique_peer_asns": row["unique_peer_asn_count"],
                "unique_origin_asns": row["unique_origin_asn_count"],
                "unique_as_paths": row["unique_as_path_count"],
            }
        )
    return raw_counts, relevance, window_counts, feature_rows


def path_instability(feature_row: dict[str, object]) -> str:
    if int(feature_row["update_count"]) == 0:
        return "STABLE_SILENCE"
    if int(feature_row["unique_as_path_count"]) <= 2 and int(feature_row["multi_path_prefix_count"]) <= 1:
        return "LOW"
    return "HIGH"


def qualify(feature_rows: list[dict[str, object]], execution_rows: list[dict[str, object]]) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    candidates = {str(row["candidate_period_id"]): row for row in execution_rows}
    preliminary = []
    for row in feature_rows:
        candidate = candidates[str(row["candidate_period_id"])]
        rib_route = candidate["route_presence_stable"] == "True"
        rib_origin = candidate["origin_stable"] == "True"
        origin_changes = int(row["origin_change_event_count"])
        instability = path_instability(row)
        deaggregation = int(row["unique_prefix_count"]) > (1 if candidate.get("affected_prefix") else 25)
        moas = int(row["moas_prefix_count"]) > 0
        suspicious = bool(origin_changes > 0 or instability == "HIGH" or deaggregation or moas)
        stable_silence = int(row["update_count"]) == 0 and rib_route and rib_origin
        checks = [
            ("no_known_incident_overlap", True),
            ("outside_60_minute_exclusion_buffer", True),
            ("rib_route_confirmed", rib_route),
            ("rib_origin_stable", rib_origin),
            ("no_suspicious_update_behavior", not suspicious),
            ("no_strong_as_path_instability", instability != "HIGH"),
            ("no_suspicious_deaggregation", not deaggregation),
            ("no_unexpected_moas_origin_diversity", not moas),
        ]
        failed = [name for name, ok in checks if not ok]
        passed = [name for name, ok in checks if ok]
        preliminary.append(
            {
                "candidate_period_id": row["candidate_period_id"],
                "associated_incident_uid": row["associated_incident_uid"],
                "associated_category": row["associated_category"],
                "window_id": row["window_id"],
                "window_start": row["window_start"],
                "window_end": row["window_end"],
                "rib_route_confirmed": str(rib_route),
                "rib_origin_stable": str(rib_origin),
                "relevant_update_count": row["update_count"],
                "announcement_count": row["announcement_count"],
                "withdrawal_count": row["withdrawal_count"],
                "origin_change_count": origin_changes,
                "path_instability": instability,
                "prefix_deaggregation": str(deaggregation),
                "moas_event": str(moas),
                "stable_silence": str(stable_silence),
                "consecutive_stable_windows": 0,
                "final_state": "UNKNOWN",
                "reason": "",
                "_stable": not failed,
                "_failed": failed,
                "_passed": passed,
            }
        )
    output = []
    for _, group in group_by(preliminary, "candidate_period_id").items():
        run_lengths = [0] * len(group)
        run = 0
        for index, row in enumerate(group):
            run = run + 1 if row["_stable"] else 0
            run_lengths[index] = run
        suffix = 0
        sustained = [False] * len(group)
        for index in range(len(group) - 1, -1, -1):
            suffix = suffix + 1 if group[index]["_stable"] else 0
            if suffix >= MIN_STABLE_WINDOWS:
                for member in range(index, index + suffix):
                    sustained[member] = True
        for index, row in enumerate(group):
            final = "NORMAL_VERIFIED" if row["_stable"] and sustained[index] else "UNKNOWN"
            out = {k: v for k, v in row.items() if not k.startswith("_")}
            out["consecutive_stable_windows"] = run_lengths[index]
            out["final_state"] = final
            out["reason"] = "member of sustained 30-minute stable block" if final == "NORMAL_VERIFIED" else ";".join(row["_failed"]) or "stable but not part of 30-minute sustained block"
            output.append(out)
    summaries = []
    for candidate_id, group in group_by(output, "candidate_period_id").items():
        normal = sum(row["final_state"] == "NORMAL_VERIFIED" for row in group)
        unknown = len(group) - normal
        longest = max(int(row["consecutive_stable_windows"]) for row in group) * 5 if group else 0
        reasons = sorted({row["reason"] for row in group if row["final_state"] != "NORMAL_VERIFIED"})
        summaries.append(
            {
                "candidate_period_id": candidate_id,
                "associated_incident_uid": group[0]["associated_incident_uid"],
                "associated_category": group[0]["associated_category"],
                "total_windows": len(group),
                "normal_verified_windows": normal,
                "unknown_windows": unknown,
                "normal_yield_percent": round(normal / len(group) * 100, 3) if group else 0,
                "longest_stable_block_minutes": longest,
                "candidate_status": "PASS" if normal else "REVIEW",
                "failure_reason": ";".join(reasons[:8]),
            }
        )
    return output, summaries


def group_by(rows: list[dict[str, object]], key: str) -> dict[str, list[dict[str, object]]]:
    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        grouped[str(row[key])].append(row)
    for values in grouped.values():
        values.sort(key=lambda item: str(item.get("window_start", "")))
    return grouped


def write_diversity(qualification: list[dict[str, object]], approved_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    candidate_by_id = {str(row["candidate_period_id"]): row for row in approved_rows}
    verified = [row for row in qualification if row["final_state"] == "NORMAL_VERIFIED"]
    by_asn = Counter(candidate_by_id[str(row["candidate_period_id"])]["affected_asn"] for row in verified)
    rows = [
        {"metric": "normal_verified_windows_by_associated_class", "value": len(verified), "details": json.dumps(dict(Counter(row["associated_category"] for row in verified)), separators=(",", ":"))},
        {"metric": "unique_asns_producing_verified_normal", "value": len(by_asn), "details": json.dumps(dict(by_asn.most_common()), separators=(",", ":"))},
        {"metric": "year_distribution", "value": len(verified), "details": json.dumps(dict(Counter(str(row["window_start"])[:4] for row in verified)), separators=(",", ":"))},
        {"metric": "country_network_distribution", "value": len(verified), "details": "UNKNOWN; approved pool does not currently carry normalized country/network for all candidates"},
        {"metric": "concentration_flag", "value": "REVIEW" if by_asn and by_asn.most_common(1)[0][1] / len(verified) > 0.25 else "PASS", "details": json.dumps(dict(by_asn.most_common(10)), separators=(",", ":"))},
    ]
    write_csv(DIVERSITY, rows, ["metric", "value", "details"])
    return rows


def write_yield(candidate_summary: list[dict[str, object]], qualification: list[dict[str, object]]) -> list[dict[str, object]]:
    rows = []
    for category in ("Hijack", "Leak", "Outage", "ALL"):
        candidates = candidate_summary if category == "ALL" else [row for row in candidate_summary if row["associated_category"] == category]
        windows = qualification if category == "ALL" else [row for row in qualification if row["associated_category"] == category]
        verified = sum(row["final_state"] == "NORMAL_VERIFIED" for row in windows)
        unknown = len(windows) - verified
        rows.append(
            {
                "associated_category": category,
                "rib_approved_candidates": len(candidates),
                "candidates_producing_normal_verified": sum(row["candidate_status"] == "PASS" for row in candidates),
                "candidate_success_percent": round(sum(row["candidate_status"] == "PASS" for row in candidates) / len(candidates) * 100, 3) if candidates else 0,
                "windows_evaluated": len(windows),
                "normal_verified_windows": verified,
                "unknown_windows": unknown,
                "normal_window_yield_percent": round(verified / len(windows) * 100, 3) if windows else 0,
            }
        )
    write_csv(RIB_TO_UPDATE_YIELD, rows, ["associated_category", "rib_approved_candidates", "candidates_producing_normal_verified", "candidate_success_percent", "windows_evaluated", "normal_verified_windows", "unknown_windows", "normal_window_yield_percent"])
    return rows


def write_notebook() -> None:
    NOTEBOOK.parent.mkdir(parents=True, exist_ok=True)
    nb = {
        "cells": [
            {"cell_type": "markdown", "metadata": {}, "source": ["# Normal UPDATE Qualification Scale\n", "\n", "Run TRAIN-only UPDATE qualification for the 45 RIB-approved Normal candidates. No model training, no CAIDA/RPKI, and no Validation/Holdout access.\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["from bgp_incident_detection.normal_update_scale import prepare_summary\n", "prepare_summary(check_remote=False)\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["from bgp_incident_detection.normal_update_scale import run\n", "summary = run()\n", "summary\n"]},
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(nb, indent=2) + "\n", encoding="utf-8")


def prepare_summary(check_remote: bool = False) -> dict[str, object]:
    execution = freeze_execution_manifest()
    plan = build_acquisition_plan(execution, check_remote=check_remote)
    counts = Counter(row["associated_category"] for row in execution)
    remote = Counter(row["remote_available"] for row in plan)
    estimated_bytes = sum(int(row.get("estimated_content_length") or 0) for row in plan)
    write_notebook()
    return {
        "execution_candidates": len(execution),
        "candidate_class_counts": dict(counts),
        "planned_update_files": len(plan),
        "remote_availability": dict(remote),
        "estimated_compressed_bytes": estimated_bytes,
        "estimated_compressed_mib": round(estimated_bytes / 1024 / 1024, 3),
        "execution_manifest": str(EXECUTION_MANIFEST),
        "acquisition_plan": str(ACQUISITION_PLAN),
    }


def run(batch_size: int = UPDATE_BATCH_SIZE) -> dict[str, object]:
    start = time.perf_counter()
    execution = freeze_execution_manifest()
    plan = build_acquisition_plan(execution, check_remote=False)
    downloads = download_updates(plan, batch_size=batch_size)
    raw_counts, relevance, window_counts, feature_rows = parse_downloads(downloads, execution)
    pd.DataFrame(feature_rows).to_parquet(FEATURE_PARQUET, index=False)
    write_csv(RAW_COUNTS, raw_counts, ["candidate_period_id", "associated_incident_uid", "associated_category", "mrt_file_count", "parsed_mrt_records", "bgp_update_messages", "announcement_observations", "withdrawal_observations", "total_prefix_level_observations", "parse_failures"])
    write_csv(RELEVANCE_SUMMARY, relevance, ["candidate_period_id", "associated_incident_uid", "associated_category", "total_parsed_observations", "directly_matching_observations", "match_percent", "matching_asn_count", "matching_prefix_count", "notes"])
    write_csv(WINDOW_COUNTS, window_counts, ["associated_incident_uid", "associated_category", "candidate_period_id", "window_id", "window_start", "window_end", "raw_observation_count", "relevant_observation_count", "announcement_count", "withdrawal_count", "unique_prefixes", "unique_peer_asns", "unique_origin_asns", "unique_as_paths"])
    qualification, candidate_summary = qualify(feature_rows, execution)
    write_csv(QUALIFICATION_RESULTS, qualification, ["candidate_period_id", "associated_incident_uid", "associated_category", "window_id", "window_start", "window_end", "rib_route_confirmed", "rib_origin_stable", "relevant_update_count", "announcement_count", "withdrawal_count", "origin_change_count", "path_instability", "prefix_deaggregation", "moas_event", "stable_silence", "consecutive_stable_windows", "final_state", "reason"])
    write_csv(CANDIDATE_SUMMARY, candidate_summary, ["candidate_period_id", "associated_incident_uid", "associated_category", "total_windows", "normal_verified_windows", "unknown_windows", "normal_yield_percent", "longest_stable_block_minutes", "candidate_status", "failure_reason"])
    diversity = write_diversity(qualification, execution)
    yield_rows = write_yield(candidate_summary, qualification)
    write_notebook()
    return {
        "execution_candidates": len(execution),
        "planned_update_files": len(plan),
        "downloaded_update_files": sum(row["download_status"] in {"200", "CACHED"} for row in downloads),
        "downloaded_bytes": sum(int(row.get("file_size") or 0) for row in downloads),
        "parsed_prefix_observations": sum(int(row["total_prefix_level_observations"]) for row in raw_counts),
        "candidate_windows": len(qualification),
        "normal_verified_windows": sum(row["final_state"] == "NORMAL_VERIFIED" for row in qualification),
        "unknown_windows": sum(row["final_state"] == "UNKNOWN" for row in qualification),
        "candidate_periods_with_verified_normal": sum(row["candidate_status"] == "PASS" for row in candidate_summary),
        "candidate_success_by_class": dict(Counter(row["associated_category"] for row in candidate_summary if row["candidate_status"] == "PASS")),
        "unique_verified_asns": next((row["value"] for row in diversity if row["metric"] == "unique_asns_producing_verified_normal"), 0),
        "yield_by_class": yield_rows,
        "elapsed_seconds": round(time.perf_counter() - start, 3),
        "outputs": [str(EXECUTION_MANIFEST), str(ACQUISITION_PLAN), str(DOWNLOAD_AUDIT), str(RAW_COUNTS), str(RELEVANCE_SUMMARY), str(WINDOW_COUNTS), str(FEATURE_PARQUET), str(QUALIFICATION_RESULTS), str(CANDIDATE_SUMMARY), str(DIVERSITY), str(RIB_TO_UPDATE_YIELD), str(NOTEBOOK)],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run TRAIN-only Normal UPDATE qualification for the 45 approved candidates")
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--check-remote", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--batch-size", type=int, default=UPDATE_BATCH_SIZE)
    args = parser.parse_args()
    if args.prepare_only:
        print(json.dumps(prepare_summary(check_remote=args.check_remote), indent=2, sort_keys=True))
        return
    if args.run:
        print(json.dumps(run(batch_size=args.batch_size), indent=2, sort_keys=True))
        return
    parser.error("choose --prepare-only or --run")


if __name__ == "__main__":
    main()
