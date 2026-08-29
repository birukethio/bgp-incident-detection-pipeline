from __future__ import annotations

import argparse
import bz2
import csv
import hashlib
import json
import math
import shutil
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from statistics import mean, median
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pandas as pd

try:
    from bgp_incident_detection.audit import parse_utc, write_csv
    from bgp_incident_detection.behavioral_features import (
        BEHAVIORAL_FEATURE_NAMES,
        METADATA_COLUMNS,
        DIAGNOSTIC_COLUMNS,
        features_from_aggregate,
        update_aggregate,
        WindowAggregate,
    )
    from bgp_incident_detection.mrt_acquisition import (
        DEFAULT_COLLECTOR,
        ceil_to_15_minutes,
        floor_to_15_minutes,
        isoformat_z,
        iter_update_slots,
        routeviews_update_filename,
        routeviews_update_url,
    )
    from bgp_incident_detection.mrt_parser import PARSED_FIELDS, bgpdump_version, parse_bgpdump_line, parse_as_path_set
    from bgp_incident_detection.normal_baseline import CONTEXT_BUFFER_MINUTES, NORMAL_CANDIDATES
    from bgp_incident_detection.windows import floor_to_five_minutes, format_utc, window_id
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import parse_utc, write_csv
    from src.bgp_incident_detection.behavioral_features import (
        BEHAVIORAL_FEATURE_NAMES,
        METADATA_COLUMNS,
        DIAGNOSTIC_COLUMNS,
        features_from_aggregate,
        update_aggregate,
        WindowAggregate,
    )
    from src.bgp_incident_detection.mrt_acquisition import (
        DEFAULT_COLLECTOR,
        ceil_to_15_minutes,
        floor_to_15_minutes,
        isoformat_z,
        iter_update_slots,
        routeviews_update_filename,
        routeviews_update_url,
    )
    from src.bgp_incident_detection.mrt_parser import PARSED_FIELDS, bgpdump_version, parse_bgpdump_line, parse_as_path_set
    from src.bgp_incident_detection.normal_baseline import CONTEXT_BUFFER_MINUTES, NORMAL_CANDIDATES
    from src.bgp_incident_detection.windows import floor_to_five_minutes, format_utc, window_id


PILOT_DIR = Path("data/pilot")
RAW_NORMAL_DIR = Path("data/raw_mrt/normal_pilot")
PARSED_NORMAL_DIR = Path("data/parsed_mrt/normal_pilot")
INCIDENT_FEATURES = PILOT_DIR / "pilot_behavioral_features_v1.parquet"
NORMAL_PERIODS = PILOT_DIR / "normal_mrt_pilot_periods_v1.csv"
NORMAL_DOWNLOAD_MANIFEST = PILOT_DIR / "normal_mrt_pilot_download_manifest_v1.csv"
NORMAL_DOWNLOAD_STATUS = PILOT_DIR / "normal_mrt_pilot_file_status_v1.csv"
NORMAL_DOWNLOAD_AUDIT = PILOT_DIR / "normal_mrt_pilot_download_audit_v1.csv"
NORMAL_RAW_COUNTS = PILOT_DIR / "normal_pilot_raw_bgp_counts_v1.csv"
NORMAL_RELEVANCE = PILOT_DIR / "normal_pilot_relevance_summary_v1.csv"
NORMAL_WINDOW_COUNTS = PILOT_DIR / "normal_pilot_window_counts_v1.csv"
NORMAL_FEATURES = PILOT_DIR / "normal_pilot_behavioral_features_v1.parquet"
NORMAL_QUALIFICATION = PILOT_DIR / "normal_pilot_qualification_results_v1.csv"
NORMAL_INCIDENT_COMPARISON = PILOT_DIR / "normal_vs_incident_behavior_summary_v1.csv"
NORMAL_PARSER_ENV = PILOT_DIR / "normal_pilot_parser_environment_v1.csv"

SELECTED_PERIOD_KEYS = [
    ("Hijack:58159", -7, "2024-07-22T13:20:00Z"),
    ("Hijack:97511", 3, "2025-05-15T18:55:00Z"),
    ("Leak:291102", -1, "2025-03-30T08:45:00Z"),
    ("Leak:426483", 7, "2025-11-06T06:00:00Z"),
    ("Outage:1014", 3, "2024-09-10T09:45:00Z"),
    ("Outage:525", 7, "2023-08-20T02:00:00Z"),
]


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def parse_required(value: str) -> datetime:
    parsed = parse_utc(value)
    if not parsed:
        raise ValueError(f"invalid UTC timestamp: {value}")
    return parsed


def period_id(row: dict[str, str]) -> str:
    safe_time = row["candidate_start"].replace(":", "").replace("-", "").replace(".000Z", "Z")
    return f"{row['incident_uid'].replace(':', '_')}_offset_{int(row['days_from_incident']):+d}_{safe_time}"


def selected_periods() -> list[dict[str, object]]:
    candidates = [
        row for row in load_csv(NORMAL_CANDIDATES)
        if row["candidate_status"] == "NORMAL_CANDIDATE"
    ]
    by_key = {
        (row["incident_uid"], int(row["days_from_incident"]), row["candidate_start"]): row
        for row in candidates
    }
    rows = []
    for key in SELECTED_PERIOD_KEYS:
        row = dict(by_key[key])
        row["candidate_period_id"] = period_id(row)
        row["associated_incident_uid"] = row.pop("incident_uid")
        row["associated_category"] = row.pop("category")
        row["candidate_offset"] = f"{int(row['days_from_incident']):+d}d"
        row["partition"] = "train"
        row["reason_selected"] = "small TRAIN-only Normal pilot; balances category, ASN/network, offset/date diversity, and download size"
        rows.append(row)
    return rows


def collection_slots_for_period(row: dict[str, object]) -> list[datetime]:
    start = floor_to_15_minutes(parse_required(str(row["candidate_start"])) - timedelta(minutes=CONTEXT_BUFFER_MINUTES))
    end = ceil_to_15_minutes(parse_required(str(row["candidate_end"])) + timedelta(minutes=CONTEXT_BUFFER_MINUTES))
    return iter_update_slots(start, end)


def local_path(candidate_period_id: str, slot: datetime) -> str:
    return str(RAW_NORMAL_DIR / candidate_period_id / routeviews_update_filename(slot))


def build_download_manifest(period_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    rows = []
    for period in period_rows:
        slots = collection_slots_for_period(period)
        for slot in slots:
            rows.append(
                {
                    "associated_incident_uid": period["associated_incident_uid"],
                    "candidate_period_id": period["candidate_period_id"],
                    "mrt_timestamp": isoformat_z(slot),
                    "mrt_url": routeviews_update_url(slot, DEFAULT_COLLECTOR),
                    "local_path": local_path(str(period["candidate_period_id"]), slot),
                    "remote_available": "NOT_CHECKED",
                    "status_code": "",
                }
            )
    return rows


def head_url(url: str, timeout_seconds: float = 15.0) -> tuple[str, str, int]:
    request = Request(url, method="HEAD", headers={"User-Agent": "bgp-incident-detection-pipeline/0.1"})
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            return str(200 <= response.status < 400), str(response.status), int(response.headers.get("Content-Length") or 0)
    except HTTPError as error:
        return "False", str(error.code), 0
    except URLError:
        return "NOT_CHECKED", "", 0


def check_manifest_availability(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    cache: dict[str, tuple[str, str, int]] = {}
    checked = []
    for row in rows:
        url = str(row["mrt_url"])
        if url not in cache:
            cache[url] = head_url(url)
        available, status_code, content_length = cache[url]
        updated = dict(row)
        updated["remote_available"] = available
        updated["status_code"] = status_code
        updated["estimated_content_length"] = content_length
        checked.append(updated)
    return checked


def write_periods(rows: list[dict[str, object]]) -> None:
    write_csv(
        NORMAL_PERIODS,
        rows,
        [
            "associated_incident_uid",
            "associated_category",
            "candidate_period_id",
            "affected_asn",
            "affected_prefix",
            "candidate_start",
            "candidate_end",
            "days_from_incident",
            "candidate_offset",
            "known_incident_overlap",
            "partition",
            "reason_selected",
        ],
    )


def write_download_manifest(rows: list[dict[str, object]]) -> None:
    write_csv(
        NORMAL_DOWNLOAD_MANIFEST,
        rows,
        [
            "associated_incident_uid",
            "candidate_period_id",
            "mrt_timestamp",
            "mrt_url",
            "local_path",
            "remote_available",
            "status_code",
            "estimated_content_length",
        ],
    )


def checksum_file(path: Path) -> str:
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


def download_file(row: dict[str, object]) -> dict[str, object]:
    destination = Path(str(row["local_path"]))
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and destination.stat().st_size > 0:
        return {
            **row,
            "http_result": "cached",
            "downloaded": "True",
            "file_size_bytes": destination.stat().st_size,
            "sha256": checksum_file(destination),
            "download_timestamp": isoformat_z(datetime.now(timezone.utc)),
            "compression_ok": str(compression_ok(destination)),
            "notes": "cached file reused",
        }
    request = Request(str(row["mrt_url"]), headers={"User-Agent": "bgp-incident-detection-pipeline/0.1"})
    try:
        with urlopen(request, timeout=180) as response:
            destination.write_bytes(response.read())
            status = str(response.status)
    except (HTTPError, URLError) as error:
        return {
            **row,
            "http_result": getattr(error, "code", ""),
            "downloaded": "False",
            "file_size_bytes": 0,
            "sha256": "",
            "download_timestamp": isoformat_z(datetime.now(timezone.utc)),
            "compression_ok": "False",
            "notes": str(error),
        }
    return {
        **row,
        "http_result": status,
        "downloaded": "True",
        "file_size_bytes": destination.stat().st_size,
        "sha256": checksum_file(destination),
        "download_timestamp": isoformat_z(datetime.now(timezone.utc)),
        "compression_ok": str(compression_ok(destination)),
        "notes": "downloaded",
    }


def download_available_files(manifest_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    status_rows = []
    for row in manifest_rows:
        if row["remote_available"] != "True":
            status_rows.append({**row, "http_result": "", "downloaded": "False", "file_size_bytes": 0, "sha256": "", "download_timestamp": "", "compression_ok": "False", "notes": "remote file was not available"})
            continue
        status_rows.append(download_file(row))
    write_csv(
        NORMAL_DOWNLOAD_STATUS,
        status_rows,
        [
            "associated_incident_uid",
            "candidate_period_id",
            "mrt_timestamp",
            "mrt_url",
            "local_path",
            "remote_available",
            "status_code",
            "estimated_content_length",
            "http_result",
            "downloaded",
            "file_size_bytes",
            "sha256",
            "download_timestamp",
            "compression_ok",
            "notes",
        ],
    )
    return status_rows


def summarize_downloads(status_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    by_period: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in status_rows:
        by_period[str(row["candidate_period_id"])].append(row)
    audit = []
    for period_id_value, rows in sorted(by_period.items()):
        planned = len(rows)
        downloaded = sum(1 for row in rows if row["downloaded"] == "True")
        corrupted = sum(1 for row in rows if row["downloaded"] == "True" and row["compression_ok"] != "True")
        missing = planned - downloaded
        duplicate_files = planned - len({row["mrt_url"] for row in rows})
        status = "PASS" if missing == 0 and corrupted == 0 and duplicate_files == 0 else "FAIL"
        audit.append(
            {
                "candidate_period_id": period_id_value,
                "associated_incident_uid": rows[0]["associated_incident_uid"],
                "planned_files": planned,
                "downloaded_files": downloaded,
                "missing_files": missing,
                "corrupted_files": corrupted,
                "duplicate_files": duplicate_files,
                "total_bytes": sum(int(row["file_size_bytes"]) for row in rows),
                "availability_percent": round(downloaded / planned * 100, 3) if planned else 0,
                "status": status,
            }
        )
    return audit


def period_metadata() -> dict[str, dict[str, str]]:
    return {row["candidate_period_id"]: row for row in load_csv(NORMAL_PERIODS)}


def relevant_to_period(parsed: dict[str, str], period: dict[str, str]) -> bool:
    asn = period["affected_asn"]
    prefix = period["affected_prefix"]
    peer_origin = {parsed["peer_asn"], parsed["origin_asn"]}
    peer_origin.discard("")
    return bool(asn and (asn in peer_origin or asn in parse_as_path_set(parsed["as_path"]))) or bool(
        prefix and parsed["prefix"] == prefix
    )


def parsed_output_path(candidate_period_id: str) -> Path:
    return PARSED_NORMAL_DIR / candidate_period_id / "parsed_bgp_observations.csv"


@dataclass
class ParseStats:
    parsed_records: int = 0
    announcements: int = 0
    withdrawals: int = 0
    relevant: int = 0
    relevant_announcements: int = 0
    relevant_withdrawals: int = 0
    matching_prefixes: set[str] = field(default_factory=set)
    matching_asns: set[str] = field(default_factory=set)
    file_count: int = 0
    parse_failures: int = 0


def parse_downloaded_files(status_rows: list[dict[str, object]]) -> tuple[list[dict[str, object]], list[dict[str, object]], dict[str, WindowAggregate], dict[str, dict[str, object]]]:
    periods = period_metadata()
    stats: dict[str, ParseStats] = defaultdict(ParseStats)
    window_aggs: dict[str, WindowAggregate] = defaultdict(WindowAggregate)
    window_meta: dict[str, dict[str, object]] = {}
    raw_window_counts: dict[str, int] = defaultdict(int)

    for row in status_rows:
        if row["downloaded"] != "True":
            continue
        period = periods[str(row["candidate_period_id"])]
        stats[str(row["candidate_period_id"])].file_count += 1
        command = ["bgpdump", "-q", "-m", str(row["local_path"])]
        process = subprocess.Popen(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert process.stdout is not None
        for line in process.stdout:
            parsed = parse_bgpdump_line(line, str(row["candidate_period_id"]), Path(str(row["local_path"])), DEFAULT_COLLECTOR)
            if parsed is None:
                continue
            stat = stats[str(row["candidate_period_id"])]
            stat.parsed_records += 1
            if parsed["announcement_or_withdrawal"] == "announcement":
                stat.announcements += 1
            elif parsed["announcement_or_withdrawal"] == "withdrawal":
                stat.withdrawals += 1
            timestamp = parse_utc(parsed["bgp_timestamp_utc"])
            if not timestamp:
                continue
            candidate_start = parse_required(period["candidate_start"])
            candidate_end = parse_required(period["candidate_end"])
            if not (candidate_start <= timestamp < candidate_end):
                continue
            start = floor_to_five_minutes(timestamp)
            wid = window_id(str(row["candidate_period_id"]), start)
            window_meta[wid] = {
                "associated_incident_uid": period["associated_incident_uid"],
                "associated_category": period["associated_category"],
                "partition": period["partition"],
                "candidate_period_id": row["candidate_period_id"],
                "window_id": wid,
                "window_start": format_utc(start),
                "window_end": format_utc(start + timedelta(minutes=5)),
                "normal_construction_state": "NORMAL_CANDIDATE",
                "raw_observation_count": 0,
            }
            raw_window_counts[wid] += 1
            is_relevant = relevant_to_period(parsed, period)
            if not is_relevant:
                continue
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
            update_aggregate(window_aggs[wid], parsed)
        process.stderr.read() if process.stderr else ""
        if process.wait() != 0:
            stats[str(row["candidate_period_id"])].parse_failures += 1

    for wid, count in raw_window_counts.items():
        if wid in window_meta:
            window_meta[wid]["raw_observation_count"] = count

    raw_counts = []
    relevance = []
    for period_id_value, stat in sorted(stats.items()):
        raw_counts.append(
            {
                "candidate_period_id": period_id_value,
                "mrt_files": stat.file_count,
                "parsed_records": stat.parsed_records,
                "announcement_observations": stat.announcements,
                "withdrawal_observations": stat.withdrawals,
                "total_prefix_level_observations": stat.parsed_records,
                "parse_failures": stat.parse_failures,
            }
        )
        relevance.append(
            {
                "candidate_period_id": period_id_value,
                "associated_incident_uid": periods[period_id_value]["associated_incident_uid"],
                "associated_category": periods[period_id_value]["associated_category"],
                "total_parsed_observations": stat.parsed_records,
                "directly_matching_observations": stat.relevant,
                "match_percent": round(stat.relevant / stat.parsed_records * 100, 3) if stat.parsed_records else 0,
                "matching_asn_count": len(stat.matching_asns),
                "matching_prefix_count": len(stat.matching_prefixes),
                "notes": "direct Normal relevance uses associated ASN/network and representative prefix where available",
            }
        )
    return raw_counts, relevance, window_aggs, window_meta


def initialize_all_candidate_windows(periods: list[dict[str, str]], existing_meta: dict[str, dict[str, object]], aggs: dict[str, WindowAggregate]) -> None:
    for period in periods:
        start = floor_to_five_minutes(parse_required(period["candidate_start"]))
        end = parse_required(period["candidate_end"])
        cursor = start
        while cursor < end:
            wid = window_id(period["candidate_period_id"], cursor)
            existing_meta.setdefault(
                wid,
                {
                    "associated_incident_uid": period["associated_incident_uid"],
                    "associated_category": period["associated_category"],
                    "partition": period["partition"],
                    "candidate_period_id": period["candidate_period_id"],
                    "window_id": wid,
                    "window_start": format_utc(cursor),
                    "window_end": format_utc(cursor + timedelta(minutes=5)),
                    "normal_construction_state": "NORMAL_CANDIDATE",
                    "raw_observation_count": 0,
                },
            )
            aggs.setdefault(wid, WindowAggregate())
            cursor += timedelta(minutes=5)


def feature_rows(window_aggs: dict[str, WindowAggregate], window_meta: dict[str, dict[str, object]]) -> list[dict[str, object]]:
    rows = []
    for wid, meta in sorted(window_meta.items(), key=lambda item: (str(item[1]["candidate_period_id"]), str(item[1]["window_start"]))):
        features = features_from_aggregate(window_aggs[wid])
        row = {
            "incident_uid": meta["candidate_period_id"],
            "incident_id": meta["candidate_period_id"],
            "category": "Normal",
            "partition": meta["partition"],
            "window_id": wid,
            "window_start": meta["window_start"],
            "window_end": meta["window_end"],
            "temporal_status": meta["normal_construction_state"],
            "associated_incident_uid": meta["associated_incident_uid"],
            "associated_category": meta["associated_category"],
            "candidate_period_id": meta["candidate_period_id"],
            "raw_observation_count": meta["raw_observation_count"],
            "has_relevant_observation": features["update_count"] > 0,
        }
        row.update(features)
        rows.append(row)
    return rows


def clean_value(value: object) -> object:
    return "" if isinstance(value, float) and math.isnan(value) else value


def write_feature_table(rows: list[dict[str, object]]) -> None:
    pd.DataFrame(rows).to_parquet(NORMAL_FEATURES, index=False)


def write_window_counts(rows: list[dict[str, object]]) -> None:
    write_csv(
        NORMAL_WINDOW_COUNTS,
        rows,
        [
            "associated_incident_uid",
            "associated_category",
            "candidate_period_id",
            "window_id",
            "window_start",
            "window_end",
            "normal_construction_state",
            "raw_observation_count",
            "relevant_observation_count",
            "announcement_count",
            "withdrawal_count",
            "unique_prefixes",
            "unique_peer_asns",
            "unique_origin_asns",
            "unique_as_paths",
        ],
    )


def window_count_rows(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    output = []
    for row in rows:
        output.append(
            {
                "associated_incident_uid": row["associated_incident_uid"],
                "associated_category": row["associated_category"],
                "candidate_period_id": row["candidate_period_id"],
                "window_id": row["window_id"],
                "window_start": row["window_start"],
                "window_end": row["window_end"],
                "normal_construction_state": row["temporal_status"],
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
    return output


def iqr_bounds(values: list[float], multiplier: float = 1.5) -> tuple[float, float]:
    if not values:
        return 0, 0
    ordered = sorted(values)
    q1 = ordered[int((len(ordered) - 1) * 0.25)]
    q3 = ordered[int((len(ordered) - 1) * 0.75)]
    spread = q3 - q1
    return q1 - multiplier * spread, q3 + multiplier * spread


def qualify_windows(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    checks = [
        "route_visibility_present",
        "stable_origin_behavior",
        "no_unexplained_origin_change",
        "no_announcement_burst",
        "no_withdrawal_burst",
        "no_extreme_as_path_instability",
        "no_suspicious_prefix_deaggregation",
        "no_unexpected_moas_origin_diversity",
        "no_large_path_prepending_anomaly",
    ]
    metrics = {
        "no_announcement_burst": "announcement_count",
        "no_withdrawal_burst": "withdrawal_count",
        "no_extreme_as_path_instability": "unique_as_path_count",
        "no_suspicious_prefix_deaggregation": "unique_prefix_count",
        "no_large_path_prepending_anomaly": "path_prepending_ratio",
    }
    bounds: dict[str, tuple[float, float]] = {}
    for check, feature in metrics.items():
        values = [float(row[feature]) for row in rows if not (isinstance(row[feature], float) and math.isnan(row[feature]))]
        bounds[check] = iqr_bounds(values)

    preliminary = []
    for row in rows:
        failed = []
        passed = []
        if bool(row["has_relevant_observation"]):
            passed.append("route_visibility_present")
        else:
            failed.append("route_visibility_present")
        if int(row["unique_origin_asn_count"]) <= 1:
            passed.extend(["stable_origin_behavior", "no_unexplained_origin_change"])
        else:
            failed.extend(["stable_origin_behavior", "no_unexplained_origin_change"])
        if int(row["moas_prefix_count"]) == 0 and float(row["origin_change_event_count"]) == 0:
            passed.append("no_unexpected_moas_origin_diversity")
        else:
            failed.append("no_unexpected_moas_origin_diversity")
        for check, feature in metrics.items():
            value = row[feature]
            if isinstance(value, float) and math.isnan(value):
                passed.append(check)
                continue
            _, upper = bounds[check]
            if float(value) <= upper:
                passed.append(check)
            else:
                failed.append(check)
        preliminary.append((row, passed, failed))

    stable_by_period: dict[str, list[bool]] = defaultdict(list)
    for row, _, failed in preliminary:
        stable_by_period[str(row["candidate_period_id"])].append(len(failed) == 0)

    sustained_by_period: dict[str, bool] = {}
    for period_id_value, flags in stable_by_period.items():
        run = 0
        sustained = False
        for flag in flags:
            run = run + 1 if flag else 0
            if run >= 6:
                sustained = True
        sustained_by_period[period_id_value] = sustained

    output = []
    for row, passed, failed in preliminary:
        sustained = sustained_by_period[str(row["candidate_period_id"])]
        final_state = "NORMAL_VERIFIED" if not failed and sustained else "UNKNOWN"
        reason = "passed all pilot qualification checks with sustained stability" if final_state == "NORMAL_VERIFIED" else "failed checks or lacks 6-window sustained stable block"
        output.append(
            {
                "candidate_period_id": row["candidate_period_id"],
                "window_id": row["window_id"],
                "window_start": row["window_start"],
                "window_end": row["window_end"],
                "raw_observation_count": row["raw_observation_count"],
                "qualification_checks_passed": json.dumps(passed, separators=(",", ":")),
                "qualification_checks_failed": json.dumps(failed, separators=(",", ":")),
                "sustained_stability_pass": str(sustained),
                "final_state": final_state,
                "reason": reason,
            }
        )
    return output


def descriptive_comparison(normal_rows: list[dict[str, object]], qualification: list[dict[str, object]]) -> list[dict[str, object]]:
    incident = pd.read_parquet(INCIDENT_FEATURES)
    incident_active = incident[incident["temporal_status"] == "INCIDENT_ACTIVE"]
    normal_df = pd.DataFrame(normal_rows)
    verified_ids = {row["window_id"] for row in qualification if row["final_state"] == "NORMAL_VERIFIED"}
    verified = normal_df[normal_df["window_id"].isin(verified_ids)]
    rows = []
    for feature in BEHAVIORAL_FEATURE_NAMES:
        inc = incident_active[feature].dropna()
        norm = verified[feature].dropna() if not verified.empty else pd.Series(dtype=float)
        rows.append(
            {
                "feature_name": feature,
                "normal_verified_count": int(norm.count()),
                "normal_median": norm.median() if norm.count() else "",
                "normal_iqr": (norm.quantile(0.75) - norm.quantile(0.25)) if norm.count() else "",
                "normal_mean": norm.mean() if norm.count() else "",
                "incident_active_count": int(inc.count()),
                "incident_active_median": inc.median() if inc.count() else "",
                "incident_active_iqr": (inc.quantile(0.75) - inc.quantile(0.25)) if inc.count() else "",
                "incident_active_mean": inc.mean() if inc.count() else "",
                "notes": "descriptive only; not used for threshold tuning",
            }
        )
    return rows


def write_parser_environment() -> None:
    write_csv(
        NORMAL_PARSER_ENV,
        [
            {
                "tool_or_library": "bgpdump",
                "version": bgpdump_version(),
                "exact_command_or_function": "bgpdump -q -m <normal-pilot-file.bz2>",
                "input_format": "RouteViews MRT UPDATE .bz2",
                "output_fields": "|".join(PARSED_FIELDS),
                "row_granularity": "one prefix-level announcement or withdrawal observation emitted by bgpdump -m",
            }
        ],
        ["tool_or_library", "version", "exact_command_or_function", "input_format", "output_fields", "row_granularity"],
    )


def run_prepare() -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    periods = selected_periods()
    manifest = check_manifest_availability(build_download_manifest(periods))
    write_periods(periods)
    write_download_manifest(manifest)
    return periods, manifest


def run_download_parse_qualify() -> dict[str, object]:
    periods = load_csv(NORMAL_PERIODS)
    manifest = load_csv(NORMAL_DOWNLOAD_MANIFEST)
    status_rows = download_available_files(manifest)
    audit = summarize_downloads(status_rows)
    write_csv(
        NORMAL_DOWNLOAD_AUDIT,
        audit,
        ["candidate_period_id", "associated_incident_uid", "planned_files", "downloaded_files", "missing_files", "corrupted_files", "duplicate_files", "total_bytes", "availability_percent", "status"],
    )
    write_parser_environment()
    raw_counts, relevance, aggs, meta = parse_downloaded_files(status_rows)
    initialize_all_candidate_windows(periods, meta, aggs)
    rows = feature_rows(aggs, meta)
    write_feature_table(rows)
    write_window_counts(window_count_rows(rows))
    write_csv(NORMAL_RAW_COUNTS, raw_counts, ["candidate_period_id", "mrt_files", "parsed_records", "announcement_observations", "withdrawal_observations", "total_prefix_level_observations", "parse_failures"])
    write_csv(NORMAL_RELEVANCE, relevance, ["candidate_period_id", "associated_incident_uid", "associated_category", "total_parsed_observations", "directly_matching_observations", "match_percent", "matching_asn_count", "matching_prefix_count", "notes"])
    qualification = qualify_windows(rows)
    write_csv(NORMAL_QUALIFICATION, qualification, ["candidate_period_id", "window_id", "window_start", "window_end", "raw_observation_count", "qualification_checks_passed", "qualification_checks_failed", "sustained_stability_pass", "final_state", "reason"])
    comparison = descriptive_comparison(rows, qualification)
    write_csv(NORMAL_INCIDENT_COMPARISON, comparison, ["feature_name", "normal_verified_count", "normal_median", "normal_iqr", "normal_mean", "incident_active_count", "incident_active_median", "incident_active_iqr", "incident_active_mean", "notes"])
    return {"periods": periods, "manifest": manifest, "status": status_rows, "audit": audit, "raw_counts": raw_counts, "relevance": relevance, "features": rows, "qualification": qualification, "comparison": comparison}


def print_prepare_summary(periods: list[dict[str, object]], manifest: list[dict[str, object]]) -> None:
    print("Selected Normal MRT pilot periods:")
    for row in periods:
        print(json.dumps({key: row[key] for key in ["candidate_period_id", "associated_incident_uid", "associated_category", "affected_asn", "affected_prefix", "candidate_start", "candidate_end", "days_from_incident", "partition"]}, sort_keys=True))
    total_size = sum(int(row.get("estimated_content_length") or 0) for row in manifest)
    print(f"planned_mrt_files={len(manifest)}")
    print(f"remote_availability={dict(Counter(row['remote_available'] for row in manifest))}")
    print(f"estimated_total_bytes={total_size}")
    print(f"estimated_total_mb={round(total_size / (1024 * 1024), 3)}")


def print_final_summary(results: dict[str, object]) -> None:
    qualification = results["qualification"]
    status_rows = results["status"]
    raw_counts = results["raw_counts"]
    print(f"mrt_files_required={len(status_rows)}")
    print(f"downloaded={sum(1 for row in status_rows if row['downloaded'] == 'True')}")
    print(f"parsed_files={sum(int(row['mrt_files']) for row in raw_counts)}")
    print(f"candidate_windows={len(qualification)}")
    print(f"qualification={dict(Counter(row['final_state'] for row in qualification))}")
    print(f"download_audit={dict(Counter(row['status'] for row in results['audit']))}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run small TRAIN-only Normal MRT pilot.")
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--download-parse-qualify", action="store_true")
    args = parser.parse_args()
    if args.prepare_only:
        periods, manifest = run_prepare()
        print_prepare_summary(periods, manifest)
        return
    if args.download_parse_qualify:
        print_final_summary(run_download_parse_qualify())
        return
    periods, manifest = run_prepare()
    print_prepare_summary(periods, manifest)


if __name__ == "__main__":
    main()
