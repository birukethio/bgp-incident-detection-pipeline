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
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pandas as pd

try:
    from bgp_incident_detection.audit import parse_utc, write_csv
    from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES, WindowAggregate, features_from_aggregate, update_aggregate
    from bgp_incident_detection.mrt_parser import PARSED_FIELDS, bgpdump_version, parse_as_path_set, parse_bgpdump_line
    from bgp_incident_detection.windows import floor_to_five_minutes, format_utc, window_id
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import parse_utc, write_csv
    from src.bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES, WindowAggregate, features_from_aggregate, update_aggregate
    from src.bgp_incident_detection.mrt_parser import PARSED_FIELDS, bgpdump_version, parse_as_path_set, parse_bgpdump_line
    from src.bgp_incident_detection.windows import floor_to_five_minutes, format_utc, window_id


PILOT_DIR = Path("data/pilot")
RAW_DIR = Path("data/raw_mrt/normal_second_pilot")
PARSED_DIR = Path("data/parsed_mrt/normal_second_pilot")

SECOND_CANDIDATES = PILOT_DIR / "normal_second_pilot_candidate_manifest_v1.csv"
SECOND_ACQUISITION_PLAN = PILOT_DIR / "normal_second_pilot_acquisition_plan_v1.csv"
RIB_READY_EXISTING = PILOT_DIR / "normal_update_ready_candidates_v1.csv"
RIB_READY_ADDITIONAL = PILOT_DIR / "normal_additional_replacement_candidates_v1.csv"
FIRST_NORMAL_QUALIFICATION = PILOT_DIR / "normal_rib_update_qualification_results_v1.csv"

EXECUTION_MANIFEST = PILOT_DIR / "normal_second_pilot_execution_manifest_v1.csv"
DOWNLOAD_FILE_STATUS = PILOT_DIR / "normal_second_pilot_download_file_status_v1.csv"
DOWNLOAD_AUDIT = PILOT_DIR / "normal_second_pilot_download_audit_v1.csv"
PARSER_ENVIRONMENT = PILOT_DIR / "normal_second_pilot_parser_environment_v1.csv"
RAW_COUNTS = PILOT_DIR / "normal_second_pilot_raw_bgp_counts_v1.csv"
RELEVANCE_SUMMARY = PILOT_DIR / "normal_second_pilot_relevance_summary_v1.csv"
WINDOW_COUNTS = PILOT_DIR / "normal_second_pilot_window_counts_v1.csv"
FEATURES = PILOT_DIR / "normal_second_pilot_behavioral_features_v1.parquet"
QUALIFICATION_RESULTS = PILOT_DIR / "normal_second_pilot_qualification_results_v1.csv"
CANDIDATE_RESULTS = PILOT_DIR / "normal_second_pilot_candidate_results_v1.csv"
PILOT_COMPARISON = PILOT_DIR / "normal_pilot_comparison_v2.csv"

PILOT_VERSION = "normal_second_pilot_v1"
MIN_STABLE_WINDOWS = 6
MIN_STABILITY_MINUTES = 30
EXCLUSION_BUFFER_MINUTES = 60


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def parse_required(value: str) -> datetime:
    parsed = parse_utc(value)
    if not parsed:
        raise ValueError(f"invalid UTC timestamp: {value}")
    return parsed


def isoformat_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def safe_candidate_dir(candidate_period_id: str) -> Path:
    return RAW_DIR / candidate_period_id.replace("/", "_")


def local_path(candidate_period_id: str, mrt_url: str) -> str:
    return str(safe_candidate_dir(candidate_period_id) / mrt_url.rsplit("/", 1)[-1])


def compression_ok(path: Path) -> bool:
    try:
        with bz2.open(path, "rb") as handle:
            handle.read(3)
        return True
    except OSError:
        return False


def checksum(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def head_url(url: str, timeout_seconds: float = 15.0) -> tuple[bool, str, int, str]:
    request = Request(url, method="HEAD", headers={"User-Agent": "bgp-incident-detection-pipeline/0.1"})
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            return 200 <= response.status < 400, str(response.status), int(response.headers.get("Content-Length") or 0), "HEAD"
    except HTTPError as error:
        return False, str(error.code), 0, f"HTTPError: {error.reason}"
    except URLError as error:
        return False, "", 0, f"URLError: {error.reason}"


def rib_evidence() -> dict[str, dict[str, str]]:
    evidence: dict[str, dict[str, str]] = {}
    for row in load_csv(RIB_READY_EXISTING):
        evidence[row["candidate_period_id"]] = {
            "rib_before": row["rib_before"],
            "rib_after": row["rib_after"],
            "origin_stable": row["origin_stable"],
            "route_presence_stable": "True",
            "known_incident_overlap": row["known_incident_overlap"],
            "exclusion_buffer_pass": row["exclusion_buffer_pass"],
        }
    for row in load_csv(RIB_READY_ADDITIONAL):
        if row["prescreen_status"] != "UPDATE_READY":
            continue
        evidence[row["candidate_period_id"]] = {
            "rib_before": row["rib_before_timestamp"],
            "rib_after": row["rib_after_timestamp"],
            "origin_stable": row["origin_stable"],
            "route_presence_stable": row["route_presence_stable"],
            "known_incident_overlap": row["known_incident_overlap"],
            "exclusion_buffer_pass": "True" if row["known_incident_overlap"] == "False" else "False",
        }
    return evidence


def freeze_execution_manifest() -> list[dict[str, object]]:
    evidence = rib_evidence()
    rows = []
    for row in load_csv(SECOND_CANDIDATES):
        if row["prescreen_status"] != "UPDATE_READY":
            raise ValueError(f"candidate is not UPDATE_READY: {row['candidate_period_id']}")
        ev = evidence[row["candidate_period_id"]]
        rows.append(
            {
                "candidate_period_id": row["candidate_period_id"],
                "associated_incident_uid": row["associated_incident_uid"],
                "associated_category": row["category"],
                "affected_asn": row["affected_asn"],
                "affected_prefix": row["affected_prefix"],
                "candidate_start": row["candidate_start"],
                "candidate_end": row["candidate_end"],
                "duration_minutes": row["candidate_duration_minutes"],
                "collector": row["collector"],
                "rib_before": ev["rib_before"],
                "rib_after": ev["rib_after"],
                "origin_stable": ev["origin_stable"],
                "route_presence_stable": ev["route_presence_stable"],
                "known_incident_overlap": ev["known_incident_overlap"],
                "exclusion_buffer_pass": ev["exclusion_buffer_pass"],
                "partition": "train",
                "pilot_version": PILOT_VERSION,
            }
        )
    if len(rows) != 8:
        raise ValueError(f"expected 8 second-pilot candidates, found {len(rows)}")
    write_csv(
        EXECUTION_MANIFEST,
        rows,
        [
            "candidate_period_id",
            "associated_incident_uid",
            "associated_category",
            "affected_asn",
            "affected_prefix",
            "candidate_start",
            "candidate_end",
            "duration_minutes",
            "collector",
            "rib_before",
            "rib_after",
            "origin_stable",
            "route_presence_stable",
            "known_incident_overlap",
            "exclusion_buffer_pass",
            "partition",
            "pilot_version",
        ],
    )
    return rows


def download_one(row: dict[str, object]) -> dict[str, object]:
    destination = Path(str(row["local_path"]))
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and destination.stat().st_size > 0:
        return {**row, "download_status": "PASS" if compression_ok(destination) else "FAIL", "file_size": destination.stat().st_size, "checksum": checksum(destination), "download_timestamp": isoformat_z(datetime.now(timezone.utc)), "notes": "cached"}
    request = Request(str(row["mrt_url"]), headers={"User-Agent": "bgp-incident-detection-pipeline/0.1"})
    try:
        with urlopen(request, timeout=180) as response:
            destination.write_bytes(response.read())
    except (HTTPError, URLError) as error:
        return {**row, "download_status": "FAIL", "file_size": 0, "checksum": "", "download_timestamp": isoformat_z(datetime.now(timezone.utc)), "notes": str(error)}
    ok = destination.exists() and destination.stat().st_size > 0 and compression_ok(destination)
    return {**row, "download_status": "PASS" if ok else "FAIL", "file_size": destination.stat().st_size if destination.exists() else 0, "checksum": checksum(destination) if ok else "", "download_timestamp": isoformat_z(datetime.now(timezone.utc)), "notes": "downloaded"}


def download_updates() -> list[dict[str, object]]:
    manifest = {row["candidate_period_id"]: row for row in load_csv(EXECUTION_MANIFEST)}
    rows = []
    for row in load_csv(SECOND_ACQUISITION_PLAN):
        if row["remote_available"] != "True":
            rows.append({**row, "local_path": local_path(row["candidate_period_id"], row["mrt_url"]), "download_status": "FAIL", "file_size": 0, "checksum": "", "download_timestamp": "", "notes": "remote unavailable"})
            continue
        rows.append(
            download_one(
                {
                    "candidate_period_id": row["candidate_period_id"],
                    "associated_incident_uid": row["associated_incident_uid"],
                    "associated_category": row["category"],
                    "collector": row["collector"],
                    "mrt_timestamp": row["mrt_timestamp"],
                    "mrt_url": row["mrt_url"],
                    "local_path": local_path(row["candidate_period_id"], row["mrt_url"]),
                    "partition": manifest[row["candidate_period_id"]]["partition"],
                }
            )
        )
    write_csv(
        DOWNLOAD_FILE_STATUS,
        rows,
        ["candidate_period_id", "associated_incident_uid", "associated_category", "collector", "mrt_timestamp", "mrt_url", "local_path", "partition", "download_status", "file_size", "checksum", "download_timestamp", "notes"],
    )
    audit = []
    for candidate_id, group in group_by(rows, "candidate_period_id").items():
        planned = len(group)
        downloaded = sum(row["download_status"] == "PASS" for row in group)
        corrupted = sum(row["download_status"] == "FAIL" and int(row["file_size"]) > 0 for row in group)
        status = "PASS" if planned == downloaded and corrupted == 0 else "FAIL"
        audit.append(
            {
                "candidate_period_id": candidate_id,
                "associated_incident_uid": group[0]["associated_incident_uid"],
                "planned_files": planned,
                "downloaded_files": downloaded,
                "missing_files": planned - downloaded,
                "corrupted_files": corrupted,
                "total_bytes": sum(int(row["file_size"]) for row in group),
                "availability_percent": round(downloaded / planned * 100, 3) if planned else 0,
                "status": status,
            }
        )
    write_csv(DOWNLOAD_AUDIT, audit, ["candidate_period_id", "associated_incident_uid", "planned_files", "downloaded_files", "missing_files", "corrupted_files", "total_bytes", "availability_percent", "status"])
    return rows


def write_parser_environment() -> None:
    write_csv(
        PARSER_ENVIRONMENT,
        [
            {
                "tool_or_library": "bgpdump",
                "version": bgpdump_version(),
                "exact_command_or_function": "bgpdump -q -m <normal-second-pilot-file.bz2>",
                "input_format": "RouteViews MRT UPDATE .bz2",
                "output_fields": "|".join(PARSED_FIELDS),
                "row_granularity": "one prefix-level BGP UPDATE observation; multi-prefix UPDATE messages appear as multiple rows",
            }
        ],
        ["tool_or_library", "version", "exact_command_or_function", "input_format", "output_fields", "row_granularity"],
    )


def group_by(rows: list[dict[str, object]], key: str) -> dict[str, list[dict[str, object]]]:
    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        grouped[str(row[key])].append(row)
    return grouped


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


def relevant_to_candidate(parsed: dict[str, str], candidate: dict[str, str]) -> bool:
    asn = candidate["affected_asn"]
    prefix = candidate["affected_prefix"]
    if prefix and parsed["prefix"] == prefix:
        return True
    peer_origin = {parsed["peer_asn"], parsed["origin_asn"]}
    peer_origin.discard("")
    return bool(asn and (asn in peer_origin or asn in parse_as_path_set(parsed["as_path"])))


def parsed_output_path(candidate_period_id: str) -> Path:
    return PARSED_DIR / candidate_period_id / "parsed_bgp_observations.csv"


def parse_and_window(status_rows: list[dict[str, object]]) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    candidates = {row["candidate_period_id"]: row for row in load_csv(EXECUTION_MANIFEST)}
    stats: dict[str, ParseStats] = defaultdict(ParseStats)
    parsed_by_candidate: dict[str, list[dict[str, str]]] = defaultdict(list)
    aggs: dict[str, WindowAggregate] = defaultdict(WindowAggregate)
    window_meta: dict[str, dict[str, object]] = {}
    raw_window_counts: Counter[str] = Counter()

    for row in status_rows:
        if row["download_status"] != "PASS":
            continue
        candidate_id = str(row["candidate_period_id"])
        candidate = candidates[candidate_id]
        stats[candidate_id].file_count += 1
        command = ["bgpdump", "-q", "-m", str(row["local_path"])]
        process = subprocess.Popen(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert process.stdout is not None
        for line in process.stdout:
            parsed = parse_bgpdump_line(line, candidate_id, Path(str(row["local_path"])), str(row["collector"]))
            if parsed is None:
                continue
            parsed_by_candidate[candidate_id].append(parsed)
            stat = stats[candidate_id]
            stat.parsed_records += 1
            if parsed["announcement_or_withdrawal"] == "announcement":
                stat.announcements += 1
            elif parsed["announcement_or_withdrawal"] == "withdrawal":
                stat.withdrawals += 1
            timestamp = parse_utc(parsed["bgp_timestamp_utc"])
            if not timestamp:
                continue
            start = parse_required(candidate["candidate_start"])
            end = parse_required(candidate["candidate_end"])
            if not (start <= timestamp < end):
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
            if not relevant_to_candidate(parsed, candidate):
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
            update_aggregate(aggs[wid], parsed)
        stderr = process.stderr.read() if process.stderr else ""
        if process.wait() != 0:
            stats[candidate_id].parse_failures += 1
            if stderr:
                print(stderr)

    for candidate in candidates.values():
        cursor = floor_to_five_minutes(parse_required(candidate["candidate_start"]))
        end = parse_required(candidate["candidate_end"])
        while cursor < end:
            wid = window_id(candidate["candidate_period_id"], cursor)
            window_meta.setdefault(
                wid,
                {
                    "candidate_period_id": candidate["candidate_period_id"],
                    "associated_incident_uid": candidate["associated_incident_uid"],
                    "associated_category": candidate["associated_category"],
                    "partition": candidate["partition"],
                    "window_id": wid,
                    "window_start": format_utc(cursor),
                    "window_end": format_utc(cursor + timedelta(minutes=5)),
                    "raw_observation_count": 0,
                },
            )
            aggs.setdefault(wid, WindowAggregate())
            cursor += timedelta(minutes=5)
    for wid, count in raw_window_counts.items():
        window_meta[wid]["raw_observation_count"] = count

    for candidate_id, rows in parsed_by_candidate.items():
        write_csv(parsed_output_path(candidate_id), rows, PARSED_FIELDS)

    raw_counts = []
    relevance = []
    for candidate_id, stat in sorted(stats.items()):
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
                "notes": "relevance uses affected ASN plus exact prefix when available; global unrelated observations are excluded from features",
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


def path_instability_status(row: dict[str, object]) -> str:
    if int(row["update_count"]) == 0:
        return "STABLE_SILENCE"
    if int(row["unique_as_path_count"]) <= 2 and int(row["multi_path_prefix_count"]) <= 1:
        return "LOW"
    return "HIGH"


def qualify(feature_rows: list[dict[str, object]]) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    candidates = {row["candidate_period_id"]: row for row in load_csv(EXECUTION_MANIFEST)}
    preliminary = []
    for row in feature_rows:
        candidate = candidates[str(row["candidate_period_id"])]
        rib_route = candidate["route_presence_stable"] == "True"
        rib_origin = candidate["origin_stable"] == "True"
        origin_changes = int(row["origin_change_event_count"])
        instability = path_instability_status(row)
        suspicious = bool(
            origin_changes > 0
            or instability == "HIGH"
            or int(row["moas_prefix_count"]) > 0
            or int(row["unique_prefix_count"]) > (1 if candidate["affected_prefix"] else 25)
        )
        stable_silence = int(row["update_count"]) == 0 and rib_route and rib_origin
        passed = []
        failed = []
        for check, ok in [
            ("no_known_related_incident_overlap", candidate["known_incident_overlap"] == "False"),
            ("outside_60_minute_exclusion_buffer", candidate["exclusion_buffer_pass"] == "True"),
            ("rib_route_confirmed", rib_route),
            ("rib_origin_stable", rib_origin),
            ("no_suspicious_relevant_update_activity", not suspicious),
            ("no_major_as_path_instability", instability != "HIGH"),
            ("no_suspicious_prefix_deaggregation", int(row["unique_prefix_count"]) <= (1 if candidate["affected_prefix"] else 25)),
            ("no_unexpected_moas_origin_diversity", int(row["moas_prefix_count"]) == 0),
        ]:
            (passed if ok else failed).append(check)
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
                "path_instability_status": instability,
                "suspicious_update_detected": str(suspicious),
                "stable_silence": str(stable_silence),
                "consecutive_stable_windows": 0,
                "qualification_checks_passed": json.dumps(passed, separators=(",", ":")),
                "qualification_checks_failed": json.dumps(failed, separators=(",", ":")),
                "_stable": not failed,
            }
        )

    rows = []
    for candidate_id, group in group_by(preliminary, "candidate_period_id").items():
        run_lengths = [0] * len(group)
        run = 0
        for index, row in enumerate(group):
            run = run + 1 if row["_stable"] else 0
            run_lengths[index] = run
        suffix_run = 0
        in_sustained_block = [False] * len(group)
        for index in range(len(group) - 1, -1, -1):
            suffix_run = suffix_run + 1 if group[index]["_stable"] else 0
            if suffix_run >= MIN_STABLE_WINDOWS:
                for member in range(index, index + suffix_run):
                    in_sustained_block[member] = True
        for index, row in enumerate(group):
            output_row = dict(row)
            output_row.pop("_stable")
            output_row["consecutive_stable_windows"] = run_lengths[index]
            final_state = "NORMAL_VERIFIED" if row["_stable"] and in_sustained_block[index] else "UNKNOWN"
            output_row["final_state"] = final_state
            output_row["reason"] = "member of a sustained RIB-confirmed 30-minute stable block" if final_state == "NORMAL_VERIFIED" else "insufficient sustained stable block or failed stability checks"
            rows.append(output_row)
    results = []
    for candidate_id, group in group_by(rows, "candidate_period_id").items():
        normal = sum(row["final_state"] == "NORMAL_VERIFIED" for row in group)
        unknown = len(group) - normal
        longest = max(int(row["consecutive_stable_windows"]) for row in group) * 5 if group else 0
        status = "PASS" if normal > 0 else "REVIEW"
        failures = sorted({reason for row in group for reason in json.loads(str(row["qualification_checks_failed"]))})
        results.append(
            {
                "candidate_period_id": candidate_id,
                "associated_incident_uid": group[0]["associated_incident_uid"],
                "category": group[0]["associated_category"],
                "total_windows": len(group),
                "normal_verified_windows": normal,
                "unknown_windows": unknown,
                "normal_yield_percent": round(normal / len(group) * 100, 3) if group else 0,
                "longest_stable_block_minutes": longest,
                "candidate_final_status": status,
                "failure_reason_if_any": ";".join(failures),
            }
        )
    return rows, results


def compare_pilots(second_candidates: list[dict[str, object]], qualification: list[dict[str, object]]) -> list[dict[str, object]]:
    first = load_csv(FIRST_NORMAL_QUALIFICATION)
    first_periods = {row["candidate_period_id"] for row in first}
    first_verified = sum(row["final_state"] == "NORMAL_VERIFIED" for row in first)
    first_unknown = sum(row["final_state"] == "UNKNOWN" for row in first)
    second_verified = sum(row["final_state"] == "NORMAL_VERIFIED" for row in qualification)
    second_unknown = sum(row["final_state"] == "UNKNOWN" for row in qualification)
    second_periods = {row["candidate_period_id"] for row in second_candidates}
    return [
        {
            "pilot": "FIRST_NORMAL_PILOT",
            "candidate_periods": len(first_periods),
            "rib_visible_periods": "see normal_rib_update_qualification_results_v1.csv",
            "total_candidate_windows": len(first),
            "normal_verified_windows": first_verified,
            "unknown_windows": first_unknown,
            "normal_yield_percent": round(first_verified / len(first) * 100, 3) if first else 0,
            "candidate_success_rate": "see first-pilot candidate-level outputs",
            "reasons_for_failure": "first pilot retained UNKNOWN where RIB/UPDATE stability evidence was insufficient",
        },
        {
            "pilot": "SECOND_NORMAL_PILOT",
            "candidate_periods": len(second_periods),
            "rib_visible_periods": len(second_periods),
            "total_candidate_windows": len(qualification),
            "normal_verified_windows": second_verified,
            "unknown_windows": second_unknown,
            "normal_yield_percent": round(second_verified / len(qualification) * 100, 3) if qualification else 0,
            "candidate_success_rate": round(sum(row["candidate_final_status"] == "PASS" for row in second_candidates) / len(second_candidates) * 100, 3) if second_candidates else 0,
            "reasons_for_failure": "second pilot uses RIB-prescreened candidates; remaining UNKNOWN windows indicate update instability or insufficient sustained block",
        },
    ]


def run() -> dict[str, object]:
    execution = freeze_execution_manifest()
    status = download_updates()
    write_parser_environment()
    raw_counts, relevance, window_counts, feature_rows = parse_and_window(status)
    pd.DataFrame(feature_rows).to_parquet(FEATURES, index=False)
    write_csv(RAW_COUNTS, raw_counts, ["candidate_period_id", "associated_incident_uid", "associated_category", "mrt_file_count", "parsed_mrt_records", "bgp_update_messages", "announcement_observations", "withdrawal_observations", "total_prefix_level_observations", "parse_failures"])
    write_csv(RELEVANCE_SUMMARY, relevance, ["candidate_period_id", "associated_incident_uid", "associated_category", "total_parsed_observations", "directly_matching_observations", "match_percent", "matching_asn_count", "matching_prefix_count", "notes"])
    write_csv(WINDOW_COUNTS, window_counts, ["associated_incident_uid", "associated_category", "candidate_period_id", "window_id", "window_start", "window_end", "raw_observation_count", "relevant_observation_count", "announcement_count", "withdrawal_count", "unique_prefixes", "unique_peer_asns", "unique_origin_asns", "unique_as_paths"])
    qualification, candidate_results = qualify(feature_rows)
    write_csv(QUALIFICATION_RESULTS, qualification, ["candidate_period_id", "associated_incident_uid", "associated_category", "window_id", "window_start", "window_end", "rib_route_confirmed", "rib_origin_stable", "relevant_update_count", "announcement_count", "withdrawal_count", "origin_change_count", "path_instability_status", "suspicious_update_detected", "stable_silence", "consecutive_stable_windows", "qualification_checks_passed", "qualification_checks_failed", "final_state", "reason"])
    write_csv(CANDIDATE_RESULTS, candidate_results, ["candidate_period_id", "associated_incident_uid", "category", "total_windows", "normal_verified_windows", "unknown_windows", "normal_yield_percent", "longest_stable_block_minutes", "candidate_final_status", "failure_reason_if_any"])
    write_csv(PILOT_COMPARISON, compare_pilots(candidate_results, qualification), ["pilot", "candidate_periods", "rib_visible_periods", "total_candidate_windows", "normal_verified_windows", "unknown_windows", "normal_yield_percent", "candidate_success_rate", "reasons_for_failure"])
    return {
        "execution_candidates": len(execution),
        "planned_files": len(status),
        "downloaded_files": sum(row["download_status"] == "PASS" for row in status),
        "total_bytes": sum(int(row["file_size"]) for row in status),
        "parsed_prefix_observations": sum(int(row["total_prefix_level_observations"]) for row in raw_counts),
        "candidate_windows": len(qualification),
        "normal_verified_windows": sum(row["final_state"] == "NORMAL_VERIFIED" for row in qualification),
        "unknown_windows": sum(row["final_state"] == "UNKNOWN" for row in qualification),
        "candidate_passes": sum(row["candidate_final_status"] == "PASS" for row in candidate_results),
    }


def prepare_summary() -> dict[str, object]:
    execution = freeze_execution_manifest()
    plan = load_csv(SECOND_ACQUISITION_PLAN)
    return {
        "execution_candidates": len(execution),
        "planned_files": len(plan),
        "remote_availability": dict(Counter(row["remote_available"] for row in plan)),
        "estimated_mib": round(sum(int(row["estimated_content_length"]) for row in plan) / 1024 / 1024, 2),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the second TRAIN-only Normal UPDATE qualification pilot.")
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if args.prepare_only:
        print(json.dumps(prepare_summary(), indent=2))
        return
    if args.run:
        print(json.dumps(run(), indent=2))
        return
    parser.error("choose --prepare-only or --run")


if __name__ == "__main__":
    main()
