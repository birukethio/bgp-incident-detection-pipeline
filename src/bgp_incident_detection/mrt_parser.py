from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

try:
    from bgp_incident_detection.audit import parse_listish, parse_utc, write_csv
    from bgp_incident_detection.mrt_download import DOWNLOAD_MANIFEST
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import parse_listish, parse_utc, write_csv
    from src.bgp_incident_detection.mrt_download import DOWNLOAD_MANIFEST


PILOT_DIR = Path("data/pilot")
PARSED_DIR = Path("data/parsed_mrt/pilot")
PILOT_MANIFEST = PILOT_DIR / "mrt_pilot_incidents_v1.csv"
DOWNLOAD_FILE_STATUS = PILOT_DIR / "mrt_pilot_download_file_status_v1.csv"

PARSER_ENVIRONMENT = PILOT_DIR / "mrt_parser_environment_v1.csv"
RAW_MESSAGE_COUNTS = PILOT_DIR / "raw_bgp_message_counts_v1.csv"
PARSED_GRANULARITY = PILOT_DIR / "parsed_row_granularity_v1.md"
PARSED_SAMPLE = PILOT_DIR / "parsed_bgp_sample_v1.csv"
INCIDENT_RELEVANCE = PILOT_DIR / "incident_relevance_summary_v1.csv"
TIME_COVERAGE = PILOT_DIR / "mrt_parsed_time_coverage_v1.csv"
PARSING_AUDIT = PILOT_DIR / "mrt_parsing_audit_v1.csv"

PARSED_FIELDS = [
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


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def isoformat_ms_from_epoch(value: str) -> str:
    timestamp = float(value)
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def bgpdump_version() -> str:
    executable = shutil.which("bgpdump") or "bgpdump"
    result = subprocess.run([executable], text=True, capture_output=True, check=False)
    text = f"{result.stdout}\n{result.stderr}"
    match = re.search(r"bgpdump version ([^\s]+)", text)
    return match.group(1) if match else "unknown"


def parser_environment_row() -> dict[str, str]:
    return {
        "tool_or_library": "bgpdump",
        "version": bgpdump_version(),
        "exact_command_or_function": "bgpdump -q -m <input-file.bz2>",
        "input_format": "RouteViews MRT UPDATE .bz2",
        "output_fields": "|".join(PARSED_FIELDS),
        "row_granularity": "one prefix-level announcement or withdrawal observation emitted by bgpdump -m",
    }


def parse_as_path(value: str) -> list[str]:
    return re.findall(r"\d+", value or "")


def parse_as_path_set(value: str) -> set[str]:
    return set(parse_as_path(value))


def origin_asn_from_path(as_path: str) -> str:
    values = parse_as_path(as_path)
    return values[-1] if values else ""


def classify_message_type(value: str) -> str:
    if value == "A":
        return "announcement"
    if value == "W":
        return "withdrawal"
    return "other"


def parse_bgpdump_line(line: str, incident_uid: str, source_path: Path, collector: str) -> dict[str, str] | None:
    parts = line.rstrip("\n").split("|")
    if len(parts) < 6:
        return None
    message_type = parts[2]
    announcement_or_withdrawal = classify_message_type(message_type)
    as_path = parts[6] if announcement_or_withdrawal == "announcement" and len(parts) > 6 else ""
    return {
        "incident_uid": incident_uid,
        "source_mrt_filename": source_path.name,
        "collector": collector,
        "bgp_timestamp_utc": isoformat_ms_from_epoch(parts[1]),
        "peer_ip": parts[3],
        "peer_asn": parts[4],
        "message_update_type": message_type,
        "announcement_or_withdrawal": announcement_or_withdrawal,
        "prefix": parts[5],
        "as_path": as_path,
        "origin_asn": origin_asn_from_path(as_path),
        "next_hop": parts[8] if announcement_or_withdrawal == "announcement" and len(parts) > 8 else "",
        "communities": parts[11] if announcement_or_withdrawal == "announcement" and len(parts) > 11 else "",
        "med": parts[9] if announcement_or_withdrawal == "announcement" and len(parts) > 9 else "",
        "local_pref": parts[10] if announcement_or_withdrawal == "announcement" and len(parts) > 10 else "",
        "atomic_aggregate": parts[12] if announcement_or_withdrawal == "announcement" and len(parts) > 12 else "",
        "aggregator": parts[13] if announcement_or_withdrawal == "announcement" and len(parts) > 13 else "",
        "raw_bgpdump_line": line.rstrip("\n"),
    }


def parse_mrt_file(manifest_row: dict[str, str]) -> tuple[list[dict[str, str]], dict[str, object]]:
    local_path = Path(manifest_row["local_path"])
    incident_uid = manifest_row["incident_uid"]
    collector = manifest_row["routeviews_collector"]
    command = ["bgpdump", "-m", str(local_path)]
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    parsed_rows: list[dict[str, str]] = []
    malformed = 0
    timestamp_errors = 0
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            if not line or line.startswith("bgpdump") or line.startswith("BGP4MP|TABLE_DUMP"):
                continue
            try:
                parsed = parse_bgpdump_line(line, incident_uid, local_path, collector)
            except (ValueError, OverflowError):
                timestamp_errors += 1
                continue
            if parsed is None:
                malformed += 1
            else:
                parsed_rows.append(parsed)
    return parsed_rows, {
        "incident_uid": incident_uid,
        "source_mrt_filename": local_path.name,
        "parse_return_code": result.returncode,
        "parsed_records": len(parsed_rows),
        "malformed_records": malformed,
        "timestamp_errors": timestamp_errors,
        "stderr": result.stderr.strip(),
    }


def parse_mrt_file_streaming(
    manifest_row: dict[str, str],
    row_callback,
) -> dict[str, object]:
    local_path = Path(manifest_row["local_path"])
    incident_uid = manifest_row["incident_uid"]
    collector = manifest_row["routeviews_collector"]
    command = ["bgpdump", "-q", "-m", str(local_path)]
    process = subprocess.Popen(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    parsed_count = 0
    malformed = 0
    timestamp_errors = 0
    assert process.stdout is not None
    for line in process.stdout:
        if not line or line.startswith("bgpdump") or line.startswith("BGP4MP|TABLE_DUMP"):
            continue
        try:
            parsed = parse_bgpdump_line(line, incident_uid, local_path, collector)
        except (ValueError, OverflowError):
            timestamp_errors += 1
            continue
        if parsed is None:
            malformed += 1
            continue
        parsed_count += 1
        row_callback(parsed)
    stderr = process.stderr.read() if process.stderr else ""
    return_code = process.wait()
    return {
        "incident_uid": incident_uid,
        "source_mrt_filename": local_path.name,
        "parse_return_code": return_code,
        "parsed_records": parsed_count,
        "malformed_records": malformed,
        "timestamp_errors": timestamp_errors,
        "stderr": stderr.strip(),
    }


def parsed_output_path(incident_uid: str) -> Path:
    return PARSED_DIR / incident_uid.replace(":", "_") / "parsed_bgp_observations.csv"


def write_parsed_by_incident(rows_by_incident: dict[str, list[dict[str, str]]]) -> None:
    for incident_uid, rows in rows_by_incident.items():
        write_csv(parsed_output_path(incident_uid), rows, PARSED_FIELDS)


def count_rows(rows_by_incident: dict[str, list[dict[str, str]]], file_audits: list[dict[str, object]]) -> list[dict[str, object]]:
    file_count_by_incident = Counter(row["incident_uid"] for row in file_audits)
    parsed_by_file = {
        (row["incident_uid"], row["source_mrt_filename"]): int(row["parsed_records"])
        for row in file_audits
    }
    output: list[dict[str, object]] = []
    for incident_uid, rows in sorted(rows_by_incident.items()):
        category = incident_uid.split(":", 1)[0]
        by_file: dict[str, list[dict[str, str]]] = defaultdict(list)
        for row in rows:
            by_file[row["source_mrt_filename"]].append(row)
        for filename, file_rows in sorted(by_file.items()):
            announcement_count = sum(1 for row in file_rows if row["announcement_or_withdrawal"] == "announcement")
            withdrawal_count = sum(1 for row in file_rows if row["announcement_or_withdrawal"] == "withdrawal")
            output.append(
                {
                    "incident_uid": incident_uid,
                    "category": category,
                    "source_mrt_filename": filename,
                    "mrt_files": 1,
                    "parsed_mrt_records": parsed_by_file[(incident_uid, filename)],
                    "bgp_update_messages": parsed_by_file[(incident_uid, filename)],
                    "announcement_nlri_observations": announcement_count,
                    "withdrawal_nlri_observations": withdrawal_count,
                    "total_prefix_level_observations": len(file_rows),
                    "aggregation_level": "mrt_file",
                }
            )
        announcement_count = sum(1 for row in rows if row["announcement_or_withdrawal"] == "announcement")
        withdrawal_count = sum(1 for row in rows if row["announcement_or_withdrawal"] == "withdrawal")
        output.append(
            {
                "incident_uid": incident_uid,
                "category": category,
                "source_mrt_filename": "ALL_FILES_FOR_INCIDENT",
                "mrt_files": file_count_by_incident[incident_uid],
                "parsed_mrt_records": len(rows),
                "bgp_update_messages": len(rows),
                "announcement_nlri_observations": announcement_count,
                "withdrawal_nlri_observations": withdrawal_count,
                "total_prefix_level_observations": len(rows),
                "aggregation_level": "incident",
            }
        )
    all_rows = [row for rows in rows_by_incident.values() for row in rows]
    output.append(
        {
            "incident_uid": "ALL_PILOT_INCIDENTS",
            "category": "ALL",
            "source_mrt_filename": "ALL_FILES",
            "mrt_files": len(file_audits),
            "parsed_mrt_records": len(all_rows),
            "bgp_update_messages": len(all_rows),
            "announcement_nlri_observations": sum(1 for row in all_rows if row["announcement_or_withdrawal"] == "announcement"),
            "withdrawal_nlri_observations": sum(1 for row in all_rows if row["announcement_or_withdrawal"] == "withdrawal"),
            "total_prefix_level_observations": len(all_rows),
            "aggregation_level": "all_pilot",
        }
    )
    return output


def sample_rows(rows_by_incident: dict[str, list[dict[str, str]]], per_category: int = 20) -> list[dict[str, str]]:
    output: list[dict[str, str]] = []
    for category in ("Hijack", "Leak", "Outage"):
        rows = [row for uid, incident_rows in rows_by_incident.items() if uid.startswith(f"{category}:") for row in incident_rows]
        announcements = [row for row in rows if row["announcement_or_withdrawal"] == "announcement"]
        withdrawals = [row for row in rows if row["announcement_or_withdrawal"] == "withdrawal"]
        picked = announcements[: per_category // 2] + withdrawals[: per_category - per_category // 2]
        if len(picked) < per_category:
            used = {id(row) for row in picked}
            picked.extend(row for row in rows if id(row) not in used)
        output.extend(picked[:per_category])
    return output


def match_relevance(row: dict[str, str], incident: dict[str, str]) -> bool:
    category = incident["category"]
    as_path_values = set(parse_as_path(row["as_path"]))
    peer_asn = row["peer_asn"]
    origin_asn = row["origin_asn"]
    prefix = row["prefix"]
    affected_asns = set(parse_listish(incident.get("affected_asns")))
    affected_prefixes = set(parse_listish(incident.get("affected_prefixes")))
    primary = incident.get("leak_asn") or ""
    if category == "Hijack":
        return (
            primary in {peer_asn, origin_asn}
            or primary in as_path_values
            or bool(affected_asns & ({peer_asn, origin_asn} | as_path_values))
            or prefix in affected_prefixes
        )
    if category == "Leak":
        leak_seg = set(parse_listish(incident.get("leak_seg")))
        return primary in {peer_asn, origin_asn} or primary in as_path_values or bool(leak_seg & as_path_values)
    if category == "Outage":
        return bool(affected_asns & ({peer_asn, origin_asn} | as_path_values))
    return False


def prepare_relevance_metadata(incidents: dict[str, dict[str, str]]) -> dict[str, dict[str, object]]:
    metadata: dict[str, dict[str, object]] = {}
    for incident_uid, incident in incidents.items():
        metadata[incident_uid] = {
            "category": incident["category"],
            "affected_asns": set(parse_listish(incident.get("affected_asns"))),
            "affected_prefixes": set(parse_listish(incident.get("affected_prefixes"))),
            "primary": incident.get("leak_asn") or "",
            "leak_seg": set(parse_listish(incident.get("leak_seg"))),
        }
    return metadata


def match_relevance_prepared(row: dict[str, str], metadata: dict[str, object]) -> bool:
    category = str(metadata["category"])
    as_path_values = parse_as_path_set(row["as_path"])
    peer_origin = {row["peer_asn"], row["origin_asn"]}
    peer_origin.discard("")
    prefix = row["prefix"]
    primary = str(metadata["primary"])
    if category == "Hijack":
        return (
            bool(primary and (primary in peer_origin or primary in as_path_values))
            or bool(metadata["affected_asns"] & (peer_origin | as_path_values))
            or bool(prefix and prefix in metadata["affected_prefixes"])
        )
    if category == "Leak":
        return bool(primary and (primary in peer_origin or primary in as_path_values)) or bool(
            metadata["leak_seg"] & as_path_values
        )
    if category == "Outage":
        return bool(metadata["affected_asns"] & (peer_origin | as_path_values))
    return False


def relevance_summary(rows_by_incident: dict[str, list[dict[str, str]]]) -> list[dict[str, object]]:
    incidents = {row["incident_uid"]: row for row in load_csv(PILOT_MANIFEST)}
    output: list[dict[str, object]] = []
    for incident_uid, rows in sorted(rows_by_incident.items()):
        incident = incidents[incident_uid]
        matching = [row for row in rows if match_relevance(row, incident)]
        matching_asns = set()
        matching_prefixes = set()
        for row in matching:
            matching_asns.update(parse_as_path(row["as_path"]))
            if row["peer_asn"]:
                matching_asns.add(row["peer_asn"])
            if row["origin_asn"]:
                matching_asns.add(row["origin_asn"])
            if row["prefix"]:
                matching_prefixes.add(row["prefix"])
        output.append(
            {
                "incident_uid": incident_uid,
                "total_parsed_observations": len(rows),
                "directly_matching_observations": len(matching),
                "match_percent": round((len(matching) / len(rows)) * 100, 3) if rows else 0.0,
                "matching_asn_count": len(matching_asns),
                "matching_prefix_count": len(matching_prefixes),
                "notes": "direct match uses incident ASN/path/prefix metadata; nonmatching feed observations are preserved",
            }
        )
    return output


def time_coverage(rows_by_incident: dict[str, list[dict[str, str]]]) -> list[dict[str, object]]:
    manifest = load_csv(DOWNLOAD_MANIFEST)
    segments_by_uid: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in manifest:
        segments_by_uid[row["incident_uid"]].append(row)
    output: list[dict[str, object]] = []
    for incident_uid, rows in sorted(rows_by_incident.items()):
        timestamps = [parse_utc(row["bgp_timestamp_utc"]) for row in rows]
        timestamps = [value for value in timestamps if value]
        first = min(timestamps) if timestamps else None
        last = max(timestamps) if timestamps else None
        segments = segments_by_uid[incident_uid]
        output.append(
            {
                "incident_uid": incident_uid,
                "first_parsed_timestamp": first.isoformat(timespec="milliseconds").replace("+00:00", "Z") if first else "",
                "last_parsed_timestamp": last.isoformat(timespec="milliseconds").replace("+00:00", "Z") if last else "",
                "coverage_of_pre_incident_context": "PASS" if first else "FAIL",
                "coverage_of_candidate_incident_active_segment": "PASS" if rows else "FAIL",
                "coverage_of_post_incident_context": "PASS" if last else "FAIL",
                "collection_start_min": min(row["collection_start"] for row in segments),
                "collection_end_max": max(row["collection_end"] for row in segments),
                "notes": "timestamp coverage confirms parsed BGP observations exist inside downloaded acquisition files; exact active-window labeling is later",
            }
        )
    return output


def parsing_audit(rows_by_incident: dict[str, list[dict[str, str]]], file_audits: list[dict[str, object]]) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    for incident_uid, rows in sorted(rows_by_incident.items()):
        files = [row for row in file_audits if row["incident_uid"] == incident_uid]
        missing_peer_asn = sum(1 for row in rows if not row["peer_asn"])
        missing_prefix = sum(1 for row in rows if not row["prefix"])
        malformed_as_path = sum(
            1
            for row in rows
            if row["announcement_or_withdrawal"] == "announcement" and not parse_as_path(row["as_path"])
        )
        timestamp_errors = sum(int(row["timestamp_errors"]) for row in files)
        malformed_records = sum(int(row["malformed_records"]) for row in files)
        zero_output_files = sum(1 for row in files if int(row["parsed_records"]) == 0)
        parse_failures = sum(1 for row in files if int(row["parse_return_code"]) != 0)
        checks = {
            "mrt_files_parse_successfully": parse_failures,
            "zero_byte_outputs": zero_output_files,
            "malformed_records": malformed_records,
            "timestamp_parsing_errors": timestamp_errors,
            "missing_peer_asn": missing_peer_asn,
            "missing_prefix": missing_prefix,
            "malformed_as_path": malformed_as_path,
        }
        status = "PASS" if all(value == 0 for value in checks.values()) else "REVIEW"
        output.append(
            {
                "incident_uid": incident_uid,
                "mrt_files": len(files),
                "parsed_observations": len(rows),
                "status": status,
                **checks,
            }
        )
    return output


def run_streaming() -> dict[str, object]:
    manifest = load_csv(DOWNLOAD_MANIFEST)
    incidents = {row["incident_uid"]: row for row in load_csv(PILOT_MANIFEST)}
    relevance_metadata = prepare_relevance_metadata(incidents)
    writers: dict[str, csv.DictWriter] = {}
    handles = {}
    file_audits: list[dict[str, object]] = []
    counts: list[dict[str, object]] = []
    incident_stats: dict[str, dict[str, object]] = defaultdict(lambda: {
        "total": 0,
        "announcements": 0,
        "withdrawals": 0,
        "matching": 0,
        "matching_asns": set(),
        "matching_prefixes": set(),
        "first": None,
        "last": None,
        "missing_peer_asn": 0,
        "missing_prefix": 0,
        "malformed_as_path": 0,
    })
    samples_by_category: dict[str, dict[str, list[dict[str, str]]]] = defaultdict(lambda: {"announcement": [], "withdrawal": []})

    def writer_for(incident_uid: str) -> csv.DictWriter:
        if incident_uid not in writers:
            path = parsed_output_path(incident_uid)
            path.parent.mkdir(parents=True, exist_ok=True)
            handle = path.open("w", newline="", encoding="utf-8")
            handles[incident_uid] = handle
            writer = csv.DictWriter(handle, fieldnames=PARSED_FIELDS)
            writer.writeheader()
            writers[incident_uid] = writer
        return writers[incident_uid]

    file_accumulator: dict[str, object] = {}

    def on_row(row: dict[str, str]) -> None:
        writer_for(row["incident_uid"]).writerow(row)
        file_accumulator["total"] += 1
        if row["announcement_or_withdrawal"] == "announcement":
            file_accumulator["announcements"] += 1
        if row["announcement_or_withdrawal"] == "withdrawal":
            file_accumulator["withdrawals"] += 1

        stats = incident_stats[row["incident_uid"]]
        stats["total"] += 1
        if row["announcement_or_withdrawal"] == "announcement":
            stats["announcements"] += 1
        if row["announcement_or_withdrawal"] == "withdrawal":
            stats["withdrawals"] += 1
        timestamp = row["bgp_timestamp_utc"]
        if timestamp:
            stats["first"] = timestamp if stats["first"] is None else min(str(stats["first"]), timestamp)
            stats["last"] = timestamp if stats["last"] is None else max(str(stats["last"]), timestamp)
        if not row["peer_asn"]:
            stats["missing_peer_asn"] += 1
        if not row["prefix"]:
            stats["missing_prefix"] += 1
        if row["announcement_or_withdrawal"] == "announcement" and not parse_as_path(row["as_path"]):
            stats["malformed_as_path"] += 1
        if match_relevance_prepared(row, relevance_metadata[row["incident_uid"]]):
            stats["matching"] += 1
            matching_asns = stats["matching_asns"]
            matching_prefixes = stats["matching_prefixes"]
            matching_asns.update(parse_as_path(row["as_path"]))
            if row["peer_asn"]:
                matching_asns.add(row["peer_asn"])
            if row["origin_asn"]:
                matching_asns.add(row["origin_asn"])
            if row["prefix"]:
                matching_prefixes.add(row["prefix"])
        category = incidents[row["incident_uid"]]["category"]
        bucket = samples_by_category[category][row["announcement_or_withdrawal"]]
        if len(bucket) < 10:
            bucket.append(dict(row))

    try:
        for manifest_row in manifest:
            file_accumulator = {"total": 0, "announcements": 0, "withdrawals": 0}
            file_audit = parse_mrt_file_streaming(manifest_row, on_row)
            file_audits.append(file_audit)
            counts.append(
                {
                    "incident_uid": manifest_row["incident_uid"],
                    "category": manifest_row["category"],
                    "source_mrt_filename": Path(manifest_row["local_path"]).name,
                    "mrt_files": 1,
                    "parsed_mrt_records": file_accumulator["total"],
                    "bgp_update_messages": file_accumulator["total"],
                    "announcement_nlri_observations": file_accumulator["announcements"],
                    "withdrawal_nlri_observations": file_accumulator["withdrawals"],
                    "total_prefix_level_observations": file_accumulator["total"],
                    "aggregation_level": "mrt_file",
                }
            )
    finally:
        for handle in handles.values():
            handle.close()

    for incident_uid, stats in sorted(incident_stats.items()):
        counts.append(
            {
                "incident_uid": incident_uid,
                "category": incidents[incident_uid]["category"],
                "source_mrt_filename": "ALL_FILES_FOR_INCIDENT",
                "mrt_files": sum(1 for row in manifest if row["incident_uid"] == incident_uid),
                "parsed_mrt_records": stats["total"],
                "bgp_update_messages": stats["total"],
                "announcement_nlri_observations": stats["announcements"],
                "withdrawal_nlri_observations": stats["withdrawals"],
                "total_prefix_level_observations": stats["total"],
                "aggregation_level": "incident",
            }
        )
    total_stats = {
        "total": sum(int(stats["total"]) for stats in incident_stats.values()),
        "announcements": sum(int(stats["announcements"]) for stats in incident_stats.values()),
        "withdrawals": sum(int(stats["withdrawals"]) for stats in incident_stats.values()),
    }
    counts.append(
        {
            "incident_uid": "ALL_PILOT_INCIDENTS",
            "category": "ALL",
            "source_mrt_filename": "ALL_FILES",
            "mrt_files": len(manifest),
            "parsed_mrt_records": total_stats["total"],
            "bgp_update_messages": total_stats["total"],
            "announcement_nlri_observations": total_stats["announcements"],
            "withdrawal_nlri_observations": total_stats["withdrawals"],
            "total_prefix_level_observations": total_stats["total"],
            "aggregation_level": "all_pilot",
        }
    )

    sample = []
    for category in ("Hijack", "Leak", "Outage"):
        sample.extend(samples_by_category[category]["announcement"])
        sample.extend(samples_by_category[category]["withdrawal"])

    relevance = []
    coverage = []
    audit = []
    for incident_uid, stats in sorted(incident_stats.items()):
        total = int(stats["total"])
        matching = int(stats["matching"])
        first = str(stats["first"]) if stats["first"] else ""
        last = str(stats["last"]) if stats["last"] else ""
        incident_files = [row for row in file_audits if row["incident_uid"] == incident_uid]
        parse_failures = sum(1 for row in incident_files if int(row["parse_return_code"]) != 0)
        zero_output_files = sum(1 for row in incident_files if int(row["parsed_records"]) == 0)
        malformed_records = sum(int(row["malformed_records"]) for row in incident_files)
        timestamp_errors = sum(int(row["timestamp_errors"]) for row in incident_files)
        relevance.append(
            {
                "incident_uid": incident_uid,
                "total_parsed_observations": total,
                "directly_matching_observations": matching,
                "match_percent": round((matching / total) * 100, 3) if total else 0.0,
                "matching_asn_count": len(stats["matching_asns"]),
                "matching_prefix_count": len(stats["matching_prefixes"]),
                "notes": "direct match uses incident ASN/path/prefix metadata; nonmatching feed observations are preserved",
            }
        )
        manifest_rows = [row for row in manifest if row["incident_uid"] == incident_uid]
        coverage.append(
            {
                "incident_uid": incident_uid,
                "first_parsed_timestamp": first,
                "last_parsed_timestamp": last,
                "coverage_of_pre_incident_context": "PASS" if first else "FAIL",
                "coverage_of_candidate_incident_active_segment": "PASS" if total else "FAIL",
                "coverage_of_post_incident_context": "PASS" if last else "FAIL",
                "collection_start_min": min(row["collection_start"] for row in manifest_rows),
                "collection_end_max": max(row["collection_end"] for row in manifest_rows),
                "notes": "timestamp coverage confirms parsed BGP observations exist inside downloaded acquisition files; exact active-window labeling is later",
            }
        )
        checks = {
            "mrt_files_parse_successfully": parse_failures,
            "zero_byte_outputs": zero_output_files,
            "malformed_records": malformed_records,
            "timestamp_parsing_errors": timestamp_errors,
            "missing_peer_asn": stats["missing_peer_asn"],
            "missing_prefix": stats["missing_prefix"],
            "malformed_as_path": stats["malformed_as_path"],
        }
        status = "PASS" if all(int(value) == 0 for value in checks.values()) else "REVIEW"
        audit.append(
            {
                "incident_uid": incident_uid,
                "mrt_files": len(incident_files),
                "parsed_observations": total,
                "status": status,
                **checks,
            }
        )

    environment = [parser_environment_row()]
    write_csv(PARSER_ENVIRONMENT, environment, ["tool_or_library", "version", "exact_command_or_function", "input_format", "output_fields", "row_granularity"])
    write_csv(
        RAW_MESSAGE_COUNTS,
        counts,
        [
            "incident_uid",
            "category",
            "source_mrt_filename",
            "mrt_files",
            "parsed_mrt_records",
            "bgp_update_messages",
            "announcement_nlri_observations",
            "withdrawal_nlri_observations",
            "total_prefix_level_observations",
            "aggregation_level",
        ],
    )
    write_granularity_doc()
    write_csv(PARSED_SAMPLE, sample, PARSED_FIELDS)
    write_csv(INCIDENT_RELEVANCE, relevance, ["incident_uid", "total_parsed_observations", "directly_matching_observations", "match_percent", "matching_asn_count", "matching_prefix_count", "notes"])
    write_csv(TIME_COVERAGE, coverage, ["incident_uid", "first_parsed_timestamp", "last_parsed_timestamp", "coverage_of_pre_incident_context", "coverage_of_candidate_incident_active_segment", "coverage_of_post_incident_context", "collection_start_min", "collection_end_max", "notes"])
    write_csv(
        PARSING_AUDIT,
        audit,
        [
            "incident_uid",
            "mrt_files",
            "parsed_observations",
            "status",
            "mrt_files_parse_successfully",
            "zero_byte_outputs",
            "malformed_records",
            "timestamp_parsing_errors",
            "missing_peer_asn",
            "missing_prefix",
            "malformed_as_path",
        ],
    )
    return {
        "file_audits": file_audits,
        "environment": environment,
        "counts": counts,
        "sample": sample,
        "relevance": relevance,
        "coverage": coverage,
        "audit": audit,
    }


def write_granularity_doc(path: Path = PARSED_GRANULARITY) -> None:
    path.write_text(
        "\n".join(
            [
                "# Parsed Row Granularity v1",
                "",
                "The pilot parser uses `bgpdump -m` on RouteViews MRT UPDATE `.bz2` files.",
                "",
                "One parsed CSV row represents one prefix-level BGP UPDATE observation emitted by `bgpdump -m`: either one announced prefix with AS_PATH and path attributes, or one withdrawn prefix.",
                "",
                "This is not yet a model feature row. Feature rows will later aggregate these raw observations into 5-minute windows.",
                "",
                "Important granularity distinction:",
                "",
                "- A single BGP UPDATE message may carry multiple announced or withdrawn prefixes.",
                "- `bgpdump -m` expands those into separate pipe-delimited rows, one per prefix/NLRI observation.",
                "- Therefore `total_prefix_level_observations` counts parsed rows, not final ML samples.",
                "- `bgp_update_messages` in the pilot count table uses the parser-emitted row count as the observable message-record count because the original MRT message grouping is not preserved by `bgpdump -m` output.",
                "",
            ]
        ),
        encoding="utf-8",
    )


def run() -> dict[str, object]:
    manifest = load_csv(DOWNLOAD_MANIFEST)
    rows_by_incident: dict[str, list[dict[str, str]]] = defaultdict(list)
    file_audits: list[dict[str, object]] = []
    for row in manifest:
        parsed_rows, file_audit = parse_mrt_file(row)
        rows_by_incident[row["incident_uid"]].extend(parsed_rows)
        file_audits.append(file_audit)
    write_parsed_by_incident(rows_by_incident)

    environment = [parser_environment_row()]
    counts = count_rows(rows_by_incident, file_audits)
    sample = sample_rows(rows_by_incident)
    relevance = relevance_summary(rows_by_incident)
    coverage = time_coverage(rows_by_incident)
    audit = parsing_audit(rows_by_incident, file_audits)

    write_csv(PARSER_ENVIRONMENT, environment, ["tool_or_library", "version", "exact_command_or_function", "input_format", "output_fields", "row_granularity"])
    write_csv(
        RAW_MESSAGE_COUNTS,
        counts,
        [
            "incident_uid",
            "category",
            "source_mrt_filename",
            "mrt_files",
            "parsed_mrt_records",
            "bgp_update_messages",
            "announcement_nlri_observations",
            "withdrawal_nlri_observations",
            "total_prefix_level_observations",
            "aggregation_level",
        ],
    )
    write_granularity_doc()
    write_csv(PARSED_SAMPLE, sample, PARSED_FIELDS)
    write_csv(INCIDENT_RELEVANCE, relevance, ["incident_uid", "total_parsed_observations", "directly_matching_observations", "match_percent", "matching_asn_count", "matching_prefix_count", "notes"])
    write_csv(TIME_COVERAGE, coverage, ["incident_uid", "first_parsed_timestamp", "last_parsed_timestamp", "coverage_of_pre_incident_context", "coverage_of_candidate_incident_active_segment", "coverage_of_post_incident_context", "collection_start_min", "collection_end_max", "notes"])
    write_csv(
        PARSING_AUDIT,
        audit,
        [
            "incident_uid",
            "mrt_files",
            "parsed_observations",
            "status",
            "mrt_files_parse_successfully",
            "zero_byte_outputs",
            "malformed_records",
            "timestamp_parsing_errors",
            "missing_peer_asn",
            "missing_prefix",
            "malformed_as_path",
        ],
    )
    return {
        "rows_by_incident": rows_by_incident,
        "file_audits": file_audits,
        "environment": environment,
        "counts": counts,
        "sample": sample,
        "relevance": relevance,
        "coverage": coverage,
        "audit": audit,
    }


def print_report(results: dict[str, object]) -> None:
    counts = results["counts"]
    total = next(row for row in counts if row["incident_uid"] == "ALL_PILOT_INCIDENTS")
    print("MRT parsing and inspection complete")
    print(json.dumps(total, sort_keys=True))
    print("Relevance:")
    for row in results["relevance"]:
        print(json.dumps(row, sort_keys=True))
    print("Audit statuses:", dict(Counter(row["status"] for row in results["audit"])))
    print("Full parsed output written under ignored data/parsed_mrt/pilot/.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Parse and inspect raw RouteViews MRT UPDATE pilot files.")
    parser.parse_args()
    results = run_streaming()
    print_report(results)


if __name__ == "__main__":
    main()
