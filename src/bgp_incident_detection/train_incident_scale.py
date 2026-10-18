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
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from statistics import mean, median
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pandas as pd

try:
    from bgp_incident_detection.audit import parse_listish, parse_utc, write_csv
    from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES, WindowAggregate, features_from_aggregate, update_aggregate
    from bgp_incident_detection.mrt_acquisition import ceil_to_15_minutes, floor_to_15_minutes, iter_update_slots, routeviews_update_filename, routeviews_update_url
    from bgp_incident_detection.mrt_parser import parse_as_path_set, parse_bgpdump_line
    from bgp_incident_detection.windows import floor_to_five_minutes, format_utc, window_id
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import parse_listish, parse_utc, write_csv
    from src.bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES, WindowAggregate, features_from_aggregate, update_aggregate
    from src.bgp_incident_detection.mrt_acquisition import ceil_to_15_minutes, floor_to_15_minutes, iter_update_slots, routeviews_update_filename, routeviews_update_url
    from src.bgp_incident_detection.mrt_parser import parse_as_path_set, parse_bgpdump_line
    from src.bgp_incident_detection.windows import floor_to_five_minutes, format_utc, window_id


TRAIN_INCIDENTS = Path("data/partitions_v2/train_incidents_v2.csv")
TRAIN_SCALE_DIR = Path("data/train_scale")
MANIFEST = TRAIN_SCALE_DIR / "train_incident_processing_manifest_v1.csv"
BATCHES = TRAIN_SCALE_DIR / "train_processing_batches_v1.csv"
ACQUISITION_PLAN = TRAIN_SCALE_DIR / "train_mrt_acquisition_plan_v1.csv"
ACQUISITION_SUMMARY = TRAIN_SCALE_DIR / "train_mrt_acquisition_summary_v1.csv"
DOWNLOAD_AUDIT = TRAIN_SCALE_DIR / "train_mrt_download_audit_v1.csv"
FEATURES_PARQUET = TRAIN_SCALE_DIR / "train_incident_behavioral_features_v1.parquet"
FEATURE_SUMMARY = TRAIN_SCALE_DIR / "train_incident_feature_summary_v1.csv"
WINDOW_IMBALANCE = TRAIN_SCALE_DIR / "train_window_imbalance_analysis_v1.csv"
FEATURE_QUALITY = TRAIN_SCALE_DIR / "train_behavioral_feature_quality_audit_v1.csv"
QUALITY_GATE = TRAIN_SCALE_DIR / "train_incident_processing_quality_gate_v1.csv"
NOTEBOOK = Path("notebooks/28_train_incident_behavioral_scale.ipynb")

RAW_TRAIN_DIR = Path("data/raw_mrt/train")
PARSED_TRAIN_DIR = Path("data/parsed_mrt/train")
RAW_PILOT_DIR = Path("data/raw_mrt/pilot")
DEFAULT_COLLECTOR = "route-views2"
CONTEXT_BUFFER_MINUTES = 60
ACTIVE_GAP_RULE_MINUTES = 60
HIJACK_LEAK_BOUNDARY_ACTIVE_MINUTES = 5
DEFAULT_BATCH_SIZE = 50
BEHAVIORAL_FEATURE_VERSION = "v1"
BEHAVIORAL_FEATURE_COUNT = 44
USER_AGENT = "bgp-incident-detection-pipeline/0.1"

MANIFEST_FIELDS = [
    "incident_uid",
    "incident_id",
    "category",
    "start_utc",
    "end_utc",
    "duration_minutes",
    "affected_asns",
    "affected_prefixes",
    "leak_asn",
    "leak_seg",
    "partition",
    "roster_version",
    "split_version",
    "primary_asn",
    "countries",
    "source_url",
    "notes",
]


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


def isoformat_ms(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def safe_incident_dir(root: Path, incident_uid: str) -> Path:
    return root / incident_uid.replace(":", "_")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def compression_ok(path: Path) -> bool:
    try:
        with bz2.open(path, "rb") as handle:
            for _ in iter(lambda: handle.read(1024 * 1024), b""):
                pass
        return True
    except OSError:
        return False


def source_commit() -> str:
    try:
        result = subprocess.run(["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True)
        return result.stdout.strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        return "UNKNOWN"


def normalize_asn(value: object) -> str:
    text = str(value or "").strip()
    if not text or text.lower() == "nan":
        return ""
    if text.endswith(".0"):
        text = text[:-2]
    return text


def json_list(value: object) -> str:
    items = parse_listish(value)
    return json.dumps(items, separators=(",", ":"))


def load_train_incidents() -> list[dict[str, str]]:
    rows = load_csv(TRAIN_INCIDENTS)
    counts = Counter(row.get("category", "") for row in rows)
    if len(rows) != 993 or counts != {"Hijack": 331, "Leak": 331, "Outage": 331}:
        raise ValueError(f"unexpected TRAIN incident counts: total={len(rows)} counts={dict(counts)}")
    if {row.get("partition") for row in rows} != {"train"}:
        raise ValueError("TRAIN incident source contains non-train rows")
    return rows


def manifest_rows() -> list[dict[str, object]]:
    output = []
    for row in load_train_incidents():
        category = row["category"]
        leak_asn = normalize_asn(row.get("leak_asn") or (row.get("primary_asn") if category == "Leak" else ""))
        output.append(
            {
                "incident_uid": row["incident_uid"],
                "incident_id": row.get("incident_id", ""),
                "category": category,
                "start_utc": row["start_utc"],
                "end_utc": row["end_utc"],
                "duration_minutes": row.get("duration_minutes", ""),
                "affected_asns": json_list(row.get("affected_asns", "")),
                "affected_prefixes": json_list(row.get("affected_prefixes", "")),
                "leak_asn": leak_asn,
                "leak_seg": row.get("leak_seg", ""),
                "partition": row.get("partition", "train"),
                "roster_version": row.get("roster_version", "v2"),
                "split_version": row.get("split_version", "v2"),
                "primary_asn": normalize_asn(row.get("primary_asn", "")),
                "countries": json_list(row.get("countries", "")),
                "source_url": row.get("source_url", ""),
                "notes": row.get("notes", ""),
            }
        )
    return output


def batch_rows(manifest: list[dict[str, object]], batch_size: int = DEFAULT_BATCH_SIZE) -> list[dict[str, object]]:
    by_class = {category: [row for row in manifest if row["category"] == category] for category in ("Hijack", "Leak", "Outage")}
    ordered: list[dict[str, object]] = []
    while any(by_class.values()):
        for category in ("Hijack", "Leak", "Outage"):
            if by_class[category]:
                ordered.append(by_class[category].pop(0))
    rows = []
    for index, row in enumerate(ordered):
        rows.append(
            {
                "batch_id": f"batch_{index // batch_size + 1:03d}",
                "incident_uid": row["incident_uid"],
                "category": row["category"],
                "processing_status": "NOT_STARTED",
            }
        )
    return rows


def active_segments(incident: dict[str, object]) -> list[tuple[str, datetime, datetime, str]]:
    start = parse_required(str(incident["start_utc"]))
    end = parse_required(str(incident["end_utc"]))
    category = str(incident["category"])
    if category == "Outage":
        return [("active_001", start, end, "documented Cloudflare outage interval")]
    if (end - start).total_seconds() / 60 <= ACTIVE_GAP_RULE_MINUTES:
        return [("active_001", start, end, "short detector span within 60-minute active-window rule")]
    first_end = min(end, start + timedelta(minutes=HIJACK_LEAK_BOUNDARY_ACTIVE_MINUTES))
    last_start = max(start, end - timedelta(minutes=HIJACK_LEAK_BOUNDARY_ACTIVE_MINUTES))
    return [
        ("active_001", start, first_end, "detector-supported first evidence boundary; silent gap remains UNKNOWN"),
        ("active_002", last_start, end, "detector-supported last evidence boundary; silent gap remains UNKNOWN"),
    ]


def local_train_path(incident_uid: str, slot: datetime) -> Path:
    return safe_incident_dir(RAW_TRAIN_DIR, incident_uid) / routeviews_update_filename(slot)


def matching_pilot_path(incident_uid: str, slot: datetime) -> Path | None:
    path = safe_incident_dir(RAW_PILOT_DIR, incident_uid) / routeviews_update_filename(slot)
    return path if path.exists() and path.stat().st_size > 0 and compression_ok(path) else None


def acquisition_rows(manifest: list[dict[str, object]], batches: list[dict[str, object]]) -> list[dict[str, object]]:
    batch_by_uid = {row["incident_uid"]: row["batch_id"] for row in batches}
    rows = []
    seen: set[tuple[str, str]] = set()
    for incident in manifest:
        incident_uid = str(incident["incident_uid"])
        for segment_id, seg_start, seg_end, segment_notes in active_segments(incident):
            collection_start = floor_to_15_minutes(seg_start - timedelta(minutes=CONTEXT_BUFFER_MINUTES))
            collection_end = ceil_to_15_minutes(seg_end + timedelta(minutes=CONTEXT_BUFFER_MINUTES))
            for slot in iter_update_slots(collection_start, collection_end):
                key = (incident_uid, isoformat_z(slot))
                if key in seen:
                    continue
                seen.add(key)
                url = routeviews_update_url(slot, DEFAULT_COLLECTOR)
                pilot_path = matching_pilot_path(incident_uid, slot)
                local_path = local_train_path(incident_uid, slot)
                rows.append(
                    {
                        "batch_id": batch_by_uid[incident_uid],
                        "incident_uid": incident_uid,
                        "category": incident["category"],
                        "active_segment_id": f"{incident_uid.replace(':', '_')}_{segment_id}",
                        "segment_start": isoformat_ms(seg_start),
                        "segment_end": isoformat_ms(seg_end),
                        "temporal_status": "INCIDENT_ACTIVE",
                        "collection_start": isoformat_z(collection_start),
                        "collection_end": isoformat_z(collection_end),
                        "collector": DEFAULT_COLLECTOR,
                        "mrt_timestamp": isoformat_z(slot),
                        "mrt_url": url,
                        "local_path": str(local_path),
                        "pilot_reuse_path": str(pilot_path) if pilot_path else "",
                        "remote_available": "",
                        "status_code": "",
                        "estimated_content_length": "",
                        "notes": segment_notes,
                    }
                )
    return sorted(rows, key=lambda row: (str(row["batch_id"]), str(row["incident_uid"]), str(row["mrt_timestamp"])))


def head_url(url: str, timeout_seconds: float = 15.0) -> tuple[bool, str, int]:
    request = Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            return 200 <= response.status < 400, str(response.status), int(response.headers.get("Content-Length") or 0)
    except HTTPError as error:
        return False, str(error.code), 0
    except URLError:
        return False, "", 0


def estimate_acquisition(rows: list[dict[str, object]], check_remote: bool = False, workers: int = 24) -> list[dict[str, object]]:
    if not check_remote:
        previous = {row["mrt_url"]: row for row in load_csv(ACQUISITION_PLAN)}
        if previous:
            enriched_rows = []
            for row in rows:
                prior = previous.get(str(row["mrt_url"]), {})
                enriched = dict(row)
                for field in ("remote_available", "status_code", "estimated_content_length"):
                    if prior.get(field):
                        enriched[field] = prior[field]
                enriched_rows.append(enriched)
            return enriched_rows
        return rows
    urls = sorted({str(row["mrt_url"]) for row in rows})
    size_by_url: dict[str, tuple[bool, str, int]] = {}
    completed = 0
    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        futures = {executor.submit(head_url, url): url for url in urls}
        for future in as_completed(futures):
            url = futures[future]
            size_by_url[url] = future.result()
            completed += 1
            if completed % 1000 == 0:
                print(f"HEAD estimated {completed} / {len(urls)} unique URLs", flush=True)
    output = []
    for row in rows:
        url = str(row["mrt_url"])
        available, status, size = size_by_url[url]
        enriched = dict(row)
        enriched["remote_available"] = str(available)
        enriched["status_code"] = status
        enriched["estimated_content_length"] = size if available else 0
        output.append(enriched)
    return output


def summarize_acquisition(plan: list[dict[str, object]], manifest: list[dict[str, object]]) -> list[dict[str, object]]:
    rows = []
    manifest_by_uid = {str(row["incident_uid"]): row for row in manifest}
    for uid, group in group_by(plan, "incident_uid").items():
        incident = manifest_by_uid[uid]
        rows.append(
            {
                "summary_level": "incident",
                "batch_id": group[0]["batch_id"],
                "incident_uid": uid,
                "category": group[0]["category"],
                "duration_minutes": incident["duration_minutes"],
                "planned_file_count": len(group),
                "unique_url_count": len({row["mrt_url"] for row in group}),
                "estimated_compressed_bytes": sum(int(row.get("estimated_content_length") or 0) for row in group),
                "estimated_compressed_mib": round(sum(int(row.get("estimated_content_length") or 0) for row in group) / 1024 / 1024, 3),
                "collection_start_min": min(str(row["collection_start"]) for row in group),
                "collection_end_max": max(str(row["collection_end"]) for row in group),
            }
        )
    for category, group in group_by(plan, "category").items():
        rows.append(
            {
                "summary_level": "class",
                "batch_id": "",
                "incident_uid": "ALL",
                "category": category,
                "duration_minutes": "",
                "planned_file_count": len(group),
                "unique_url_count": len({row["mrt_url"] for row in group}),
                "estimated_compressed_bytes": sum(int(row.get("estimated_content_length") or 0) for row in group),
                "estimated_compressed_mib": round(sum(int(row.get("estimated_content_length") or 0) for row in group) / 1024 / 1024, 3),
                "collection_start_min": "",
                "collection_end_max": "",
            }
        )
    rows.append(
        {
            "summary_level": "all",
            "batch_id": "",
            "incident_uid": "ALL",
            "category": "ALL",
            "duration_minutes": "",
            "planned_file_count": len(plan),
            "unique_url_count": len({row["mrt_url"] for row in plan}),
            "estimated_compressed_bytes": sum(int(row.get("estimated_content_length") or 0) for row in plan),
            "estimated_compressed_mib": round(sum(int(row.get("estimated_content_length") or 0) for row in plan) / 1024 / 1024, 3),
            "collection_start_min": "",
            "collection_end_max": "",
        }
    )
    return rows


def group_by(rows: list[dict[str, object]], key: str) -> dict[str, list[dict[str, object]]]:
    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        grouped[str(row[key])].append(row)
    return grouped


def prepare(batch_size: int = DEFAULT_BATCH_SIZE, check_remote: bool = False, head_workers: int = 24) -> dict[str, object]:
    manifest = manifest_rows()
    batches = batch_rows(manifest, batch_size=batch_size)
    plan = estimate_acquisition(acquisition_rows(manifest, batches), check_remote=check_remote, workers=head_workers)
    summary = summarize_acquisition(plan, manifest)
    write_csv(MANIFEST, manifest, MANIFEST_FIELDS)
    write_csv(BATCHES, batches, ["batch_id", "incident_uid", "category", "processing_status"])
    write_csv(
        ACQUISITION_PLAN,
        plan,
        [
            "batch_id",
            "incident_uid",
            "category",
            "active_segment_id",
            "segment_start",
            "segment_end",
            "temporal_status",
            "collection_start",
            "collection_end",
            "collector",
            "mrt_timestamp",
            "mrt_url",
            "local_path",
            "pilot_reuse_path",
            "remote_available",
            "status_code",
            "estimated_content_length",
            "notes",
        ],
    )
    write_csv(
        ACQUISITION_SUMMARY,
        summary,
        ["summary_level", "batch_id", "incident_uid", "category", "duration_minutes", "planned_file_count", "unique_url_count", "estimated_compressed_bytes", "estimated_compressed_mib", "collection_start_min", "collection_end_max"],
    )
    write_notebook()
    counts = Counter(row["category"] for row in manifest)
    total_bytes = sum(int(row.get("estimated_content_length") or 0) for row in plan)
    top20 = sorted([row for row in summary if row["summary_level"] == "incident"], key=lambda row: (int(row["planned_file_count"]), int(row["estimated_compressed_bytes"])), reverse=True)[:20]
    return {
        "manifest_incidents": len(manifest),
        "manifest_counts": dict(counts),
        "train_only": {row["partition"] for row in manifest} == {"train"},
        "batch_count": len({row["batch_id"] for row in batches}),
        "batch_size": batch_size,
        "planned_file_assignments": len(plan),
        "unique_mrt_urls": len({row["mrt_url"] for row in plan}),
        "estimated_download_bytes": total_bytes,
        "estimated_download_gib": round(total_bytes / 1024 / 1024 / 1024, 3),
        "remote_checked": check_remote,
        "top20_largest_incidents": top20,
        "outputs": [str(MANIFEST), str(BATCHES), str(ACQUISITION_PLAN), str(ACQUISITION_SUMMARY), str(NOTEBOOK)],
    }


def copy_or_download(row: dict[str, str]) -> dict[str, object]:
    destination = Path(row["local_path"])
    destination.parent.mkdir(parents=True, exist_ok=True)
    pilot_path = Path(row["pilot_reuse_path"]) if row.get("pilot_reuse_path") else None
    if destination.exists() and destination.stat().st_size > 0 and compression_ok(destination):
        return {**row, "download_status": "CACHED", "file_size": destination.stat().st_size, "checksum": sha256(destination), "download_seconds": 0.0}
    if pilot_path and pilot_path.exists() and pilot_path.stat().st_size > 0 and compression_ok(pilot_path):
        shutil.copy2(pilot_path, destination)
        return {**row, "download_status": "REUSED_FROM_PILOT", "file_size": destination.stat().st_size, "checksum": sha256(destination), "download_seconds": 0.0}
    start = time.perf_counter()
    request = Request(row["mrt_url"], headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(request, timeout=180.0) as response, destination.open("wb") as handle:
            shutil.copyfileobj(response, handle, length=1024 * 1024)
            status = str(response.status)
    except (HTTPError, URLError, TimeoutError) as error:
        return {**row, "download_status": str(getattr(error, "code", "")) or "FAILED", "file_size": 0, "checksum": "", "download_seconds": round(time.perf_counter() - start, 3)}
    ok = destination.exists() and destination.stat().st_size > 0 and compression_ok(destination)
    return {**row, "download_status": status if ok else "CORRUPT", "file_size": destination.stat().st_size if destination.exists() else 0, "checksum": sha256(destination) if ok else "", "download_seconds": round(time.perf_counter() - start, 3)}


@dataclass
class IncidentStats:
    raw_mrt_files: int = 0
    raw_bgp_observations: int = 0
    relevant_observations: int = 0
    parse_failures: int = 0
    malformed_records: int = 0
    missing_peer_asn: int = 0
    missing_prefix: int = 0
    malformed_as_path: int = 0
    matching_asns: set[str] = field(default_factory=set)
    matching_prefixes: set[str] = field(default_factory=set)


def relevance_targets(incident: dict[str, object]) -> tuple[set[str], set[str], list[str]]:
    category = str(incident["category"])
    asns = set(parse_listish(incident.get("affected_asns", "")))
    primary = normalize_asn(incident.get("primary_asn", ""))
    if primary:
        asns.add(primary)
    leak_asn = normalize_asn(incident.get("leak_asn", ""))
    if category == "Leak" and leak_asn:
        asns.add(leak_asn)
    prefixes = set(parse_listish(incident.get("affected_prefixes", "")))
    leak_seg = parse_listish(incident.get("leak_seg", ""))
    return {normalize_asn(asn) for asn in asns if normalize_asn(asn)}, {str(prefix) for prefix in prefixes if str(prefix)}, [normalize_asn(asn) for asn in leak_seg if normalize_asn(asn)]


def relevant_with_targets(parsed: dict[str, str], target_asns: set[str], target_prefixes: set[str], leak_seg: list[str]) -> bool:
    if parsed["prefix"] and parsed["prefix"] in target_prefixes:
        return True
    path_set = parse_as_path_set(parsed["as_path"])
    peer_origin = {parsed["peer_asn"], parsed["origin_asn"]}
    peer_origin.discard("")
    if target_asns & (path_set | peer_origin):
        return True
    if leak_seg and all(asn in path_set for asn in leak_seg):
        return True
    return False


def relevant(parsed: dict[str, str], incident: dict[str, object]) -> bool:
    target_asns, target_prefixes, leak_seg = relevance_targets(incident)
    return relevant_with_targets(parsed, target_asns, target_prefixes, leak_seg)


def window_slots(start: datetime, end: datetime) -> list[datetime]:
    cursor = floor_to_five_minutes(start)
    stop = end
    slots = []
    while cursor < stop:
        slots.append(cursor)
        cursor += timedelta(minutes=5)
    return slots


def temporal_windows(incident: dict[str, object]) -> dict[str, dict[str, object]]:
    windows: dict[str, dict[str, object]] = {}
    for segment_id, seg_start, seg_end, _ in active_segments(incident):
        pre_start = seg_start - timedelta(minutes=CONTEXT_BUFFER_MINUTES)
        post_end = seg_end + timedelta(minutes=CONTEXT_BUFFER_MINUTES)
        for slot in window_slots(pre_start, seg_start):
            wid = window_id(str(incident["incident_uid"]), slot)
            windows[wid] = {"window_start": slot, "window_end": slot + timedelta(minutes=5), "temporal_status": "PRE_CONTEXT"}
        for slot in window_slots(seg_start, seg_end):
            wid = window_id(str(incident["incident_uid"]), slot)
            windows[wid] = {"window_start": slot, "window_end": slot + timedelta(minutes=5), "temporal_status": "INCIDENT_ACTIVE"}
        for slot in window_slots(seg_end, post_end):
            wid = window_id(str(incident["incident_uid"]), slot)
            windows[wid] = {"window_start": slot, "window_end": slot + timedelta(minutes=5), "temporal_status": "POST_CONTEXT"}
    return windows


def parse_and_feature_incident(incident: dict[str, object], download_rows: list[dict[str, object]]) -> tuple[list[dict[str, object]], IncidentStats]:
    stats = IncidentStats(raw_mrt_files=len(download_rows))
    windows = temporal_windows(incident)
    aggregates: dict[str, WindowAggregate] = {wid: WindowAggregate() for wid in windows}
    raw_window_counts: Counter[str] = Counter()
    target_asns, target_prefixes, leak_seg = relevance_targets(incident)
    text_targets = target_asns | target_prefixes
    parsed_path = safe_incident_dir(PARSED_TRAIN_DIR, str(incident["incident_uid"])) / "parsed_relevant_bgp_observations.csv"
    parsed_path.parent.mkdir(parents=True, exist_ok=True)
    with parsed_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["incident_uid", "source_mrt_filename", "collector", "bgp_timestamp_utc", "peer_ip", "peer_asn", "message_update_type", "announcement_or_withdrawal", "prefix", "as_path", "origin_asn", "next_hop", "communities", "med", "local_pref", "atomic_aggregate", "aggregator", "raw_bgpdump_line"])
        writer.writeheader()
        for row in download_rows:
            if row.get("download_status") not in {"200", "CACHED", "REUSED_FROM_PILOT"}:
                continue
            path = Path(str(row["local_path"]))
            process = subprocess.Popen(["bgpdump", "-q", "-m", str(path)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            assert process.stdout is not None
            for line in process.stdout:
                parts = line.rstrip("\n").split("|")
                if len(parts) < 6:
                    stats.malformed_records += 1
                    continue
                stats.raw_bgp_observations += 1
                try:
                    raw_ts = datetime.fromtimestamp(float(parts[1]), tz=timezone.utc)
                    raw_wid = window_id(str(incident["incident_uid"]), floor_to_five_minutes(raw_ts))
                    if raw_wid in windows:
                        raw_window_counts[raw_wid] += 1
                except (ValueError, OverflowError):
                    stats.malformed_records += 1
                if text_targets and not any(str(target) in line for target in text_targets):
                    continue
                parsed = parse_bgpdump_line(line, str(incident["incident_uid"]), path, str(row["collector"]))
                if not parsed:
                    stats.malformed_records += 1
                    continue
                if not parsed["peer_asn"]:
                    stats.missing_peer_asn += 1
                if not parsed["prefix"]:
                    stats.missing_prefix += 1
                if parsed["announcement_or_withdrawal"] == "announcement" and not parsed["as_path"]:
                    stats.malformed_as_path += 1
                if not relevant_with_targets(parsed, target_asns, target_prefixes, leak_seg):
                    continue
                writer.writerow(parsed)
                stats.relevant_observations += 1
                stats.matching_prefixes.add(parsed["prefix"])
                stats.matching_asns.update(parse_as_path_set(parsed["as_path"]))
                if parsed["peer_asn"]:
                    stats.matching_asns.add(parsed["peer_asn"])
                if parsed["origin_asn"]:
                    stats.matching_asns.add(parsed["origin_asn"])
                ts = parse_utc(parsed["bgp_timestamp_utc"])
                if not ts:
                    continue
                wid = window_id(str(incident["incident_uid"]), floor_to_five_minutes(ts))
                if wid in aggregates:
                    update_aggregate(aggregates[wid], parsed)
            stderr = process.stderr.read() if process.stderr else ""
            if process.wait() != 0:
                stats.parse_failures += 1
                if stderr:
                    print(stderr)
    rows = []
    for wid, meta in sorted(windows.items(), key=lambda item: item[1]["window_start"]):
        features = features_from_aggregate(aggregates[wid])
        row = {
            "incident_uid": incident["incident_uid"],
            "incident_id": incident["incident_id"],
            "category": incident["category"],
            "partition": incident["partition"],
            "window_id": wid,
            "window_start": format_utc(meta["window_start"]),
            "window_end": format_utc(meta["window_end"]),
            "temporal_status": meta["temporal_status"],
            "behavioral_feature_version": BEHAVIORAL_FEATURE_VERSION,
            "behavioral_feature_count": BEHAVIORAL_FEATURE_COUNT,
            "raw_observation_count": raw_window_counts.get(wid, 0),
            "has_relevant_observation": features["update_count"] > 0,
        }
        row.update(features)
        rows.append(row)
    return rows, stats


def run_batches(max_batches: int | None = None) -> dict[str, object]:
    manifest = load_csv(MANIFEST) if MANIFEST.exists() else manifest_rows()
    batches = load_csv(BATCHES) if BATCHES.exists() else batch_rows(manifest)
    plan = load_csv(ACQUISITION_PLAN) if ACQUISITION_PLAN.exists() else acquisition_rows(manifest, batches)
    batch_ids = sorted({row["batch_id"] for row in batches})
    if max_batches is not None:
        batch_ids = batch_ids[:max_batches]
    incidents = {row["incident_uid"]: row for row in manifest if any(batch["incident_uid"] == row["incident_uid"] and batch["batch_id"] in batch_ids for batch in batches)}
    plan_by_uid = group_by([row for row in plan if row["incident_uid"] in incidents], "incident_uid")
    all_features = []
    quality_rows = []
    summary_rows = []
    download_audit = []
    for index, (uid, incident) in enumerate(incidents.items(), start=1):
        start_time = time.perf_counter()
        downloads = [copy_or_download(row) for row in plan_by_uid.get(uid, [])]
        download_audit.extend(downloads)
        features, stats = parse_and_feature_incident(incident, downloads)
        all_features.extend(features)
        active = sum(row["temporal_status"] == "INCIDENT_ACTIVE" for row in features)
        pre = sum(row["temporal_status"] == "PRE_CONTEXT" for row in features)
        post = sum(row["temporal_status"] == "POST_CONTEXT" for row in features)
        status = "PASS" if downloads and all(row["download_status"] in {"200", "CACHED", "REUSED_FROM_PILOT"} for row in downloads) and stats.parse_failures == 0 else "REVIEW"
        if stats.relevant_observations == 0:
            status = "REVIEW"
        reasons = []
        if stats.relevant_observations == 0:
            reasons.append("no relevant observations")
        if stats.parse_failures:
            reasons.append("parser failure")
        summary_rows.append(
            {
                "incident_uid": uid,
                "category": incident["category"],
                "duration_minutes": incident["duration_minutes"],
                "raw_mrt_files": len(downloads),
                "raw_bgp_observations": stats.raw_bgp_observations,
                "relevant_observations": stats.relevant_observations,
                "active_5min_windows": active,
                "unknown_5min_windows": 0,
                "pre_context_windows": pre,
                "post_context_windows": post,
                "total_feature_rows": len(features),
            }
        )
        quality_rows.append({"incident_uid": uid, "category": incident["category"], "status": status, "review_reasons": ";".join(reasons), "elapsed_seconds": round(time.perf_counter() - start_time, 3)})
        print(f"Incident {index} / {len(incidents)} {uid} status={status} files={len(downloads)} raw={stats.raw_bgp_observations} relevant={stats.relevant_observations} feature_rows={len(features)}", flush=True)
    pd.DataFrame(all_features).to_parquet(FEATURES_PARQUET, index=False)
    write_csv(DOWNLOAD_AUDIT, download_audit, list(download_audit[0].keys()) if download_audit else ["incident_uid"])
    write_csv(FEATURE_SUMMARY, summary_rows, ["incident_uid", "category", "duration_minutes", "raw_mrt_files", "raw_bgp_observations", "relevant_observations", "active_5min_windows", "unknown_5min_windows", "pre_context_windows", "post_context_windows", "total_feature_rows"])
    write_csv(QUALITY_GATE, quality_rows, ["incident_uid", "category", "status", "review_reasons", "elapsed_seconds"])
    write_imbalance(summary_rows)
    write_feature_quality(all_features)
    return {
        "incidents_processed": len(incidents),
        "quality_counts": dict(Counter(row["status"] for row in quality_rows)),
        "raw_mrt_files": len(download_audit),
        "raw_bgp_observations": sum(int(row["raw_bgp_observations"]) for row in summary_rows),
        "relevant_observations": sum(int(row["relevant_observations"]) for row in summary_rows),
        "feature_rows": len(all_features),
        "outputs": [str(DOWNLOAD_AUDIT), str(FEATURES_PARQUET), str(FEATURE_SUMMARY), str(WINDOW_IMBALANCE), str(FEATURE_QUALITY), str(QUALITY_GATE)],
    }


def percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    pos = (len(ordered) - 1) * q
    lo = math.floor(pos)
    hi = min(math.ceil(pos), len(ordered) - 1)
    if lo == hi:
        return ordered[lo]
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (pos - lo)


def write_imbalance(summary_rows: list[dict[str, object]]) -> None:
    rows = []
    for category in ("Hijack", "Leak", "Outage", "ALL"):
        group = summary_rows if category == "ALL" else [row for row in summary_rows if row["category"] == category]
        values = [float(row["total_feature_rows"]) for row in group]
        total = sum(values)
        for level, pct in [("top_1_percent", 0.01), ("top_5_percent", 0.05), ("top_10_percent", 0.10)]:
            n = max(1, math.ceil(len(values) * pct)) if values else 0
            contribution = sum(sorted(values, reverse=True)[:n])
            rows.append({"category": category, "metric": level, "value": round(contribution / total * 100, 3) if total else 0, "notes": f"top {n} incidents"})
        rows.extend(
            [
                {"category": category, "metric": "min_rows_per_incident", "value": min(values) if values else 0, "notes": ""},
                {"category": category, "metric": "median_rows_per_incident", "value": median(values) if values else 0, "notes": ""},
                {"category": category, "metric": "mean_rows_per_incident", "value": round(mean(values), 3) if values else 0, "notes": ""},
                {"category": category, "metric": "p75_rows_per_incident", "value": percentile(values, 0.75), "notes": ""},
                {"category": category, "metric": "p90_rows_per_incident", "value": percentile(values, 0.90), "notes": ""},
                {"category": category, "metric": "p95_rows_per_incident", "value": percentile(values, 0.95), "notes": ""},
                {"category": category, "metric": "p99_rows_per_incident", "value": percentile(values, 0.99), "notes": ""},
                {"category": category, "metric": "max_rows_per_incident", "value": max(values) if values else 0, "notes": ""},
                {"category": category, "metric": "total_feature_rows", "value": total, "notes": ""},
            ]
        )
    write_csv(WINDOW_IMBALANCE, rows, ["category", "metric", "value", "notes"])


def write_feature_quality(feature_rows: list[dict[str, object]]) -> None:
    df = pd.DataFrame(feature_rows)
    rows = []
    for feature in BEHAVIORAL_FEATURE_NAMES:
        series = pd.to_numeric(df[feature], errors="coerce") if feature in df else pd.Series(dtype=float)
        rows.append(
            {
                "feature": feature,
                "missing_rate": round(series.isna().mean() * 100, 3) if len(series) else 0,
                "zero_rate": round((series == 0).mean() * 100, 3) if len(series) else 0,
                "min": series.min(skipna=True) if len(series) else "",
                "median": series.median(skipna=True) if len(series) else "",
                "mean": series.mean(skipna=True) if len(series) else "",
                "p95": series.quantile(0.95) if len(series) else "",
                "max": series.max(skipna=True) if len(series) else "",
                "unique_values": series.nunique(dropna=True),
                "constant_feature": str(series.nunique(dropna=True) <= 1),
                "sparse_feature": str((series == 0).mean() > 0.95) if len(series) else "False",
                "invalid_values": 0,
            }
        )
    write_csv(FEATURE_QUALITY, rows, ["feature", "missing_rate", "zero_rate", "min", "median", "mean", "p95", "max", "unique_values", "constant_feature", "sparse_feature", "invalid_values"])


def write_notebook() -> None:
    NOTEBOOK.parent.mkdir(parents=True, exist_ok=True)
    notebook = {
        "cells": [
            {"cell_type": "markdown", "metadata": {}, "source": ["# TRAIN Incident Behavioral Scale\n", "\n", "Build the full TRAIN incident-side behavioral feature corpus. Validation and Holdout remain untouched; no Normal labels, CAIDA/RPKI, model training, weighting, or window cap are introduced.\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["from bgp_incident_detection.train_incident_scale import prepare\n", "prepare(check_remote=False)\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["from bgp_incident_detection.train_incident_scale import run_batches\n", "# run_batches()  # intentionally explicit because this downloads/parses TRAIN MRT data\n"]},
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Plan and run full TRAIN incident behavioral feature extraction")
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--check-remote", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--head-workers", type=int, default=24)
    parser.add_argument("--max-batches", type=int)
    args = parser.parse_args()
    if args.prepare_only:
        print(json.dumps(prepare(batch_size=args.batch_size, check_remote=args.check_remote, head_workers=args.head_workers), indent=2, sort_keys=True))
        return
    if args.run:
        print(json.dumps(run_batches(max_batches=args.max_batches), indent=2, sort_keys=True))
        return
    parser.error("choose --prepare-only or --run")


if __name__ == "__main__":
    main()
