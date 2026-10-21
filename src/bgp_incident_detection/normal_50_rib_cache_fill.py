from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import shutil
import sqlite3
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
    from bgp_incident_detection.normal_rib_batch50 import (
        APPROVED_POOL_V2,
        FILL_PLAN,
        PRESCREEN_50,
        RIB_DATA_REQUIRED,
        classify_from_index,
        head_url,
        indexed_ribs,
        load_csv,
    )
    from bgp_incident_detection.normal_rib_scale import ROUTE_PRESENCE_UNSTABLE
    from bgp_incident_detection.rib_cache_index import NO_OBSERVABILITY, ORIGIN_UNSTABLE
    from bgp_incident_detection.rib_index_engine import DB_PATH, db_connect, index_rib, initialize_db, lookup_asn, lookup_prefix
    from bgp_incident_detection.rib_normal import validate_bzip2
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import parse_utc, write_csv
    from src.bgp_incident_detection.mrt_acquisition import ceil_to_15_minutes, floor_to_15_minutes, iter_update_slots, routeviews_update_url
    from src.bgp_incident_detection.normal_pool_scale import CONTEXT_BUFFER_MINUTES, PRESCREEN_PASS
    from src.bgp_incident_detection.normal_rib_batch50 import (
        APPROVED_POOL_V2,
        FILL_PLAN,
        PRESCREEN_50,
        RIB_DATA_REQUIRED,
        classify_from_index,
        head_url,
        indexed_ribs,
        load_csv,
    )
    from src.bgp_incident_detection.normal_rib_scale import ROUTE_PRESENCE_UNSTABLE
    from src.bgp_incident_detection.rib_cache_index import NO_OBSERVABILITY, ORIGIN_UNSTABLE
    from src.bgp_incident_detection.rib_index_engine import DB_PATH, db_connect, index_rib, initialize_db, lookup_asn, lookup_prefix
    from src.bgp_incident_detection.rib_normal import validate_bzip2


EXECUTION_MANIFEST = Path("data/normal_scale/normal_50_rib_cache_fill_execution_manifest_v1.csv")
CACHE_FILL_AUDIT = Path("data/normal_scale/normal_50_rib_cache_fill_audit_v1.csv")
PRESCREEN_COMPLETE = Path("data/normal_scale/normal_rib_prescreen_50_complete_v1.csv")
APPROVED_POOL_V3 = Path("data/normal_scale/normal_rib_approved_pool_v3.csv")
UPDATE_ESTIMATE_V4 = Path("data/normal_scale/normal_approved_update_acquisition_estimate_v4.csv")
RIB_CACHE_INDEX = Path("data/normal_scale/rib_cache_index_v1.csv")
RAW_RIB_ROOT = Path("data/cache/routeviews_rib/raw")

BATCH_SIZE = 20
USER_AGENT = "bgp-incident-detection-pipeline/0.1"


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


def local_rib_path(collector: str, rib_timestamp: str) -> Path:
    ts = parse_required(rib_timestamp)
    return RAW_RIB_ROOT / collector / f"{ts:%Y%m%d}" / f"rib.{ts:%Y%m%d.%H%M}.bz2"


def missing_workload() -> list[dict[str, object]]:
    rows = []
    for row in load_csv(FILL_PLAN):
        if row.get("already_indexed") == "True":
            continue
        collector = row.get("collector") or "route-views2"
        rib_timestamp = row["rib_timestamp"]
        rows.append(
            {
                "collector": collector,
                "rib_timestamp": rib_timestamp,
                "rib_url": row["rib_url"],
                "required_by_candidate_count": row.get("candidate_count", "1"),
                "download_required": row.get("download_required", "True"),
                "index_required": "True",
                "execution_status": "PENDING",
                "local_path": str(local_rib_path(collector, rib_timestamp)),
            }
        )
    return rows


def write_execution_manifest(rows: list[dict[str, object]]) -> None:
    write_csv(
        EXECUTION_MANIFEST,
        rows,
        ["collector", "rib_timestamp", "rib_url", "required_by_candidate_count", "download_required", "index_required", "execution_status", "local_path", "estimated_content_length", "head_status"],
    )


def estimate_sizes(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    output = []
    for row in rows:
        ok, status, size = head_url(str(row["rib_url"]))
        enriched = dict(row)
        enriched["estimated_content_length"] = size if ok else ""
        enriched["head_status"] = status
        output.append(enriched)
    return output


def targets_by_rib(candidates: list[dict[str, str]]) -> dict[tuple[str, str], list[dict[str, str]]]:
    targets: dict[tuple[str, str], dict[tuple[str, str, str], dict[str, str]]] = defaultdict(dict)
    for row in candidates:
        collector = row.get("collector") or "route-views2"
        for side in ("before", "after"):
            ts = row[f"rib_{side}_timestamp"]
            target_kind = "prefix" if row.get("affected_prefix") else "asn"
            target_value = row.get("affected_prefix") or row["affected_asn"]
            targets[(collector, ts)][(row["candidate_period_id"], target_kind, target_value)] = {
                "candidate_period_id": row["candidate_period_id"],
                "affected_asn": row["affected_asn"],
                "affected_prefix": row.get("affected_prefix", ""),
                "target_kind": target_kind,
                "target_value": target_value,
            }
    return {key: list(value.values()) for key, value in targets.items()}


def download_rib(row: dict[str, object]) -> dict[str, object]:
    path = Path(str(row["local_path"]))
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.stat().st_size > 0 and validate_bzip2(path):
        return {
            "download_status": "CACHED",
            "download_bytes": path.stat().st_size,
            "download_seconds": 0.0,
            "checksum": sha256(path),
            "cache_reused": "True",
            "error": "",
        }
    start = time.perf_counter()
    request = Request(str(row["rib_url"]), headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(request, timeout=600.0) as response, path.open("wb") as handle:
            shutil.copyfileobj(response, handle, length=1024 * 1024)
            http_status = str(response.status)
        if not path.exists() or path.stat().st_size <= 0:
            return {"download_status": "FAILED", "download_bytes": 0, "download_seconds": round(time.perf_counter() - start, 3), "checksum": "", "cache_reused": "False", "error": "downloaded file is empty"}
        if not validate_bzip2(path):
            return {"download_status": "FAILED", "download_bytes": path.stat().st_size, "download_seconds": round(time.perf_counter() - start, 3), "checksum": "", "cache_reused": "False", "error": "downloaded file failed bzip2 validation"}
        return {
            "download_status": http_status,
            "download_bytes": path.stat().st_size,
            "download_seconds": round(time.perf_counter() - start, 3),
            "checksum": sha256(path),
            "cache_reused": "False",
            "error": "",
        }
    except (HTTPError, URLError, TimeoutError) as error:
        return {
            "download_status": str(getattr(error, "code", "")) or "FAILED",
            "download_bytes": 0,
            "download_seconds": round(time.perf_counter() - start, 3),
            "checksum": "",
            "cache_reused": "False",
            "error": str(error),
        }


def update_rib_cache_index(audit_rows: list[dict[str, object]]) -> None:
    existing = {
        (row["collector"], row["rib_timestamp"], row["source_url"]): row
        for row in load_csv(RIB_CACHE_INDEX)
    }
    now = isoformat_z(datetime.now(timezone.utc))
    for row in audit_rows:
        if str(row.get("download_status")) not in {"200", "CACHED"}:
            continue
        key = (str(row["collector"]), str(row["rib_timestamp"]), str(row["rib_url"]))
        existing[key] = {
            "collector": row["collector"],
            "rib_timestamp": row["rib_timestamp"],
            "source_url": row["rib_url"],
            "local_path": row["local_path"],
            "downloaded": str(row.get("cache_reused") != "True"),
            "parsed": str(row.get("index_status") == "INDEXED"),
            "file_size": row["download_bytes"],
            "checksum": row["checksum"],
            "last_used": now,
            "status": row["download_status"],
        }
    write_csv(
        RIB_CACHE_INDEX,
        sorted(existing.values(), key=lambda item: (item["collector"], item["rib_timestamp"], item["source_url"])),
        ["collector", "rib_timestamp", "source_url", "local_path", "downloaded", "parsed", "file_size", "checksum", "last_used", "status"],
    )


def append_audit_rows(rows: list[dict[str, object]]) -> None:
    existing = load_csv(CACHE_FILL_AUDIT)
    by_key = {(row["collector"], row["rib_timestamp"]): row for row in existing}
    for row in rows:
        by_key[(str(row["collector"]), str(row["rib_timestamp"]))] = {k: str(v) for k, v in row.items()}
    write_csv(
        CACHE_FILL_AUDIT,
        sorted(by_key.values(), key=lambda item: (item["collector"], item["rib_timestamp"])),
        ["collector", "rib_timestamp", "download_status", "download_bytes", "download_seconds", "checksum", "index_status", "indexed_rows", "index_seconds", "cache_reused", "error", "rib_url", "local_path", "batch_number"],
    )


def process_batches(rows: list[dict[str, object]], batch_size: int = BATCH_SIZE) -> list[dict[str, object]]:
    candidates = load_csv(PRESCREEN_50)
    target_map = targets_by_rib(candidates)
    conn = db_connect(DB_PATH)
    initialize_db(conn)
    all_audit: list[dict[str, object]] = []
    for batch_index, offset in enumerate(range(0, len(rows), batch_size), start=1):
        batch = rows[offset : offset + batch_size]
        for row in batch:
            download = download_rib(row)
            index_status = "NOT_INDEXED"
            indexed_rows = 0
            index_seconds = 0.0
            error = download.get("error", "")
            if str(download["download_status"]) in {"200", "CACHED"}:
                rib = {"collector": row["collector"], "rib_timestamp": row["rib_timestamp"], "source_file": row["local_path"]}
                index_result = index_rib(conn, rib, target_map.get((str(row["collector"]), str(row["rib_timestamp"])), []))
                index_status = str(index_result["index_status"])
                indexed_rows = int(index_result["rows_indexed"])
                index_seconds = float(index_result["elapsed_seconds"])
                if index_status != "INDEXED":
                    error = f"{error}; {index_result.get('notes', '')}".strip("; ")
            audit = {
                "collector": row["collector"],
                "rib_timestamp": row["rib_timestamp"],
                "download_status": download["download_status"],
                "download_bytes": download["download_bytes"],
                "download_seconds": download["download_seconds"],
                "checksum": download["checksum"],
                "index_status": index_status,
                "indexed_rows": indexed_rows,
                "index_seconds": index_seconds,
                "cache_reused": download["cache_reused"],
                "error": error,
                "rib_url": row["rib_url"],
                "local_path": row["local_path"],
                "batch_number": batch_index,
            }
            all_audit.append(audit)
            append_audit_rows([audit])
            update_rib_cache_index([audit])
            print(
                f"{len(all_audit)} / {len(rows)} "
                f"{row['collector']} {row['rib_timestamp']} "
                f"download={audit['download_status']} index={audit['index_status']} "
                f"rows={audit['indexed_rows']}",
                flush=True,
            )
        print(f"Batch {batch_index} checkpoint complete: {min(offset + len(batch), len(rows))} / {len(rows)}", flush=True)
    conn.close()
    return all_audit


def rerun_50_from_index() -> list[dict[str, object]]:
    candidates = load_csv(PRESCREEN_50)
    conn = sqlite3.connect(DB_PATH)
    indexed = indexed_ribs(conn)
    rows = []
    for candidate in candidates:
        collector = candidate.get("collector") or "route-views2"
        before_key = (collector, candidate["rib_before_timestamp"])
        after_key = (collector, candidate["rib_after_timestamp"])
        if before_key not in indexed or after_key not in indexed:
            result = {
                "asn_visible_before": "False",
                "asn_visible_after": "False",
                "prefix_visible_before": "False" if candidate.get("affected_prefix") else "NOT_APPLICABLE",
                "prefix_visible_after": "False" if candidate.get("affected_prefix") else "NOT_APPLICABLE",
                "origin_before": "[]",
                "origin_after": "[]",
                "origin_stable": "False",
                "route_presence_stable": "False",
                "prescreen_status": RIB_DATA_REQUIRED,
                "reason": "one or both required RIB snapshots failed acquisition or indexing",
            }
        else:
            states = {}
            for side in ("before", "after"):
                ts = candidate[f"rib_{side}_timestamp"]
                if candidate.get("affected_prefix"):
                    states[side], _ = lookup_prefix(conn, collector, ts, candidate["affected_prefix"])
                else:
                    states[side], _ = lookup_asn(conn, collector, ts, candidate["affected_asn"])
            result = classify_from_index(candidate, states["before"], states["after"])
        rows.append(
            {
                "candidate_period_id": candidate["candidate_period_id"],
                "associated_incident_uid": candidate["associated_incident_uid"],
                "associated_category": candidate["associated_category"],
                "affected_asn": candidate["affected_asn"],
                "affected_prefix": candidate.get("affected_prefix", ""),
                "candidate_start": candidate["candidate_start"],
                "candidate_end": candidate["candidate_end"],
                "collector": collector,
                "rib_before_timestamp": candidate["rib_before_timestamp"],
                "rib_after_timestamp": candidate["rib_after_timestamp"],
                **result,
            }
        )
    conn.close()
    write_csv(
        PRESCREEN_COMPLETE,
        rows,
        ["candidate_period_id", "associated_incident_uid", "associated_category", "affected_asn", "affected_prefix", "candidate_start", "candidate_end", "collector", "rib_before_timestamp", "rib_after_timestamp", "asn_visible_before", "asn_visible_after", "prefix_visible_before", "prefix_visible_after", "origin_before", "origin_after", "origin_stable", "route_presence_stable", "prescreen_status", "reason"],
    )
    return rows


def approved_pool_v3(new_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    by_id = {row["candidate_period_id"]: dict(row) for row in load_csv(APPROVED_POOL_V2)}
    for row in new_rows:
        if row.get("prescreen_status") == PRESCREEN_PASS:
            enriched = dict(row)
            enriched["partition"] = "train"
            enriched["duration_minutes"] = str(round((parse_required(str(row["candidate_end"])) - parse_required(str(row["candidate_start"]))).total_seconds() / 60))
            enriched["selection_reason"] = row.get("reason", "")
            by_id[row["candidate_period_id"]] = enriched
    rows = sorted(by_id.values(), key=lambda item: (item.get("associated_category", ""), item.get("affected_asn", ""), item["candidate_period_id"]))
    write_csv(
        APPROVED_POOL_V3,
        rows,
        ["candidate_period_id", "associated_incident_uid", "associated_category", "partition", "affected_asn", "affected_prefix", "candidate_start", "candidate_end", "duration_minutes", "days_from_incident", "collector", "rib_visible_before", "rib_visible_after", "origin_stable", "route_presence_stable", "known_incident_overlap", "prescreen_status", "selection_reason", "rib_before_timestamp", "rib_after_timestamp", "prefix_visible_before", "prefix_visible_after", "source_provenance", "selection_year", "selection_duration_bucket", "selection_country"],
    )
    return rows


def update_slots(row: dict[str, object]) -> list[datetime]:
    start = floor_to_15_minutes(parse_required(str(row["candidate_start"])) - timedelta(minutes=CONTEXT_BUFFER_MINUTES))
    end = ceil_to_15_minutes(parse_required(str(row["candidate_end"])) + timedelta(minutes=CONTEXT_BUFFER_MINUTES))
    return iter_update_slots(start, end)


def build_update_estimate(approved_rows: list[dict[str, object]], newly_approved_ids: set[str]) -> list[dict[str, object]]:
    prior = {row["candidate_period_id"]: row for row in load_csv(Path("data/normal_scale/normal_approved_update_acquisition_estimate_v3.csv"))}
    rows = []
    for row in approved_rows:
        if not row.get("candidate_start") or not row.get("candidate_end"):
            continue
        slots = update_slots(row)
        check_remote = row["candidate_period_id"] in newly_approved_ids
        available = 0
        total_bytes = 0
        if check_remote:
            for slot in slots:
                ok, _, size = head_url(routeviews_update_url(slot, str(row.get("collector") or "route-views2")))
                available += int(ok)
                total_bytes += size if ok else 0
        previous = prior.get(row["candidate_period_id"], {})
        rows.append(
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
                "remote_availability_checked": str(check_remote or previous.get("remote_availability_checked") == "True"),
                "remote_available_file_count": available if check_remote else previous.get("remote_available_file_count", ""),
                "remote_availability_percent": round(100 * available / len(slots), 3) if check_remote and slots else previous.get("remote_availability_percent", ""),
                "estimated_compressed_bytes": total_bytes if check_remote else previous.get("estimated_compressed_bytes", ""),
                "estimated_compressed_mib": round(total_bytes / 1024 / 1024, 3) if check_remote else previous.get("estimated_compressed_mib", ""),
                "expected_5_minute_window_count": math.ceil((parse_required(str(row["candidate_end"])) - parse_required(str(row["candidate_start"]))).total_seconds() / 300),
                "notes": "UPDATE HEAD estimate only; no UPDATE MRT files downloaded",
            }
        )
    write_csv(
        UPDATE_ESTIMATE_V4,
        rows,
        ["candidate_period_id", "associated_incident_uid", "associated_category", "affected_asn", "collector", "candidate_start", "candidate_end", "collection_start", "collection_end", "required_update_file_count", "remote_availability_checked", "remote_available_file_count", "remote_availability_percent", "estimated_compressed_bytes", "estimated_compressed_mib", "expected_5_minute_window_count", "notes"],
    )
    return rows


def run_plan(estimate: bool = False) -> dict[str, object]:
    rows = missing_workload()
    if estimate:
        rows = estimate_sizes(rows)
    write_execution_manifest(rows)
    batches = [{"batch": index // BATCH_SIZE + 1, "count": len(rows[index : index + BATCH_SIZE]), "first_rib": rows[index]["rib_timestamp"], "last_rib": rows[index + len(rows[index : index + BATCH_SIZE]) - 1]["rib_timestamp"]} for index in range(0, len(rows), BATCH_SIZE)]
    return {
        "missing_rib_workload": len(rows),
        "estimated_total_compressed_bytes": sum(int(row.get("estimated_content_length") or 0) for row in rows),
        "estimated_total_compressed_gib": round(sum(int(row.get("estimated_content_length") or 0) for row in rows) / 1024 / 1024 / 1024, 3),
        "batches": batches,
        "existing_cache_hits": sum(row.get("download_required") == "False" for row in rows),
        "execution_manifest": str(EXECUTION_MANIFEST),
    }


def run(batch_size: int = BATCH_SIZE, estimate_only: bool = False, skip_update_head: bool = False) -> dict[str, object]:
    if estimate_only:
        return run_plan(estimate=True)
    start = time.perf_counter()
    workload = missing_workload()
    if not EXECUTION_MANIFEST.exists():
        write_execution_manifest(workload)
    audit = process_batches(workload, batch_size=batch_size)
    complete = rerun_50_from_index()
    newly_approved_ids = {row["candidate_period_id"] for row in complete if row.get("prescreen_status") == PRESCREEN_PASS}
    approved = approved_pool_v3(complete)
    estimate = build_update_estimate(approved, set() if skip_update_head else newly_approved_ids)
    status_counts = Counter(row["prescreen_status"] for row in complete)
    approved_counts = Counter(row.get("associated_category", "") for row in approved)
    asn_counts = Counter(row.get("affected_asn", "") for row in approved if row.get("affected_asn"))
    return {
        "workload_ribs": len(workload),
        "downloaded_ribs": sum(row["download_status"] == "200" for row in audit),
        "cache_reused_ribs": sum(row["download_status"] == "CACHED" for row in audit),
        "indexed_ribs": sum(row["index_status"] == "INDEXED" for row in audit),
        "total_downloaded_bytes": sum(int(row["download_bytes"]) for row in audit if row["download_status"] == "200"),
        "total_cache_index_seconds": round(sum(float(row["download_seconds"]) + float(row["index_seconds"]) for row in audit), 3),
        "prescreen_status_counts": dict(status_counts),
        "pass_by_class": dict(Counter(row["associated_category"] for row in complete if row["prescreen_status"] == PRESCREEN_PASS)),
        "approved_pool_by_class": dict(approved_counts),
        "approved_total": len(approved),
        "approved_unique_asns": len(asn_counts),
        "approved_max_candidates_per_asn": max(asn_counts.values()) if asn_counts else 0,
        "approved_update_file_count": sum(int(row.get("required_update_file_count") or 0) for row in estimate),
        "approved_expected_5_minute_windows": sum(int(row.get("expected_5_minute_window_count") or 0) for row in estimate),
        "elapsed_seconds": round(time.perf_counter() - start, 3),
        "outputs": [str(EXECUTION_MANIFEST), str(CACHE_FILL_AUDIT), str(PRESCREEN_COMPLETE), str(APPROVED_POOL_V3), str(UPDATE_ESTIMATE_V4)],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Fill/index missing RIB snapshots for the frozen 50-candidate Normal prescreen batch")
    parser.add_argument("--plan", action="store_true")
    parser.add_argument("--estimate", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--batch-size", type=int, default=BATCH_SIZE)
    parser.add_argument("--skip-update-head", action="store_true")
    args = parser.parse_args()
    if args.plan:
        print(json.dumps(run_plan(estimate=args.estimate), indent=2, sort_keys=True))
    elif args.run:
        print(json.dumps(run(batch_size=args.batch_size, skip_update_head=args.skip_update_head), indent=2, sort_keys=True))
    else:
        parser.error("choose --plan or --run")


if __name__ == "__main__":
    main()
