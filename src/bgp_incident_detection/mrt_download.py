from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    from bgp_incident_detection.audit import parse_utc, write_csv
    from bgp_incident_detection.mrt_acquisition import (
        ACQUISITION_PLAN,
        DEFAULT_COLLECTOR,
        PILOT_MANIFEST,
        RAW_MRT_DIR,
        ceil_to_15_minutes,
        floor_to_15_minutes,
        iter_update_slots,
        routeviews_update_filename,
        routeviews_update_url,
    )
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import parse_utc, write_csv
    from src.bgp_incident_detection.mrt_acquisition import (
        ACQUISITION_PLAN,
        DEFAULT_COLLECTOR,
        PILOT_MANIFEST,
        RAW_MRT_DIR,
        ceil_to_15_minutes,
        floor_to_15_minutes,
        iter_update_slots,
        routeviews_update_filename,
        routeviews_update_url,
    )


PILOT_DIR = Path("data/pilot")
ACTIVE_SEGMENTS = PILOT_DIR / "pilot_candidate_active_segments_v1.csv"
REMOTE_AVAILABILITY = PILOT_DIR / "mrt_pilot_remote_availability_v1.csv"
DOWNLOAD_MANIFEST = PILOT_DIR / "mrt_pilot_download_manifest_v1.csv"
DOWNLOAD_FILE_STATUS = PILOT_DIR / "mrt_pilot_download_file_status_v1.csv"
DOWNLOAD_AUDIT = PILOT_DIR / "mrt_pilot_download_audit_v1.csv"
GAP_RULE = "max_gap_between_active_bins<=60m"
CONTEXT_BUFFER_MINUTES = 60


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def isoformat_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_required(value: str) -> datetime:
    parsed = parse_utc(value)
    if not parsed:
        raise ValueError(f"invalid UTC timestamp: {value}")
    return parsed


def safe_incident_dir(incident_uid: str) -> Path:
    return RAW_MRT_DIR / incident_uid.replace(":", "_")


def timestamp_from_url(url: str) -> datetime:
    filename = url.rsplit("/", 1)[-1]
    timestamp = filename.removeprefix("updates.").removesuffix(".bz2")
    return datetime.strptime(timestamp, "%Y%m%d.%H%M").replace(tzinfo=timezone.utc)


def local_path_for(incident_uid: str, slot: datetime) -> str:
    return str(safe_incident_dir(incident_uid) / routeviews_update_filename(slot))


def slots_for_interval(start_text: str, end_text: str) -> list[datetime]:
    start = floor_to_15_minutes(parse_required(start_text) - timedelta(minutes=CONTEXT_BUFFER_MINUTES))
    end = ceil_to_15_minutes(parse_required(end_text) + timedelta(minutes=CONTEXT_BUFFER_MINUTES))
    return iter_update_slots(start, end)


def build_download_manifest_rows(
    collector: str = DEFAULT_COLLECTOR,
    gap_rule: str = GAP_RULE,
) -> list[dict[str, object]]:
    pilot_rows = {row["incident_uid"]: row for row in load_csv(PILOT_MANIFEST)}
    plan_rows = load_csv(ACQUISITION_PLAN)
    availability = {
        row["mrt_url"]: row
        for row in load_csv(REMOTE_AVAILABILITY)
        if row.get("available") == "True"
    }
    rows: list[dict[str, object]] = []
    seen_by_incident: dict[str, set[str]] = {}

    active_segments = [
        row for row in load_csv(ACTIVE_SEGMENTS)
        if row["gap_rule"] == gap_rule and row["category"] in {"Hijack", "Leak"}
    ]
    for segment in active_segments:
        incident_uid = segment["incident_uid"]
        segment_id = f"{incident_uid.replace(':', '_')}_segment_{segment['active_segment_index']}_{gap_rule.split('<=')[-1]}"
        collection_slots = slots_for_interval(segment["active_segment_start"], segment["active_segment_end"])
        collection_start = isoformat_z(collection_slots[0])
        collection_end = isoformat_z(collection_slots[-1])
        for slot in collection_slots:
            url = routeviews_update_url(slot, collector)
            seen_by_incident.setdefault(incident_uid, set())
            if url in seen_by_incident[incident_uid]:
                continue
            seen_by_incident[incident_uid].add(url)
            rows.append(
                {
                    "incident_uid": incident_uid,
                    "category": segment["category"],
                    "active_segment_id": segment_id,
                    "segment_start": segment["active_segment_start"],
                    "segment_end": segment["active_segment_end"],
                    "collection_start": collection_start,
                    "collection_end": collection_end,
                    "routeviews_collector": collector,
                    "mrt_timestamp": isoformat_z(slot),
                    "mrt_url": url,
                    "local_path": local_path_for(incident_uid, slot),
                    "expected_status": "available" if url in availability else "not_previously_verified",
                }
            )

    for plan in plan_rows:
        if plan["category"] != "Outage":
            continue
        incident_uid = plan["incident_uid"]
        for url in json.loads(plan["mrt_urls"]):
            slot = timestamp_from_url(url)
            seen_by_incident.setdefault(incident_uid, set())
            if url in seen_by_incident[incident_uid]:
                continue
            seen_by_incident[incident_uid].add(url)
            rows.append(
                {
                    "incident_uid": incident_uid,
                    "category": plan["category"],
                    "active_segment_id": f"{incident_uid.replace(':', '_')}_documented_outage_interval",
                    "segment_start": pilot_rows[incident_uid]["start_utc"],
                    "segment_end": pilot_rows[incident_uid]["end_utc"],
                    "collection_start": plan["collection_start"],
                    "collection_end": plan["collection_end"],
                    "routeviews_collector": collector,
                    "mrt_timestamp": isoformat_z(slot),
                    "mrt_url": url,
                    "local_path": local_path_for(incident_uid, slot),
                    "expected_status": "available" if url in availability else "not_previously_verified",
                }
            )
    return sorted(rows, key=lambda row: (str(row["incident_uid"]), str(row["mrt_timestamp"]), str(row["active_segment_id"])))


def write_download_manifest(rows: list[dict[str, object]]) -> None:
    write_csv(
        DOWNLOAD_MANIFEST,
        rows,
        [
            "incident_uid",
            "category",
            "active_segment_id",
            "segment_start",
            "segment_end",
            "collection_start",
            "collection_end",
            "routeviews_collector",
            "mrt_timestamp",
            "mrt_url",
            "local_path",
            "expected_status",
        ],
    )


def head_content_length(url: str, timeout_seconds: float = 15.0) -> tuple[bool, str, int, str]:
    request = Request(url, method="HEAD", headers={"User-Agent": "bgp-incident-detection-pipeline/0.1"})
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            length = int(response.headers.get("Content-Length") or 0)
            return 200 <= response.status < 400, str(response.status), length, "HEAD content-length"
    except HTTPError as error:
        return False, str(error.code), 0, f"HEAD HTTPError: {error.reason}"
    except URLError as error:
        return False, "", 0, f"HEAD URLError: {error.reason}"


def estimate_manifest_size(
    manifest_rows: list[dict[str, object]],
    workers: int = 16,
    timeout_seconds: float = 15.0,
) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(head_content_length, str(row["mrt_url"]), timeout_seconds): row
            for row in manifest_rows
        }
        for future in as_completed(futures):
            row = futures[future]
            available, status_code, content_length, notes = future.result()
            result = dict(row)
            result.update(
                {
                    "estimated_available": str(available),
                    "estimated_status_code": status_code,
                    "estimated_content_length": content_length,
                    "estimate_notes": notes,
                }
            )
            results.append(result)
    return sorted(results, key=lambda row: (str(row["incident_uid"]), str(row["mrt_timestamp"])))


def summarize_manifest(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    by_uid: dict[str, list[dict[str, object]]] = {}
    for row in rows:
        by_uid.setdefault(str(row["incident_uid"]), []).append(row)
    for incident_uid, incident_rows in sorted(by_uid.items()):
        output.append(
            {
                "incident_uid": incident_uid,
                "category": incident_rows[0]["category"],
                "planned_files": len(incident_rows),
                "estimated_bytes": sum(int(row.get("estimated_content_length") or 0) for row in incident_rows),
                "collection_start_min": min(str(row["collection_start"]) for row in incident_rows),
                "collection_end_max": max(str(row["collection_end"]) for row in incident_rows),
            }
        )
    return output


def checksum_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_one(row: dict[str, object], timeout_seconds: float = 120.0) -> dict[str, object]:
    local_path = Path(str(row["local_path"]))
    local_path.parent.mkdir(parents=True, exist_ok=True)
    if local_path.exists() and local_path.stat().st_size > 0:
        return {
            **row,
            "http_status": "cached",
            "downloaded": "True",
            "file_size_bytes": local_path.stat().st_size,
            "sha256": checksum_file(local_path),
            "download_timestamp": isoformat_z(datetime.now(timezone.utc)),
            "notes": "existing non-empty file reused",
        }

    request = Request(str(row["mrt_url"]), method="GET", headers={"User-Agent": "bgp-incident-detection-pipeline/0.1"})
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            content = response.read()
            local_path.write_bytes(content)
            file_size = local_path.stat().st_size
            return {
                **row,
                "http_status": str(response.status),
                "downloaded": str(200 <= response.status < 400 and file_size > 0),
                "file_size_bytes": file_size,
                "sha256": checksum_file(local_path) if file_size > 0 else "",
                "download_timestamp": isoformat_z(datetime.now(timezone.utc)),
                "notes": "downloaded",
            }
    except HTTPError as error:
        return {
            **row,
            "http_status": str(error.code),
            "downloaded": "False",
            "file_size_bytes": 0,
            "sha256": "",
            "download_timestamp": isoformat_z(datetime.now(timezone.utc)),
            "notes": f"HTTPError: {error.reason}",
        }
    except URLError as error:
        return {
            **row,
            "http_status": "",
            "downloaded": "False",
            "file_size_bytes": 0,
            "sha256": "",
            "download_timestamp": isoformat_z(datetime.now(timezone.utc)),
            "notes": f"URLError: {error.reason}",
        }


def download_manifest(
    manifest_rows: list[dict[str, object]],
    workers: int = 4,
    timeout_seconds: float = 120.0,
) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(download_one, row, timeout_seconds): row
            for row in manifest_rows
            if row["expected_status"] == "available"
        }
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda row: (str(row["incident_uid"]), str(row["mrt_timestamp"])))


def compression_ok(path: Path) -> bool:
    if path.suffix != ".bz2" or not path.exists() or path.stat().st_size < 3:
        return False
    return path.read_bytes()[:3] == b"BZh"


def audit_downloads(manifest_rows: list[dict[str, object]], status_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    status_by_local_path = {str(row["local_path"]): row for row in status_rows}
    by_uid: dict[str, list[dict[str, object]]] = {}
    for row in manifest_rows:
        by_uid.setdefault(str(row["incident_uid"]), []).append(row)
    output: list[dict[str, object]] = []
    for incident_uid, rows in sorted(by_uid.items()):
        local_paths = [str(row["local_path"]) for row in rows]
        duplicate_count = len(local_paths) - len(set(local_paths))
        downloaded = 0
        corrupted = 0
        total_bytes = 0
        for local_path_text in set(local_paths):
            status = status_by_local_path.get(local_path_text)
            path = Path(local_path_text)
            if status and status.get("downloaded") == "True" and path.exists() and path.stat().st_size > 0:
                downloaded += 1
                total_bytes += path.stat().st_size
                if not compression_ok(path) or not status.get("sha256"):
                    corrupted += 1
            else:
                corrupted += 1 if path.exists() and path.stat().st_size == 0 else 0
        missing = len(set(local_paths)) - downloaded
        availability = round((downloaded / len(set(local_paths))) * 100, 3) if local_paths else 0.0
        status = "PASS" if missing == 0 and corrupted == 0 and duplicate_count == 0 else "FAIL"
        output.append(
            {
                "incident_uid": incident_uid,
                "planned_files": len(set(local_paths)),
                "downloaded_files": downloaded,
                "missing_files": missing,
                "corrupted_files": corrupted,
                "duplicate_files": duplicate_count,
                "total_bytes": total_bytes,
                "availability_percent": availability,
                "status": status,
            }
        )
    return output


def write_file_status(rows: list[dict[str, object]]) -> None:
    write_csv(
        DOWNLOAD_FILE_STATUS,
        rows,
        [
            "incident_uid",
            "category",
            "active_segment_id",
            "segment_start",
            "segment_end",
            "collection_start",
            "collection_end",
            "routeviews_collector",
            "mrt_timestamp",
            "mrt_url",
            "local_path",
            "expected_status",
            "http_status",
            "downloaded",
            "file_size_bytes",
            "sha256",
            "download_timestamp",
            "notes",
        ],
    )


def write_download_audit(rows: list[dict[str, object]]) -> None:
    write_csv(
        DOWNLOAD_AUDIT,
        rows,
        [
            "incident_uid",
            "planned_files",
            "downloaded_files",
            "missing_files",
            "corrupted_files",
            "duplicate_files",
            "total_bytes",
            "availability_percent",
            "status",
        ],
    )


def build_and_estimate_manifest(workers: int = 16, timeout_seconds: float = 15.0) -> list[dict[str, object]]:
    rows = build_download_manifest_rows()
    estimated = estimate_manifest_size(rows, workers, timeout_seconds)
    write_download_manifest(estimated)
    return estimated


def run_download(workers: int = 4, timeout_seconds: float = 120.0) -> dict[str, list[dict[str, object]]]:
    manifest_rows = load_csv(DOWNLOAD_MANIFEST)
    status_rows = download_manifest(manifest_rows, workers, timeout_seconds)
    audit_rows = audit_downloads(manifest_rows, status_rows)
    write_file_status(status_rows)
    write_download_audit(audit_rows)
    return {"status": status_rows, "audit": audit_rows}


def print_manifest_summary(rows: list[dict[str, object]]) -> None:
    summary = summarize_manifest(rows)
    print("Frozen pilot download manifest summary")
    print("Planned files:", len(rows))
    print("Estimated bytes:", sum(int(row.get("estimated_content_length") or 0) for row in rows))
    print("Expected statuses:", dict(Counter(row["expected_status"] for row in rows)))
    for row in summary:
        print(json.dumps(row, sort_keys=True))


def print_download_summary(results: dict[str, list[dict[str, object]]]) -> None:
    status_rows = results["status"]
    audit_rows = results["audit"]
    print("MRT pilot download complete")
    print("File status rows:", len(status_rows))
    print("Downloaded files:", sum(1 for row in status_rows if row["downloaded"] == "True"))
    print("Audit statuses:", dict(Counter(row["status"] for row in audit_rows)))
    print("Total bytes:", sum(int(row["total_bytes"]) for row in audit_rows))
    for row in audit_rows:
        print(json.dumps(row, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser(description="Freeze and execute the refined RouteViews MRT pilot download manifest.")
    parser.add_argument("--estimate-only", action="store_true")
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    args = parser.parse_args()
    if args.estimate_only:
        rows = build_and_estimate_manifest(max(args.workers, 1), args.timeout_seconds)
        print_manifest_summary(rows)
    elif args.download:
        results = run_download(max(args.workers, 1), args.timeout_seconds)
        print_download_summary(results)
    else:
        rows = build_download_manifest_rows()
        write_download_manifest(rows)
        print_manifest_summary(rows)


if __name__ == "__main__":
    main()
