from __future__ import annotations

import argparse
import bz2
import csv
import hashlib
import json
import re
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
    from bgp_incident_detection.mrt_acquisition import DEFAULT_COLLECTOR, routeviews_base_url, routeviews_month_path
    from bgp_incident_detection.mrt_parser import bgpdump_version, parse_as_path_set, origin_asn_from_path
    from bgp_incident_detection.normal_pilot import (
        NORMAL_FEATURES,
        NORMAL_PERIODS,
        NORMAL_QUALIFICATION,
        parse_required,
    )
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import parse_utc, write_csv
    from src.bgp_incident_detection.mrt_acquisition import DEFAULT_COLLECTOR, routeviews_base_url, routeviews_month_path
    from src.bgp_incident_detection.mrt_parser import bgpdump_version, parse_as_path_set, origin_asn_from_path
    from src.bgp_incident_detection.normal_pilot import (
        NORMAL_FEATURES,
        NORMAL_PERIODS,
        NORMAL_QUALIFICATION,
        parse_required,
    )


PILOT_DIR = Path("data/pilot")
RAW_RIB_DIR = Path("data/raw_mrt/normal_pilot_rib")

RIB_ACQUISITION_PLAN = PILOT_DIR / "normal_rib_acquisition_plan_v1.csv"
RIB_DOWNLOAD_AUDIT = PILOT_DIR / "normal_rib_download_audit_v1.csv"
RIB_STABILITY = PILOT_DIR / "normal_rib_stability_v1.csv"
RIB_UPDATE_QUALIFICATION = PILOT_DIR / "normal_rib_update_qualification_results_v1.csv"
NORMAL_METHOD_COMPARISON = PILOT_DIR / "normal_method_comparison_v1.csv"
RIB_SUSTAINED_SENSITIVITY = PILOT_DIR / "normal_rib_sustained_stability_sensitivity_v1.csv"
RIB_PARSER_ENV = PILOT_DIR / "normal_rib_parser_environment_v1.csv"

SUSTAINED_WINDOWS = {
    "15m": 3,
    "30m": 6,
    "60m": 12,
}
RIB_MATCH_SCAN_LIMIT = 1000
RIB_SCAN_TIMEOUT_SECONDS = 30


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def isoformat_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def routeviews_rib_filename(value: datetime) -> str:
    return f"rib.{value:%Y%m%d.%H%M}.bz2"


def routeviews_rib_url(value: datetime, collector: str = DEFAULT_COLLECTOR) -> str:
    return f"{routeviews_base_url(collector)}{routeviews_month_path(value)}/RIBS/{routeviews_rib_filename(value)}"


def rib_index_url(value: datetime, collector: str = DEFAULT_COLLECTOR) -> str:
    return f"{routeviews_base_url(collector)}{routeviews_month_path(value)}/RIBS/"


def local_rib_path(slot: datetime, collector: str = DEFAULT_COLLECTOR) -> str:
    return str(RAW_RIB_DIR / collector / routeviews_month_path(slot) / routeviews_rib_filename(slot))


def head_url(url: str, timeout_seconds: float = 20.0) -> tuple[str, str, int, str]:
    request = Request(url, method="HEAD", headers={"User-Agent": "bgp-incident-detection-pipeline/0.1"})
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            return str(200 <= response.status < 400), str(response.status), int(response.headers.get("Content-Length") or 0), "HEAD"
    except HTTPError as error:
        return "False", str(error.code), 0, f"HTTPError: {error.reason}"
    except URLError as error:
        return "False", "", 0, f"URLError: {error.reason}"


def available_rib_slots_for_month(month: datetime, collector: str = DEFAULT_COLLECTOR) -> list[datetime]:
    url = rib_index_url(month, collector)
    request = Request(url, headers={"User-Agent": "bgp-incident-detection-pipeline/0.1"})
    try:
        with urlopen(request, timeout=30.0) as response:
            html = response.read().decode("utf-8", errors="replace")
    except (HTTPError, URLError):
        return fallback_two_hour_slots(month)
    timestamps = sorted(set(re.findall(r"rib\.(\d{8}\.\d{4})\.bz2", html)))
    slots = [
        datetime.strptime(value, "%Y%m%d.%H%M").replace(tzinfo=timezone.utc)
        for value in timestamps
    ]
    return slots or fallback_two_hour_slots(month)


def fallback_two_hour_slots(month: datetime) -> list[datetime]:
    first = datetime(month.year, month.month, 1, tzinfo=timezone.utc)
    next_month = datetime(month.year + (month.month == 12), 1 if month.month == 12 else month.month + 1, 1, tzinfo=timezone.utc)
    slots = []
    cursor = first
    while cursor < next_month:
        slots.append(cursor)
        cursor += timedelta(hours=2)
    return slots


def month_floor(value: datetime) -> datetime:
    return datetime(value.year, value.month, 1, tzinfo=timezone.utc)


def surrounding_months(start: datetime, end: datetime) -> list[datetime]:
    months = {month_floor(start), month_floor(end)}
    before = start - timedelta(days=1)
    after = end + timedelta(days=1)
    months.add(month_floor(before))
    months.add(month_floor(after))
    return sorted(months)


def nearest_ribs(start: datetime, end: datetime, collector: str = DEFAULT_COLLECTOR) -> tuple[datetime, datetime, str]:
    slots = []
    for month in surrounding_months(start, end):
        slots.extend(available_rib_slots_for_month(month, collector))
    unique = sorted(set(slots))
    before = [slot for slot in unique if slot <= start]
    after = [slot for slot in unique if slot >= end]
    if not before or not after:
        raise ValueError(f"could not find surrounding RIBs for {start} to {end}")
    deltas = sorted(set((unique[index + 1] - unique[index]).total_seconds() / 60 for index in range(len(unique) - 1)))
    cadence = ",".join(str(int(value)) for value in deltas[:5])
    return before[-1], after[0], f"observed archive cadence minutes: {cadence}"


def build_rib_plan() -> list[dict[str, object]]:
    rows = []
    for period in load_csv(NORMAL_PERIODS):
        start = parse_required(period["candidate_start"])
        end = parse_required(period["candidate_end"])
        before, after, cadence_notes = nearest_ribs(start, end)
        before_available, before_status, before_size, before_notes = head_url(routeviews_rib_url(before))
        after_available, after_status, after_size, after_notes = head_url(routeviews_rib_url(after))
        rows.append(
            {
                "candidate_period_id": period["candidate_period_id"],
                "associated_incident_uid": period["associated_incident_uid"],
                "associated_category": period["associated_category"],
                "affected_asn": period["affected_asn"],
                "affected_prefix": period["affected_prefix"],
                "candidate_start": period["candidate_start"],
                "candidate_end": period["candidate_end"],
                "rib_before_timestamp": isoformat_z(before),
                "rib_after_timestamp": isoformat_z(after),
                "rib_before_url": routeviews_rib_url(before),
                "rib_after_url": routeviews_rib_url(after),
                "remote_available": str(before_available == "True" and after_available == "True"),
                "rib_before_status_code": before_status,
                "rib_after_status_code": after_status,
                "rib_before_estimated_content_length": before_size,
                "rib_after_estimated_content_length": after_size,
                "rib_before_local_path": local_rib_path(before),
                "rib_after_local_path": local_rib_path(after),
                "archive_cadence_notes": cadence_notes,
                "availability_notes": f"before={before_notes}; after={after_notes}",
            }
        )
    return rows


def write_rib_plan(rows: list[dict[str, object]]) -> None:
    write_csv(
        RIB_ACQUISITION_PLAN,
        rows,
        [
            "candidate_period_id",
            "associated_incident_uid",
            "associated_category",
            "affected_asn",
            "affected_prefix",
            "candidate_start",
            "candidate_end",
            "rib_before_timestamp",
            "rib_after_timestamp",
            "rib_before_url",
            "rib_after_url",
            "remote_available",
            "rib_before_status_code",
            "rib_after_status_code",
            "rib_before_estimated_content_length",
            "rib_after_estimated_content_length",
            "rib_before_local_path",
            "rib_after_local_path",
            "archive_cadence_notes",
            "availability_notes",
        ],
    )


def checksum_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_url(url: str, local_path: str, timeout_seconds: float = 300.0) -> dict[str, object]:
    path = Path(local_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.stat().st_size > 0:
        return {
            "mrt_url": url,
            "local_path": str(path),
            "http_status": "cached",
            "downloaded": "True",
            "file_size_bytes": path.stat().st_size,
            "sha256": checksum_file(path),
            "download_timestamp": isoformat_z(datetime.now(timezone.utc)),
            "compression_valid": str(validate_bzip2(path)),
            "notes": "cached existing file",
        }
    request = Request(url, headers={"User-Agent": "bgp-incident-detection-pipeline/0.1"})
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            path.write_bytes(response.read())
            return {
                "mrt_url": url,
                "local_path": str(path),
                "http_status": str(response.status),
                "downloaded": str(200 <= response.status < 400),
                "file_size_bytes": path.stat().st_size if path.exists() else 0,
                "sha256": checksum_file(path) if path.exists() else "",
                "download_timestamp": isoformat_z(datetime.now(timezone.utc)),
                "compression_valid": str(validate_bzip2(path)),
                "notes": "downloaded",
            }
    except (HTTPError, URLError) as error:
        return {
            "mrt_url": url,
            "local_path": str(path),
            "http_status": getattr(error, "code", ""),
            "downloaded": "False",
            "file_size_bytes": 0,
            "sha256": "",
            "download_timestamp": isoformat_z(datetime.now(timezone.utc)),
            "compression_valid": "False",
            "notes": str(error),
        }


def validate_bzip2(path: Path) -> bool:
    try:
        with bz2.open(path, "rb") as handle:
            handle.read(1024)
        return True
    except OSError:
        return False


def unique_rib_downloads(plan_rows: list[dict[str, str]]) -> list[dict[str, str]]:
    seen = {}
    for row in plan_rows:
        seen[row["rib_before_url"]] = row["rib_before_local_path"]
        seen[row["rib_after_url"]] = row["rib_after_local_path"]
    return [{"mrt_url": url, "local_path": path} for url, path in sorted(seen.items())]


def download_ribs() -> list[dict[str, object]]:
    rows = []
    plan = load_csv(RIB_ACQUISITION_PLAN)
    for row in unique_rib_downloads(plan):
        rows.append(download_url(row["mrt_url"], row["local_path"]))
    write_csv(
        RIB_DOWNLOAD_AUDIT,
        rows,
        ["mrt_url", "local_path", "http_status", "downloaded", "file_size_bytes", "sha256", "download_timestamp", "compression_valid", "notes"],
    )
    return rows


def parse_rib_line(line: str) -> dict[str, str] | None:
    parts = line.rstrip("\n").split("|")
    if len(parts) < 7:
        return None
    if parts[2] not in {"B", "A"}:
        return None
    as_path = parts[6]
    return {
        "timestamp": parts[1],
        "prefix": parts[5],
        "peer_asn": parts[4],
        "peer_ip": parts[3],
        "as_path": as_path,
        "origin_asn": origin_asn_from_path(as_path),
    }


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


def inspect_rib_with_mrtparse(path: str, affected_asn: str, affected_prefix: str) -> RibState:
    import mrtparse

    state = RibState()
    peers: dict[int, dict[str, str]] = {}
    for record in mrtparse.Reader(path):
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
            if state.matched_rows >= RIB_MATCH_SCAN_LIMIT:
                return state
    return state


def row_matches_target(row: dict[str, str], affected_asn: str, affected_prefix: str) -> bool:
    if affected_prefix and row["prefix"] == affected_prefix:
        return True
    path_asns = parse_as_path_set(row["as_path"])
    return bool(affected_asn and (row["origin_asn"] == affected_asn or row["peer_asn"] == affected_asn or affected_asn in path_asns))


@dataclass
class RibState:
    route_present: bool = False
    prefixes: set[str] = field(default_factory=set)
    origins: set[str] = field(default_factory=set)
    paths: Counter[str] = field(default_factory=Counter)
    peer_asns: set[str] = field(default_factory=set)
    matched_rows: int = 0
    scan_timed_out: bool = False


def inspect_rib(path: str, affected_asn: str, affected_prefix: str) -> RibState:
    state = RibState()
    command = ["bgpdump", "-q", "-m", path]
    grep_terms = [term for term in [affected_prefix, affected_asn] if term]
    process = subprocess.Popen(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    grep = None
    stdout = process.stdout
    if grep_terms and stdout is not None:
        grep_command = ["grep", "-F", "-m", str(RIB_MATCH_SCAN_LIMIT)]
        for term in grep_terms:
            grep_command.extend(["-e", term])
        grep = subprocess.Popen(grep_command, text=True, stdin=stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout.close()
        stdout = grep.stdout
    assert stdout is not None
    try:
        output, _ = (grep.communicate(timeout=RIB_SCAN_TIMEOUT_SECONDS) if grep is not None else process.communicate(timeout=RIB_SCAN_TIMEOUT_SECONDS))
    except subprocess.TimeoutExpired:
        state.scan_timed_out = True
        if grep is not None:
            grep.kill()
            output, _ = grep.communicate()
        else:
            process.kill()
            output, _ = process.communicate()
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()
    for line in output.splitlines():
        parsed = parse_rib_line(line)
        if parsed is None:
            continue
        if not row_matches_target(parsed, affected_asn, affected_prefix):
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
    return state


def compact_set(values: set[str], limit: int = 20) -> str:
    ordered = sorted(values)
    return json.dumps(ordered[:limit], separators=(",", ":"))


def top_paths(paths: Counter[str], limit: int = 5) -> str:
    return json.dumps([path for path, _ in paths.most_common(limit)], separators=(",", ":"))


def state_key(state: RibState) -> tuple[frozenset[str], frozenset[str]]:
    return frozenset(state.prefixes), frozenset(state.origins)


def build_rib_stability() -> list[dict[str, object]]:
    rows = []
    plan = load_csv(RIB_ACQUISITION_PLAN)
    state_cache: dict[tuple[str, str, str], RibState] = {}
    for row in plan:
        before_key = (row["rib_before_local_path"], row["affected_asn"], row["affected_prefix"])
        after_key = (row["rib_after_local_path"], row["affected_asn"], row["affected_prefix"])
        if before_key not in state_cache:
            state_cache[before_key] = inspect_rib(*before_key)
        if after_key not in state_cache:
            state_cache[after_key] = inspect_rib(*after_key)
        before = state_cache[before_key]
        after = state_cache[after_key]
        common_prefixes = before.prefixes & after.prefixes
        origins_stable = bool(before.origins and before.origins == after.origins)
        route_stable = before.route_present and after.route_present and bool(common_prefixes or row["affected_prefix"])
        exact_paths_same = bool(before.paths and set(before.paths) == set(after.paths))
        path_status = "STABLE_EXACT" if exact_paths_same else ("REVIEW_CHANGED_PATHS" if route_stable else "UNKNOWN")
        target_prefixes = sorted(common_prefixes or before.prefixes or after.prefixes or ({row["affected_prefix"]} if row["affected_prefix"] else set()))
        if not target_prefixes:
            target_prefixes = [""]
        for prefix in target_prefixes[:50]:
            rows.append(
                {
                    "candidate_period_id": row["candidate_period_id"],
                    "prefix": prefix,
                    "origin_before": compact_set(before.origins),
                    "origin_after": compact_set(after.origins),
                    "route_present_before": str(before.route_present),
                    "route_present_after": str(after.route_present),
                    "path_before": top_paths(before.paths),
                    "path_after": top_paths(after.paths),
                    "origin_stable": str(origins_stable),
                    "route_presence_stable": str(route_stable),
                    "path_stability_status": path_status,
                    "matched_rib_rows_before": before.matched_rows,
                    "matched_rib_rows_after": after.matched_rows,
                    "matched_prefix_count_before": len(before.prefixes),
                    "matched_prefix_count_after": len(after.prefixes),
                    "rib_scan_timed_out_before": str(before.scan_timed_out),
                    "rib_scan_timed_out_after": str(after.scan_timed_out),
                    "notes": "bounded pilot RIB evidence scan; exact prefix inspected when available; otherwise ASN/path-origin matching was used",
                    "scan_limit": RIB_MATCH_SCAN_LIMIT,
                }
            )
    write_csv(
        RIB_STABILITY,
        rows,
        [
            "candidate_period_id",
            "prefix",
            "origin_before",
            "origin_after",
            "route_present_before",
            "route_present_after",
            "path_before",
            "path_after",
            "origin_stable",
            "route_presence_stable",
            "path_stability_status",
            "matched_rib_rows_before",
            "matched_rib_rows_after",
            "matched_prefix_count_before",
            "matched_prefix_count_after",
            "rib_scan_timed_out_before",
            "rib_scan_timed_out_after",
            "notes",
            "scan_limit",
        ],
    )
    return rows


def suspicious_update(row: pd.Series) -> bool:
    if not bool(row["has_relevant_observation"]):
        return False
    return bool(
        int(row["unique_origin_asn_count"]) > 1
        or int(row["moas_prefix_count"]) > 0
        or float(row["origin_change_event_count"]) > 0
        or int(row["unique_as_path_count"]) > max(10, int(row["update_count"]) * 0.1)
    )


def stable_periods_by_sustained_requirement(base_rows: list[dict[str, object]], required_windows: int) -> set[str]:
    stable_periods = set()
    by_period: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in base_rows:
        by_period[str(row["candidate_period_id"])].append(row)
    for period_id, rows in by_period.items():
        run = 0
        for row in sorted(rows, key=lambda item: str(item["window_start"])):
            stable = row["qualification_status"] == "PASS_RIB_STABLE_SILENCE" or row["qualification_status"] == "PASS_RIB_STABLE_LOW_UPDATE"
            run = run + 1 if stable else 0
            if run >= required_windows:
                stable_periods.add(period_id)
                break
    return stable_periods


def reevaluate_windows() -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    features = pd.read_parquet(NORMAL_FEATURES)
    periods = {row["candidate_period_id"]: row for row in load_csv(NORMAL_PERIODS)}
    stability_rows = load_csv(RIB_STABILITY)
    stable_by_period = defaultdict(list)
    for row in stability_rows:
        stable_by_period[row["candidate_period_id"]].append(row)
    base_rows = []
    for _, feature in features.sort_values(["candidate_period_id", "window_start"]).iterrows():
        period_id = str(feature["candidate_period_id"])
        stabilities = stable_by_period.get(period_id, [])
        rib_route_confirmed = any(row["route_presence_stable"] == "True" for row in stabilities)
        rib_origin_stable = any(row["origin_stable"] == "True" for row in stabilities)
        update_count = int(feature["update_count"])
        suspicious = suspicious_update(feature)
        stable_silence = update_count == 0 and rib_route_confirmed and rib_origin_stable and not suspicious
        low_update_stable = update_count > 0 and rib_route_confirmed and rib_origin_stable and not suspicious
        if stable_silence:
            status = "PASS_RIB_STABLE_SILENCE"
            reason = "zero relevant UPDATE observations accepted because before/after RIB state confirms stable visibility and origin"
        elif low_update_stable:
            status = "PASS_RIB_STABLE_LOW_UPDATE"
            reason = "relevant UPDATE observations present but no suspicious route-change signal and RIB state is stable"
        elif not rib_route_confirmed:
            status = "UNKNOWN_RIB_ROUTE_NOT_CONFIRMED"
            reason = "RIB snapshots do not confirm stable visibility for the associated ASN/prefix/network"
        elif not rib_origin_stable:
            status = "UNKNOWN_RIB_ORIGIN_NOT_STABLE"
            reason = "RIB snapshots do not confirm stable origin state"
        else:
            status = "UNKNOWN_SUSPICIOUS_UPDATE"
            reason = "UPDATE activity contains suspicious route-change signal"
        base_rows.append(
            {
                "candidate_period_id": period_id,
                "window_id": feature["window_id"],
                "window_start": feature["window_start"],
                "window_end": feature["window_end"],
                "rib_route_confirmed": str(rib_route_confirmed),
                "rib_origin_stable": str(rib_origin_stable),
                "relevant_update_count": update_count,
                "suspicious_update_detected": str(suspicious),
                "stable_silence": str(stable_silence),
                "qualification_status": status,
                "associated_category": periods[period_id]["associated_category"],
                "candidate_offset": periods[period_id]["candidate_offset"],
                "reason": reason,
            }
        )
    stable_30 = stable_periods_by_sustained_requirement(base_rows, SUSTAINED_WINDOWS["30m"])
    qualification = []
    for row in base_rows:
        passed = row["candidate_period_id"] in stable_30 and row["qualification_status"] in {
            "PASS_RIB_STABLE_SILENCE",
            "PASS_RIB_STABLE_LOW_UPDATE",
        }
        qualification.append({**row, "final_state": "NORMAL_VERIFIED" if passed else "UNKNOWN"})
    write_csv(
        RIB_UPDATE_QUALIFICATION,
        qualification,
        [
            "candidate_period_id",
            "window_id",
            "window_start",
            "window_end",
            "rib_route_confirmed",
            "rib_origin_stable",
            "relevant_update_count",
            "suspicious_update_detected",
            "stable_silence",
            "qualification_status",
            "final_state",
            "reason",
        ],
    )
    sensitivity = build_sensitivity(base_rows)
    write_csv(
        RIB_SUSTAINED_SENSITIVITY,
        sensitivity,
        [
            "sustained_stability_minutes",
            "minimum_consecutive_windows",
            "verified_windows",
            "unknown_windows",
            "verified_periods",
            "interpretation",
        ],
    )
    return qualification, sensitivity


def build_sensitivity(base_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    output = []
    for label, required in SUSTAINED_WINDOWS.items():
        stable_periods = stable_periods_by_sustained_requirement(base_rows, required)
        verified = sum(
            1
            for row in base_rows
            if row["candidate_period_id"] in stable_periods
            and row["qualification_status"] in {"PASS_RIB_STABLE_SILENCE", "PASS_RIB_STABLE_LOW_UPDATE"}
        )
        minutes = int(label.removesuffix("m"))
        output.append(
            {
                "sustained_stability_minutes": minutes,
                "minimum_consecutive_windows": required,
                "verified_windows": verified,
                "unknown_windows": len(base_rows) - verified,
                "verified_periods": len(stable_periods),
                "interpretation": "pilot sensitivity only; not a frozen Normal-label rule",
            }
        )
    return output


def write_method_comparison(rib_update_rows: list[dict[str, object]]) -> None:
    method_a = load_csv(NORMAL_QUALIFICATION)
    method_a_verified = sum(row["final_state"] == "NORMAL_VERIFIED" for row in method_a)
    method_b_verified = sum(row["final_state"] == "NORMAL_VERIFIED" for row in rib_update_rows)
    candidate_windows = len(rib_update_rows)
    rows = [
        {
            "method": "A_UPDATE_EVIDENCE_ONLY",
            "candidate_windows": candidate_windows,
            "verified_normal_windows": method_a_verified,
            "unknown_windows": candidate_windows - method_a_verified,
            "false_rejection_risk": "HIGH",
            "methodological_interpretation": "UPDATE archives record changes, so silent stable routing can be incorrectly rejected without RIB state",
        },
        {
            "method": "B_RIB_STATE_PLUS_UPDATE_ACTIVITY",
            "candidate_windows": candidate_windows,
            "verified_normal_windows": method_b_verified,
            "unknown_windows": candidate_windows - method_b_verified,
            "false_rejection_risk": "LOWER_BUT_DEPENDS_ON_RIB_VISIBILITY",
            "methodological_interpretation": "RIB state can validate stable silence when before/after routing state is visible and origin-stable",
        },
    ]
    write_csv(
        NORMAL_METHOD_COMPARISON,
        rows,
        [
            "method",
            "candidate_windows",
            "verified_normal_windows",
            "unknown_windows",
            "false_rejection_risk",
            "methodological_interpretation",
        ],
    )


def write_parser_environment() -> None:
    write_csv(
        RIB_PARSER_ENV,
        [
            {
                "tool_or_library": "bgpdump",
                "version": bgpdump_version(),
                "exact_command_or_function": "bgpdump -q -m <routeviews-rib-file.bz2>",
                "input_format": "RouteViews MRT RIB .bz2",
                "output_fields": "timestamp|prefix|peer_asn|peer_ip|as_path|origin_asn",
                "row_granularity": "one RouteViews RIB route entry visible from one peer",
            }
        ],
        ["tool_or_library", "version", "exact_command_or_function", "input_format", "output_fields", "row_granularity"],
    )


def run_prepare() -> list[dict[str, object]]:
    rows = build_rib_plan()
    write_rib_plan(rows)
    write_parser_environment()
    return rows


def run_full() -> dict[str, object]:
    plan = load_csv(RIB_ACQUISITION_PLAN) if RIB_ACQUISITION_PLAN.exists() else run_prepare()
    downloads = download_ribs()
    stability = build_rib_stability()
    qualification, sensitivity = reevaluate_windows()
    write_method_comparison(qualification)
    return {
        "rib_files_required": len(unique_rib_downloads(plan)),
        "rib_files_downloaded": sum(row["downloaded"] == "True" for row in downloads),
        "visible_periods": len({row["candidate_period_id"] for row in stability if row["route_presence_stable"] == "True"}),
        "stable_silence_windows": sum(row["stable_silence"] == "True" for row in qualification),
        "normal_verified_30m": sum(row["final_state"] == "NORMAL_VERIFIED" for row in qualification),
        "unknown_30m": sum(row["final_state"] == "UNKNOWN" for row in qualification),
        "sensitivity": sensitivity,
    }


def print_prepare_summary(rows: list[dict[str, object]]) -> None:
    unique_urls = {}
    for row in rows:
        unique_urls[row["rib_before_url"]] = int(row["rib_before_estimated_content_length"])
        unique_urls[row["rib_after_url"]] = int(row["rib_after_estimated_content_length"])
    print(f"candidate_periods={len(rows)}")
    print(f"unique_rib_files_required={len(unique_urls)}")
    print(f"remote_available={sum(row['remote_available'] == 'True' for row in rows)}/{len(rows)} periods")
    print(f"estimated_bytes={sum(unique_urls.values())}")
    print(f"estimated_mib={round(sum(unique_urls.values()) / 1024 / 1024, 2)}")
    for row in rows:
        print(
            f"{row['candidate_period_id']} before={row['rib_before_timestamp']} "
            f"after={row['rib_after_timestamp']} available={row['remote_available']}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="RIB-assisted Normal pilot verification")
    parser.add_argument("--prepare-only", action="store_true", help="Build and HEAD-check the RIB acquisition plan only")
    parser.add_argument("--download-parse-qualify", action="store_true", help="Download selected RIBs, inspect state, and re-qualify Normal windows")
    args = parser.parse_args()
    if args.prepare_only:
        print_prepare_summary(run_prepare())
    elif args.download_parse_qualify:
        print(json.dumps(run_full(), indent=2))
    else:
        parser.error("choose --prepare-only or --download-parse-qualify")


if __name__ == "__main__":
    main()
