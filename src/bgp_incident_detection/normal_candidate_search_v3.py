from __future__ import annotations

import argparse
import csv
import json
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from bgp_incident_detection.audit import parse_listish, parse_utc, write_csv
    from bgp_incident_detection.mrt_acquisition import (
        DEFAULT_COLLECTOR,
        ceil_to_15_minutes,
        floor_to_15_minutes,
        iter_update_slots,
        routeviews_update_url,
    )
    from bgp_incident_detection.normal_baseline import related_incident_overlap, roster_index
    from bgp_incident_detection.normal_rib_prescreen import COLLECTOR_SEQUENCE, download_file, head_url, local_rib_path, rib_url_for
    from bgp_incident_detection.rib_normal import RibState, nearest_ribs, parse_rib_line, row_matches_target
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import parse_listish, parse_utc, write_csv
    from src.bgp_incident_detection.mrt_acquisition import (
        DEFAULT_COLLECTOR,
        ceil_to_15_minutes,
        floor_to_15_minutes,
        iter_update_slots,
        routeviews_update_url,
    )
    from src.bgp_incident_detection.normal_baseline import related_incident_overlap, roster_index
    from src.bgp_incident_detection.normal_rib_prescreen import COLLECTOR_SEQUENCE, download_file, head_url, local_rib_path, rib_url_for
    from src.bgp_incident_detection.rib_normal import RibState, nearest_ribs, parse_rib_line, row_matches_target


PILOT_DIR = Path("data/pilot")
ROSTER = Path("data/roster_v2/frozen_incident_roster_v2.csv")
PILOT_MANIFEST = PILOT_DIR / "mrt_pilot_incidents_v1.csv"
ACTIVE_SEGMENTS = PILOT_DIR / "pilot_candidate_active_segments_v1.csv"
EXISTING_READY = PILOT_DIR / "normal_update_ready_candidates_v1.csv"

ADDITIONAL_CANDIDATES = PILOT_DIR / "normal_additional_replacement_candidates_v1.csv"
SECOND_PILOT_MANIFEST = PILOT_DIR / "normal_second_pilot_candidate_manifest_v1.csv"
SECOND_PILOT_ACQUISITION_PLAN = PILOT_DIR / "normal_second_pilot_acquisition_plan_v1.csv"

UNRESOLVED_CONTROLS = ("Hijack:58159", "Hijack:97511", "Leak:426483")
OFFSETS = (-1, 1, -3, 3, -7, 7, -14, 14, -21, 21, -30, 30)
TARGET_READY_PER_CONTROL = 3
MAX_EVALUATED_PER_CONTROL = 20
MIN_DURATION_MINUTES = 30
EXCLUSION_BUFFER_MINUTES = 60
CONTEXT_BUFFER_MINUTES = 60
GAP_RULE = "max_gap_between_active_bins<=60m"
INSPECTION_CACHE: dict[tuple[str, str, str, str], dict[str, object]] = {}
NEAREST_RIB_CACHE: dict[tuple[str, str, str], tuple[datetime, datetime]] = {}
QUICK_RIB_SCAN_TIMEOUT_SECONDS = 8
MAX_PREFIXES_PER_HIJACK = 8


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


def first_value(value: str | None) -> str:
    values = parse_listish(value)
    return values[0] if values else ""


def anchor_for(row: dict[str, str]) -> tuple[str, str]:
    if row["category"] == "Leak":
        return row.get("leak_asn") or first_value(row.get("affected_asns")), first_value(row.get("affected_prefixes"))
    return first_value(row.get("affected_asns")), first_value(row.get("affected_prefixes"))


def anchors_for(row: dict[str, str]) -> list[tuple[str, str]]:
    if row["category"] == "Leak":
        return [anchor_for(row)]
    asn = first_value(row.get("affected_asns"))
    prefixes = parse_listish(row.get("affected_prefixes"))[:MAX_PREFIXES_PER_HIJACK]
    return [(asn, prefix) for prefix in prefixes] or [(asn, "")]


def active_ranges() -> dict[str, list[tuple[str, datetime]]]:
    ranges: dict[str, list[tuple[str, datetime]]] = defaultdict(list)
    for row in load_csv(ACTIVE_SEGMENTS):
        if row["incident_uid"] not in UNRESOLVED_CONTROLS:
            continue
        if row["gap_rule"] != GAP_RULE:
            continue
        ranges[row["incident_uid"]].append((f"segment_{row['active_segment_index']}", parse_required(row["active_segment_start"])))
    return {uid: sorted(values, key=lambda item: item[1]) for uid, values in ranges.items()}


def candidate_period_id(row: dict[str, object]) -> str:
    safe_time = str(row["candidate_start"]).replace(":", "").replace("-", "").replace(".000Z", "Z")
    segment = str(row["source_active_segment"]).replace("segment_", "s")
    prefix = str(row.get("affected_prefix") or "asn").replace("/", "_").replace(".", "_")
    return f"{str(row['associated_incident_uid']).replace(':', '_')}_{prefix}_{segment}_offset_{int(row['days_from_incident']):+d}_{safe_time}"


def base_candidate_rows() -> list[dict[str, object]]:
    pilot = {row["incident_uid"]: row for row in load_csv(PILOT_MANIFEST)}
    ranges = active_ranges()
    rows: list[dict[str, object]] = []
    for uid in UNRESOLVED_CONTROLS:
        pilot_row = pilot[uid]
        anchors = anchors_for(pilot_row)
        for segment_id, active_start in ranges[uid]:
            for offset in OFFSETS:
                for asn, prefix in anchors:
                    candidate_start = active_start + timedelta(days=offset)
                    candidate_end = candidate_start + timedelta(minutes=MIN_DURATION_MINUTES)
                    row = {
                        "associated_incident_uid": uid,
                        "category": pilot_row["category"],
                        "affected_asn": asn,
                        "affected_prefix": prefix,
                        "source_active_segment": segment_id,
                        "candidate_start": isoformat_z(candidate_start),
                        "candidate_end": isoformat_z(candidate_end),
                        "candidate_duration_minutes": MIN_DURATION_MINUTES,
                        "days_from_incident": offset,
                    }
                    row["candidate_period_id"] = candidate_period_id(row)
                    rows.append(row)
    return rows


def attach_overlap(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    known = roster_index(load_csv(ROSTER))
    output = []
    for row in rows:
        start = parse_required(str(row["candidate_start"]))
        end = parse_required(str(row["candidate_end"]))
        direct, direct_ids = related_incident_overlap(
            start,
            end,
            str(row["affected_asn"]),
            str(row["affected_prefix"]),
            known,
            str(row["associated_incident_uid"]),
            buffer_minutes=0,
        )
        buffered, buffer_ids = related_incident_overlap(
            start,
            end,
            str(row["affected_asn"]),
            str(row["affected_prefix"]),
            known,
            str(row["associated_incident_uid"]),
            buffer_minutes=EXCLUSION_BUFFER_MINUTES,
        )
        enriched = dict(row)
        enriched["known_incident_overlap"] = str(direct or buffered)
        enriched["overlap_notes"] = (
            f"direct_overlap_ids={json.dumps(direct_ids, separators=(',', ':'))}; "
            f"buffer_overlap_ids={json.dumps(buffer_ids, separators=(',', ':'))}; "
            f"exclusion_buffer_minutes={EXCLUSION_BUFFER_MINUTES}"
        )
        output.append(enriched)
    return output


def candidate_for_prescreen(row: dict[str, object]) -> dict[str, str]:
    return {
        "associated_incident_uid": str(row["associated_incident_uid"]),
        "category": str(row["category"]),
        "affected_asn": str(row["affected_asn"]),
        "affected_prefix": str(row["affected_prefix"]),
        "candidate_start": str(row["candidate_start"]),
        "candidate_end": str(row["candidate_end"]),
        "days_from_incident": str(row["days_from_incident"]),
        "known_incident_overlap": str(row["known_incident_overlap"]),
    }


def inspect_candidate(row: dict[str, object]) -> dict[str, object]:
    if int(row["candidate_duration_minutes"]) < MIN_DURATION_MINUTES:
        return status_row(row, "INELIGIBLE_DURATION", "", "", "", "", "False", "False", "False", "False", "duration below 30 minutes")
    if row["known_incident_overlap"] == "True":
        return status_row(row, "KNOWN_INCIDENT_OVERLAP", "", "", "", "", "False", "False", "False", "False", str(row["overlap_notes"]))

    checked_notes = []
    for collector in [DEFAULT_COLLECTOR]:
        cache_key = (
            str(row["candidate_start"]),
            str(row["candidate_end"]),
            str(row["affected_asn"]),
            str(row["affected_prefix"]),
            collector,
        )
        if cache_key not in INSPECTION_CACHE:
            INSPECTION_CACHE[cache_key] = inspect_candidate_on_collector_quick(candidate_for_prescreen(row), collector)
        result = INSPECTION_CACHE[cache_key]
        checked_notes.append(f"{collector}:{result['rib_visibility_status']}")
        if result["rib_visibility_status"] == "PASS":
            return status_row(
                row,
                "UPDATE_READY",
                collector,
                str(result["asn_visible_before"]),
                str(result["asn_visible_after"]),
                str(result["origin_stable"]),
                str(result["route_presence_stable"]),
                str(result["rib_before_timestamp"]),
                str(result["rib_after_timestamp"]),
                str(result["prefix_visible_before"]),
                "selected first collector with positive RIB visibility; " + "; ".join(checked_notes),
            )
        if collector == DEFAULT_COLLECTOR and result["rib_visibility_status"] == "PASS":
            break
    statuses = {note.split(":", 1)[1] for note in checked_notes}
    if statuses == {"NO_OBSERVABILITY"}:
        final_status = "NO_OBSERVABILITY"
        reason = "; ".join(checked_notes)
    else:
        final_status = "RIB_REVIEW"
        reason = "; ".join(checked_notes)
    if final_status != "UPDATE_READY":
        reason += "; alternate collectors require separate targeted parsing if route-views2 does not provide quick observability"
    return status_row(row, final_status, "", "False", "False", "False", "False", "", "", "", reason)


def quick_inspect_rib(path: str, affected_asn: str, affected_prefix: str) -> RibState:
    state = RibState()
    command = ["bgpdump", "-q", "-m", path]
    grep_terms = [term for term in [affected_prefix, affected_asn] if term]
    process = subprocess.Popen(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    grep = None
    stdout = process.stdout
    if grep_terms and stdout is not None:
        grep_command = ["grep", "-F", "-m", "200"]
        for term in grep_terms:
            grep_command.extend(["-e", term])
        grep = subprocess.Popen(grep_command, text=True, stdin=stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout.close()
    try:
        output, _ = (grep.communicate(timeout=QUICK_RIB_SCAN_TIMEOUT_SECONDS) if grep else process.communicate(timeout=QUICK_RIB_SCAN_TIMEOUT_SECONDS))
    except subprocess.TimeoutExpired:
        state.scan_timed_out = True
        if grep:
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
    return state


def inspect_candidate_on_collector_quick(row: dict[str, str], collector: str) -> dict[str, object]:
    start = parse_required(row["candidate_start"])
    end = parse_required(row["candidate_end"])
    rib_cache_key = (isoformat_z(start), isoformat_z(end), DEFAULT_COLLECTOR)
    if rib_cache_key not in NEAREST_RIB_CACHE:
        before, after, _ = nearest_ribs(start, end, DEFAULT_COLLECTOR)
        NEAREST_RIB_CACHE[rib_cache_key] = (before, after)
    before, after = NEAREST_RIB_CACHE[rib_cache_key]
    before_url = rib_url_for(before, collector)
    after_url = rib_url_for(after, collector)
    before_available, before_status, _, before_notes = head_url(before_url)
    after_available, after_status, _, after_notes = head_url(after_url)
    before_state = RibState()
    after_state = RibState()
    if before_available and after_available:
        before_path = local_rib_path(before, collector)
        after_path = local_rib_path(after, collector)
        before_ok, _, _, _ = download_file(before_url, before_path)
        after_ok, _, _, _ = download_file(after_url, after_path)
        if before_ok:
            before_state = quick_inspect_rib(before_path, row["affected_asn"], row.get("affected_prefix") or "")
        if after_ok:
            after_state = quick_inspect_rib(after_path, row["affected_asn"], row.get("affected_prefix") or "")
    prefix = row.get("affected_prefix") or ""
    route_stable = before_state.route_present and after_state.route_present
    prefix_stable = True if not prefix else prefix in before_state.prefixes and prefix in after_state.prefixes
    origin_stable = bool(before_state.origins) and before_state.origins == after_state.origins
    if route_stable and prefix_stable and (origin_stable or not prefix):
        status = "PASS"
    elif before_state.scan_timed_out or after_state.scan_timed_out:
        status = "RIB_REVIEW"
    else:
        status = "NO_OBSERVABILITY"
    return {
        "rib_visibility_status": status,
        "collector": collector,
        "asn_visible_before": str(before_state.route_present),
        "asn_visible_after": str(after_state.route_present),
        "origin_stable": str(origin_stable),
        "route_presence_stable": str(route_stable),
        "rib_before_timestamp": isoformat_z(before),
        "rib_after_timestamp": isoformat_z(after),
        "prefix_visible_before": str(prefix in before_state.prefixes) if prefix else "NOT_APPLICABLE",
        "prefix_visible_after": str(prefix in after_state.prefixes) if prefix else "NOT_APPLICABLE",
        "notes": f"before_head={before_status or before_notes}; after_head={after_status or after_notes}",
    }


def status_row(
    row: dict[str, object],
    status: str,
    collector: str,
    rib_before_visible: str,
    rib_after_visible: str,
    origin_stable: str,
    route_presence_stable: str,
    rib_before_timestamp: str,
    rib_after_timestamp: str,
    prefix_visible: str,
    reason: str,
) -> dict[str, object]:
    return {
        "associated_incident_uid": row["associated_incident_uid"],
        "category": row["category"],
        "affected_asn": row["affected_asn"],
        "affected_prefix": row["affected_prefix"],
        "candidate_start": row["candidate_start"],
        "candidate_end": row["candidate_end"],
        "candidate_duration_minutes": row["candidate_duration_minutes"],
        "days_from_incident": row["days_from_incident"],
        "collector": collector,
        "rib_visible_before": rib_before_visible,
        "rib_visible_after": rib_after_visible,
        "origin_stable": origin_stable,
        "route_presence_stable": route_presence_stable,
        "known_incident_overlap": row["known_incident_overlap"],
        "duration_pass": str(int(row["candidate_duration_minutes"]) >= MIN_DURATION_MINUTES),
        "prescreen_status": status,
        "selection_reason": reason,
        "candidate_period_id": row["candidate_period_id"],
        "source_active_segment": row["source_active_segment"],
        "rib_before_timestamp": rib_before_timestamp,
        "rib_after_timestamp": rib_after_timestamp,
        "prefix_visible": prefix_visible,
    }


def search_candidates() -> list[dict[str, object]]:
    evaluated: list[dict[str, object]] = []
    ready_counts: Counter[str] = Counter()
    evaluated_counts: Counter[str] = Counter()
    for row in attach_overlap(base_candidate_rows()):
        uid = str(row["associated_incident_uid"])
        if ready_counts[uid] >= TARGET_READY_PER_CONTROL:
            continue
        if evaluated_counts[uid] >= MAX_EVALUATED_PER_CONTROL:
            continue
        result = inspect_candidate(row)
        evaluated.append(result)
        evaluated_counts[uid] += 1
        if result["prescreen_status"] == "UPDATE_READY":
            ready_counts[uid] += 1
            print(f"{uid}: accepted {ready_counts[uid]}/{TARGET_READY_PER_CONTROL} {result['candidate_period_id']}", flush=True)
        else:
            print(f"{uid}: {result['prescreen_status']} {result['candidate_period_id']}", flush=True)
    write_csv(
        ADDITIONAL_CANDIDATES,
        evaluated,
        [
            "associated_incident_uid",
            "category",
            "affected_asn",
            "affected_prefix",
            "candidate_start",
            "candidate_end",
            "candidate_duration_minutes",
            "days_from_incident",
            "collector",
            "rib_visible_before",
            "rib_visible_after",
            "origin_stable",
            "route_presence_stable",
            "known_incident_overlap",
            "duration_pass",
            "prescreen_status",
            "selection_reason",
            "candidate_period_id",
            "source_active_segment",
            "rib_before_timestamp",
            "rib_after_timestamp",
            "prefix_visible",
        ],
    )
    return evaluated


def build_second_manifest(additional: list[dict[str, object]]) -> list[dict[str, object]]:
    existing = load_csv(EXISTING_READY)
    rows: list[dict[str, object]] = []
    for row in existing:
        rows.append(
            {
                "candidate_period_id": row["candidate_period_id"],
                "associated_incident_uid": row["associated_incident_uid"],
                "category": row["associated_category"],
                "affected_asn": row["affected_asn"],
                "affected_prefix": row["affected_prefix"],
                "candidate_start": row["candidate_start"],
                "candidate_end": row["candidate_end"],
                "candidate_duration_minutes": row["duration_minutes"],
                "collector": row["collector"],
                "candidate_source": "existing_rib_prescreen_v1",
                "prescreen_status": row["final_prescreen_status"],
            }
        )
    for row in additional:
        if row["prescreen_status"] != "UPDATE_READY":
            continue
        rows.append(
            {
                "candidate_period_id": row["candidate_period_id"],
                "associated_incident_uid": row["associated_incident_uid"],
                "category": row["category"],
                "affected_asn": row["affected_asn"],
                "affected_prefix": row["affected_prefix"],
                "candidate_start": row["candidate_start"],
                "candidate_end": row["candidate_end"],
                "candidate_duration_minutes": row["candidate_duration_minutes"],
                "collector": row["collector"],
                "candidate_source": "additional_search_v3",
                "prescreen_status": row["prescreen_status"],
            }
        )
    write_csv(
        SECOND_PILOT_MANIFEST,
        rows,
        [
            "candidate_period_id",
            "associated_incident_uid",
            "category",
            "affected_asn",
            "affected_prefix",
            "candidate_start",
            "candidate_end",
            "candidate_duration_minutes",
            "collector",
            "candidate_source",
            "prescreen_status",
        ],
    )
    return rows


def update_slots(start_text: str, end_text: str) -> list[datetime]:
    start = floor_to_15_minutes(parse_required(start_text) - timedelta(minutes=CONTEXT_BUFFER_MINUTES))
    end = ceil_to_15_minutes(parse_required(end_text) + timedelta(minutes=CONTEXT_BUFFER_MINUTES))
    return iter_update_slots(start, end)


def build_acquisition_plan(manifest_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    rows = []
    for candidate in manifest_rows:
        slots = update_slots(str(candidate["candidate_start"]), str(candidate["candidate_end"]))
        collection_start = isoformat_z(slots[0])
        collection_end = isoformat_z(slots[-1])
        for slot in slots:
            url = routeviews_update_url(slot, str(candidate["collector"]))
            available, status_code, content_length, notes = head_url(url)
            rows.append(
                {
                    "candidate_period_id": candidate["candidate_period_id"],
                    "associated_incident_uid": candidate["associated_incident_uid"],
                    "category": candidate["category"],
                    "collector": candidate["collector"],
                    "collection_start": collection_start,
                    "collection_end": collection_end,
                    "mrt_timestamp": isoformat_z(slot),
                    "mrt_url": url,
                    "remote_available": str(available),
                    "status_code": status_code,
                    "estimated_content_length": content_length,
                    "notes": f"{notes}; dry-run only, no UPDATE download",
                }
            )
    write_csv(
        SECOND_PILOT_ACQUISITION_PLAN,
        rows,
        [
            "candidate_period_id",
            "associated_incident_uid",
            "category",
            "collector",
            "collection_start",
            "collection_end",
            "mrt_timestamp",
            "mrt_url",
            "remote_available",
            "status_code",
            "estimated_content_length",
            "notes",
        ],
    )
    return rows


def run() -> dict[str, object]:
    additional = search_candidates()
    manifest = build_second_manifest(additional)
    plan = build_acquisition_plan(manifest)
    ready_by_uid = Counter(row["associated_incident_uid"] for row in additional if row["prescreen_status"] == "UPDATE_READY")
    return {
        "new_candidates_evaluated": len(additional),
        "new_update_ready": sum(row["prescreen_status"] == "UPDATE_READY" for row in additional),
        "new_update_ready_by_control": dict(ready_by_uid),
        "all_unresolved_have_ready": all(ready_by_uid[uid] >= 1 for uid in UNRESOLVED_CONTROLS),
        "alternate_collectors": sorted({row["collector"] for row in additional if row["prescreen_status"] == "UPDATE_READY" and row["collector"] != DEFAULT_COLLECTOR}),
        "second_pilot_candidates": len(manifest),
        "second_pilot_update_files": len(plan),
        "all_update_files_available": all(row["remote_available"] == "True" for row in plan),
        "estimated_update_mib": round(sum(int(row["estimated_content_length"]) for row in plan) / 1024 / 1024, 2),
        "prescreen_status_counts": dict(Counter(row["prescreen_status"] for row in additional)),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Find and pre-screen additional Normal replacement candidates")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if not args.run:
        parser.error("choose --run")
    print(json.dumps(run(), indent=2))


if __name__ == "__main__":
    main()
