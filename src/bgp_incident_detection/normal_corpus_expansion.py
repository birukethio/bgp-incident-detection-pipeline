from __future__ import annotations

import argparse
import csv
import json
import math
import sqlite3
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

import pandas as pd

try:
    from bgp_incident_detection.audit import parse_utc, write_csv
    from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES
    from bgp_incident_detection.mrt_acquisition import ceil_to_15_minutes, floor_to_15_minutes, iter_update_slots, routeviews_update_url
    from bgp_incident_detection.normal_50_rib_cache_fill import download_rib, local_rib_path, update_rib_cache_index
    from bgp_incident_detection.normal_pool_scale import CONTEXT_BUFFER_MINUTES, EXCLUSION_BUFFER_MINUTES, MIN_DURATION_MINUTES, PRESCREEN_PASS
    from bgp_incident_detection.normal_rib_batch50 import RIB_DATA_REQUIRED, classify_from_index, head_url, indexed_ribs, previously_screened_ids
    from bgp_incident_detection.normal_update_scale import (
        BEHAVIORAL_FEATURE_COUNT,
        BEHAVIORAL_FEATURE_VERSION,
        MIN_STABLE_WINDOWS,
        NORMAL_METHOD_VERSION,
        build_acquisition_plan,
        download_one,
        parse_downloads,
        qualify,
    )
    from bgp_incident_detection.rib_cache_index import NO_OBSERVABILITY, ORIGIN_UNSTABLE
    from bgp_incident_detection.rib_index_engine import DB_PATH, db_connect, index_rib, initialize_db, lookup_asn, lookup_prefix
    from bgp_incident_detection.windows import format_utc
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import parse_utc, write_csv
    from src.bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES
    from src.bgp_incident_detection.mrt_acquisition import ceil_to_15_minutes, floor_to_15_minutes, iter_update_slots, routeviews_update_url
    from src.bgp_incident_detection.normal_50_rib_cache_fill import download_rib, local_rib_path, update_rib_cache_index
    from src.bgp_incident_detection.normal_pool_scale import CONTEXT_BUFFER_MINUTES, EXCLUSION_BUFFER_MINUTES, MIN_DURATION_MINUTES, PRESCREEN_PASS
    from src.bgp_incident_detection.normal_rib_batch50 import RIB_DATA_REQUIRED, classify_from_index, head_url, indexed_ribs, previously_screened_ids
    from src.bgp_incident_detection.normal_update_scale import (
        BEHAVIORAL_FEATURE_COUNT,
        BEHAVIORAL_FEATURE_VERSION,
        MIN_STABLE_WINDOWS,
        NORMAL_METHOD_VERSION,
        build_acquisition_plan,
        download_one,
        parse_downloads,
        qualify,
    )
    from src.bgp_incident_detection.rib_cache_index import NO_OBSERVABILITY, ORIGIN_UNSTABLE
    from src.bgp_incident_detection.rib_index_engine import DB_PATH, db_connect, index_rib, initialize_db, lookup_asn, lookup_prefix
    from src.bgp_incident_detection.windows import format_utc


NORMAL_SCALE_DIR = Path("data/normal_scale")
PRIORITY_QUEUE = NORMAL_SCALE_DIR / "normal_rib_priority_queue_v2.csv"
PREVIOUS_QUALIFICATION = NORMAL_SCALE_DIR / "normal_qualification_results_v1.csv"
PREVIOUS_FEATURES = NORMAL_SCALE_DIR / "normal_behavioral_features_v1.parquet"

EXPANSION_MANIFEST = NORMAL_SCALE_DIR / "normal_expansion_candidate_manifest_v1.csv"
EXPANSION_RIB_RESULTS = NORMAL_SCALE_DIR / "normal_expansion_rib_results_v1.csv"
EXPANSION_UPDATE_AUDIT = NORMAL_SCALE_DIR / "normal_expansion_update_audit_v1.csv"
EXPANSION_QUALIFICATION = NORMAL_SCALE_DIR / "normal_expansion_qualification_results_v1.csv"
VERIFIED_CORPUS_V2 = NORMAL_SCALE_DIR / "normal_verified_corpus_v2.parquet"
VERIFIED_CORPUS_SUMMARY = NORMAL_SCALE_DIR / "normal_verified_corpus_v2_summary.csv"
NOTEBOOK = Path("notebooks/26_normal_verified_corpus_expansion.ipynb")

TARGET_CANDIDATES = 100
TARGET_CLASS_COUNTS = {"Hijack": 34, "Leak": 33, "Outage": 33}
MAX_CANDIDATES_PER_ASN = 3
NORMAL_CHECKPOINT_WINDOWS = 500
ASN_CONTRIBUTION_REVIEW_THRESHOLD = 15.0
UPDATE_BATCH_SIZE = 100

RIB_RESULT_FIELDS = [
    "candidate_period_id",
    "associated_incident_uid",
    "associated_category",
    "partition",
    "affected_asn",
    "affected_prefix",
    "candidate_start",
    "candidate_end",
    "collector",
    "rib_before_timestamp",
    "rib_after_timestamp",
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

QUALIFICATION_FIELDS = [
    "candidate_period_id",
    "associated_incident_uid",
    "associated_category",
    "window_id",
    "window_start",
    "window_end",
    "rib_route_confirmed",
    "rib_origin_stable",
    "relevant_update_count",
    "announcement_count",
    "withdrawal_count",
    "origin_change_count",
    "path_instability",
    "prefix_deaggregation",
    "moas_event",
    "stable_silence",
    "consecutive_stable_windows",
    "final_state",
    "reason",
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


def processed_candidate_ids() -> set[str]:
    ids = set(previously_screened_ids())
    for path in [
        NORMAL_SCALE_DIR / "normal_rib_prescreen_50_complete_v1.csv",
        NORMAL_SCALE_DIR / "normal_rib_approved_pool_v3.csv",
        PREVIOUS_QUALIFICATION,
        EXPANSION_QUALIFICATION,
    ]:
        for row in load_csv(path):
            if row.get("candidate_period_id"):
                ids.add(row["candidate_period_id"])
    return ids


def select_expansion_candidates(queue_rows: list[dict[str, str]], processed_ids: set[str] | None = None) -> list[dict[str, str]]:
    processed = processed_ids if processed_ids is not None else processed_candidate_ids()
    eligible = [
        row
        for row in queue_rows
        if row.get("partition") == "train"
        and row.get("candidate_period_id") not in processed
        and row.get("associated_category") in TARGET_CLASS_COUNTS
        and row.get("affected_asn")
        and float(row.get("duration_minutes") or 0) >= MIN_DURATION_MINUTES
    ]
    selected: list[dict[str, str]] = []
    ids: set[str] = set()
    class_counts: Counter[str] = Counter()
    asn_counts: Counter[str] = Counter()

    def add(row: dict[str, str], prefer_new_asn: bool) -> None:
        if len(selected) >= TARGET_CANDIDATES:
            return
        category = row["associated_category"]
        asn = str(row["affected_asn"])
        if class_counts[category] >= TARGET_CLASS_COUNTS[category]:
            return
        if row["candidate_period_id"] in ids:
            return
        if asn_counts[asn] >= MAX_CANDIDATES_PER_ASN:
            return
        if prefer_new_asn and asn_counts[asn] > 0:
            return
        selected.append(row)
        ids.add(row["candidate_period_id"])
        class_counts[category] += 1
        asn_counts[asn] += 1

    for row in eligible:
        add(row, prefer_new_asn=True)
    for row in eligible:
        add(row, prefer_new_asn=False)
    return selected


def selected_or_existing_manifest() -> list[dict[str, str]]:
    existing = load_csv(EXPANSION_MANIFEST)
    if existing:
        return existing
    return select_expansion_candidates(load_csv(PRIORITY_QUEUE))


def candidate_manifest_rows(selected: list[dict[str, str]]) -> list[dict[str, object]]:
    rows = []
    for row in selected:
        rows.append(
            {
                "candidate_period_id": row["candidate_period_id"],
                "associated_incident_uid": row["associated_incident_uid"],
                "associated_category": row["associated_category"],
                "partition": row.get("partition", "train"),
                "affected_asn": row["affected_asn"],
                "affected_prefix": row.get("affected_prefix", ""),
                "candidate_start": row["candidate_start"],
                "candidate_end": row["candidate_end"],
                "duration_minutes": row.get("duration_minutes", ""),
                "days_from_incident": row.get("days_from_incident", ""),
                "collector": row.get("collector") or "route-views2",
                "rib_before_timestamp": row["rib_before_timestamp"],
                "rib_after_timestamp": row["rib_after_timestamp"],
                "rib_before_url": row["rib_before_url"],
                "rib_after_url": row["rib_after_url"],
                "selection_reason": "TRAIN-only priority candidate; selected for Normal expansion with fixed v1 rules",
                "normal_method_version": NORMAL_METHOD_VERSION,
                "behavioral_feature_version": BEHAVIORAL_FEATURE_VERSION,
                "behavioral_feature_count": BEHAVIORAL_FEATURE_COUNT,
            }
        )
    return rows


def required_ribs(selected: list[dict[str, str]], indexed: set[tuple[str, str]]) -> list[dict[str, object]]:
    required: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for row in selected:
        collector = row.get("collector") or "route-views2"
        for side in ("before", "after"):
            required[(collector, row[f"rib_{side}_timestamp"], row[f"rib_{side}_url"])].add(row["candidate_period_id"])
    rows = []
    for collector, ts, url in sorted(required):
        key = (collector, ts)
        rows.append(
            {
                "collector": collector,
                "rib_timestamp": ts,
                "rib_url": url,
                "required_by_candidate_count": len(required[(collector, ts, url)]),
                "already_indexed": str(key in indexed),
                "local_path": str(local_rib_path(collector, ts)),
            }
        )
    return rows


def targets_by_rib(candidates: Iterable[dict[str, str]]) -> dict[tuple[str, str], list[dict[str, str]]]:
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


def fill_missing_ribs(selected: list[dict[str, str]], batch_size: int = 20) -> list[dict[str, object]]:
    conn = db_connect(DB_PATH)
    initialize_db(conn)
    indexed = indexed_ribs(conn)
    workload = [row for row in required_ribs(selected, indexed) if row["already_indexed"] != "True"]
    target_map = targets_by_rib(selected)
    audit_rows: list[dict[str, object]] = []
    for index, row in enumerate(workload, start=1):
        download = download_rib(row)
        index_status = "NOT_INDEXED"
        indexed_rows = 0
        index_seconds = 0.0
        error = download.get("error", "")
        if str(download["download_status"]) in {"200", "CACHED"}:
            rib = {"collector": row["collector"], "rib_timestamp": row["rib_timestamp"], "source_file": row["local_path"]}
            result = index_rib(conn, rib, target_map.get((str(row["collector"]), str(row["rib_timestamp"])), []))
            index_status = str(result["index_status"])
            indexed_rows = int(result["rows_indexed"])
            index_seconds = float(result["elapsed_seconds"])
            if index_status != "INDEXED":
                error = f"{error}; {result.get('notes', '')}".strip("; ")
        audit = {
            "collector": row["collector"],
            "rib_timestamp": row["rib_timestamp"],
            "rib_url": row["rib_url"],
            "local_path": row["local_path"],
            "download_status": download["download_status"],
            "download_bytes": download["download_bytes"],
            "download_seconds": download["download_seconds"],
            "checksum": download["checksum"],
            "index_status": index_status,
            "indexed_rows": indexed_rows,
            "index_seconds": round(index_seconds, 3),
            "cache_reused": download["cache_reused"],
            "error": error,
            "batch_number": math.ceil(index / batch_size),
        }
        audit_rows.append(audit)
        update_rib_cache_index([audit])
        print(f"RIB {index} / {len(workload)} {row['rib_timestamp']} download={audit['download_status']} index={audit['index_status']} rows={audit['indexed_rows']}", flush=True)
    conn.close()
    return audit_rows


def screen_from_index(selected: list[dict[str, str]]) -> list[dict[str, object]]:
    conn = sqlite3.connect(DB_PATH)
    indexed = indexed_ribs(conn)
    rows = []
    for candidate in selected:
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
                "reason": "one or both required RIB snapshots are not yet available in the persistent index",
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
                "partition": candidate.get("partition", "train"),
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
    return rows


def execution_rows(pass_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    rows = []
    for row in pass_rows:
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
    return rows


def estimate_update_size(plan_rows: list[dict[str, object]], check_remote: bool) -> list[dict[str, object]]:
    rows = []
    for row in plan_rows:
        enriched = dict(row)
        if check_remote:
            ok, status, size = head_url(str(row["mrt_url"]))
            enriched["remote_available"] = str(ok)
            enriched["status_code"] = status
            enriched["estimated_content_length"] = size if ok else 0
        rows.append(enriched)
    return rows


def download_updates(plan_rows: list[dict[str, object]], batch_size: int = UPDATE_BATCH_SIZE) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for offset in range(0, len(plan_rows), batch_size):
        for row in plan_rows[offset : offset + batch_size]:
            rows.append(download_one(row))
        write_csv(
            EXPANSION_UPDATE_AUDIT,
            rows,
            ["candidate_period_id", "associated_incident_uid", "associated_category", "collector", "mrt_timestamp", "mrt_url", "local_path", "file_size", "checksum", "download_status", "download_timestamp", "partition", "remote_available", "status_code", "estimated_content_length", "download_seconds"],
        )
        print(f"UPDATE {min(offset + batch_size, len(plan_rows))} / {len(plan_rows)} files processed", flush=True)
    return rows


def build_corpus_v2(new_qualification: list[dict[str, object]], new_feature_rows: list[dict[str, object]], rib_rows: list[dict[str, object]]) -> pd.DataFrame:
    previous_qualification = pd.read_csv(PREVIOUS_QUALIFICATION)
    previous_verified = previous_qualification[previous_qualification["final_state"] == "NORMAL_VERIFIED"].copy()
    if len(previous_verified) != 194:
        raise ValueError(f"expected 194 previous NORMAL_VERIFIED windows, found {len(previous_verified)}")

    candidate_meta = {
        str(row["candidate_period_id"]): row
        for path in [NORMAL_SCALE_DIR / "normal_rib_approved_pool_v3.csv"]
        for row in load_csv(path)
    }
    candidate_meta.update({str(row["candidate_period_id"]): row for row in rib_rows})
    previous_features = pd.read_parquet(PREVIOUS_FEATURES)
    previous_feature_cols = ["candidate_period_id", "window_id"] + BEHAVIORAL_FEATURE_NAMES
    previous_verified = previous_verified.merge(previous_features[previous_feature_cols], on=["candidate_period_id", "window_id"], how="left")
    previous_verified["normal_verified_corpus_version"] = "normal_verified_corpus_v1"

    new_verified_rows = [row for row in new_qualification if row["final_state"] == "NORMAL_VERIFIED"]
    new_verified = pd.DataFrame(new_verified_rows)
    if not new_verified.empty:
        new_features = pd.DataFrame(new_feature_rows)
        new_verified = new_verified.merge(new_features[previous_feature_cols], on=["candidate_period_id", "window_id"], how="left")
        new_verified["normal_verified_corpus_version"] = "normal_verified_corpus_v2_increment"
    else:
        new_verified = pd.DataFrame(columns=previous_verified.columns)

    combined = pd.concat([previous_verified, new_verified], ignore_index=True, sort=False)
    combined["category"] = "Normal"
    combined["partition"] = "train"
    combined["normal_method_version"] = NORMAL_METHOD_VERSION
    combined["behavioral_feature_version"] = BEHAVIORAL_FEATURE_VERSION
    combined["behavioral_feature_count"] = BEHAVIORAL_FEATURE_COUNT
    combined["affected_asn"] = combined["candidate_period_id"].map(lambda cid: candidate_meta.get(str(cid), {}).get("affected_asn", ""))
    combined["collector"] = combined["candidate_period_id"].map(lambda cid: candidate_meta.get(str(cid), {}).get("collector", "route-views2"))
    combined = combined.drop_duplicates(subset=["window_id"], keep="first")
    for column in combined.columns:
        if combined[column].dtype == "object":
            combined[column] = combined[column].map(lambda value: "" if pd.isna(value) else str(value))
    combined.to_parquet(VERIFIED_CORPUS_V2, index=False)
    return combined


def write_summary(
    selected: list[dict[str, str]],
    rib_rows: list[dict[str, object]],
    plan_rows: list[dict[str, object]],
    downloads: list[dict[str, object]],
    qualification: list[dict[str, object]],
    corpus: pd.DataFrame,
    elapsed_seconds: float,
) -> list[dict[str, object]]:
    new_verified = [row for row in qualification if row["final_state"] == "NORMAL_VERIFIED"]
    old_verified_count = 194
    by_asn = Counter(str(row.get("affected_asn", "")) for _, row in corpus.iterrows() if str(row.get("affected_asn", "")))
    max_asn_windows = by_asn.most_common(1)[0][1] if by_asn else 0
    max_asn_percent = round(max_asn_windows / len(corpus) * 100, 3) if len(corpus) else 0
    new_windows_by_class = Counter(row["associated_category"] for row in new_verified)
    corpus_by_class = Counter(str(row["associated_category"]) for _, row in corpus.iterrows())
    candidate_success_ids = {row["candidate_period_id"] for row in new_verified}
    rows = [
        {"metric": "selected_candidates", "value": len(selected), "details": json.dumps(dict(Counter(row["associated_category"] for row in selected)), separators=(",", ":"))},
        {"metric": "selected_unique_asns", "value": len({row["affected_asn"] for row in selected}), "details": ""},
        {"metric": "rib_prescreen_pass_candidates", "value": sum(row["prescreen_status"] == PRESCREEN_PASS for row in rib_rows), "details": json.dumps(dict(Counter(row["associated_category"] for row in rib_rows if row["prescreen_status"] == PRESCREEN_PASS)), separators=(",", ":"))},
        {"metric": "rib_prescreen_status_counts", "value": len(rib_rows), "details": json.dumps(dict(Counter(row["prescreen_status"] for row in rib_rows)), separators=(",", ":"))},
        {"metric": "planned_update_files_for_rib_pass_candidates", "value": len(plan_rows), "details": ""},
        {"metric": "downloaded_update_files", "value": sum(row.get("download_status") in {"200", "CACHED"} for row in downloads), "details": ""},
        {"metric": "downloaded_update_bytes", "value": sum(int(row.get("file_size") or 0) for row in downloads), "details": ""},
        {"metric": "new_5_minute_windows_evaluated", "value": len(qualification), "details": ""},
        {"metric": "new_normal_verified_windows", "value": len(new_verified), "details": json.dumps(dict(new_windows_by_class), separators=(",", ":"))},
        {"metric": "new_unknown_windows", "value": sum(row["final_state"] == "UNKNOWN" for row in qualification), "details": ""},
        {"metric": "new_normal_qualification_yield_percent", "value": round(len(new_verified) / len(qualification) * 100, 3) if qualification else 0, "details": ""},
        {"metric": "candidate_periods_producing_new_normal", "value": len(candidate_success_ids), "details": json.dumps(dict(Counter(row["associated_category"] for row in rib_rows if row["candidate_period_id"] in candidate_success_ids)), separators=(",", ":"))},
        {"metric": "previous_verified_windows_preserved", "value": old_verified_count, "details": ""},
        {"metric": "cumulative_verified_normal_windows", "value": len(corpus), "details": json.dumps(dict(corpus_by_class), separators=(",", ":"))},
        {"metric": "unique_asns_in_cumulative_corpus", "value": len(by_asn), "details": ""},
        {"metric": "largest_single_asn_contribution_percent", "value": max_asn_percent, "details": json.dumps(dict(by_asn.most_common(10)), separators=(",", ":"))},
        {"metric": "asn_concentration_status", "value": "REVIEW" if max_asn_percent > ASN_CONTRIBUTION_REVIEW_THRESHOLD else "PASS", "details": f"review threshold is >{ASN_CONTRIBUTION_REVIEW_THRESHOLD}%"},
        {"metric": "checkpoint_500_windows_reached", "value": str(len(corpus) >= NORMAL_CHECKPOINT_WINDOWS), "details": "operational checkpoint only"},
        {"metric": "behavioral_feature_count_preserved", "value": BEHAVIORAL_FEATURE_COUNT, "details": ""},
        {"metric": "behavioral_feature_schema_preserved", "value": str(len(BEHAVIORAL_FEATURE_NAMES) == BEHAVIORAL_FEATURE_COUNT), "details": ""},
        {"metric": "minimum_sustained_stability_windows_preserved", "value": MIN_STABLE_WINDOWS, "details": "6 windows = 30 minutes"},
        {"metric": "exclusion_buffer_minutes_preserved", "value": EXCLUSION_BUFFER_MINUTES, "details": ""},
        {"metric": "context_buffer_minutes_preserved", "value": CONTEXT_BUFFER_MINUTES, "details": ""},
        {"metric": "methodology_rules_changed", "value": "NO", "details": ""},
        {"metric": "elapsed_seconds", "value": round(elapsed_seconds, 3), "details": ""},
    ]
    write_csv(VERIFIED_CORPUS_SUMMARY, rows, ["metric", "value", "details"])
    return rows


def write_notebook() -> None:
    NOTEBOOK.parent.mkdir(parents=True, exist_ok=True)
    notebook = {
        "cells": [
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": [
                    "# TRAIN-only Verified Normal Corpus Expansion\n",
                    "\n",
                    "Expand the verified Normal corpus using the frozen RIB + UPDATE qualification method. This notebook does not alter Normal rules, Validation/Holdout data, model training, CAIDA/RPKI, or frozen incident partitions.\n",
                ],
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": ["from bgp_incident_detection.normal_corpus_expansion import prepare_summary\n", "prepare_summary()\n"],
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": ["from bgp_incident_detection.normal_corpus_expansion import run\n", "summary = run()\n", "summary\n"],
            },
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")


def prepare_summary() -> dict[str, object]:
    selected = selected_or_existing_manifest()
    manifest = candidate_manifest_rows(selected)
    conn = sqlite3.connect(DB_PATH)
    indexed = indexed_ribs(conn)
    conn.close()
    ribs = required_ribs(selected, indexed)
    upper_bound_update_files = 0
    unique_urls = set()
    for row in selected:
        start = floor_to_15_minutes(parse_required(row["candidate_start"]) - timedelta(minutes=CONTEXT_BUFFER_MINUTES))
        end = ceil_to_15_minutes(parse_required(row["candidate_end"]) + timedelta(minutes=CONTEXT_BUFFER_MINUTES))
        slots = iter_update_slots(start, end)
        upper_bound_update_files += len(slots)
        for slot in slots:
            unique_urls.add(routeviews_update_url(slot, row.get("collector") or "route-views2"))
    write_csv(
        EXPANSION_MANIFEST,
        manifest,
        ["candidate_period_id", "associated_incident_uid", "associated_category", "partition", "affected_asn", "affected_prefix", "candidate_start", "candidate_end", "duration_minutes", "days_from_incident", "collector", "rib_before_timestamp", "rib_after_timestamp", "rib_before_url", "rib_after_url", "selection_reason", "normal_method_version", "behavioral_feature_version", "behavioral_feature_count"],
    )
    write_notebook()
    return {
        "selected_candidate_count": len(selected),
        "selected_class_distribution": dict(Counter(row["associated_category"] for row in selected)),
        "unique_asn_count": len({row["affected_asn"] for row in selected}),
        "required_unique_rib_snapshots": len(ribs),
        "already_indexed_rib_snapshots": sum(row["already_indexed"] == "True" for row in ribs),
        "missing_or_not_indexed_rib_snapshots": sum(row["already_indexed"] != "True" for row in ribs),
        "upper_bound_update_file_assignments_if_all_pass": upper_bound_update_files,
        "upper_bound_unique_update_urls_if_all_pass": len(unique_urls),
        "outputs": [str(EXPANSION_MANIFEST), str(NOTEBOOK)],
    }


def run(batch_size: int = UPDATE_BATCH_SIZE, rib_batch_size: int = 20, check_remote: bool = True) -> dict[str, object]:
    start = time.perf_counter()
    selected = selected_or_existing_manifest()
    manifest = candidate_manifest_rows(selected)
    write_csv(
        EXPANSION_MANIFEST,
        manifest,
        ["candidate_period_id", "associated_incident_uid", "associated_category", "partition", "affected_asn", "affected_prefix", "candidate_start", "candidate_end", "duration_minutes", "days_from_incident", "collector", "rib_before_timestamp", "rib_after_timestamp", "rib_before_url", "rib_after_url", "selection_reason", "normal_method_version", "behavioral_feature_version", "behavioral_feature_count"],
    )
    fill_missing_ribs(selected, batch_size=rib_batch_size)
    rib_rows = screen_from_index(selected)
    write_csv(EXPANSION_RIB_RESULTS, rib_rows, RIB_RESULT_FIELDS)
    pass_rows = [row for row in rib_rows if row["prescreen_status"] == PRESCREEN_PASS]
    execution = execution_rows(pass_rows)
    plan = build_acquisition_plan(execution, check_remote=False)
    plan = estimate_update_size(plan, check_remote=check_remote)
    downloads = download_updates(plan, batch_size=batch_size)
    raw_counts, relevance, window_counts, feature_rows = parse_downloads(downloads, execution)
    qualification, _candidate_summary = qualify(feature_rows, execution)
    write_csv(EXPANSION_QUALIFICATION, qualification, QUALIFICATION_FIELDS)
    corpus = build_corpus_v2(qualification, feature_rows, rib_rows)
    summary_rows = write_summary(selected, rib_rows, plan, downloads, qualification, corpus, time.perf_counter() - start)
    write_notebook()
    return {
        "selected_candidates": len(selected),
        "selected_class_distribution": dict(Counter(row["associated_category"] for row in selected)),
        "rib_prescreen_pass": sum(row["prescreen_status"] == PRESCREEN_PASS for row in rib_rows),
        "rib_prescreen_pass_by_class": dict(Counter(row["associated_category"] for row in rib_rows if row["prescreen_status"] == PRESCREEN_PASS)),
        "update_files_planned": len(plan),
        "update_files_downloaded": sum(row.get("download_status") in {"200", "CACHED"} for row in downloads),
        "update_download_bytes": sum(int(row.get("file_size") or 0) for row in downloads),
        "new_windows_evaluated": len(qualification),
        "new_normal_verified_windows": sum(row["final_state"] == "NORMAL_VERIFIED" for row in qualification),
        "cumulative_verified_normal_windows": len(corpus),
        "unique_asns": next((row["value"] for row in summary_rows if row["metric"] == "unique_asns_in_cumulative_corpus"), 0),
        "largest_single_asn_contribution_percent": next((row["value"] for row in summary_rows if row["metric"] == "largest_single_asn_contribution_percent"), 0),
        "checkpoint_500_reached": next((row["value"] for row in summary_rows if row["metric"] == "checkpoint_500_windows_reached"), "False"),
        "methodology_rules_changed": "NO",
        "outputs": [str(EXPANSION_MANIFEST), str(EXPANSION_RIB_RESULTS), str(EXPANSION_UPDATE_AUDIT), str(EXPANSION_QUALIFICATION), str(VERIFIED_CORPUS_V2), str(VERIFIED_CORPUS_SUMMARY), str(NOTEBOOK)],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Expand the TRAIN-only verified Normal corpus with fixed v1 rules")
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--skip-remote-head", action="store_true")
    parser.add_argument("--batch-size", type=int, default=UPDATE_BATCH_SIZE)
    parser.add_argument("--rib-batch-size", type=int, default=20)
    args = parser.parse_args()
    if args.prepare_only:
        print(json.dumps(prepare_summary(), indent=2, sort_keys=True))
        return
    if args.run:
        print(json.dumps(run(batch_size=args.batch_size, rib_batch_size=args.rib_batch_size, check_remote=not args.skip_remote_head), indent=2, sort_keys=True))
        return
    parser.error("choose --prepare-only or --run")


if __name__ == "__main__":
    main()
