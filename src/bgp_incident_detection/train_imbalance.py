from __future__ import annotations

import argparse
import json
import math
import shutil
import time
from collections import Counter
from pathlib import Path

import pandas as pd

try:
    from bgp_incident_detection.audit import write_csv
    from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES
    from bgp_incident_detection.full_train_execution import (
        BEHAVIORAL_FEATURE_COUNT,
        shared_download_rows,
        parse_batch_once,
        safe_batch_path,
    )
    from bgp_incident_detection.train_incident_scale import (
        ACQUISITION_PLAN,
        FEATURE_SUMMARY,
        FEATURES_PARQUET,
        MANIFEST,
        QUALITY_GATE,
        TRAIN_SCALE_DIR,
        load_csv,
        relevance_targets,
    )
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import write_csv
    from src.bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES
    from src.bgp_incident_detection.full_train_execution import (
        BEHAVIORAL_FEATURE_COUNT,
        shared_download_rows,
        parse_batch_once,
        safe_batch_path,
    )
    from src.bgp_incident_detection.train_incident_scale import (
        ACQUISITION_PLAN,
        FEATURE_SUMMARY,
        FEATURES_PARQUET,
        MANIFEST,
        QUALITY_GATE,
        TRAIN_SCALE_DIR,
        load_csv,
        relevance_targets,
    )


REVIEW_RESOLUTION = TRAIN_SCALE_DIR / "train_review_incident_resolution_v1.csv"
CORPUS_AUDIT_V2 = TRAIN_SCALE_DIR / "train_behavioral_corpus_audit_v2.csv"
STRATEGY_COMPARISON = TRAIN_SCALE_DIR / "train_imbalance_strategy_comparison_v1.csv"
NOTEBOOK = Path("notebooks/31_train_review_and_imbalance_strategy.ipynb")
REVIEW_BATCH_ID = "review_reprocess_v1"


def review_incidents() -> list[dict[str, str]]:
    quality = [row for row in load_csv(QUALITY_GATE) if row["status"] == "REVIEW"]
    if len(quality) != 10:
        raise ValueError(f"expected exactly 10 REVIEW incidents, found {len(quality)}")
    summary = {row["incident_uid"]: row for row in load_csv(FEATURE_SUMMARY)}
    output = []
    for row in quality:
        joined = dict(row)
        joined.update(summary.get(row["incident_uid"], {}))
        output.append(joined)
    return output


def clean_review_cache() -> None:
    raw = Path("data/raw_mrt/train_batches") / REVIEW_BATCH_ID
    if raw.exists():
        shutil.rmtree(raw)
    parsed = Path("data/parsed_mrt/train")
    for row in review_incidents():
        path = parsed / row["incident_uid"].replace(":", "_")
        if path.exists():
            shutil.rmtree(path)


def review_plan_rows() -> list[dict[str, str]]:
    review_uids = {row["incident_uid"] for row in review_incidents()}
    rows = []
    for row in load_csv(ACQUISITION_PLAN):
        if row["incident_uid"] not in review_uids:
            continue
        updated = dict(row)
        updated["batch_id"] = REVIEW_BATCH_ID
        updated["local_path"] = str(safe_batch_path(REVIEW_BATCH_ID, row["mrt_url"]))
        rows.append(updated)
    return rows


def parser_status(downloads: list[dict[str, object]], stats: dict[str, object]) -> str:
    if int(stats["parse_failures"]) > 0:
        return "PARSER_REVIEW"
    if not downloads:
        return "NO_FILES"
    return "PARSER_PASS"


def download_integrity(downloads: list[dict[str, object]]) -> str:
    if not downloads:
        return "NO_FILES"
    bad = [row for row in downloads if row.get("download_status") not in {"200", "CACHED", "REUSED_FROM_PILOT"}]
    return "DOWNLOAD_REVIEW" if bad else "DOWNLOAD_PASS"


def resolution_disposition(original: dict[str, str], downloads: list[dict[str, object]], stats: dict[str, object], incident: dict[str, str]) -> tuple[str, str]:
    dl_status = download_integrity(downloads)
    ps = parser_status(downloads, stats)
    relevant = int(stats["relevant_observations"])
    target_asns, target_prefixes, leak_seg = relevance_targets(incident)
    if dl_status == "DOWNLOAD_REVIEW" or ps == "PARSER_REVIEW":
        return "EXCLUDE_TECHNICAL_FAILURE", "Reprocess still has download/parser integrity concern."
    if relevant > 0 and original.get("review_reasons") != "no relevant observations":
        return "PASS_AFTER_REPROCESS", "Reprocess resolved prior technical review condition."
    if relevant > 0:
        return "PASS_AFTER_REPROCESS", "Reprocess found incident-relevant observations."
    if not target_asns and not target_prefixes and not leak_seg:
        return "KEEP_WITH_LIMITATION", "No usable ASN/prefix/path relevance metadata; retained as metadata-limited TRAIN incident."
    return "KEEP_WITH_ZERO_OBSERVATIONS", "MRT parsed successfully, but RouteViews route-views2 had no observations matching the incident metadata."


def reprocess_review_incidents(download_workers: int = 8) -> list[dict[str, object]]:
    clean_review_cache()
    manifest = {row["incident_uid"]: row for row in load_csv(MANIFEST)}
    reviews = review_incidents()
    review_uids = [row["incident_uid"] for row in reviews]
    plan = review_plan_rows()
    unique_downloads, expanded = shared_download_rows(REVIEW_BATCH_ID, plan, workers=download_workers)
    features_by_uid, stats_by_uid = parse_batch_once(REVIEW_BATCH_ID, manifest, review_uids, expanded)
    expanded_by_uid: dict[str, list[dict[str, object]]] = {}
    for row in expanded:
        expanded_by_uid.setdefault(str(row["incident_uid"]), []).append(row)
    original_by_uid = {row["incident_uid"]: row for row in reviews}
    rows = []
    for uid in review_uids:
        incident = manifest[uid]
        stats = stats_by_uid[uid]
        downloads = expanded_by_uid.get(uid, [])
        disposition, notes = resolution_disposition(original_by_uid[uid], downloads, stats, incident)
        rows.append(
            {
                "incident_uid": uid,
                "category": incident["category"],
                "original_review_reason": original_by_uid[uid].get("review_reasons", ""),
                "raw_mrt_files": len(downloads),
                "raw_observations": stats["raw_bgp_observations"],
                "relevant_observations": stats["relevant_observations"],
                "active_windows": sum(row["temporal_status"] == "INCIDENT_ACTIVE" for row in features_by_uid[uid]),
                "feature_rows": len(features_by_uid[uid]),
                "parser_status": parser_status(downloads, stats),
                "download_integrity": download_integrity(downloads),
                "resolution_disposition": disposition,
                "notes": notes,
            }
        )
    write_csv(
        REVIEW_RESOLUTION,
        rows,
        [
            "incident_uid",
            "category",
            "original_review_reason",
            "raw_mrt_files",
            "raw_observations",
            "relevant_observations",
            "active_windows",
            "feature_rows",
            "parser_status",
            "download_integrity",
            "resolution_disposition",
            "notes",
        ],
    )
    clean_review_cache()
    return rows


def feature_row_counts(df: pd.DataFrame) -> pd.Series:
    return df.groupby("incident_uid").size()


def top_share(counts: pd.Series, pct: float) -> float:
    if counts.empty:
        return 0.0
    n = max(1, math.ceil(len(counts) * pct))
    return round(counts.sort_values(ascending=False).head(n).sum() / counts.sum() * 100, 3)


def cap_rows_for_incident(group: pd.DataFrame, cap: int) -> pd.DataFrame:
    if len(group) <= cap:
        return group
    ordered = group.sort_values("window_start").reset_index(drop=True)
    if cap <= 3:
        positions = sorted(set([0, len(ordered) // 2, len(ordered) - 1]))[:cap]
    else:
        positions = {0, len(ordered) // 2, len(ordered) - 1}
        remaining = cap - len(positions)
        if remaining > 0:
            for index in range(1, remaining + 1):
                positions.add(round(index * (len(ordered) - 1) / (remaining + 1)))
        if len(positions) < cap:
            for index in range(len(ordered)):
                positions.add(index)
                if len(positions) >= cap:
                    break
    return ordered.iloc[sorted(positions)[:cap]].copy()


def apply_cap(df: pd.DataFrame, cap: int | None) -> pd.DataFrame:
    if cap is None:
        return df.copy()
    return pd.concat([cap_rows_for_incident(group, cap) for _, group in df.groupby("incident_uid", sort=False)], ignore_index=True)


def add_incident_weights(df: pd.DataFrame) -> pd.DataFrame:
    output = df.copy()
    counts = output.groupby("incident_uid").size().to_dict()
    output["row_weight"] = output["incident_uid"].map(lambda uid: 1.0 / counts[uid])
    return output


def strategy_row(name: str, cap_definition: str, original: pd.DataFrame, candidate: pd.DataFrame, weighted: bool, notes: str) -> dict[str, object]:
    counts = feature_row_counts(candidate)
    class_rows = candidate["category"].value_counts().to_dict()
    weighted_df = add_incident_weights(candidate) if weighted else candidate.assign(row_weight=1.0)
    incident_weights = weighted_df.groupby("incident_uid")["row_weight"].sum()
    return {
        "strategy": name,
        "cap_definition": cap_definition,
        "total_rows": len(candidate),
        "rows_removed": len(original) - len(candidate),
        "hijack_rows": class_rows.get("Hijack", 0),
        "leak_rows": class_rows.get("Leak", 0),
        "outage_rows": class_rows.get("Outage", 0),
        "incidents_retained": candidate["incident_uid"].nunique(),
        "median_rows_per_incident": float(counts.median()) if len(counts) else 0,
        "p95_rows_per_incident": float(counts.quantile(0.95)) if len(counts) else 0,
        "max_rows_per_incident": int(counts.max()) if len(counts) else 0,
        "top_1pct_row_share": top_share(counts, 0.01),
        "top_5pct_row_share": top_share(counts, 0.05),
        "top_10pct_row_share": top_share(counts, 0.10),
        "effective_weight_range": f"{incident_weights.min():.6f}-{incident_weights.max():.6f}" if len(incident_weights) else "",
        "notes": notes,
    }


def compare_strategies() -> list[dict[str, object]]:
    df = pd.read_parquet(FEATURES_PARQUET)
    if set(df["partition"].unique()) != {"train"}:
        raise ValueError("feature corpus contains non-TRAIN partitions")
    counts = feature_row_counts(df)
    caps = {
        "global_p90": int(math.ceil(counts.quantile(0.90))),
        "global_p95": int(math.ceil(counts.quantile(0.95))),
        "global_p99": int(math.ceil(counts.quantile(0.99))),
    }
    rows = [
        strategy_row("A_NATURAL_UNADJUSTED", "none", df, df, False, "All TRAIN rows retained equally."),
        strategy_row("B_INCIDENT_AWARE_WEIGHTING", "none", df, df, True, "All TRAIN rows retained; each incident contributes total weight about 1."),
    ]
    for label, cap in caps.items():
        capped = apply_cap(df, cap)
        rows.append(strategy_row("C_CAP_PLUS_INCIDENT_AWARE_WEIGHTING", label, df, capped, True, "Percentile cap with onset/middle/end/even temporal coverage, then incident-aware weights."))
        rows.append(strategy_row("D_CAP_ONLY", label, df, capped, False, "Diagnostic percentile cap only; no weights."))
    write_csv(
        STRATEGY_COMPARISON,
        rows,
        [
            "strategy",
            "cap_definition",
            "total_rows",
            "rows_removed",
            "hijack_rows",
            "leak_rows",
            "outage_rows",
            "incidents_retained",
            "median_rows_per_incident",
            "p95_rows_per_incident",
            "max_rows_per_incident",
            "top_1pct_row_share",
            "top_5pct_row_share",
            "top_10pct_row_share",
            "effective_weight_range",
            "notes",
        ],
    )
    return rows


def write_corpus_audit_v2(resolution_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    df = pd.read_parquet(FEATURES_PARQUET)
    dispositions = Counter(row["resolution_disposition"] for row in resolution_rows)
    excluded = dispositions.get("EXCLUDE_TECHNICAL_FAILURE", 0)
    quality = pd.read_csv(QUALITY_GATE)
    pass_count = int((quality.status == "PASS").sum()) + dispositions.get("PASS_AFTER_REPROCESS", 0) + dispositions.get("KEEP_WITH_ZERO_OBSERVATIONS", 0)
    limitation_count = dispositions.get("KEEP_WITH_LIMITATION", 0)
    row = {
        "expected_incidents": 993,
        "included_incidents": 993 - excluded,
        "excluded_incidents": excluded,
        "PASS": pass_count,
        "KEEP_WITH_LIMITATION": limitation_count,
        "technical_exclusions": excluded,
        "feature_rows": len(df),
        "duplicate_window_ids": int(df.duplicated(["incident_uid", "window_id"]).sum()),
        "schema_status": "PASS" if len([name for name in BEHAVIORAL_FEATURE_NAMES if name in df.columns]) == BEHAVIORAL_FEATURE_COUNT else "FAIL",
        "validation_contamination": str("validation" in set(df["partition"])),
        "holdout_contamination": str("holdout" in set(df["partition"])),
        "overall_status": "PASS" if excluded == 0 and limitation_count == 0 else ("REVIEW" if excluded == 0 else "FAIL"),
        "notes": "Original 68,031-row corpus unchanged; review dispositions are advisory resolution metadata.",
    }
    write_csv(
        CORPUS_AUDIT_V2,
        [row],
        [
            "expected_incidents",
            "included_incidents",
            "excluded_incidents",
            "PASS",
            "KEEP_WITH_LIMITATION",
            "technical_exclusions",
            "feature_rows",
            "duplicate_window_ids",
            "schema_status",
            "validation_contamination",
            "holdout_contamination",
            "overall_status",
            "notes",
        ],
    )
    return [row]


def write_notebook() -> None:
    NOTEBOOK.parent.mkdir(parents=True, exist_ok=True)
    nb = {
        "cells": [
            {"cell_type": "markdown", "metadata": {}, "source": ["# TRAIN Review Resolution and Imbalance Strategy\n", "\n", "TRAIN-only diagnostic step. It does not touch Validation/Holdout, does not alter the frozen behavioral feature corpus, and does not train models.\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["from bgp_incident_detection.train_imbalance import run\n", "run()\n"]},
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(nb, indent=2) + "\n", encoding="utf-8")


def run(download_workers: int = 8, skip_reprocess: bool = False) -> dict[str, object]:
    start = time.perf_counter()
    write_notebook()
    resolution = read_resolution() if skip_reprocess and REVIEW_RESOLUTION.exists() else reprocess_review_incidents(download_workers=download_workers)
    audit = write_corpus_audit_v2(resolution)
    strategies = compare_strategies()
    return {
        "review_incidents": len(resolution),
        "resolution_counts": dict(Counter(row["resolution_disposition"] for row in resolution)),
        "audit_status": audit[0]["overall_status"],
        "strategy_rows": len(strategies),
        "elapsed_seconds": round(time.perf_counter() - start, 3),
        "outputs": [str(REVIEW_RESOLUTION), str(CORPUS_AUDIT_V2), str(STRATEGY_COMPARISON), str(NOTEBOOK)],
    }


def read_resolution() -> list[dict[str, object]]:
    return load_csv(REVIEW_RESOLUTION)


def main() -> None:
    parser = argparse.ArgumentParser(description="Resolve TRAIN REVIEW incidents and compare imbalance strategies")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--skip-reprocess", action="store_true")
    parser.add_argument("--download-workers", type=int, default=8)
    args = parser.parse_args()
    if args.run:
        print(json.dumps(run(download_workers=args.download_workers, skip_reprocess=args.skip_reprocess), indent=2, sort_keys=True))
        return
    parser.error("choose --run")


if __name__ == "__main__":
    main()
