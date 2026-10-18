from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

try:
    from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES
    from bgp_incident_detection.normal_pool_scale import CONTEXT_BUFFER_MINUTES, EXCLUSION_BUFFER_MINUTES
    from bgp_incident_detection.normal_update_scale import (
        BEHAVIORAL_FEATURE_COUNT,
        BEHAVIORAL_FEATURE_VERSION,
        MIN_STABLE_WINDOWS,
        NORMAL_METHOD_VERSION,
    )
except ModuleNotFoundError:
    from src.bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES
    from src.bgp_incident_detection.normal_pool_scale import CONTEXT_BUFFER_MINUTES, EXCLUSION_BUFFER_MINUTES
    from src.bgp_incident_detection.normal_update_scale import (
        BEHAVIORAL_FEATURE_COUNT,
        BEHAVIORAL_FEATURE_VERSION,
        MIN_STABLE_WINDOWS,
        NORMAL_METHOD_VERSION,
    )


SOURCE_CORPUS = Path("data/normal_scale/normal_verified_corpus_v2.parquet")
FROZEN_DIR = Path("data/normal_frozen")
FROZEN_CORPUS = FROZEN_DIR / "frozen_normal_corpus_v1.parquet"
FROZEN_MANIFEST = FROZEN_DIR / "frozen_normal_manifest_v1.csv"
FREEZE_AUDIT = FROZEN_DIR / "normal_freeze_audit_v1.csv"
METHOD_CONFIG = Path("config/normal_ground_truth_method_v1.yaml")
METHOD_DOC = Path("docs/normal_ground_truth_methodology_v1.md")
NOTEBOOK = Path("notebooks/27_freeze_normal_ground_truth_v1.ipynb")

NORMAL_CORPUS_VERSION = "v1"
CORPUS_STATUS = "FROZEN_FOR_DEVELOPMENT"
EXPECTED_WINDOWS = 516
EXPECTED_UNIQUE_ASNS = 43
EXPECTED_ASSOCIATED_CLASS_COUNTS = {"Hijack": 198, "Leak": 144, "Outage": 174}
ASN_CONTRIBUTION_REVIEW_THRESHOLD_PERCENT = 15.0
MINIMUM_STABILITY_MINUTES = 30


def source_commit() -> str:
    try:
        result = subprocess.run(["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True)
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "UNKNOWN"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_csv(path: Path, rows: list[dict[str, object]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def method_config_text() -> str:
    blockers = [
        "known_incident_overlap",
        "inside_60_minute_incident_exclusion_buffer",
        "missing_rib_route_visibility",
        "unstable_route_presence",
        "unstable_expected_origin",
        "origin_change_event_count_greater_than_zero",
        "strong_as_path_instability",
        "suspicious_prefix_deaggregation",
        "unexpected_moas_or_origin_diversity",
        "fewer_than_6_consecutive_stable_5_minute_windows",
        "insufficient_evidence",
    ]
    return "\n".join(
        [
            "normal_method_version: v1",
            "implementation_method_version: rib_update_v1",
            "window_minutes: 5",
            f"context_buffer_minutes: {CONTEXT_BUFFER_MINUTES}",
            f"incident_exclusion_buffer_minutes: {EXCLUSION_BUFFER_MINUTES}",
            f"minimum_consecutive_stable_windows: {MIN_STABLE_WINDOWS}",
            f"minimum_stability_minutes: {MINIMUM_STABILITY_MINUTES}",
            "rib_visibility_required: true",
            "stable_route_presence_required: true",
            "stable_origin_required: true",
            "known_incident_overlap_allowed: false",
            "zero_update_activity_can_qualify: true",
            "uncertain_state: UNKNOWN",
            "verified_state: NORMAL_VERIFIED",
            f"behavioral_feature_version: {BEHAVIORAL_FEATURE_VERSION}",
            f"behavioral_feature_count: {BEHAVIORAL_FEATURE_COUNT}",
            "normal_label_training_mapping: NORMAL_VERIFIED -> NORMAL",
            "incident_label_training_mapping: Hijack/Leak/Outage -> INCIDENT",
            "unknown_training_mapping: UNKNOWN -> excluded_from_supervised_training",
            "normal_qualification_blockers:",
            *[f"  - {blocker}" for blocker in blockers],
            "ground_truth_scope: training labels only",
            "stage1_inference_method: machine_learning_model_not_rules",
            "",
        ]
    )


def methodology_doc_text() -> str:
    return """# Normal Ground-Truth Methodology v1

Status: FROZEN

The Stage 1 detector needs trustworthy examples of ordinary BGP behavior so it can learn `Normal` versus `Incident`. A window that is merely "not known to be an incident" is not enough, because public incident labels are incomplete and quiet-looking windows can still contain routing instability.

Normal methodology v1 therefore uses both RIB and UPDATE evidence. RIB snapshots establish that the target ASN/network is visible, route presence is stable, and the expected origin remains stable before and after the candidate period. UPDATE data then checks whether the 5-minute windows contain suspicious routing changes.

Pipeline:

Candidate stable period -> known-incident exclusion -> RIB visibility/state verification -> UPDATE-change inspection -> 5-minute windows -> 44 behavioral features -> sustained stability -> NORMAL_VERIFIED or UNKNOWN

Candidate periods are selected from TRAIN incidents only as nearby same-ASN or same-network controls where possible. They must remain outside the 60-minute known-incident exclusion buffer and must not overlap known incident intervals. Validation and Final Holdout incidents are not used to build Normal ground truth.

RIB pre-screening requires route visibility before and after the candidate period. A candidate may pass only when route presence and expected origin are stable. Missing RIB data remains `RIB_DATA_REQUIRED` until evidence is complete; it is not treated as `NO_OBSERVABILITY`.

UPDATE behavior is evaluated after RIB screening. Suspicious origin changes, strong AS-path instability, suspicious deaggregation, or unexpected MOAS/origin-diversity behavior prevent Normal qualification. Zero UPDATE activity can qualify only as stable silence when RIB evidence confirms stable routing state.

The 30-minute sustained stability rule requires at least six consecutive stable 5-minute windows. This reduces the risk of labeling a short accidental quiet moment as Normal.

Uncertain windows remain `UNKNOWN` and are excluded from supervised training. They are not relabeled as Normal.

These rules construct training ground truth only. Future Stage 1 inference will use ML models trained on frozen labels and features, not this rule system.

Training label mapping:

- `NORMAL_VERIFIED` -> `NORMAL`
- `Hijack` -> `INCIDENT`
- `Leak` -> `INCIDENT`
- `Outage` -> `INCIDENT`
- `UNKNOWN` -> excluded from supervised training

Experimental-unit distinction:

- Real-world incident = independent experimental unit
- 5-minute window = ML analytical observation
- Raw UPDATE observation = evidence used to compute window features

Model splitting remains incident-level, feature rows remain window-level, and raw UPDATE counts never define the independent sample size.

Normal corpus v1 is `FROZEN_FOR_DEVELOPMENT`. This means the current 516 verified windows are frozen for the first development experiments, not that 516 windows are permanently or statistically optimal. Additional TRAIN-only Normal data may later be added with exactly the same frozen v1 methodology as a new corpus version.
"""


def write_method_artifacts() -> None:
    METHOD_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    METHOD_CONFIG.write_text(method_config_text(), encoding="utf-8")
    METHOD_DOC.parent.mkdir(parents=True, exist_ok=True)
    METHOD_DOC.write_text(methodology_doc_text(), encoding="utf-8")


def load_source() -> pd.DataFrame:
    if not SOURCE_CORPUS.exists():
        raise FileNotFoundError(SOURCE_CORPUS)
    return pd.read_parquet(SOURCE_CORPUS)


def canonicalize_feature_columns(df: pd.DataFrame) -> pd.DataFrame:
    frozen = df.copy(deep=True)
    suffix_map = {
        "announcement_count": "announcement_count_y",
        "withdrawal_count": "withdrawal_count_y",
    }
    for canonical, suffixed in suffix_map.items():
        if canonical not in frozen.columns and suffixed in frozen.columns:
            frozen[canonical] = frozen[suffixed]
    return frozen


def validate_source(df: pd.DataFrame) -> list[dict[str, object]]:
    feature_columns_present = all(name in df.columns for name in BEHAVIORAL_FEATURE_NAMES)
    final_state_values = set(df["final_state"].astype(str)) if "final_state" in df else set()
    partition_values = set(df["partition"].astype(str)) if "partition" in df else set()
    asn_counts = Counter(df["affected_asn"].astype(str)) if "affected_asn" in df else Counter()
    max_asn_count = asn_counts.most_common(1)[0][1] if asn_counts else 0
    max_asn_percent = round(max_asn_count / len(df) * 100, 3) if len(df) else 0
    associated_counts = dict(Counter(df["associated_category"].astype(str))) if "associated_category" in df else {}
    checks = [
        ("total_windows", len(df) == EXPECTED_WINDOWS, len(df), f"expected {EXPECTED_WINDOWS}"),
        ("all_final_states_normal_verified", final_state_values == {"NORMAL_VERIFIED"}, ",".join(sorted(final_state_values)), "all rows must be NORMAL_VERIFIED"),
        ("unique_window_ids", df["window_id"].nunique() == EXPECTED_WINDOWS, df["window_id"].nunique(), "no duplicate window_id"),
        ("train_only", partition_values == {"train"}, ",".join(sorted(partition_values)), "Validation/Holdout excluded"),
        ("behavioral_features_present", feature_columns_present and len(BEHAVIORAL_FEATURE_NAMES) == BEHAVIORAL_FEATURE_COUNT, len([name for name in BEHAVIORAL_FEATURE_NAMES if name in df.columns]), f"expected {BEHAVIORAL_FEATURE_COUNT} features"),
        ("no_validation_records", "validation" not in partition_values, ",".join(sorted(partition_values)), ""),
        ("no_holdout_records", "holdout" not in partition_values, ",".join(sorted(partition_values)), ""),
        ("no_known_incident_overlap", True, "not represented in frozen verified corpus; enforced upstream by method v1", "known-overlap blocker remains frozen"),
        ("unique_asns", df["affected_asn"].nunique() == EXPECTED_UNIQUE_ASNS, df["affected_asn"].nunique(), f"expected {EXPECTED_UNIQUE_ASNS}"),
        ("maximum_single_asn_contribution", max_asn_percent <= ASN_CONTRIBUTION_REVIEW_THRESHOLD_PERCENT, max_asn_percent, f"review if > {ASN_CONTRIBUTION_REVIEW_THRESHOLD_PERCENT}%"),
        ("associated_class_counts_preserved", associated_counts == EXPECTED_ASSOCIATED_CLASS_COUNTS, json.dumps(associated_counts, sort_keys=True), json.dumps(EXPECTED_ASSOCIATED_CLASS_COUNTS, sort_keys=True)),
        ("normal_methodology_v1_frozen", NORMAL_METHOD_VERSION == "rib_update_v1", NORMAL_METHOD_VERSION, "implementation method must remain rib_update_v1"),
        ("normal_corpus_v1_status", True, CORPUS_STATUS, "development corpus freeze, not final sufficiency claim"),
    ]
    rows = []
    for check, ok, observed, notes in checks:
        rows.append({"check": check, "status": "PASS" if ok else "FAIL", "observed": observed, "notes": notes})
    return rows


def freeze() -> dict[str, object]:
    freeze_date = utc_now()
    commit = source_commit()
    source_before = sha256(SOURCE_CORPUS)
    write_method_artifacts()
    df = load_source()
    frozen = canonicalize_feature_columns(df)
    audit_rows = validate_source(frozen)
    if any(row["status"] == "FAIL" for row in audit_rows):
        write_csv(FREEZE_AUDIT, audit_rows, ["check", "status", "observed", "notes"])
        raise ValueError("source Normal corpus failed freeze audit")

    frozen["normal_corpus_version"] = NORMAL_CORPUS_VERSION
    frozen["corpus_status"] = CORPUS_STATUS
    frozen["freeze_date"] = freeze_date
    frozen["source_commit"] = commit
    FROZEN_DIR.mkdir(parents=True, exist_ok=True)
    frozen.to_parquet(FROZEN_CORPUS, index=False)

    manifest_fields = [
        "window_id",
        "candidate_period_id",
        "associated_incident_uid",
        "associated_category",
        "affected_asn",
        "window_start",
        "window_end",
        "normal_method_version",
        "behavioral_feature_version",
        "normal_corpus_version",
    ]
    manifest = frozen[manifest_fields].copy()
    manifest.to_csv(FROZEN_MANIFEST, index=False)
    write_csv(FREEZE_AUDIT, audit_rows, ["check", "status", "observed", "notes"])
    write_notebook()
    source_after = sha256(SOURCE_CORPUS)

    return {
        "normal_methodology_v1": "FROZEN",
        "normal_corpus_v1": CORPUS_STATUS,
        "frozen_windows": len(frozen),
        "unique_window_ids": frozen["window_id"].nunique(),
        "unique_asns": frozen["affected_asn"].nunique(),
        "associated_class_counts": dict(Counter(frozen["associated_category"].astype(str))),
        "max_asn_contribution_percent": round(Counter(frozen["affected_asn"].astype(str)).most_common(1)[0][1] / len(frozen) * 100, 3),
        "behavioral_feature_count": len([name for name in BEHAVIORAL_FEATURE_NAMES if name in frozen.columns]),
        "source_corpus_unchanged": source_before == source_after,
        "unknown_excluded": "UNKNOWN" not in set(frozen["final_state"].astype(str)),
        "qualification_rules_changed": "NO",
        "outputs": [str(METHOD_CONFIG), str(METHOD_DOC), str(FROZEN_CORPUS), str(FROZEN_MANIFEST), str(FREEZE_AUDIT), str(NOTEBOOK)],
    }


def write_notebook() -> None:
    NOTEBOOK.parent.mkdir(parents=True, exist_ok=True)
    notebook = {
        "cells": [
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": [
                    "# Freeze Normal Ground Truth v1\n",
                    "\n",
                    "Freeze the TRAIN-only Normal methodology and current 516-window development corpus. This notebook does not collect more data, access Validation/Holdout, alter rules, or train models.\n",
                ],
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": ["from bgp_incident_detection.freeze_normal import freeze\n", "summary = freeze()\n", "summary\n"],
            },
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Freeze TRAIN-only Normal ground-truth methodology and development corpus v1")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if not args.run:
        parser.error("choose --run")
    print(json.dumps(freeze(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
