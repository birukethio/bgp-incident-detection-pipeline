from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

try:
    from bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT
except ModuleNotFoundError:
    from src.bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT


OUT_DIR = Path("data/tti_train_full_v1")
ROSTER = Path("data/partitions_v2/train_incidents_v2.csv")
TRAIN_V4 = Path("data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1.parquet")
EVIDENCE_MANIFEST = Path("data/enrichment/evidence/train_evidence_manifest_v1.csv")
EVIDENCE_SAMPLE = Path("data/enrichment/evidence/train_v1/batch_001.parquet")
PILOT_V2_FEATURES = Path("data/tti_pilot/tti_horizon_v4_features_v2.csv")
LEVEL1_MANIFEST = Path("data/tti_pilot/level1_ensemble_manifest_v2.json")

HORIZONS = [30, 60, 120, 300]
CLASSES = ["Hijack", "Leak", "Outage"]
V4_FEATURES = FEATURES_BY_VARIANT["V4"]
LABEL = "TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS"
REASON = "full TRAIN timestamp-preserving incident-relevant observations are unavailable; compact evidence is aggregated to frozen 5-minute window grain"


def write_csv(path: Path, df: pd.DataFrame) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False)


def load_roster() -> pd.DataFrame:
    roster = pd.read_csv(ROSTER, low_memory=False)
    if len(roster) != 993:
        raise ValueError(f"Expected 993 TRAIN incidents; found {len(roster)}.")
    if set(roster["partition"].astype(str).str.lower()) != {"train"}:
        raise ValueError("Full TTI scale-up must use TRAIN incidents only.")
    counts = roster["category"].value_counts().to_dict()
    if counts != {"Hijack": 331, "Leak": 331, "Outage": 331}:
        raise ValueError(f"Expected 331/331/331 TRAIN class balance; found {counts}.")
    return roster


def artifact_evidence() -> dict[str, Any]:
    evidence_manifest = pd.read_csv(EVIDENCE_MANIFEST)
    evidence_sample = pd.read_parquet(EVIDENCE_SAMPLE)
    train_v4 = pd.read_parquet(TRAIN_V4, columns=["incident_uid", "window_id", "partition"])
    with LEVEL1_MANIFEST.open(encoding="utf-8") as handle:
        level1 = json.load(handle)
    return {
        "evidence_incident_count": int(evidence_manifest["incident_count"].sum()),
        "evidence_window_count": int(evidence_manifest["window_count"].sum()),
        "evidence_rows": int(evidence_manifest["evidence_rows"].sum()),
        "evidence_columns": list(evidence_sample.columns),
        "train_v4_rows": len(train_v4),
        "train_v4_incidents": int(train_v4["incident_uid"].nunique()),
        "level1_status": level1.get("status"),
        "level1_model_directory": level1.get("model_directory"),
    }


def has_timestamp_preserving_full_train_evidence(info: dict[str, Any]) -> bool:
    columns = set(info["evidence_columns"])
    return "observation_timestamp" in columns or "bgp_timestamp_utc" in columns


def roster_output(roster: pd.DataFrame, info: dict[str, Any]) -> pd.DataFrame:
    cols = [
        "incident_uid",
        "incident_id",
        "category",
        "partition",
        "start_utc",
        "end_utc",
        "duration_minutes",
        "primary_asn",
        "affected_asns",
        "affected_prefixes",
        "source_url",
    ]
    out = roster[[col for col in cols if col in roster.columns]].copy()
    out["tti_experiment"] = LABEL
    out["tti_scaleup_status"] = "REVIEW_NOT_SCORED"
    out["review_reason"] = REASON
    out["available_compact_evidence_window_count"] = info["evidence_window_count"]
    out["available_compact_evidence_rows"] = info["evidence_rows"]
    return out


def horizon_grid(roster: pd.DataFrame) -> pd.DataFrame:
    base = roster[["incident_uid", "incident_id", "category", "partition", "start_utc"]].copy()
    rows = []
    for _, row in base.iterrows():
        for horizon in HORIZONS:
            rows.append(
                {
                    "incident_uid": row["incident_uid"],
                    "incident_id": row["incident_id"],
                    "true_class": row["category"],
                    "partition": row["partition"],
                    "documented_start_utc": row["start_utc"],
                    "horizon_seconds": horizon,
                    "selected_onset": pd.NA,
                    "horizon_cutoff_utc": pd.NA,
                    "onset_review_flag": "INSUFFICIENT_TIMESTAMP_PRESERVING_EVIDENCE",
                    "status": "REVIEW_NOT_SCORED",
                    "notes": REASON,
                }
            )
    return pd.DataFrame(rows)


def predictions(grid: pd.DataFrame) -> pd.DataFrame:
    out = grid.copy()
    out["hijack_probability"] = pd.NA
    out["leak_probability"] = pd.NA
    out["outage_probability"] = pd.NA
    out["predicted_top1_class"] = "NOT_SCORED"
    out["true_class_rank"] = pd.NA
    out["top1_correct"] = pd.NA
    out["top2_correct"] = pd.NA
    return out[
        [
            "incident_id",
            "incident_uid",
            "true_class",
            "partition",
            "horizon_seconds",
            "selected_onset",
            "hijack_probability",
            "leak_probability",
            "outage_probability",
            "predicted_top1_class",
            "true_class_rank",
            "top1_correct",
            "top2_correct",
            "onset_review_flag",
            "status",
            "notes",
        ]
    ]


def metrics() -> pd.DataFrame:
    rows = []
    for horizon in HORIZONS:
        rows.append(
            {
                "horizon_seconds": horizon,
                "total_eligible_incidents": 993,
                "incidents_successfully_evaluated": 0,
                "incidents_excluded_or_reviewed": 993,
                "review_reason": REASON,
                "macro_f1": pd.NA,
                "macro_f1_ci_lower": pd.NA,
                "macro_f1_ci_upper": pd.NA,
                "hijack_f1": pd.NA,
                "leak_f1": pd.NA,
                "outage_f1": pd.NA,
                "top1_accuracy": pd.NA,
                "top2_accuracy": pd.NA,
                "mrr": pd.NA,
                "scope": LABEL,
                "status": "REVIEW_NOT_SCORED",
            }
        )
    return pd.DataFrame(rows)


def confusion() -> pd.DataFrame:
    rows = []
    for horizon in HORIZONS:
        for true_class in CLASSES:
            for predicted in CLASSES:
                rows.append(
                    {
                        "horizon_seconds": horizon,
                        "true_class": true_class,
                        "predicted_class": predicted,
                        "count": 0,
                        "status": "NOT_SCORED",
                    }
                )
    return pd.DataFrame(rows)


def checkpoints(roster: pd.DataFrame) -> pd.DataFrame:
    out = roster[["incident_id", "incident_uid", "category", "partition"]].copy()
    out = out.rename(columns={"category": "true_class"})
    out["top1_tti_checkpoint"] = ">300s / NOT_IDENTIFIED_WITHIN_TESTED_HORIZON"
    out["top2_tti_checkpoint"] = ">300s / NOT_IDENTIFIED_WITHIN_TESTED_HORIZON"
    out["stable_correct_checkpoint"] = ">300s / NOT_IDENTIFIED_WITHIN_TESTED_HORIZON"
    out["identified_top1_by_30s"] = False
    out["identified_top1_by_60s"] = False
    out["identified_top1_by_120s"] = False
    out["identified_top1_by_300s"] = False
    out["identified_top2_by_30s"] = False
    out["identified_top2_by_60s"] = False
    out["identified_top2_by_120s"] = False
    out["identified_top2_by_300s"] = False
    out["prediction_changes_after_initial_correct"] = pd.NA
    out["onset_review_flag"] = "INSUFFICIENT_TIMESTAMP_PRESERVING_EVIDENCE"
    out["status"] = "REVIEW_NOT_SCORED"
    out["notes"] = REASON
    return out


def trajectories(roster: pd.DataFrame) -> pd.DataFrame:
    out = roster[["incident_id", "incident_uid", "category", "partition"]].copy()
    out = out.rename(columns={"category": "true_class"})
    out["trajectory"] = "30s:NOT_SCORED -> 60s:NOT_SCORED -> 120s:NOT_SCORED -> 300s:NOT_SCORED"
    for horizon in HORIZONS:
        out[f"h{horizon}_top1"] = "NOT_SCORED"
        out[f"h{horizon}_true_rank"] = pd.NA
        out[f"h{horizon}_top1_correct"] = pd.NA
        out[f"h{horizon}_top2_correct"] = pd.NA
    out["onset_review_flag"] = "INSUFFICIENT_TIMESTAMP_PRESERVING_EVIDENCE"
    out["status"] = "REVIEW_NOT_SCORED"
    return out


def per_class_tti() -> pd.DataFrame:
    rows = []
    for cls in CLASSES:
        rows.append(
            {
                "class": cls,
                "eligible_incidents": 331,
                "evaluated_incidents": 0,
                "identified_by_30s_count": 0,
                "identified_by_30s_percent": 0.0,
                "identified_by_60s_count": 0,
                "identified_by_60s_percent": 0.0,
                "identified_by_120s_count": 0,
                "identified_by_120s_percent": 0.0,
                "identified_by_300s_count": 0,
                "identified_by_300s_percent": 0.0,
                "not_identified_within_300s_count": 331,
                "not_identified_within_300s_percent": 100.0,
                "median_checkpoint_tti": pd.NA,
                "status": "REVIEW_NOT_SCORED",
                "notes": REASON,
            }
        )
    return pd.DataFrame(rows)


def onset_quality(roster: pd.DataFrame) -> pd.DataFrame:
    out = roster[["incident_id", "incident_uid", "category", "partition", "start_utc"]].copy()
    out["documented_start_utc"] = out.pop("start_utc")
    out["selected_onset"] = pd.NA
    out["onset_rule"] = "FIRST_POST_DOCUMENTED_EVENT_EVIDENCE"
    out["first_post_start_routeviews_evidence"] = pd.NA
    out["offset_from_documented_start_seconds"] = pd.NA
    out["onset_quality"] = "INSUFFICIENT_EVIDENCE"
    out["review_flag"] = "INSUFFICIENT_TIMESTAMP_PRESERVING_EVIDENCE"
    out["notes"] = REASON
    return out


def compatibility(grid: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, row in grid.iterrows():
        rows.append(
            {
                "incident_uid": row["incident_uid"],
                "incident_id": row["incident_id"],
                "category": row["true_class"],
                "partition": row["partition"],
                "horizon_seconds": row["horizon_seconds"],
                "expected_feature_count": 74,
                "observed_feature_count": 0,
                "feature_order_matches_v4": "NO",
                "compatible_data_types": "NO",
                "missing_required_features": json.dumps(V4_FEATURES),
                "nan_or_inf_status": "NOT_EVALUATED",
                "status": "FAIL_NOT_SCORED",
                "notes": REASON,
            }
        )
    return pd.DataFrame(rows)


def leakage(grid: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, row in grid.iterrows():
        rows.append(
            {
                "incident_uid": row["incident_uid"],
                "incident_id": row["incident_id"],
                "category": row["true_class"],
                "partition": row["partition"],
                "horizon_seconds": row["horizon_seconds"],
                "observable_onset_utc": pd.NA,
                "horizon_cutoff_utc": pd.NA,
                "max_observation_timestamp_utc": pd.NA,
                "assertion": "max(observation_timestamp) <= onset + horizon",
                "status": "REVIEW_NOT_VERIFIABLE",
                "observations_checked": 0,
                "notes": REASON,
            }
        )
    return pd.DataFrame(rows)


def methodology_doc(info: dict[str, Any]) -> str:
    cols = ", ".join(info["evidence_columns"])
    return f"""# Full TRAIN TTI Methodology v1

Experiment label: **{LABEL}**

Approved target methodology: onset = `FIRST_POST_DOCUMENTED_EVENT_EVIDENCE`; cumulative horizons = 30, 60, 120, and 300 seconds; exact frozen V4 schema = 44 Behavioral + 14 CAIDA + 16 RPKI/ROV features; inference uses the verified `reconstructed_level1_v1` five-model XGBoost ensemble with no Level-2 temporal stacker.

## Gate Finding

The full 993-incident TRAIN scale-up cannot be scored from the currently preserved full-TRAIN artifacts without changing the validated pilot methodology. The reusable full TRAIN evidence store is aggregated at the frozen five-minute window grain and contains `window_start` / `window_end`, but no per-observation BGP timestamp column such as `observation_timestamp` or `bgp_timestamp_utc`.

Available compact evidence columns:

`{cols}`

The evidence manifest covers {info['evidence_incident_count']} TRAIN incidents and {info['evidence_window_count']} frozen five-minute windows, but that is not sufficient to construct 30/60/120/300-second cumulative horizons relative to observable onset.

## Preservation

No Validation or Final Holdout artifacts were accessed for scoring. No model was retrained, tuned, calibrated, or modified. Existing primary Praxis results remain untouched.
"""


def summary_doc(info: dict[str, Any]) -> str:
    return f"""# Full TRAIN TTI Summary v1

**{LABEL}**

Disposition: `FULL_TRAIN_TTI_REQUIRES_REVIEW`

The 9-incident pilot demonstrated that timestamp-preserving RouteViews observations can produce horizon-safe V4 rows. The full TRAIN artifacts currently preserved in the workspace do not contain equivalent timestamp-preserving observations for all 993 TRAIN incidents.

## Counts

- Eligible TRAIN incidents: 993
- Class balance: 331 Hijack / 331 Leak / 331 Outage
- Requested horizons: 30, 60, 120, 300 seconds
- Horizon rows planned: 3,972
- Horizon rows scored: 0
- Incidents requiring review: 993

## Why Scoring Stopped

The available full TRAIN compact evidence store is aggregated by `window_id + prefix + origin_asn + normalized_as_path + collector`. It preserves multiplicity through `observation_count`, but it does not preserve event-level observation timestamps inside each five-minute window. Therefore it cannot prove that a feature at the 30-second, 60-second, 120-second, or 300-second cutoff used only evidence available before that cutoff.

Using the five-minute evidence rows as a substitute would collapse the partial horizons into the already completed five-minute representation and would be a methodological change.

## Required Remediation Before Scale-Up Scoring

Recreate or recover timestamp-preserving TRAIN incident-relevant observations with at least:

- `incident_uid`
- `bgp_timestamp_utc` or `observation_timestamp`
- prefix
- origin ASN
- normalized AS path
- announcement/withdrawal indicator
- peer ASN
- collector/source MRT provenance

Then regenerate the 30/60/120/300-second V4 rows and rerun the compatibility/leakage gates before applying the reconstructed Level-1 ensemble.

## Available Evidence

- Compact evidence incident count: {info['evidence_incident_count']}
- Compact evidence window count: {info['evidence_window_count']}
- Compact evidence rows: {info['evidence_rows']}
- Frozen TRAIN V4 rows: {info['train_v4_rows']}
- Reconstructed Level-1 status: {info['level1_status']}

No figures with performance metrics were generated because there are no valid full TRAIN TTI scores to plot.

FULL_TRAIN_TTI_REQUIRES_REVIEW
"""


def run() -> str:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    roster = load_roster()
    info = artifact_evidence()
    if has_timestamp_preserving_full_train_evidence(info):
        raise RuntimeError("Timestamp-preserving full TRAIN evidence appears available; this REVIEW gate should be replaced by the full scorer.")

    roster_df = roster_output(roster, info)
    grid = horizon_grid(roster)
    write_csv(OUT_DIR / "tti_train_full_incident_roster_v1.csv", roster_df)
    write_csv(OUT_DIR / "tti_train_full_predictions_v1.csv", predictions(grid))
    write_csv(OUT_DIR / "tti_train_full_horizon_metrics_v1.csv", metrics())
    write_csv(OUT_DIR / "tti_train_full_confusion_matrices_v1.csv", confusion())
    write_csv(OUT_DIR / "tti_train_full_checkpoint_tti_v1.csv", checkpoints(roster))
    write_csv(OUT_DIR / "tti_train_full_prediction_trajectories_v1.csv", trajectories(roster))
    write_csv(OUT_DIR / "tti_train_full_per_class_tti_v1.csv", per_class_tti())
    write_csv(OUT_DIR / "tti_train_full_onset_quality_v1.csv", onset_quality(roster))
    write_csv(OUT_DIR / "tti_train_full_v4_compatibility_v1.csv", compatibility(grid))
    write_csv(OUT_DIR / "tti_train_full_leakage_assertions_v1.csv", leakage(grid))
    (OUT_DIR / "tti_train_full_methodology_v1.md").write_text(methodology_doc(info), encoding="utf-8")
    (OUT_DIR / "tti_train_full_summary_v1.md").write_text(summary_doc(info), encoding="utf-8")
    return "FULL_TRAIN_TTI_REQUIRES_REVIEW"


def main() -> None:
    parser = argparse.ArgumentParser(description="Full TRAIN TTI scale-up gate.")
    parser.parse_args()
    print(run())


if __name__ == "__main__":
    main()
