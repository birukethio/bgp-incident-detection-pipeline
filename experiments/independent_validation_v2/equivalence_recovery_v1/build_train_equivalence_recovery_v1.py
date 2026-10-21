from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd


REPO = Path(__file__).resolve().parents[3]
OUT = REPO / "experiments" / "independent_validation_v2" / "equivalence_recovery_v1"


ARTIFACTS = [
    ("source_incident_roster", "data/partitions_v2/train_incidents_v2.csv", "csv", "incident IDs, labels, timestamps, metadata"),
    ("raw_routeviews_mrt", "data/raw_mrt/train_batches", "directory", "raw MRT cache if retained"),
    ("timestamped_routeviews_evidence", "data/tti_timestamped_train_v1/evidence", "directory", "timestamp-preserving incident-relevant observations"),
    ("compact_routeviews_evidence", "data/enrichment/evidence/train_v1", "directory", "window/prefix/origin/path compact enrichment evidence"),
    ("five_minute_behavioral_windows", "data/train_frozen/frozen_train_behavioral_corpus_v1.parquet", "parquet", "5-minute analytical windows and 44 behavioral features"),
    ("caida_features", "data/enrichment/caida/train_caida_features_v1.parquet", "parquet", "14 CAIDA features and snapshot mapping"),
    ("rpki_features", "data/enrichment/rpki/train_rpki_features_v1.parquet", "parquet", "16 RPKI/ROV features"),
    ("v4_features", "data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1.parquet", "parquet", "74-feature V4 rows"),
    ("level1_window_scores", "data/modeling_k1/k1_window_oof_probabilities_v1.parquet", "parquet", "OOF Level-1 window probabilities"),
    ("mean_aggregation_results", "data/modeling_k1/k1_incident_level_predictions_v1.parquet", "parquet", "K1-B0 mean probability and temporal stacker incident predictions"),
    ("level2_meta_features", "data/modeling_k1/k1_incident_meta_features_v1.parquet", "parquet", "retrospective temporal meta-features"),
    ("level2_fold_results", "data/modeling_k1/k1_fold_results_v1.csv", "csv", "fold-level K1/B0 metrics"),
    ("k2_reproduction", "data/modeling_k2/k2_k1_reproduction_v1.csv", "csv", "K2 reproduction check"),
    ("level1_reconstructed_models", "data/tti_pilot/reconstructed_level1_v1", "directory", "reconstructed Level-1 model artifacts"),
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def dir_size(path: Path) -> int:
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file()) if path.exists() else 0


def artifact_inventory() -> pd.DataFrame:
    rows = []
    for name, rel, kind, contents in ARTIFACTS:
        path = REPO / rel
        exists = path.exists()
        row_count = ""
        col_count = ""
        columns = ""
        if exists and path.is_file() and path.suffix == ".parquet":
            df = pd.read_parquet(path)
            row_count = len(df)
            col_count = len(df.columns)
            columns = "|".join(df.columns[:30])
        elif exists and path.is_file() and path.suffix == ".csv":
            df = pd.read_csv(path)
            row_count = len(df)
            col_count = len(df.columns)
            columns = "|".join(df.columns[:30])
        rows.append(
            {
                "artifact_role": name,
                "relative_path": rel,
                "artifact_type": kind,
                "exists": "YES" if exists else "NO",
                "size_bytes": path.stat().st_size if exists and path.is_file() else dir_size(path) if exists and path.is_dir() else 0,
                "row_count": row_count,
                "column_count": col_count,
                "first_columns": columns,
                "train_only": "YES",
                "reference_use": contents,
                "equivalence_stage_supported": stage_for_artifact(name),
            }
        )
    return pd.DataFrame(rows)


def stage_for_artifact(name: str) -> str:
    if name in {"source_incident_roster"}:
        return "E0_METADATA_REFERENCE"
    if name in {"raw_routeviews_mrt", "timestamped_routeviews_evidence"}:
        return "E1_ROUTEVIEWS_WINDOW_REFERENCE_PARTIAL"
    if name in {"five_minute_behavioral_windows", "caida_features", "rpki_features", "v4_features", "compact_routeviews_evidence"}:
        return "E2_FEATURE_REFERENCE"
    if name in {"level1_window_scores", "level1_reconstructed_models"}:
        return "E3_LEVEL1_REFERENCE"
    if name in {"mean_aggregation_results"}:
        return "E4_MEAN_AGGREGATION_AND_E6_LEVEL2_REFERENCE"
    if name in {"level2_meta_features"}:
        return "E5_META_FEATURE_REFERENCE"
    if name in {"level2_fold_results", "k2_reproduction"}:
        return "E6_SUMMARY_REFERENCE"
    return "UNKNOWN"


def select_fixtures() -> pd.DataFrame:
    v4_cols = ["incident_uid", "incident_id", "category", "window_id", "window_start", "window_end", "raw_observation_count", "has_relevant_observation"]
    v4 = pd.read_parquet(REPO / "data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1.parquet", columns=v4_cols)
    probs = pd.read_parquet(REPO / "data/modeling_k1/k1_window_oof_probabilities_v1.parquet", columns=["incident_uid", "window_id"])
    meta = pd.read_parquet(REPO / "data/modeling_k1/k1_incident_meta_features_v1.parquet", columns=["incident_uid"])
    pred = pd.read_parquet(REPO / "data/modeling_k1/k1_incident_level_predictions_v1.parquet", columns=["incident_uid", "candidate_id"])
    pred_incidents = set(pred["incident_uid"].unique())
    complete = (
        v4.groupby(["incident_uid", "incident_id", "category"])
        .agg(
            window_count=("window_id", "count"),
            raw_observation_sum=("raw_observation_count", "sum"),
            nonzero_windows=("has_relevant_observation", "sum"),
            first_window_start=("window_start", "min"),
            last_window_end=("window_end", "max"),
        )
        .reset_index()
    )
    prob_counts = probs.groupby("incident_uid").size().rename("level1_window_score_rows").reset_index()
    complete = complete.merge(prob_counts, on="incident_uid", how="left")
    complete["has_v4_reference"] = "YES"
    complete["has_level1_window_scores"] = complete["level1_window_score_rows"].fillna(0).eq(complete["window_count"]).map({True: "YES", False: "NO"})
    complete["has_meta_features"] = complete["incident_uid"].isin(set(meta["incident_uid"])).map({True: "YES", False: "NO"})
    complete["has_incident_predictions"] = complete["incident_uid"].isin(pred_incidents).map({True: "YES", False: "NO"})
    complete["reference_chain_completeness"] = complete[
        ["has_v4_reference", "has_level1_window_scores", "has_meta_features", "has_incident_predictions"]
    ].eq("YES").sum(axis=1)

    selected_rows = []
    for category in ["Hijack", "Leak", "Outage"]:
        sub = complete[(complete["category"] == category) & (complete["reference_chain_completeness"] == 4)].copy()
        sub = sub.sort_values(["window_count", "raw_observation_sum", "incident_uid"])
        for bucket, row in [("SHORT", sub.iloc[0]), ("MEDIAN", sub.iloc[len(sub) // 2]), ("LONG", sub.iloc[-1])]:
            selected_rows.append({**row.to_dict(), "fixture_bucket": bucket, "selection_basis": "deterministic category short/median/long among incidents with V4, Level-1 scores, meta-features, and incident predictions"})
    out = pd.DataFrame(selected_rows)
    cols = ["incident_uid", "incident_id", "category", "fixture_bucket", "window_count", "raw_observation_sum", "nonzero_windows", "first_window_start", "last_window_end", "level1_window_score_rows", "has_v4_reference", "has_level1_window_scores", "has_meta_features", "has_incident_predictions", "reference_chain_completeness", "selection_basis"]
    return out[cols]


def write_tolerance_spec() -> None:
    (OUT / "train_equivalence_tolerance_specification_v1.md").write_text(
        """# TRAIN Equivalence Tolerance Specification v1

Defined before any new implementation comparison.

- Window count, `window_id`, `incident_uid`, `window_start`, and `window_end`: exact string/count match required.
- Feature schema: exact 74/74 feature names and order required.
- Integer/count features: exact match required.
- Floating-point features: `EXACT_MATCH` if bitwise/string-equivalent after serialization; `NUMERICALLY_EQUIVALENT` if absolute difference <= 1e-9 and relative difference <= 1e-9.
- Level-1 probabilities: exact match preferred; numerically equivalent if maximum absolute probability difference <= 1e-9.
- Mean aggregation probabilities: numerically equivalent if maximum absolute probability difference <= 1e-9.
- Level-2 meta-features: exact for count/rank/vote features; <= 1e-9 absolute/relative tolerance for floating-point summaries.
- Level-2 class scores/ranking/predicted class: probability tolerance <= 1e-9 and identical predicted class/rank ordering.

Tolerances must not be loosened after observing discrepancies.
""",
        encoding="utf-8",
    )


def compare_windows(fixtures: pd.DataFrame) -> pd.DataFrame:
    v4 = pd.read_parquet(REPO / "data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1.parquet", columns=["incident_uid", "window_id", "window_start", "window_end"])
    rows = []
    for _, fx in fixtures.iterrows():
        sub = v4[v4["incident_uid"] == fx["incident_uid"]]
        rows.append(
            {
                "incident_uid": fx["incident_uid"],
                "stage": "E1_WINDOW_LINKAGE",
                "reference_window_count": len(sub),
                "new_implementation_window_count": "",
                "comparison_status": "REFERENCE_ARTIFACT_AVAILABLE_NEW_IMPLEMENTATION_NOT_RUN",
                "timestamp_reference_available": "YES",
                "incident_linkage_reference_available": "YES",
                "notes": "Stored frozen V4 window IDs/timestamps are available. No new implementation output was generated in this recovery step.",
            }
        )
    return pd.DataFrame(rows)


def compare_features(fixtures: pd.DataFrame) -> pd.DataFrame:
    try:
        from bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT
    except Exception:
        import sys
        sys.path.insert(0, str(REPO / "src"))
        from bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT
    features = FEATURES_BY_VARIANT["V4"]
    v4 = pd.read_parquet(REPO / "data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1.parquet", columns=["incident_uid"] + features)
    rows = []
    for _, fx in fixtures.iterrows():
        sub = v4[v4["incident_uid"] == fx["incident_uid"]]
        rows.append(
            {
                "incident_uid": fx["incident_uid"],
                "stage": "E2_V4_FEATURES",
                "reference_rows": len(sub),
                "reference_feature_count": len(features),
                "new_implementation_rows": "",
                "new_implementation_feature_count": "",
                "comparison_status": "REFERENCE_ARTIFACT_AVAILABLE_NEW_IMPLEMENTATION_NOT_RUN",
                "missing_reference_features": "",
                "notes": "Frozen V4 reference rows are available, but equivalence requires a newly assembled implementation output for comparison.",
            }
        )
    return pd.DataFrame(rows)


def compare_level1(fixtures: pd.DataFrame) -> pd.DataFrame:
    probs = pd.read_parquet(REPO / "data/modeling_k1/k1_window_oof_probabilities_v1.parquet")
    rows = []
    for _, fx in fixtures.iterrows():
        sub = probs[probs["incident_uid"] == fx["incident_uid"]]
        rows.append(
            {
                "incident_uid": fx["incident_uid"],
                "stage": "E3_LEVEL1_WINDOW_SCORES",
                "reference_score_rows": len(sub),
                "new_implementation_score_rows": "",
                "comparison_status": "REFERENCE_ARTIFACT_AVAILABLE_NEW_IMPLEMENTATION_NOT_RUN",
                "probability_columns": "p_hijack|p_leak|p_outage",
                "notes": "Stored TRAIN OOF Level-1 probabilities are available. No new implementation scores were generated.",
            }
        )
    return pd.DataFrame(rows)


def compare_mean(fixtures: pd.DataFrame) -> pd.DataFrame:
    pred = pd.read_parquet(REPO / "data/modeling_k1/k1_incident_level_predictions_v1.parquet")
    rows = []
    for _, fx in fixtures.iterrows():
        sub = pred[(pred["incident_uid"] == fx["incident_uid"]) & (pred["candidate_id"] == "K1-B0_MEAN_PROBABILITY")]
        rows.append(
            {
                "incident_uid": fx["incident_uid"],
                "stage": "E4_MEAN_AGGREGATION",
                "reference_rows": len(sub),
                "new_implementation_rows": "",
                "comparison_status": "REFERENCE_ARTIFACT_AVAILABLE_NEW_IMPLEMENTATION_NOT_RUN" if len(sub) else "REFERENCE_ARTIFACT_UNAVAILABLE",
                "notes": "Mean aggregation incident reference is available when row_count=1; no new implementation aggregation was generated.",
            }
        )
    return pd.DataFrame(rows)


def compare_meta(fixtures: pd.DataFrame) -> pd.DataFrame:
    meta = pd.read_parquet(REPO / "data/modeling_k1/k1_incident_meta_features_v1.parquet")
    rows = []
    for _, fx in fixtures.iterrows():
        sub = meta[meta["incident_uid"] == fx["incident_uid"]]
        rows.append(
            {
                "incident_uid": fx["incident_uid"],
                "stage": "E5_LEVEL2_META_FEATURES",
                "reference_rows": len(sub),
                "reference_meta_feature_count": max(0, len(meta.columns) - 3),
                "new_implementation_rows": "",
                "comparison_status": "REFERENCE_ARTIFACT_AVAILABLE_NEW_IMPLEMENTATION_NOT_RUN" if len(sub) else "REFERENCE_ARTIFACT_UNAVAILABLE",
                "notes": "Retrospective temporal meta-feature references are available; no new implementation meta-features were generated.",
            }
        )
    return pd.DataFrame(rows)


def compare_level2(fixtures: pd.DataFrame) -> pd.DataFrame:
    pred = pd.read_parquet(REPO / "data/modeling_k1/k1_incident_level_predictions_v1.parquet")
    rows = []
    for _, fx in fixtures.iterrows():
        sub = pred[(pred["incident_uid"] == fx["incident_uid"]) & (pred["candidate_id"] != "K1-B0_MEAN_PROBABILITY")]
        rows.append(
            {
                "incident_uid": fx["incident_uid"],
                "stage": "E6_LEVEL2_FINAL_SCORES",
                "reference_rows": len(sub),
                "available_candidate_ids": "|".join(sorted(sub["candidate_id"].astype(str).unique())),
                "new_implementation_rows": "",
                "comparison_status": "REFERENCE_ARTIFACT_AVAILABLE_NEW_IMPLEMENTATION_NOT_RUN" if len(sub) else "REFERENCE_ARTIFACT_UNAVAILABLE",
                "notes": "Stored K1 incident-level prediction references exist; no new implementation final scores were generated.",
            }
        )
    return pd.DataFrame(rows)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    inventory = artifact_inventory()
    inventory.to_csv(OUT / "train_equivalence_artifact_inventory_v1.csv", index=False)
    fixtures = select_fixtures()
    fixtures.to_csv(OUT / "train_equivalence_fixture_roster_v1.csv", index=False)
    (OUT / "train_equivalence_fixture_roster_v1.sha256").write_text(
        f"{sha256(OUT / 'train_equivalence_fixture_roster_v1.csv')}  train_equivalence_fixture_roster_v1.csv\n",
        encoding="utf-8",
    )
    write_tolerance_spec()
    compare_windows(fixtures).to_csv(OUT / "train_equivalence_window_comparison_v1.csv", index=False)
    compare_features(fixtures).to_csv(OUT / "train_equivalence_feature_comparison_v1.csv", index=False)
    compare_level1(fixtures).to_csv(OUT / "train_equivalence_level1_comparison_v1.csv", index=False)
    compare_mean(fixtures).to_csv(OUT / "train_equivalence_mean_aggregation_v1.csv", index=False)
    compare_meta(fixtures).to_csv(OUT / "train_equivalence_meta_feature_comparison_v1.csv", index=False)
    compare_level2(fixtures).to_csv(OUT / "train_equivalence_level2_comparison_v1.csv", index=False)

    failure = f"""# TRAIN Equivalence Failure Analysis v1

Generated UTC: {datetime.now(timezone.utc).isoformat()}

## Finding

Stored TRAIN reference artifacts are available from frozen V4 features through Level-1 probabilities, mean aggregation, Level-2 meta-features, and final K1 incident predictions for the selected fixtures.

However, this recovery step did not find a frozen end-to-end implementation output regenerated from source incident metadata and RouteViews evidence for the same fixtures. Therefore, the artifacts can define a strong TRAIN-only fixture roster and reference targets, but they cannot by themselves establish implementation equivalence for a newly assembled IEC reconstruction/scoring implementation.

## Equivalence Stage Assessment

- E1 RouteViews/window count/timestamp/linkage: reference windows available, but no new implementation output compared.
- E2 V4 74-feature vectors: reference vectors available, but no new implementation output compared.
- E3 Level-1 scores: reference OOF scores available, but no new implementation output compared.
- E4 Mean aggregation: reference rows available, but no new implementation output compared.
- E5 Retrospective temporal meta-features: reference rows available, but no new implementation output compared.
- E6 Level-2 scores/ranking/predicted class: reference rows available, but no new implementation output compared.

## Cause Classification

Primary blocker: `missing historical artifact` / `new implementation output not generated`.

No evidence was found that the existing TRAIN reference artifacts are wrong. The limitation is that equivalence requires a side-by-side comparison between reference outputs and a newly assembled IEC execution implementation applied only to frozen TRAIN fixtures.
"""
    (OUT / "train_equivalence_failure_analysis_v1.md").write_text(failure, encoding="utf-8")

    summary = f"""# TRAIN Equivalence Recovery Summary v1

Generated UTC: {datetime.now(timezone.utc).isoformat()}

## Fixture Recovery

- Artifact inventory rows: {len(inventory)}
- Frozen fixture incidents: {len(fixtures)}
- Fixture classes: {fixtures['category'].value_counts().to_dict()}
- Fixture buckets: {fixtures['fixture_bucket'].value_counts().to_dict()}

## Result

The project contains enough TRAIN-only reference artifacts to freeze a deterministic fixture set and define comparison targets through E6. It does not, by itself, establish equivalence, because no new IEC reconstruction/scoring implementation was run on those fixtures in this recovery step and no pre-existing side-by-side regenerated outputs were found.

## Recommendation

The recovered fixture set is suitable for a future implementation-equivalence run. The next controlled step would be to apply the new IEC execution implementation only to these TRAIN fixture incidents and compare against the frozen reference artifacts using `train_equivalence_tolerance_specification_v1.md`.

Disposition: `INSUFFICIENT_REFERENCE_ARTIFACTS`
"""
    (OUT / "train_equivalence_summary_v1.md").write_text(summary, encoding="utf-8")
    (OUT / "train_equivalence_final_disposition_v1.md").write_text(
        "# TRAIN Equivalence Final Disposition v1\n\n`INSUFFICIENT_REFERENCE_ARTIFACTS`\n\nA deterministic TRAIN-only fixture set and reference targets were recovered, but equivalence is not established until a newly assembled IEC implementation is run on those fixtures and compared against the preserved references. No IEC incidents were scored; Validation and Final Holdout were not accessed.\n",
        encoding="utf-8",
    )
    print(json.dumps({"fixtures": len(fixtures), "disposition": "INSUFFICIENT_REFERENCE_ARTIFACTS"}, indent=2))


if __name__ == "__main__":
    main()
