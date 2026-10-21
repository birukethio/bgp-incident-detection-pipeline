from __future__ import annotations

import csv
import re
from pathlib import Path


ROOT = Path("/Users/biruk/Documents/New project")
DOCS = ROOT / "docs"


def write_csv(path: Path, rows: list[dict[str, object]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def feature_names_from_yaml(path: Path, keys: tuple[str, ...]) -> list[str]:
    names: list[str] = []
    text = path.read_text(encoding="utf-8")
    for line in text.splitlines():
        stripped = line.strip()
        for key in keys:
            match = re.match(rf"{key}:\s*(.+)$", stripped)
            if match:
                value = match.group(1).strip().strip('"').strip("'")
                if value and value not in names:
                    names.append(value)
    return names


def existing(path: str) -> str:
    return "YES" if (ROOT / path).exists() else "NO"


def build_artifact_rows() -> list[dict[str, object]]:
    return [
        {
            "artifact": "docs/enrichment_evidence_store_v1.md",
            "exists": existing("docs/enrichment_evidence_store_v1.md"),
            "grain": "one aggregated row per 5-minute TRAIN window and prefix/origin/normalized_as_path/collector tuple",
            "timestamp_resolution": "5-minute window bounds only",
            "tti_reuse_value": "Useful for full-window CAIDA/RPKI and for designing a future evidence schema; insufficient for 30/60/120-second exact TTI.",
            "limitation": "No per-observation timestamp; no announcement/withdrawal split; no peer ASN/NEXT_HOP/community/MED/LOCAL_PREF/atomic aggregate.",
        },
        {
            "artifact": "data/enrichment/evidence/train_v1/*.parquet",
            "exists": existing("data/enrichment/evidence/train_v1"),
            "grain": "compact TRAIN evidence batches",
            "timestamp_resolution": "window_start/window_end only",
            "tti_reuse_value": "Can remap CAIDA/RPKI for completed 5-minute windows; cannot determine which observations occurred before a partial horizon.",
            "limitation": "Parquet reader unavailable in current runtime; schema confirmed from docs/code/manifest, not full column read.",
        },
        {
            "artifact": "data/enrichment/evidence/train_evidence_manifest_v1.csv",
            "exists": existing("data/enrichment/evidence/train_evidence_manifest_v1.csv"),
            "grain": "batch manifest",
            "timestamp_resolution": "batch/window counts only",
            "tti_reuse_value": "Confirms compact evidence coverage and PASS status by batch.",
            "limitation": "Does not contain per-observation timestamps.",
        },
        {
            "artifact": "src/bgp_incident_detection/mrt_parser.py",
            "exists": existing("src/bgp_incident_detection/mrt_parser.py"),
            "grain": "parser code emits prefix-level BGP observations",
            "timestamp_resolution": "bgp_timestamp_utc in milliseconds from bgpdump epoch field",
            "tti_reuse_value": "Correct basis for a future timestamped evidence store or targeted reparse.",
            "limitation": "Full TRAIN parsed corpus was intentionally not retained.",
        },
        {
            "artifact": "data/parsed_mrt/pilot/*/parsed_bgp_observations.csv and normal-scale parsed CSVs",
            "exists": existing("data/parsed_mrt"),
            "grain": "prefix-level parsed BGP observations for pilots/normal candidates",
            "timestamp_resolution": "per-observation bgp_timestamp_utc",
            "tti_reuse_value": "Useful for validating TTI code on small existing subsets without reparsing all RouteViews.",
            "limitation": "Not a complete 993-incident TRAIN corpus.",
        },
        {
            "artifact": "data/train_scale/train_incident_processing_manifest_v1.csv",
            "exists": existing("data/train_scale/train_incident_processing_manifest_v1.csv"),
            "grain": "TRAIN incident acquisition/processing manifest",
            "timestamp_resolution": "incident start/end and metadata",
            "tti_reuse_value": "Contains incident metadata and relevance fields for onset predicates.",
            "limitation": "Incident source start time is not the same as RouteViews-observable onset.",
        },
        {
            "artifact": "data/train_scale/train_mrt_acquisition_plan_v1.csv",
            "exists": existing("data/train_scale/train_mrt_acquisition_plan_v1.csv"),
            "grain": "MRT file acquisition plan",
            "timestamp_resolution": "15-minute MRT file timestamps plus collection ranges",
            "tti_reuse_value": "Can identify the exact RouteViews files that would need targeted reparse for TTI.",
            "limitation": "Does not expose message timestamps inside files.",
        },
        {
            "artifact": "data/raw_mrt/train/",
            "exists": existing("data/raw_mrt/train"),
            "grain": "raw MRT files",
            "timestamp_resolution": "per-message timestamps inside MRT if files exist",
            "tti_reuse_value": "Would permit exact reconstruction if present.",
            "limitation": "No raw TRAIN .bz2 files were found in this audit; previous pipeline recovered disk after batch processing.",
        },
        {
            "artifact": "data/train_frozen/frozen_train_behavioral_corpus_v1.parquet",
            "exists": existing("data/train_frozen/frozen_train_behavioral_corpus_v1.parquet"),
            "grain": "completed 5-minute behavioral feature rows",
            "timestamp_resolution": "window_start/window_end only",
            "tti_reuse_value": "Reference target schema and full-window values.",
            "limitation": "Completed-window features cannot be truncated to 30/60/120 seconds without raw timestamps.",
        },
        {
            "artifact": "config/k1_second_level_xgb_final_v1.yaml and config/k1_incident_meta_feature_schema_v1.yaml",
            "exists": "YES" if existing("config/k1_second_level_xgb_final_v1.yaml") == "YES" and existing("config/k1_incident_meta_feature_schema_v1.yaml") == "YES" else "NO",
            "grain": "frozen K1 second-level model specification and meta-feature schema",
            "timestamp_resolution": "incident-level temporal summaries over window probabilities",
            "tti_reuse_value": "Documents why K1 is not the first valid TTI target.",
            "limitation": "Meta-features use incident window sequence summaries; applying them at early horizons would need a separate causal prefix design.",
        },
    ]


def build_feature_rows() -> list[dict[str, object]]:
    behavioral = feature_names_from_yaml(ROOT / "config/behavioral_feature_schema_v1.yaml", ("feature_name",))
    caida = feature_names_from_yaml(ROOT / "config/caida_feature_schema_v1.yaml", ("name",))
    rpki = feature_names_from_yaml(ROOT / "config/rpki_feature_schema_v1.yaml", ("name",))
    rows: list[dict[str, object]] = []
    for name in behavioral:
        future_reason = "Requires exact observations up to the horizon, including bgp_timestamp_utc and parser fields such as announcement/withdrawal, peer_asn, prefix, AS_PATH, and optional attributes."
        if name.endswith("_rate_per_minute"):
            future_reason += " Also requires a predeclared denominator decision: keep frozen 5-minute denominator for compatibility or use elapsed-horizon denominator for a new representation."
        rows.append(
            {
                "feature_group": "Behavioral",
                "feature_name": name,
                "safe_from_current_compact_evidence": "NO",
                "safe_from_existing_full_window_features": "NO",
                "safe_if_timestamped_observations_exist": "YES_WITH_PROTOCOL",
                "partial_horizons_supported": "30s;60s;120s;300s only with per-observation timestamps",
                "future_leakage_risk": "HIGH if computed from completed 5-minute window; LOW if strictly filters bgp_timestamp_utc <= onset+horizon.",
                "notes": future_reason,
            }
        )
    for name in caida:
        rows.append(
            {
                "feature_group": "CAIDA",
                "feature_name": name,
                "safe_from_current_compact_evidence": "NO_FOR_PARTIAL; YES_FOR_COMPLETED_5MIN",
                "safe_from_existing_full_window_features": "NO_FOR_PARTIAL",
                "safe_if_timestamped_observations_exist": "YES_WITH_ASOF_SNAPSHOT",
                "partial_horizons_supported": "30s;60s;120s;300s only with timestamped prefix/path evidence",
                "future_leakage_risk": "Use nearest CAIDA relationship snapshot available at or before horizon_end; do not use future snapshots.",
                "notes": "Requires normalized_as_path and observation multiplicity for observations available by the horizon.",
            }
        )
    for name in rpki:
        rows.append(
            {
                "feature_group": "RPKI/ROV",
                "feature_name": name,
                "safe_from_current_compact_evidence": "NO_FOR_PARTIAL; YES_FOR_COMPLETED_5MIN",
                "safe_from_existing_full_window_features": "NO_FOR_PARTIAL",
                "safe_if_timestamped_observations_exist": "YES_WITH_ASOF_VRP_SNAPSHOT",
                "partial_horizons_supported": "30s;60s;120s;300s only with timestamped prefix/origin evidence",
                "future_leakage_risk": "Use VRP state available at or before horizon_end; do not use future ROA state.",
                "notes": "Requires prefix, origin_asn, observation_count, and observation date/horizon time.",
            }
        )
    return rows


def build_code_change_rows() -> list[dict[str, object]]:
    return [
        {
            "path": "src/bgp_incident_detection/caida_train_enrichment.py",
            "current_role": "Streams bgpdump output, filters relevant observations, writes compact 5-minute evidence, calculates CAIDA features.",
            "needed_for_tti": "Add optional timestamped compact evidence writer with bgp_timestamp_utc or sub-bin offsets and preserve announcement_or_withdrawal/peer_asn if behavioral reconstruction will use the same store.",
            "risk": "Changing current code must be versioned; do not overwrite existing train_v1 evidence or CAIDA outputs.",
        },
        {
            "path": "src/bgp_incident_detection/behavioral_features.py",
            "current_role": "Aggregates parsed observations into completed 5-minute behavioral features.",
            "needed_for_tti": "Add horizon-limited aggregation that filters observations by observable_onset_utc <= timestamp <= onset+horizon and records horizon_seconds.",
            "risk": "Rate features and window-completion statistics need explicit denominator/missingness rules.",
        },
        {
            "path": "src/bgp_incident_detection/rpki_train_enrichment.py",
            "current_role": "Builds RPKI/ROV features from compact 5-minute evidence.",
            "needed_for_tti": "Add horizon-aware input support once timestamped prefix/origin evidence exists; select VRP snapshots as of horizon_end.",
            "risk": "Using same-day/future VRP state before it was observable would leak future control-plane authorization information.",
        },
        {
            "path": "src/bgp_incident_detection/k1_incident_stacking.py",
            "current_role": "Builds incident-level temporal meta-features from full incident window probability sequences.",
            "needed_for_tti": "Do not use frozen K1 directly for initial TTI. A future K1-TTI variant would need causal prefix-only meta-features and retraining.",
            "risk": "Full sequence summaries would leak future windows into early classification.",
        },
        {
            "path": "new: src/bgp_incident_detection/tti_audit_or_horizon_features.py",
            "current_role": "Not present.",
            "needed_for_tti": "Create a versioned module to build onset records, horizon feature vectors, and audit tables without altering frozen V4 artifacts.",
            "risk": "Must keep Validation/Holdout sealed unless a future protocol explicitly authorizes access.",
        },
        {
            "path": "new: notebooks/58_tti_feasibility_and_design.ipynb",
            "current_role": "Not present.",
            "needed_for_tti": "Document the audit/design only; later experiment notebook should be separate and predeclared.",
            "risk": "Notebook must not run model evaluation during the audit step.",
        },
    ]


def main() -> None:
    DOCS.mkdir(parents=True, exist_ok=True)
    write_csv(
        DOCS / "tti_reusable_artifacts_audit_v1.csv",
        build_artifact_rows(),
        ["artifact", "exists", "grain", "timestamp_resolution", "tti_reuse_value", "limitation"],
    )
    feature_rows = build_feature_rows()
    write_csv(
        DOCS / "tti_feature_horizon_safety_v1.csv",
        feature_rows,
        [
            "feature_group",
            "feature_name",
            "safe_from_current_compact_evidence",
            "safe_from_existing_full_window_features",
            "safe_if_timestamped_observations_exist",
            "partial_horizons_supported",
            "future_leakage_risk",
            "notes",
        ],
    )
    write_csv(
        DOCS / "tti_required_code_changes_v1.csv",
        build_code_change_rows(),
        ["path", "current_role", "needed_for_tti", "risk"],
    )
    summary_rows = [
        {"question": "Can current compact evidence reconstruct 30/60/120/300s V4-compatible features exactly?", "answer": "NO", "evidence": "Compact evidence is aggregated by completed 5-minute window and lacks per-observation timestamp."},
        {"question": "Can pilot parsed CSVs support a small proof-of-concept?", "answer": "YES_FOR_SMALL_SUBSETS", "evidence": "Parsed pilot/normal CSVs retain bgp_timestamp_utc, but they are not the complete TRAIN corpus."},
        {"question": "Can frozen Level-1 XGBoost consume partial-horizon features?", "answer": "TECHNICALLY_YES", "evidence": "The model expects 74 numeric V4 columns; horizon-limited features can match the schema if generated with identical column order and preprocessing."},
        {"question": "Is retraining scientifically required for a production early-classification model?", "answer": "LIKELY_YES", "evidence": "Partial horizons are censored observations with different distributions from completed 5-minute training windows."},
        {"question": "Should frozen K1 be used directly for initial TTI?", "answer": "NO", "evidence": "K1 second-level meta-features summarize full incident probability sequences, including early/middle/late segments and slopes."},
    ]
    write_csv(DOCS / "tti_audit_summary_v1.csv", summary_rows, ["question", "answer", "evidence"])

    report = """# Time-to-Identify Audit Report v1

## Scope

This audit addresses the advisor's Time to Identify (TTI) concern without modifying frozen data, models, Validation artifacts, Final Holdout artifacts, Chapter 3/4 results, or any existing experiment. No TTI experiment was executed.

The current final Praxis architecture uses completed non-overlapping five-minute analytical windows. Therefore, the final reported model performance is a completed-window incident classification/ranking result, not a measurement of how quickly the system can identify an incident after the first observable BGP evidence.

## Short Answer

The existing compact TRAIN evidence store is not sufficient to reconstruct exact frozen V4-compatible features at 30, 60, 120, or 300 seconds without reparsing or having retained timestamped observations. It stores `window_start` and `window_end`, but not the original `bgp_timestamp_utc` for each observation. It also omits several parser fields needed for the 44 Behavioral features.

The pilot and normal parsed CSV artifacts do contain per-observation timestamps, so they can support a small code-level proof of concept. They do not cover the full frozen TRAIN corpus.

## Existing Timestamp-Level Evidence

The parser emits `bgp_timestamp_utc` at prefix-level observation grain from `bgpdump -q -m`. This timestamp is available in parsed pilot and normal-candidate CSVs under `data/parsed_mrt/`.

For the full TRAIN feature corpus, the retained durable evidence is mostly at completed five-minute grain:

- frozen behavioral feature rows contain `window_start` and `window_end`;
- compact enrichment evidence contains `window_start`, `window_end`, `prefix`, `origin_asn`, `normalized_as_path`, `observation_count`, and collector/provenance fields;
- CAIDA and RPKI feature batches are already aggregated to one row per frozen five-minute `window_id`.

The full raw parsed TRAIN observation corpus was intentionally not retained, and no raw TRAIN MRT `.bz2` files were found under `data/raw_mrt/train/` during this audit.

## Proposed Observable-Onset Definition

Use a RouteViews-observable onset, not the source-reported incident start alone.

`observable_onset_utc = the earliest BGP UPDATE timestamp from the predeclared RouteViews collector/acquisition interval that satisfies the incident-specific relevance predicate.`

The relevance predicate must use only frozen incident metadata:

- Hijack: affected prefix when known, victim ASN, hijacker ASN, and origin/path evidence tied to the incident.
- Leak: `leak_asn`, `leak_seg`, observed origin/path evidence tied to the leak event, and affected prefix only when actually available.
- Outage: affected ASN/network and BGP-visible withdrawals/announcements involving affected networks.

If no matching RouteViews observation exists, TTI is not measurable for that incident from RouteViews alone. The source start time may be retained as documented incident onset, but it should not be substituted for BGP-observable onset in an early-classification experiment.

## Feature Safety at Partial Horizons

The companion table `docs/tti_feature_horizon_safety_v1.csv` classifies all 74 V4 features.

Summary:

- 44 Behavioral features: not recoverable exactly at partial horizons from the current compact evidence store or frozen completed-window features. They are computable if timestamped parsed observations are available and the aggregation filters strictly to `timestamp <= observable_onset_utc + horizon`.
- 14 CAIDA features: can be remapped at partial horizons only if timestamped prefix/path evidence exists. Use the nearest CAIDA snapshot available at or before the horizon time.
- 16 RPKI/ROV features: can be remapped at partial horizons only if timestamped prefix/origin evidence exists. Use VRP data available at or before the horizon time.

Completed five-minute values must not be reused for a 30/60/120-second horizon because that would include observations from the future part of the window.

## Frozen Level-1 Versus K1

The frozen Level-1 XGBoost model can technically consume a 74-column V4-compatible vector at each horizon if the feature order and preprocessing are preserved. That would evaluate robustness of the completed-window model under censored partial evidence. It is not the same as a model trained specifically for early classification.

The frozen K1 incident-level temporal stacker should not be used directly for the first TTI experiment. Its meta-features summarize a sequence of window probabilities, including early/middle/late thirds, slopes, and full incident-level probability distribution summaries. Applying those summaries to partial evidence would either be undefined or would leak future windows unless the stacker were redesigned as a causal prefix-only architecture.

## Recommended Early-Classification Experiment

Recommended first experiment after review:

1. Keep the final frozen model artifacts untouched.
2. Build a small TRAIN-only pilot using existing parsed pilot/normal CSVs to validate horizon aggregation logic.
3. Create a new timestamped evidence store version, for example `data/enrichment/evidence_timestamped/train_tti_v1/`, that preserves `bgp_timestamp_utc`, `announcement_or_withdrawal`, `peer_asn`, `prefix`, `origin_asn`, `normalized_as_path`, optional attributes needed by Behavioral features, collector, MRT filename/checksum, and incident UID.
4. Define `observable_onset_utc` per incident from the first relevant RouteViews observation.
5. For each horizon `h in {30, 60, 120, 300}` seconds, aggregate only observations in `[observable_onset_utc, observable_onset_utc + h]`.
6. Recompute the 74 V4 columns with no future observations.
7. Evaluate the frozen Level-1 XGBoost candidate first, reporting that this is a no-retraining partial-horizon robustness/TTI audit.
8. Treat a trained TTI-specific model or causal K1-prefix stacker as a separate future experiment requiring TRAIN-only development and a predeclared evaluation protocol.

## Is Retraining Scientifically Required?

For an initial advisor-facing diagnostic, retraining is not required if the question is: "How does the frozen completed-window Level-1 model behave when only early evidence is provided?"

For a scientifically optimized early-classification system, retraining is likely required because the feature distribution changes materially. Partial windows have lower counts, different rates, more missing ratios, and less stable path/prefix diversity than completed five-minute windows. A retrained model would need TRAIN-only development and should not reuse Validation or Final Holdout for tuning.

## Risks and Limitations

- The current compact evidence store cannot determine whether an observation occurred in the first 30 seconds or the last 30 seconds of a five-minute window.
- Completed-window features would leak future observations into early-horizon claims.
- Rate features need a predeclared denominator policy. Using `/5` preserves frozen-model scale but under-represents elapsed-time intensity; using `/horizon_minutes` creates a materially different representation.
- CAIDA and RPKI temporal alignment must use snapshots available at or before the horizon time.
- Outage BGP-observable onset may lag the documented Cloudflare outage start.
- Incidents with no relevant RouteViews observation near onset cannot receive a defensible TTI from RouteViews alone.
- K1 should remain a final incident-level classifier/ranker unless a causal early-prefix stacker is separately designed and trained.

## Audit Disposition

Disposition: `REVIEW_DESIGN_REQUIRED_BEFORE_TTI_EXECUTION`.

The experiment is feasible, but not from the current compact evidence store alone. The safest next step is to create a versioned timestamped evidence layer or perform a targeted TRAIN-only reparse for a small TTI pilot, then review the observed onset and horizon-feature behavior before any Validation or Holdout access.
"""
    (DOCS / "tti_audit_report_v1.md").write_text(report, encoding="utf-8")


if __name__ == "__main__":
    main()
