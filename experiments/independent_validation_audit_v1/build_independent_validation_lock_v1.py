from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def artifact_entry(name: str, relative_path: str, role: str, artifact_type: str, notes: str = "") -> dict[str, str]:
    path = REPO / relative_path
    entry = {
        "name": name,
        "role": role,
        "artifact_type": artifact_type,
        "relative_path": relative_path,
        "status": "PRESENT" if path.exists() else "MISSING",
        "sha256": sha256(path) if path.exists() and path.is_file() else "",
        "notes": notes,
    }
    return entry


def write(path_name: str, content: str) -> None:
    (OUT / path_name).write_text(content.strip() + "\n", encoding="utf-8")


def roster_rules() -> str:
    return """
# Locked Confirmation Roster Rules v1

STATUS: LOCKED_PENDING_EXECUTION

## Purpose

These rules define how an independent confirmation roster may be constructed before any model scoring occurs. They apply only to the future independent confirmation experiment and do not modify the frozen 1,419-incident Praxis corpus, TRAIN, Validation, Final Holdout, TTI results, prior-shift results, provenance audit, figures, or manuscript text.

## Primary and Secondary Sources

Primary sources:

- Hijack and Leak: RouteLLM verified routing-anomaly benchmark.
- Outage: IODA outage events or curated IODA outage/shutdown records.

Secondary corroboration/adjudication sources:

- MANRS / GRIP.
- Operator writeups and public postmortems, including but not limited to Kentik, ThousandEyes, BGPmon, RIPE Labs, NOG posts, and public ISP reports.

Secondary sources may corroborate, clarify, or adjudicate a candidate event, but they may not weaken the inclusion rules.

## Label Terminology

`SOURCE_LABEL` is the event type or category provided by the independent source before local normalization.

`FINAL_ADJUDICATED_LABEL` is the locked label used for evaluation after source-label review, taxonomy mapping, deduplication, overlap review, and metadata-quality checks.

The pipeline must preserve both fields. A source label may be rejected or marked ambiguous, but it may not be silently overwritten.

## Inclusion Rules

An event may enter the locked confirmation roster only if all conditions hold:

1. The candidate source is not Cloudflare and does not use a Cloudflare event ID as the event definition.
2. The event has a clear `SOURCE_LABEL` that can be mapped to Hijack, Leak, or Outage without using model predictions.
3. A `FINAL_ADJUDICATED_LABEL` is assigned before model scoring.
4. The event has a UTC-normalizable documented start time.
5. The event has either a documented end time, a documented duration, or a predeclared source-specific active-window rule.
6. The affected ASN, network, or operator is available.
7. For Hijack, affected prefix information is required unless an explicit public source shows the event is a path/origin hijack whose affected prefix can be recovered from the independent record.
8. For Leak, leak ASN or leaking AS path segment is required; exact prefixes are preferred but not mandatory if the source provides sufficient ASN/path/time evidence for RouteViews reconstruction.
9. For Outage, the event must be ASN/network scoped or otherwise mappable to RouteViews-observable network reachability. Purely geographic, traffic-only, or platform-only outage annotations are excluded unless an affected ASN/network can be identified.
10. RouteViews evidence must be reconstructable for the event interval.
11. The event must be classified as `NEW_INDEPENDENT_EVENT` after overlap checks against the frozen 1,419-event corpus.
12. The event must pass V4 feature-generation feasibility before scoring.

## Exclusion Rules

Exclude an event before scoring if any condition holds:

- It is a confirmed same real-world event already present in the frozen 1,419-event corpus.
- It lacks a usable start time.
- It lacks required ASN/network metadata.
- It lacks required prefix/path metadata for the class-specific rule.
- It cannot be reconstructed from RouteViews under the frozen acquisition/evidence method.
- The source label is ambiguous and cannot be adjudicated without model predictions.
- The event class would need to be inferred locally from the same variables used as model features.
- The event is only a Cloudflare corroboration of an existing source, rather than a source-separated record.
- Licensing/access restrictions prevent reproducible dissertation use.

## Overlap Rules

Compare each candidate to the existing 1,419-event corpus using:

- candidate source event ID;
- event class;
- start and end time overlap;
- affected ASN(s);
- affected prefix(es);
- affected country/network/operator;
- source description/title;
- public incident report URL;
- RouteViews event signature where available.

Classify overlap as:

- `NEW_INDEPENDENT_EVENT`
- `POSSIBLE_SAME_EVENT`
- `CONFIRMED_SAME_EVENT`
- `REVIEW_REQUIRED`

Only `NEW_INDEPENDENT_EVENT` records may enter the locked evaluation roster.

## Deduplication Rules

If multiple independent sources describe the same real-world event, keep one canonical confirmation event and preserve all corroborating sources in provenance fields. Prefer the record with the strongest source provenance, clearest timing, best ASN/prefix completeness, and most reproducible public evidence.

Do not create multiple confirmation incidents from the same real-world incident unless the source evidence clearly identifies distinct independent events with distinct time windows and affected networks.

## Temporal Eligibility

All event windows must be UTC-normalized before scoring. The incident window must be frozen before model scoring. No event window may be shortened, extended, or reinterpreted after observing model predictions.

For Hijack/Leak, source-reported event-active evidence should be used where available. Silent gaps may be classified according to the frozen incident-window policy, not a post-hoc rule.

For Outage, source-documented outage intervals are eligible when they represent network reachability loss or other RouteViews-observable outage behavior.

## RouteViews Evidence Requirement

Each candidate must have:

- a RouteViews collector/acquisition plan;
- a file availability audit;
- a parsing/reconstruction audit;
- evidence that the event interval can generate frozen V4-compatible features;
- a failure classification if reconstruction is not possible.

Events failing this requirement are not scored and must remain in the failed/excluded incident ledger.

## Ambiguity Handling

Ambiguous events are marked `REVIEW_REQUIRED` and excluded from the locked confirmation roster unless adjudication is completed before scoring. Adjudication may use source documentation, secondary corroboration, metadata completeness, and independent routing evidence, but may not use model predictions.

## Adjudication Procedure

For each candidate:

1. Preserve source-native fields.
2. Map `SOURCE_LABEL` to candidate normalized class.
3. Check metadata completeness.
4. Run overlap/dedup review.
5. Use secondary sources only to corroborate or clarify.
6. Assign `FINAL_ADJUDICATED_LABEL`.
7. Freeze the event roster with checksums.
8. Only then generate features and score.

## One-Time Rule

After the independent confirmation roster is locked, no additional events may be acquired or added except through a separately versioned protocol before any scoring. After scoring begins, no event additions, exclusions, relabeling, or timing edits are allowed except predeclared technical-failure handling.
"""


def model_manifest() -> dict[str, object]:
    artifacts = [
        artifact_entry("level1_ensemble_manifest", "data/tti_pilot/level1_ensemble_manifest_v2.json", "Level-1 ensemble inference manifest", "json"),
        artifact_entry("level1_feature_schema", "data/tti_pilot/reconstructed_level1_v1/feature_schema_v4.json", "Frozen V4 feature order for Level-1", "json"),
        artifact_entry("level1_fold_1_model", "data/tti_pilot/reconstructed_level1_v1/level1_xgb_fold_1_hist_njobs_minus1.joblib", "Level-1 XGBoost fold model", "joblib"),
        artifact_entry("level1_fold_2_model", "data/tti_pilot/reconstructed_level1_v1/level1_xgb_fold_2_hist_njobs_minus1.joblib", "Level-1 XGBoost fold model", "joblib"),
        artifact_entry("level1_fold_3_model", "data/tti_pilot/reconstructed_level1_v1/level1_xgb_fold_3_hist_njobs_minus1.joblib", "Level-1 XGBoost fold model", "joblib"),
        artifact_entry("level1_fold_4_model", "data/tti_pilot/reconstructed_level1_v1/level1_xgb_fold_4_hist_njobs_minus1.joblib", "Level-1 XGBoost fold model", "joblib"),
        artifact_entry("level1_fold_5_model", "data/tti_pilot/reconstructed_level1_v1/level1_xgb_fold_5_hist_njobs_minus1.joblib", "Level-1 XGBoost fold model", "joblib"),
        artifact_entry("level2_xgb_frozen_spec", "config/k1_second_level_xgb_final_v1.yaml", "Level-2 XGBoost frozen specification", "yaml", "Standalone serialized Level-2 binary was not located during this lock audit; this config is the frozen specification artifact visible in the repository."),
        artifact_entry("level2_verification", "data/final_prep/k1_fixed_second_level_verification_v1.csv", "Level-2 fixed deployable verification record", "csv"),
        artifact_entry("behavioral_feature_schema", "config/behavioral_feature_schema_v1.yaml", "Behavioral feature schema", "yaml"),
        artifact_entry("caida_feature_schema", "config/caida_feature_schema_v1.yaml", "CAIDA feature schema", "yaml"),
        artifact_entry("rpki_feature_schema", "config/rpki_feature_schema_v1.yaml", "RPKI/ROV feature schema", "yaml"),
        artifact_entry("v4_train_feature_manifest", "data/train_frozen/frozen_train_v4_behavioral_caida_rpki_audit_v1.csv", "Frozen V4 train schema/audit manifest", "csv"),
        artifact_entry("meta_feature_schema", "config/k1_incident_meta_feature_schema_v1.yaml", "K1 meta-feature schema", "yaml"),
        artifact_entry("final_candidate_config", "config/k1_final_candidate_v1_1_deployable.yaml", "Final deployable K1 candidate config", "yaml"),
        artifact_entry("preprocessing_and_stacking_code", "src/bgp_incident_detection/k1_incident_stacking.py", "Aggregation, meta-feature, imputation, and ranking code", "python"),
        artifact_entry("level1_reconstruction_code", "src/bgp_incident_detection/level1_reconstruction.py", "Level-1 reconstruction logic", "python"),
        artifact_entry("caida_mapping_code", "src/bgp_incident_detection/caida_features.py", "CAIDA feature mapping logic", "python"),
        artifact_entry("rpki_rov_logic", "src/bgp_incident_detection/rpki_features.py", "RPKI/ROV feature logic", "python"),
        artifact_entry("level1_scoring_code", "src/bgp_incident_detection/tti_level1_scoring.py", "Level-1 scoring and class ranking code", "python"),
    ]
    return {
        "status": "LOCKED_PENDING_EXECUTION",
        "lock_scope": "independent_validation_pre_evaluation_model_artifacts",
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "non_destructive": True,
        "model_scoring_performed": False,
        "validation_accessed": False,
        "final_holdout_accessed": False,
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
    }


def lock_doc(timestamp: str, manifest_sha: str) -> str:
    return f"""
STATUS: LOCKED_PENDING_EXECUTION
LOCK_TIMESTAMP_UTC: {timestamp}

# Independent Validation Lock v1

## Non-Destructive Boundary

This lock package freezes the protocol for a future independent confirmation evaluation. It does not execute model scoring on RouteLLM, IODA, MANRS, GRIP, operator writeups, or any other new confirmation incident. It does not modify frozen TRAIN, Validation, Final Holdout, TTI, provenance, prior-shift, model, figure, table, or manuscript artifacts. The existing Final Holdout remains untouched and authoritative.

## Confirmation-Set Rules

Primary candidate sources are:

- RouteLLM for Hijack and Leak.
- IODA for Outage.

Secondary corroboration/adjudication sources are:

- MANRS / GRIP.
- Operator writeups and public postmortems.

The complete locked roster rules are in `locked_confirmation_roster_rules_v1.md`. The central rule is that every event must preserve both `SOURCE_LABEL` and `FINAL_ADJUDICATED_LABEL`. The source label records what the independent provider reported; the final adjudicated label is the locked normalized label used for evaluation after metadata, taxonomy, overlap, and ambiguity review.

Only `NEW_INDEPENDENT_EVENT` records that satisfy the locked inclusion criteria may enter the future confirmation roster.

## H1: Independent Classification and Ranking Performance

**Primary test.** Evaluate the frozen final architecture on the locked independent confirmation incidents.

**Primary metric.** Incident-level Macro F1.

**Comparator/baseline.** Practical confirmation floor rather than a model-selection comparator. The floor is defined before observing independent confirmation results.

**Practical acceptance criterion.**

- Macro F1 point estimate >= 0.70.
- Incident-level bootstrap 95% CI lower bound >= 0.60.
- Top-2 accuracy >= 0.85.

This benchmark is scientifically defensible because it is substantially above the balanced three-class chance baseline, preserves ranking performance as a required operational property, and allows realistic degradation under source-separated labels without weakening the original terminal Final Holdout result.

**Secondary metrics.**

- Per-class precision/recall/F1.
- Top-1 accuracy.
- Top-2 accuracy.
- MRR.
- Confusion matrix.

**Decision rule.**

- `SUPPORTED`: Macro F1 point estimate and CI lower bound pass, and Top-2 passes.
- `SUPPORTED_WITH_CAVEAT`: point estimate passes but CI, class-specific results, or source-specific results require review.
- `NOT_SUPPORTED`: Macro F1 point estimate or Top-2 falls below the predeclared floor.

## H2: Behavioral-Only vs Behavioral + CAIDA + RPKI/ROV

**Comparison.** Behavioral-only versus full V4 Behavioral + CAIDA + RPKI/ROV on exactly the same independent incidents.

**Primary metric.** Incident-level Macro F1.

**Definition.** `Delta_H2 = MacroF1_combined - MacroF1_behavioral`.

**Statistical procedure.**

- Paired incident-level bootstrap.
- 10,000 iterations.
- Random seed: 20260914.
- 95% percentile confidence interval.

**Supported rule.** H2 is supported if `Delta_H2 >= 0.03` and the 95% CI does not show a clear negative effect. H2 is not supported if the point estimate is below +0.03 or the paired interval indicates material degradation.

**Execution gate.** H2 may be executed only if a Behavioral-only comparator is frozen or equivalently reconstructable before independent confirmation scoring. Feature importance is not the primary H2 test.

## H3: Mean Aggregation vs Retrospective Temporal Stacker

**Comparison.** Mean Level-1 aggregation versus the existing frozen K1 temporal stacker on exactly the same independent incidents.

**Primary metric.** Incident-level Macro F1.

**Definition.** `Delta_H3 = MacroF1_stacker - MacroF1_mean`.

**Statistical procedure.**

- Paired incident-level bootstrap.
- 10,000 iterations.
- Random seed: 20260914.
- 95% percentile confidence interval.

**Supported rule.** H3 is supported if `Delta_H3 >= 0.03` and the 95% CI does not show a clear negative effect. Secondary support may be noted if MRR improves by at least +0.02 without severe class-specific regression.

**Interpretation boundary.** The temporal stacker has been classified as `RETROSPECTIVE`. H3 is therefore a test of retrospective incident-level temporal aggregation. It must not be presented as live/prospective classification or operational TTI.

## Simple Baselines Frozen for Reporting

The following baselines are frozen now and may not be expanded after results are observed:

1. Majority-class baseline calculated on the locked independent confirmation roster.
2. Behavioral-only classifier, only if frozen/reconstructable before scoring.
3. Mean Level-1 aggregation using the frozen Level-1 probabilities.
4. Simple RPKI/origin-mismatch rule where scientifically applicable, limited to Hijack-oriented diagnostic reporting and not a replacement for multiclass evaluation.
5. Valley-free/relationship rule where scientifically applicable, limited to Leak-oriented diagnostic reporting and not a replacement for multiclass evaluation.

Rule-based baselines must be reported as diagnostic baselines only when the required inputs exist and the rule is meaningful for the relevant class.

## Bootstrap and Statistical Rules

- Resampling unit: independent incident.
- Iterations: 10,000.
- Seed: 20260914.
- Interval type: percentile 95% CI.
- H2/H3: paired incident-level resampling over exactly the same incident IDs.
- Class stratification: no stratification for the primary bootstrap unless the locked cohort design explicitly freezes a balanced diagnostic subset before scoring. Report class counts and use incident-level resampling.
- Non-evaluable incidents: keep in the failed/excluded incident ledger; exclude from metric denominators only if they meet predeclared failure categories before scoring.
- Missing features: apply the frozen V4 missing-value policy; incompatibilities are `EXCLUDED_V4_COMPATIBILITY_FAILURE` before scoring.

The bootstrap/statistical procedure is identical for H2 and H3.

## Frozen Model and Schema Artifacts

The model lock manifest is `independent_validation_model_lock_manifest_v1.json`.

Manifest SHA-256 at lock creation:

`{manifest_sha}`

The manifest includes checksums for Level-1 model artifacts, the Level-2 frozen specification/verification artifacts, Behavioral/CAIDA/RPKI/V4/meta schemas, preprocessing and aggregation code, CAIDA mapping logic, RPKI/ROV logic, and scoring/ranking code.

No artifact listed in the manifest may change after this lock without creating a new protocol version before scoring.

## Evaluation Outputs Frozen for Future Execution

When the future evaluation is executed, produce exactly these output classes:

- incident-level predictions;
- Hijack/Leak/Outage scores;
- Top-1 prediction;
- Top-2 membership;
- true-class rank;
- confusion matrices;
- per-class precision/recall/F1;
- incident Macro F1;
- MRR;
- H2 paired difference and CI;
- H3 paired difference and CI;
- failed/excluded incident ledger;
- source-specific performance;
- date/temporal breakdown where sample size permits.

No additional primary metrics or baselines may be introduced after observing results.

## Exclusions

The only allowed exclusion categories are:

- `EXCLUDED_OVERLAPS_EXISTING_CORPUS`
- `EXCLUDED_MISSING_TIME`
- `EXCLUDED_MISSING_ASN_OR_PREFIX`
- `EXCLUDED_ROUTEVIEWS_RECONSTRUCTION_FAILURE`
- `EXCLUDED_V4_COMPATIBILITY_FAILURE`
- `EXCLUDED_LABEL_AMBIGUITY`
- `EXCLUDED_LICENSE_OR_ACCESS_RESTRICTION`
- `REVIEW_REQUIRED`

Exclusions must be assigned before prediction review.

## Interpretation Boundaries

The following limitations are preregistered:

- Independent labels come from heterogeneous sources rather than one common source.
- RouteLLM is treated as a preprint unless its publication status is updated and documented before scoring.
- IODA Outage semantics may not exactly equal BGP-originated Outage.
- Public RouteViews visibility differs from enterprise-local telemetry.
- Level-2 temporal stacking is retrospective.
- The test does not establish enterprise deployment performance.
- The test evaluates source-separated generalization, not universal Internet prevalence.
- Confirmation results do not replace the existing one-time Final Holdout result.

## One-Time Execution Rule

The future independent confirmation set may be scored once after roster, features, artifacts, and this protocol are frozen. After results are observed, no event additions, event exclusions, label changes, time-window changes, model changes, feature changes, baseline additions, or metric changes may be made and presented as confirmatory.

## Stop Condition

This lock package stops before event acquisition beyond the locked rules and before any model scoring. The next permissible step is event-roster construction strictly under `locked_confirmation_roster_rules_v1.md`, not model evaluation.
"""


def main() -> None:
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    write("locked_confirmation_roster_rules_v1.md", roster_rules())
    manifest = model_manifest()
    manifest_path = OUT / "independent_validation_model_lock_manifest_v1.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    manifest_sha = sha256(manifest_path)
    write("INDEPENDENT_VALIDATION_LOCK_v1.md", lock_doc(timestamp, manifest_sha))
    lock_sha = sha256(OUT / "INDEPENDENT_VALIDATION_LOCK_v1.md")
    (OUT / "INDEPENDENT_VALIDATION_LOCK_v1.sha256").write_text(
        f"{lock_sha}  INDEPENDENT_VALIDATION_LOCK_v1.md\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
