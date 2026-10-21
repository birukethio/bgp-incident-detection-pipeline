STATUS: LOCKED_PENDING_EXECUTION
LOCK_TIMESTAMP_UTC: 2026-09-14T19:52:59+00:00

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

`1cee5b9f42411222d932e26142e77c2dfebaa04cd37108a54824605078ab96ee`

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
