# Frozen Protocol v1: Retrospective Early-Classification / RouteViews-Observable Checkpoint TTI

Status: FROZEN FOR INDEPENDENT CONFIRMATION

This protocol freezes the retrospective early-classification / Time-to-Identify (TTI) methodology before any Validation TTI data are accessed. It is an additive TRAIN-only experimental protocol and does not modify the primary Praxis architecture, Final Holdout results, model artifacts, or manuscript conclusions.

## Absolute Preservation Requirements

- Validation TTI data must not be accessed until this protocol is frozen.
- Final Holdout must remain untouched by the TTI experiment.
- No model retraining, tuning, calibration, threshold selection, optimization, or modification is permitted.
- No additional TRAIN tuning or methodology change is permitted after the completed TRAIN TTI results.
- No methodology, model, feature, horizon, onset, exclusion criterion, metric, or interpretation rule may be changed after observing Validation TTI results.
- Existing authoritative Final Holdout results remain immutable: Macro F1 = 0.920177; Top-2 = 0.990610; MRR = 0.958529.

## Analysis Label

`RETROSPECTIVE EARLY-CLASSIFICATION / ROUTEVIEWS-OBSERVABLE CHECKPOINT TTI`

This analysis is explicitly distinct from:

- the 25.58 ms downstream computational latency benchmark;
- live enterprise operational TTI;
- the complete Level-1 + Level-2 temporal-stacking final Praxis architecture.

## Research Population

- Original TRAIN corpus: 993 incidents.
- TRAIN TTI-evaluable cohort: 983 incidents.
- TTI-evaluable class counts: 327 Hijack / 329 Leak / 327 Outage.
- Excluded from TTI denominators:
  - 9 incidents excluded because of insufficient RouteViews evidence.
  - 1 incident excluded because a valid onset could not be established.
- Excluded incidents remain preserved in the original 993-incident TRAIN corpus and are not relabeled or removed from the primary experiment.

## Observable-Onset Definition

`FIRST_POST_DOCUMENTED_EVENT_EVIDENCE`

Definition: the first incident-relevant RouteViews observation at or after the independently documented incident start.

This onset rule is frozen. Do not redefine onset after observing Validation TTI predictions.

## Observation Checkpoints

The cumulative observation horizons are fixed as:

- 30 seconds
- 60 seconds
- 120 seconds
- 300 seconds

Each checkpoint uses only BGP evidence observable at or before the selected onset plus the checkpoint duration. Do not interpolate between checkpoints.

## Feature Representation

Frozen V4 representation, exactly 74 features:

- 44 Behavioral features
- 14 historical CAIDA AS-relationship features
- 16 historical RPKI/ROV features

Feature names, ordering, historical snapshot mapping, missing-value behavior, and feature definitions are frozen. The v2.1 compatibility gate requires 74/74 feature compatibility PASS and 3,932/3,932 horizon leakage assertions PASS.

## Classifier

The classifier is the verified reconstructed five-model Level-1 XGBoost ensemble.

- The ensemble has exact probability equivalence to the preserved original TRAIN fingerprint.
- Class order is fixed as: Hijack, Leak, Outage.
- Inference uses arithmetic mean class probability across the five reconstructed fold-specific Level-1 models.
- Multiclass probability ordering is used directly.
- No manual classification threshold is permitted.
- No retraining, tuning, calibration, threshold selection, or model modification is permitted.

## Primary Early-Classification Metrics

At each checkpoint report:

- Macro F1
- Top-1 accuracy
- Top-2 accuracy
- MRR
- per-class precision / recall / F1
- confusion matrix
- 95% incident-level bootstrap confidence interval for Macro F1

The sample unit for uncertainty is the incident, not a five-minute or partial-horizon row.

## TTI Definitions

`Top1_TTI_checkpoint` = earliest evaluated checkpoint where Top-1 equals the true class.

`Top2_TTI_checkpoint` = earliest evaluated checkpoint where the true class appears within the Top-2 ranking.

Allowed outcomes:

- <=30s
- <=60s
- <=120s
- <=300s
- NOT_IDENTIFIED_WITHIN_300S

Do not interpolate between checkpoints. A checkpoint result such as `<=60s` means the first tested checkpoint at which the condition held was 60 seconds or earlier; it is not an exact continuous-time identification claim.

## Prediction-Stability Definition

`stable_correct_checkpoint` = earliest evaluated checkpoint from which Top-1 remains correct through all later tested checkpoints.

This is a descriptive stability metric only. Do not rename it TSCC in the manuscript.

Also preserve and report cases where:

- Top-1 changes from correct to incorrect;
- Top-2 changes from correct to incorrect;
- true-class probability confidence decreases with additional evidence;
- maximum class-probability confidence decreases with additional evidence.

These are valid experimental findings and must not be removed.

## Independent Confirmation Rule

The exact same frozen methodology may subsequently be applied to Validation as a one-time independent TTI confirmation.

After Validation TTI results are observed, do not change any of the following:

- methodology;
- model;
- feature definitions or order;
- observation horizons;
- onset definition;
- exclusion criteria;
- metrics;
- bootstrap confidence interval procedure;
- prediction-stability definitions;
- interpretation rules.

Final Holdout remains sealed and is not part of the TTI experiment.

## Frozen TRAIN Reference Results

| Horizon | Macro F1 | Top-1 | Top-2 | MRR |
|---:|---:|---:|---:|---:|
| 30s | 0.790817 | 0.790437 | 0.932859 | 0.884028 |
| 60s | 0.843014 | 0.842319 | 0.953204 | 0.913360 |
| 120s | 0.873308 | 0.872838 | 0.973550 | 0.932011 |
| 300s | 0.898440 | 0.898271 | 0.972533 | 0.944557 |

TRAIN checkpoint reference:

- Top-1 correct by <=300s: 910/983 = 92.574%.
- Top-2 correct by <=300s: 965/983 = 98.169%.
- Stable Top-1 from <=30s: 748.
- First stably correct <=60s: 56.
- First stably correct <=120s: 42.
- First stably correct <=300s: 37.
- Never stably correct within tested horizon: 100.
- Correct Top-1 then later incorrect: 39.

## Frozen Artifact Inputs

The protocol manifest records SHA-256 checksums for:

- this frozen protocol document;
- V4 feature schema;
- reconstructed Level-1 ensemble manifest;
- TRAIN TTI-evaluable cohort;
- v2.1 feature gate;
- v2.1 compatibility and leakage artifacts;
- v2.1 V4 feature corpus;
- TRAIN scoring summary and metric artifacts;
- reconstructed model checksums.

## Disposition

`TTI_PROTOCOL_FROZEN_FOR_INDEPENDENT_CONFIRMATION`
