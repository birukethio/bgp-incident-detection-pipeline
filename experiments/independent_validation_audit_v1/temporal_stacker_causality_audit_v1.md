# Temporal Stacker Causality Audit v1

## Question

Can the final K1 temporal stacker be interpreted as a causal/prospective early detector, or should it be evaluated as a retrospective/post-window incident classifier?

## Evidence Inspected

- `config/k1_incident_meta_feature_schema_v1.yaml`
- `config/k1_second_level_xgb_final_v1.yaml`
- `src/bgp_incident_detection/k1_incident_stacking.py`
- `src/bgp_incident_detection/k1_forensic_audit.py`

## Temporal Feature Construction

The K1 incident meta-feature schema uses deterministic chronological equal-count segmentation into EARLY, MIDDLE, and LATE thirds. The implementation sorts the complete window group by `window_start`, then computes:

- all-window mean class probabilities;
- probability quantiles;
- top-class proportions;
- EARLY/MIDDLE/LATE segment probability means;
- late-minus-early probability changes;
- linear probability slopes over the full incident sequence;
- observed temporal span from minimum `window_start` to maximum `window_end`.

These features require the complete eligible incident window sequence. The LATE segment, late-minus-early features, full-sequence slopes, and final observed temporal span cannot be known at the beginning or middle of a live event.

## Causality Classification

`RETROSPECTIVE`

The final K1 temporal stacker is a retrospective/post-window incident classifier and ranking model. It is appropriate for classifying an incident after the configured observation window has been assembled. It should not be described as a live causal detector or as the model responsible for sub-five-minute TTI.

## Consequence for Independent Confirmation

An independent confirmation set may evaluate K1 as a retrospective incident-classification system using complete eligible incident windows. That would be consistent with the final Praxis architecture and Final Holdout evaluation.

If the research question is prospective operational detection, a separate causal/online experiment is required. That experiment should use only evidence available up to each decision time and should not use K1's LATE-segment or full-sequence meta-features.

## Relationship to TTI

The existing TTI work correctly separates early-horizon evaluation from the final K1 architecture by using the verified Level-1 XGBoost ensemble only. This separation should be preserved in dissertation language:

- Final K1: retrospective/post-window incident classification and ranking.
- TTI: retrospective early-classification sensitivity using partial RouteViews evidence and Level-1 only.

## Disposition

The stacker is valid for the final retrospective architecture but not causal/prospective without redesign. Future independent confirmation should report this explicitly.
