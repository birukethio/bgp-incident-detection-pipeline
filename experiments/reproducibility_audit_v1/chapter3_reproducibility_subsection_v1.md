# Chapter 3 Reproducibility Subsection Draft v1

## Proposed insertion location

Insert near the end of Chapter 3 after the model architecture and evaluation protocol sections, before the transition to Chapter 4.

## Draft text

The final experiment was frozen as an incident-level supervised classification and ranking pipeline. The authoritative corpus contains 1,419 externally labeled BGP incidents balanced to 473 Hijack, 473 Leak, and 473 Outage cases. Incidents, not windows, are the independent experimental unit. The frozen v2 split assigns 993 incidents to TRAIN, 213 to Validation, and 213 to Final Holdout, with no incident UID overlap across partitions. Five-minute RouteViews UPDATE windows inherit the incident partition and label. The feature representation is V4, consisting of 74 frozen features: 44 behavioral BGP features, 14 historical CAIDA AS-relationship features, and 16 historical RPKI/ROV features. TRAIN development used I1 incident-aware sample weighting so that incidents with many five-minute windows did not dominate model fitting. The final architecture uses a five-model cross-fit Level-1 XGBoost ensemble followed by a Level-2 XGBoost temporal stacker that summarizes window-level class scores at the incident level. Evaluation reports incident-level Macro F1, Top-1, Top-2, MRR, per-class precision, recall, and F1. The terminal Final Holdout was evaluated once after model freeze; it remains immutable and is not used for model selection or further tuning. Separate post-hoc audits document corpus balancing, label provenance, partition independence, calibration terminology, and the Hijack:68538 quality-gate caveat.
