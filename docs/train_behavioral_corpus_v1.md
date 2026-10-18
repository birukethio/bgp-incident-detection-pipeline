# TRAIN Behavioral Corpus v1

This document freezes the resolved TRAIN behavioral baseline before CAIDA/RPKI enrichment or modeling.

Pipeline:

993 independent TRAIN incidents -> RouteViews MRT UPDATE data -> prefix-level observations -> incident-relevant filtering -> non-overlapping 5-minute windows -> 44 behavioral features -> 68,031 behavioral feature rows.

Definitions:

- Incident = independent experimental unit.
- 5-minute window = ML analytical observation.
- One window = one feature row.
- UPDATE volume affects feature values, not row count.
- Zero-observation windows are preserved when source data coverage exists.
- Missing source data is not interpreted as zero activity.
- No imbalance correction is baked into the frozen corpus.

Frozen artifact:

- `data/train_frozen/frozen_train_behavioral_corpus_v1.parquet`

Scope:

- TRAIN only.
- 331 Hijack, 331 Leak, and 331 Outage incidents.
- Validation and Final Holdout remain untouched.
- CAIDA AS-relationship features are not present.
- RPKI/ROV features are not present.
- Weights and window caps are documented as future modeling configurations only.
