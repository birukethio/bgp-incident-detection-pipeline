# Normal Ground-Truth Methodology v1

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
