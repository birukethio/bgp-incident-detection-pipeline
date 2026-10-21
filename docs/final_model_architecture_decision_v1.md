# Final Model Architecture Decision v1

## Scope

Phase G is a planning and protocol-freeze step. It does not rerun experiments, access Validation, access Final Holdout, tune thresholds, or alter labels/features.

## Selected Primary Task

Given BGP behavior associated with an incident, classify and rank Hijack, Leak, and Outage.

## Selected Architecture

`RF_LOCK_CANDIDATE_V1` uses a multiclass Random Forest for the Stage 2 incident task:

- Feature variant: V4
- Feature count: 74 = 44 Behavioral + 14 CAIDA + 16 RPKI
- Imbalance treatment: I1 incident-aware weighting
- Probability output: P(Hijack), P(Leak), P(Outage)
- Ranking rule: sort class probabilities descending
- Incident-level aggregation: mean class probability across all eligible windows for the incident

TRAIN evidence for the selected candidate:

- Incident Macro F1: 0.742814
- Incident Top-1: 0.751259
- Incident Top-2: 0.931521
- Incident MRR: 0.864216

## Negative Architecture Experiments

F0 full-V4 one-vs-rest experts and F1 domain-informed experts are retained as useful negative experiments. F0 slightly improved window Macro F1, but S2_BASE retained stronger incident Macro F1 and best incident MRR. F1 feature restriction degraded performance. The expert design also tripled model count from 5 fold models to 15 fold/expert models.

## Stage 1 Status

`STAGE1_STATUS = UNRESOLVED_EXPERIMENTAL_AUXILIARY`.

Stage 1 Normal-vs-Incident detection is documented as an important negative result and limitation. Trustworthy Normal labels were constructed conservatively, only 516 Normal windows qualified, and probability separation remained weak. Threshold optimization, calibration, and W1 class/group balancing did not produce a reliable hard gate. Therefore Stage 1 is excluded as a mandatory final hard gate for the locked primary incident evaluation.

Potential future work includes a broader Normal corpus, anomaly detection, one-class or semi-supervised learning, temporal sequence modeling, and external Normal datasets. None of that is implemented in Phase G.

## Validation Protocol

The next controlled step is exactly one Validation confirmation of the predeclared V4 + I1 + multiclass Stage 2 candidate. Validation is not a leaderboard. If Validation performs poorly, the result must be recorded and any further development must return to TRAIN in a new explicitly versioned cycle while Final Holdout remains sealed.
