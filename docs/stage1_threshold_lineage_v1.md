# Stage 1 Threshold Lineage v1

Stage 1 tau was intended for the experimental NORMAL-vs-INCIDENT gate: classify a five-minute window as NORMAL when `P(NORMAL) >= tau`, otherwise INCIDENT.

It was never part of Stage 2 Hijack/Leak/Outage classification. The final K1 primary system performs multiclass incident classification/ranking with `P(Hijack)`, `P(Leak)`, and `P(Outage)`.

Authoritative Phase E recovered values:

- TRAIN-CV proposed tau: `0.06`
- fold thresholds: `[0.06, 0.62, 0.32, 0.32, 0.45]`
- ROC-AUC: `0.696260`
- NORMAL PR-AUC: `0.014019`
- NORMAL precision/recall/F1: `0.036036` / `0.007752` / `0.012759`
- INCIDENT recall: `0.998427`
- false-NORMAL incident rate: `0.001573`

Phase E2 W1 class/group weighting:

- proposed W1 tau: `0.72`
- fold thresholds: `[0.72, 0.73, 0.73, 0.73, 0.72]`
- ROC-AUC: `0.758050`
- NORMAL PR-AUC: `0.016167`
- false-NORMAL incident rate: `0.265188`

The issue was not simply threshold selection. The probability distributions lacked sufficient NORMAL/INCIDENT discrimination: ROC-AUC improved under W1, but NORMAL PR-AUC stayed very weak and false-NORMAL incident risk remained too high.

An earlier tau chosen using Holdout performance is treated as `THRESHOLD_SELECTION_LEAKAGE_RISK`. The corrected methodology derived threshold candidates with TRAIN grouped CV only. Since Stage 1 remained unresolved, no Stage 1 tau entered the final K1 production architecture.

Final status: `UNRESOLVED_EXPERIMENTAL_AUXILIARY`.

`tau_threshold_used_in_final_k1 = NO`
