# Master Praxis Experimental Record v1

Praxis title: An Artificial Intelligence–Based Classification and Ranking System for Border Gateway Protocol Incidents in Enterprise Networks

This record is an index and dissertation handoff. It reads existing authoritative artifacts and does not train, tune, recompute Validation, or recompute Final Holdout.

## Terminal Result
- Final Holdout incidents: 213 with 71/71/71 class balance.
- Final Holdout window rows: 14906.
- V4 features: 74 = 44 Behavioral + 14 CAIDA + 16 RPKI/ROV.
- Incident Macro F1: 0.920177 with 95% CI [0.880117, 0.954402].
- Top-1: 0.920188; Top-2: 0.990610; MRR: 0.958529.
- Hijack F1: 0.877698; Leak F1: 0.904110; Outage F1: 0.978723.
- True class rank counts: rank 1 = 196, rank 2 = 15, rank 3 = 2.
- Second-level hash: 40df040321ef.

## Phase Progression
- P0 Incident roster and v2 partitions: Use v2 as authoritative corpus (AUTHORITATIVE_CURRENT).
- P1 RouteViews acquisition and processing: Proceed to frozen behavioral corpus (AUTHORITATIVE_CURRENT).
- P2 Behavioral feature corpus: Use as base feature family (AUTHORITATIVE_CURRENT).
- P3 Normal ground-truth development: Keep Stage 1 auxiliary (AUTHORITATIVE_CURRENT).
- P4 CAIDA enrichment: Retain CAIDA in V4 (AUTHORITATIVE_CURRENT).
- P5 RPKI/ROV enrichment: Retain RPKI in V4 (AUTHORITATIVE_CURRENT).
- P6 Feature variants: Use V4 for later models (AUTHORITATIVE_CURRENT).
- P7 Imbalance strategies: Carry I1 forward (AUTHORITATIVE_CURRENT).
- P8 Baseline modeling: Proceed to enrichment/imbalance (HISTORICAL_EXPERIMENT).
- P9 Stage 1 experiments: Keep Stage 1 auxiliary (HISTORICAL_EXPERIMENT).
- P10 Domain-expert architecture: KEEP_MULTICLASS_STAGE2 (HISTORICAL_EXPERIMENT).
- P11 Random Forest optimization: PROMOTE_PHASE_H2_RF as RF benchmark (HISTORICAL_EXPERIMENT).
- P12 XGBoost comparison/refinement: PROMOTE_PHASE_I2_XGB (AUTHORITATIVE_CURRENT).
- P13 Phase J Validation: VALIDATION_CONFIRMATION_PASS (AUTHORITATIVE_CURRENT).
- P14 K1 incident-level stacking: CARRY_XGB_INCIDENT_STACKER (AUTHORITATIVE_CURRENT).
- P15 K2 forensic verification: K1_GAIN_CONFIRMED (AUTHORITATIVE_CURRENT).
- P16 K2.5 architecture comparator: KEEP_XGB_XGB_K1 (AUTHORITATIVE_CURRENT).
- P17 L0 deployable freeze: READY_FOR_PHASE_L (AUTHORITATIVE_CURRENT).
- P18 Final Holdout: FINAL_HOLDOUT_EVALUATED_NO_FURTHER_TUNING (AUTHORITATIVE_CURRENT).
