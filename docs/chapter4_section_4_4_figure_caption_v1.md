# Section 4.4 Figure Caption v1

## Figure 4.x Incident Imbalance and Weighting Results

This figure compares the three predeclared TRAIN-only imbalance strategies: I0, I1, and I2. I0 used the natural five-minute window representation without incident-aware weighting or temporal capping. I1 retained all available windows but applied incident-aware weighting so that each incident contributed approximately equal aggregate training influence. I2 added the same incident-aware weighting but capped long incidents at 164 five-minute windows. The primary comparison metric is incident-level Macro F1 from grouped cross-validation; Top-2 and MRR are shown because they were consistently recorded for all three strategies.

I1 is highlighted as the selected strategy, not because it maximized every metric, but because the recorded decision states: "Incident is the independent unit; weighting reduces long-incident dominance without data removal." The recorded supporting evidence was: "Phase B: I1 improved group-level behavior while preserving all observations." The p95 cap audit context is: 32956 windows removed from capped RF_HIER_STAGE2 over-cap groups across folds (50.118620% of those groups' original rows).

Evidence boundary: this figure uses existing TRAIN-only artifacts only. No model was retrained. Validation was not accessed or recomputed. Final Holdout was not accessed or recomputed.

Sources:

- `data/modeling/imbalance_strategy_model_comparison_v1.csv`
- `data/modeling/p95_temporal_sampling_audit_v1.csv`
- `data/modeling/experiment_decision_ledger_v1.csv`
