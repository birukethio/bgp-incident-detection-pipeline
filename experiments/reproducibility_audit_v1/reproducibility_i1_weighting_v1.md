# I1 Incident Aware Weighting Reproducibility v1

## Formula

`I1` retains all eligible windows and assigns each training row a sample weight of `1 / n_i`, where `n_i` is the number of eligible windows for the same incident or model group on the training side of the current fold. The aggregate influence of an incident is therefore approximately one unit regardless of how many windows it contributes.

## Worked Example

If Incident A contributes 4 windows, each window receives weight 0.25, for an aggregate weight of 1.0. If Incident B contributes 200 windows, each window receives weight 0.005, also totaling 1.0. The calculation is performed within training folds only, so held-out incidents do not influence fitted weights.

## Evidence

The recovered Level-1 training specification cites `src/bgp_incident_detection/imbalance_model_experiment.py` and `data/modeling/xgboost_weight_semantics_audit_v1.csv`. The corpus balancing audit also records the same formula.
