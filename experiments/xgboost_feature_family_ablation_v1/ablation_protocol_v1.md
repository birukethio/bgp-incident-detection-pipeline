# Controlled XGBoost Feature-Family Ablation Protocol v1

Status: predeclared before execution.

Label: **POST-FEEDBACK SUPPLEMENTARY TRAIN-ONLY XGBOOST ABLATION EXPERIMENT**

## Inputs

- TRAIN only: 993 incidents and 68,031 five-minute windows.
- Classes and order: `HIJACK`, `LEAK`, `OUTAGE`.
- Frozen V4 schema: 44 Behavioral + 14 CAIDA + 16 RPKI/ROV features.
- Frozen five-fold incident-grouped assignments.
- Refined Level-1 XGBoost candidate `PHASEI2_XGB_LOCAL_004`.
- Seeds: 20260828, 20260829, 20260830, 20260831, 20260901.
- Median imputation fitted within each training fold.
- I1 sample weight: inverse number of training-fold windows for each incident.
- Incident inference: arithmetic mean of held-out window class probabilities.

## Configurations

1. `full_v4`: all 74 features.
2. `minus_caida`: 44 Behavioral + 16 RPKI/ROV features (60).
3. `minus_rpki`: 44 Behavioral + 14 CAIDA features (58).
4. `minus_behavioral`: 14 CAIDA + 16 RPKI/ROV features (30).
5. `behavioral_only`: 44 Behavioral features.

All subsets are selected directly from the same frozen V4 TRAIN Parquet. No historical V1-V3 matrix is loaded.

## Baseline Gate

The full V4 configuration is run first. Each seed's reproduced incident metrics are compared with `data/modeling/xgb_multiseed_seed_results_v2.csv`. Metric tolerance is `1e-12`. Principal-seed window probabilities are additionally compared with `data/modeling_k1/k1_window_oof_probabilities_v1.parquet`; required maximum absolute probability difference is `1e-6` and predicted-class agreement is `1.0`. Other seeds have metric references but no preserved historical probability rows. Ablations may run only after this gate passes.

## Statistical Protocol

- Primary endpoint: incident-level Macro F1.
- Contrast: `Full V4 - ablated configuration`.
- Resampling unit: incident, not five-minute window.
- Resamples: 2,000.
- Bootstrap seed: 20260828.
- Identical sampled incident indices are used for all configurations and seeds.
- Within each replicate, the paired Macro-F1 difference is calculated for each seed and averaged across the five fixed seeds.
- Interval: 2.5th and 97.5th percentiles of the paired difference distribution.
- Comparisons are exploratory. No confirmatory p-values or Holm-adjusted tests are performed.

## Protection Rules

Validation and Final Holdout files are prohibited inputs. Existing research artifacts, models, manuscript files, and results are not modified or overwritten. Outputs are confined to this versioned directory. No Git commit or push is part of this execution.
