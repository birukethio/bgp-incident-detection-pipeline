# Controlled XGBoost Feature-Family Ablation Final Report v1

**POST-FEEDBACK SUPPLEMENTARY TRAIN-ONLY XGBOOST ABLATION EXPERIMENT**

## Scope and Protection

The experiment used only the frozen TRAIN corpus: 993 incidents, 331 per class, and 68,031 five-minute windows. It did not access Validation or Final Holdout and did not modify any historical artifact, model, manuscript file, or reported Praxis result. No hyperparameter or feature-definition tuning was performed. No Git commit or push was performed.

## A. Baseline Reproduction

The refined Full V4 candidate was reproduced before executing any ablation. All five seed-specific metrics matched the historical records within the predeclared `1e-12` tolerance. The principal seed also reproduced all 68,031 preserved historical window probabilities exactly.

| Seed | Historical Macro F1 | Reproduced Macro F1 | Difference | Probability comparison |
|---:|---:|---:|---:|---|
| 20260828 | 0.802937 | 0.802937 | 0.000000 | max absolute difference 0.0; class agreement 1.0 |
| 20260829 | 0.804194 | 0.804194 | 0.000000 | historical probability rows not preserved |
| 20260830 | 0.805328 | 0.805328 | 0.000000 | historical probability rows not preserved |
| 20260831 | 0.807431 | 0.807431 | 0.000000 | historical probability rows not preserved |
| 20260901 | 0.808497 | 0.808497 | 0.000000 | historical probability rows not preserved |
| **Five-seed mean** | **0.805678** | **0.805678** | **0.000000** | **PASS** |

The other six recorded metrics for every seed also passed. See `baseline_reproduction_gate_v1.csv` for the complete comparison.

## B. Feature-Ablation Results

Values are means across the five fixed XGBoost seeds. Seed standard deviations are retained in `xgb_ablation_summary_metrics_v1.csv`.

| Configuration | Features | Macro F1 | Hijack F1 | Leak F1 | Outage F1 | Top-1 | Top-2 | MRR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Full V4 | 74 | **0.805678** | **0.756196** | 0.851923 | **0.808913** | **0.807049** | 0.934743 | **0.892649** |
| V4 minus CAIDA | 60 | 0.798148 | 0.746929 | 0.842306 | 0.805209 | 0.799799 | 0.930111 | 0.888251 |
| V4 minus RPKI/ROV | 58 | 0.796178 | 0.736844 | **0.852001** | 0.799689 | 0.797986 | **0.934945** | 0.888150 |
| V4 minus Behavioral | 30 | 0.761936 | 0.685420 | 0.813813 | 0.786576 | 0.766365 | 0.929909 | 0.871501 |
| Behavioral only | 44 | 0.785825 | 0.723469 | 0.841606 | 0.792400 | 0.788117 | 0.932528 | 0.882813 |

Full V4 produced the highest Macro F1, Top-1, MRR, Hijack F1, and Outage F1. The RPKI-removed configuration produced a slightly higher Leak F1 and Top-2; these secondary metric differences do not change the predeclared Macro-F1 endpoint.

## C. Paired Comparisons

The same 993 incident indices were resampled for Full V4 and each ablation. Each bootstrap replicate calculated the paired Macro-F1 difference for each seed and then averaged the five seed-specific differences.

| Comparison: Full V4 minus... | Delta Macro F1 | Paired bootstrap 95% CI |
|---|---:|---:|
| V4 minus CAIDA | +0.007530 | [-0.002620, 0.017394] |
| V4 minus RPKI/ROV | +0.009500 | [-0.000987, 0.020727] |
| V4 minus Behavioral | **+0.043741** | **[0.027060, 0.062264]** |
| Behavioral only | **+0.019853** | **[0.006453, 0.033762]** |

Protocol: 2,000 paired incident-level resamples, bootstrap seed 20260828, percentile intervals. The comparisons are exploratory; no confirmatory p-values or Holm-adjusted tests were applied.

## D. H2 Assessment

**H2 is partially supported.** Full V4 achieved higher observed incident-level Macro F1 than every ablated configuration. The paired interval for removing the Behavioral family was entirely above zero, providing clear evidence that the Behavioral family contributed materially under the frozen XGBoost protocol. Full V4 also outperformed Behavioral-only with an interval entirely above zero, supporting a joint contribution from CAIDA and RPKI/ROV enrichment. However, the individual CAIDA-removal and RPKI-removal intervals included zero. Therefore, this experiment does not establish separate, statistically stable incremental Macro-F1 benefits for each enrichment family considered individually.

## E. Reproducibility

### New source and protocol

- `run_xgboost_feature_family_ablation_v1.py`
- `ablation_protocol_v1.md`

### Output artifacts

- `input_hash_verification_v1.csv`
- `environment_manifest_v1.csv`
- `baseline_reproduction_gate_v1.csv`
- `baseline_seed_metrics_v1.csv`
- `baseline_window_oof_predictions_v1.parquet`
- `baseline_incident_oof_predictions_v1.parquet`
- `xgb_ablation_seed_metrics_v1.csv`
- `xgb_ablation_summary_metrics_v1.csv`
- `xgb_ablation_window_oof_predictions_v1.parquet`
- `xgb_ablation_incident_oof_predictions_v1.parquet`
- `xgb_ablation_paired_bootstrap_v1.csv`
- `output_checksums_v1.csv`

Prediction integrity checks found 68,031 window rows and 993 incident rows for every configuration-seed pair, all five folds, no missing probabilities, and class counts of 331/331/331.

### Commands

From the repository root:

```bash
PYTHONDONTWRITEBYTECODE=1 /opt/anaconda3/bin/python experiments/xgboost_feature_family_ablation_v1/run_xgboost_feature_family_ablation_v1.py --phase baseline
PYTHONDONTWRITEBYTECODE=1 /opt/anaconda3/bin/python experiments/xgboost_feature_family_ablation_v1/run_xgboost_feature_family_ablation_v1.py --phase ablations
```

The optional `--phase bootstrap` recalculates the predeclared bootstrap from the already persisted incident predictions without refitting models.

## F. Historical Random-Forest Discrepancy

The historical `0.541436` and refined `0.784588` Random Forest values measure different experiments. The `0.541436` result came from an untuned 200-tree hierarchical Random Forest evaluated end to end across four classes: Normal, Hijack, Leak, and Outage. Its Normal-class F1 was approximately 0.010657, which materially lowered four-class Macro F1. The refined `0.784588` result used a tuned 1,200-tree Random Forest and evaluated only the three incident classes at Level 1. The refined XGBoost value `0.805678` likewise represents three-class incident-level grouped CV. The difference is consequently explained by both task definition and model refinement; `0.541436` is not the correct full-feature comparator for this controlled XGBoost H2 experiment.

## Final Interpretation Boundary

These findings supplement the historical Praxis after faculty feedback. They do not replace the terminal Validation or Final Holdout results, and they do not change the final two-level architecture. They should be reported as a new TRAIN-only controlled sensitivity experiment using the frozen Level-1 XGBoost specification.
