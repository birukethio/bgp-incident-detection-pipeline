# Final Level-2 Reconstruction and Prediction Equivalence Test

**Artifact status:** Reconstructed Level-2 model - post-feedback reproducibility evaluation

**Disposition:** `EXACT_REPRODUCTION`

The original trained Level-2 object was not preserved. This artifact is one controlled post-feedback reconstruction using the frozen implementation, configuration, TRAIN meta-features, seed, and environment. No Level-1 model was retrained, and Final Holdout labels were not used for fitting, tuning, calibration, or model selection.

## Equivalence results

- Predicted-label agreement: 213/213
- Full ranking agreement: 213/213
- Mean absolute class-score difference: 4.0657411796504933e-17
- Maximum absolute class-score difference: 1.1102230246251565e-16
- Incidents with any score difference > 1e-12: 0
- Incidents with any score difference > 1e-6: 0
- Label or ranking discrepancies: 0

## Aggregate metrics

| Metric | Original archived | Reconstructed | Delta |
|---|---:|---:|---:|
| incident_macro_f1 | 0.920176945007678 | 0.920176945007678 | 0 |
| top1 | 0.920187793427230 | 0.920187793427230 | 0 |
| top2 | 0.990610328638498 | 0.990610328638498 | 0 |
| mrr | 0.958528951486698 | 0.958528951486698 | 0 |

The archived predictions remain the authoritative historical Final Holdout result. The reconstructed model is retained separately as reproducibility evidence and is not a replacement for the unavailable original serialized object.
