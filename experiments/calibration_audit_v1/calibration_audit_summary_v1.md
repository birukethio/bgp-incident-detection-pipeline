# Frozen-Prediction Calibration Audit v1

Generated UTC: 2026-09-14T23:56:35.794611+00:00

Scope: additive diagnostic audit only. No model was retrained, recalibrated, or rerun. Validation and Final Holdout predictions were not recomputed. Official results were not changed.

## Prediction Artifacts Audited

- TRAIN: `data/modeling_k1/k1_incident_level_predictions_v1.parquet`, candidate `K1-M2_XGB_K1-TEMPORAL`, N=993.
- Validation: `data/validation/validation_incident_rankings_v1.csv`, Phase J stored validation rankings, N=213. This is not the post-Validation K1 Final Holdout architecture.
- Final Holdout: `data/final_holdout/final_holdout_incident_rankings_v1.csv`, frozen terminal K1 predictions, N=213.

## Calibration Definitions

- Multiclass Brier score: mean over incidents of the squared Euclidean distance between the three score outputs and the one-hot true class vector.
- One-vs-rest Brier: mean squared error between one class score and the binary indicator for that class.
- Log loss: mean negative log of the true-class score, with clipping only for safe logarithm calculation using epsilon `1e-15`. Stored scores were not modified.
- Top-1 ECE: 10 equal-width confidence bins on max class score. ECE = sum over bins of `n_bin / N * abs(bin_accuracy - bin_mean_confidence)`.
- Equal-frequency ECE: reported as sensitivity only, using up to 10 quantile-like bins.

## Headline Results

Final Holdout diagnostic calibration:

- Multiclass Brier score: 0.116324
- Log loss: 0.215438
- Top-1 ECE, 10 equal-width bins: 0.042380
- Top-1 ECE, 10 equal-frequency bins: 0.029633
- Mean Top-1 confidence: 0.892056
- Observed Top-1 accuracy: 0.920188

High-confidence errors across audited partitions with Top-1 score >= 0.90: 13.

## Interpretation

Top-1, Top-2, and MRR evaluate ordering quality. Brier score, log loss, ECE, and reliability diagrams evaluate probabilistic calibration. A classifier can rank classes effectively while still being imperfectly calibrated. The frozen K1 classifier has strong ordering performance on the Final Holdout, but the reliability diagnostics show enough calibration imperfection, including high-confidence errors, that unqualified operational wording such as “true probability” would be too strong.

Recommendation: `PROBABILITY_TERMINOLOGY_SUPPORTED_WITH_CALIBRATION_LIMITATION`.

The most defensible Praxis wording is to describe outputs as normalized class probabilities or class scores, while explicitly documenting calibration as a limitation. For conservative operational claims, prefer “model score,” “class score,” or “class-ranking score.”
