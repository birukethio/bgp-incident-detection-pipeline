# K1 Final Training and Inference Protocol v1

1. Generate leakage-safe OOF first-level predictions across all TRAIN incidents.
2. Derive frozen K1 meta-features from those OOF probabilities.
3. Train the final second-level stacker on all 993 TRAIN incident meta rows.
4. Separately train the final first-level XGBoost on all TRAIN window rows, or use the documented crossfit ensemble strategy if probability shift is concerning.
5. At inference time, first-level model(s) score unseen incident windows, frozen meta-features are generated, and the second-level stacker outputs P(Hijack), P(Leak), P(Outage) ranked descending.

The meta-model is trained on OOF probabilities, not first-level in-sample predictions.
