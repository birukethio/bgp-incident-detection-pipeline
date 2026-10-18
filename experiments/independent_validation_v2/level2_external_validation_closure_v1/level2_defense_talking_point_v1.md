# Defense Talking Point v1

If asked why the source-separated external Level-2 validation was not executed:

> We verified that the independent implementation could reproduce the final pipeline exactly through E5: windows, V4 features, Level-1 probabilities, mean aggregation, and Level-2 meta-features. The stopping point was E6, because the original trained Level-2 XGBoost object was never persisted as a binary artifact. The repository preserves the Level-2 configuration, meta-feature generation, TRAIN-derived reference predictions, and Final Holdout results, but not the trained model object itself. Rather than refit Level 2 after the external roster was known and risk presenting a newly fitted model as the original frozen model, I closed the external Level-2 validation with a documented limitation. This does not change the original Final Holdout result; it limits only the additional source-separated Level-2 confirmation claim.

Short version:

> Level 2 is procedurally reproducible, but the exact original trained artifact is not recoverable. I therefore did not execute source-separated Level-2 external validation, because refitting after the external roster existed would compromise the validation boundary.

