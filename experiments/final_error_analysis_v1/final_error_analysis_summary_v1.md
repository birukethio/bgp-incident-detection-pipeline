# Final Incident Level Error Analysis v1

## Scope

Generated UTC: 2026-09-15T13:12:51.970881+00:00

This is an additive diagnostic analysis using existing frozen prediction artifacts only. No model was retrained, recalibrated, tuned, or rerun. Validation and Final Holdout artifacts were not recomputed.

## Prediction Sources

| partition | candidate_id | incident_count | correct_count | top1_accuracy | top2_accuracy | mean_mrr | prediction_source |
| --- | --- | --- | --- | --- | --- | --- | --- |
| TRAIN | K1-M2_XGB_K1-TEMPORAL | 993 | 928 | 0.9345417925478349 | 0.9929506545820745 | 0.9660960053709298 | data/modeling_k1/k1_incident_level_predictions_v1.parquet |
| VALIDATION | XGB_REFINED_TRAIN_CANDIDATE_PHASE_J | 213 | 153 | 0.7183098591549296 | 0.9014084507042254 | 0.8427230046948356 | data/validation/validation_incident_rankings_v1.csv |
| FINAL_HOLDOUT | K1_FINAL_SECOND_LEVEL_XGB_V1 | 213 | 196 | 0.92018779342723 | 0.9906103286384976 | 0.9585289514866979 | data/final_holdout/final_holdout_incident_rankings_v1.csv |

## Final Holdout Error Findings

- Top-1 error count: 17 of 213.
- Highest error-rate class: Hijack (14.085%).
- Lowest error-rate class: Outage (2.817%).
- Dominant confusion pair: HIJACK_TO_LEAK with 9 incidents.
- Top-1 errors recovered by Top-2: 15/17 (88.235%).
- True class rank 3 among Top-1 errors: 2/17.
- Incorrect-case median Top-1/Top-2 margin: 0.356255; low-margin threshold used for description: <= 0.1.
- Sparse RouteViews association: Misclassified median relevant observations 19804.000; correct median 19287.500.

## Interpretation Boundary

The RPKI, CAIDA, Behavioral, visibility, and partition-context summaries are descriptive associations only. They do not establish causation and do not imply leakage. `Hijack:68538` is cross-referenced as a quality-gate inconsistency in the broader remediation work but is not treated as a Final Holdout error because its frozen prediction was correct.

## Operational Implication

The large difference between Final Holdout Top-1 and Top-2 is operationally meaningful: most Top-1 errors still ranked the true class second. This supports interpreting the system as ranked diagnostic assistance rather than a single-label oracle.

## Chapter 4 Draft Subsection

The final error analysis examined frozen incident-level predictions for TRAIN nested-CV, the independent Validation confirmation, and the terminal Final Holdout. On the Final Holdout, the classifier made 17 Top-1 errors among 213 incidents. Error patterns were reported by true/predicted class pair and by whether the true class remained in the Top-2 ranking. This distinction matters because the system is designed to rank likely incident causes, not only to issue a single class label. Most Final Holdout Top-1 errors were recovered at Top-2, explaining why Top-2 accuracy remained substantially higher than Top-1 accuracy. Descriptive comparisons of frozen Behavioral, CAIDA, RPKI/ROV, and RouteViews visibility features suggest that some errors occur in incidents with ambiguous routing evidence or weaker separability between class signatures, but these comparisons are associative and should not be read as causal explanations. The analysis therefore supports the final ranking-oriented interpretation while preserving the original one-time Holdout result.

## Final Disposition

`FINAL_ERROR_ANALYSIS_COMPLETE_WITH_DESCRIPTIVE_LIMITATIONS`
