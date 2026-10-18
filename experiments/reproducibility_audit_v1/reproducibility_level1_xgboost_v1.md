# Level 1 XGBoost Reproducibility v1

## Candidate

`XGB_REFINED_TRAIN_CANDIDATE` is the frozen Level-1 model family used by the final K1 architecture.

## Hyperparameters

| hyperparameter | value |
| --- | --- |
| colsample_bytree | 0.9 |
| gamma | 0 |
| learning_rate | 0.125 |
| max_depth | 6 |
| min_child_weight | 1 |
| n_estimators | 600 |
| reg_alpha | 0.01 |
| reg_lambda | 2.0 |
| subsample | 0.9 |
| objective | multi:softprob |
| num_class | 3 |
| eval_metric | mlogloss |

## Feature and Weighting Inputs

Input features are the frozen V4 74-feature schema in exact order. I1 incident-aware sample weights are used. Missing values are handled with median imputation fitted only on the training side of each fold.

## Reconstruction Note

The original serialized Level-1 artifact was not preserved. A controlled reconstruction under `data/tti_pilot/reconstructed_level1_v1/` passed exact probability equivalence against 68,031 preserved TRAIN predictions: max, mean, and median absolute probability differences were all 0.0.
