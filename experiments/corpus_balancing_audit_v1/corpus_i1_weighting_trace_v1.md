# Corpus I1 Weighting Trace v1

I1 is not a corpus selection or balancing operation. It is a model-training sample-weighting strategy applied inside each TRAIN grouped-CV fold.

Recovered implementation: `src/bgp_incident_detection/imbalance_model_experiment.py`.

The function is:

```python
def group_aware_weights(train: pd.DataFrame) -> np.ndarray:
    group_sizes = train.groupby("model_group_id")["window_id"].transform("count").astype(float)
    return (1.0 / group_sizes).to_numpy()
```

For the final multiclass XGBoost pathway, the validation-confirmation helper also uses:

```python
counts = df.groupby("incident_uid")["window_id"].transform("count")
return (1.0 / counts).to_numpy(dtype=float)
```

The XGBoost weight audit confirms fold-local equal aggregate incident/group influence:

| fold | train_rows | train_incident_groups | min_group_weight | median_group_weight | max_group_weight | group_weight_semantics                                                                                          | status |
| ---- | ---------- | --------------------- | ---------------- | ------------------- | ---------------- | --------------------------------------------------------------------------------------------------------------- | ------ |
| 1    | 53399      | 794                   | 1.0              | 1.0                 | 1.0              | same group_aware_weights(train_fold) function used for RF and XGBoost; weights computed from training side only | PASS   |
| 2    | 53402      | 795                   | 1.0              | 1.0                 | 1.0              | same group_aware_weights(train_fold) function used for RF and XGBoost; weights computed from training side only | PASS   |
| 3    | 54897      | 795                   | 1.0              | 1.0                 | 1.0              | same group_aware_weights(train_fold) function used for RF and XGBoost; weights computed from training side only | PASS   |
| 4    | 55693      | 794                   | 1.0              | 1.0                 | 1.0              | same group_aware_weights(train_fold) function used for RF and XGBoost; weights computed from training side only | PASS   |
| 5    | 54733      | 794                   | 1.0              | 1.0                 | 1.0              | same group_aware_weights(train_fold) function used for RF and XGBoost; weights computed from training side only | PASS   |

The imbalance experiment audit records the same semantics:

| fold | model_task     | imbalance_condition | training_rows_before_treatment | training_rows_after_treatment | independent_training_groups | min_aggregate_group_weight | median_aggregate_group_weight | max_aggregate_group_weight | effective_class_weights                                                                                              | status | notes                                                                                             |
| ---- | -------------- | ------------------- | ------------------------------ | ----------------------------- | --------------------------- | -------------------------- | ----------------------------- | -------------------------- | -------------------------------------------------------------------------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------- |
| 1    | RF_SINGLE      | I1                  | 53837                          | 53837                         | 794                         | 1.0                        | 1.0                           | 1.0                        | {"HIJACK": 260.96700705728887, "LEAK": 263.0954488740575, "NORMAL": 6.125634610758512, "OUTAGE": 263.8119094578951}  | PASS   | I0 preserves natural row imbalance; I1/I2 compute 1/N group weights inside the training fold only |
| 2    | RF_SINGLE      | I1                  | 53857                          | 53857                         | 795                         | 1.0                        | 1.0                           | 1.0                        | {"HIJACK": 262.3517420667844, "LEAK": 261.4768048062609, "NORMAL": 6.405710972139538, "OUTAGE": 264.76574215481514}  | PASS   | I0 preserves natural row imbalance; I1/I2 compute 1/N group weights inside the training fold only |
| 3    | RF_SINGLE      | I1                  | 55340                          | 55340                         | 795                         | 1.0                        | 1.0                           | 1.0                        | {"HIJACK": 261.82015391043575, "LEAK": 263.1489014593243, "NORMAL": 6.187528659893616, "OUTAGE": 263.84341597034637} | PASS   | I0 preserves natural row imbalance; I1/I2 compute 1/N group weights inside the training fold only |
| 4    | RF_SINGLE      | I1                  | 56047                          | 56047                         | 794                         | 1.0                        | 1.0                           | 1.0                        | {"HIJACK": 262.8917628570447, "LEAK": 262.7890319505855, "NORMAL": 5.221110859450351, "OUTAGE": 263.0980943329195}   | PASS   | I0 preserves natural row imbalance; I1/I2 compute 1/N group weights inside the training fold only |
| 5    | RF_SINGLE      | I1                  | 55107                          | 55107                         | 794                         | 1.0                        | 1.0                           | 1.0                        | {"HIJACK": 262.40146490170434, "LEAK": 262.92245586362895, "NORMAL": 5.403952748184472, "OUTAGE": 263.2721264864822} | PASS   | I0 preserves natural row imbalance; I1/I2 compute 1/N group weights inside the training fold only |
| 1    | RF_HIER_STAGE1 | I1                  | 53837                          | 53837                         | 794                         | 1.0                        | 1.0                           | 1.0                        | {"INCIDENT": 787.8743653892415, "NORMAL": 6.125634610758512}                                                         | PASS   | I0 preserves natural row imbalance; I1/I2 compute 1/N group weights inside the training fold only |
| 1    | RF_HIER_STAGE2 | I1                  | 53399                          | 53399                         | 794                         | 1.0                        | 1.0                           | 1.0                        | {"HIJACK": 264.0, "LEAK": 265.0, "OUTAGE": 265.0}                                                                    | PASS   | I0 preserves natural row imbalance; I1/I2 compute 1/N group weights inside the training fold only |
| 2    | RF_HIER_STAGE1 | I1                  | 53857                          | 53857                         | 795                         | 1.0                        | 1.0                           | 1.0                        | {"INCIDENT": 788.5942890278604, "NORMAL": 6.405710972139538}                                                         | PASS   | I0 preserves natural row imbalance; I1/I2 compute 1/N group weights inside the training fold only |
| 2    | RF_HIER_STAGE2 | I1                  | 53402                          | 53402                         | 795                         | 1.0                        | 1.0                           | 1.0                        | {"HIJACK": 265.0, "LEAK": 264.0, "OUTAGE": 266.0}                                                                    | PASS   | I0 preserves natural row imbalance; I1/I2 compute 1/N group weights inside the training fold only |
| 3    | RF_HIER_STAGE1 | I1                  | 55340                          | 55340                         | 795                         | 1.0                        | 1.0                           | 1.0                        | {"INCIDENT": 788.8124713401064, "NORMAL": 6.187528659893616}                                                         | PASS   | I0 preserves natural row imbalance; I1/I2 compute 1/N group weights inside the training fold only |
