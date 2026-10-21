# K1 Nested Stacking Topology v1

For each outer grouped TRAIN fold, the outer test incidents are held out by `incident_uid`. The first-level XGBoost model is trained only on outer TRAIN incidents. Meta-training rows are built from inner grouped OOF predictions inside that outer TRAIN set. The second-level K1 model is trained only on those meta-training incidents, then predicts the outer held-out incidents. Thus the outer test incident cannot influence first-level fitting, second-level preprocessing, hyperparameter selection, or second-level fitting.
