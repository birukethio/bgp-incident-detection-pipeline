# Early Horizon Methodology v2

This is an additive TRAIN-only Level-1 post-hoc early-classification / observation-horizon experiment.

It does not modify, overwrite, delete, regenerate, or reinterpret the frozen primary Praxis experiment, final five-minute V4 model, incident-level temporal stacking architecture, Validation confirmation, Final Holdout results, figures, tables, or manuscript results.

## Scope

- Partition: TRAIN only.
- Classifier: verified frozen Level-1 XGBoost only.
- Level-2 temporal stacker: not used, not retrained, not evaluated.
- Horizons: 30, 60, 120, 300, 600, and 900 seconds from selected observable onset.
- Onset rule: the existing selected observable onset from the TTI pipeline.
- Feature representation: V4-compatible 74-feature representation using 44 Behavioral, 14 CAIDA AS-relationship, and 16 historical RPKI/ROV features.

## Chronology

This experiment was performed after the primary five-minute model development and after the Validation TTI confirmation work. It is therefore presented transparently as a post-hoc TRAIN-only Level-1 horizon study requested to address the advisor's TTI question and to test whether the existing five-minute analytical representation is empirically defensible.

It must not be written as if the 300-second window was originally selected by this horizon optimization.
