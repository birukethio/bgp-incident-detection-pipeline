# Current Frozen Study Inventory v1

## Scope and Stop Rule

This inventory is read-only documentation for an independent-validation protocol design. It does not retrain, rescore, relabel, repartition, or recompute any frozen experiment. The existing Final Holdout remains the terminal evaluation of the current Praxis architecture and is not accessed or recomputed by this audit.

## Frozen Corpus and Partitions

The authoritative balanced corpus contains 1,419 independent incidents:

- Hijack: 473 incidents
- Leak: 473 incidents
- Outage: 473 incidents

The frozen v2 incident-level partition is:

- TRAIN: 993 incidents, 331 per class
- Validation: 213 incidents, 71 per class
- Final Holdout: 213 incidents, 71 per class

Key local artifacts:

- `data/roster_v2/frozen_incident_roster_v2.csv`
- `data/partitions_v2/frozen_partition_manifest_v2.csv`
- `data/partitions_v2/train_incidents_v2.csv`
- `data/partitions_v2/validation_incidents_v2.csv`
- `data/partitions_v2/holdout_incidents_v2.csv`

## Frozen Feature Representation

The final model uses the frozen V4 feature schema with exactly 74 features:

- 44 Behavioral BGP features
- 14 historical CAIDA AS-relationship features
- 16 historical RPKI/ROV features

Key local artifacts:

- `data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1.parquet`
- `data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1_feature_manifest.csv`
- `config/feature_variants_v1.yaml`
- `config/behavioral_feature_schema_v1.yaml`
- `config/caida_feature_schema_v1.yaml`
- `config/rpki_feature_schema_v1.yaml`

To apply the frozen model to any independent confirmation set, the candidate events must be converted to this exact schema, ordering, data type policy, historical CAIDA mapping, historical RPKI/ROV mapping, and missing-value policy. No feature definitions may be changed after the confirmation set is observed.

## Frozen Model Architecture

The final Praxis architecture is an XGBoost-to-XGBoost incident-level architecture:

- Level 1: frozen XGBoost multiclass probability model over 74 V4 features.
- Level 1 inference: five-model cross-fit ensemble, recovered and probability-equivalent to the preserved TRAIN fingerprint.
- Level 2: frozen K1 incident temporal XGBoost stacker over incident-level meta-features.
- Ranking rule: sort Hijack, Leak, and Outage by descending incident-level probability.

Key local artifacts:

- `config/k1_final_candidate_v1_1_deployable.yaml`
- `config/k1_incident_meta_feature_schema_v1.yaml`
- `config/k1_second_level_xgb_final_v1.yaml`
- `data/tti_pilot/level1_ensemble_manifest_v2.json`
- `data/tti_pilot/reconstructed_level1_v1/`
- `data/tti_pilot/level1_probability_equivalence_v2.csv`
- `src/bgp_incident_detection/k1_incident_stacking.py`

The recovered Level-1 ensemble had exact probability equivalence against the preserved TRAIN fingerprint: 68,031 predictions compared, predicted-class agreement 1.0, maximum absolute probability difference 0.0, mean absolute probability difference 0.0, and per-class probability correlations 1.0.

## Terminal Final Holdout Result

The terminal authoritative Final Holdout result is recorded in `config/final_praxis_result_v1.yaml`:

- Holdout incidents: 213
- Holdout rows: 14,906
- Macro F1: 0.920177
- 95% CI: [0.880117, 0.954402]
- Top-1: 0.920188
- Top-2: 0.990610
- MRR: 0.958529
- Hijack F1: 0.877698
- Leak F1: 0.904110
- Outage F1: 0.978723
- Rank 1: 196
- Rank 2: 15
- Rank 3: 2
- Second-level parameter hash: `40df040321ef`

This audit does not reinterpret that result. Any future independent confirmation set would be additive and would not replace the one-time Final Holdout evaluation.

## Existing Provenance Findings

The label-provenance audit traced the final corpus to Cloudflare-derived incident sources and concluded `PASS_WITH_DOCUMENTED_EVIDENCE_SOURCE_OVERLAP`. The important distinction is:

- External label provenance: labels came from external Cloudflare incident/event feeds or outage annotations rather than from the model pipeline.
- Underlying evidence-source independence: Cloudflare's detection evidence may use public routing data and related signals that conceptually overlap Behavioral, CAIDA, or RPKI/ROV model features.

Key local artifacts:

- `experiments/label_provenance_audit_v1/cloudflare_label_entry_trace_v1.md`
- `experiments/label_provenance_audit_v1/label_provenance_final_disposition_v1.md`
- `experiments/label_provenance_audit_v1/direct_target_leakage_check_v1.csv`

## Existing TTI Work

The retrospective early-classification/TTI work is separate from the final K1 incident-level architecture:

- TTI uses the verified Level-1 XGBoost ensemble only.
- TTI does not use Level-2 temporal stacking.
- TTI uses checkpoint-based horizons and does not claim continuous live operational TTI.

Key local artifacts:

- `data/tti_validation_confirmation_v1/tti_validation_confirmation_summary_v1.md`
- `experiments/tti_early_horizon_v2/early_horizon_final_verification_v2.md`
- `experiments/tti_early_horizon_v2/early_horizon_final_disposition_v2.md`

The early-horizon v2 TRAIN analysis had disposition `PASS_WITH_DOCUMENTED_EXCLUSIONS`.

## Existing Class-Prior Sensitivity Analysis

The natural-distribution work is best described as a prevalence-reweighted prior-shift sensitivity analysis. It did not retrain, recalibrate, or duplicate incidents. It changed only evaluation weights/class priors on existing TRAIN nested-CV predictions.

Key local artifacts:

- `experiments/natural_distribution_v1/natural_distribution_reweighting_verification_v1.md`
- `experiments/natural_distribution_v1/natural_distribution_summary_v1.md`

Observed source-corpus proportions used in that sensitivity analysis were Hijack 47.2176%, Leak 52.5835%, and Outage 0.1989%.

## Artifacts Required Before Applying the Frozen Model to a New Confirmation Set

An independent confirmation execution, if later authorized, must freeze these inputs before first scoring:

1. Confirmation incident roster with incident IDs, class labels, source provenance, start/end times, affected ASN(s), and prefixes when applicable.
2. Confirmed non-overlap audit against the 1,419-incident frozen corpus.
3. RouteViews acquisition/reconstruction manifest and evidence-quality audit.
4. Frozen V4 feature file with exact 74-feature schema/order.
5. CAIDA and RPKI historical snapshot manifests.
6. Level-1 ensemble manifest and model checksums.
7. Level-2 K1 stacker config and model checksum.
8. Missing-value/imputation policy and class order.
9. Locked metrics/statistical protocol.
10. Pre-access exclusion and failure rules.

No Validation or Final Holdout artifact needs to be accessed to design or freeze this independent confirmation protocol.
