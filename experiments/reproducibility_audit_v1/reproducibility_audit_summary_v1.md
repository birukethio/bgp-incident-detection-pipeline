# Final Methodology Reproducibility Audit Summary v1

## Audit Scope

Generated UTC: 2026-09-15T13:03:28.052960+00:00

This audit is additive and documentation-only. It did not run training, validation, holdout prediction, feature regeneration, or manuscript edits.

## Recovered Core Methodology

- Final corpus: 1,419 incidents; 473 per class.
- Split: TRAIN 993, Validation 213, Final Holdout 213.
- Feature schema: V4 = 74 features = 44 Behavioral + 14 CAIDA + 16 RPKI/ROV.
- Weighting: I1 incident-aware window weights.
- Level 1: five-model crossfit XGBoost ensemble.
- Level 2: XGBoost temporal stacker over incident meta-features.
- Final Holdout remains terminal and immutable.

## Supporting Remediation Audits Incorporated

- Corpus balancing: `REPRODUCIBLE_WITH_DOCUMENTED_GAPS`.
- Label provenance: `PASS_WITH_DOCUMENTED_OVERLAP`, with zero direct target leakage found in the V4 feature schema.
- Partition independence: `PASS_WITH_DOCUMENTED_RELATED_EVENTS`.
- Calibration terminology: `PROBABILITY_TERMINOLOGY_SUPPORTED_WITH_CALIBRATION_LIMITATION`.
- Hijack:68538: `QUALITY_GATE_INCONSISTENCY`, documented as a limitation rather than a change to official results.

## Unrecovered or Limited Items

| area | status | gap | impact | mitigation |
| --- | --- | --- | --- | --- |
| Initial Hijack/Leak 473 selection script | NOT_UNIQUELY_RECOVERED | The first-pass executable quality-stratified sampling script was not uniquely recovered. | Final roster membership is preserved and auditable, but exact re-execution from raw pools is not fully turnkey. | Use frozen roster, strata, quality ranks, and corpus balancing audit as authoritative history. |
| Full-universe Hijack/Leak preselection duplicate collapse | NOT_RECOVERED | A full-universe duplicate-collapse artifact before v1 selection was not found. | Does not alter final v2 corpus, because v2 confirmed duplicates were remediated and replacements documented. | Cite v2 duplicate canonicalization and corpus balancing audit. |
| Original serialized frozen Level-1 model | NOT_PRESERVED_BUT_EQUIVALENT_RECONSTRUCTED_ARTIFACT_EXISTS | The original loadable Level-1 XGBoost model artifact was not preserved. | Direct loading of the historical model is impossible. | Five-model Level-1 reconstruction passed exact probability equivalence against 68,031 preserved TRAIN predictions. |
| Historical hardware and thread execution settings | PARTIALLY_RECOVERED | Recorded software versions exist for XGBoost; full hardware/thread details are incomplete outside selected manifests. | May affect timing reproducibility, not metric artifacts. | Report current environment and recorded XGBoost environment separately. |
| Hijack:68538 | QUALITY_GATE_INCONSISTENCY | One retained Holdout case had source-side hijack evidence but no retained incident-relevant RouteViews observations. | Documented limitation; official final Holdout remains immutable. | Cite Hijack:68538 audit and present as limitation rather than changing results. |
| Score calibration | SUPPORTED_WITH_CALIBRATION_LIMITATION | Scores are probability-like and normalized but imperfectly calibrated. | Ranking metrics remain valid; operational likelihood claims require caution. | Use probability terminology with calibration limitation or class-ranking score terminology. |

## Disposition

`REPRODUCIBLE_WITH_DOCUMENTED_LIMITATIONS`

The final pipeline is sufficiently documented for Chapter 3 methods, dissertation defense, and reproducibility narrative. The remaining limitations should be disclosed rather than resolved by altering historical artifacts.
