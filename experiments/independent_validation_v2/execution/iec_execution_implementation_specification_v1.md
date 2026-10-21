# IEC Execution Implementation Specification v1

Generated UTC: 2026-09-15T15:03:51.282877+00:00

## Scope

This is an additive source-separated IEC execution record under `experiments/independent_validation_v2/execution/`.
The frozen IEC roster contains 63 candidate incidents and is read from
`experiments/independent_validation_v2/v2_IEC_final_source_separated_roster.csv`.

## Frozen Inputs

| Step | Required frozen methodology | Authoritative artifact/code found |
| --- | --- | --- |
| IEC roster and labels | Source-native non-Cloudflare labels, deterministic mapping, no event replacement | `experiments/independent_validation_v2/V2_IEC_AUTOMATED_EVALUATION_LOCK.md`; `v2_IEC_final_source_separated_roster.csv`; `v2_IEC_source_label_mapping_rules.csv` |
| Collector and archive | RouteViews `route-views2`, 15-minute UPDATE files, UTC slot handling | `experiments/reproducibility_audit_v1/reproducibility_routeviews_pipeline_v1.md`; `src/bgp_incident_detection/mrt_acquisition.py`; `src/bgp_incident_detection/mrt_download.py` |
| Parser | `bgpdump 1.6.2`, `bgpdump -q -m`, one row per prefix-level announcement/withdrawal observation | `experiments/reproducibility_audit_v1/reproducibility_routeviews_pipeline_v1.md`; `src/bgp_incident_detection/mrt_parser.py` |
| Windowing | Five-minute RouteViews-observable analytical windows | `experiments/reproducibility_audit_v1/reproducibility_windowing_v1.md`; `src/bgp_incident_detection/windows.py` |
| Behavioral features | Frozen 44-feature behavioral family | `experiments/reproducibility_audit_v1/reproducibility_feature_dictionary_v1.csv`; `src/bgp_incident_detection/behavioral_features.py` |
| CAIDA features | Frozen 14 historical AS-relationship features | `experiments/reproducibility_audit_v1/reproducibility_caida_v1.md`; `src/bgp_incident_detection/caida_features.py` |
| RPKI/ROV features | Frozen 16 historical RPKI/ROV features | `experiments/reproducibility_audit_v1/reproducibility_rpki_v1.md`; `src/bgp_incident_detection/rpki_features.py` |
| V4 schema | 44 Behavioral + 14 CAIDA + 16 RPKI/ROV = 74 features | `config/final_model_candidate_v3_1_xgb_refined.yaml`; `src/bgp_incident_detection/feature_ablation.py` |
| Level-1 model | Reconstructed five-model XGBoost ensemble with exact TRAIN probability equivalence | `data/tti_pilot/reconstructed_level1_v1/`; `experiments/reproducibility_audit_v1/reproducibility_level1_xgboost_v1.md` |
| Level-2 model | XGBoost retrospective incident temporal stacker | `config/k1_second_level_xgb_final_v1.yaml`; `config/k1_incident_meta_feature_schema_v1.yaml`; `experiments/reproducibility_audit_v1/reproducibility_level2_stacker_v1.md` |

## Blocking Finding

The frozen artifacts document the final pipeline and contain reconstructed Level-1 models, but the workspace does not contain a frozen, verified, source-native IEC reconstruction/scoring implementation capable of taking arbitrary non-Cloudflare IEC event metadata through RouteViews acquisition, incident-relevance filtering, V4 feature construction, Level-1 scoring, Level-2 meta-feature construction, and final incident scoring.

The prior independent-validation execution path under `experiments/independent_validation_execution_v1/` is a stopped zero-prediction record, not a reusable scoring implementation. Therefore, the required implementation-equivalence gate cannot be passed without creating and validating a new end-to-end reconstruction implementation. Per the IEC protocol, this execution stops before model scoring.
