# Final Manuscript Integration Map v1

| chapter | section | integration_action | source_artifact |
| --- | --- | --- | --- |
| Chapter 1 | Title/problem/thesis/RQs | Narrow from root-cause oracle to BGP incident classification and ranking; clarify retrospective RouteViews scope and enterprise motivation. | docs/praxis_terminology_register_v1.csv; FINAL_RESEARCH_CLAIMS_BOUNDARY_v1.md |
| Chapter 2 | Literature review | Add/strengthen source dependence, BGP anomaly detection, route leaks/hijacks/outages, RPKI/ROV, calibration, early time-series classification, and streaming/BMP/Kafka future-work literature. | FINAL_REFERENCE_REMEDIATION_PLAN_v1.csv |
| Chapter 3 | Dataset and labels | Integrate 1,419 corpus construction, Cloudflare label-entry trace, label provenance, duplicate remediation, 473/class selection, and partitioning. | experiments/corpus_balancing_audit_v1; experiments/label_provenance_audit_v1 |
| Chapter 3 | Feature engineering | Summarize 44 Behavioral, 14 CAIDA, 16 RPKI/ROV V4 schema; move full dictionary to Appendix A. | experiments/reproducibility_audit_v1/reproducibility_feature_dictionary_v1.csv |
| Chapter 3 | Modeling | Describe Level-1 XGBoost and retrospective Level-2 K1 stacker; explicitly bound Level-2 as retrospective incident-level aggregation. | docs/final_model_specification_v1.md |
| Chapter 3 | TTI methodology | Insert early-horizon Level-1-only retrospective checkpoint method and denominator exclusions. | experiments/tti_early_horizon_v2/chapter3_tti_methodology_subsection_v2.md |
| Chapter 4 | Core results | Keep final holdout, K1 stacking, K2 stability, K2.5 comparator, RF/XGB selection, and key ablations; move detailed pilots to appendix. | docs/chapter4_results_evidence_map_v1.csv |
| Chapter 4 | Remediation results | Add label provenance/cross-source, prior-shift, calibration, error analysis, TTI, and IEC closure summaries without replacing official results. | experiments/*_v1; experiments/tti_early_horizon_v2 |
| Chapter 5 | Interpretation | Connect results to RQs/Hs with explicit caveats on Cloudflare/source dependence, balancing, calibration, Level-2, and external validation. | FINAL_RESEARCH_CLAIMS_BOUNDARY_v1.md |
| Chapter 5 | Future work | Real-time BMP/Kafka ingestion, incremental feature updates, prospective TTSC/TTI, enterprise-local telemetry, external prospective validation, and causal temporal models. | docs/future_work_register_v1.csv |
