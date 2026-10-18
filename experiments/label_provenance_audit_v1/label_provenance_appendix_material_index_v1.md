# Label Provenance Appendix Material Index

The main chapters should use the compact provenance tables and concise methodology text. The detailed audit artifacts are better suited for an appendix or supporting artifact set.

| Appendix Candidate | Reason | Recommended Placement |
|---|---|---|
| `label_provenance_incident_level_v1.csv` | Full incident-level provenance is too large for the main chapter but supports reproducibility. | Appendix: Label provenance detail |
| `label_provenance_source_summary_v1.csv` | Summarizes source/provider and class relationships. | Appendix: Source summary |
| `label_feature_overlap_v1.csv` | Shows conceptual relationship between label evidence and feature families. | Appendix: Feature-overlap audit |
| `direct_target_leakage_check_v1.csv` | Documents feature-level target-leakage screening. | Appendix: Leakage checklist |
| `cloudflare_label_entry_trace_v1.md` and `.csv` | Traces Cloudflare API endpoints, response fields, and local code path. | Appendix: Cloudflare API lineage |
| `label_provenance_final_disposition_v1.md` | Records the final audit disposition and stop condition. | Appendix: Final provenance disposition |
