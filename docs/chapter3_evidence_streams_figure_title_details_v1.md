# Figure 3.x. Three Evidence Streams and Boundary Conditions for BGP Incident Classification and Ranking

**Recommended title:** Three Evidence Streams and Boundary Conditions for BGP Incident Classification and Ranking

**Short title option:** Evidence Streams for H/L/O Classification

**Suggested placement:** Chapter 3 methodology, after the feature-engineering overview and before the model architecture subsection.

**Caption:** The final feature representation combines three evidence streams: BGP behavioral evidence from RouteViews-observable updates, CAIDA AS-policy evidence, and historical RPKI/ROV origin-authorization evidence. These streams form the frozen V4 feature vector used for Hijack, Leak, and Outage classification/ranking. Public-collector visibility and label provenance are shown as boundary conditions because they constrain interpretation: the model observes public routing evidence and externally documented labels, not enterprise-local telemetry or direct root-cause proof.

**Boundary language for manuscript:** This figure should be interpreted as a feature-evidence architecture. It does not claim live enterprise alerting latency, direct root-cause determination, or complete visibility into all Internet routing state.

**Generated files:**

- `figures/chapter3/figure_3_evidence_streams_hlo_boundary_conditions_v1.pdf`
- `figures/chapter3/figure_3_evidence_streams_hlo_boundary_conditions_v1.png`
- `figures/chapter3/figure_3_evidence_streams_hlo_boundary_conditions_v1_highres_chart_only.jpg`

