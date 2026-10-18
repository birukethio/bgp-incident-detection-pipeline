# Label Provenance Audit v1

## Scope

This additive forensic audit examines the final frozen 1,419-incident corpus: 473 Hijack, 473 Leak, and 473 Outage incidents. It does not modify labels, partitions, features, models, Validation results, Final Holdout results, TTI artifacts, prevalence-sensitivity artifacts, manuscripts, tables, or figures.

## Overall Disposition

`PASS_WITH_DOCUMENTED_OVERLAP`

The audit found documented conceptual overlap between external label evidence and model feature families, especially for Hijack and Leak, but found no direct target leakage in the frozen 74-feature V4 schema.

## Counts by Label/Feature Relationship

| Classification | Count | Percent |
|---|---:|---:|
| NORMAL_PREDICTIVE_ASSOCIATION | 0 | 0.00% |
| PARTIAL_EVIDENCE_OVERLAP | 1,419 | 100.00% |
| POTENTIAL_CIRCULAR_LABELING | 0 | 0.00% |
| DIRECT_TARGET_LEAKAGE | 0 | 0.00% |
| REVIEW_REQUIRED | 0 | 0.00% |

## Critical Leakage Check

- V4 features checked: 74
- Features containing direct label/source/id/provider leakage: 0
- Source/provider identifiers included as model features: no
- Incident id or incident uid included as predictive features: no
- Source event type/classification included as predictive features: no
- Label text or label-derived numeric encoding included as predictive features: no

## Source-Level Findings

Some source/provider lineages supply only one class in the final roster:

- Cloudflare Radar BGP hijack detector/source feed
- Cloudflare Radar BGP route leak detector/source feed
- Cloudflare Radar outage catalog/feed
- Cloudflare Radar outage social/catalog feed
- Cloudflare Radar/Cloudflare blog outage report

This is not direct leakage because source/provider identifiers are not part of the model feature matrix. It remains a provenance caveat: the corpus is assembled from class-specific external source feeds.

## Interpretation

Conceptual overlap is expected in this domain. A hijack should often produce origin/RPKI/path anomalies; a route leak should often produce path-policy anomalies; and an outage should often produce withdrawal or reachability/visibility changes. These are legitimate observable routing signals when they are independently observed in RouteViews-derived windows and not directly copied from the label source as target variables.

## Methodology-Ready Paragraph

A forensic label-provenance audit was conducted for the frozen 1,419-incident corpus. For each incident, the audit traced the source feed or report, source event identifier, documented timing, affected ASN/prefix metadata, and pipeline normalization. The label evidence was then compared against the frozen V4 feature families: 44 Behavioral BGP features, 14 historical CAIDA AS-relationship features, and 16 historical RPKI/ROV features. The audit distinguished normal predictive association and conceptual evidence overlap from circular label construction and direct target leakage.

## Limitations-Ready Paragraph

The audit is limited by the level of detail preserved in source records. Hijack and Leak records retain stable Cloudflare Radar detector event identifiers and notes, but usually not public article URLs. Therefore, the audit can verify that source/provider/class identifiers are absent from the model feature schema and that labels were not inferred by the model pipeline, but it cannot reconstruct every internal detector decision made by the external source.
