# Hijack:68538 Final Disposition v1

Generated UTC: 2026-09-14T23:51:22.958158+00:00

Disposition: `QUALITY_GATE_INCONSISTENCY`

Rationale: `Hijack:68538` has explicit source-side Cloudflare Radar hijack evidence, including affected prefixes, hijacker ASN, victim ASNs, detector tags, peer visibility, and message count. However, the final Holdout processing quality gate records `REVIEW` because no directly relevant RouteViews observations were found. The audit confirms this means `ROUTING_DATA_PRESENT_BUT_NO_INCIDENT_RELEVANT_MATCH`: RouteViews MRT data existed, were downloaded, and parsed, but the relevance filter retained zero incident-specific observations.

The incident should not be permanently removed by this audit. Its inclusion represents a quality-gate consistency caveat: the final evaluation pipeline permitted a REVIEW case with valid feature rows, whereas a stricter current rule requiring incident-relevant RouteViews evidence would require either exclusion or explicit documented limitation before evaluation.

## Manuscript-ready limitations paragraph

One retained Final Holdout case, Hijack:68538, had strong preserved Cloudflare Radar hijack provenance but no incident-relevant RouteViews observations after the final relevance filter. RouteViews MRT files were successfully retrieved and parsed, so the issue was not absence of routing data; rather, broad routing observations were present but did not match the incident-specific ASN/prefix criteria used by the pipeline. The case produced valid V4 feature rows through the frozen context-window and default/zero-value feature pipeline and was correctly classified in the frozen Final Holdout predictions. A post-hoc exclusion sensitivity analysis showed only a small aggregate change, but the appropriate interpretation is a documented data-quality limitation rather than a change to the official terminal Holdout result.
