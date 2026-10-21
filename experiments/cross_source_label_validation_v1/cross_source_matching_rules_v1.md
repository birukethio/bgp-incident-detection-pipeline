# Cross-Source Same-Event Matching Rules v1

This label-validation audit uses only source evidence and incident metadata. It does not use model predictions, model features, window-level feature values, or model errors.

## Accepted same-event match

An independent source match is accepted only when all of the following are present:

1. The source is not Cloudflare and does not rely on Cloudflare as the primary label authority.
2. The source uses source-native incident terminology that deterministically maps to Hijack, Leak, or Outage.
3. The source event can be tied to a Cloudflare incident by event time plus ASN, prefix, AS-path, location/network, or outage-cause evidence.
4. The external label is not ambiguous.

## Match-strength categories

- `STRONG_SAME_EVENT`: source-native label plus overlapping time and specific ASN/prefix/path/network evidence.
- `MODERATE_SAME_EVENT`: source-native label plus overlapping time and partial ASN/network evidence. Retained only if not ambiguous.
- `AGGREGATE_CONTEXT_ONLY`: aggregate country/month/source metric; excluded from agreement.
- `ROUTING_EVIDENCE_ONLY`: raw BGP/RIS/RouteViews/RIPEstat observation without source-native class label; excluded from agreement.
- `NO_ACCEPTED_MATCH`: no deterministic same-event independent classification found.

## Exclusions

MANRS monthly country/economy matches and RIPEstat raw BGP update matches are documented as searched/supporting context, but are excluded from label-agreement metrics unless a source-native event classification identifies the same real-world incident.
