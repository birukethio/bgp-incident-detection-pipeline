# Leak Event Identification Policy v1

This policy resolves the roster-level Leak prefix question before MRT acquisition. It does not modify Roster v2 and does not extract features.

## Decision

Exact affected prefix lists are not required to freeze the Leak incident roster because the incident can be identified at the event level using:

- verified event time bounds: `min_ts` or `detected_ts` through `max_ts`
- `leak_asn`
- `leak_seg`, the involved AS-path segment
- `origin_count`
- `prefix_count`
- `peer_count`
- countries and Cloudflare source event ID/provenance

The absence of exact prefix lists is an acceptable limitation for roster freezing, not a reason to invent prefixes.

## Incident Identification

For each Leak incident, use Cloudflare event identity and metadata to locate candidate BGP UPDATE evidence:

1. Search only within the incident's reviewed time window.
2. Filter candidate AS paths for the leak ASN and the involved `leak_seg`.
3. Use observed origin/path evidence in RouteViews/RIS updates to identify the leaked announcements.
4. Derive exact prefixes from matching MRT UPDATE NLRI during feature extraction.

## Feature Extraction

Feature extraction may compute prefix-level features from the prefixes observed in matching BGP updates. Those prefixes are derived evidence from MRT data, not original Cloudflare source labels.

## Ground-Truth Labeling

The ground-truth label remains the incident-level Cloudflare Leak event. A 5-minute bin should be labeled Leak only when leak-specific evidence is observed in or near that bin according to the later active-window policy. Long silent gaps remain UNKNOWN, not Leak.

## Guardrails

- Do not invent missing prefixes.
- Do not treat `prefix_count` as a prefix list.
- Do not label every prefix announced by the leak ASN as leaked.
- Keep the continuity/gap threshold parameterized until the MRT observation distribution is inspected.
