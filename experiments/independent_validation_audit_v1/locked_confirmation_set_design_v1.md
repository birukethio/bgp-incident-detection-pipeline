# Locked Confirmation Set Design v1

## Design Objective

The confirmation set should test whether the frozen Praxis architecture generalizes to independently sourced labels whose provenance is not Cloudflare. It must be built and locked before first scoring. It must not replace or reinterpret the terminal Final Holdout result.

## Recommended Design

Use a source-separated, event-level confirmation set with two tiers:

1. **Primary confirmation cohort**
   - Hijack/Leak from RouteLLM if accessible and metadata-complete.
   - Outage from IODA curated/API events if ASN/network scoped.
   - Exclude any event that matches the existing 1,419-event corpus.

2. **Secondary adjudication cohort**
   - MANRS/GRIP, operator postmortems, Kentik/ThousandEyes/BGPmon/RIPE reports, BGPStream/Atlantic Council, and GLBAD records.
   - Use these mainly to resolve sparse classes, validate ambiguous cases, or provide descriptive sensitivity checks.

## Do Not Force 30/30/30

A 30/30/30 design is acceptable only if the source-native data supports it after quality filtering and overlap removal. If one class has fewer usable independent events, the confirmation set should preserve the defensible event count rather than padding with weaker records.

Preferred reporting:

- Natural/source-preserving confirmation cohort: all eligible independent events.
- Optional balanced diagnostic subset: only if at least 30 per class are available without weakening criteria.

## Inclusion Criteria

An event is eligible only if all criteria are met:

1. Source is not Cloudflare and not derived from a Cloudflare event ID.
2. Event class can be mapped prospectively to Hijack, Leak, or Outage.
3. Start time is available and UTC-normalizable.
4. End time or defensible active interval rule is available.
5. Affected ASN/network is available; affected prefix is required for Hijack and preferred for Leak.
6. RouteViews reconstruction is feasible over the event window.
7. Event does not overlap the final 1,419-event corpus by event ID, description, ASN/prefix/time, or source narrative.
8. License/access allows dissertation use.
9. Event metadata can be frozen before model scoring.

## Exclusion Criteria

Exclude or classify as review-only:

- Events with only a date and no usable time.
- Outages that are purely regional/geographic with no ASN/network mapping.
- Events that are the same real-world incident already in the Cloudflare corpus.
- Events whose class is inferred locally from the same V4 features rather than supplied by an external source.
- Events with RouteViews coverage failure after acquisition.
- Events requiring a post-hoc class-specific rule after predictions are seen.

## Deduplication Rules

Before scoring, compare every candidate against the 1,419 frozen incidents using:

- class/category;
- start/end temporal overlap;
- affected ASN(s);
- affected prefix(es);
- source event IDs;
- event descriptions and public reports;
- country/network/operator.

Classify each candidate as `NEW_INDEPENDENT_EVENT`, `POSSIBLE_SAME_EVENT`, `CONFIRMED_SAME_EVENT`, or `REVIEW_REQUIRED`. Only `NEW_INDEPENDENT_EVENT` records may enter the locked confirmation cohort.

## Confirmation Cohort Lock

The final cohort should be frozen as:

- source-native roster;
- normalized roster;
- overlap audit;
- RouteViews acquisition manifest;
- feature manifest;
- exclusion log;
- SHA-256 checksums.

Only after this freeze should the frozen model be applied.
