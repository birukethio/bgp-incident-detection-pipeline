# Locked Confirmation Roster Rules v1

STATUS: LOCKED_PENDING_EXECUTION

## Purpose

These rules define how an independent confirmation roster may be constructed before any model scoring occurs. They apply only to the future independent confirmation experiment and do not modify the frozen 1,419-incident Praxis corpus, TRAIN, Validation, Final Holdout, TTI results, prior-shift results, provenance audit, figures, or manuscript text.

## Primary and Secondary Sources

Primary sources:

- Hijack and Leak: RouteLLM verified routing-anomaly benchmark.
- Outage: IODA outage events or curated IODA outage/shutdown records.

Secondary corroboration/adjudication sources:

- MANRS / GRIP.
- Operator writeups and public postmortems, including but not limited to Kentik, ThousandEyes, BGPmon, RIPE Labs, NOG posts, and public ISP reports.

Secondary sources may corroborate, clarify, or adjudicate a candidate event, but they may not weaken the inclusion rules.

## Label Terminology

`SOURCE_LABEL` is the event type or category provided by the independent source before local normalization.

`FINAL_ADJUDICATED_LABEL` is the locked label used for evaluation after source-label review, taxonomy mapping, deduplication, overlap review, and metadata-quality checks.

The pipeline must preserve both fields. A source label may be rejected or marked ambiguous, but it may not be silently overwritten.

## Inclusion Rules

An event may enter the locked confirmation roster only if all conditions hold:

1. The candidate source is not Cloudflare and does not use a Cloudflare event ID as the event definition.
2. The event has a clear `SOURCE_LABEL` that can be mapped to Hijack, Leak, or Outage without using model predictions.
3. A `FINAL_ADJUDICATED_LABEL` is assigned before model scoring.
4. The event has a UTC-normalizable documented start time.
5. The event has either a documented end time, a documented duration, or a predeclared source-specific active-window rule.
6. The affected ASN, network, or operator is available.
7. For Hijack, affected prefix information is required unless an explicit public source shows the event is a path/origin hijack whose affected prefix can be recovered from the independent record.
8. For Leak, leak ASN or leaking AS path segment is required; exact prefixes are preferred but not mandatory if the source provides sufficient ASN/path/time evidence for RouteViews reconstruction.
9. For Outage, the event must be ASN/network scoped or otherwise mappable to RouteViews-observable network reachability. Purely geographic, traffic-only, or platform-only outage annotations are excluded unless an affected ASN/network can be identified.
10. RouteViews evidence must be reconstructable for the event interval.
11. The event must be classified as `NEW_INDEPENDENT_EVENT` after overlap checks against the frozen 1,419-event corpus.
12. The event must pass V4 feature-generation feasibility before scoring.

## Exclusion Rules

Exclude an event before scoring if any condition holds:

- It is a confirmed same real-world event already present in the frozen 1,419-event corpus.
- It lacks a usable start time.
- It lacks required ASN/network metadata.
- It lacks required prefix/path metadata for the class-specific rule.
- It cannot be reconstructed from RouteViews under the frozen acquisition/evidence method.
- The source label is ambiguous and cannot be adjudicated without model predictions.
- The event class would need to be inferred locally from the same variables used as model features.
- The event is only a Cloudflare corroboration of an existing source, rather than a source-separated record.
- Licensing/access restrictions prevent reproducible dissertation use.

## Overlap Rules

Compare each candidate to the existing 1,419-event corpus using:

- candidate source event ID;
- event class;
- start and end time overlap;
- affected ASN(s);
- affected prefix(es);
- affected country/network/operator;
- source description/title;
- public incident report URL;
- RouteViews event signature where available.

Classify overlap as:

- `NEW_INDEPENDENT_EVENT`
- `POSSIBLE_SAME_EVENT`
- `CONFIRMED_SAME_EVENT`
- `REVIEW_REQUIRED`

Only `NEW_INDEPENDENT_EVENT` records may enter the locked evaluation roster.

## Deduplication Rules

If multiple independent sources describe the same real-world event, keep one canonical confirmation event and preserve all corroborating sources in provenance fields. Prefer the record with the strongest source provenance, clearest timing, best ASN/prefix completeness, and most reproducible public evidence.

Do not create multiple confirmation incidents from the same real-world incident unless the source evidence clearly identifies distinct independent events with distinct time windows and affected networks.

## Temporal Eligibility

All event windows must be UTC-normalized before scoring. The incident window must be frozen before model scoring. No event window may be shortened, extended, or reinterpreted after observing model predictions.

For Hijack/Leak, source-reported event-active evidence should be used where available. Silent gaps may be classified according to the frozen incident-window policy, not a post-hoc rule.

For Outage, source-documented outage intervals are eligible when they represent network reachability loss or other RouteViews-observable outage behavior.

## RouteViews Evidence Requirement

Each candidate must have:

- a RouteViews collector/acquisition plan;
- a file availability audit;
- a parsing/reconstruction audit;
- evidence that the event interval can generate frozen V4-compatible features;
- a failure classification if reconstruction is not possible.

Events failing this requirement are not scored and must remain in the failed/excluded incident ledger.

## Ambiguity Handling

Ambiguous events are marked `REVIEW_REQUIRED` and excluded from the locked confirmation roster unless adjudication is completed before scoring. Adjudication may use source documentation, secondary corroboration, metadata completeness, and independent routing evidence, but may not use model predictions.

## Adjudication Procedure

For each candidate:

1. Preserve source-native fields.
2. Map `SOURCE_LABEL` to candidate normalized class.
3. Check metadata completeness.
4. Run overlap/dedup review.
5. Use secondary sources only to corroborate or clarify.
6. Assign `FINAL_ADJUDICATED_LABEL`.
7. Freeze the event roster with checksums.
8. Only then generate features and score.

## One-Time Rule

After the independent confirmation roster is locked, no additional events may be acquired or added except through a separately versioned protocol before any scoring. After scoring begins, no event additions, exclusions, relabeling, or timing edits are allowed except predeclared technical-failure handling.
