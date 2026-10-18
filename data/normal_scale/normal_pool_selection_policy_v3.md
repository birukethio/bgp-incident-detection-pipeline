# Normal Pool Selection Policy V3

This policy defines a TRAIN-only, pre-acquisition candidate pool for stable BGP Normal controls.
It does not create `NORMAL_VERIFIED` labels and does not download UPDATE MRT files.

## Invariant Rules

- Use only frozen Roster v2 incidents in the TRAIN partition.
- Preserve the 60-minute known-incident exclusion buffer.
- Preserve the 30-minute sustained-stability requirement.
- Use the same ASN/network as the associated incident; use the same prefix when a reliable prefix exists.
- Reject candidate periods that overlap known Hijack, Leak, or Outage incidents involving the same ASN or prefix.
- Require positive RIB visibility before UPDATE acquisition planning.
- Require stable expected origin evidence in before/after RIBs.
- Choose collectors from observability evidence, starting with `route-views2`.
- Treat UNKNOWN or REVIEW periods as unlabeled, not Normal.
- Do not require one matched Normal control for every incident.

## Controlled Scale Design

- Select approximately 20 Hijack-associated, 20 Leak-associated, and 20 Outage-associated TRAIN networks.
- Generate offset candidates at -1, +1, -3, +3, -7, +7, -14, +14, -21, +21, -30, and +30 days.
- RIB parsing in this design pass is capped at 0 evaluated candidates per associated incident/network.
- Candidates beyond the cap remain REVIEW until a later expansion run evaluates them.

## Leak-Specific Additions

- Leak controls require leak ASN/network RIB visibility before and after the candidate period.
- Leak controls require stable origin evidence even when exact affected prefix lists are unavailable.
- Prefixes must not be invented. When no source prefix exists, the candidate is evaluated using ASN/path-origin evidence.
- Obvious prefix deaggregation or path instability detected later in UPDATE behavior keeps a window UNKNOWN.

## Diversity And Dominance

- Candidate selection preserves year, ASN/network, country, duration, prefix count, and visibility diversity where possible.
- A configurable maximum accepted-candidate count per ASN/network should be set after reviewing this scale-design distribution.
- The maximum is intentionally not frozen in v3.

## Matched-Control Exceptions

- `Hijack:97511` remains `NORMAL_CONTROL_OBSERVABILITY_UNRESOLVED` and is not forced into the candidate pool.

## Methodological Meaning

A future Normal label must be positive evidence of stable route state, not simply absence of a known incident.
RIB state establishes that the route existed and the expected origin was stable; UPDATE behavior is later used to reject suspicious instability.
