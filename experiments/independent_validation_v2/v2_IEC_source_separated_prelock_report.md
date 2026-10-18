# V2 IEC Source-Separated Prelock Report

Generated UTC: 2026-09-15T14:39:33.776330+00:00

This report applies deterministic, prospective source-native label mapping rules to the existing non-Cloudflare IEC candidate pool. No model output was used.

## Required Answers
1. Events surviving IEC criteria: 63
2. H/L/O counts: Hijack=16, Leak=17, Outage=30
3. Independent sources providing labels:
   - Hijack / BGPHorizon: 1
   - Hijack / MANRS: 10
   - Hijack / NOG/NANOG: 1
   - Hijack / Qrator: 3
   - Hijack / RouteCause: 1
   - Leak / Kentik: 1
   - Leak / MANRS: 5
   - Leak / Qrator: 11
   - Outage / IODA: 30
4. All accepted source labels explicit: YES
5. Cloudflare-primary labels present: 0
6. Original 1,419 incidents present in accepted roster: 0
7. All accepted events reconstructable: YES
8. Underlying evidence overlap among accepted events:
   - MODERATE: 32
   - LOW: 30
   - HIGH: 1

## Candidate Accounting
- Starting candidates: 73
- Accepted: 63
- Excluded: 10
- Metadata-limited accepted events: 61
- RouteViews status counts: {'ROUTEVIEWS_AVAILABLE': 73}
- Original-corpus overlap status counts: {'NEW_INDEPENDENT_EVENT': 73}

## Exclusions By Reason
- EXCLUDE_AMBIGUOUS_SOURCE_LABEL: 10

## Interpretation Boundary
Label-source independence means the IEC label was taken from a non-Cloudflare source-native record. It does not imply complete underlying evidence-source independence: several accepted Hijack/Leak sources use BGP routing observations that conceptually overlap with Behavioral, CAIDA, or RPKI/ROV feature evidence.

Disposition: `READY_FOR_AUTOMATED_IEC_LOCK`
