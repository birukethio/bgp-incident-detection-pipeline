# Independent Validation Execution Summary v1

## Status

`INDEPENDENT_VALIDATION_INCONCLUSIVE`

## Execution Boundary

This run followed the locked pre-evaluation protocol until a required source-availability gate failed. No model scoring was performed. No model was retrained, tuned, calibrated, or modified. No TRAIN, Validation, Final Holdout, TTI, provenance, prior-shift, manuscript, figure, table, or previous experimental artifact was modified.

## Pre-Scoring Checks

- Lock checksum verified: PASS.
- Locked artifact checksum verification: 20/20 MATCH.
- Validation accessed: NO.
- Final Holdout accessed or recomputed: NO.
- Model scoring performed: NO.

## Source Gate Outcome

The locked protocol requires RouteLLM as the primary independent Hijack/Leak source and IODA as the primary independent Outage source.

RouteLLM source-native event records were not available for construction of the confirmation roster:

- No local RouteLLM event roster was found.
- The arXiv paper/source package was inspected for repository/dataset links.
- The paper/source confirms a 232-event benchmark and open-source intent, but no usable event-roster URL was present in the inspected source package.
- Exact GitHub repository searches for the RouteLLM BGP benchmark returned zero matching repositories.

Because RouteLLM is the locked primary Hijack/Leak source, replacing it with MANRS/GRIP/operator writeups would deviate from the lock. Scoring only IODA Outage candidates would also violate the locked all-class H1/H2/H3 confirmation design.

## Result

The evaluation stopped before roster construction, RouteViews reconstruction, feature generation, and model scoring.

## Required Final Questions

1. How many genuinely independent incidents were evaluated? 0.
2. What sources supplied them? None; RouteLLM source-native event roster was unavailable and IODA was not acquired after the all-class gate failed.
3. Was any event duplicated from the existing 1,419-event corpus? No event-level comparison was possible because no accepted candidate roster was constructed.
4. Did all 20 frozen artifacts match the preregistered checksums? Yes, 20/20 matched.
5. Was H1 supported? Inconclusive; not executed.
6. Was H2 supported? Inconclusive; not executed.
7. Was H3 supported? Inconclusive; not executed.
8. What were the paired differences and 95% CIs? Not computed.
9. Which class generalized best? Not evaluated.
10. Which class generalized worst? Not evaluated.
11. What were the dominant error modes? Not evaluated.
12. Did performance materially change relative to the Cloudflare-derived evaluation? Not evaluated.
13. What does this imply about source dependence? No empirical conclusion can be drawn; the independent source roster could not be constructed under the lock.
14. What conclusions remain defensible? The frozen model/artifact lock is intact, and the protocol appropriately prevented a post-hoc source substitution.
15. What claims must be narrowed? Any claim of independent RouteLLM/IODA confirmation must not be made until the source-native event roster is acquired and evaluated under the locked rules.
