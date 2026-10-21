# V2 IEC Execution Summary v1

Generated UTC: 2026-09-15T15:03:51.276900+00:00

## Status

`SOURCE_SEPARATED_IEC_INCONCLUSIVE`

## Protocol Gate Outcome

- Frozen IEC roster rows: 63
- Frozen IEC class counts: {'Outage': 30, 'Leak': 17, 'Hijack': 16}
- Locked artifact verification: PASS
- Implementation equivalence: `IMPLEMENTATION_EQUIVALENCE_FAIL`
- Model scoring performed: NO
- Validation accessed/recomputed: NO
- Original Final Holdout accessed/recomputed: NO

The execution stopped before RouteViews reconstruction and model inference because a frozen, verified IEC reconstruction/scoring implementation was not available, and no suitable non-IEC fixture was present to prove end-to-end implementation equivalence for the new source-native IEC events.

## Required Questions

1. Evaluable IEC incidents: 0 of 63; none were scored because implementation equivalence failed before reconstruction/inference.
2. Final H/L/O evaluable counts: Hijack=0, Leak=0, Outage=0.
3. Implementation equivalence passed: NO.
4. Frozen artifacts matched: YES.
5. External Macro F1 and 95% CI: NA, not executed.
6. Top-1, Top-2, MRR: NA, not executed.
7. Class-specific F1: NA, not executed.
8. Delta_H2 and paired CI: NA, not executed.
9. Delta_H3 and paired CI: NA, not executed.
10. Best/worst external source/class: NA, not evaluated.
11. Dominant external errors: NA, no predictions produced.
12. Descriptive comparison with original Final Holdout: not possible; original Final Holdout remains authoritative and unchanged.
13. Cloudflare label-source dependence implication: inconclusive; the source-separated roster is locked, but the frozen model was not executed.
14. Claims strengthened: source-separated roster construction and lock discipline are strengthened; performance generalization is not.
15. Claims narrowed: no source-separated external performance claim should be made until a verified IEC reconstruction/scoring implementation passes the equivalence gate and is executed once.

## Disposition

`SOURCE_SEPARATED_IEC_INCONCLUSIVE`
