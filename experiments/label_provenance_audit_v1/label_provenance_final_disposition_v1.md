# Label Provenance Final Disposition v1

## Disposition

`PASS_WITH_DOCUMENTED_OVERLAP`

## Summary

- Final corpus audited: 1,419 incidents.
- Class counts: 473 Hijack / 473 Leak / 473 Outage.
- Direct target leakage found in V4 feature schema: 0.
- Review-required incidents: 0.
- Dominant relationship: `PARTIAL_EVIDENCE_OVERLAP`.

## Finding

The audit supports the conclusion that the final labels are externally sourced and preserved through normalization rather than inferred from the final model features. The model features are domain routing observations that can legitimately correlate with incident type. The observed overlap is therefore documented as conceptual/evidence overlap, not as direct target leakage.

## Stop Condition

No labels or experiments were changed.
