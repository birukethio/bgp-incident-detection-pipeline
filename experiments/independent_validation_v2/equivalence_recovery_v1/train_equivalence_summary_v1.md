# TRAIN Equivalence Recovery Summary v1

Generated UTC: 2026-09-15T15:58:19.751504+00:00

## Fixture Recovery

- Artifact inventory rows: 14
- Frozen fixture incidents: 9
- Fixture classes: {'Hijack': 3, 'Leak': 3, 'Outage': 3}
- Fixture buckets: {'SHORT': 3, 'MEDIAN': 3, 'LONG': 3}

## Result

The project contains enough TRAIN-only reference artifacts to freeze a deterministic fixture set and define comparison targets through E6. It does not, by itself, establish equivalence, because no new IEC reconstruction/scoring implementation was run on those fixtures in this recovery step and no pre-existing side-by-side regenerated outputs were found.

## Recommendation

The recovered fixture set is suitable for a future implementation-equivalence run. The next controlled step would be to apply the new IEC execution implementation only to these TRAIN fixture incidents and compare against the frozen reference artifacts using `train_equivalence_tolerance_specification_v1.md`.

Disposition: `INSUFFICIENT_REFERENCE_ARTIFACTS`
