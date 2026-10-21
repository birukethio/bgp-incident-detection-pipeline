# Full TRAIN TTI Summary v1

**TRAIN-ONLY RETROSPECTIVE EARLY-CLASSIFICATION ANALYSIS**

Disposition: `FULL_TRAIN_TTI_REQUIRES_REVIEW`

The 9-incident pilot demonstrated that timestamp-preserving RouteViews observations can produce horizon-safe V4 rows. The full TRAIN artifacts currently preserved in the workspace do not contain equivalent timestamp-preserving observations for all 993 TRAIN incidents.

## Counts

- Eligible TRAIN incidents: 993
- Class balance: 331 Hijack / 331 Leak / 331 Outage
- Requested horizons: 30, 60, 120, 300 seconds
- Horizon rows planned: 3,972
- Horizon rows scored: 0
- Incidents requiring review: 993

## Why Scoring Stopped

The available full TRAIN compact evidence store is aggregated by `window_id + prefix + origin_asn + normalized_as_path + collector`. It preserves multiplicity through `observation_count`, but it does not preserve event-level observation timestamps inside each five-minute window. Therefore it cannot prove that a feature at the 30-second, 60-second, 120-second, or 300-second cutoff used only evidence available before that cutoff.

Using the five-minute evidence rows as a substitute would collapse the partial horizons into the already completed five-minute representation and would be a methodological change.

## Required Remediation Before Scale-Up Scoring

Recreate or recover timestamp-preserving TRAIN incident-relevant observations with at least:

- `incident_uid`
- `bgp_timestamp_utc` or `observation_timestamp`
- prefix
- origin ASN
- normalized AS path
- announcement/withdrawal indicator
- peer ASN
- collector/source MRT provenance

Then regenerate the 30/60/120/300-second V4 rows and rerun the compatibility/leakage gates before applying the reconstructed Level-1 ensemble.

## Available Evidence

- Compact evidence incident count: 993
- Compact evidence window count: 68031
- Compact evidence rows: 79526035
- Frozen TRAIN V4 rows: 68031
- Reconstructed Level-1 status: RECONSTRUCTED_LEVEL1_EQUIVALENCE_PASS

No figures with performance metrics were generated because there are no valid full TRAIN TTI scores to plot.

FULL_TRAIN_TTI_REQUIRES_REVIEW
