# Prospective Source-Separated External Validation Protocol Draft v1

Status: `DRAFT_PENDING_PILOT_RECONSTRUCTION_VERIFICATION`

Created UTC: 2026-09-18T20:39:33.407192+00:00

## Separation from the original study

The original 1,419-incident experiment, its TRAIN/Validation/Final Holdout partitions, frozen feature definitions, and terminal Final Holdout results remain authoritative and immutable. No external incident may be used for training, tuning, calibration, threshold selection, feature revision, or model selection.

## Prospective chronology

1. Lock nine engineering-pilot incidents from historical non-Cloudflare candidates.
2. Permanently exclude those pilot incidents from any final external roster.
3. Verify exact RouteViews-to-V4 reconstruction and frozen Level-1 inference on the pilot.
4. Freeze the executable reconstruction runner, schemas, checksums, and this protocol.
5. Only after that freeze, collect and lock a new final external cohort.
6. Run the frozen Level-1 path once and retain every reconstruction and prediction outcome.

The historical 73-candidate/63-incident IEC roster is not represented as prospectively selected under this protocol.

## Reproducible classifier scope

External inference is limited to the verified reconstructed five-model Level-1 XGBoost ensemble and frozen mean incident aggregation. The originally fitted Level-2 artifact was not persisted. No Level-2 refit or substitute is permitted.

## Inclusion criteria for the future final roster

- Non-Cloudflare source-native Hijack, Leak, or Outage label.
- Traceable primary or strong secondary source.
- Sufficient time and ASN/prefix/entity metadata for RouteViews reconstruction.
- No overlap with the original 1,419 incidents.
- Not one of the nine pilot incidents.
- Not used in any model development or engineering verification.
- Deterministic class mapping fixed before model output is viewed.

## Exclusion criteria

- Ambiguous or mixed class without deterministic mapping.
- Documentation too vague for reconstruction.
- Cloudflare-only or Cloudflare-derived labeling.
- Original-corpus overlap.
- Pilot membership.
- Model output used in candidate selection or adjudication.

## Required reporting

Candidate count, accepted count, reconstruction count, inference count, and reconstruction yield are reported separately. Performance metrics use only incidents reaching inference, while failures remain visible in the exclusion and reconstruction ledgers.
