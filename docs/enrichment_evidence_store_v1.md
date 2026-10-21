# Enrichment Evidence Store v1

This dataset is the reusable compact evidence layer between RouteViews MRT parsing and enrichment feature calculation. It is generated during TRAIN-only streaming parses and is intended to prevent reparsing the full RouteViews MRT corpus for later CAIDA recalculation or RPKI/ROV enrichment.

## Row Grain

One row represents aggregated incident-relevant BGP evidence for one frozen 5-minute TRAIN window and one unique `(prefix, origin_asn, normalized_as_path, collector)` tuple. It is not one raw BGP UPDATE message and it is not one final model feature row. Repeated matching observations are collapsed into `observation_count`.

## Schema

- `window_id`: frozen TRAIN window identifier, unchanged from the V1 behavioral corpus.
- `incident_uid`: source incident UID inherited from the frozen TRAIN corpus.
- `window_start`, `window_end`: UTC 5-minute window bounds.
- `prefix`: announced or withdrawn prefix/NLRI when available.
- `origin_asn`: origin ASN extracted from the normalized AS_PATH when available.
- `normalized_as_path`: numeric AS path with consecutive prepending collapsed.
- `observation_count`: multiplicity of collapsed matching observations.
- `collector`: RouteViews collector that produced the source evidence.
- `source_mrt_count`: number of distinct MRT files contributing to the collapsed row.
- `processing_batch_id`: volume-aware TRAIN processing batch.
- `parser`, `parser_command`: parser provenance.
- `source_commit`: code commit used to create the evidence file.
- `behavioral_feature_version`, `caida_feature_version`: feature-version provenance.

## Reuse

CAIDA AS-relationship features use `normalized_as_path + window timestamp` to map AS transitions against the temporally selected CAIDA snapshot. Future RPKI/ROV enrichment can use the same evidence store because ROA validation is driven by `timestamp/window + prefix + origin_asn`. RPKI/ROV features are not created in this step.

## Partition Boundary

The evidence store is TRAIN-only for this phase. Validation and Final Holdout incidents are not accessed.
