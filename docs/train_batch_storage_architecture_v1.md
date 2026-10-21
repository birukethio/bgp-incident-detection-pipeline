# TRAIN Batch Storage Architecture v1

This architecture solves a storage/resource problem without changing the scientific dataset.

The 993 TRAIN incidents remain unchanged. No incidents are removed, no windows are capped, no windows are downsampled, no sample weights are applied, and the frozen 44 behavioral features remain unchanged.

## Storage Classes

Permanent artifacts:

- source manifests
- volume-aware batch plan
- MRT URL, filename, checksum, and status metadata
- compact 5-minute behavioral feature rows
- incident summaries
- quality-gate results
- processing logs
- parser version, code commit, feature schema version, and incident/window mappings

Temporary/cache artifacts:

- compressed RouteViews MRT UPDATE binaries for the current processing scope
- decompressed or parser-stream state
- large filtered observation scratch files

Temporary artifacts may be removed only after the compact feature output and quality gate for a batch are verified.

## Directory Configuration

The directory roots are defined in `config/storage_config_v1.yaml`.

Default local profile:

- `RAW_MRT_ROOT`: `data/raw_mrt/train_batches`
- `PARSED_TEMP_ROOT`: `data/parsed_mrt/train_batches_temp`
- `FEATURE_OUTPUT_ROOT`: `data/train_scale/features`
- `AUDIT_OUTPUT_ROOT`: `data/train_scale`
- `CACHE_ROOT`: `data/cache/train_mrt`

External drive example:

- root: `/Volumes/<external-volume>/bgp-praxis-data/`
- children: `raw_mrt/`, `parsed_temp/`, `cache/`, `features/`, `audit/`

The pipeline must not hard-code a user home directory. A mounted external SSD can be used by switching the configured roots.

## Disk Safety Gate

Before any batch download, calculate:

`required_free_bytes = estimated_compressed_bytes + estimated_peak_temp_bytes + estimated_feature_bytes + safety_reserve_bytes`

where:

- `estimated_peak_temp_bytes = estimated_compressed_bytes * parser_temp_factor`
- `estimated_feature_bytes = estimated_compressed_bytes * feature_output_factor`
- `safety_reserve_bytes` is a fixed reserve to avoid filling the filesystem

The first config uses:

- `parser_temp_factor = 1.25`
- `feature_output_factor = 0.02`
- `safety_reserve_bytes = 5 GiB`

These are operational safety parameters only. They are not ML sampling rules.

## Volume-Aware Batching

The existing 50-incident batches are useful for human tracking but do not correspond to equal disk volume. Full TRAIN planning estimated about 35.95 GiB of compressed MRT files before parsed scratch and feature outputs, while local free disk was about 32 GiB.

Volume-aware batches target a configurable compressed-MRT budget, initially documented as `target_mrt_bytes_per_batch = 2 GiB`. The target is a processing-resource limit, not a window cap or sampling decision.

Within each processing scope, each MRT URL is downloaded once:

`MRT URL -> one local cached file -> multiple incident consumers`

The URL-to-consumer mapping, checksum, parser version, source commit, feature schema version, batch ID, incident UID, and window IDs are persisted so outputs remain reproducible after raw/intermediate cleanup.

## Streaming Parser Design

Avoid giant persistent bgpdump text outputs.

Use:

`compressed MRT -> bgpdump stdout -> parser/filter -> per-window aggregate -> compact features`

Do not write full global RouteViews text output to disk. Only incident-relevant observations may be written to temporary scratch files, and even those should be removed after batch verification when configured.

## Lifecycle

One batch:

1. Determine required MRT files.
2. Check free disk and required disk.
3. Download only current-batch MRT files.
4. Verify checksum and compression integrity.
5. Stream parse MRT files.
6. Filter incident-relevant observations.
7. Create 5-minute windows.
8. Calculate the frozen 44 behavioral features.
9. Write compact permanent feature and audit outputs.
10. Verify batch output.
11. Remove temporary parsed files.
12. Optionally remove raw MRT files according to retention policy.

Persisted statuses:

`PLANNED`, `DOWNLOADING`, `DOWNLOADED`, `PARSING`, `FEATURED`, `VERIFIED`, `CLEANED`, `REVIEW`, `FAIL`

Successful restarts should skip already verified batches and should not regenerate validated outputs unless explicitly requested.
