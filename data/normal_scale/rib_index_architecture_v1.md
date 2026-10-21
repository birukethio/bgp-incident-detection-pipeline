# RouteViews RIB Index Architecture v1

## Selected Method

Streaming `bgpdump -q -m` into a persistent relational index was selected for this step. The index is target-aware: each cached RIB is parsed once for the benchmark targets required by that RIB, and subsequent candidate screening performs SQL lookups instead of rescanning raw RIB files.

DuckDB is not installed in the current Python environment, so this run uses the standard-library SQLite backend with the same relational schema shape.

Database path: `data/cache/routeviews_rib/index/rib_index.sqlite`

## Tables

`rib_routes(collector, rib_timestamp, prefix, origin_asn, peer_asn, as_path, source_file, target_kind, target_value)`

`rib_index_metadata(collector, rib_timestamp, source_file, checksum, index_status, rows_indexed, started_at, completed_at, elapsed_seconds, parser, parser_version, raw_size_bytes, notes)`

## Lookup Patterns

- ASN lookup: `collector + rib_timestamp + target_kind='asn' + target_value` returns route count, prefixes, peers, origins, and AS paths.
- Prefix lookup: `collector + rib_timestamp + prefix` returns origin ASNs, peer ASNs, and AS paths.

## Resumability

A rerun computes each raw RIB SHA-256 checksum and skips an already indexed RIB when the metadata checksum and `INDEXED` status match. Raw binary RIB files are never modified and are not copied into the database.

## Scope

This is not a full global RIB materialization. It indexes only the target evidence needed for the existing 12-candidate benchmark. No UPDATE MRT files are downloaded, no Normal labels are created, and no Validation/Holdout data is accessed.
