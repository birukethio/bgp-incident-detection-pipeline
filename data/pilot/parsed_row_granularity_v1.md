# Parsed Row Granularity v1

The pilot parser uses `bgpdump -m` on RouteViews MRT UPDATE `.bz2` files.

One parsed CSV row represents one prefix-level BGP UPDATE observation emitted by `bgpdump -m`: either one announced prefix with AS_PATH and path attributes, or one withdrawn prefix.

This is not yet a model feature row. Feature rows will later aggregate these raw observations into 5-minute windows.

Important granularity distinction:

- A single BGP UPDATE message may carry multiple announced or withdrawn prefixes.
- `bgpdump -m` expands those into separate pipe-delimited rows, one per prefix/NLRI observation.
- Therefore `total_prefix_level_observations` counts parsed rows, not final ML samples.
- `bgp_update_messages` in the pilot count table uses the parser-emitted row count as the observable message-record count because the original MRT message grouping is not preserved by `bgpdump -m` output.
