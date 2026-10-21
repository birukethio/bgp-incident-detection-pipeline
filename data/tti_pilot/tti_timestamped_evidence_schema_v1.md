# TTI Timestamped Evidence Schema v1

One row represents one incident-relevant prefix-level BGP observation from `bgpdump -q -m` for a pilot MRT file. Unlike the compact enrichment evidence store, this pilot evidence preserves `bgp_timestamp_utc`.

Columns:

- incident_uid
- incident_id
- category
- partition
- source_mrt_filename
- collector
- bgp_timestamp_utc
- peer_ip
- peer_asn
- message_update_type
- announcement_or_withdrawal
- prefix
- as_path
- origin_asn
- next_hop
- communities
- med
- local_pref
- atomic_aggregate
- aggregator
- normalized_as_path

This evidence is not a model feature row and is not a completed five-minute window.
