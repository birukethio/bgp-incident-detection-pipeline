# Data Acquisition Reproducibility v1

## Recovered Data Sources

- Cloudflare-derived source records supplied final Hijack, Leak, and Outage candidate pools.
- RouteViews UPDATE archives supplied public BGP observations; RIPE RIS was not used for the final feature extraction path.
- CAIDA AS-relationship snapshots supplied historical AS relationship context.
- Historical RPKI/VRP data supplied ROV validity features.
- Label provenance is externally sourced and documented in `experiments/label_provenance_audit_v1/`.

## Corpus Accounting

The final corpus is the frozen v2 roster: 1,419 incidents with 473 Hijack, 473 Leak, and 473 Outage. The split is 993 TRAIN, 213 Validation, and 213 Final Holdout. The corpus balancing audit documents raw Cloudflare-derived source records of 112,290 Hijack, 125,051 Leak, and 804 Outage before quality and balancing steps, and identifies the initial selection gaps.

## Endpoint and Code Path Evidence

Cloudflare endpoint and source-label tracing is documented in `experiments/label_provenance_audit_v1/cloudflare_label_entry_trace_v1.csv` and `.md`. Local collection code includes `cloudflare_incidents/fetch_cloudflare_all_incidents_to_2026_01.mjs`, `cloudflare_incidents/fetch_cloudflare_leaks_range.mjs`, and outage roster builders. Where exact API pagination parameters are not recoverable from preserved logs, this audit marks them as documented limitation rather than re-creating them.

## Limitations

The collected-corpus distribution should not be described as global Internet-wide prevalence. The original first-pass Hijack/Leak sampling script is not uniquely recovered, but final roster membership and v2 duplicate remediation are preserved.
