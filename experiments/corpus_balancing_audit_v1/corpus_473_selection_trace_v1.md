# Corpus 473 Selection Trace v1

## Scope

This is an additive forensic audit. No corpus, partition, feature, model, Validation, Final Holdout, TTI, or manuscript artifact was modified.

## Raw Candidate Universe

- Hijack raw/source-validated usable candidates: 112,290.
- Leak raw/source-validated usable candidates: 125,051.
- Outage raw records: 804; documented usable final outage pool: 473.

The source/API trace is preserved in `experiments/label_provenance_audit_v1/cloudflare_label_entry_trace_v1.csv`:

| class  | cloudflare_endpoint                      | event_identifier_field | event_type_or_class_field                           | local_raw_artifact                                                        | final_label_entry_path                                                                                                                             | label_supplied_or_inferred                                                                                                                                           |
| ------ | ---------------------------------------- | ---------------------- | --------------------------------------------------- | ------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Hijack | GET /client/v4/radar/bgp/hijacks/events  | id                     | event_type                                          | cloudflare_incidents/raw_hijacks_all_available_to_2026-01_cloudflare.json | fetch_cloudflare_all_incidents_to_2026_01.mjs -> build_training_ready_all_cloudflare_roster.mjs / build_stratified_quality_leak_hijack_samples.mjs | Supplied by selected Cloudflare BGP hijack endpoint; local code hard-codes category after endpoint selection rather than inferring from features                     |
| Leak   | GET /client/v4/radar/bgp/leaks/events    | id                     | leak_type                                           | cloudflare_incidents/raw_leaks_all_available_to_2026-01_cloudflare.json   | fetch_cloudflare_all_incidents_to_2026_01.mjs -> build_training_ready_all_cloudflare_roster.mjs / build_stratified_quality_leak_hijack_samples.mjs | Supplied by selected Cloudflare BGP route leak endpoint; local code hard-codes category after endpoint selection rather than inferring from features                 |
| Outage | GET /client/v4/radar/annotations/outages | id                     | eventType plus outage.outageType/outage.outageCause | cloudflare_incidents/raw_outages_all_available_to_2026-01_cloudflare.json | fetch_cloudflare_all_incidents_to_2026_01.mjs -> build_quality_controlled_outage_roster.mjs -> build_clean_outage_asn_roster.mjs                   | Supplied by selected Cloudflare outage-annotation endpoint as eventType=OUTAGE; local code normalizes outage annotations and filters for usable ASN/network evidence |

## Historical 473-per-class Selection Procedure Recovered

For Hijack and Leak, the recovered artifact-level selection procedure is:

`one high-quality incident per stratum first, then round-robin by next-best quality within strata until target count`

The selected sample artifacts are:

- `cloudflare_incidents/stratified_quality_hijack_sample_473.csv`
- `cloudflare_incidents/stratified_quality_leak_sample_473.csv`

Both contain 473 selected rows with `sampling_stratum`, `quality_score`, and `quality_rank_within_stratum`. Notes embedded in the selected rows state that quality favored longer duration, stronger source/detector evidence, peer visibility, prefix count, and confidence metadata.

Outage did not require undersampling from the final usable pool: the documented final outage pool contained 473 events and all were retained.

## Selection Type

The preserved evidence supports this classification:

- Hijack: quality-stratified deterministic selection from the Cloudflare-derived usable candidate pool.
- Leak: quality-stratified deterministic selection from the Cloudflare-derived usable candidate pool.
- Outage: QC-filtered final pool retained at 473.

The artifacts do not support a claim that the final 473 Hijack or Leak events were simple random samples. No random seed for the initial 473 Hijack/Leak selection was found in the recovered sampling artifacts.

## v2 Duplicate/Replacement Procedure

The first balanced v1 roster was later remediated. Confirmed duplicate groups were canonicalized in `data/roster_v2/duplicate_canonicalization_plan.csv`:

- Confirmed TRUE_DUPLICATE groups: 56
- Records excluded from v2: 96
- Replacements added: 96

Class counts after duplicate collapse and replacements are recorded in `data/roster_v2/roster_v2_summary.csv`:

| metric                         | value |
| ------------------------------ | ----- |
| post_duplicate_collapse_Hijack | 443   |
| post_duplicate_collapse_Leak   | 416   |
| post_duplicate_collapse_Outage | 464   |
| replacements_needed_Hijack     | 30    |
| replacements_needed_Leak       | 57    |
| replacements_needed_Outage     | 9     |
| replacements_found_Hijack      | 30    |
| replacements_found_Leak        | 57    |
| replacements_found_Outage      | 9     |
| v2_total                       | 1419  |
| v2_Hijack                      | 473   |
| v2_Leak                        | 473   |
| v2_Outage                      | 473   |

## Reproducibility Gaps

- A full-universe Hijack/Leak duplicate-collapse artifact before the initial 473 selection was not found.
- The selected sample CSVs and summaries preserve the selected records and quality/stratum fields, but the executable script implementing the original quality-stratified selection was not uniquely recovered in this audit.
- Therefore, the exact final v2 roster is reproducible by preserved frozen artifacts and checksums, while the original first-pass 473 Hijack/Leak sampling algorithm is reconstructable only at the artifact/summary level.
