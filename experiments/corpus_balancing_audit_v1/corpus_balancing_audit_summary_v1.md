# Corpus Balancing Audit Summary v1

## Final Answer

The final 1,419-event Praxis corpus was deliberately balanced to 473 Hijack / 473 Leak / 473 Outage incidents. The recovered evidence shows that Hijack and Leak were selected from much larger Cloudflare-derived usable candidate pools using quality-stratified sampling, while the final usable Outage pool already contained 473 incidents and was retained in full. Confirmed duplicate groups were later remediated in v2, removing 96 noncanonical records and adding 96 replacements to restore exact class balance.

## Key Counts

| Stage                                      | Hijack | Leak   | Outage | Total  | Operation                                                                                                                                 |
| ------------------------------------------ | ------ | ------ | ------ | ------ | ----------------------------------------------------------------------------------------------------------------------------------------- |
| Raw Cloudflare-derived source records      | 112290 | 125051 | 804    | 238145 | Fetched available Cloudflare Radar BGP/outage records through 2026-01; these are source records, not yet class-balanced corpus incidents. |
| Documented deduplication/source validation | 112290 | 125051 | 770    | 238111 | Outage deduplication documented; full-universe Hijack/Leak duplicate collapse artifact not found.                                         |
| Usable pre-balancing candidate pool        | 112290 | 125051 | 473    | 237814 | Observed collected-corpus distribution before deliberate balancing.                                                                       |
| Balanced v1 selected                       | 473    | 473    | 473    | 1419   | Quality-stratified Hijack/Leak sample plus 473 final Outage pool.                                                                         |
| Post-v2 duplicate collapse                 | 443    | 416    | 464    | 1323   | Confirmed duplicate groups removed logically while preserving source audit records.                                                       |
| V2 replacements added                      | 30     | 57     | 9      | 96     | Replacement incidents selected from unsampled candidate pools to restore class balance.                                                   |
| Frozen final v2 corpus                     | 473    | 473    | 473    | 1419   | Authoritative corpus used for final partitions and experiments.                                                                           |

## Exact Historical Selection Procedure Recovered

For Hijack and Leak, the recovered summary states:

> one high-quality incident per stratum first, then round-robin by next-best quality within strata until target count

The sample rows themselves preserve `sampling_stratum`, `quality_score`, and `quality_rank_within_stratum`, and notes describe the quality criteria. No evidence was found that simple random sampling was used for the first 473 Hijack/Leak samples.

## Natural Distribution Link

The observed pre-balancing collected-corpus proportions were Hijack 47.2176%, Leak 52.5835%, and Outage 0.1989%, as documented in `experiments/natural_distribution_v1/natural_distribution_accounting_v1.csv`. These proportions are a collected-corpus prior-shift sensitivity reference, not a claim about global Internet-wide BGP incident prevalence.

## Reproducibility Disposition

`REPRODUCIBLE_WITH_DOCUMENTED_GAPS`

The frozen roster, partition manifest, v2 duplicate/remediation plan, endpoint provenance, and I1 weighting formula are preserved and auditable. The main gap is that the executable first-pass Hijack/Leak stratified selection script and full-universe preselection duplicate-collapse artifact were not uniquely recovered.

## Manuscript Table DOCX

experiments/corpus_balancing_audit_v1/manuscript_tables_corpus_balancing_v1.docx
