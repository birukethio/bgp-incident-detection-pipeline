# Natural Distribution Provenance Audit v1

This additive audit estimates the observed class distribution of the collected, source-validated incident corpus before deliberate 473/473/473 balancing. It does **not** claim global Internet-wide incident prevalence.

## Definition

**Observed Natural Distribution** = class proportions of usable, source-validated collected incidents before deliberate balancing.

For this repository, the usable pre-balancing counts are:

| Class | Count | Proportion |
|---|---:|---:|
| Hijack | 112,290 | 0.472176 |
| Leak | 125,051 | 0.525835 |
| Outage | 473 | 0.001989 |
| Total | 237,814 | 1.000000 |

## Provenance Findings

- Raw all-available Cloudflare-derived roster: 112,290 Hijack, 125,051 Leak, and 804 Outage candidate records.
- Outage has a separate quality-controlled lineage: 804 all-available records, 770 deduplicated QC records, and 473 recommended final outage-pool records.
- Hijack and Leak sampling audit records all raw candidates as eligible before deliberate stratified selection.
- Full-universe Hijack/Leak duplicate collapse was not found as a separate artifact. Duplicate remediation is documented for the sampled balanced v2 corpus: 56 TRUE_DUPLICATE groups, removing 96 sampled incidents before 96 replacements restored balance.
- RouteViews-insufficient TTI exclusions belong to the later early-horizon TTI analysis and were not used to define the pre-balancing natural distribution.

## Suitability

The pre-balancing corpus is suitable for an **observed collected-corpus natural-distribution sensitivity analysis** with caveats:

- It is source-observed and repository-grounded.
- It is not a claim about real-world Internet prevalence.
- It is not a complete feature-ready evaluation corpus for all 237,814 incidents.
- Therefore, this phase uses a safe TRAIN-only class-prior reweighted sensitivity view rather than creating a new final generalization claim.

## Source Artifacts

See `natural_distribution_source_inventory_v1.csv` for SHA-256 checksums.
