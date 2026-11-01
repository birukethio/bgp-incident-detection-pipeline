# Historical Validity Audit: CAIDA and RPKI/ROV

## Disposition

`HISTORICAL_AVAILABILITY_CLAIM_CONTRADICTED_AS_WRITTEN`

The implementation used archived, date-indexed CAIDA and RIPE NCC RPKI data rather than present-day lookup APIs. However, it did not enforce that a selected file had been published by the exact BGP observation time. Same-month CAIDA selection and same-calendar-day VRP selection therefore introduced confirmed temporal-availability violations.

## Implemented Procedure

- CAIDA: select `YYYYMM01.as-rel2.txt.bz2` from the serial-2 archive using the UTC month of each five-minute window.
- RPKI: select five trust-anchor-specific `roas.csv.xz` files using the UTC calendar date of each window. If an exact date failed, search backward up to 30 days.
- ROV: load validated VRP CSV exports and compare observed prefix length and origin ASN against covering VRPs. The code did not reconstruct validation from `repo.tar.xz` objects and did not query a current validation API.
- Partition consistency: Validation and Final Holdout called the same mapping functions used for TRAIN.

## Coverage

| Partition | Windows | Incidents | CAIDA months | RPKI observation dates | RPKI file entries | RPKI fallback entries |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| TRAIN | 68,031 | 993 | 47 | 746 | 3,730 | 15 |
| Validation | 12,920 | 213 | 39 | 279 | 1,395 | 0 |
| Final Holdout | 14,906 | 213 | 40 | 263 | 1,315 | 5 |

All windows received CAIDA and RPKI feature rows. This is structural coverage, not proof of strict historical availability.

## Missing-Data Semantics

- Unknown CAIDA adjacency is counted as an unknown relationship, not silently treated as valley-free.
- A window without AS-path evidence has zero count features and undefined ratio/statistical features (`NaN`).
- RPKI `NOT_FOUND` means no covering VRP existed in the selected archive export.
- Missing or malformed prefix/origin evidence is `UNEVALUABLE`, not `NOT_FOUND`.
- No prefix-origin evidence produces zero counts, `NaN` ratios, and dominant-state code 0.
- Model pipelines median-imputed undefined numeric values using TRAIN-fitted imputers.

## Section 3.8 Replacement

CAIDA enrichment used the monthly CAIDA Inferred AS Relationships serial-2 file named for the UTC month of each five-minute BGP window (`YYYYMM01.as-rel2.txt.bz2`). RPKI/ROV enrichment used RIPE NCC historical `roas.csv.xz` validated-payload exports for five trust anchors, selecting the UTC calendar date of each window and, when an exact date was unavailable, searching backward for the nearest earlier archive date within 30 days. The TRAIN mapping contained 746 distinct observation dates and 3,730 trust-anchor file entries, comprising 3,715 exact-date entries and 15 fallback entries. The same date-mapping functions were applied to Validation and Final Holdout. These procedures used archived date-indexed metadata rather than present-day APIs; however, they did not compare each file's publication timestamp with the exact window timestamp. Consequently, the existing enrichment should be described as calendar-aligned historical reconstruction, not strict as-of historical availability. A strict no-future-information claim requires feature reconstruction using only files demonstrably published at or before each observation time.

## Appendix A and Citation Corrections

1. Keep the 14 CAIDA and 16 RPKI/ROV feature names and formulas unchanged.
2. Replace unqualified descriptions such as “historically available at the observation time” with “archived and aligned by UTC month/date under the implemented calendar-matching rule.”
3. Add the timing limitation above to the CAIDA and RPKI family notes.
4. Cite the CAIDA AS Relationships serial-2 dataset and date range used: https://www.caida.org/catalog/datasets/as-relationships/
5. Cite the RIPE NCC daily RPKI dump archive and its validated `roas.csv.xz` format: https://www.ripe.net/ripe/mail/archives/routing-wg/2024-January/004812.html
6. Cite RFC 6811 for the implemented Valid/Invalid/NotFound route-origin-validation semantics: https://www.rfc-editor.org/info/rfc6811/

## Remediation Boundary

The issue cannot be resolved by wording alone if the Praxis retains a strict no-future-information claim. A corrected analysis must select, per window and trust anchor, the latest archive artifact whose authoritative publication timestamp is not later than the window start; persist publication time, source URL, checksum, and fallback reason; reconstruct all 14 CAIDA and 16 RPKI/ROV features; and repeat model fitting and evaluation under the frozen architecture and hyperparameters. Because Final Holdout results have already been observed, a corrected rerun should be labeled a post-hoc remediation/sensitivity analysis unless a new untouched external evaluation cohort is reserved.
