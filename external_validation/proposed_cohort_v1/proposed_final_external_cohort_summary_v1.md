# Proposed prospective Level-1 external cohort v1

Scope: **Prospective source-separated external validation of the frozen reproducibly preserved Level-1 BGP incident-classification path.**

This proposal was built after the protocol freeze and without model inference, feature inspection, Validation access, Final Holdout access, or Level-2 use.

## Accounting

- Candidates reviewed: 37
- Source-screening eligible: 18
- LABEL_AMBIGUOUS: 0
- SOURCE_INSUFFICIENT: 0
- TIMESTAMP_REVIEW: 9
- ORIGINAL_CORPUS_OVERLAP: 0
- PILOT_EXCLUDED: 9
- ARCHIVAL_COVERAGE_INELIGIBLE: 1
- Proposed cohort: 18 (3 Hijack, 5 Leak, 10 Outage)

## Distribution

- Source distribution: {'BGPHorizon': 2, 'IODA': 10, 'Kentik': 1, 'MANRS': 3, 'Qrator': 1, 'Qrator Labs': 1}
- Event-year distribution: {2019: 1, 2020: 1, 2021: 11, 2022: 1, 2023: 1, 2026: 3}
- One-source dominance: YES (55.6%); this is expected to be driven by IODA outage records and is a documented limitation.
- One-period dominance: YES (61.1% in the largest year).

The target of roughly 10 events per class was not forced. Timestamp-inadequate and pilot events remain visible as exclusions. Cohort membership was determined only by frozen source, label, timestamp, overlap, and archive criteria.
