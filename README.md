# BGP Incident Classification and Ranking

This repository contains the completed doctoral Praxis pipeline for classifying and ranking three BGP incident types: **Hijack**, **Leak**, and **Outage**. The final architecture operates directly on incident evidence; the earlier experimental `Normal` versus `Incident` gate was not adopted as part of the final model.

## Final Architecture

The frozen analytical path is:

1. Historical RouteViews BGP UPDATE evidence is reconstructed into five-minute analytical windows.
2. Each window is represented by the frozen **V4 74-feature schema**:
   - 44 Behavioral BGP features
   - 14 historical CAIDA AS-relationship features
   - 16 historical RPKI/ROV features
3. A five-model Level-1 XGBoost ensemble produces Hijack, Leak, and Outage probabilities for each window.
4. Incident-level temporal summary features are constructed from the Level-1 probability sequence.
5. The retrospective Level-2 XGBoost stacker produces the final incident classification and class ranking.

The historical Normal-versus-Incident experiments are retained for auditability as a negative/auxiliary research branch. They are not the deployed final architecture and no Stage-1 threshold is used in the final Hijack/Leak/Outage classifier.

## Frozen Corpus

The authoritative incident corpus is Roster v2:

`data/roster_v2/frozen_incident_roster_v2.csv`

| Category | Incidents |
|---|---:|
| Hijack | 473 |
| Leak | 473 |
| Outage | 473 |
| **Total** | **1,419** |

The corpus was frozen after duplicate remediation, timestamp review, source normalization, and quality checks. Historical/developmental rosters remain in the repository only for provenance and must not be substituted for Roster v2.

## Frozen Partitions

Partitions were assigned once at the incident level using seed `20260828`. All five-minute windows inherit their incident's partition.

| Partition | Hijack | Leak | Outage | Total |
|---|---:|---:|---:|---:|
| TRAIN | 331 | 331 | 331 | 993 |
| Validation | 71 | 71 | 71 | 213 |
| Final Holdout | 71 | 71 | 71 | 213 |
| **Total** | **473** | **473** | **473** | **1,419** |

The authoritative assignment is `data/partitions_v2/frozen_partition_manifest_v2.csv`. The independent experimental unit is `incident_uid`; partitions are never reassigned after feature extraction.

## Evaluation Integrity

- Model development and grouped/nested cross-validation use TRAIN only.
- Validation is a separately controlled confirmation partition.
- The sealed Final Holdout contains 213 incidents and was evaluated once after the architecture was frozen.
- The Final Holdout was not used for feature selection, ablation decisions, balancing, hyperparameter tuning, threshold selection, or model selection.
- Post-Holdout audits and sensitivity analyses are additive and do not replace or reinterpret the terminal result.

## Terminal Final Holdout Result

| Metric | Value |
|---|---:|
| Macro F1 | 0.920177 |
| Macro F1 95% CI | [0.880117, 0.954402] |
| Top-1 accuracy | 0.920188 |
| Top-2 accuracy | 0.990610 |
| Mean reciprocal rank | 0.958529 |

Per-class F1 scores were `0.877698` for Hijack, `0.904110` for Leak, and `0.978723` for Outage. These values are frozen and authoritative.

## Project Status

The primary Praxis experiment is complete. The repository includes:

- corpus and partition provenance;
- RouteViews acquisition and parsing code;
- five-minute Behavioral feature construction;
- historical CAIDA and RPKI/ROV enrichment;
- V1-V4 and feature-family ablation studies;
- Random Forest and XGBoost comparisons;
- TRAIN grouped/nested evaluation and forensic leakage checks;
- Validation and terminal Final Holdout records;
- calibration, error, latency, provenance, and reproducibility audits;
- TRAIN-only retrospective early-classification/TTI sensitivity analyses;
- publication-ready tables, figures, and manuscript deliverables.

There are no unfinished "next pipeline steps" for the frozen Praxis experiment. Future research directions are documented separately and are not required to reproduce the reported study.

## Repository Guide

| Path | Contents |
|---|---|
| `config/` | Frozen schemas, model configurations, and evaluation protocols |
| `src/bgp_incident_detection/` | Reproducible pipeline and audit implementations |
| `tests/` | Automated integrity and reproducibility checks |
| `data/` | Compact rosters, manifests, summaries, and versioned result artifacts |
| `docs/` | Evidence audits, methodology records, captions, and result tables |
| `experiments/` | Additive forensic and sensitivity analyses |
| `external_validation/` | Source-separated Level-1 validation protocols and records |
| `figures/` | Publication-ready Chapter 3-5 figures |
| `notebooks/` | Versioned experimental notebooks |
| `deliverables/` | Final manuscript and related deliverables |

## Reproducibility

Run the repository checks from the project root:

```bash
pytest -q
```

The current release passes **390 tests**. Authoritative model/configuration details and software environments are recorded in the versioned manifests under `config/`, `data/`, `docs/`, and `experiments/reproducibility_audit_v1/`.

The original fitted Level-2 binary was not persisted historically. Its methodology and configuration are procedurally specified, while the exact originally fitted object is not recoverable. For that reason, source-separated external validation was limited to the reproducibly preserved Level-1 path; no claim of external Level-2 confirmation is made.

## Data and Security

Raw RouteViews MRT archives, large generated feature matrices, temporary caches, API credentials, and oversized serialized development models are intentionally excluded from Git. The repository retains compact provenance manifests, checksums, schemas, source URLs, code, and result summaries needed to audit the study without publishing local caches or secrets.

## Scope and Interpretation

The balanced corpus supports controlled comparison across Hijack, Leak, and Outage classes; it does not estimate global Internet-wide incident prevalence. Results are bounded by public-collector visibility, external label provenance, historical CAIDA/RPKI availability, and the retrospective nature of the Level-2 temporal stacker.
