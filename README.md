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

The Praxis research and its primary experimental evaluation are complete. This repository preserves the final code, frozen experimental configurations, result artifacts, quality and reproducibility audits, manuscript-ready tables, and supporting documentation. Earlier developmental experiments are retained for transparency and provenance but do not replace the authoritative final results. Any remaining extensions are future research opportunities rather than incomplete steps in the reported study.

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
| `notebooks/` | Versioned experimental notebooks |
| `deliverables/` | Final manuscript and related deliverables |

## Reproducibility

Run the repository checks from the project root:

```bash
pytest -q
```

The current release passes **390 tests**. Authoritative model/configuration details and software environments are recorded in the versioned manifests under `config/`, `data/`, `docs/`, and `experiments/reproducibility_audit_v1/`.

The original fitted Level-2 binary was not persisted historically. Its methodology and configuration are procedurally specified, while the exact originally fitted object is not recoverable. For that reason, source-separated external validation was limited to the reproducibly preserved Level-1 path; no claim of external Level-2 confirmation is made.

## Appendix E Reproducibility Artifacts

The following additive artifacts support the reproducibility inventory reported in Appendix E:

| Path | Purpose |
|---|---|
| `experiments/xgboost_feature_family_ablation_v1/` | Supplementary TRAIN-only, five-seed XGBoost feature-family ablation, paired bootstrap results, prediction archives, and plotting code |
| `experiments/level2_reconstruction_v1/` | Post-feedback reconstruction of the frozen Level-2 procedure and incident-by-incident comparison with the archived Final Holdout predictions |
| `experiments/historical_metadata_validity_audit_v1/` | Read-only audit of historical CAIDA and RPKI/ROV metadata selection and temporal-availability limitations |
| `data/modeling_k1/k1_incident_level_predictions_v1.parquet` | Preserved TRAIN incident-level K1 predictions used for paired architecture comparisons |

The controlled Level-2 reconstruction used Python `3.12.2`, XGBoost `3.4.1`, the frozen 74-column Level-2 schema, seed `20260828`, and the original `tree_method=hist`/`n_jobs=-1` implementation. It reproduced all 213 archived Final Holdout labels and rankings; the maximum absolute class-score difference was `1.1102230246251565e-16`. The resulting serialized object is explicitly labeled **Reconstructed Level-2 model - post-feedback reproducibility evaluation**. It is not the unavailable original serialized model and does not replace the frozen historical predictions or terminal Final Holdout result.

Verify the published artifact checksums from the repository root:

```bash
python - <<'PY'
from pathlib import Path
import hashlib
import pandas as pd

for manifest in [
    Path("experiments/xgboost_feature_family_ablation_v1/output_checksums_v1.csv"),
    Path("experiments/level2_reconstruction_v1/level2_reconstruction_output_checksums_v1.csv"),
]:
    rows = pd.read_csv(manifest)
    for row in rows.itertuples(index=False):
        path = manifest.parent / row.file
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        assert actual == row.sha256, f"checksum mismatch: {path}"
    print(f"PASS: {manifest}")
PY
```

The exact generation commands recorded by the experiments are:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python experiments/xgboost_feature_family_ablation_v1/run_xgboost_feature_family_ablation_v1.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python experiments/level2_reconstruction_v1/run_level2_reconstruction_v1.py
```

These runners intentionally refuse to overwrite preserved outputs. The XGBoost ablation additionally requires `data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1.parquet`, which is not published pending redistribution-permission review. Consequently, the repository provides auditable code, configurations, checksums, preserved predictions, and results, but does **not** claim complete fresh-clone reproduction of the ablation from its frozen input matrix. Raw MRT archives also remain excluded.

The Level-2 `.joblib` files use Python pickle-compatible serialization. Load them only from a trusted copy after verifying the SHA-256 values in `experiments/level2_reconstruction_v1/level2_reconstruction_output_checksums_v1.csv`. The standalone XGBoost JSON model is provided as the more portable model representation.

## Data and Security

Raw RouteViews MRT archives, large generated feature matrices, temporary caches, API credentials, and oversized serialized development models are intentionally excluded from Git. The repository retains compact provenance manifests, checksums, schemas, source URLs, code, and result summaries needed to audit the study without publishing local caches or secrets.

## Scope and Interpretation

The balanced corpus supports controlled comparison across Hijack, Leak, and Outage classes; it does not estimate global Internet-wide incident prevalence. Results are bounded by public-collector visibility, external label provenance, historical CAIDA/RPKI availability, and the retrospective nature of the Level-2 temporal stacker.
