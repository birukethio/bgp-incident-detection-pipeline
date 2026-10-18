from __future__ import annotations

import csv
import hashlib
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FREEZE = ROOT / "external_validation/protocol_frozen_v1"
SOURCE_RUNNER = ROOT / "external_validation/reconstruction/run_level1_external_pilot_v1.py"
SOURCE_FINALIZER = ROOT / "external_validation/reconstruction/finalize_level1_external_pilot_v1.py"
FROZEN_RUNNER = FREEZE / "runners/external_level1_reconstruction_runner_frozen_v1.py"
FROZEN_FINALIZER = FREEZE / "runners/external_level1_inference_finalization_runner_frozen_v1.py"
SCHEMA = ROOT / "data/tti_pilot/reconstructed_level1_v1/feature_schema_v4.json"
MODEL_DIR = ROOT / "data/tti_pilot/reconstructed_level1_v1"
PILOT_EXCLUSIONS = ROOT / "external_validation/manifests/pilot_exclusion_from_final_roster_v1.csv"
PILOT_CHANGES = ROOT / "external_validation/reconstruction/pilot_v1/pilot_engineering_change_log_v1.csv"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_head() -> str:
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()


def rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


def main() -> None:
    FREEZE.mkdir(parents=True, exist_ok=True)
    FROZEN_RUNNER.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(SOURCE_RUNNER, FROZEN_RUNNER)
    shutil.copy2(SOURCE_FINALIZER, FROZEN_FINALIZER)
    frozen_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

    protocol = f"""# Frozen Prospective External Level-1 Validation Protocol v1

**Frozen UTC:** {frozen_at}  
**Repository HEAD:** `{git_head()}`

## Scope

**Prospective source-separated external validation of the frozen reproducibly preserved Level-1 BGP incident-classification path.**

This prospective extension evaluates external generalization of the reproducibly preserved Level-1 classification path with frozen mean incident aggregation. It does not externally validate the historical retrospective Level-2 temporal stacker.

The original 1,419-incident Praxis corpus, Validation partition, Final Holdout, models, and reported results remain immutable and outside this extension.

## Frozen path

`RouteViews route-views2 reconstruction -> frozen five-minute windows -> 44 Behavioral + 14 historical CAIDA + 16 historical RPKI/ROV features -> preserved five-model Level-1 XGBoost ensemble -> arithmetic mean incident aggregation`

The reconstruction, feature-generation, historical-enrichment, frozen Level-1 inference, and mean incident-aggregation procedures were frozen before selection of the final prospective external-validation cohort.

## Eligibility

### Source and label

The primary/deciding label source must be non-Cloudflare and human-readable. Priority is: primary operator report; official organization statement; RIPE NCC/RIPE Labs; Internet Society/Pulse/MANRS; Kentik; Qrator; recognized routing-security organization; peer-reviewed paper; established research dataset; NANOG-equivalent operator material. Search summaries and LLM output are not ground truth.

Deterministic mappings:

- **HIJACK:** explicit BGP/prefix hijack, unauthorized or forged origin, or documented more-specific hijack.
- **LEAK:** explicit route leak, unintended export/transit, or propagation outside intended routing-policy scope.
- **OUTAGE:** explicit routing/connectivity outage, routing-related reachability loss, shutdown/disconnection, or externally observable reachability loss tied to the event.
- Mixed or unclear cases are `LABEL_AMBIGUOUS`.

### Historical-enrichment eligibility

Historical-enrichment eligibility. A candidate external incident is eligible for the final external-validation cohort only if the frozen pipeline can reproduce all three required evidence families using historically appropriate inputs consistent with the original methodology: Behavioral BGP evidence, CAIDA serial-2 AS-relationship context, and historical RPKI/ROV context. Archive availability is assessed before model inference and without reference to model predictions. If a required historical enrichment artifact is unavailable, the candidate is recorded as ARCHIVAL_COVERAGE_INELIGIBLE or REVIEW and is not made eligible through later-snapshot substitution, zero filling, inferred enrichment, or any prediction-dependent workaround.

Because exact historical enrichment is required, the prospective external-validation population is limited to incidents for which the frozen historical CAIDA and RPKI/ROV inputs remain reproducibly available. This is an archival data-availability boundary and may reduce representation of older incidents. It must not be interpreted as model failure.

## Frozen reconstruction rules

- Collector: `route-views2` only.
- Context: 60 minutes before and after each frozen active segment.
- Active segments: Outage uses documented start/end; Hijack/Leak spans at most 60 minutes remain one segment; longer spans use the first and last five-minute boundary segments, leaving the silent interior unknown.
- Retrieval: standard RouteViews filename generation; when standard URLs are absent, the official directory index may resolve actual nonaligned filenames overlapping the unchanged interval.
- Parsing: `bgpdump -q -m`; BGP timestamps determine five-minute membership.
- Relevance: exact affected prefix, affected/primary/leak ASN in peer/origin/AS_PATH, or complete leak-segment presence in AS_PATH.
- Features: exact frozen 44 Behavioral, 14 CAIDA serial-2, and 16 historical RPKI/ROV definitions.
- Schema: exactly 74 names/order/dtypes with schema SHA-256 `{sha256(SCHEMA)}`.
- Missing values: frozen NaN behavior and native XGBoost missing-value handling; no new imputation.
- Inference: arithmetic mean class probabilities from the five preserved Level-1 fold models.
- Incident aggregation: arithmetic mean class probability across all eligible reconstructed five-minute windows.

## Pilot engineering corrections

Pilot engineering corrections were limited to retrieval-layer compatibility and did not alter incident labels, event intervals, relevance predicates, analytical windows, feature definitions, enrichment rules, model parameters, aggregation rules, or prediction-based eligibility.

- `PILOT-FIX-001`: generic successful-download status normalization.
- `PILOT-FIX-002`: generic official-directory index fallback for legacy nonaligned RouteViews filenames; observations remain assigned by BGP timestamp.

## Fixed dispositions

`ACCEPTED`, `TIMESTAMP_REVIEW`, `LABEL_AMBIGUOUS`, `SOURCE_INSUFFICIENT`, `ORIGINAL_CORPUS_OVERLAP`, `PILOT_EXCLUDED`, `ARCHIVAL_COVERAGE_INELIGIBLE`, `RECONSTRUCTION_FAILED`, `SCHEMA_MISMATCH`, `INFERENCE_FAILED`.

No new scientific disposition may be created after model predictions are viewed.

## Reporting denominators

- **Source-screening yield:** accepted external incidents / candidate incidents reviewed.
- **Exact reconstruction yield:** incidents achieving exact 74-feature V4 reconstruction / accepted locked incidents.
- **Inference yield:** incidents reaching frozen Level-1 inference / accepted locked incidents.

Classification metrics apply only to incidents reaching inference; every failure remains visible.

## Post-freeze change prohibition

After protocol freeze, the reconstruction or inference pipeline may not be scientifically modified for a specific final-cohort incident. No feature rule, relevance predicate, historical-snapshot rule, observation interval, label mapping, or model behavior may be altered after the final cohort is locked. Unexpected failures remain reported failures.

Pure infrastructure recovery is permitted only when it is generic, does not change the scientific mapping, is documented separately, and is applied consistently to every applicable incident.

## Cohort construction boundary

No pilot incident or original-corpus incident is eligible. Membership depends only on source independence, label clarity, timestamp adequacy, overlap checks, historical archive availability, and reconstruction eligibility. Model output, feature values, predicted class, confidence, probability, and score margin are prohibited from cohort selection.
"""
    protocol_path = FREEZE / "external_level1_protocol_frozen_v1.md"
    protocol_path.write_text(protocol, encoding="utf-8")

    authority_files = {
        "relevance_and_windowing": ROOT / "src/bgp_incident_detection/train_incident_scale.py",
        "behavioral_features": ROOT / "src/bgp_incident_detection/behavioral_features.py",
        "five_minute_windowing": ROOT / "src/bgp_incident_detection/windows.py",
        "mrt_parser": ROOT / "src/bgp_incident_detection/mrt_parser.py",
        "caida_features": ROOT / "src/bgp_incident_detection/caida_features.py",
        "rpki_features": ROOT / "src/bgp_incident_detection/rpki_features.py",
    }
    models = [MODEL_DIR / f"level1_xgb_fold_{fold}_hist_njobs_minus1.joblib" for fold in range(1, 6)]
    metadata = [MODEL_DIR / f"level1_xgb_fold_{fold}_hist_njobs_minus1.metadata.json" for fold in range(1, 6)]
    manifest = {
        "protocol_version": "external_level1_protocol_frozen_v1",
        "freeze_timestamp_utc": frozen_at,
        "git_head_at_freeze": git_head(),
        "statement": "The reconstruction, feature-generation, historical-enrichment, frozen Level-1 inference, and mean incident-aggregation procedures were frozen before selection of the final prospective external-validation cohort.",
        "scope": "Prospective source-separated external validation of the frozen reproducibly preserved Level-1 BGP incident-classification path.",
        "level2_external_validation": False,
        "protocol": {"path": rel(protocol_path), "sha256": sha256(protocol_path)},
        "reconstruction_runner": {"path": rel(FROZEN_RUNNER), "sha256": sha256(FROZEN_RUNNER)},
        "inference_finalization_runner": {"path": rel(FROZEN_FINALIZER), "sha256": sha256(FROZEN_FINALIZER)},
        "feature_schema": {"path": rel(SCHEMA), "sha256": sha256(SCHEMA), "feature_count": 74},
        "level1_models": [{"path": rel(path), "sha256": sha256(path)} for path in models],
        "level1_model_metadata": [{"path": rel(path), "sha256": sha256(path)} for path in metadata],
        "collector_selection_rule": "route-views2 only",
        "context_buffer_minutes": 60,
        "incident_active_segmentation_rule": "Outage documented interval; Hijack/Leak <=60m one segment; >60m first/last 5m boundary segments",
        "relevance_predicate": {"version": "frozen_train_incident_scale_v1", "path": rel(authority_files["relevance_and_windowing"]), "sha256": sha256(authority_files["relevance_and_windowing"])},
        "five_minute_windowing": {"path": rel(authority_files["five_minute_windowing"]), "sha256": sha256(authority_files["five_minute_windowing"])},
        "behavioral_rule": {"version": "44_feature_v1", "path": rel(authority_files["behavioral_features"]), "sha256": sha256(authority_files["behavioral_features"])},
        "caida_rule": {"version": "14_feature_serial2_v1", "path": rel(authority_files["caida_features"]), "sha256": sha256(authority_files["caida_features"])},
        "rpki_rule": {"version": "16_feature_historical_v1", "path": rel(authority_files["rpki_features"]), "sha256": sha256(authority_files["rpki_features"])},
        "mrt_parser": {"path": rel(authority_files["mrt_parser"]), "sha256": sha256(authority_files["mrt_parser"])},
        "missing_value_behavior": "Frozen NaN behavior; no new imputation; native XGBoost missing-value handling",
        "mean_incident_aggregation_rule": "Arithmetic mean class probability across all eligible reconstructed five-minute windows",
        "pilot_exclusion_ledger": {"path": rel(PILOT_EXCLUSIONS), "sha256": sha256(PILOT_EXCLUSIONS)},
        "pilot_engineering_change_log": {"path": rel(PILOT_CHANGES), "sha256": sha256(PILOT_CHANGES)},
        "fixed_dispositions": ["ACCEPTED", "TIMESTAMP_REVIEW", "LABEL_AMBIGUOUS", "SOURCE_INSUFFICIENT", "ORIGINAL_CORPUS_OVERLAP", "PILOT_EXCLUDED", "ARCHIVAL_COVERAGE_INELIGIBLE", "RECONSTRUCTION_FAILED", "SCHEMA_MISMATCH", "INFERENCE_FAILED"],
    }
    manifest_path = FREEZE / "external_level1_protocol_freeze_manifest_v1.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    checksum_paths = [protocol_path, manifest_path, FROZEN_RUNNER, FROZEN_FINALIZER, SCHEMA, PILOT_EXCLUSIONS, PILOT_CHANGES, *models, *metadata, *authority_files.values()]
    rows = [{"artifact": rel(path), "sha256": sha256(path), "size_bytes": path.stat().st_size, "freeze_timestamp_utc": frozen_at} for path in checksum_paths]
    checksums = FREEZE / "external_level1_protocol_freeze_checksums_v1.csv"
    with checksums.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(json.dumps({"freeze_timestamp_utc": frozen_at, "git_head": git_head(), "protocol_sha256": sha256(protocol_path), "manifest_sha256": sha256(manifest_path)}, indent=2))


if __name__ == "__main__":
    main()
