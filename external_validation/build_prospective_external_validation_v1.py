"""Build additive prospective external-validation pilot and protocol scaffolding.

This script performs no model fitting and no inference. It freezes pilot identity,
records the reproducibility boundary, and writes the pre-evaluation protocol draft.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd


REPO = Path(__file__).resolve().parents[1]
ROOT = REPO / "external_validation"
SOURCE = REPO / "experiments/independent_validation_v2/v2_IEC_final_source_separated_roster.csv"
PILOT_IDS = [
    "V2-HIJACK-003", "V2-HIJACK-006", "V2-HIJACK-008",
    "V2-LEAK-002", "V2-LEAK-003", "V2-LEAK-007",
    "V2-OUTAGE-001", "V2-OUTAGE-002", "V2-OUTAGE-003",
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.strip() + "\n", encoding="utf-8")


def main() -> None:
    for directory in ["protocol", "pilot", "sources", "manifests", "reconstruction", "features", "predictions", "metrics", "figures", "logs", "final_report"]:
        (ROOT / directory).mkdir(parents=True, exist_ok=True)

    source = pd.read_csv(SOURCE)
    pilot = source[source["candidate_id"].isin(PILOT_IDS)].copy()
    assert len(pilot) == 9
    assert pilot["iec_label"].value_counts().to_dict() == {"Hijack": 3, "Leak": 3, "Outage": 3}
    pilot["study_role"] = "ENGINEERING_PILOT_ONLY"
    pilot["final_external_eligibility"] = "PERMANENTLY_EXCLUDED"
    pilot["exclusion_reason"] = "USED_TO_VERIFY_RECONSTRUCTION_BEFORE_PROSPECTIVE_FINAL_ROSTER_SELECTION"
    pilot["model_output_used_for_selection"] = "NO"
    pilot.to_csv(ROOT / "pilot/external_reconstruction_pilot_manifest_v1.csv", index=False)

    normalized_times = {
        "V2-HIJACK-003": ("2008-02-24T18:47:00Z", "2008-02-24T21:01:00Z", "PASS", "RIPE NCC RIS event timeline; source-corroborated correction to candidate metadata."),
        "V2-HIJACK-006": ("2020-07-30T01:15:38Z", "2020-07-30T02:27:27Z", "PASS", "Exact boundaries preserved from candidate source record."),
        "V2-HIJACK-008": ("2020-04-01T19:28:00Z", "", "REVIEW", "Source reports approximately one hour but no exact end timestamp; no end time invented."),
        "V2-LEAK-002": ("2018-05-18T09:36:00Z", "2018-05-18T10:06:00Z", "PASS", "Exact boundaries preserved from candidate source record."),
        "V2-LEAK-003": ("2019-06-24T10:35:00Z", "2019-06-24T12:38:00Z", "PASS", "Exact boundaries preserved from candidate source record."),
        "V2-LEAK-007": ("2021-02-11T04:36:41Z", "2021-02-11T04:50:10Z", "PASS", "Exact boundaries preserved from candidate source record."),
        "V2-OUTAGE-001": ("2021-07-02T02:40:00Z", "2021-07-02T03:15:00Z", "PASS", "IODA curated interval normalized to UTC."),
        "V2-OUTAGE-002": ("2021-06-15T13:50:00Z", "2021-06-15T14:30:00Z", "PASS", "IODA curated interval normalized to UTC."),
        "V2-OUTAGE-003": ("2021-06-04T02:50:00Z", "2021-06-04T05:50:00Z", "PASS", "IODA curated interval normalized to UTC."),
    }
    time_rows = []
    for candidate_id in PILOT_IDS:
        start, end, status, notes = normalized_times[candidate_id]
        time_rows.append({"candidate_id": candidate_id, "normalized_start_utc": start, "normalized_end_utc": end, "timestamp_gate": status, "notes": notes})
    pd.DataFrame(time_rows).to_csv(ROOT / "pilot/pilot_timestamp_normalization_gate_v1.csv", index=False)

    exclusions = pilot[["candidate_id", "iec_label", "study_role", "final_external_eligibility", "exclusion_reason"]]
    exclusions.to_csv(ROOT / "manifests/pilot_exclusion_from_final_roster_v1.csv", index=False)

    boundary = {
        "study": "Prospective Source-Separated External Validation of the Frozen BGP Incident Classification and Ranking System",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "original_experiment_status": "IMMUTABLE_AUTHORITATIVE",
        "original_corpus_incidents": 1419,
        "train_incidents": 993,
        "validation_incidents": 213,
        "final_holdout_incidents": 213,
        "reproducible_external_inference_path": "FROZEN_LEVEL1_FIVE_MODEL_XGBOOST_ENSEMBLE_WITH_MEAN_INCIDENT_AGGREGATION",
        "level2_status": "NOT_USABLE_ORIGINAL_TRAINED_ARTIFACT_NOT_PERSISTED",
        "pilot_incidents": 9,
        "pilot_final_roster_eligibility": "PERMANENTLY_EXCLUDED",
        "final_roster_collection_status": "PROHIBITED_UNTIL_RUNNER_AND_PROTOCOL_FROZEN",
    }
    write(ROOT / "protocol/study_boundary_v1.json", json.dumps(boundary, indent=2))

    write(ROOT / "protocol/prospective_external_validation_protocol_draft_v1.md", f"""
# Prospective Source-Separated External Validation Protocol Draft v1

Status: `DRAFT_PENDING_PILOT_RECONSTRUCTION_VERIFICATION`

Created UTC: {boundary['created_utc']}

## Separation from the original study

The original 1,419-incident experiment, its TRAIN/Validation/Final Holdout partitions, frozen feature definitions, and terminal Final Holdout results remain authoritative and immutable. No external incident may be used for training, tuning, calibration, threshold selection, feature revision, or model selection.

## Prospective chronology

1. Lock nine engineering-pilot incidents from historical non-Cloudflare candidates.
2. Permanently exclude those pilot incidents from any final external roster.
3. Verify exact RouteViews-to-V4 reconstruction and frozen Level-1 inference on the pilot.
4. Freeze the executable reconstruction runner, schemas, checksums, and this protocol.
5. Only after that freeze, collect and lock a new final external cohort.
6. Run the frozen Level-1 path once and retain every reconstruction and prediction outcome.

The historical 73-candidate/63-incident IEC roster is not represented as prospectively selected under this protocol.

## Reproducible classifier scope

External inference is limited to the verified reconstructed five-model Level-1 XGBoost ensemble and frozen mean incident aggregation. The originally fitted Level-2 artifact was not persisted. No Level-2 refit or substitute is permitted.

## Inclusion criteria for the future final roster

- Non-Cloudflare source-native Hijack, Leak, or Outage label.
- Traceable primary or strong secondary source.
- Sufficient time and ASN/prefix/entity metadata for RouteViews reconstruction.
- No overlap with the original 1,419 incidents.
- Not one of the nine pilot incidents.
- Not used in any model development or engineering verification.
- Deterministic class mapping fixed before model output is viewed.

## Exclusion criteria

- Ambiguous or mixed class without deterministic mapping.
- Documentation too vague for reconstruction.
- Cloudflare-only or Cloudflare-derived labeling.
- Original-corpus overlap.
- Pilot membership.
- Model output used in candidate selection or adjudication.

## Required reporting

Candidate count, accepted count, reconstruction count, inference count, and reconstruction yield are reported separately. Performance metrics use only incidents reaching inference, while failures remain visible in the exclusion and reconstruction ledgers.
""")

    authority_rows = [
        ("V4 schema", "src/bgp_incident_detection/feature_ablation.py; data/tti_pilot/reconstructed_level1_v1/feature_schema_v4.json", "74_FEATURE_ORDER_FROZEN"),
        ("Level-1 models", "data/tti_pilot/reconstructed_level1_v1/level1_xgb_fold_*.joblib", "EXACT_TRAIN_PROBABILITY_EQUIVALENCE"),
        ("Behavioral", "src/bgp_incident_detection/behavioral_features.py", "44_FEATURES"),
        ("CAIDA", "src/bgp_incident_detection/caida_features.py", "14_HISTORICAL_FEATURES"),
        ("RPKI/ROV", "src/bgp_incident_detection/rpki_features.py", "16_HISTORICAL_FEATURES"),
        ("Level-2", "experiments/independent_validation_v2/level2_external_validation_closure_v1/", "NOT_USABLE_ARTIFACT_NOT_PERSISTED"),
    ]
    pd.DataFrame(authority_rows, columns=["component", "authoritative_source", "status"]).to_csv(ROOT / "protocol/reconstruction_authority_map_v1.csv", index=False)

    artifacts = [
        ROOT / "pilot/external_reconstruction_pilot_manifest_v1.csv",
        ROOT / "pilot/pilot_timestamp_normalization_gate_v1.csv",
        ROOT / "manifests/pilot_exclusion_from_final_roster_v1.csv",
        ROOT / "protocol/study_boundary_v1.json",
        ROOT / "protocol/prospective_external_validation_protocol_draft_v1.md",
        ROOT / "protocol/reconstruction_authority_map_v1.csv",
    ]
    pd.DataFrame([{"artifact": str(p.relative_to(REPO)), "sha256": sha256(p)} for p in artifacts]).to_csv(ROOT / "manifests/prepilot_checksums_v1.csv", index=False)


if __name__ == "__main__":
    main()
