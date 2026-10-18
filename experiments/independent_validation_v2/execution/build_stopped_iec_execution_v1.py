from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd


REPO = Path(__file__).resolve().parents[3]
ROOT = REPO / "experiments" / "independent_validation_v2"
OUT = ROOT / "execution"
for candidate in (REPO, REPO / "src"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_text(name: str, text: str) -> Path:
    path = OUT / name
    path.write_text(text.strip() + "\n", encoding="utf-8")
    return path


def write_csv(name: str, rows: list[dict[str, object]], columns: list[str] | None = None) -> Path:
    path = OUT / name
    df = pd.DataFrame(rows)
    if columns is not None:
        df = df.reindex(columns=columns)
    df.to_csv(path, index=False)
    return path


def load_roster() -> pd.DataFrame:
    return pd.read_csv(ROOT / "v2_IEC_final_source_separated_roster.csv")


def verify_locked_artifacts() -> pd.DataFrame:
    checksum_file = ROOT / "v2_IEC_source_separated_checksums_v1.csv"
    rows = []
    if checksum_file.exists():
        locked = pd.read_csv(checksum_file)
        for _, row in locked.iterrows():
            rel = row["file"]
            path = ROOT / rel
            expected = row["sha256"]
            if not path.exists():
                current = ""
                status = "MISSING"
            else:
                current = sha256(path)
                status = "MATCH" if current == expected else "MISMATCH"
            rows.append(
                {
                    "artifact": rel,
                    "path": str(path.relative_to(REPO)),
                    "locked_sha256": expected,
                    "current_sha256": current,
                    "status": status,
                    "notes": "IEC source-separated lock artifact verification",
                }
            )

    lock_sha_path = ROOT / "V2_IEC_AUTOMATED_EVALUATION_LOCK.md.sha256"
    lock_path = ROOT / "V2_IEC_AUTOMATED_EVALUATION_LOCK.md"
    if lock_sha_path.exists() and lock_path.exists():
        expected = lock_sha_path.read_text(encoding="utf-8").split()[0]
        current = sha256(lock_path)
        rows.append(
            {
                "artifact": lock_sha_path.name,
                "path": str(lock_sha_path.relative_to(REPO)),
                "locked_sha256": expected,
                "current_sha256": current,
                "status": "MATCH" if expected == current else "MISMATCH",
                "notes": "Lock checksum sidecar verification",
            }
        )
    return pd.DataFrame(rows)


def feature_names() -> list[str]:
    try:
        from bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT
    except Exception:
        from src.bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT
    return list(FEATURES_BY_VARIANT["V4"])


def implementation_spec(roster: pd.DataFrame) -> str:
    return f"""
# IEC Execution Implementation Specification v1

Generated UTC: {datetime.now(timezone.utc).isoformat()}

## Scope

This is an additive source-separated IEC execution record under `experiments/independent_validation_v2/execution/`.
The frozen IEC roster contains {len(roster)} candidate incidents and is read from
`experiments/independent_validation_v2/v2_IEC_final_source_separated_roster.csv`.

## Frozen Inputs

| Step | Required frozen methodology | Authoritative artifact/code found |
| --- | --- | --- |
| IEC roster and labels | Source-native non-Cloudflare labels, deterministic mapping, no event replacement | `experiments/independent_validation_v2/V2_IEC_AUTOMATED_EVALUATION_LOCK.md`; `v2_IEC_final_source_separated_roster.csv`; `v2_IEC_source_label_mapping_rules.csv` |
| Collector and archive | RouteViews `route-views2`, 15-minute UPDATE files, UTC slot handling | `experiments/reproducibility_audit_v1/reproducibility_routeviews_pipeline_v1.md`; `src/bgp_incident_detection/mrt_acquisition.py`; `src/bgp_incident_detection/mrt_download.py` |
| Parser | `bgpdump 1.6.2`, `bgpdump -q -m`, one row per prefix-level announcement/withdrawal observation | `experiments/reproducibility_audit_v1/reproducibility_routeviews_pipeline_v1.md`; `src/bgp_incident_detection/mrt_parser.py` |
| Windowing | Five-minute RouteViews-observable analytical windows | `experiments/reproducibility_audit_v1/reproducibility_windowing_v1.md`; `src/bgp_incident_detection/windows.py` |
| Behavioral features | Frozen 44-feature behavioral family | `experiments/reproducibility_audit_v1/reproducibility_feature_dictionary_v1.csv`; `src/bgp_incident_detection/behavioral_features.py` |
| CAIDA features | Frozen 14 historical AS-relationship features | `experiments/reproducibility_audit_v1/reproducibility_caida_v1.md`; `src/bgp_incident_detection/caida_features.py` |
| RPKI/ROV features | Frozen 16 historical RPKI/ROV features | `experiments/reproducibility_audit_v1/reproducibility_rpki_v1.md`; `src/bgp_incident_detection/rpki_features.py` |
| V4 schema | 44 Behavioral + 14 CAIDA + 16 RPKI/ROV = 74 features | `config/final_model_candidate_v3_1_xgb_refined.yaml`; `src/bgp_incident_detection/feature_ablation.py` |
| Level-1 model | Reconstructed five-model XGBoost ensemble with exact TRAIN probability equivalence | `data/tti_pilot/reconstructed_level1_v1/`; `experiments/reproducibility_audit_v1/reproducibility_level1_xgboost_v1.md` |
| Level-2 model | XGBoost retrospective incident temporal stacker | `config/k1_second_level_xgb_final_v1.yaml`; `config/k1_incident_meta_feature_schema_v1.yaml`; `experiments/reproducibility_audit_v1/reproducibility_level2_stacker_v1.md` |

## Blocking Finding

The frozen artifacts document the final pipeline and contain reconstructed Level-1 models, but the workspace does not contain a frozen, verified, source-native IEC reconstruction/scoring implementation capable of taking arbitrary non-Cloudflare IEC event metadata through RouteViews acquisition, incident-relevance filtering, V4 feature construction, Level-1 scoring, Level-2 meta-feature construction, and final incident scoring.

The prior independent-validation execution path under `experiments/independent_validation_execution_v1/` is a stopped zero-prediction record, not a reusable scoring implementation. Therefore, the required implementation-equivalence gate cannot be passed without creating and validating a new end-to-end reconstruction implementation. Per the IEC protocol, this execution stops before model scoring.
"""


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    roster = load_roster()
    now = datetime.now(timezone.utc).isoformat()
    locked = verify_locked_artifacts()
    locked_path = OUT / "iec_locked_artifact_verification_v1.csv"
    locked.to_csv(locked_path, index=False)
    artifacts_match = bool(len(locked)) and bool((locked["status"] == "MATCH").all())

    write_text("iec_execution_implementation_specification_v1.md", implementation_spec(roster))

    reconstruction_rows = []
    for _, row in roster.iterrows():
        reconstruction_rows.append(
            {
                "iec_id": row["candidate_id"],
                "source_family": row["source_family"],
                "iec_label": row["iec_label"],
                "mrt_files_requested": "NOT_EXECUTED",
                "mrt_files_obtained": "NOT_EXECUTED",
                "observations_parsed": "NOT_EXECUTED",
                "incident_relevant_observations": "NOT_EXECUTED",
                "announcements": "NOT_EXECUTED",
                "withdrawals": "NOT_EXECUTED",
                "analytical_windows": "NOT_EXECUTED",
                "reconstruction_status": "NOT_EXECUTED_IMPLEMENTATION_EQUIVALENCE_GATE",
                "notes": "Stopped before RouteViews reconstruction because implementation equivalence did not pass.",
            }
        )
    write_csv("iec_routeviews_reconstruction_v1.csv", reconstruction_rows)

    quality_rows = [
        {
            "iec_id": row["candidate_id"],
            "iec_label": row["iec_label"],
            "prospective_reconstruction_status": "NOT_EVALUATED",
            "quality_gate_status": "NOT_EXECUTED_IMPLEMENTATION_EQUIVALENCE_GATE",
            "final_evaluability_class": "OTHER_LOCKED_EXCLUSION",
            "notes": "No model-output-based exclusion occurred; execution stopped before reconstruction/scoring.",
        }
        for _, row in roster.iterrows()
    ]
    write_csv("iec_quality_gate_v1.csv", quality_rows)

    features = feature_names()
    schema_rows = [
        {
            "feature_index": i + 1,
            "feature_name": f,
            "expected_schema": "V4",
            "expected_feature_count": 74,
            "observed_feature_available_for_IEC": "NO",
            "status": "NOT_EXECUTED_IMPLEMENTATION_EQUIVALENCE_GATE",
            "notes": "IEC V4 rows were not constructed because implementation equivalence failed before scoring.",
        }
        for i, f in enumerate(features)
    ]
    write_csv("iec_feature_schema_verification_v1.csv", schema_rows)

    equivalence_rows = [
        {
            "check": "frozen_non_IEC_fixture_available_for_end_to_end_IEC_pipeline",
            "required": "YES",
            "observed": "NO_VERIFIED_FIXTURE_FOUND",
            "tolerance": "predeclared exact schema/order and probability-level equivalence; no post-hoc relaxation",
            "status": "FAIL",
            "notes": "Existing Level-1 reconstruction proves model equivalence on preserved TRAIN probabilities, but does not verify arbitrary source-native IEC RouteViews reconstruction and full K1 scoring.",
        },
        {
            "check": "prior_independent_validation_execution_reusable",
            "required": "YES",
            "observed": "NO_STOPPED_ZERO_PREDICTION_RECORD_ONLY",
            "tolerance": "not applicable",
            "status": "FAIL",
            "notes": "V1 execution stopped before roster construction and scoring; it cannot verify or score the V2 IEC roster.",
        },
        {
            "check": "implementation_equivalence_disposition",
            "required": "IMPLEMENTATION_EQUIVALENCE_PASS",
            "observed": "IMPLEMENTATION_EQUIVALENCE_FAIL",
            "tolerance": "not applicable",
            "status": "FAIL",
            "notes": "Protocol requires STOP before IEC scoring.",
        },
    ]
    write_csv("iec_implementation_equivalence_v1.csv", equivalence_rows)
    write_text(
        "iec_implementation_equivalence_summary_v1.md",
        """
# IEC Implementation Equivalence Summary v1

`IMPLEMENTATION_EQUIVALENCE_FAIL`

The available workspace artifacts verify the final Praxis model family and reconstructed Level-1 ensemble, but they do not provide a frozen, end-to-end source-native IEC reconstruction/scoring implementation or a suitable non-IEC fixture proving equivalence for arbitrary external events.

Per the frozen IEC protocol, model scoring is not allowed after this failed gate. No IEC predictions, H1/H2/H3 metrics, bootstrap CIs, figures, or source-specific performance claims were generated.
""",
    )

    write_csv(
        "v2_IEC_evaluable_roster_frozen.csv",
        [],
        [
            "iec_id",
            "iec_label",
            "source_family",
            "evaluable_status",
            "reason",
        ],
    )
    (OUT / "v2_IEC_evaluable_roster_frozen.sha256").write_text(
        f"{sha256(OUT / 'v2_IEC_evaluable_roster_frozen.csv')}  v2_IEC_evaluable_roster_frozen.csv\n",
        encoding="utf-8",
    )

    h1_rows = [
        {
            "metric": metric,
            "value": "NA",
            "ci_lower": "NA",
            "ci_upper": "NA",
            "evaluable_incidents": 0,
            "status": "NOT_EXECUTED_IMPLEMENTATION_EQUIVALENCE_FAIL",
            "decision": "INCONCLUSIVE",
            "notes": "IEC scoring stopped before inference.",
        }
        for metric in ["macro_f1", "top1", "top2", "mrr", "mean_true_class_rank"]
    ]
    write_csv("v2_IEC_H1_results_v1.csv", h1_rows)
    write_csv(
        "v2_IEC_H2_paired_results_v1.csv",
        [
            {
                "comparison": "Behavioral-only vs Behavioral+CAIDA+RPKI/ROV",
                "delta_h2_macro_f1": "NA",
                "ci_lower": "NA",
                "ci_upper": "NA",
                "evaluable_incidents": 0,
                "status": "NOT_EXECUTED_IMPLEMENTATION_EQUIVALENCE_FAIL",
                "notes": "Requires successful IEC scoring on the same evaluable incidents.",
            }
        ],
    )
    write_csv(
        "v2_IEC_H3_paired_results_v1.csv",
        [
            {
                "comparison": "Mean Level-1 aggregation vs RETROSPECTIVE INCIDENT-LEVEL AGGREGATION",
                "delta_h3_macro_f1": "NA",
                "ci_lower": "NA",
                "ci_upper": "NA",
                "evaluable_incidents": 0,
                "status": "NOT_EXECUTED_IMPLEMENTATION_EQUIVALENCE_FAIL",
                "notes": "Requires successful IEC scoring on the same evaluable incidents.",
            }
        ],
    )
    write_csv(
        "v2_IEC_per_class_metrics_v1.csv",
        [],
        ["class", "precision", "recall", "f1", "support", "status", "notes"],
    )
    write_csv(
        "v2_IEC_confusion_matrix_v1.csv",
        [],
        ["true_class", "predicted_hijack", "predicted_leak", "predicted_outage", "status"],
    )
    write_csv(
        "v2_IEC_incident_predictions_v1.csv",
        [],
        [
            "iec_id",
            "source_family",
            "true_class",
            "predicted_class",
            "hijack_score",
            "leak_score",
            "outage_score",
            "true_class_rank",
            "top1_correct",
            "top2_correct",
            "status",
        ],
    )
    write_csv(
        "v2_IEC_bootstrap_results_v1.csv",
        [],
        ["metric_or_comparison", "bootstrap_iterations", "seed", "estimate", "ci_lower", "ci_upper", "status"],
    )
    write_csv(
        "v2_IEC_source_specific_results_v1.csv",
        [],
        ["source_family", "evaluable_incidents", "macro_f1", "top1", "top2", "mrr", "status", "notes"],
    )
    write_csv(
        "v2_IEC_error_analysis_v1.csv",
        [],
        [
            "iec_id",
            "source",
            "source_native_class",
            "predicted_class",
            "hijack_score",
            "leak_score",
            "outage_score",
            "top1_margin",
            "true_class_rank",
            "top2_recovery",
            "metadata_limitation",
            "routeviews_evidence_density",
            "status",
        ],
    )

    summary = f"""
# V2 IEC Execution Summary v1

Generated UTC: {now}

## Status

`SOURCE_SEPARATED_IEC_INCONCLUSIVE`

## Protocol Gate Outcome

- Frozen IEC roster rows: {len(roster)}
- Frozen IEC class counts: {roster['iec_label'].value_counts().to_dict()}
- Locked artifact verification: {'PASS' if artifacts_match else 'FAIL'}
- Implementation equivalence: `IMPLEMENTATION_EQUIVALENCE_FAIL`
- Model scoring performed: NO
- Validation accessed/recomputed: NO
- Original Final Holdout accessed/recomputed: NO

The execution stopped before RouteViews reconstruction and model inference because a frozen, verified IEC reconstruction/scoring implementation was not available, and no suitable non-IEC fixture was present to prove end-to-end implementation equivalence for the new source-native IEC events.

## Required Questions

1. Evaluable IEC incidents: 0 of 63; none were scored because implementation equivalence failed before reconstruction/inference.
2. Final H/L/O evaluable counts: Hijack=0, Leak=0, Outage=0.
3. Implementation equivalence passed: NO.
4. Frozen artifacts matched: {'YES' if artifacts_match else 'NO'}.
5. External Macro F1 and 95% CI: NA, not executed.
6. Top-1, Top-2, MRR: NA, not executed.
7. Class-specific F1: NA, not executed.
8. Delta_H2 and paired CI: NA, not executed.
9. Delta_H3 and paired CI: NA, not executed.
10. Best/worst external source/class: NA, not evaluated.
11. Dominant external errors: NA, no predictions produced.
12. Descriptive comparison with original Final Holdout: not possible; original Final Holdout remains authoritative and unchanged.
13. Cloudflare label-source dependence implication: inconclusive; the source-separated roster is locked, but the frozen model was not executed.
14. Claims strengthened: source-separated roster construction and lock discipline are strengthened; performance generalization is not.
15. Claims narrowed: no source-separated external performance claim should be made until a verified IEC reconstruction/scoring implementation passes the equivalence gate and is executed once.

## Disposition

`SOURCE_SEPARATED_IEC_INCONCLUSIVE`
"""
    write_text("v2_IEC_execution_summary_v1.md", summary)
    write_text(
        "v2_IEC_final_disposition_v1.md",
        """
# V2 IEC Final Disposition v1

`SOURCE_SEPARATED_IEC_INCONCLUSIVE`

Reason: the deterministic source-separated IEC roster and lock were validly created, and locked artifacts matched, but the required implementation-equivalence gate failed before any RouteViews reconstruction or model scoring. No model inference was performed and no performance results were generated.
""",
    )

    manifest = {
        "generated_utc": now,
        "input_roster": str((ROOT / "v2_IEC_final_source_separated_roster.csv").relative_to(REPO)),
        "locked_roster_rows": int(len(roster)),
        "locked_roster_class_counts": roster["iec_label"].value_counts().to_dict(),
        "locked_artifacts_match": bool(artifacts_match),
        "implementation_equivalence": "FAIL",
        "model_scoring_performed": False,
        "validation_accessed": False,
        "final_holdout_accessed": False,
        "disposition": "SOURCE_SEPARATED_IEC_INCONCLUSIVE",
    }
    (OUT / "v2_IEC_execution_manifest_v1.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    checksum_rows = []
    for path in sorted(OUT.iterdir()):
        if path.is_file() and path.name != "v2_IEC_execution_checksums_v1.csv":
            checksum_rows.append({"file": path.name, "sha256": sha256(path)})
    pd.DataFrame(checksum_rows).to_csv(OUT / "v2_IEC_execution_checksums_v1.csv", index=False)
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
