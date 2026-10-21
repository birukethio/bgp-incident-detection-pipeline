from __future__ import annotations

import csv
import hashlib
import json
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import pandas as pd
import yaml


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "experiments" / "reproducibility_audit_v1"


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def read_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def read_text(path: Path, default: str = "") -> str:
    if not path.exists():
        return default
    return path.read_text(encoding="utf-8")


def sha256(path: Path, max_bytes: int = 500_000_000) -> str:
    if not path.exists():
        return "NOT_FOUND"
    if path.is_file() and path.stat().st_size > max_bytes:
        return f"NOT_HASHED_SIZE_{path.stat().st_size}_BYTES"
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fieldnames is None:
        fieldnames = list(rows[0].keys()) if rows else []
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def md_table(rows: list[dict[str, Any]], columns: list[str]) -> str:
    if not rows:
        return ""
    header = "| " + " | ".join(columns) + " |"
    sep = "| " + " | ".join(["---"] * len(columns)) + " |"
    body = []
    for row in rows:
        vals = []
        for col in columns:
            val = str(row.get(col, "")).replace("\n", "<br>")
            vals.append(val)
        body.append("| " + " | ".join(vals) + " |")
    return "\n".join([header, sep, *body])


def write_md(path: Path, title: str, sections: list[tuple[str, str]]) -> None:
    content = [f"# {title}", ""]
    for heading, body in sections:
        content.extend([f"## {heading}", "", body.strip(), ""])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(content).rstrip() + "\n", encoding="utf-8")


def load_features() -> tuple[list[dict[str, Any]], list[str]]:
    behavioral = read_yaml(ROOT / "config/behavioral_feature_schema_v1.yaml")
    caida = read_yaml(ROOT / "config/caida_feature_schema_v1.yaml")
    rpki = read_yaml(ROOT / "config/rpki_feature_schema_v1.yaml")
    rows: list[dict[str, Any]] = []
    global_order = 1
    for item in behavioral.get("features", []):
        rows.append(
            {
                "global_order": global_order,
                "family_order": item.get("order"),
                "feature_name": item.get("feature_name"),
                "feature_family": "Behavioral",
                "definition": item.get("definition", ""),
                "formula": item.get("formula", ""),
                "source_inputs": item.get("source_fields", ""),
                "aggregation_method": item.get("aggregation_method", ""),
                "missing_or_zero_behavior": item.get("zero_window_behavior", ""),
                "verification_status": item.get("verification_status", "RECOVERED_FROM_SCHEMA"),
                "schema_source": "config/behavioral_feature_schema_v1.yaml",
            }
        )
        global_order += 1
    for item in caida.get("features", []):
        rows.append(
            {
                "global_order": global_order,
                "family_order": item.get("order"),
                "feature_name": item.get("name"),
                "feature_family": "CAIDA AS-relationship",
                "definition": item.get("definition", ""),
                "formula": item.get("formula", ""),
                "source_inputs": item.get("required_inputs", ""),
                "aggregation_method": "AS_PATH transition/path aggregation",
                "missing_or_zero_behavior": f"zero: {item.get('zero_behavior', '')}; missing: {item.get('missing_behavior', '')}",
                "verification_status": "RECOVERED_FROM_SCHEMA",
                "schema_source": "config/caida_feature_schema_v1.yaml",
            }
        )
        global_order += 1
    for item in rpki.get("features", []):
        rows.append(
            {
                "global_order": global_order,
                "family_order": item.get("order"),
                "feature_name": item.get("name"),
                "feature_family": "RPKI/ROV",
                "definition": item.get("definition", ""),
                "formula": item.get("formula", ""),
                "source_inputs": item.get("required_inputs", ""),
                "aggregation_method": item.get("aggregation_method", ""),
                "missing_or_zero_behavior": f"zero: {item.get('zero_behavior', '')}; missing: {item.get('missing_behavior', '')}",
                "verification_status": "RECOVERED_FROM_SCHEMA",
                "schema_source": "config/rpki_feature_schema_v1.yaml",
            }
        )
        global_order += 1
    return rows, [r["feature_name"] for r in rows]


def parquet_summary(path: Path, feature_names: list[str]) -> dict[str, Any]:
    if not path.exists():
        return {"path": rel(path), "exists": False}
    df = pd.read_parquet(path)
    category_col = "category" if "category" in df.columns else "true_class" if "true_class" in df.columns else None
    counts = df[category_col].value_counts().to_dict() if category_col else {}
    present = [f for f in feature_names if f in df.columns]
    return {
        "path": rel(path),
        "exists": True,
        "rows": len(df),
        "columns": len(df.columns),
        "feature_columns_present": len(present),
        "missing_features": ", ".join([f for f in feature_names if f not in df.columns]),
        "class_counts": json.dumps(counts, sort_keys=True),
    }


def csv_counts(path: Path, key: str | None = None) -> dict[str, Any]:
    if not path.exists():
        return {"path": rel(path), "exists": False}
    df = pd.read_csv(path)
    out: dict[str, Any] = {"path": rel(path), "exists": True, "rows": len(df), "columns": len(df.columns)}
    if key and key in df.columns:
        out["counts"] = json.dumps(df[key].value_counts().to_dict(), sort_keys=True)
    return out


def get_final_metrics() -> dict[str, Any]:
    final = read_yaml(ROOT / "config/final_praxis_result_v1.yaml")
    return {
        "holdout_incidents": final.get("holdout_incidents"),
        "holdout_window_rows": final.get("holdout_window_rows"),
        "incident_macro_f1": final.get("incident_macro_f1"),
        "macro_f1_ci_lower": (final.get("macro_f1_ci_95") or {}).get("ci_lower_95"),
        "macro_f1_ci_upper": (final.get("macro_f1_ci_95") or {}).get("ci_upper_95"),
        "top1": final.get("top1"),
        "top2": final.get("top2"),
        "mrr": final.get("mrr"),
        "hijack_f1": final.get("hijack_f1"),
        "leak_f1": final.get("leak_f1"),
        "outage_f1": final.get("outage_f1"),
        "second_level_parameter_hash": final.get("second_level_parameter_hash"),
        "source_commit": final.get("source_commit"),
    }


def make_artifact_map(feature_names: list[str]) -> list[dict[str, Any]]:
    candidates = [
        ("Frozen v2 roster", "data/roster_v2/frozen_incident_roster_v2.csv"),
        ("Frozen v2 partition manifest", "data/partitions_v2/frozen_partition_manifest_v2.csv"),
        ("TRAIN partition", "data/partitions_v2/train_incidents_v2.csv"),
        ("Validation partition", "data/partitions_v2/validation_incidents_v2.csv"),
        ("Final Holdout partition", "data/partitions_v2/holdout_incidents_v2.csv"),
        ("Frozen TRAIN V4 feature corpus", "data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1.parquet"),
        ("Final Holdout V4 feature corpus", "data/final_holdout/final_holdout_v4_features_v1.parquet"),
        ("Behavioral feature schema", "config/behavioral_feature_schema_v1.yaml"),
        ("CAIDA feature schema", "config/caida_feature_schema_v1.yaml"),
        ("RPKI feature schema", "config/rpki_feature_schema_v1.yaml"),
        ("Refined Level-1 XGBoost candidate", "config/final_model_candidate_v3_1_xgb_refined.yaml"),
        ("Deployable K1 candidate", "config/k1_final_candidate_v1_1_deployable.yaml"),
        ("K1 meta-feature schema", "config/k1_incident_meta_feature_schema_v1.yaml"),
        ("Final terminal Holdout result", "config/final_praxis_result_v1.yaml"),
        ("Level-1 reconstruction spec", "data/tti_pilot/level1_training_specification_v1.csv"),
        ("Level-1 probability equivalence", "data/tti_pilot/level1_probability_equivalence_v2.csv"),
        ("RouteViews source plan", "data/pilot/routeviews_source_plan_v1.md"),
        ("MRT parser environment", "data/pilot/mrt_parser_environment_v1.csv"),
        ("Corpus balancing audit", "experiments/corpus_balancing_audit_v1/corpus_balancing_audit_summary_v1.md"),
        ("Label provenance audit", "experiments/label_provenance_audit_v1/label_provenance_final_disposition_v1.md"),
        ("Partition independence audit", "experiments/partition_independence_audit_v1/partition_independence_final_disposition_v1.md"),
        ("Calibration terminology audit", "experiments/calibration_audit_v1/calibration_terminology_recommendation_v1.md"),
        ("Hijack 68538 audit", "experiments/hijack_68538_audit_v1/hijack_68538_final_disposition_v1.md"),
    ]
    rows = []
    for role, path_s in candidates:
        p = ROOT / path_s
        rows.append(
            {
                "artifact_role": role,
                "source_artifact": path_s,
                "exists": p.exists(),
                "sha256": sha256(p) if p.exists() else "NOT_FOUND",
                "reproducibility_use": "Authoritative current source" if "audit" not in role.lower() else "Supporting forensic audit",
                "notes": "",
            }
        )
    train_summary = parquet_summary(ROOT / "data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1.parquet", feature_names)
    holdout_summary = parquet_summary(ROOT / "data/final_holdout/final_holdout_v4_features_v1.parquet", feature_names)
    rows.append(
        {
            "artifact_role": "TRAIN V4 schema verification",
            "source_artifact": train_summary["path"],
            "exists": train_summary["exists"],
            "sha256": "SEE_ROW_ABOVE",
            "reproducibility_use": "Feature count verification",
            "notes": json.dumps(train_summary, sort_keys=True),
        }
    )
    rows.append(
        {
            "artifact_role": "Holdout V4 schema verification",
            "source_artifact": holdout_summary["path"],
            "exists": holdout_summary["exists"],
            "sha256": "SEE_ROW_ABOVE",
            "reproducibility_use": "Final evaluation feature count verification",
            "notes": json.dumps(holdout_summary, sort_keys=True),
        }
    )
    return rows


def make_gap_rows() -> list[dict[str, Any]]:
    return [
        {
            "area": "Initial Hijack/Leak 473 selection script",
            "status": "NOT_UNIQUELY_RECOVERED",
            "gap": "The first-pass executable quality-stratified sampling script was not uniquely recovered.",
            "impact": "Final roster membership is preserved and auditable, but exact re-execution from raw pools is not fully turnkey.",
            "mitigation": "Use frozen roster, strata, quality ranks, and corpus balancing audit as authoritative history.",
        },
        {
            "area": "Full-universe Hijack/Leak preselection duplicate collapse",
            "status": "NOT_RECOVERED",
            "gap": "A full-universe duplicate-collapse artifact before v1 selection was not found.",
            "impact": "Does not alter final v2 corpus, because v2 confirmed duplicates were remediated and replacements documented.",
            "mitigation": "Cite v2 duplicate canonicalization and corpus balancing audit.",
        },
        {
            "area": "Original serialized frozen Level-1 model",
            "status": "NOT_PRESERVED_BUT_EQUIVALENT_RECONSTRUCTED_ARTIFACT_EXISTS",
            "gap": "The original loadable Level-1 XGBoost model artifact was not preserved.",
            "impact": "Direct loading of the historical model is impossible.",
            "mitigation": "Five-model Level-1 reconstruction passed exact probability equivalence against 68,031 preserved TRAIN predictions.",
        },
        {
            "area": "Historical hardware and thread execution settings",
            "status": "PARTIALLY_RECOVERED",
            "gap": "Recorded software versions exist for XGBoost; full hardware/thread details are incomplete outside selected manifests.",
            "impact": "May affect timing reproducibility, not metric artifacts.",
            "mitigation": "Report current environment and recorded XGBoost environment separately.",
        },
        {
            "area": "Hijack:68538",
            "status": "QUALITY_GATE_INCONSISTENCY",
            "gap": "One retained Holdout case had source-side hijack evidence but no retained incident-relevant RouteViews observations.",
            "impact": "Documented limitation; official final Holdout remains immutable.",
            "mitigation": "Cite Hijack:68538 audit and present as limitation rather than changing results.",
        },
        {
            "area": "Score calibration",
            "status": "SUPPORTED_WITH_CALIBRATION_LIMITATION",
            "gap": "Scores are probability-like and normalized but imperfectly calibrated.",
            "impact": "Ranking metrics remain valid; operational likelihood claims require caution.",
            "mitigation": "Use probability terminology with calibration limitation or class-ranking score terminology.",
        },
    ]


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now(timezone.utc).isoformat()
    features, feature_names = load_features()
    write_csv(
        OUT / "reproducibility_feature_dictionary_v1.csv",
        features,
        [
            "global_order",
            "family_order",
            "feature_name",
            "feature_family",
            "definition",
            "formula",
            "source_inputs",
            "aggregation_method",
            "missing_or_zero_behavior",
            "verification_status",
            "schema_source",
        ],
    )
    write_md(
        OUT / "reproducibility_feature_dictionary_v1.md",
        "Complete Frozen V4 Feature Dictionary v1",
        [
            (
                "Scope",
                "This appendix dictionary documents the frozen V4 74-feature representation used by the final Praxis model. It is assembled from the frozen behavioral, CAIDA, and RPKI schema files and does not redefine any feature.",
            ),
            ("Feature Inventory", md_table(features, ["global_order", "feature_name", "feature_family", "definition", "formula", "missing_or_zero_behavior"])),
        ],
    )

    final_metrics = get_final_metrics()
    artifact_rows = make_artifact_map(feature_names)
    write_csv(OUT / "reproducibility_artifact_map_v1.csv", artifact_rows)
    gap_rows = make_gap_rows()
    write_csv(OUT / "reproducibility_gap_analysis_v1.csv", gap_rows)

    data_acquisition = [
        (
            "Recovered Data Sources",
            "\n".join(
                [
                    "- Cloudflare-derived source records supplied final Hijack, Leak, and Outage candidate pools.",
                    "- RouteViews UPDATE archives supplied public BGP observations; RIPE RIS was not used for the final feature extraction path.",
                    "- CAIDA AS-relationship snapshots supplied historical AS relationship context.",
                    "- Historical RPKI/VRP data supplied ROV validity features.",
                    "- Label provenance is externally sourced and documented in `experiments/label_provenance_audit_v1/`.",
                ]
            ),
        ),
        (
            "Corpus Accounting",
            "The final corpus is the frozen v2 roster: 1,419 incidents with 473 Hijack, 473 Leak, and 473 Outage. The split is 993 TRAIN, 213 Validation, and 213 Final Holdout. The corpus balancing audit documents raw Cloudflare-derived source records of 112,290 Hijack, 125,051 Leak, and 804 Outage before quality and balancing steps, and identifies the initial selection gaps.",
        ),
        (
            "Endpoint and Code Path Evidence",
            "Cloudflare endpoint and source-label tracing is documented in `experiments/label_provenance_audit_v1/cloudflare_label_entry_trace_v1.csv` and `.md`. Local collection code includes `cloudflare_incidents/fetch_cloudflare_all_incidents_to_2026_01.mjs`, `cloudflare_incidents/fetch_cloudflare_leaks_range.mjs`, and outage roster builders. Where exact API pagination parameters are not recoverable from preserved logs, this audit marks them as documented limitation rather than re-creating them.",
        ),
        (
            "Limitations",
            "The collected-corpus distribution should not be described as global Internet-wide prevalence. The original first-pass Hijack/Leak sampling script is not uniquely recovered, but final roster membership and v2 duplicate remediation are preserved.",
        ),
    ]
    write_md(OUT / "reproducibility_data_acquisition_v1.md", "Data Acquisition Reproducibility v1", data_acquisition)

    write_md(
        OUT / "reproducibility_routeviews_pipeline_v1.md",
        "RouteViews Pipeline Reproducibility v1",
        [
            ("Collector and Archive", read_text(ROOT / "data/pilot/routeviews_source_plan_v1.md")),
            (
                "Parser",
                "The recorded parser environment is `bgpdump 1.6.2` using `bgpdump -q -m <input-file.bz2>`. One parsed output row represents one prefix-level announcement or withdrawal observation emitted from an UPDATE record, not a final feature row.",
            ),
            (
                "Acquisition and Processing",
                "MRT files were planned in 15-minute UTC UPDATE slots. The full TRAIN plan recorded 25,099 MRT assignments and 20,524 unique MRT URLs. The processing path retained incident-relevant prefix-level observations and later aggregated them into five-minute analytical windows.",
            ),
            (
                "Non-recovered Details",
                "Exact network transfer conditions and all temporary cache states are not part of the frozen methodology; source URLs, manifests, and parser metadata are preserved.",
            ),
        ],
    )

    write_md(
        OUT / "reproducibility_windowing_v1.md",
        "Five Minute Windowing Reproducibility v1",
        [
            (
                "Analytical Unit",
                "The model input unit is a five-minute incident-relevant BGP window. The independent experimental unit remains the incident; all windows inherit their incident partition and label.",
            ),
            (
                "Window Construction",
                "RouteViews UPDATE observations are assigned to UTC five-minute windows using BGP timestamps. Hijack and Leak active windows are derived from detector-supported observations; Outage intervals use documented Cloudflare outage start and end intervals. Silent gaps are not automatically treated as Normal.",
            ),
            (
                "Row Counts",
                "The frozen TRAIN V4 corpus contains 68,031 rows. The Final Holdout V4 corpus contains 14,906 rows. The final Holdout evaluation remains terminal and immutable.",
            ),
            (
                "TTI Boundary",
                "The retrospective early-classification/TTI work is a separate post-hoc analysis and does not replace the primary five-minute Level-1 plus Level-2 temporal stacking architecture.",
            ),
        ],
    )

    write_md(
        OUT / "reproducibility_caida_v1.md",
        "CAIDA AS Relationship Feature Reproducibility v1",
        [
            ("Feature Set", "The frozen V4 schema contains 14 CAIDA AS-relationship features, documented in `config/caida_feature_schema_v1.yaml`."),
            (
                "Historical Alignment",
                "CAIDA relationship data are selected as historical context for the observation period. Features are computed from observed AS_PATH transitions and valley-free relationship checks; source/provider identifiers are not included as model features.",
            ),
            ("Definitions", md_table([r for r in features if r["feature_family"] == "CAIDA AS-relationship"], ["family_order", "feature_name", "definition", "formula"])),
        ],
    )

    write_md(
        OUT / "reproducibility_rpki_v1.md",
        "RPKI ROV Feature Reproducibility v1",
        [
            ("Feature Set", "The frozen V4 schema contains 16 RPKI/ROV features, documented in `config/rpki_feature_schema_v1.yaml`."),
            (
                "Historical Alignment",
                "RPKI/VRP state is evaluated using historical VRP information corresponding to the observation period. The feature family preserves VALID, INVALID_ORIGIN, INVALID_LENGTH, NOT_FOUND, and UNEVALUABLE states without adding post-outcome label information.",
            ),
            ("Definitions", md_table([r for r in features if r["feature_family"] == "RPKI/ROV"], ["family_order", "feature_name", "definition", "formula"])),
        ],
    )

    write_md(
        OUT / "reproducibility_i1_weighting_v1.md",
        "I1 Incident Aware Weighting Reproducibility v1",
        [
            (
                "Formula",
                "`I1` retains all eligible windows and assigns each training row a sample weight of `1 / n_i`, where `n_i` is the number of eligible windows for the same incident or model group on the training side of the current fold. The aggregate influence of an incident is therefore approximately one unit regardless of how many windows it contributes.",
            ),
            (
                "Worked Example",
                "If Incident A contributes 4 windows, each window receives weight 0.25, for an aggregate weight of 1.0. If Incident B contributes 200 windows, each window receives weight 0.005, also totaling 1.0. The calculation is performed within training folds only, so held-out incidents do not influence fitted weights.",
            ),
            (
                "Evidence",
                "The recovered Level-1 training specification cites `src/bgp_incident_detection/imbalance_model_experiment.py` and `data/modeling/xgboost_weight_semantics_audit_v1.csv`. The corpus balancing audit also records the same formula.",
            ),
        ],
    )

    level1_config = read_yaml(ROOT / "config/final_model_candidate_v3_1_xgb_refined.yaml")
    hp = level1_config.get("selected_hyperparameters", {})
    write_md(
        OUT / "reproducibility_level1_xgboost_v1.md",
        "Level 1 XGBoost Reproducibility v1",
        [
            ("Candidate", "`XGB_REFINED_TRAIN_CANDIDATE` is the frozen Level-1 model family used by the final K1 architecture."),
            (
                "Hyperparameters",
                md_table(
                    [{"hyperparameter": k, "value": v} for k, v in hp.items()] + [{"hyperparameter": "objective", "value": level1_config.get("objective")}, {"hyperparameter": "num_class", "value": level1_config.get("num_class")}, {"hyperparameter": "eval_metric", "value": level1_config.get("eval_metric")}],
                    ["hyperparameter", "value"],
                ),
            ),
            (
                "Feature and Weighting Inputs",
                "Input features are the frozen V4 74-feature schema in exact order. I1 incident-aware sample weights are used. Missing values are handled with median imputation fitted only on the training side of each fold.",
            ),
            (
                "Reconstruction Note",
                "The original serialized Level-1 artifact was not preserved. A controlled reconstruction under `data/tti_pilot/reconstructed_level1_v1/` passed exact probability equivalence against 68,031 preserved TRAIN predictions: max, mean, and median absolute probability differences were all 0.0.",
            ),
        ],
    )

    k1 = read_yaml(ROOT / "config/k1_final_candidate_v1_1_deployable.yaml")
    write_md(
        OUT / "reproducibility_level2_stacker_v1.md",
        "Level 2 Temporal Stacker Reproducibility v1",
        [
            (
                "Architecture",
                "The final Praxis architecture is `A0_XGB_TO_XGB`: five fold-specific Level-1 XGBoost models generate window-level class probabilities, and a Level-2 XGBoost temporal stacker consumes incident-level meta-features derived from those probabilities.",
            ),
            (
                "Meta Feature Schema",
                "`config/k1_incident_meta_feature_schema_v1.yaml` freezes 74 incident-level meta-features, including probability summaries, class-vote proportions, confidence/margin/entropy summaries, early/middle/late temporal summaries, and probability slopes.",
            ),
            (
                "Inference",
                f"Final first-level inference strategy: `{k1.get('first_level_inference_strategy')}`. Ranking rule: `{k1.get('ranking_rule')}`. Second-level configuration: `{k1.get('second_level_configuration')}`.",
            ),
        ],
    )

    write_md(
        OUT / "reproducibility_grouped_cv_v1.md",
        "Grouped Cross Validation Reproducibility v1",
        [
            (
                "Grouping Rule",
                "Cross-validation is incident grouped: no incident appears in more than one split for a given training/evaluation comparison. Window rows inherit incident membership, preventing window-level leakage.",
            ),
            (
                "Fold Assignment Evidence",
                "Recovered artifacts cite `data/modeling/baseline_v1_grouped_cv_assignments_v1.csv`, with `cv_seed=20260828`, and K1 leakage audits confirm grouped out-of-fold probability generation for Level-1.",
            ),
            (
                "Validation and Holdout",
                "Validation was first accessed in Phase J for a single confirmation of the locked refined XGBoost candidate. K1 was developed after Validation using TRAIN-only nested/grouped procedures and was not Validation-confirmed. Final Holdout remained sealed until Phase L and is now closed.",
            ),
        ],
    )

    write_md(
        OUT / "reproducibility_metrics_v1.md",
        "Evaluation Metrics Reproducibility v1",
        [
            (
                "Primary Metrics",
                "Incident-level Macro F1, Top-1 accuracy, Top-2 accuracy, and MRR are the principal metrics. Per-class precision, recall, and F1 are reported for Hijack, Leak, and Outage. Window-level metrics are development diagnostics only and must not be mixed with incident-level uncertainty.",
            ),
            (
                "Ranking",
                "Class ranking is descending score for Hijack, Leak, and Outage. Because calibration diagnostics found imperfect calibration, the scores should be interpreted primarily as class-ranking scores rather than operationally calibrated probabilities.",
            ),
            (
                "Terminal Final Holdout",
                f"Final Holdout: N={final_metrics['holdout_incidents']}, Macro F1={final_metrics['incident_macro_f1']}, 95% CI=[{final_metrics['macro_f1_ci_lower']}, {final_metrics['macro_f1_ci_upper']}], Top-1={final_metrics['top1']}, Top-2={final_metrics['top2']}, MRR={final_metrics['mrr']}. Source: `config/final_praxis_result_v1.yaml`.",
            ),
        ],
    )

    env_rows = [
        {"component": "audit_python", "version": platform.python_version(), "source": "current audit runtime", "status": "RECORDED"},
        {"component": "platform", "version": platform.platform(), "source": "current audit runtime", "status": "RECORDED"},
    ]
    env_path = ROOT / "data/modeling/xgboost_environment_v1.csv"
    if env_path.exists():
        env_df = pd.read_csv(env_path)
        for _, row in env_df.iterrows():
            env_rows.append(
                {
                    "component": row.get("package", ""),
                    "version": row.get("version", ""),
                    "source": "data/modeling/xgboost_environment_v1.csv",
                    "status": row.get("status", "RECORDED"),
                }
            )
    parser_env_path = ROOT / "data/pilot/mrt_parser_environment_v1.csv"
    if parser_env_path.exists():
        parser_df = pd.read_csv(parser_env_path)
        for _, row in parser_df.iterrows():
            env_rows.append(
                {
                    "component": row.get("tool_or_library", ""),
                    "version": row.get("version", ""),
                    "source": "data/pilot/mrt_parser_environment_v1.csv",
                    "status": "RECORDED",
                }
            )
    write_csv(OUT / "reproducibility_software_environment_v1.csv", env_rows)

    spec_rows = [
        {"item": "Final corpus", "value": "1,419 incidents; 473 Hijack / 473 Leak / 473 Outage", "source": "data/roster_v2/frozen_incident_roster_v2.csv"},
        {"item": "Experimental split", "value": "TRAIN 993; Validation 213; Final Holdout 213", "source": "data/partitions_v2/frozen_partition_manifest_v2.csv"},
        {"item": "Analytical window", "value": "5-minute RouteViews-observable BGP windows", "source": "src/bgp_incident_detection/windows.py"},
        {"item": "Feature schema", "value": "V4 = 74 features; 44 Behavioral + 14 CAIDA + 16 RPKI/ROV", "source": "config/*_feature_schema_v1.yaml"},
        {"item": "Weighting", "value": "I1 incident-aware sample weights", "source": "data/tti_pilot/level1_training_specification_v1.csv"},
        {"item": "Level-1 classifier", "value": "Five-model crossfit XGBoost ensemble", "source": "config/k1_final_candidate_v1_1_deployable.yaml"},
        {"item": "Level-2 classifier", "value": "XGBoost incident temporal stacker", "source": "config/k1_second_level_xgb_final_v1.yaml"},
        {"item": "Evaluation", "value": "Incident-level grouped/nested CV; frozen one-time Final Holdout", "source": "config/final_praxis_result_v1.yaml"},
        {"item": "Final metrics", "value": f"Macro F1 {final_metrics['incident_macro_f1']}; Top-2 {final_metrics['top2']}; MRR {final_metrics['mrr']}", "source": "config/final_praxis_result_v1.yaml"},
    ]
    write_csv(OUT / "reproducibility_final_experimental_specification_v1.csv", spec_rows)
    write_md(
        OUT / "reproducibility_final_experimental_specification_v1.md",
        "Final Experimental Reproducibility Specification v1",
        [("Specification Table", md_table(spec_rows, ["item", "value", "source"]))],
    )

    write_md(
        OUT / "chapter3_reproducibility_subsection_v1.md",
        "Chapter 3 Reproducibility Subsection Draft v1",
        [
            (
                "Proposed insertion location",
                "Insert near the end of Chapter 3 after the model architecture and evaluation protocol sections, before the transition to Chapter 4.",
            ),
            (
                "Draft text",
                "The final experiment was frozen as an incident-level supervised classification and ranking pipeline. The authoritative corpus contains 1,419 externally labeled BGP incidents balanced to 473 Hijack, 473 Leak, and 473 Outage cases. Incidents, not windows, are the independent experimental unit. The frozen v2 split assigns 993 incidents to TRAIN, 213 to Validation, and 213 to Final Holdout, with no incident UID overlap across partitions. Five-minute RouteViews UPDATE windows inherit the incident partition and label. The feature representation is V4, consisting of 74 frozen features: 44 behavioral BGP features, 14 historical CAIDA AS-relationship features, and 16 historical RPKI/ROV features. TRAIN development used I1 incident-aware sample weighting so that incidents with many five-minute windows did not dominate model fitting. The final architecture uses a five-model cross-fit Level-1 XGBoost ensemble followed by a Level-2 XGBoost temporal stacker that summarizes window-level class scores at the incident level. Evaluation reports incident-level Macro F1, Top-1, Top-2, MRR, per-class precision, recall, and F1. The terminal Final Holdout was evaluated once after model freeze; it remains immutable and is not used for model selection or further tuning. Separate post-hoc audits document corpus balancing, label provenance, partition independence, calibration terminology, and the Hijack:68538 quality-gate caveat.",
            ),
        ],
    )

    summary_sections = [
        (
            "Audit Scope",
            f"Generated UTC: {generated_at}\n\nThis audit is additive and documentation-only. It did not run training, validation, holdout prediction, feature regeneration, or manuscript edits.",
        ),
        (
            "Recovered Core Methodology",
            "\n".join(
                [
                    "- Final corpus: 1,419 incidents; 473 per class.",
                    "- Split: TRAIN 993, Validation 213, Final Holdout 213.",
                    "- Feature schema: V4 = 74 features = 44 Behavioral + 14 CAIDA + 16 RPKI/ROV.",
                    "- Weighting: I1 incident-aware window weights.",
                    "- Level 1: five-model crossfit XGBoost ensemble.",
                    "- Level 2: XGBoost temporal stacker over incident meta-features.",
                    "- Final Holdout remains terminal and immutable.",
                ]
            ),
        ),
        (
            "Supporting Remediation Audits Incorporated",
            "\n".join(
                [
                    "- Corpus balancing: `REPRODUCIBLE_WITH_DOCUMENTED_GAPS`.",
                    "- Label provenance: `PASS_WITH_DOCUMENTED_OVERLAP`, with zero direct target leakage found in the V4 feature schema.",
                    "- Partition independence: `PASS_WITH_DOCUMENTED_RELATED_EVENTS`.",
                    "- Calibration terminology: `PROBABILITY_TERMINOLOGY_SUPPORTED_WITH_CALIBRATION_LIMITATION`.",
                    "- Hijack:68538: `QUALITY_GATE_INCONSISTENCY`, documented as a limitation rather than a change to official results.",
                ]
            ),
        ),
        ("Unrecovered or Limited Items", md_table(gap_rows, ["area", "status", "gap", "impact", "mitigation"])),
        (
            "Disposition",
            "`REPRODUCIBLE_WITH_DOCUMENTED_LIMITATIONS`\n\nThe final pipeline is sufficiently documented for Chapter 3 methods, dissertation defense, and reproducibility narrative. The remaining limitations should be disclosed rather than resolved by altering historical artifacts.",
        ),
    ]
    write_md(OUT / "reproducibility_audit_summary_v1.md", "Final Methodology Reproducibility Audit Summary v1", summary_sections)
    write_md(
        OUT / "reproducibility_final_disposition_v1.md",
        "Reproducibility Final Disposition v1",
        [
            (
                "Final Disposition",
                "`REPRODUCIBLE_WITH_DOCUMENTED_LIMITATIONS`",
            ),
            (
                "Rationale",
                "The authoritative corpus, split, feature schemas, training specification, Level-1 reconstruction evidence, Level-2 architecture specification, grouped CV semantics, metrics, and terminal Final Holdout result are preserved in versioned artifacts. The audit identifies several important but bounded limitations: the original first-pass Hijack/Leak sampling script was not uniquely recovered, the original serialized Level-1 model was not preserved but was reconstructed with exact probability equivalence, historical hardware details are incomplete, and Hijack:68538 remains a documented quality-gate inconsistency.",
            ),
            (
                "Stop Condition",
                "No datasets, models, labels, partitions, metrics, figures, tables, or manuscript files were modified by this audit.",
            ),
        ],
    )

    manifest_rows = [{"output_file": rel(p), "sha256": sha256(p), "generated_utc": generated_at} for p in sorted(OUT.glob("reproducibility_*_v1.*"))]
    manifest_rows += [{"output_file": rel(p), "sha256": sha256(p), "generated_utc": generated_at} for p in sorted(OUT.glob("chapter3_*_v1.md"))]
    write_csv(OUT / "reproducibility_output_manifest_v1.csv", manifest_rows)


if __name__ == "__main__":
    main()
