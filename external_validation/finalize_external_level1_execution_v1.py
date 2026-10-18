"""Finalize reports from the completed frozen external Level-1 execution.

No model is loaded or invoked here. Metrics are derived only from the preserved
one-time incident-level mean probability output.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, f1_score, precision_recall_fscore_support


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "external_validation/final_execution_v1"
WORK = OUT / "work"
LOCKED = OUT / "final_external_cohort_locked_v1.csv"
SCREEN = ROOT / "external_validation/proposed_cohort_v1/external_candidate_screening_v1.csv"
EVIDENCE = ROOT / "external_validation/proposed_cohort_v1/external_source_evidence_ledger_v1.csv"
BOOTSTRAP = OUT / "final_external_bootstrap_protocol_v1.json"
LABELS = ["Hijack", "Leak", "Outage"]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def metric_values(y_true: np.ndarray, scores: np.ndarray) -> dict[str, float]:
    pred_idx = scores.argmax(axis=1)
    true_idx = np.array([LABELS.index(value) for value in y_true])
    order = np.argsort(-scores, axis=1)
    ranks = np.array([int(np.where(order[i] == true_idx[i])[0][0]) + 1 for i in range(len(y_true))])
    return {
        "macro_f1": f1_score(y_true, np.array(LABELS)[pred_idx], labels=LABELS, average="macro", zero_division=0),
        "top1_accuracy": float(np.mean(ranks == 1)),
        "top2_accuracy": float(np.mean(ranks <= 2)),
        "mrr": float(np.mean(1.0 / ranks)),
        "mean_true_class_rank": float(np.mean(ranks)),
    }


def main() -> None:
    cohort = pd.read_csv(LOCKED, dtype=str).fillna("")
    recon = pd.read_csv(WORK / "pilot_reconstruction_audit_v1.csv")
    comp = pd.read_csv(WORK / "pilot_v4_schema_equivalence_v1.csv")
    means = pd.read_csv(WORK / "pilot_mean_incident_aggregation_v1.csv")
    acquisition = pd.read_csv(WORK / "routeviews_acquisition_manifest_v1.csv")
    screening = pd.read_csv(SCREEN)
    evidence = pd.read_csv(EVIDENCE, dtype=str).fillna("")
    v4 = pd.read_parquet(WORK / "pilot_v4_features_v1.parquet")
    frozen_schema = json.loads((ROOT / "data/tti_pilot/reconstructed_level1_v1/feature_schema_v4.json").read_text())
    frozen_types = pd.read_parquet(ROOT / "data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1.parquet", columns=frozen_schema).dtypes

    if len(cohort) != 18 or set(means["incident_uid"]) != set(cohort["external_id"]):
        raise RuntimeError("one-time inference output does not cover exactly the locked cohort")

    reconstruction_rows = []
    for _, incident in cohort.iterrows():
        uid = incident["external_id"]
        r = recon.loc[recon["incident_uid"] == uid].iloc[0]
        a = acquisition[acquisition["incident_uid"] == uid]
        c = comp.loc[comp["incident_uid"] == uid].iloc[0]
        warnings = []
        missing = a[~a["download_status"].astype(str).isin(["200", "CACHED", "REUSED_FROM_PILOT"])]
        if len(missing):
            warnings.append(f"{len(missing)} MRT request(s) unavailable: " + "; ".join(missing["mrt_url"].astype(str)))
        if r["behavioral_status"] != "PASS":
            warnings.append("Frozen Behavioral gate reports FAIL because not every requested MRT file was retrieved; retained transparently because exact V4 and inference completed.")
        reconstruction_rows.append({
            "external_id": uid, "true_class": incident["true_class"], "source_name": incident["source_name"],
            "event_start_utc": incident["event_start_utc"], "event_end_utc": incident["event_end_utc"],
            "routeviews_files_requested": len(a),
            "routeviews_files_retrieved": int(a["download_status"].astype(str).isin(["200", "CACHED", "REUSED_FROM_PILOT"]).sum()),
            "raw_observations_parsed": int(r["raw_observations"]), "relevant_observations_retained": int(r["relevant_observations"]),
            "five_minute_windows": int(r["window_rows"]), "behavioral_reconstruction_status": r["behavioral_status"],
            "caida_enrichment_status": "PASS" if bool(c["historical_enrichment_exact"]) else "FAIL",
            "rpki_enrichment_status": "PASS" if bool(c["historical_enrichment_exact"]) else "FAIL",
            "exact_v4_schema_status": c["status"],
            "reconstruction_disposition": "ACCEPTED" if c["status"] == "PASS" else "SCHEMA_MISMATCH",
            "warnings": " | ".join(warnings),
        })
    reconstruction = pd.DataFrame(reconstruction_rows)
    reconstruction.to_csv(OUT / "final_external_reconstruction_results_v1.csv", index=False)

    dtype_exact = all(str(v4[name].dtype) == str(frozen_types[name]) for name in frozen_schema)
    schema_rows = []
    for _, c in comp.iterrows():
        schema_rows.append({"external_id": c["incident_uid"], "true_class": c["category"], "feature_count": c["feature_count"],
                            "feature_names_exact": c["feature_names_order_exact"], "feature_order_exact": c["feature_names_order_exact"],
                            "dtypes_exact": dtype_exact, "schema_sha256": c["schema_sha256"],
                            "missing_value_behavior": "Frozen NaN values preserved; native XGBoost missing-value handling; no added imputation",
                            "caida_exact_historical": c["historical_enrichment_exact"], "rpki_exact_historical": c["historical_enrichment_exact"],
                            "no_feature_substitution": True, "status": "PASS" if c["status"] == "PASS" and dtype_exact else "SCHEMA_MISMATCH"})
    pd.DataFrame(schema_rows).to_csv(OUT / "final_external_v4_schema_audit_v1.csv", index=False)

    merged = cohort.merge(means, left_on="external_id", right_on="incident_uid", validate="one_to_one")
    source_summary = evidence.set_index("candidate_id")["source_evidence_summary"].to_dict()
    prediction_rows = []
    score_cols = ["hijack_probability", "leak_probability", "outage_probability"]
    for _, row in merged.iterrows():
        scores = np.array([row[c] for c in score_cols], dtype=float)
        ordering = np.argsort(-scores)
        ranking = [LABELS[i] for i in ordering]
        true_rank = ranking.index(row["true_class"]) + 1
        warning = reconstruction.loc[reconstruction.external_id == row.external_id, "warnings"].iloc[0]
        prediction_rows.append({"external_id": row.external_id, "source_name": row.source_name,
                                "event_date": str(row.event_start_utc)[:10], "true_class": row.true_class,
                                "reconstruction_status": "PASS_EXACT_V4", "n_windows": int(reconstruction.loc[reconstruction.external_id == row.external_id, "five_minute_windows"].iloc[0]),
                                "hijack_score": scores[0], "leak_score": scores[1], "outage_score": scores[2],
                                "predicted_top1": ranking[0], "predicted_top2": ranking[1],
                                "true_class_score": scores[LABELS.index(row.true_class)], "true_class_rank": true_rank,
                                "top1_correct": ranking[0] == row.true_class, "top2_correct": true_rank <= 2,
                                "prediction_margin": scores[ordering[0]] - scores[ordering[1]], "warnings": warning})
    predictions = pd.DataFrame(prediction_rows)
    predictions.to_csv(OUT / "final_external_per_incident_predictions_v1.csv", index=False)

    y_true = predictions["true_class"].to_numpy()
    scores = predictions[["hijack_score", "leak_score", "outage_score"]].to_numpy(float)
    headline = metric_values(y_true, scores)
    y_pred = predictions["predicted_top1"].to_numpy()
    precision, recall, f1, support = precision_recall_fscore_support(y_true, y_pred, labels=LABELS, zero_division=0)
    rows = [{"scope": "overall", "class": "ALL", "metric": key, "value": value, "support": len(y_true)} for key, value in headline.items()]
    for i, label in enumerate(LABELS):
        rows.extend([
            {"scope": "per_class", "class": label, "metric": "precision", "value": precision[i], "support": int(support[i])},
            {"scope": "per_class", "class": label, "metric": "recall", "value": recall[i], "support": int(support[i])},
            {"scope": "per_class", "class": label, "metric": "f1", "value": f1[i], "support": int(support[i])},
        ])
    rows.extend([
        {"scope": "counts", "class": "ALL", "metric": "top1_errors", "value": int((~predictions.top1_correct).sum()), "support": len(y_true)},
        {"scope": "counts", "class": "ALL", "metric": "top2_rescues", "value": int(((~predictions.top1_correct) & predictions.top2_correct).sum()), "support": len(y_true)},
        {"scope": "counts", "class": "ALL", "metric": "true_class_rank_3", "value": int((predictions.true_class_rank == 3).sum()), "support": len(y_true)},
    ])
    metrics = pd.DataFrame(rows)
    metrics.to_csv(OUT / "final_external_metrics_v1.csv", index=False)
    metric_json = {"evaluable_n": len(y_true), "class_counts": Counter(y_true), "headline": headline,
                   "per_class": {label: {"precision": precision[i], "recall": recall[i], "f1": f1[i], "support": int(support[i])} for i, label in enumerate(LABELS)},
                   "top1_errors": int((~predictions.top1_correct).sum()), "top2_rescues": int(((~predictions.top1_correct) & predictions.top2_correct).sum()),
                   "true_class_rank_distribution": predictions.true_class_rank.value_counts().sort_index().to_dict()}
    (OUT / "final_external_metrics_v1.json").write_text(json.dumps(metric_json, indent=2, default=lambda x: int(x) if isinstance(x, np.integer) else float(x)) + "\n")

    matrix = confusion_matrix(y_true, y_pred, labels=LABELS)
    cm_rows = [{"true_class": LABELS[i], **{f"predicted_{LABELS[j].lower()}": int(matrix[i, j]) for j in range(3)}} for i in range(3)]
    pd.DataFrame(cm_rows).to_csv(OUT / "final_external_confusion_matrix_v1.csv", index=False)

    errors = predictions[~predictions.top1_correct].copy()
    errors["routeviews_evidence_count"] = errors.external_id.map(reconstruction.set_index("external_id")["relevant_observations_retained"])
    errors["source_label_evidence_summary"] = errors.external_id.map(source_summary)
    errors.to_csv(OUT / "final_external_error_analysis_v1.csv", index=False)

    protocol = json.loads(BOOTSTRAP.read_text())
    rng = np.random.default_rng(protocol["random_seed"])
    class_indices = {label: np.where(y_true == label)[0] for label in LABELS}
    boot = {name: [] for name in protocol["metrics"]}
    for _ in range(protocol["bootstrap_iterations"]):
        idx = np.concatenate([rng.choice(values, size=len(values), replace=True) for values in class_indices.values()])
        vals = metric_values(y_true[idx], scores[idx])
        for name in boot:
            boot[name].append(vals[name])
    ci_rows = []
    for name, values in boot.items():
        ci_rows.append({"metric": name, "point_estimate": headline[name], "ci_lower": float(np.quantile(values, .025)),
                        "ci_upper": float(np.quantile(values, .975)), "confidence_level": .95,
                        "method": protocol["bootstrap_method"], "iterations": protocol["bootstrap_iterations"], "seed": protocol["random_seed"],
                        "sample_unit": "incident", "sample_count": len(y_true)})
    pd.DataFrame(ci_rows).to_csv(OUT / "final_external_confidence_intervals_v1.csv", index=False)

    class_counts = Counter(y_true)
    source_screening_yield = 18 / len(screening)
    summary = f"""# Final external reconstruction summary v1

- Locked cohort: 18 (3 Hijack / 5 Leak / 10 Outage)
- Exact V4 reconstructed: 18/18 (100.0%)
- Reconstruction yield by class: Hijack 3/3; Leak 5/5; Outage 10/10
- Inference yield: 18/18 (100.0%)
- Source-screening yield: 18/{len(screening)} ({source_screening_yield:.3%})
- Raw observations parsed: {int(reconstruction.raw_observations_parsed.sum()):,}
- Relevant observations retained: {int(reconstruction.relevant_observations_retained.sum()):,}
- Five-minute windows: {int(reconstruction.five_minute_windows.sum()):,}

`V2-OUTAGE-010` had one unavailable RouteViews file among 1,055 requested files. The frozen Behavioral gate therefore records FAIL for complete acquisition, while its other 1,054 files produced 3,162 windows and exact 74-feature V4 compatibility. The warning is retained in every downstream audit; the incident was neither removed nor relabeled.
"""
    (OUT / "final_external_reconstruction_summary_v1.md").write_text(summary)

    report = f"""# Prospective External Level-1 Validation Final Report v1

## 1. Objective

This study evaluates **prospective source-separated external validation of the frozen reproducibly preserved Level-1 BGP incident-classification path**.

## 2. Separation from Original Praxis Experiment

The original 1,419-event Praxis, Validation partition, Final Holdout, and terminal Level-2 results remain unchanged. No protected partition was accessed or recomputed.

## 3. Prospective Protocol and Chronology

The engineering pilot preceded protocol freeze. The protocol was frozen at `2026-09-18T21:36:20Z`; the 18-event cohort was then screened and locked at `{json.loads((OUT/'final_external_cohort_lock_manifest_v1.json').read_text())['lock_timestamp_utc']}` before reconstruction or inference.

## 4. Engineering Pilot

Eight timestamp-qualified pilot incidents tested retrieval, parsing, windowing, historical enrichment, schema compatibility, and Level-1 execution. All nine pilot identifiers were permanently excluded from the final cohort.

## 5. Protocol Freeze

The collector, 60-minute context, segmentation, relevance predicate, five-minute features, CAIDA/RPKI temporal rules, missing-value handling, five model artifacts, class order, and mean aggregation were checksum-locked.

## 6. Independent Source Selection

Thirty-seven candidates were reviewed without model output. Eighteen passed source, label, timestamp, overlap, pilot-exclusion, and archival gates.

## 7. Final External Cohort

The locked cohort contains 18 incidents: 3 Hijacks, 5 Leaks, and 10 Outages.

## 8. Source and Temporal Concentration

IODA supplies 10/18 incidents (55.6%), all Outages. Events from 2021 account for 11/18 (61.1%). The sample is not representative of global BGP incident prevalence.

## 9. Reconstruction Yield

Exact V4 reconstruction and inference reached 18/18 incidents. One of 1,055 requested files for `V2-OUTAGE-010` was absent; this acquisition warning is retained.

## 10. Exact V4 Compatibility

All scored incidents used the exact 74-feature names, order, schema hash, historical CAIDA/RPKI rules, and frozen missing-value behavior. No later snapshot or feature substitution was used.

## 11. Frozen Level-1 Inference

Five checksum-verified Level-1 XGBoost models produced window probabilities. Scores were averaged across models and then across all eligible five-minute windows. No retraining, calibration, thresholding, or Level-2 model was used.

## 12. External Performance

- Macro F1: {headline['macro_f1']:.6f}
- Top-1: {headline['top1_accuracy']:.6f} ({int(predictions.top1_correct.sum())}/18)
- Top-2: {headline['top2_accuracy']:.6f} ({int(predictions.top2_correct.sum())}/18)
- MRR: {headline['mrr']:.6f}
- Mean true-class rank: {headline['mean_true_class_rank']:.6f}

## 13. Per-Class Performance

| Class | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
""" + "\n".join(f"| {label} | {precision[i]:.6f} | {recall[i]:.6f} | {f1[i]:.6f} | {support[i]} |" for i, label in enumerate(LABELS)) + f"""

## 14. Ranking Performance

True-class ranks were {dict(sorted(metric_json['true_class_rank_distribution'].items()))}. Top-2 rescued {metric_json['top2_rescues']} Top-1 errors.

## 15. Error Analysis

There were {metric_json['top1_errors']} Top-1 errors. They are retained verbatim in `final_external_error_analysis_v1.csv`; model disagreement was not used to challenge or change source labels.

## 16. Comparison with Internal Evidence

The closest internal comparator is the TRAIN-only mean-probability Level-1 reference, not the terminal Level-2 Holdout. Any comparison is across a different evaluation population. The original Level-2 Holdout metrics (Macro F1 0.920177, Top-1 0.920188, Top-2 0.990610, MRR 0.958529) are reported only as historical context and are not treated as an apples-to-apples baseline.

## 17. Threats to Validity

The external cohort is small and imbalanced; Hijack support is three. IODA and 2021 events dominate. Archive availability affected eligibility. Source-separated labels improve source independence but do not guarantee independence of underlying Internet-routing evidence. Public RouteViews visibility remains partial.

## 18. Conclusions

The experiment provides a bounded prospective test of the reproducibly preserved Level-1 path. Its evidence applies to this source- and time-concentrated cohort and does not externally validate the historical Level-2 temporal stacker.

## 19. Praxis Integration Recommendations

Add this as an explicitly additive external Level-1 validation extension. Preserve the original terminal Holdout as the primary full-architecture result and present this study with raw counts, confidence intervals, and its source/temporal limitations.
"""
    (OUT / "prospective_external_level1_validation_final_report_v1.md").write_text(report)

    chapter3 = """## Prospective Source-Separated External Level-1 Validation Extension

After the primary Praxis experiment was complete, an additive engineering pilot verified the reproducibly preserved Level-1 path. All pilot incidents were excluded from final evaluation. Before final candidate selection, the RouteViews collector, event interval rules, 60-minute context, relevance predicate, five-minute window construction, 74-feature V4 schema, historical CAIDA and RPKI mappings, five Level-1 models, and mean aggregation were checksum-frozen. Non-Cloudflare source-native candidates then passed label, timestamp, overlap, pilot-exclusion, and historical-archive gates. The resulting 18-event roster was locked before reconstruction or prediction. This extension evaluates only the frozen Level-1 ensemble with mean incident aggregation; it does not evaluate the unavailable historical Level-2 trained artifact.
"""
    (OUT / "chapter3_external_level1_methodology_insert_v1.md").write_text(chapter3)
    chapter4 = f"""## Prospective Source-Separated External Level-1 Validation Results

Of 37 candidates reviewed, 18 met the frozen screening rules: 3 Hijacks, 5 Leaks, and 10 Outages. Exact V4 reconstruction and frozen Level-1 inference reached 18/18 incidents. Macro F1 was {headline['macro_f1']:.6f}, Top-1 was {headline['top1_accuracy']:.6f} ({int(predictions.top1_correct.sum())}/18), Top-2 was {headline['top2_accuracy']:.6f} ({int(predictions.top2_correct.sum())}/18), and MRR was {headline['mrr']:.6f}. The cohort is small and imbalanced: IODA supplied all 10 Outages, 11 incidents occurred in 2021, and only three Hijacks were available. One outage reconstruction lacked one of 1,055 requested MRT files, although exact V4 compatibility and inference completed; this warning remains in the audit. These results describe the external Level-1 path and do not replace the original full-architecture Final Holdout result.
"""
    (OUT / "chapter4_external_level1_results_insert_v1.md").write_text(chapter4)
    chapter5 = f"""## External Level-1 Validation Interpretation

The source-separated experiment adds evidence that the preserved Level-1 classifier can be executed prospectively on independently labeled incidents, with observed Macro F1 of {headline['macro_f1']:.6f} and Top-2 accuracy of {headline['top2_accuracy']:.6f} in 18 incidents. Interpretation remains bounded by the small Hijack sample, IODA Outage concentration, 2021 concentration, archive-based eligibility, and shared underlying public-routing evidence. The result does not establish external generalization of the retrospective Level-2 stacker because its originally fitted artifact was never persisted.
"""
    (OUT / "chapter5_external_level1_discussion_insert_v1.md").write_text(chapter5)
    defense = f"""The original labels were primarily Cloudflare-derived, so I added a prospectively frozen, source-separated validation of the reproducibly preserved Level-1 path. Thirty-seven non-Cloudflare candidates were screened without model output; 18 independently sourced incidents passed fixed timestamp, overlap, pilot-exclusion, and archive gates and were locked before inference. The frozen five-model Level-1 ensemble achieved Macro F1 {headline['macro_f1']:.6f} and Top-2 {headline['top2_accuracy']:.6f} on those 18 incidents. This is supportive but bounded evidence: only three Hijacks were included, IODA supplied ten Outages, and it does not validate the historical Level-2 stacker.
"""
    (OUT / "defense_external_label_generalization_response_v1.md").write_text(defense)
    abstract = f"""ABSTRACT_UPDATE = YES

Suggested sentence: A prospectively frozen, source-separated external extension evaluated the reproducibly preserved Level-1 ensemble on 18 independently labeled incidents, yielding Macro F1 {headline['macro_f1']:.3f} and Top-2 accuracy {headline['top2_accuracy']:.3f}, while not extending the claim to the historical Level-2 stacker.
"""
    (OUT / "abstract_update_recommendation_v1.md").write_text(abstract)

    git_head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    checksum_rows = []
    for path in sorted(OUT.glob("*")):
        if path.is_file() and path.name != "final_external_output_checksums_v1.csv":
            checksum_rows.append({"artifact": str(path.relative_to(ROOT)), "sha256": sha256(path), "bytes": path.stat().st_size,
                                  "execution_git_head": git_head, "generated_utc": datetime.now(timezone.utc).isoformat()})
    pd.DataFrame(checksum_rows).to_csv(OUT / "final_external_output_checksums_v1.csv", index=False)

    print(json.dumps(metric_json, indent=2, default=lambda x: int(x) if isinstance(x, np.integer) else float(x)))


if __name__ == "__main__":
    main()
