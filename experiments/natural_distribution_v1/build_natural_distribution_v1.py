from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "experiments" / "natural_distribution_v1"

ALL_AVAILABLE = ROOT / "cloudflare_incidents" / "training_ready_bgp_incident_roster_all_available_to_2026-01.csv"
SAMPLING_AUDIT = ROOT / "cloudflare_incidents" / "stratified_quality_sampling_audit.csv"
OUTAGE_DEDUP = ROOT / "cloudflare_incidents" / "quality_controlled_cloudflare_outage_roster_deduplicated.csv"
OUTAGE_POOL = ROOT / "cloudflare_incidents" / "recommended_final_cloudflare_outage_pool.csv"
BALANCED_V1 = ROOT / "cloudflare_incidents" / "balanced_incident_level_roster_473_each_leak_hijack_outage.csv"
BALANCED_V2 = ROOT / "data" / "roster_v2" / "balanced_incident_roster_v2.csv"
DUP_PLAN = ROOT / "data" / "roster_v2" / "duplicate_canonicalization_plan.csv"
REPLACEMENTS = ROOT / "data" / "roster_v2" / "replacement_incidents.csv"
K1_PREDS = ROOT / "data" / "modeling_k1" / "k1_incident_level_predictions_v1.parquet"
K1_RESULTS = ROOT / "data" / "modeling_k1" / "k1_model_results_v1.csv"

FINAL_K1_CANDIDATE = "K1-M2_XGB_K1-TEMPORAL"
CLASS_ORDER = ["HIJACK", "LEAK", "OUTAGE"]
PROB_COLS = ["p_hijack", "p_leak", "p_outage"]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def norm_category(s: pd.Series) -> pd.Series:
    return s.astype(str).str.strip().str.upper()


def read_sources() -> dict[str, pd.DataFrame]:
    frames = {
        "all_available": pd.read_csv(ALL_AVAILABLE),
        "sampling_audit": pd.read_csv(SAMPLING_AUDIT),
        "outage_dedup": pd.read_csv(OUTAGE_DEDUP),
        "outage_pool": pd.read_csv(OUTAGE_POOL),
        "balanced_v1": pd.read_csv(BALANCED_V1),
        "balanced_v2": pd.read_csv(BALANCED_V2),
        "dup_plan": pd.read_csv(DUP_PLAN),
        "replacements": pd.read_csv(REPLACEMENTS),
        "k1_preds": pd.read_parquet(K1_PREDS),
        "k1_results": pd.read_csv(K1_RESULTS),
    }
    return frames


def accounting(frames: dict[str, pd.DataFrame]) -> pd.DataFrame:
    all_counts = norm_category(frames["all_available"]["category"]).value_counts()
    audit = frames["sampling_audit"].copy()
    audit["category_norm"] = norm_category(audit["category"])
    eligible = dict(zip(audit["category_norm"], audit["eligible_count"]))
    raw_audit = dict(zip(audit["category_norm"], audit["raw_count"]))

    outage_dedup_count = len(frames["outage_dedup"])
    outage_pool_count = len(frames["outage_pool"])
    b1_counts = norm_category(frames["balanced_v1"]["category"]).value_counts()
    b2_counts = norm_category(frames["balanced_v2"]["category"]).value_counts()

    dup_plan = frames["dup_plan"].copy()
    dup_plan["category_norm"] = norm_category(dup_plan["category"])
    repl = frames["replacements"].copy()
    repl["category_norm"] = norm_category(repl["category"])

    # Known from the v2 duplicate canonicalization plan: records_to_exclude lists
    # duplicate incident_uids in the already sampled balanced roster.
    removed_by_class = {"HIJACK": 0, "LEAK": 0, "OUTAGE": 0}
    for _, row in dup_plan.iterrows():
        cat = row["category_norm"]
        val = row.get("records_to_exclude_from_v2", "")
        try:
            parsed = json.loads(val) if isinstance(val, str) and val.strip() else []
        except json.JSONDecodeError:
            parsed = [x for x in str(val).split(";") if x.strip()]
        removed_by_class[cat] = removed_by_class.get(cat, 0) + len(parsed)

    rows = []
    stages = [
        (
            "raw_candidate_incidents",
            {
                "HIJACK": int(all_counts.get("HIJACK", 0)),
                "LEAK": int(all_counts.get("LEAK", 0)),
                "OUTAGE": int(all_counts.get("OUTAGE", 0)),
            },
            "training_ready_bgp_incident_roster_all_available_to_2026-01.csv",
            "All candidate records in the all-available Cloudflare-derived roster before deliberate class balancing.",
        ),
        (
            "deduplication",
            {
                "HIJACK": int(all_counts.get("HIJACK", 0)),
                "LEAK": int(all_counts.get("LEAK", 0)),
                "OUTAGE": int(outage_dedup_count),
            },
            "quality_controlled_cloudflare_outage_roster_deduplicated.csv; full-universe Hijack/Leak duplicate-collapse artifact not found",
            "Outage has a documented deduplicated QC roster. Full-universe Hijack/Leak duplicate collapse was not found; duplicate remediation is documented later for the sampled v2 roster.",
        ),
        (
            "source_validation",
            {
                "HIJACK": int(all_counts.get("HIJACK", 0)),
                "LEAK": int(all_counts.get("LEAK", 0)),
                "OUTAGE": int(outage_dedup_count),
            },
            "training_ready_bgp_incident_roster_all_available_to_2026-01.csv; quality_controlled_cloudflare_outage_roster_deduplicated.csv",
            "Cloudflare-derived source/provenance retained. No external global prevalence is imposed.",
        ),
        (
            "quality_filtering_usable_prebalancing",
            {
                "HIJACK": int(eligible.get("HIJACK", all_counts.get("HIJACK", 0))),
                "LEAK": int(eligible.get("LEAK", all_counts.get("LEAK", 0))),
                "OUTAGE": int(outage_pool_count),
            },
            "stratified_quality_sampling_audit.csv; recommended_final_cloudflare_outage_pool.csv",
            "This is the observed natural distribution used here: usable, source-validated candidate incidents before deliberate 473/473/473 balancing.",
        ),
        (
            "balanced_v1_selected",
            {
                "HIJACK": int(b1_counts.get("HIJACK", 0)),
                "LEAK": int(b1_counts.get("LEAK", 0)),
                "OUTAGE": int(b1_counts.get("OUTAGE", 0)),
            },
            "balanced_incident_level_roster_473_each_leak_hijack_outage.csv",
            "Deliberate class-equalized scientific corpus.",
        ),
        (
            "balanced_v2_post_duplicate_collapse",
            {
                "HIJACK": int(b1_counts.get("HIJACK", 0) - removed_by_class.get("HIJACK", 0)),
                "LEAK": int(b1_counts.get("LEAK", 0) - removed_by_class.get("LEAK", 0)),
                "OUTAGE": int(b1_counts.get("OUTAGE", 0) - removed_by_class.get("OUTAGE", 0)),
            },
            "duplicate_canonicalization_plan.csv",
            "Confirmed duplicate groups collapsed logically inside the balanced roster; source records preserved.",
        ),
        (
            "balanced_v2_replacements_added",
            {
                "HIJACK": int(repl["category_norm"].value_counts().get("HIJACK", 0)),
                "LEAK": int(repl["category_norm"].value_counts().get("LEAK", 0)),
                "OUTAGE": int(repl["category_norm"].value_counts().get("OUTAGE", 0)),
            },
            "replacement_incidents.csv",
            "Replacement incidents selected to restore 473 incidents per class after duplicate collapse.",
        ),
        (
            "balanced_final_v2",
            {
                "HIJACK": int(b2_counts.get("HIJACK", 0)),
                "LEAK": int(b2_counts.get("LEAK", 0)),
                "OUTAGE": int(b2_counts.get("OUTAGE", 0)),
            },
            "balanced_incident_roster_v2.csv",
            "Authoritative balanced frozen corpus retained unchanged.",
        ),
    ]
    for stage, counts, source, notes in stages:
        total = sum(counts.values())
        for klass in ["HIJACK", "LEAK", "OUTAGE"]:
            rows.append(
                {
                    "stage": stage,
                    "category": klass.title(),
                    "count": counts.get(klass, 0),
                    "proportion_within_stage": counts.get(klass, 0) / total if total else np.nan,
                    "source_artifact": source,
                    "notes": notes,
                }
            )
    return pd.DataFrame(rows)


def build_roster(frames: dict[str, pd.DataFrame]) -> pd.DataFrame:
    all_df = frames["all_available"].copy()
    all_df["category_norm"] = norm_category(all_df["category"])
    outage_pool_ids = set(frames["outage_pool"]["incident_id"].astype(str))
    cols = [
        c
        for c in [
            "incident_id",
            "incident_name",
            "category",
            "incident_date",
            "start_utc",
            "end_utc",
            "duration_minutes",
            "primary_asn",
            "affected_asns",
            "affected_prefixes",
            "prefix_count",
            "peer_count",
            "countries",
            "source_url",
            "confidence_score",
            "notes",
        ]
        if c in all_df.columns
    ]
    roster = all_df[cols + ["category_norm"]].copy()
    roster["incident_uid"] = roster["category_norm"].str.title() + ":" + roster["incident_id"].astype(str)
    roster["source_system"] = np.select(
        [
            roster["category_norm"].eq("HIJACK"),
            roster["category_norm"].eq("LEAK"),
            roster["category_norm"].eq("OUTAGE"),
        ],
        [
            "Cloudflare Radar BGP hijack detector/source feed",
            "Cloudflare Radar BGP route leak detector/source feed",
            "Cloudflare Radar outage catalog/feed",
        ],
        default="Cloudflare-derived incident source",
    )
    roster["source_validated"] = True
    roster["usable_prebalancing"] = np.where(
        roster["category_norm"].isin(["HIJACK", "LEAK"]),
        True,
        roster["incident_id"].astype(str).isin(outage_pool_ids),
    )
    roster["prebalance_exclusion_reason"] = np.where(
        roster["usable_prebalancing"],
        "",
        "Outage did not enter recommended final quality-controlled outage pool.",
    )
    roster["natural_distribution_definition"] = "Observed collected-corpus distribution before deliberate class balancing"
    order = ["incident_uid"] + [c for c in roster.columns if c != "incident_uid"]
    return roster[order].sort_values(["category_norm", "incident_id"], kind="stable")


def rank_metrics(preds: pd.DataFrame) -> pd.DataFrame:
    pred = preds.copy()
    prob = pred[PROB_COLS].to_numpy()
    pred["predicted_class"] = np.array(CLASS_ORDER)[prob.argmax(axis=1)]
    true_idx = pred["true_class"].map({c: i for i, c in enumerate(CLASS_ORDER)}).to_numpy()
    ranks = []
    top2 = []
    for row, idx in zip(prob, true_idx):
        order = np.argsort(row)[::-1]
        rank = int(np.where(order == idx)[0][0] + 1)
        ranks.append(rank)
        top2.append(rank <= 2)
    pred["true_class_rank"] = ranks
    pred["top1_correct"] = pred["predicted_class"].eq(pred["true_class"])
    pred["top2_correct"] = top2
    pred["reciprocal_rank"] = 1 / pred["true_class_rank"]
    return pred


def natural_reweighted_metrics(pred: pd.DataFrame, natural_counts: dict[str, int]) -> tuple[pd.DataFrame, pd.DataFrame]:
    labels = CLASS_ORDER
    y_true = pred["true_class"].to_numpy()
    y_pred = pred["predicted_class"].to_numpy()
    cm = confusion_matrix(y_true, y_pred, labels=labels)

    # Row-normalized class-conditional error behavior from TRAIN-only nested CV.
    row_sums = cm.sum(axis=1, keepdims=True)
    row_rates = np.divide(cm, row_sums, out=np.zeros_like(cm, dtype=float), where=row_sums != 0)
    natural_vector = np.array([natural_counts[c] for c in labels], dtype=float)
    weighted_cm = row_rates * natural_vector[:, None]

    tp = np.diag(weighted_cm)
    pred_pos = weighted_cm.sum(axis=0)
    true_pos = weighted_cm.sum(axis=1)
    precision = np.divide(tp, pred_pos, out=np.zeros_like(tp), where=pred_pos != 0)
    recall = np.divide(tp, true_pos, out=np.zeros_like(tp), where=true_pos != 0)
    f1 = np.divide(2 * precision * recall, precision + recall, out=np.zeros_like(tp), where=(precision + recall) != 0)
    support_prop = natural_vector / natural_vector.sum()

    per_class_top2 = pred.groupby("true_class")["top2_correct"].mean().reindex(labels)
    per_class_mrr = pred.groupby("true_class")["reciprocal_rank"].mean().reindex(labels)

    metric_rows = []
    for i, klass in enumerate(labels):
        metric_rows.extend(
            [
                {
                    "metric_scope": "per_class_natural_prior_reweighted",
                    "metric": "precision",
                    "category": klass.title(),
                    "value": precision[i],
                    "source_artifact": str(K1_PREDS.relative_to(ROOT)),
                    "notes": "Precision recomputed from TRAIN class-conditional confusion rates under observed natural class priors.",
                },
                {
                    "metric_scope": "per_class_natural_prior_reweighted",
                    "metric": "recall",
                    "category": klass.title(),
                    "value": recall[i],
                    "source_artifact": str(K1_PREDS.relative_to(ROOT)),
                    "notes": "Recall is class-conditional behavior from TRAIN nested-CV predictions.",
                },
                {
                    "metric_scope": "per_class_natural_prior_reweighted",
                    "metric": "f1",
                    "category": klass.title(),
                    "value": f1[i],
                    "source_artifact": str(K1_PREDS.relative_to(ROOT)),
                    "notes": "F1 recomputed using natural-prior precision and class-conditional recall.",
                },
            ]
        )
    aggregate = {
        "macro_f1": float(np.mean(f1)),
        "weighted_f1": float(np.sum(f1 * support_prop)),
        "top1_accuracy": float(np.trace(weighted_cm) / weighted_cm.sum()),
        "top2_accuracy": float(np.sum(per_class_top2.to_numpy() * support_prop)),
        "mrr": float(np.sum(per_class_mrr.to_numpy() * support_prop)),
    }
    for metric, value in aggregate.items():
        metric_rows.append(
            {
                "metric_scope": "aggregate_natural_prior_reweighted",
                "metric": metric,
                "category": "All",
                "value": value,
                "source_artifact": str(K1_PREDS.relative_to(ROOT)),
                "notes": "TRAIN-only K1 nested-CV incident predictions reweighted to the observed usable pre-balancing collected-corpus class distribution.",
            }
        )

    cm_rows = []
    for i, true_class in enumerate(labels):
        for j, pred_class in enumerate(labels):
            cm_rows.append(
                {
                    "true_class": true_class.title(),
                    "predicted_class": pred_class.title(),
                    "balanced_train_count": int(cm[i, j]),
                    "balanced_train_row_rate": float(row_rates[i, j]),
                    "natural_prior_reweighted_count": float(weighted_cm[i, j]),
                    "source_artifact": str(K1_PREDS.relative_to(ROOT)),
                }
            )
    return pd.DataFrame(metric_rows), pd.DataFrame(cm_rows)


def source_inventory() -> pd.DataFrame:
    paths = [
        ALL_AVAILABLE,
        SAMPLING_AUDIT,
        OUTAGE_DEDUP,
        OUTAGE_POOL,
        BALANCED_V1,
        BALANCED_V2,
        DUP_PLAN,
        REPLACEMENTS,
        K1_PREDS,
        K1_RESULTS,
    ]
    rows = []
    for p in paths:
        rows.append(
            {
                "artifact": str(p.relative_to(ROOT)),
                "exists": p.exists(),
                "sha256": sha256(p) if p.exists() else "",
            }
        )
    return pd.DataFrame(rows)


def write_reports(account: pd.DataFrame, metrics: pd.DataFrame, cm: pd.DataFrame, pred: pd.DataFrame) -> None:
    usable = account[account["stage"].eq("quality_filtering_usable_prebalancing")]
    natural_counts = dict(zip(usable["category"], usable["count"]))
    total = sum(natural_counts.values())
    proportions = {k: v / total for k, v in natural_counts.items()}

    selected = pred["candidate_id"].iloc[0]
    k1_results = pd.read_csv(K1_RESULTS)
    selected_row = k1_results[k1_results["candidate_id"].eq(selected)].iloc[0].to_dict()

    audit_md = f"""# Natural Distribution Provenance Audit v1

This additive audit estimates the observed class distribution of the collected, source-validated incident corpus before deliberate 473/473/473 balancing. It does **not** claim global Internet-wide incident prevalence.

## Definition

**Observed Natural Distribution** = class proportions of usable, source-validated collected incidents before deliberate balancing.

For this repository, the usable pre-balancing counts are:

| Class | Count | Proportion |
|---|---:|---:|
| Hijack | {natural_counts['Hijack']:,} | {proportions['Hijack']:.6f} |
| Leak | {natural_counts['Leak']:,} | {proportions['Leak']:.6f} |
| Outage | {natural_counts['Outage']:,} | {proportions['Outage']:.6f} |
| Total | {total:,} | 1.000000 |

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
- It is not a complete feature-ready evaluation corpus for all {total:,} incidents.
- Therefore, this phase uses a safe TRAIN-only class-prior reweighted sensitivity view rather than creating a new final generalization claim.

## Source Artifacts

See `natural_distribution_source_inventory_v1.csv` for SHA-256 checksums.
"""
    (OUT / "natural_distribution_audit_v1.md").write_text(audit_md)

    design_md = f"""# Natural Distribution Evaluation Design v1

## Objective

Evaluate how the already-developed K1 classifier behavior would summarize under the observed collected-corpus class prior, without retraining and without touching Validation or Final Holdout.

## Evaluation Type

**TRAIN-only class-prior reweighted sensitivity analysis.**

The selected prediction artifact is `{K1_PREDS.relative_to(ROOT)}` filtered to `{FINAL_K1_CANDIDATE}`. This is the existing TRAIN-only nested-CV incident-level K1 prediction artifact:

- incidents: 993
- class balance: 331 Hijack / 331 Leak / 331 Outage
- Validation used: no
- Final Holdout status: sealed

## Why Not a New Natural Final Holdout?

The all-available pre-balancing corpus does not have final K1 features/predictions for every candidate incident. Creating those predictions would require additional acquisition/feature generation/model execution beyond this audit. Reusing or reshaping the sealed Final Holdout would risk confusing the terminal balanced holdout result, so this design avoids it.

## Reweighting Method

1. Compute class-conditional confusion behavior from existing TRAIN nested-CV incident predictions.
2. Apply those class-conditional rates to the observed natural class counts:
   - Hijack: {natural_counts['Hijack']:,}
   - Leak: {natural_counts['Leak']:,}
   - Outage: {natural_counts['Outage']:,}
3. Recompute natural-prior precision, recall, F1, weighted F1, Top-1, Top-2, and MRR.

## Interpretation Boundary

Balanced corpus = controlled scientific comparison across classes.

Natural distribution = sensitivity analysis under observed class prevalence in the collected source corpus.

This analysis does not replace the authoritative balanced Final Holdout result and does not estimate global Internet-wide incident prevalence.
"""
    (OUT / "natural_distribution_evaluation_design_v1.md").write_text(design_md)

    agg = metrics[metrics["metric_scope"].eq("aggregate_natural_prior_reweighted")]
    per = metrics[metrics["metric_scope"].eq("per_class_natural_prior_reweighted")]
    summary_lines = [
        "# Natural Distribution Summary v1",
        "",
        "## Disposition",
        "",
        "`NATURAL_DISTRIBUTION_TRAIN_ONLY_SENSITIVITY_COMPLETE`",
        "",
        "## Natural Distribution Counts",
        "",
        f"- Hijack: {natural_counts['Hijack']:,} ({proportions['Hijack']:.4%})",
        f"- Leak: {natural_counts['Leak']:,} ({proportions['Leak']:.4%})",
        f"- Outage: {natural_counts['Outage']:,} ({proportions['Outage']:.4%})",
        "",
        "## Reweighted Metrics",
        "",
    ]
    for _, row in agg.iterrows():
        summary_lines.append(f"- {row['metric']}: {row['value']:.6f}")
    summary_lines.extend(
        [
            "",
            "## Per-Class Natural-Prior Metrics",
            "",
            per.pivot_table(index="category", columns="metric", values="value", aggfunc="first")
            .reset_index()
            .to_markdown(index=False, floatfmt=".6f"),
            "",
            "## Balanced K1 Reference",
            "",
            f"- Candidate: {selected}",
            f"- Balanced TRAIN nested-CV Macro F1: {selected_row['incident_macro_f1']:.6f}",
            f"- Balanced TRAIN nested-CV Top-1: {selected_row['top1']:.6f}",
            f"- Balanced TRAIN nested-CV Top-2: {selected_row['top2']:.6f}",
            f"- Balanced TRAIN nested-CV MRR: {selected_row['mrr']:.6f}",
            "",
            "## Caveat",
            "",
            "Because outages are rare in the observed collected-corpus distribution, weighted aggregate scores are dominated by Hijack and Leak behavior. Macro F1 remains the more class-balanced summary; weighted F1 is the prevalence-sensitive summary.",
        ]
    )
    (OUT / "natural_distribution_summary_v1.md").write_text("\n".join(summary_lines) + "\n")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    frames = read_sources()

    account = accounting(frames)
    account.to_csv(OUT / "natural_distribution_accounting_v1.csv", index=False)

    roster = build_roster(frames)
    roster.to_csv(OUT / "natural_distribution_incident_roster_v1.csv", index=False)

    usable = account[account["stage"].eq("quality_filtering_usable_prebalancing")]
    natural_counts = {row["category"].upper(): int(row["count"]) for _, row in usable.iterrows()}

    preds = frames["k1_preds"]
    pred = preds[preds["candidate_id"].eq(FINAL_K1_CANDIDATE)].copy()
    if len(pred) != 993:
        raise RuntimeError(f"Expected 993 TRAIN incident predictions for {FINAL_K1_CANDIDATE}, found {len(pred)}")
    pred = rank_metrics(pred)

    metrics, cm = natural_reweighted_metrics(pred, natural_counts)
    metrics.to_csv(OUT / "natural_distribution_metrics_v1.csv", index=False)
    cm.to_csv(OUT / "natural_distribution_confusion_matrix_v1.csv", index=False)
    source_inventory().to_csv(OUT / "natural_distribution_source_inventory_v1.csv", index=False)

    write_reports(account, metrics, cm, pred)


if __name__ == "__main__":
    main()
