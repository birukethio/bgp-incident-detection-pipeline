from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, precision_recall_fscore_support


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "experiments" / "tti_early_horizon_v2"

TRAIN_ROSTER = ROOT / "data/partitions_v2/train_incidents_v2.csv"
TTI_COHORT = ROOT / "data/tti_train_full_v2_1/tti_train_evaluable_cohort_v2_1.csv"
INSUFFICIENT = ROOT / "data/tti_train_full_v2_1/tti_insufficient_evidence_review_v2_1.csv"
PRED = OUT / "early_horizon_predictions_v2.csv"
METRICS = OUT / "early_horizon_metrics_v2.csv"
TTI = OUT / "early_horizon_tti_v2.csv"
LEAKAGE = OUT / "early_horizon_leakage_assertions_v2.csv"

HORIZONS = [30, 60, 120, 300, 600, 900]
HORIZON_LABELS = {
    30: "30 sec",
    60: "60 sec",
    120: "120 sec",
    300: "300 sec (5 min)",
    600: "600 sec (10 min)",
    900: "900 sec (15 min)",
}
CLASSES = ["Hijack", "Leak", "Outage"]
EXPECTED = {
    30: dict(macro_f1=0.790817, top1_accuracy=0.790437, top2_accuracy=0.932859, mrr=0.884028, hijack_f1=0.778378, leak_f1=0.769231, outage_f1=0.824841),
    60: dict(macro_f1=0.843014, top1_accuracy=0.842319, top2_accuracy=0.953204, mrr=0.913360, hijack_f1=0.824022, leak_f1=0.829822, outage_f1=0.875197),
    120: dict(macro_f1=0.873308, top1_accuracy=0.872838, top2_accuracy=0.973550, mrr=0.932011, hijack_f1=0.857143, leak_f1=0.877743, outage_f1=0.885039),
    300: dict(macro_f1=0.898440, top1_accuracy=0.898271, top2_accuracy=0.972533, mrr=0.944557, hijack_f1=0.887240, leak_f1=0.901538, outage_f1=0.906542),
    600: dict(macro_f1=0.904445, top1_accuracy=0.904419, top2_accuracy=0.979445, mrr=0.948784, hijack_f1=0.891603, leak_f1=0.913505, outage_f1=0.908228),
    900: dict(macro_f1=0.893060, top1_accuracy=0.893004, top2_accuracy=0.972222, mrr=0.941872, hijack_f1=0.882083, leak_f1=0.897898, outage_f1=0.899200),
}


def load_inputs() -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    roster = pd.read_csv(TRAIN_ROSTER, low_memory=False)
    cohort = pd.read_csv(TTI_COHORT, low_memory=False)
    insufficient = pd.read_csv(INSUFFICIENT, low_memory=False)
    pred = pd.read_csv(PRED, low_memory=False)
    tti = pd.read_csv(TTI, low_memory=False)
    return roster, cohort, insufficient, pred, tti


def recompute_metrics(pred: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for horizon, group in pred.groupby("horizon_seconds", sort=True):
        y_true = group["true_class"]
        y_pred = group["predicted_top1_class"]
        _, _, class_f1, support = precision_recall_fscore_support(y_true, y_pred, labels=CLASSES, zero_division=0)
        rows.append(
            {
                "horizon_seconds": int(horizon),
                "horizon": HORIZON_LABELS[int(horizon)],
                "evaluable_incidents": int(len(group)),
                "macro_f1": f1_score(y_true, y_pred, labels=CLASSES, average="macro", zero_division=0),
                "top1_accuracy": float(group["top1_correct"].astype(bool).mean()),
                "top2_accuracy": float(group["top2_correct"].astype(bool).mean()),
                "mrr": float((1.0 / group["true_class_rank"].astype(float)).mean()),
                "hijack_f1": float(class_f1[0]),
                "leak_f1": float(class_f1[1]),
                "outage_f1": float(class_f1[2]),
                "hijack_support": int(support[0]),
                "leak_support": int(support[1]),
                "outage_support": int(support[2]),
            }
        )
    out = pd.DataFrame(rows)
    for metric in ["macro_f1", "top1_accuracy", "top2_accuracy", "mrr", "hijack_f1", "leak_f1", "outage_f1"]:
        out[f"{metric}_expected_rounded"] = out["horizon_seconds"].map(lambda h: EXPECTED[int(h)][metric])
        out[f"{metric}_round6_match"] = np.isclose(out[metric].round(6), out[f"{metric}_expected_rounded"], atol=0, rtol=0)
    return out


def incident_accounting(roster: pd.DataFrame, cohort: pd.DataFrame, insufficient: pd.DataFrame, pred: pd.DataFrame) -> pd.DataFrame:
    roster_ids = set(roster["incident_uid"].astype(str))
    cohort_ids = set(cohort.loc[cohort["tti_evaluable_status"].eq("TTI_EVALUABLE"), "incident_uid"].astype(str))
    pred_ids = set(pred["incident_uid"].astype(str))
    excluded_ids = sorted(roster_ids - cohort_ids)
    insufficient_map = insufficient.set_index("incident_uid").to_dict("index")
    cohort_map = cohort.set_index("incident_uid").to_dict("index")
    roster_map = roster.set_index("incident_uid").to_dict("index")
    rows = []
    rows.append(
        {
            "row_type": "SUMMARY",
            "incident_uid": "",
            "incident_id": "",
            "category": "",
            "train_corpus_count": len(roster_ids),
            "tti_evaluable_count": len(cohort_ids),
            "excluded_count": len(excluded_ids),
            "final_tti_denominator": len(pred_ids),
            "status": "PASS" if len(roster_ids) == 993 and len(cohort_ids) == 983 and len(pred_ids) == 983 and len(excluded_ids) == 10 else "REVIEW",
            "exclusion_reason": "993 TRAIN -> 983 TTI-evaluable -> 10 excluded before scoring",
            "evidence": "train roster, tti_train_evaluable_cohort_v2_1, early_horizon_predictions_v2",
        }
    )
    for uid in excluded_ids:
        r = roster_map.get(uid, {})
        inc = insufficient_map.get(uid)
        coh = cohort_map.get(uid, {})
        if inc:
            reason = inc.get("final_tti_status", "TTI_NOT_EVALUABLE_INSUFFICIENT_ROUTEVIEWS_EVIDENCE")
            evidence = inc.get("notes", "")
        else:
            reason = coh.get("tti_evaluable_status", "TTI_NOT_EVALUABLE_ONSET_UNRESOLVED")
            evidence = "No valid FIRST_POST_DOCUMENTED_EVENT_EVIDENCE onset under frozen methodology."
        rows.append(
            {
                "row_type": "EXCLUDED_INCIDENT",
                "incident_uid": uid,
                "incident_id": r.get("incident_id", uid.split(":")[-1]),
                "category": r.get("category", uid.split(":")[0]),
                "train_corpus_count": "",
                "tti_evaluable_count": "",
                "excluded_count": "",
                "final_tti_denominator": "",
                "status": reason,
                "exclusion_reason": reason,
                "evidence": evidence,
            }
        )
    return pd.DataFrame(rows)


def horizon_denominators(pred: pd.DataFrame, tti: pd.DataFrame) -> pd.DataFrame:
    rows = []
    tti_ids = set(tti["incident_uid"])
    for horizon in HORIZONS:
        hp = pred[pred["horizon_seconds"].eq(horizon)]
        ids = set(hp["incident_uid"])
        rows.append(
            {
                "horizon_seconds": horizon,
                "horizon": HORIZON_LABELS[horizon],
                "prediction_rows": len(hp),
                "unique_incidents": len(ids),
                "same_as_tti_denominator_983": len(ids) == 983,
                "missing_from_983_count": len(tti_ids - ids),
                "extra_vs_983_count": len(ids - tti_ids),
            }
        )
    return pd.DataFrame(rows)


def tti_cumulative(tti: pd.DataFrame) -> pd.DataFrame:
    denom = len(tti)
    rows = []
    for kind, col in [("Top-1", "top1_tti_checkpoint"), ("Top-2", "top2_tti_checkpoint")]:
        cumulative = 0
        for label, horizon in [("<=30s", 30), ("<=60s", 60), ("<=120s", 120), ("<=300s", 300), ("<=600s", 600), ("<=900s", 900)]:
            newly = int((tti[col] == label).sum())
            cumulative += newly
            rows.append(
                {
                    "metric": kind,
                    "checkpoint": label,
                    "checkpoint_seconds": horizon,
                    "newly_identified_count": newly,
                    "cumulative_identified_count": cumulative,
                    "eligible_denominator": denom,
                    "newly_identified_percent": newly / denom * 100,
                    "cumulative_identified_percent": cumulative / denom * 100,
                }
            )
        not_id = int((tti[col] == "NOT_IDENTIFIED_WITHIN_AVAILABLE_HORIZONS").sum())
        rows.append(
            {
                "metric": kind,
                "checkpoint": "NOT_IDENTIFIED_WITHIN_900S_OR_AVAILABLE_HORIZONS",
                "checkpoint_seconds": "",
                "newly_identified_count": not_id,
                "cumulative_identified_count": cumulative,
                "eligible_denominator": denom,
                "newly_identified_percent": not_id / denom * 100,
                "cumulative_identified_percent": cumulative / denom * 100,
            }
        )
    return pd.DataFrame(rows)


def class_tti(tti: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for cls, group in tti.groupby("true_class", sort=True):
        denom = len(group)
        for horizon in HORIZONS:
            count = int((group["top1_tti_checkpoint_seconds"].fillna(np.inf) <= horizon).sum())
            rows.append(
                {
                    "class": cls,
                    "checkpoint_seconds": horizon,
                    "checkpoint": f"<={horizon}s",
                    "top1_cumulative_identified_count": count,
                    "class_denominator": denom,
                    "top1_cumulative_identified_percent": count / denom * 100,
                }
            )
    return pd.DataFrame(rows)


def saturation_statement(metrics_check: pd.DataFrame) -> tuple[pd.DataFrame, str]:
    m = metrics_check.set_index("horizon_seconds")
    rows = []
    for start, end in zip(HORIZONS[:-1], HORIZONS[1:]):
        delta = float(m.loc[end, "macro_f1"] - m.loc[start, "macro_f1"])
        rows.append({"transition": f"{start}->{end}", "macro_f1_delta": delta})
    df = pd.DataFrame(rows)
    statement = (
        "Classification performance improved substantially as evidence accumulated through the first five minutes. "
        "Beyond 300 seconds, gains were small and inconsistent: Macro F1 increased by 0.006005 from 300 to 600 seconds "
        "and then declined by 0.011385 from 600 to 900 seconds. Five minutes therefore represents a practical analytical "
        "tradeoff point rather than a mathematically proven optimum."
    )
    return df, statement


def write_reports(
    accounting: pd.DataFrame,
    denominators: pd.DataFrame,
    metrics_check: pd.DataFrame,
    tti_cum: pd.DataFrame,
    class_rates: pd.DataFrame,
    sat: pd.DataFrame,
    statement: str,
    leakage_failures: int,
) -> str:
    all_metric_matches = metrics_check.filter(like="_round6_match").all().all()
    denom_ok = denominators.loc[denominators["horizon_seconds"].isin([30, 60, 120, 300]), "unique_incidents"].eq(983).all()
    leakage_ok = leakage_failures == 0
    disposition = "PASS_WITH_DOCUMENTED_EXCLUSIONS" if all_metric_matches and denom_ok and leakage_ok else "REVIEW_REQUIRED"
    median_rule = (
        "Median checkpoint TTI is calculated over the 983 TTI-denominator incidents by taking the median of the earliest "
        "checkpoint seconds where the relevant condition is met; incidents not identified within available horizons are excluded "
        "from the numeric median and reported separately."
    )
    tti = pd.read_csv(TTI, low_memory=False)
    median_top1 = tti["top1_tti_checkpoint_seconds"].dropna().median()
    median_top2 = tti["top2_tti_checkpoint_seconds"].dropna().median()
    lines = [
        "# Early Horizon Final Verification v2",
        "",
        "This is a verification-only continuation of the additive TRAIN-only Level-1 early-horizon experiment. No Validation or Final Holdout rows were accessed, recomputed, or modified. No frozen model or manuscript result was changed.",
        "",
        "## Final disposition",
        "",
        f"`{disposition}`",
        "",
        "## Incident accounting",
        "",
        accounting.to_markdown(index=False),
        "",
        "## Horizon denominators",
        "",
        denominators.to_markdown(index=False),
        "",
        "The 10 absent TRAIN incidents were excluded before TTI scoring: nine had genuinely insufficient RouteViews evidence under the frozen relevance predicates, and one had unresolved observable onset under the frozen FIRST_POST_DOCUMENTED_EVENT_EVIDENCE rule.",
        "",
        "## Metric verification",
        "",
        metrics_check[[
            "horizon", "evaluable_incidents", "macro_f1", "top1_accuracy", "top2_accuracy", "mrr", "hijack_f1", "leak_f1", "outage_f1"
        ]].to_markdown(index=False),
        "",
        f"All rounded-to-6 expected metric checks passed: `{bool(all_metric_matches)}`.",
        f"Leakage assertion failures: `{leakage_failures}`.",
        "",
        "## TTI cumulative percentages",
        "",
        tti_cum.to_markdown(index=False),
        "",
        "## Class-specific Top-1 cumulative TTI",
        "",
        class_rates.to_markdown(index=False),
        "",
        "## Saturation check",
        "",
        sat.to_markdown(index=False),
        "",
        statement,
        "",
        "## Median checkpoint TTI",
        "",
        median_rule,
        "",
        f"- Median Top-1 checkpoint TTI among identified incidents: <= {int(median_top1)} seconds.",
        f"- Median Top-2 checkpoint TTI among identified incidents: <= {int(median_top2)} seconds.",
    ]
    (OUT / "early_horizon_final_verification_v2.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (OUT / "early_horizon_final_disposition_v2.md").write_text(f"# Early Horizon Final Disposition v2\n\n`{disposition}`\n\n{statement}\n", encoding="utf-8")
    return disposition


def main() -> None:
    roster, cohort, insufficient, pred, tti = load_inputs()
    accounting = incident_accounting(roster, cohort, insufficient, pred)
    denominators = horizon_denominators(pred, tti)
    metrics_check = recompute_metrics(pred)
    tti_cum = tti_cumulative(tti)
    class_rates = class_tti(tti)
    sat, statement = saturation_statement(metrics_check)
    leakage = pd.read_csv(LEAKAGE, low_memory=False)
    leakage_failures = int((leakage["status"] != "PASS").sum())

    accounting.to_csv(OUT / "early_horizon_incident_accounting_v2.csv", index=False)
    denominators.to_csv(OUT / "early_horizon_horizon_denominators_v2.csv", index=False)
    metrics_check.to_csv(OUT / "early_horizon_metric_reverification_v2.csv", index=False)
    tti_cum.to_csv(OUT / "early_horizon_tti_cumulative_v2.csv", index=False)
    class_rates.to_csv(OUT / "early_horizon_class_tti_v2.csv", index=False)
    sat.to_csv(OUT / "early_horizon_saturation_verification_v2.csv", index=False)
    disposition = write_reports(accounting, denominators, metrics_check, tti_cum, class_rates, sat, statement, leakage_failures)
    print(disposition)


if __name__ == "__main__":
    main()
