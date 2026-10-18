from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parent
PROJECT = ROOT.parents[1]
ROSTER_PATH = PROJECT / "data/roster_v2/frozen_incident_roster_v2.csv"

KENTIK_PATH = PROJECT / "cloudflare_incidents/cloudflare_kentik_route_leak_validation_2024-2025.csv"
PULSE_ADDITIONAL_PATH = PROJECT / "cloudflare_incidents/cloudflare_pulse_additional_matched_outage_records.csv"
PULSE_IQ_PATH = PROJECT / "cloudflare_incidents/cloudflare_pulse_matched_outage_records_2025_iq.csv"
MANRS_IODA_PATH = PROJECT / "cloudflare_incidents/cloudflare_manrs_ioda_matched_incidents_2021-2025.csv"
RIPESTAT_STRONG_PATH = PROJECT / "cloudflare_incidents/exhaustive_daily_cloudflare_ripestat_strong_matches_2024-2025.csv"

SEED = 20260915
LABELS = ["Hijack", "Leak", "Outage"]


def safe_str(value) -> str:
    if pd.isna(value):
        return ""
    return str(value)


def parse_list_text(value) -> list[str]:
    if pd.isna(value) or value == "":
        return []
    text = str(value)
    try:
        parsed = ast.literal_eval(text)
        if isinstance(parsed, list):
            return [str(v) for v in parsed]
    except Exception:
        pass
    return [text]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def build_label_mapping_rules() -> pd.DataFrame:
    rows = [
        {
            "source_native_term_pattern": "hijack | BGP hijack | route hijack | prefix hijack | unauthorized origin | route misorigination",
            "mapped_label": "Hijack",
            "include_in_agreement": "YES",
            "exclusion_condition": "Exclude if the external source is only an aggregate count and cannot be tied to the same incident.",
            "rationale": "Terms denote unauthorized origin/prefix origination events matching the study's Hijack class.",
        },
        {
            "source_native_term_pattern": "route leak | BGP leak | path leak | route optimizer leak | valley-free violation",
            "mapped_label": "Leak",
            "include_in_agreement": "YES",
            "exclusion_condition": "Exclude if no same-event time, ASN, or AS-path evidence links the source event to a Cloudflare incident.",
            "rationale": "Terms denote policy/path propagation failures matching the study's Leak class.",
        },
        {
            "source_native_term_pattern": "outage | Internet outage | Internet shutdown | disruption | loss of connectivity | government-directed shutdown",
            "mapped_label": "Outage",
            "include_in_agreement": "YES",
            "exclusion_condition": "Exclude ambiguous traffic-only anomalies when no outage/shutdown/loss-of-connectivity claim is made.",
            "rationale": "Terms denote reachability/connectivity outage events matching the study's Outage class.",
        },
        {
            "source_native_term_pattern": "RIPEstat BGP update match | RouteViews/RIS update evidence without incident label",
            "mapped_label": "AMBIGUOUS_SUPPORTING_EVIDENCE_ONLY",
            "include_in_agreement": "NO",
            "exclusion_condition": "Always excluded from label agreement unless paired with an independent source-native class label.",
            "rationale": "Raw routing observations can corroborate data visibility but do not independently classify the real-world incident.",
        },
        {
            "source_native_term_pattern": "MANRS monthly country/economy routeMisoriginations summary",
            "mapped_label": "AMBIGUOUS_AGGREGATE_CONTEXT_ONLY",
            "include_in_agreement": "NO",
            "exclusion_condition": "Excluded when matching uses only category, country/economy, and calendar month.",
            "rationale": "Aggregate counts do not deterministically identify the same real-world Cloudflare incident.",
        },
    ]
    return pd.DataFrame(rows)


def add_kentik_matches(roster: pd.DataFrame) -> list[dict]:
    rows: list[dict] = []
    if not KENTIK_PATH.exists():
        return rows
    df = pd.read_csv(KENTIK_PATH)
    df = df[df["cloudflare_match_status"].eq("confirmed")].copy()
    roster_by_id = roster.set_index(roster["incident_id"].astype(str))
    for _, row in df.iterrows():
        cf_id = str(int(row["cloudflare_id"]))
        if cf_id not in roster_by_id.index:
            continue
        r = roster_by_id.loc[cf_id]
        rows.append(
            {
                "incident_uid": r["incident_uid"],
                "original_incident_id": cf_id,
                "cloudflare_label": r["category"],
                "event_date_time": r["start_utc"],
                "event_end_time": r["end_utc"],
                "asn": row["kentik_leaker_asn"],
                "prefix": "",
                "independent_source": "Kentik",
                "source_url_reference": row["kentik_source_url"],
                "source_native_terminology": row["kentik_incident_name"],
                "deterministic_mapped_label": "Leak",
                "match_evidence": "time_overlap; leak_asn; AS-path segment; source-native route/path leak terminology",
                "match_strength": "STRONG_SAME_EVENT",
                "agreement": r["category"] == "Leak",
                "source_count_non_cloudflare": 1,
                "corroborating_non_cloudflare_sources": "",
                "supporting_artifact": str(KENTIK_PATH.relative_to(PROJECT)),
            }
        )
    return rows


def add_pulse_matches(roster: pd.DataFrame) -> list[dict]:
    rows: list[dict] = []
    roster_by_id = roster.set_index(roster["incident_id"].astype(str))
    for source_path in [PULSE_ADDITIONAL_PATH, PULSE_IQ_PATH]:
        if not source_path.exists():
            continue
        df = pd.read_csv(source_path)
        for _, row in df.iterrows():
            cf_id = str(row["cloudflare_outage_id"])
            if cf_id not in roster_by_id.index:
                continue
            r = roster_by_id.loc[cf_id]
            note = " ".join(
                [
                    safe_str(row.get("pulse_source_note", "")),
                    safe_str(row.get("pulse_verification_level", "")),
                    safe_str(row.get("source_separation_note", "")),
                ]
            )
            corroborators = []
            if "IODA" in note:
                corroborators.append("IODA")
            source_count = 1 + len(set(corroborators))
            rows.append(
                {
                    "incident_uid": r["incident_uid"],
                    "original_incident_id": cf_id,
                    "cloudflare_label": r["category"],
                    "event_date_time": r["start_utc"],
                    "event_end_time": r["end_utc"],
                    "asn": safe_str(row.get("cloudflare_asns", "")),
                    "prefix": "",
                    "independent_source": "Internet Society Pulse",
                    "source_url_reference": row["pulse_source_url"],
                    "source_native_terminology": f"{safe_str(row.get('pulse_cause', ''))}; {safe_str(row.get('pulse_shutdown_reach', ''))}",
                    "deterministic_mapped_label": "Outage",
                    "match_evidence": "country/location match; overlapping outage interval; compatible outage/shutdown cause; source-native outage/shutdown terminology",
                    "match_strength": "STRONG_SAME_EVENT",
                    "agreement": r["category"] == "Outage",
                    "source_count_non_cloudflare": source_count,
                    "corroborating_non_cloudflare_sources": "|".join(sorted(set(corroborators))),
                    "supporting_artifact": str(source_path.relative_to(PROJECT)),
                }
            )
    return rows


def build_unmatched(roster: pd.DataFrame, matched_ids: set[str]) -> pd.DataFrame:
    rows = []
    for _, r in roster.iterrows():
        iid = str(r["incident_id"])
        if iid in matched_ids:
            continue
        searched_context = []
        if r["category"] == "Hijack":
            searched_context.append("MANRS monthly country/economy routeMisoriginations summaries; RIPEstat routing evidence where available")
            reason = "No deterministic non-Cloudflare same-event source-native Hijack classification located in existing source artifacts."
        elif r["category"] == "Leak":
            searched_context.append("Kentik route-leak reports; MANRS/Qrator/Mauch/RIPEstat leak matching artifacts")
            reason = "No accepted deterministic same-event non-Cloudflare source-native Leak classification located, or candidate was not in frozen Cloudflare roster."
        else:
            searched_context.append("Internet Society Pulse outage/shutdown records")
            reason = "No deterministic same-event Pulse/non-Cloudflare outage source match located in existing source artifacts."
        rows.append(
            {
                "incident_uid": r["incident_uid"],
                "incident_id": iid,
                "cloudflare_label": r["category"],
                "event_date_time": r["start_utc"],
                "asn": r.get("primary_asn", ""),
                "prefix": r.get("affected_prefixes", ""),
                "searched_source_context": "; ".join(searched_context),
                "unmatched_reason": reason,
            }
        )
    return pd.DataFrame(rows)


def cohen_kappa(conf: pd.DataFrame) -> float:
    mat = conf.reindex(index=LABELS, columns=LABELS, fill_value=0).to_numpy(dtype=float)
    n = mat.sum()
    if n == 0:
        return float("nan")
    po = np.trace(mat) / n
    pe = (mat.sum(axis=1) * mat.sum(axis=0)).sum() / (n * n)
    if np.isclose(1 - pe, 0):
        return float("nan")
    return float((po - pe) / (1 - pe))


def bootstrap_ci(values: np.ndarray, reps: int = 10000) -> tuple[float, float]:
    if len(values) == 0:
        return float("nan"), float("nan")
    rng = np.random.default_rng(SEED)
    draws = rng.choice(values, size=(reps, len(values)), replace=True).mean(axis=1)
    return float(np.quantile(draws, 0.025)), float(np.quantile(draws, 0.975))


def build_metrics(matched: pd.DataFrame, roster: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    conf = pd.crosstab(matched["cloudflare_label"], matched["deterministic_mapped_label"]).reindex(index=LABELS, columns=LABELS, fill_value=0)
    n_original = len(roster)
    n_matched = matched["original_incident_id"].nunique()
    agree = matched["agreement"].astype(bool).to_numpy()
    lo, hi = bootstrap_ci(agree.astype(int))
    rows = [
        {"metric": "original_incidents_searched", "class": "ALL", "value": n_original, "notes": "Frozen roster v2 incident count."},
        {"metric": "independently_corroborated_incidents", "class": "ALL", "value": n_matched, "notes": "Unique Cloudflare incidents with accepted same-event non-Cloudflare source-native label."},
        {"metric": "corroboration_rate", "class": "ALL", "value": n_matched / n_original if n_original else np.nan, "notes": "Corroborated / searched."},
        {"metric": "overall_exact_label_agreement", "class": "ALL", "value": float(agree.mean()) if len(agree) else np.nan, "notes": "Agreement among accepted corroborated incidents only."},
        {"metric": "overall_agreement_bootstrap_ci_lower_95", "class": "ALL", "value": lo, "notes": f"Incident-level bootstrap; seed={SEED}; reps=10000."},
        {"metric": "overall_agreement_bootstrap_ci_upper_95", "class": "ALL", "value": hi, "notes": f"Incident-level bootstrap; seed={SEED}; reps=10000."},
        {"metric": "cohens_kappa", "class": "ALL", "value": cohen_kappa(conf), "notes": "Cloudflare label versus deterministic independent-source mapped label."},
        {"metric": "multi_non_cloudflare_source_supported_incidents", "class": "ALL", "value": int((matched["source_count_non_cloudflare"] > 1).sum()), "notes": "Counts accepted incidents whose source packet records more than one non-Cloudflare source."},
        {"metric": "disagreement_count", "class": "ALL", "value": int((~matched["agreement"].astype(bool)).sum()), "notes": "Accepted corroborated incidents with different mapped labels."},
    ]
    for label in LABELS:
        sub = matched[matched["cloudflare_label"].eq(label)]
        rows.extend(
            [
                {"metric": "corroborated_incidents", "class": label, "value": len(sub), "notes": "Accepted same-event matches by Cloudflare class."},
                {"metric": "class_exact_label_agreement", "class": label, "value": float(sub["agreement"].mean()) if len(sub) else np.nan, "notes": "Agreement among accepted same-event matches in class."},
            ]
        )
    source_summary = (
        matched.groupby(["independent_source", "cloudflare_label", "deterministic_mapped_label"], dropna=False)
        .agg(
            matched_incidents=("original_incident_id", "nunique"),
            agreements=("agreement", "sum"),
            mean_agreement=("agreement", "mean"),
            multi_source_supported=("source_count_non_cloudflare", lambda s: int((s > 1).sum())),
        )
        .reset_index()
    )
    return pd.DataFrame(rows), conf.reset_index().rename(columns={"cloudflare_label": "cloudflare_label"}), source_summary


def write_rules() -> None:
    (ROOT / "cross_source_matching_rules_v1.md").write_text(
        """# Cross-Source Same-Event Matching Rules v1

This label-validation audit uses only source evidence and incident metadata. It does not use model predictions, model features, window-level feature values, or model errors.

## Accepted same-event match

An independent source match is accepted only when all of the following are present:

1. The source is not Cloudflare and does not rely on Cloudflare as the primary label authority.
2. The source uses source-native incident terminology that deterministically maps to Hijack, Leak, or Outage.
3. The source event can be tied to a Cloudflare incident by event time plus ASN, prefix, AS-path, location/network, or outage-cause evidence.
4. The external label is not ambiguous.

## Match-strength categories

- `STRONG_SAME_EVENT`: source-native label plus overlapping time and specific ASN/prefix/path/network evidence.
- `MODERATE_SAME_EVENT`: source-native label plus overlapping time and partial ASN/network evidence. Retained only if not ambiguous.
- `AGGREGATE_CONTEXT_ONLY`: aggregate country/month/source metric; excluded from agreement.
- `ROUTING_EVIDENCE_ONLY`: raw BGP/RIS/RouteViews/RIPEstat observation without source-native class label; excluded from agreement.
- `NO_ACCEPTED_MATCH`: no deterministic same-event independent classification found.

## Exclusions

MANRS monthly country/economy matches and RIPEstat raw BGP update matches are documented as searched/supporting context, but are excluded from label-agreement metrics unless a source-native event classification identifies the same real-world incident.
""",
        encoding="utf-8",
    )


def make_figures(metrics: pd.DataFrame, conf: pd.DataFrame) -> None:
    fig_dir = ROOT / "figures"
    fig_dir.mkdir(exist_ok=True)

    # Architecture diagram
    fig, ax = plt.subplots(figsize=(12, 5), dpi=200)
    ax.axis("off")
    boxes = [
        ("Frozen Cloudflare\\n1,419 incidents", 0.05, 0.58),
        ("Independent\\nsource artifacts", 0.29, 0.58),
        ("Predeclared\\nmatch + mapping rules", 0.53, 0.58),
        ("Accepted same-event\\nnon-Cloudflare labels", 0.77, 0.58),
        ("Agreement metrics\\n+ manuscript tables", 0.77, 0.20),
    ]
    for text, x, y in boxes:
        ax.add_patch(plt.Rectangle((x, y), 0.18, 0.18, fill=True, facecolor="#eef4fb", edgecolor="#2b4c7e", linewidth=1.4))
        ax.text(x + 0.09, y + 0.09, text, ha="center", va="center", fontsize=10, color="#10233f")
    arrows = [((0.23, 0.67), (0.29, 0.67)), ((0.47, 0.67), (0.53, 0.67)), ((0.71, 0.67), (0.77, 0.67)), ((0.86, 0.58), (0.86, 0.38))]
    for start, end in arrows:
        ax.annotate("", xy=end, xytext=start, arrowprops={"arrowstyle": "->", "lw": 1.5, "color": "#2b4c7e"})
    ax.text(0.5, 0.93, "Cross-Source Label Validation Architecture", ha="center", va="center", fontsize=14, weight="bold")
    fig.tight_layout()
    fig.savefig(fig_dir / "figure_cross_source_label_validation_architecture_v1.png", bbox_inches="tight")
    fig.savefig(fig_dir / "figure_cross_source_label_validation_architecture_v1.pdf", bbox_inches="tight")
    plt.close(fig)

    # Agreement by class
    class_rows = metrics[metrics["metric"].eq("class_exact_label_agreement")].copy()
    count_rows = metrics[metrics["metric"].eq("corroborated_incidents")].set_index("class")
    class_rows["value"] = class_rows["value"].astype(float)
    fig, ax = plt.subplots(figsize=(8, 5), dpi=220)
    colors = ["#4969a8", "#e7893c", "#5f9e6e"]
    bars = ax.bar(class_rows["class"], class_rows["value"], color=colors, width=0.55)
    ax.set_ylim(0, 1.08)
    ax.set_ylabel("Exact label agreement")
    ax.set_title("Label Agreement by Incident Class")
    ax.grid(axis="y", alpha=0.25)
    for bar, (_, row) in zip(bars, class_rows.iterrows()):
        n = int(count_rows.loc[row["class"], "value"]) if row["class"] in count_rows.index else 0
        label = "NA" if pd.isna(row["value"]) else f"{row['value']:.3f}\\n(n={n})"
        ax.text(bar.get_x() + bar.get_width() / 2, min((0 if pd.isna(row["value"]) else row["value"]) + 0.03, 1.05), label, ha="center", va="bottom", fontsize=9)
    fig.tight_layout()
    fig.savefig(fig_dir / "figure_label_agreement_by_incident_class_v1.png", bbox_inches="tight")
    fig.savefig(fig_dir / "figure_label_agreement_by_incident_class_v1.pdf", bbox_inches="tight")
    plt.close(fig)


def write_markdown_tables(matched: pd.DataFrame, metrics: pd.DataFrame, conf: pd.DataFrame) -> None:
    table = metrics[metrics["metric"].isin([
        "original_incidents_searched",
        "independently_corroborated_incidents",
        "corroboration_rate",
        "overall_exact_label_agreement",
        "cohens_kappa",
        "multi_non_cloudflare_source_supported_incidents",
    ])].copy()
    table.to_csv(ROOT / "table_cross_source_validation_of_incident_labels_v1.csv", index=False)
    (ROOT / "table_cross_source_validation_of_incident_labels_v1.md").write_text(table.to_markdown(index=False), encoding="utf-8")
    conf.to_csv(ROOT / "table_cloudflare_vs_independent_confusion_matrix_v1.csv", index=False)
    (ROOT / "table_cloudflare_vs_independent_confusion_matrix_v1.md").write_text(conf.to_markdown(index=False), encoding="utf-8")


def write_summary(roster: pd.DataFrame, matched: pd.DataFrame, unmatched: pd.DataFrame, metrics: pd.DataFrame, conf: pd.DataFrame, source_summary: pd.DataFrame) -> None:
    m = metrics.set_index(["metric", "class"])["value"]
    rate = float(m[("corroboration_rate", "ALL")])
    agreement = float(m[("overall_exact_label_agreement", "ALL")])
    kappa = float(m[("cohens_kappa", "ALL")])
    ci_low = float(m[("overall_agreement_bootstrap_ci_lower_95", "ALL")])
    ci_high = float(m[("overall_agreement_bootstrap_ci_upper_95", "ALL")])
    lines = [
        "# Cross-Source Label Validation Summary v1",
        "",
        "This additive audit compares Cloudflare Radar labels in the frozen 1,419-incident corpus with independent non-Cloudflare source-native labels for the same real-world incidents. No model predictions, features, or model outputs were used.",
        "",
        "## Scope",
        "",
        f"- Original incidents searched: {len(roster):,}",
        f"- Accepted independently corroborated incidents: {matched['original_incident_id'].nunique():,}",
        f"- Corroboration rate: {rate:.6f}",
        f"- Overall exact agreement among corroborated incidents: {agreement:.6f}",
        f"- Bootstrap 95% CI for overall agreement: [{ci_low:.6f}, {ci_high:.6f}]",
        f"- Cohen's kappa: {kappa:.6f}",
        f"- Disagreements: {int((~matched['agreement'].astype(bool)).sum())}",
        f"- Supported by more than one non-Cloudflare source: {int((matched['source_count_non_cloudflare'] > 1).sum())}",
        "",
        "## Key interpretation",
        "",
        "The accepted same-event corroboration set is small and class-skewed: it contains one Kentik route-leak match and Internet Society Pulse outage/shutdown matches. No Hijack incident in the frozen corpus had a deterministic same-event non-Cloudflare source-native classification in the available local evidence. Therefore the observed agreement is best interpreted as high agreement within the externally corroborated subset, not as a corpus-wide proof that all Cloudflare labels are independently verified.",
        "",
        "MANRS monthly country/economy route-misorigination summaries and RIPEstat raw BGP update matches were inspected as supporting context, but excluded from agreement metrics because they do not independently classify a specific same real-world incident.",
        "",
        "## Outputs",
        "",
        "- `cross_source_matched_incidents_v1.csv`",
        "- `cross_source_unmatched_incidents_v1.csv`",
        "- `cross_source_agreement_metrics_v1.csv`",
        "- `cross_source_confusion_matrix_v1.csv`",
        "- `cross_source_source_summary_v1.csv`",
        "- `figures/figure_cross_source_label_validation_architecture_v1.png`",
        "- `figures/figure_label_agreement_by_incident_class_v1.png`",
    ]
    (ROOT / "cross_source_validation_summary_v1.md").write_text("\\n".join(lines) + "\\n", encoding="utf-8")


def main() -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    roster = pd.read_csv(ROSTER_PATH)
    label_rules = build_label_mapping_rules()
    label_rules.to_csv(ROOT / "cross_source_label_mapping_rules_v1.csv", index=False)
    write_rules()

    matched_rows = add_kentik_matches(roster) + add_pulse_matches(roster)
    matched = pd.DataFrame(matched_rows).drop_duplicates(subset=["original_incident_id", "independent_source", "source_url_reference"]).sort_values(["cloudflare_label", "original_incident_id"])
    matched["agreement"] = matched["agreement"].astype(bool)
    matched.to_csv(ROOT / "cross_source_matched_incidents_v1.csv", index=False)

    matched_ids = set(matched["original_incident_id"].astype(str))
    unmatched = build_unmatched(roster, matched_ids)
    unmatched.to_csv(ROOT / "cross_source_unmatched_incidents_v1.csv", index=False)

    disagreements = matched[~matched["agreement"]].copy()
    disagreements.to_csv(ROOT / "cross_source_disagreements_v1.csv", index=False)

    metrics, conf, source_summary = build_metrics(matched, roster)
    metrics.to_csv(ROOT / "cross_source_agreement_metrics_v1.csv", index=False)
    conf.to_csv(ROOT / "cross_source_confusion_matrix_v1.csv", index=False)
    source_summary.to_csv(ROOT / "cross_source_source_summary_v1.csv", index=False)

    make_figures(metrics, conf)
    write_markdown_tables(matched, metrics, conf)
    write_summary(roster, matched, unmatched, metrics, conf, source_summary)

    # Artifact/checksum manifest.
    artifacts = []
    for path in sorted(ROOT.rglob("*")):
        if path.is_file() and path.name != "cross_source_output_checksums_v1.csv":
            artifacts.append({"artifact": str(path.relative_to(PROJECT)), "sha256": sha256(path), "size_bytes": path.stat().st_size})
    pd.DataFrame(artifacts).to_csv(ROOT / "cross_source_output_checksums_v1.csv", index=False)

    print(json.dumps({
        "original_incidents": len(roster),
        "matched_incidents": int(matched["original_incident_id"].nunique()),
        "unmatched_incidents": len(unmatched),
        "agreement": float(matched["agreement"].mean()) if len(matched) else None,
        "outputs": str(ROOT),
    }, indent=2))


if __name__ == "__main__":
    main()
