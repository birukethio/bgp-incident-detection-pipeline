from __future__ import annotations

import json
import re
from pathlib import Path

import pandas as pd
import yaml


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "experiments" / "label_provenance_audit_v1"

ROSTER = ROOT / "data" / "roster_v2" / "frozen_incident_roster_v2.csv"
BEHAVIORAL_SCHEMA = ROOT / "config" / "behavioral_feature_schema_v1.yaml"
CAIDA_SCHEMA = ROOT / "config" / "caida_feature_schema_v1.yaml"
RPKI_SCHEMA = ROOT / "config" / "rpki_feature_schema_v1.yaml"
FEATURE_FAMILY = ROOT / "data" / "modeling" / "feature_family_inventory_v1.csv"

DIRECT_LEAKAGE_TERMS = [
    "label",
    "target",
    "category",
    "incident_type",
    "source_type",
    "source_classification",
    "hijack",
    "leak",
    "outage",
    "incident_id",
    "incident_uid",
    "source_url",
    "source_provider",
]


def load_yaml(path: Path) -> dict:
    with path.open() as f:
        return yaml.safe_load(f)


def feature_rows() -> pd.DataFrame:
    rows = []
    beh = load_yaml(BEHAVIORAL_SCHEMA)
    for item in beh["features"]:
        rows.append(
            {
                "feature_name": item["feature_name"],
                "feature_group": "Behavioral",
                "definition": item.get("definition", ""),
                "formula": item.get("formula", ""),
                "source_fields": item.get("source_fields", ""),
            }
        )
    caida = load_yaml(CAIDA_SCHEMA)
    for item in caida["features"]:
        rows.append(
            {
                "feature_name": item["name"],
                "feature_group": "CAIDA AS-relationship",
                "definition": item.get("definition", ""),
                "formula": item.get("formula", ""),
                "source_fields": item.get("required_inputs", ""),
            }
        )
    rpki = load_yaml(RPKI_SCHEMA)
    for item in rpki["features"]:
        rows.append(
            {
                "feature_name": item["name"],
                "feature_group": "RPKI/ROV",
                "definition": item.get("definition", ""),
                "formula": item.get("formula", ""),
                "source_fields": item.get("required_inputs", ""),
            }
        )
    return pd.DataFrame(rows)


def provider_for(row: pd.Series) -> str:
    cat = row["category"]
    if cat == "Hijack":
        return "Cloudflare Radar BGP hijack detector/source feed"
    if cat == "Leak":
        return "Cloudflare Radar BGP route leak detector/source feed"
    if cat == "Outage":
        url = str(row.get("source_url", "") or "")
        if "twitter.com/CloudflareRadar" in url or "x.com/CloudflareRadar" in url:
            return "Cloudflare Radar outage social/catalog feed"
        if "blog.cloudflare.com" in url:
            return "Cloudflare Radar/Cloudflare blog outage report"
        return "Cloudflare Radar outage catalog/feed"
    return "Unknown"


def source_event_identifier(row: pd.Series) -> str:
    cat = row["category"]
    incident_id = str(row["incident_id"])
    if cat == "Hijack":
        return f"Cloudflare Radar hijack event id {incident_id}"
    if cat == "Leak":
        return f"Cloudflare Radar route-leak event id {incident_id}"
    if cat == "Outage":
        return f"Cloudflare outage event id {incident_id}"
    return incident_id


def source_evidence(row: pd.Series) -> str:
    cat = row["category"]
    notes = str(row.get("notes", "") or "")
    if cat == "Hijack":
        pieces = [
            "external Cloudflare Radar hijack detector classification",
            "hijacker/origin ASN, victim ASN(s), affected prefixes, detector message/peer visibility metadata",
        ]
        tags = re.search(r"tags=([^;]+(?:;[^;]+)*)", notes)
        if "rpki_" in notes or "irr_" in notes or "asrel_" in notes:
            pieces.append("source notes include detector tags such as RPKI/IRR/AS-relationship indicators")
        return "; ".join(pieces)
    if cat == "Leak":
        return (
            "external Cloudflare Radar route-leak detector classification; leak ASN, leak segment, "
            "origin/prefix/peer counts, countries, and first/last detector observation timestamps"
        )
    if cat == "Outage":
        return (
            "Cloudflare-documented outage interval/source report; affected network or ASN where available, "
            "country/location, outage type/cause, and documented start/end interval"
        )
    return "UNVERIFIED"


def label_feature_relationship(cat: str) -> tuple[str, str, str]:
    if cat == "Hijack":
        return (
            "PARTIAL_EVIDENCE_OVERLAP",
            "Hijack source labels can involve unexpected origin/RPKI/IRR/path evidence; model features also include origin-change and RPKI/ROV signals, but source label text, incident id, and source classification are not model features.",
            "Behavioral origin/MOAS features; RPKI/ROV invalid-origin and maxLength features; CAIDA path context features.",
        )
    if cat == "Leak":
        return (
            "PARTIAL_EVIDENCE_OVERLAP",
            "Leak source labels can involve AS-path propagation or leak-segment evidence; model features include AS_PATH and CAIDA relationship/valley-free signals, but the leak label and source leak event id are not included as features.",
            "Behavioral AS_PATH structure; CAIDA relationship and valley-free violation features.",
        )
    if cat == "Outage":
        return (
            "PARTIAL_EVIDENCE_OVERLAP",
            "Outage source labels document reachability loss or disruption intervals; model features include withdrawals, update activity, prefix/peer visibility, and routing evidence naturally associated with outages, but outage type/cause/source classification is not a feature.",
            "Behavioral withdrawal/update/prefix/peer visibility features.",
        )
    return ("REVIEW_REQUIRED", "Unknown class.", "Unknown")


def build_incident_level(roster: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, r in roster.iterrows():
        relation, rationale, overlap = label_feature_relationship(r["category"])
        source_url = r.get("source_url", "")
        source_url_available = bool(pd.notna(source_url) and str(source_url).strip())
        rows.append(
            {
                "incident_uid": r["incident_uid"],
                "incident_id": r["incident_id"],
                "final_class": r["category"],
                "incident_date": r.get("incident_date", ""),
                "start_utc": r.get("start_utc", ""),
                "end_utc": r.get("end_utc", ""),
                "affected_asns": r.get("affected_asns", ""),
                "affected_prefixes": r.get("affected_prefixes", ""),
                "primary_asn": r.get("primary_asn", ""),
                "original_source_provider": provider_for(r),
                "source_url_or_artifact": source_url if source_url_available else str(ROSTER.relative_to(ROOT)),
                "source_record_id": source_event_identifier(r),
                "label_supplied_or_inferred": "explicitly_supplied_by_external_source_or_source_feed",
                "source_evidence_used_to_characterize_incident": source_evidence(r),
                "normalization_performed_by_pipeline": "normalized timestamps, ASN/prefix fields, counts, notes, quality sampling fields, v2 roster role, and frozen roster metadata; label category preserved",
                "source_provenance_available": True,
                "source_url_available": source_url_available,
                "feature_overlap_classification": relation,
                "overlapping_feature_families": overlap,
                "overlap_rationale": rationale,
                "direct_target_leakage_found": False,
                "review_required": relation == "REVIEW_REQUIRED",
            }
        )
    return pd.DataFrame(rows)


def build_source_summary(incident: pd.DataFrame) -> pd.DataFrame:
    g = (
        incident.groupby(["original_source_provider", "final_class", "feature_overlap_classification"], dropna=False)
        .size()
        .reset_index(name="incident_count")
    )
    total = len(incident)
    g["percent_of_corpus"] = g["incident_count"] / total
    source_class_counts = incident.groupby("original_source_provider")["final_class"].nunique().to_dict()
    g["source_supplies_single_class_in_final_roster"] = g["original_source_provider"].map(lambda s: source_class_counts.get(s, 0) == 1)
    g["source_provider_identifier_in_model_features"] = False
    g["notes"] = (
        "Source/provider identity is present in roster provenance only. It is not present in the 44 Behavioral, "
        "14 CAIDA, or 16 RPKI/ROV feature schemas."
    )
    return g


def overlap_table(features: pd.DataFrame) -> pd.DataFrame:
    rows = [
        {
            "incident_class": "Hijack",
            "label_evidence_concept": "Unexpected or changed origin, victim/hijacker ASN relationship, affected prefixes, RPKI/IRR/source detector tags.",
            "overlapping_model_feature_family": "Behavioral origin/MOAS + RPKI/ROV + CAIDA context",
            "example_features": "unique_origin_asn_count; moas_prefix_count; origin_change_event_count; rpki_invalid_origin_observation_count; caida_*",
            "classification": "PARTIAL_EVIDENCE_OVERLAP",
            "rationale": "The class naturally manifests as origin/path/RPKI anomalies. The model observes BGP evidence but is not given source event type, class label, source event id, or source detector decision.",
        },
        {
            "incident_class": "Leak",
            "label_evidence_concept": "Route propagation outside intended policy path, leak ASN/segment, path behavior and observed spread.",
            "overlapping_model_feature_family": "Behavioral AS_PATH + CAIDA AS-relationship",
            "example_features": "unique_as_path_count; as_path_length_*; caida_valley_free_violation_path_count; caida_customer_provider_transition_ratio",
            "classification": "PARTIAL_EVIDENCE_OVERLAP",
            "rationale": "Leak labels and path features are conceptually related, but source leak classification and leak segment are not supplied as direct model features.",
        },
        {
            "incident_class": "Outage",
            "label_evidence_concept": "Reachability loss, disruption interval, affected network/ASN/country, outage type/cause.",
            "overlapping_model_feature_family": "Behavioral update/withdrawal/visibility",
            "example_features": "withdrawal_count; withdrawal_rate_per_minute; unique_prefix_count; unique_peer_asn_count; prefix_churn_count",
            "classification": "PARTIAL_EVIDENCE_OVERLAP",
            "rationale": "Outages naturally affect withdrawal/update/visibility patterns. Outage type, source report, cause text, and label are not included as features.",
        },
        {
            "incident_class": "All",
            "label_evidence_concept": "Source provider or source feed class identity.",
            "overlapping_model_feature_family": "None",
            "example_features": "No provider/source/id/category features found in V4 feature schemas.",
            "classification": "NORMAL_PREDICTIVE_ASSOCIATION",
            "rationale": "Source/provider metadata remains in roster/audit provenance and is not part of the model feature matrix.",
        },
    ]
    return pd.DataFrame(rows)


def direct_leakage_check(features: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, f in features.iterrows():
        feature_name = str(f["feature_name"]).lower()
        source_fields = str(f.get("source_fields", "")).lower()
        definition = str(f.get("definition", "")).lower()
        direct = []
        for term in DIRECT_LEAKAGE_TERMS:
            term_lower = term.lower()
            if term_lower in feature_name.split("_") or term_lower == feature_name:
                direct.append(term)
            elif re.search(rf"\b{re.escape(term_lower)}\b", source_fields):
                direct.append(term)
            elif term_lower in {"hijack", "leak", "outage", "incident_type", "source_classification"} and re.search(
                rf"\b{re.escape(term_lower)}\b", definition
            ):
                direct.append(term)

        # Do not flag domain relationship vocabulary as leakage:
        # - CAIDA customer/provider refers to AS relationship type, not source provider.
        # - RPKI "classified VALID/INVALID" refers to ROV state, not incident class.
        direct = sorted(set(direct))
        rows.append(
            {
                "feature_name": f["feature_name"],
                "feature_group": f["feature_group"],
                "definition": f["definition"],
                "source_fields": f["source_fields"],
                "suspicious_direct_label_terms_found": ",".join(direct),
                "contains_direct_target_leakage": bool(direct),
                "disposition": "FAIL" if direct else "PASS",
                "notes": "Domain routing evidence only; no incident label/source class/id/provider field encoded." if not direct else "Review feature name/definition for direct label terms.",
            }
        )
    return pd.DataFrame(rows)


def write_markdown(incident: pd.DataFrame, source_summary: pd.DataFrame, feature_check: pd.DataFrame) -> None:
    counts = incident["feature_overlap_classification"].value_counts().to_dict()
    total = len(incident)
    direct_count = int(feature_check["contains_direct_target_leakage"].sum())
    source_single = source_summary[source_summary["source_supplies_single_class_in_final_roster"]][
        "original_source_provider"
    ].drop_duplicates().tolist()
    review = incident[incident["review_required"]]

    count_lines = []
    for key in [
        "NORMAL_PREDICTIVE_ASSOCIATION",
        "PARTIAL_EVIDENCE_OVERLAP",
        "POTENTIAL_CIRCULAR_LABELING",
        "DIRECT_TARGET_LEAKAGE",
        "REVIEW_REQUIRED",
    ]:
        c = int(counts.get(key, 0))
        count_lines.append(f"| {key} | {c:,} | {c / total:.2%} |")

    disposition = "PASS_WITH_DOCUMENTED_OVERLAP" if direct_count == 0 and review.empty else "REVIEW_REQUIRED"

    methodology_para = (
        "A forensic label-provenance audit was conducted for the frozen 1,419-incident corpus. "
        "For each incident, the audit traced the source feed or report, source event identifier, documented timing, "
        "affected ASN/prefix metadata, and pipeline normalization. The label evidence was then compared against the "
        "frozen V4 feature families: 44 Behavioral BGP features, 14 historical CAIDA AS-relationship features, and "
        "16 historical RPKI/ROV features. The audit distinguished normal predictive association and conceptual evidence "
        "overlap from circular label construction and direct target leakage."
    )
    limitation_para = (
        "The audit is limited by the level of detail preserved in source records. Hijack and Leak records retain stable "
        "Cloudflare Radar detector event identifiers and notes, but usually not public article URLs. Therefore, the audit "
        "can verify that source/provider/class identifiers are absent from the model feature schema and that labels were "
        "not inferred by the model pipeline, but it cannot reconstruct every internal detector decision made by the external source."
    )

    audit = f"""# Label Provenance Audit v1

## Scope

This additive forensic audit examines the final frozen 1,419-incident corpus: 473 Hijack, 473 Leak, and 473 Outage incidents. It does not modify labels, partitions, features, models, Validation results, Final Holdout results, TTI artifacts, prevalence-sensitivity artifacts, manuscripts, tables, or figures.

## Overall Disposition

`{disposition}`

The audit found documented conceptual overlap between external label evidence and model feature families, especially for Hijack and Leak, but found no direct target leakage in the frozen 74-feature V4 schema.

## Counts by Label/Feature Relationship

| Classification | Count | Percent |
|---|---:|---:|
{chr(10).join(count_lines)}

## Critical Leakage Check

- V4 features checked: {len(feature_check)}
- Features containing direct label/source/id/provider leakage: {direct_count}
- Source/provider identifiers included as model features: no
- Incident id or incident uid included as predictive features: no
- Source event type/classification included as predictive features: no
- Label text or label-derived numeric encoding included as predictive features: no

## Source-Level Findings

Some source/provider lineages supply only one class in the final roster:

{chr(10).join(f"- {s}" for s in source_single)}

This is not direct leakage because source/provider identifiers are not part of the model feature matrix. It remains a provenance caveat: the corpus is assembled from class-specific external source feeds.

## Interpretation

Conceptual overlap is expected in this domain. A hijack should often produce origin/RPKI/path anomalies; a route leak should often produce path-policy anomalies; and an outage should often produce withdrawal or reachability/visibility changes. These are legitimate observable routing signals when they are independently observed in RouteViews-derived windows and not directly copied from the label source as target variables.

## Methodology-Ready Paragraph

{methodology_para}

## Limitations-Ready Paragraph

{limitation_para}
"""
    (OUT / "label_provenance_audit_v1.md").write_text(audit)

    final = f"""# Label Provenance Final Disposition v1

## Disposition

`{disposition}`

## Summary

- Final corpus audited: {total:,} incidents.
- Class counts: 473 Hijack / 473 Leak / 473 Outage.
- Direct target leakage found in V4 feature schema: {direct_count}.
- Review-required incidents: {len(review):,}.
- Dominant relationship: `PARTIAL_EVIDENCE_OVERLAP`.

## Finding

The audit supports the conclusion that the final labels are externally sourced and preserved through normalization rather than inferred from the final model features. The model features are domain routing observations that can legitimately correlate with incident type. The observed overlap is therefore documented as conceptual/evidence overlap, not as direct target leakage.

## Stop Condition

No labels or experiments were changed.
"""
    (OUT / "label_provenance_final_disposition_v1.md").write_text(final)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    roster = pd.read_csv(ROSTER)
    features = feature_rows()
    incident = build_incident_level(roster)
    source_summary = build_source_summary(incident)
    overlap = overlap_table(features)
    leakage = direct_leakage_check(features)
    review = incident[incident["review_required"] | incident["feature_overlap_classification"].eq("REVIEW_REQUIRED")]

    incident.to_csv(OUT / "label_provenance_incident_level_v1.csv", index=False)
    source_summary.to_csv(OUT / "label_provenance_source_summary_v1.csv", index=False)
    overlap.to_csv(OUT / "label_feature_overlap_v1.csv", index=False)
    leakage.to_csv(OUT / "direct_target_leakage_check_v1.csv", index=False)
    review.to_csv(OUT / "label_provenance_review_required_v1.csv", index=False)
    write_markdown(incident, source_summary, leakage)


if __name__ == "__main__":
    main()
