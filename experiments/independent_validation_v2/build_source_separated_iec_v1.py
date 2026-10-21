from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import pandas as pd


ROOT = Path(__file__).resolve().parents[2]
SOURCE_DIR = ROOT / "experiments" / "independent_validation_audit_v2"
OUT_DIR = ROOT / "experiments" / "independent_validation_v2"


MAPPING_RULES = [
    {
        "mapping_rule_id": "H1_HIJACK_EXPLICIT",
        "source_native_pattern": r"\b(bgp\s+)?(route\s+|prefix\s+|origin\s+)?hijack(?:ed|ing)?\b",
        "mapped_study_class": "Hijack",
        "confidence": "EXPLICIT",
        "notes": "Explicit source-native hijack terminology.",
    },
    {
        "mapping_rule_id": "H2_UNAUTHORIZED_ORIGIN",
        "source_native_pattern": r"\bunauthori[sz]ed\s+(origin(?:ation)?s?|prefix(?:es)?|announcement(?:s)?)\b|\bwrong[-\s]?origin\b",
        "mapped_study_class": "Hijack",
        "confidence": "EXPLICIT",
        "notes": "Explicit unauthorized/wrong-origin label evidence maps deterministically to Hijack.",
    },
    {
        "mapping_rule_id": "H3_WELL_KNOWN_HIJACK_CASE",
        "source_native_pattern": r"\byoutube\s+hijack\b|\bpaker?stan\s+telecom\s*/\s*youtube\b",
        "mapped_study_class": "Hijack",
        "confidence": "EXPLICIT",
        "notes": "Named public incident is source-native hijack terminology in the candidate record.",
    },
    {
        "mapping_rule_id": "L1_ROUTE_LEAK_EXPLICIT",
        "source_native_pattern": r"\b(bgp\s+)?route\s+leak(?:age|ed|ing)?\b|\bleaked\s+(?:upstream\s+)?(?:prefix|prefixes|routes)\b|\bleaking\s+(?:thousands\s+of\s+)?prefixes\b",
        "mapped_study_class": "Leak",
        "confidence": "EXPLICIT",
        "notes": "Explicit source-native route-leak terminology.",
    },
    {
        "mapping_rule_id": "L2_EXPORT_POLICY_LEAK",
        "source_native_pattern": r"\bexport[-\s]?policy\s+leak\b|\bpolicy/export\s+violation\b|\bleak\s+between\s+upstreams\b",
        "mapped_study_class": "Leak",
        "confidence": "EXPLICIT",
        "notes": "Explicit policy/export leak description maps deterministically to Leak.",
    },
    {
        "mapping_rule_id": "O1_AS_SCOPED_OUTAGE_EXPLICIT",
        "source_native_pattern": r"\b(as[-\s]?scoped\s+)?(?:internet\s+)?outage\b.*\bbgp[-\s]?visible\b|\bbgp[-\s]?visible\b.*\boutage\b",
        "mapped_study_class": "Outage",
        "confidence": "EXPLICIT",
        "notes": "Explicit outage with BGP visibility / Internet reachability loss for an identified ASN.",
    },
    {
        "mapping_rule_id": "O2_MANUALLY_VERIFIED_IODA_OUTAGE",
        "source_native_pattern": r"\bioda\s+manually\s+verified\b.*\boutage\b|\bmanually\s+verified\s+ioda\s+outage\b",
        "mapped_study_class": "Outage",
        "confidence": "EXPLICIT",
        "notes": "IODA manually verified AS-scoped outage source record.",
    },
    {
        "mapping_rule_id": "X1_AMBIGUOUS_GENERIC_ROUTING_EVENT",
        "source_native_pattern": r"\b(anomaly|routing\s+incident|routing\s+instability|connectivity\s+event)\b",
        "mapped_study_class": "EXCLUDE",
        "confidence": "AMBIGUOUS",
        "notes": "Generic labels do not deterministically map to H/L/O.",
    },
]


SOURCE_METHODS = {
    "MANRS": {
        "bgp_updates": "YES_OR_REFERENCED",
        "routeviews": "POSSIBLE_OR_REFERENCED",
        "ripe_ris": "POSSIBLE_OR_REFERENCED",
        "rpki": "POSSIBLE",
        "irr": "UNKNOWN",
        "as_relationships": "POSSIBLE",
        "active_measurements": "UNKNOWN",
        "operator_confirmation": "POSSIBLE",
        "traffic_reachability_telemetry": "UNKNOWN",
        "other_evidence": "community incident analysis",
        "underlying_evidence_overlap": "MODERATE",
    },
    "Qrator": {
        "bgp_updates": "YES",
        "routeviews": "UNKNOWN",
        "ripe_ris": "UNKNOWN",
        "rpki": "POSSIBLE",
        "irr": "UNKNOWN",
        "as_relationships": "POSSIBLE",
        "active_measurements": "UNKNOWN",
        "operator_confirmation": "UNKNOWN",
        "traffic_reachability_telemetry": "UNKNOWN",
        "other_evidence": "Qrator.Radar BGP monitoring",
        "underlying_evidence_overlap": "MODERATE",
    },
    "Kentik": {
        "bgp_updates": "YES",
        "routeviews": "POSSIBLE",
        "ripe_ris": "POSSIBLE",
        "rpki": "POSSIBLE",
        "irr": "UNKNOWN",
        "as_relationships": "POSSIBLE",
        "active_measurements": "UNKNOWN",
        "operator_confirmation": "POSSIBLE",
        "traffic_reachability_telemetry": "POSSIBLE",
        "other_evidence": "Kentik BGP/traffic analysis",
        "underlying_evidence_overlap": "MODERATE",
    },
    "BGPHorizon": {
        "bgp_updates": "YES",
        "routeviews": "POSSIBLE",
        "ripe_ris": "POSSIBLE",
        "rpki": "UNKNOWN",
        "irr": "UNKNOWN",
        "as_relationships": "UNKNOWN",
        "active_measurements": "UNKNOWN",
        "operator_confirmation": "UNKNOWN",
        "traffic_reachability_telemetry": "UNKNOWN",
        "other_evidence": "BGP incident analysis",
        "underlying_evidence_overlap": "MODERATE",
    },
    "RouteCause": {
        "bgp_updates": "YES",
        "routeviews": "YES",
        "ripe_ris": "YES",
        "rpki": "NO",
        "irr": "UNKNOWN",
        "as_relationships": "UNKNOWN",
        "active_measurements": "UNKNOWN",
        "operator_confirmation": "POSSIBLE",
        "traffic_reachability_telemetry": "UNKNOWN",
        "other_evidence": "reproducible MRT-based demonstration",
        "underlying_evidence_overlap": "HIGH",
    },
    "IODA": {
        "bgp_updates": "YES_FOR_BGP_VISIBILITY",
        "routeviews": "UNKNOWN",
        "ripe_ris": "UNKNOWN",
        "rpki": "NO",
        "irr": "NO",
        "as_relationships": "NO",
        "active_measurements": "YES",
        "operator_confirmation": "POSSIBLE",
        "traffic_reachability_telemetry": "YES",
        "other_evidence": "IODA outage signals and curated investigated outage records",
        "underlying_evidence_overlap": "LOW",
    },
    "NOG/NANOG": {
        "bgp_updates": "POSSIBLE_OR_REFERENCED",
        "routeviews": "POSSIBLE_OR_REFERENCED",
        "ripe_ris": "POSSIBLE_OR_REFERENCED",
        "rpki": "UNKNOWN",
        "irr": "UNKNOWN",
        "as_relationships": "UNKNOWN",
        "active_measurements": "UNKNOWN",
        "operator_confirmation": "POSSIBLE",
        "traffic_reachability_telemetry": "UNKNOWN",
        "other_evidence": "operator/community documentation",
        "underlying_evidence_overlap": "MODERATE",
    },
}


def clean(value: object) -> str:
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except TypeError:
        pass
    return str(value).strip()


def pick(row: pd.Series, names: Iterable[str], default: str = "") -> str:
    for name in names:
        if name in row.index:
            value = clean(row[name])
            if value:
                return value
    return default


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_candidates() -> pd.DataFrame:
    p = SOURCE_DIR / "v2_expert_adjudication_form.csv"
    if not p.exists():
        raise FileNotFoundError(p)
    return pd.read_csv(p)


def source_blob(row: pd.Series) -> str:
    fields = [
        "source_derived_evidence_summary",
        "exact_source_evidence_available_to_reviewer",
        "primary_evidence_source",
        "source_type",
        "corroborating_sources",
        "source_event_identifier",
    ]
    return " | ".join(pick(row, [f]) for f in fields if pick(row, [f]))


def apply_mapping(row: pd.Series) -> dict[str, str]:
    text = source_blob(row)
    matches = []
    for rule in MAPPING_RULES:
        if re.search(rule["source_native_pattern"], text, flags=re.IGNORECASE):
            matches.append(rule)
    exclude = [m for m in matches if m["mapped_study_class"] == "EXCLUDE"]
    explicit = [m for m in matches if m["confidence"] == "EXPLICIT" and m["mapped_study_class"] != "EXCLUDE"]
    proposed = pick(row, ["proposed_class"])
    if exclude and not explicit:
        return {
            "explicit_source_label": "AMBIGUOUS_GENERIC_SOURCE_LABEL",
            "deterministic_mapped_class": "",
            "mapping_rule_id": exclude[0]["mapping_rule_id"],
            "source_label_confidence": "AMBIGUOUS",
            "mapping_notes": exclude[0]["notes"],
        }
    classes = sorted({m["mapped_study_class"] for m in explicit})
    if len(classes) == 1 and classes[0].lower() == proposed.lower():
        label = explicit[0]["mapped_study_class"].upper()
        return {
            "explicit_source_label": label,
            "deterministic_mapped_class": explicit[0]["mapped_study_class"],
            "mapping_rule_id": explicit[0]["mapping_rule_id"],
            "source_label_confidence": "EXPLICIT",
            "mapping_notes": explicit[0]["notes"],
        }
    if len(classes) > 1:
        return {
            "explicit_source_label": "MULTIPLE_EXPLICIT_LABELS",
            "deterministic_mapped_class": "",
            "mapping_rule_id": "EXCLUDE_MULTIPLE_EXPLICIT_CLASSES",
            "source_label_confidence": "AMBIGUOUS",
            "mapping_notes": "Source text matched more than one H/L/O class.",
        }
    return {
        "explicit_source_label": "NO_EXPLICIT_SOURCE_NATIVE_HLO_LABEL_DETECTED",
        "deterministic_mapped_class": "",
        "mapping_rule_id": "EXCLUDE_AMBIGUOUS_SOURCE_LABEL",
        "source_label_confidence": "UNSUPPORTED",
        "mapping_notes": "No explicit source-native label matched the frozen mapping table.",
    }


def metadata_status(row: pd.Series) -> str:
    dt = pick(row, ["event_date_time"])
    asn = pick(row, ["affected_asn", "asn"])
    routeviews = routeviews_status(row)
    partial = pick(row, ["partial_prefix_metadata"]).upper()
    prefix = pick(row, ["prefixes_available_from_source", "prefix"])
    source_event = pick(row, ["source_event_identifier", "candidate_id"])
    if not (dt and asn and source_event):
        return "METADATA_INSUFFICIENT"
    if routeviews != "ROUTEVIEWS_AVAILABLE":
        return "METADATA_INSUFFICIENT"
    if partial == "YES" or not prefix:
        return "METADATA_PARTIAL_BUT_RECONSTRUCTABLE"
    return "METADATA_COMPLETE"


def routeviews_status(row: pd.Series) -> str:
    raw = pick(row, ["routeviews_archive_availability_confirmed", "routeviews_availability"])
    if raw.upper() in {"YES", "ROUTEVIEWS_AVAILABLE", "TRUE"}:
        return "ROUTEVIEWS_AVAILABLE"
    if raw.upper() in {"NO", "FALSE", "UNAVAILABLE"}:
        return "ROUTEVIEWS_NOT_AVAILABLE"
    return raw or "ROUTEVIEWS_UNKNOWN"


def source_family(row: pd.Series) -> str:
    st = pick(row, ["source_type"])
    src = pick(row, ["primary_evidence_source"])
    blob = f"{st} {src}".lower()
    for family in SOURCE_METHODS:
        if family.lower() in blob:
            return family
    if "nanog" in blob or "nog" in blob:
        return "NOG/NANOG"
    if "internet society" in blob:
        return "MANRS"
    return st or "UNKNOWN"


def method_profile(family: str) -> dict[str, str]:
    return SOURCE_METHODS.get(
        family,
        {
            "bgp_updates": "UNKNOWN",
            "routeviews": "UNKNOWN",
            "ripe_ris": "UNKNOWN",
            "rpki": "UNKNOWN",
            "irr": "UNKNOWN",
            "as_relationships": "UNKNOWN",
            "active_measurements": "UNKNOWN",
            "operator_confirmation": "UNKNOWN",
            "traffic_reachability_telemetry": "UNKNOWN",
            "other_evidence": "not characterized",
            "underlying_evidence_overlap": "UNKNOWN",
        },
    )


def build_verification(candidates: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, row in candidates.iterrows():
        mapping = apply_mapping(row)
        family = source_family(row)
        methods = method_profile(family)
        primary_source = pick(row, ["primary_evidence_source"])
        overlap = pick(row, ["overlap_status_with_original_1419_corpus", "overlap_status"], "NOT_RECORDED")
        metadata = metadata_status(row)
        routeviews = routeviews_status(row)
        non_cloudflare = "NO" if "cloudflare" in primary_source.lower() else "YES"
        accepted = (
            non_cloudflare == "YES"
            and mapping["source_label_confidence"] == "EXPLICIT"
            and bool(mapping["deterministic_mapped_class"])
            and metadata in {"METADATA_COMPLETE", "METADATA_PARTIAL_BUT_RECONSTRUCTABLE"}
            and routeviews == "ROUTEVIEWS_AVAILABLE"
            and overlap == "NEW_INDEPENDENT_EVENT"
        )
        if accepted:
            reason = "ACCEPT_SOURCE_SEPARATED_IEC"
        elif non_cloudflare != "YES":
            reason = "EXCLUDE_CLOUDFLARE_PRIMARY_LABEL"
        elif mapping["source_label_confidence"] != "EXPLICIT":
            reason = mapping["mapping_rule_id"]
        elif metadata == "METADATA_INSUFFICIENT":
            reason = "EXCLUDE_METADATA_INSUFFICIENT"
        elif routeviews != "ROUTEVIEWS_AVAILABLE":
            reason = "EXCLUDE_ROUTEVIEWS_NOT_AVAILABLE"
        elif overlap != "NEW_INDEPENDENT_EVENT":
            reason = "EXCLUDE_NOT_NEW_INDEPENDENT_EVENT"
        else:
            reason = "EXCLUDE_OTHER"
        rows.append(
            {
                "candidate_id": pick(row, ["candidate_id"]),
                "proposed_class": pick(row, ["proposed_class"]),
                "event_date_time": pick(row, ["event_date_time"]),
                "event_end_time": pick(row, ["event_end_time"]),
                "affected_asn": pick(row, ["affected_asn", "asn"]),
                "origin_asn_where_applicable": pick(row, ["origin_asn_where_applicable"]),
                "prefixes_available_from_source": pick(row, ["prefixes_available_from_source", "prefix"]),
                "affected_prefix_count_reported": pick(row, ["affected_prefix_count_reported"]),
                "primary_evidence_source": primary_source,
                "source_type": pick(row, ["source_type"]),
                "source_family": family,
                "primary_source_url_or_reference": pick(row, ["primary_source_url_or_reference"]),
                "source_event_identifier": pick(row, ["source_event_identifier"], pick(row, ["candidate_id"])),
                "source_evidence_text_used_for_mapping": source_blob(row),
                **mapping,
                "metadata_status": metadata,
                "routeviews_archive_status": routeviews,
                "overlap_status_original_1419": overlap,
                "primary_source_non_cloudflare": non_cloudflare,
                "label_source_independent_from_cloudflare": "YES" if non_cloudflare == "YES" else "NO",
                "bgp_updates_used_by_label_source": methods["bgp_updates"],
                "routeviews_used_by_label_source": methods["routeviews"],
                "ripe_ris_used_by_label_source": methods["ripe_ris"],
                "rpki_used_by_label_source": methods["rpki"],
                "irr_used_by_label_source": methods["irr"],
                "as_relationships_used_by_label_source": methods["as_relationships"],
                "active_measurements_used_by_label_source": methods["active_measurements"],
                "operator_confirmation_used_by_label_source": methods["operator_confirmation"],
                "traffic_reachability_telemetry_used_by_label_source": methods["traffic_reachability_telemetry"],
                "other_label_evidence": methods["other_evidence"],
                "underlying_evidence_overlap": methods["underlying_evidence_overlap"],
                "iec_acceptance_status": "ACCEPT" if accepted else "EXCLUDE",
                "exclusion_reason": "" if accepted else reason,
                "selection_used_model_output": "NO",
            }
        )
    return pd.DataFrame(rows)


def build_exclusion_ledger(verification: pd.DataFrame) -> pd.DataFrame:
    excluded = verification[verification["iec_acceptance_status"] != "ACCEPT"].copy()
    if excluded.empty:
        return pd.DataFrame(
            columns=[
                "candidate_id",
                "proposed_class",
                "exclusion_reason",
                "source_label_confidence",
                "metadata_status",
                "routeviews_archive_status",
                "overlap_status_original_1419",
                "primary_source_non_cloudflare",
            ]
        )
    return excluded[
        [
            "candidate_id",
            "proposed_class",
            "exclusion_reason",
            "source_label_confidence",
            "metadata_status",
            "routeviews_archive_status",
            "overlap_status_original_1419",
            "primary_source_non_cloudflare",
        ]
    ]


def build_roster(verification: pd.DataFrame) -> pd.DataFrame:
    accepted = verification[verification["iec_acceptance_status"] == "ACCEPT"].copy()
    cols = [
        "candidate_id",
        "deterministic_mapped_class",
        "explicit_source_label",
        "mapping_rule_id",
        "source_label_confidence",
        "event_date_time",
        "event_end_time",
        "affected_asn",
        "origin_asn_where_applicable",
        "prefixes_available_from_source",
        "affected_prefix_count_reported",
        "metadata_status",
        "routeviews_archive_status",
        "primary_evidence_source",
        "source_type",
        "source_family",
        "primary_source_url_or_reference",
        "source_event_identifier",
        "overlap_status_original_1419",
        "label_source_independent_from_cloudflare",
        "underlying_evidence_overlap",
        "selection_used_model_output",
    ]
    return accepted[cols].rename(columns={"deterministic_mapped_class": "iec_label"})


def write_mapping_rules() -> Path:
    path = OUT_DIR / "v2_IEC_source_label_mapping_rules.csv"
    pd.DataFrame(MAPPING_RULES).to_csv(path, index=False)
    return path


def write_report(verification: pd.DataFrame, roster: pd.DataFrame, exclusions: pd.DataFrame) -> Path:
    counts = roster["iec_label"].value_counts().to_dict() if not roster.empty else {}
    source_dist = roster.groupby(["iec_label", "source_family"]).size().reset_index(name="count") if not roster.empty else pd.DataFrame()
    overlap_counts = verification["overlap_status_original_1419"].value_counts().to_dict()
    route_counts = verification["routeviews_archive_status"].value_counts().to_dict()
    metadata_limited = int((roster["metadata_status"] == "METADATA_PARTIAL_BUT_RECONSTRUCTABLE").sum()) if not roster.empty else 0
    all_explicit = bool((roster["source_label_confidence"] == "EXPLICIT").all()) if not roster.empty else False
    cloudflare_primary = int((verification["primary_source_non_cloudflare"] != "YES").sum())
    original_present = int((roster["overlap_status_original_1419"] != "NEW_INDEPENDENT_EVENT").sum()) if not roster.empty else 0
    reconstructable = bool(roster["metadata_status"].isin(["METADATA_COMPLETE", "METADATA_PARTIAL_BUT_RECONSTRUCTABLE"]).all()) if not roster.empty else False
    disposition = "READY_FOR_AUTOMATED_IEC_LOCK" if len(roster) > 0 and all_explicit and cloudflare_primary == 0 and original_present == 0 and reconstructable else "INSUFFICIENT_EXPLICIT_SOURCE_LABELS"

    lines = [
        "# V2 IEC Source-Separated Prelock Report",
        "",
        f"Generated UTC: {datetime.now(timezone.utc).isoformat()}",
        "",
        "This report applies deterministic, prospective source-native label mapping rules to the existing non-Cloudflare IEC candidate pool. No model output was used.",
        "",
        "## Required Answers",
        f"1. Events surviving IEC criteria: {len(roster)}",
        f"2. H/L/O counts: Hijack={counts.get('Hijack', 0)}, Leak={counts.get('Leak', 0)}, Outage={counts.get('Outage', 0)}",
        "3. Independent sources providing labels:",
    ]
    if source_dist.empty:
        lines.append("   - None")
    else:
        for _, r in source_dist.iterrows():
            lines.append(f"   - {r['iec_label']} / {r['source_family']}: {int(r['count'])}")
    lines.extend(
        [
            f"4. All accepted source labels explicit: {'YES' if all_explicit else 'NO'}",
            f"5. Cloudflare-primary labels present: {cloudflare_primary}",
            f"6. Original 1,419 incidents present in accepted roster: {original_present}",
            f"7. All accepted events reconstructable: {'YES' if reconstructable else 'NO'}",
            "8. Underlying evidence overlap among accepted events:",
        ]
    )
    for value, count in (roster["underlying_evidence_overlap"].value_counts().to_dict() if not roster.empty else {}).items():
        lines.append(f"   - {value}: {count}")
    lines.extend(
        [
            "",
            "## Candidate Accounting",
            f"- Starting candidates: {len(verification)}",
            f"- Accepted: {len(roster)}",
            f"- Excluded: {len(exclusions)}",
            f"- Metadata-limited accepted events: {metadata_limited}",
            f"- RouteViews status counts: {route_counts}",
            f"- Original-corpus overlap status counts: {overlap_counts}",
            "",
            "## Exclusions By Reason",
        ]
    )
    if exclusions.empty:
        lines.append("- None")
    else:
        for reason, count in exclusions["exclusion_reason"].value_counts().to_dict().items():
            lines.append(f"- {reason}: {count}")
    lines.extend(
        [
            "",
            "## Interpretation Boundary",
            "Label-source independence means the IEC label was taken from a non-Cloudflare source-native record. It does not imply complete underlying evidence-source independence: several accepted Hijack/Leak sources use BGP routing observations that conceptually overlap with Behavioral, CAIDA, or RPKI/ROV feature evidence.",
            "",
            f"Disposition: `{disposition}`",
            "",
        ]
    )
    path = OUT_DIR / "v2_IEC_source_separated_prelock_report.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def write_lock(roster: pd.DataFrame, generated_files: list[Path]) -> Path:
    lock_path = OUT_DIR / "V2_IEC_AUTOMATED_EVALUATION_LOCK.md"
    lines = [
        "# V2 IEC Automated Evaluation Lock",
        "",
        f"Generated UTC: {datetime.now(timezone.utc).isoformat()}",
        "",
        "This lock freezes the source-separated IEC roster and evaluation protocol before any model scoring.",
        "",
        "## Frozen Items",
        f"- IEC roster rows: {len(roster)}",
        f"- Hijack: {int((roster['iec_label'] == 'Hijack').sum())}",
        f"- Leak: {int((roster['iec_label'] == 'Leak').sum())}",
        f"- Outage: {int((roster['iec_label'] == 'Outage').sum())}",
        "- Source-native labels: frozen in `v2_IEC_final_source_separated_roster.csv`.",
        "- Mapping rules: frozen in `v2_IEC_source_label_mapping_rules.csv`.",
        "- Exclusions: frozen in `v2_IEC_automatic_exclusion_ledger.csv`.",
        "- Model artifacts and feature schemas: no changes permitted; verification/scoring must use the existing frozen Praxis artifacts.",
        "- Hypotheses: H1/H2/H3 source-separated IEC confirmation, feature-enrichment delta, and retrospective Level-2 comparison.",
        "- Bootstrap procedure: incident-level paired bootstrap with predeclared seed(s) from the scoring protocol.",
        "- Acceptance rules: no event replacement, tuning, retraining, recalibration, thresholding, or roster edits after scoring.",
        "",
        "## Checksums",
    ]
    for path in generated_files:
        if path.exists():
            lines.append(f"- `{path.name}`: `{sha256(path)}`")
    lines.extend(["", "Status: `IEC_ROSTER_AND_PROTOCOL_LOCKED_BEFORE_SCORING`", ""])
    lock_path.write_text("\n".join(lines), encoding="utf-8")
    (OUT_DIR / "V2_IEC_AUTOMATED_EVALUATION_LOCK.md.sha256").write_text(
        f"{sha256(lock_path)}  {lock_path.name}\n", encoding="utf-8"
    )
    return lock_path


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    candidates = load_candidates()
    rules_path = write_mapping_rules()
    verification = build_verification(candidates)
    verification_path = OUT_DIR / "v2_IEC_source_native_verification.csv"
    verification.to_csv(verification_path, index=False)
    exclusions = build_exclusion_ledger(verification)
    exclusions_path = OUT_DIR / "v2_IEC_automatic_exclusion_ledger.csv"
    exclusions.to_csv(exclusions_path, index=False)
    roster = build_roster(verification)
    roster_path = OUT_DIR / "v2_IEC_final_source_separated_roster.csv"
    roster.to_csv(roster_path, index=False)
    report_path = write_report(verification, roster, exclusions)

    generated = [rules_path, verification_path, exclusions_path, roster_path, report_path]
    disposition = "INSUFFICIENT_EXPLICIT_SOURCE_LABELS"
    if report_path.read_text(encoding="utf-8").strip().endswith("`READY_FOR_AUTOMATED_IEC_LOCK`"):
        lock_path = write_lock(roster, generated)
        generated.extend([lock_path, OUT_DIR / "V2_IEC_AUTOMATED_EVALUATION_LOCK.md.sha256"])
        disposition = "READY_FOR_AUTOMATED_IEC_LOCK"

    checksum_rows = [{"file": p.name, "sha256": sha256(p)} for p in generated if p.exists()]
    checksum_path = OUT_DIR / "v2_IEC_source_separated_checksums_v1.csv"
    pd.DataFrame(checksum_rows).to_csv(checksum_path, index=False)
    manifest = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "source_candidate_artifact": str(SOURCE_DIR / "v2_expert_adjudication_form.csv"),
        "candidate_count": int(len(verification)),
        "accepted_count": int(len(roster)),
        "excluded_count": int(len(exclusions)),
        "accepted_class_counts": roster["iec_label"].value_counts().to_dict(),
        "model_scoring_performed": False,
        "validation_accessed": False,
        "final_holdout_accessed": False,
        "disposition": disposition,
    }
    (OUT_DIR / "v2_IEC_source_separated_manifest_v1.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
