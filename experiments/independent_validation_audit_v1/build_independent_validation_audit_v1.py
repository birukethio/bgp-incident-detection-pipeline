from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent


SOURCES = {
    "RouteLLM": "https://arxiv.org/abs/2608.22812",
    "RouteLLM summary": "https://seekingsapiens.com/paper/the-surprising-effectiveness-of-llms-in-bgp-security-mining-an-unprecedented-amount-of-incidents-and-boosting-anomaly-detection/",
    "MANRS data sources": "https://manrs.org/manrs-observatory/data-sources/",
    "MANRS API docs": "https://docs.manrs.org/docs/getting-started/",
    "IODA API": "https://api.ioda.inetintel.cc.gatech.edu/v2/",
    "IODA APNIC overview": "https://blog.apnic.net/2024/09/11/ioda-internet-outage-detection-and-analysis/",
    "IODA glossary": "https://ioda.inetintel.cc.gatech.edu/resources?tab=glossary",
    "IODA curated outages repo": "https://github.com/InetIntel/internet_outages",
    "BGPStream data access": "https://bgpstream.caida.org/docs/overview/data-access",
    "Atlantic Council BGP incident data": "https://www.atlanticcouncil.org/resources/bgp-incident-data/",
    "GLBAD paper": "https://www.mdpi.com/2079-9292/14/24/4940",
    "RIPE RIS raw dataset": "https://labs.ripe.net/datarepository/data-sets/routing-information-service-ris-raw-dataset/",
    "RIPEstat BGP Updates": "https://stat.ripe.net/docs/data-api/api-endpoints/bgp-updates",
}


def write_text(name: str, text: str) -> None:
    path = ROOT / name
    path.write_text(text.strip() + "\n", encoding="utf-8")


def write_csv(name: str, rows: list[dict[str, object]], fieldnames: list[str]) -> None:
    path = ROOT / name
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def current_inventory() -> str:
    return f"""
# Current Frozen Study Inventory v1

## Scope and Stop Rule

This inventory is read-only documentation for an independent-validation protocol design. It does not retrain, rescore, relabel, repartition, or recompute any frozen experiment. The existing Final Holdout remains the terminal evaluation of the current Praxis architecture and is not accessed or recomputed by this audit.

## Frozen Corpus and Partitions

The authoritative balanced corpus contains 1,419 independent incidents:

- Hijack: 473 incidents
- Leak: 473 incidents
- Outage: 473 incidents

The frozen v2 incident-level partition is:

- TRAIN: 993 incidents, 331 per class
- Validation: 213 incidents, 71 per class
- Final Holdout: 213 incidents, 71 per class

Key local artifacts:

- `data/roster_v2/frozen_incident_roster_v2.csv`
- `data/partitions_v2/frozen_partition_manifest_v2.csv`
- `data/partitions_v2/train_incidents_v2.csv`
- `data/partitions_v2/validation_incidents_v2.csv`
- `data/partitions_v2/holdout_incidents_v2.csv`

## Frozen Feature Representation

The final model uses the frozen V4 feature schema with exactly 74 features:

- 44 Behavioral BGP features
- 14 historical CAIDA AS-relationship features
- 16 historical RPKI/ROV features

Key local artifacts:

- `data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1.parquet`
- `data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1_feature_manifest.csv`
- `config/feature_variants_v1.yaml`
- `config/behavioral_feature_schema_v1.yaml`
- `config/caida_feature_schema_v1.yaml`
- `config/rpki_feature_schema_v1.yaml`

To apply the frozen model to any independent confirmation set, the candidate events must be converted to this exact schema, ordering, data type policy, historical CAIDA mapping, historical RPKI/ROV mapping, and missing-value policy. No feature definitions may be changed after the confirmation set is observed.

## Frozen Model Architecture

The final Praxis architecture is an XGBoost-to-XGBoost incident-level architecture:

- Level 1: frozen XGBoost multiclass probability model over 74 V4 features.
- Level 1 inference: five-model cross-fit ensemble, recovered and probability-equivalent to the preserved TRAIN fingerprint.
- Level 2: frozen K1 incident temporal XGBoost stacker over incident-level meta-features.
- Ranking rule: sort Hijack, Leak, and Outage by descending incident-level probability.

Key local artifacts:

- `config/k1_final_candidate_v1_1_deployable.yaml`
- `config/k1_incident_meta_feature_schema_v1.yaml`
- `config/k1_second_level_xgb_final_v1.yaml`
- `data/tti_pilot/level1_ensemble_manifest_v2.json`
- `data/tti_pilot/reconstructed_level1_v1/`
- `data/tti_pilot/level1_probability_equivalence_v2.csv`
- `src/bgp_incident_detection/k1_incident_stacking.py`

The recovered Level-1 ensemble had exact probability equivalence against the preserved TRAIN fingerprint: 68,031 predictions compared, predicted-class agreement 1.0, maximum absolute probability difference 0.0, mean absolute probability difference 0.0, and per-class probability correlations 1.0.

## Terminal Final Holdout Result

The terminal authoritative Final Holdout result is recorded in `config/final_praxis_result_v1.yaml`:

- Holdout incidents: 213
- Holdout rows: 14,906
- Macro F1: 0.920177
- 95% CI: [0.880117, 0.954402]
- Top-1: 0.920188
- Top-2: 0.990610
- MRR: 0.958529
- Hijack F1: 0.877698
- Leak F1: 0.904110
- Outage F1: 0.978723
- Rank 1: 196
- Rank 2: 15
- Rank 3: 2
- Second-level parameter hash: `40df040321ef`

This audit does not reinterpret that result. Any future independent confirmation set would be additive and would not replace the one-time Final Holdout evaluation.

## Existing Provenance Findings

The label-provenance audit traced the final corpus to Cloudflare-derived incident sources and concluded `PASS_WITH_DOCUMENTED_EVIDENCE_SOURCE_OVERLAP`. The important distinction is:

- External label provenance: labels came from external Cloudflare incident/event feeds or outage annotations rather than from the model pipeline.
- Underlying evidence-source independence: Cloudflare's detection evidence may use public routing data and related signals that conceptually overlap Behavioral, CAIDA, or RPKI/ROV model features.

Key local artifacts:

- `experiments/label_provenance_audit_v1/cloudflare_label_entry_trace_v1.md`
- `experiments/label_provenance_audit_v1/label_provenance_final_disposition_v1.md`
- `experiments/label_provenance_audit_v1/direct_target_leakage_check_v1.csv`

## Existing TTI Work

The retrospective early-classification/TTI work is separate from the final K1 incident-level architecture:

- TTI uses the verified Level-1 XGBoost ensemble only.
- TTI does not use Level-2 temporal stacking.
- TTI uses checkpoint-based horizons and does not claim continuous live operational TTI.

Key local artifacts:

- `data/tti_validation_confirmation_v1/tti_validation_confirmation_summary_v1.md`
- `experiments/tti_early_horizon_v2/early_horizon_final_verification_v2.md`
- `experiments/tti_early_horizon_v2/early_horizon_final_disposition_v2.md`

The early-horizon v2 TRAIN analysis had disposition `PASS_WITH_DOCUMENTED_EXCLUSIONS`.

## Existing Class-Prior Sensitivity Analysis

The natural-distribution work is best described as a prevalence-reweighted prior-shift sensitivity analysis. It did not retrain, recalibrate, or duplicate incidents. It changed only evaluation weights/class priors on existing TRAIN nested-CV predictions.

Key local artifacts:

- `experiments/natural_distribution_v1/natural_distribution_reweighting_verification_v1.md`
- `experiments/natural_distribution_v1/natural_distribution_summary_v1.md`

Observed source-corpus proportions used in that sensitivity analysis were Hijack 47.2176%, Leak 52.5835%, and Outage 0.1989%.

## Artifacts Required Before Applying the Frozen Model to a New Confirmation Set

An independent confirmation execution, if later authorized, must freeze these inputs before first scoring:

1. Confirmation incident roster with incident IDs, class labels, source provenance, start/end times, affected ASN(s), and prefixes when applicable.
2. Confirmed non-overlap audit against the 1,419-incident frozen corpus.
3. RouteViews acquisition/reconstruction manifest and evidence-quality audit.
4. Frozen V4 feature file with exact 74-feature schema/order.
5. CAIDA and RPKI historical snapshot manifests.
6. Level-1 ensemble manifest and model checksums.
7. Level-2 K1 stacker config and model checksum.
8. Missing-value/imputation policy and class order.
9. Locked metrics/statistical protocol.
10. Pre-access exclusion and failure rules.

No Validation or Final Holdout artifact needs to be accessed to design or freeze this independent confirmation protocol.
"""


CANDIDATE_FIELDNAMES = [
    "candidate_id",
    "exact_source_dataset_name",
    "provider_or_publication",
    "source_type",
    "access_method",
    "license_or_restrictions",
    "available_event_classes",
    "class_coverage",
    "event_counts_or_dates",
    "prefix_availability",
    "asn_availability",
    "time_availability",
    "independent_labels",
    "label_method",
    "cloudflare_dependence",
    "routeviews_dependence",
    "ripe_ris_dependence",
    "rpki_or_as_relationship_dependence",
    "raw_or_reconstructable_bgp_evidence",
    "routeviews_mappability",
    "taxonomy_alignment",
    "overlap_risk_with_existing_corpus",
    "label_source_dependence_risk",
    "v4_compatibility",
    "LABEL_INDEPENDENCE",
    "FEATURE_SOURCE_INDEPENDENCE",
    "TEMPORAL_COMPATIBILITY",
    "ROUTEVIEWS_RECONSTRUCTABILITY",
    "CLASS_COMPATIBILITY",
    "OVERALL_USEFULNESS",
    "rating_explanation",
    "source_urls",
]


def candidate_rows() -> list[dict[str, object]]:
    return [
        {
            "candidate_id": "C01",
            "exact_source_dataset_name": "RouteLLM verified routing-anomaly benchmark",
            "provider_or_publication": "Liu et al.; IEEE ICNP 2026 / arXiv 2608.22812",
            "source_type": "Peer-reviewed benchmark mined from public operator mailing lists with expert validation",
            "access_method": "Public benchmark/code reported by paper; exact download/license must be verified before use",
            "license_or_restrictions": "Not frozen in this audit; must verify repository license and redistribution permissions",
            "available_event_classes": "Prefix hijack, path hijack, route leak, related routing anomalies",
            "class_coverage": "Strong for Hijack and Leak; not designed as an Outage corpus",
            "event_counts_or_dates": "Reported 232 confirmed routing-anomaly events; exact usable counts require dataset ingestion",
            "prefix_availability": "Reported structured extraction includes affected prefixes when available",
            "asn_availability": "Reported offending/victim networks available when extractable",
            "time_availability": "Reported start/end times available for benchmark records; must verify per record",
            "independent_labels": "Yes, relative to Cloudflare, subject to benchmark documentation",
            "label_method": "Operator mailing-list reports extracted with LLM pipeline and reviewed by routing-security experts",
            "cloudflare_dependence": "No direct Cloudflare dependence identified in audit",
            "routeviews_dependence": "Historical BGP data may be used to fill/validate records",
            "ripe_ris_dependence": "Historical BGP data may include RIS-derived evidence; verify record-level provenance",
            "rpki_or_as_relationship_dependence": "IRR/RPKI may be used to fill gaps according to paper summaries",
            "raw_or_reconstructable_bgp_evidence": "Likely reconstructable for records with time, ASN, prefix",
            "routeviews_mappability": "Moderate to high after record-level parsing",
            "taxonomy_alignment": "High for Hijack/Leak; low for Outage",
            "overlap_risk_with_existing_corpus": "Moderate; high-profile public incidents may already be in Cloudflare corpus",
            "label_source_dependence_risk": "Low Cloudflare dependence; moderate routing-evidence overlap",
            "v4_compatibility": "High if event times and ASN/prefix metadata are present",
            "LABEL_INDEPENDENCE": "HIGH",
            "FEATURE_SOURCE_INDEPENDENCE": "MODERATE",
            "TEMPORAL_COMPATIBILITY": "HIGH",
            "ROUTEVIEWS_RECONSTRUCTABILITY": "MODERATE",
            "CLASS_COMPATIBILITY": "HIGH",
            "OVERALL_USEFULNESS": "HIGH",
            "rating_explanation": "Best candidate for source-separated Hijack/Leak confirmation, but must pass license/access and overlap checks.",
            "source_urls": f"{SOURCES['RouteLLM']}; {SOURCES['RouteLLM summary']}",
        },
        {
            "candidate_id": "C02",
            "exact_source_dataset_name": "IODA outage events and curated Internet outages",
            "provider_or_publication": "Georgia Tech Internet Intelligence Lab / IODA; Internet outages repository",
            "source_type": "Internet outage detection system, API, and curated research dataset",
            "access_method": "IODA API endpoints and curated GitHub CSVs",
            "license_or_restrictions": "Repository/API terms must be checked before redistribution",
            "available_event_classes": "Internet outages, shutdowns, reachability drops",
            "class_coverage": "Strong for Outage only",
            "event_counts_or_dates": "API dynamic; curated SIGCOMM dataset available but not event-counted in this audit",
            "prefix_availability": "Usually aggregated by country/region/ASN; prefix detail varies",
            "asn_availability": "Available for ASN-level events/signals when event scope is ASN",
            "time_availability": "Time-series and event/alert windows available",
            "independent_labels": "Yes for curated outages and IODA-detected events, relative to Cloudflare",
            "label_method": "Anomaly detection over BGP visibility, active probing, telescope, and other signals; curated paper dataset has manual validation",
            "cloudflare_dependence": "No Cloudflare dependence identified",
            "routeviews_dependence": "IODA BGP signal uses RouteViews plus RIPE RIS via bgpview",
            "ripe_ris_dependence": "Yes, for BGP visibility signal",
            "rpki_or_as_relationship_dependence": "No core RPKI/AS relationship dependence identified for outage labels",
            "raw_or_reconstructable_bgp_evidence": "High for ASN/time outage events; non-BGP signals add independent evidence",
            "routeviews_mappability": "High for ASN events with timestamps; moderate for purely geographic outages",
            "taxonomy_alignment": "High for Outage if defined as BGP-visible Internet outage; review for traffic-only/geographic events",
            "overlap_risk_with_existing_corpus": "Moderate to high for notable outages already validated against Cloudflare",
            "label_source_dependence_risk": "Moderate because BGP visibility is one IODA signal; lower when active probing/telescope also support event",
            "v4_compatibility": "High for ASN/time scoped events; low for events without ASN/network mapping",
            "LABEL_INDEPENDENCE": "HIGH",
            "FEATURE_SOURCE_INDEPENDENCE": "MODERATE",
            "TEMPORAL_COMPATIBILITY": "HIGH",
            "ROUTEVIEWS_RECONSTRUCTABILITY": "HIGH",
            "CLASS_COMPATIBILITY": "HIGH",
            "OVERALL_USEFULNESS": "HIGH",
            "rating_explanation": "Best candidate for an independent Outage confirmation source, provided the selected events have ASN/network scope and are not merely traffic annotations.",
            "source_urls": f"{SOURCES['IODA API']}; {SOURCES['IODA APNIC overview']}; {SOURCES['IODA glossary']}; {SOURCES['IODA curated outages repo']}",
        },
        {
            "candidate_id": "C03",
            "exact_source_dataset_name": "MANRS Observatory / GRIP incidents",
            "provider_or_publication": "MANRS Observatory and Georgia Tech GRIP",
            "source_type": "Operational routing-security observatory using GRIP incident detection",
            "access_method": "MANRS API / Observatory records where accessible",
            "license_or_restrictions": "Requires API access and terms review",
            "available_event_classes": "Route leaks, route misoriginations/hijacks, AS-path manipulation, bogons",
            "class_coverage": "Strong for Hijack/Leak; no direct Outage class",
            "event_counts_or_dates": "Not counted in this audit; local MANRS summary files were empty",
            "prefix_availability": "GRIP/MANRS may expose affected prefixes depending on endpoint",
            "asn_availability": "Yes at AS/operator level",
            "time_availability": "Incident timestamps expected; must verify endpoint granularity",
            "independent_labels": "Partly; source-separated from Cloudflare but BGP-detector derived",
            "label_method": "GRIP detects/classifies BGP incidents; MANRS combines routing, registry, RPKI, IRR, and other sources",
            "cloudflare_dependence": "No direct Cloudflare dependence identified",
            "routeviews_dependence": "Routing collector dependence likely through GRIP/MANRS data sources",
            "ripe_ris_dependence": "MANRS identifies RIPE RIS as a ground-truth routing source",
            "rpki_or_as_relationship_dependence": "RPKI and IRR are MANRS data sources",
            "raw_or_reconstructable_bgp_evidence": "Likely reconstructable but endpoint access and detail must be validated",
            "routeviews_mappability": "Moderate",
            "taxonomy_alignment": "High for Hijack/Leak; none for Outage",
            "overlap_risk_with_existing_corpus": "High for events already matched in prior local Cloudflare/MANRS audits",
            "label_source_dependence_risk": "Moderate; independent provider but similar BGP evidence sources",
            "v4_compatibility": "Moderate to high if prefix/time fields are present",
            "LABEL_INDEPENDENCE": "MODERATE",
            "FEATURE_SOURCE_INDEPENDENCE": "LOW",
            "TEMPORAL_COMPATIBILITY": "MODERATE",
            "ROUTEVIEWS_RECONSTRUCTABILITY": "MODERATE",
            "CLASS_COMPATIBILITY": "HIGH",
            "OVERALL_USEFULNESS": "MODERATE",
            "rating_explanation": "Useful secondary/adjudication source for Hijack/Leak, but not enough evidence-source independence for the strongest confirmation set.",
            "source_urls": f"{SOURCES['MANRS data sources']}; {SOURCES['MANRS API docs']}",
        },
        {
            "candidate_id": "C04",
            "exact_source_dataset_name": "Atlantic Council BGP incident data / BGPStream-based incident data",
            "provider_or_publication": "Atlantic Council Cyber Statecraft Initiative; CAIDA BGPStream data access framework",
            "source_type": "Downloadable BGP incident dataset derived from BGPStream observations",
            "access_method": "Public dataset download; BGPStream tooling",
            "license_or_restrictions": "Dataset terms must be checked",
            "available_event_classes": "BGP attacks/malfunctions and related incidents",
            "class_coverage": "Potential Hijack/Leak; Outage unclear",
            "event_counts_or_dates": "First five months of 2020; exact count not recovered in this audit",
            "prefix_availability": "Likely present for BGPStream events; must verify",
            "asn_availability": "Likely present",
            "time_availability": "Likely present",
            "independent_labels": "Partly; independent from Cloudflare but BGPStream-derived",
            "label_method": "BGPStream event/detection data and incident classification",
            "cloudflare_dependence": "No direct Cloudflare dependence identified",
            "routeviews_dependence": "BGPStream brokers public collector data including RouteViews",
            "ripe_ris_dependence": "BGPStream brokers public collector data including RIPE RIS",
            "rpki_or_as_relationship_dependence": "Depends on event type; not primary from docs reviewed",
            "raw_or_reconstructable_bgp_evidence": "High, because source is BGP data",
            "routeviews_mappability": "High, but feature-source overlap is high",
            "taxonomy_alignment": "Moderate",
            "overlap_risk_with_existing_corpus": "Moderate",
            "label_source_dependence_risk": "Moderate to high because labels arise from BGP observations similar to Behavioral features",
            "v4_compatibility": "High for BGP-scoped records",
            "LABEL_INDEPENDENCE": "MODERATE",
            "FEATURE_SOURCE_INDEPENDENCE": "LOW",
            "TEMPORAL_COMPATIBILITY": "MODERATE",
            "ROUTEVIEWS_RECONSTRUCTABILITY": "HIGH",
            "CLASS_COMPATIBILITY": "MODERATE",
            "OVERALL_USEFULNESS": "MODERATE",
            "rating_explanation": "Useful diagnostic or supplemental set, but less compelling as independent confirmation because it is collector-derived and narrow in time.",
            "source_urls": f"{SOURCES['BGPStream data access']}; {SOURCES['Atlantic Council BGP incident data']}",
        },
        {
            "candidate_id": "C05",
            "exact_source_dataset_name": "GLBAD historical BGP anomaly dataset/list",
            "provider_or_publication": "Electronics 2025 GLBAD paper",
            "source_type": "Peer-reviewed historical anomaly study",
            "access_method": "Paper and any supplementary data if available",
            "license_or_restrictions": "Open-access article; supplementary-data rights must be checked",
            "available_event_classes": "Hijack, route leak, outage",
            "class_coverage": "All three classes but small",
            "event_counts_or_dates": "20 historical anomalies reported: 8 hijacks, 7 leaks, 5 outages, 2005-2024",
            "prefix_availability": "Varies; paper table may not provide full affected-prefix lists",
            "asn_availability": "Varies",
            "time_availability": "Dates available; exact start/end requires supplemental validation",
            "independent_labels": "Partly; labels based on historical public reports",
            "label_method": "Historical incident selection plus RIPE RIS data extraction for analysis",
            "cloudflare_dependence": "No Cloudflare dependence identified",
            "routeviews_dependence": "No RouteViews dependence identified in paper summary",
            "ripe_ris_dependence": "Uses RIPE RIS six-hour-before/after windows for data extraction",
            "rpki_or_as_relationship_dependence": "Not primary from reviewed summary",
            "raw_or_reconstructable_bgp_evidence": "Potentially reconstructable but may require manual metadata recovery",
            "routeviews_mappability": "Moderate",
            "taxonomy_alignment": "Moderate to high",
            "overlap_risk_with_existing_corpus": "High for famous historical incidents",
            "label_source_dependence_risk": "Moderate",
            "v4_compatibility": "Moderate if exact times/ASNs/prefixes are recovered",
            "LABEL_INDEPENDENCE": "MODERATE",
            "FEATURE_SOURCE_INDEPENDENCE": "LOW",
            "TEMPORAL_COMPATIBILITY": "LOW",
            "ROUTEVIEWS_RECONSTRUCTABILITY": "MODERATE",
            "CLASS_COMPATIBILITY": "MODERATE",
            "OVERALL_USEFULNESS": "MODERATE",
            "rating_explanation": "Good literature-backed seed list across all classes, but probably too small and metadata-light to be the primary confirmation set.",
            "source_urls": SOURCES["GLBAD paper"],
        },
        {
            "candidate_id": "C06",
            "exact_source_dataset_name": "Operator postmortem/writeup corpus: Kentik, ThousandEyes, BGPmon, RIPE Labs, public NOG/ISP RCAs",
            "provider_or_publication": "Multiple operator and measurement-provider reports",
            "source_type": "Human-authored incident reports and postmortems",
            "access_method": "Manual curation from public writeups; local candidate CSVs already exist for some leak reports",
            "license_or_restrictions": "Each source must be cited and reused under fair-use/dissertation quotation limits",
            "available_event_classes": "Hijack, Leak, Outage depending on source",
            "class_coverage": "Sparse but high quality",
            "event_counts_or_dates": "Local non-Kentik leak candidate file has 25 rows; Kentik/Cloudflare matched validation file has 3 rows",
            "prefix_availability": "Varies by report",
            "asn_availability": "Often present",
            "time_availability": "Varies; only exact timed records should be eligible",
            "independent_labels": "Yes when report source is independent from Cloudflare",
            "label_method": "Operator/provider narrative and incident analysis",
            "cloudflare_dependence": "No, unless using Cloudflare-matched local validation rows",
            "routeviews_dependence": "Some providers use BGP collector data; report-specific",
            "ripe_ris_dependence": "Report-specific",
            "rpki_or_as_relationship_dependence": "Report-specific",
            "raw_or_reconstructable_bgp_evidence": "Moderate; depends on metadata completeness",
            "routeviews_mappability": "Moderate",
            "taxonomy_alignment": "High after manual curation",
            "overlap_risk_with_existing_corpus": "High for incidents already used to validate Cloudflare rows",
            "label_source_dependence_risk": "Low to moderate",
            "v4_compatibility": "Moderate",
            "LABEL_INDEPENDENCE": "HIGH",
            "FEATURE_SOURCE_INDEPENDENCE": "MODERATE",
            "TEMPORAL_COMPATIBILITY": "MODERATE",
            "ROUTEVIEWS_RECONSTRUCTABILITY": "MODERATE",
            "CLASS_COMPATIBILITY": "MODERATE",
            "OVERALL_USEFULNESS": "MODERATE",
            "rating_explanation": "Excellent for high-confidence supplemental labels, but too sparse and inconsistent to stand alone.",
            "source_urls": "Local artifacts: cloudflare_incidents/cloudflare_kentik_route_leak_validation_2024-2025.csv; cloudflare_incidents/external_route_leak_writeup_candidates_non_kentik.csv",
        },
        {
            "candidate_id": "C07",
            "exact_source_dataset_name": "RIPE NCC incident reports and case studies",
            "provider_or_publication": "RIPE NCC / RIPE Labs / RIPE mailing-list incident analyses",
            "source_type": "Primary or near-primary incident reports",
            "access_method": "Manual curation from public RIPE pages and mailing-list archives",
            "license_or_restrictions": "Citation and reuse terms must be checked per page",
            "available_event_classes": "Mostly Hijack/Leak case studies; some outage/shutdown evidence",
            "class_coverage": "Sparse",
            "event_counts_or_dates": "Not a broad event corpus in this audit",
            "prefix_availability": "Often present for case studies",
            "asn_availability": "Often present",
            "time_availability": "Varies",
            "independent_labels": "High for specific reports",
            "label_method": "RIPE NCC analysis and routing-data interpretation",
            "cloudflare_dependence": "No direct Cloudflare dependence identified",
            "routeviews_dependence": "Not primary; RIPE relies on RIS and related data",
            "ripe_ris_dependence": "High",
            "rpki_or_as_relationship_dependence": "Report-specific",
            "raw_or_reconstructable_bgp_evidence": "High when report has exact event metadata",
            "routeviews_mappability": "Moderate",
            "taxonomy_alignment": "High for individual reports",
            "overlap_risk_with_existing_corpus": "High for famous events",
            "label_source_dependence_risk": "Moderate because RIPE evidence is routing-data based",
            "v4_compatibility": "Moderate",
            "LABEL_INDEPENDENCE": "HIGH",
            "FEATURE_SOURCE_INDEPENDENCE": "LOW",
            "TEMPORAL_COMPATIBILITY": "MODERATE",
            "ROUTEVIEWS_RECONSTRUCTABILITY": "MODERATE",
            "CLASS_COMPATIBILITY": "LOW",
            "OVERALL_USEFULNESS": "LOW",
            "rating_explanation": "Strong individual validation cases, not a scalable locked confirmation dataset.",
            "source_urls": f"{SOURCES['RIPE RIS raw dataset']}; {SOURCES['RIPEstat BGP Updates']}",
        },
        {
            "candidate_id": "C08",
            "exact_source_dataset_name": "RIPE RIS / RIPEstat BGP Updates raw evidence",
            "provider_or_publication": "RIPE NCC",
            "source_type": "Routing evidence repository/API, not an incident-label corpus",
            "access_method": "RIS MRT archives and RIPEstat BGP Updates API",
            "license_or_restrictions": "RIPE terms apply",
            "available_event_classes": "No intrinsic class labels",
            "class_coverage": "None without external labels",
            "event_counts_or_dates": "Not applicable",
            "prefix_availability": "Yes for queried updates",
            "asn_availability": "Yes through AS_PATH/origin",
            "time_availability": "Yes",
            "independent_labels": "No",
            "label_method": "No labels; raw BGP updates/RIBs",
            "cloudflare_dependence": "No",
            "routeviews_dependence": "No; separate public collector system",
            "ripe_ris_dependence": "It is RIPE RIS",
            "rpki_or_as_relationship_dependence": "No intrinsic RPKI/AS relationship labels",
            "raw_or_reconstructable_bgp_evidence": "High",
            "routeviews_mappability": "Evidence can be compared, but not a label source",
            "taxonomy_alignment": "Not applicable without labels",
            "overlap_risk_with_existing_corpus": "Evidence-only",
            "label_source_dependence_risk": "Not usable as label source",
            "v4_compatibility": "Evidence can support features, but using it as labels would be circular",
            "LABEL_INDEPENDENCE": "LOW",
            "FEATURE_SOURCE_INDEPENDENCE": "LOW",
            "TEMPORAL_COMPATIBILITY": "HIGH",
            "ROUTEVIEWS_RECONSTRUCTABILITY": "LOW",
            "CLASS_COMPATIBILITY": "LOW",
            "OVERALL_USEFULNESS": "LOW",
            "rating_explanation": "Important corroborating evidence, but not an independent label source.",
            "source_urls": f"{SOURCES['RIPE RIS raw dataset']}; {SOURCES['RIPEstat BGP Updates']}",
        },
        {
            "candidate_id": "C09",
            "exact_source_dataset_name": "RPKI/ROV incident reports and invalid-origin event reports",
            "provider_or_publication": "Mixed RPKI observatories, NOG posts, operator reports",
            "source_type": "Targeted incident reports",
            "access_method": "Manual curation",
            "license_or_restrictions": "Per-source restrictions",
            "available_event_classes": "Mostly Hijack/misorigin and RPKI-related outages",
            "class_coverage": "Sparse and biased",
            "event_counts_or_dates": "Not counted in this audit",
            "prefix_availability": "Usually present",
            "asn_availability": "Usually present",
            "time_availability": "Varies",
            "independent_labels": "Partly",
            "label_method": "RPKI validity/ROA state and operator confirmation",
            "cloudflare_dependence": "No direct dependence identified",
            "routeviews_dependence": "Often validated against BGP collectors",
            "ripe_ris_dependence": "Often used",
            "rpki_or_as_relationship_dependence": "High RPKI dependence",
            "raw_or_reconstructable_bgp_evidence": "Moderate",
            "routeviews_mappability": "Moderate",
            "taxonomy_alignment": "Moderate for Hijack; low for Leak/Outage",
            "overlap_risk_with_existing_corpus": "Moderate",
            "label_source_dependence_risk": "High for RPKI features because label evidence may be close to feature family",
            "v4_compatibility": "Moderate",
            "LABEL_INDEPENDENCE": "MODERATE",
            "FEATURE_SOURCE_INDEPENDENCE": "LOW",
            "TEMPORAL_COMPATIBILITY": "MODERATE",
            "ROUTEVIEWS_RECONSTRUCTABILITY": "MODERATE",
            "CLASS_COMPATIBILITY": "LOW",
            "OVERALL_USEFULNESS": "LOW",
            "rating_explanation": "Useful for limitations and targeted diagnostics, but risky for H2 because RPKI evidence may drive both labels and features.",
            "source_urls": "Manual source-specific curation required",
        },
        {
            "candidate_id": "C10",
            "exact_source_dataset_name": "LACNIC/BGPStream route-leak aggregates",
            "provider_or_publication": "LACNIC/BGPStream-derived local aggregate artifacts",
            "source_type": "Aggregate route-leak summaries",
            "access_method": "Local CSV artifacts",
            "license_or_restrictions": "Unknown",
            "available_event_classes": "Route leak aggregates",
            "class_coverage": "Leak aggregate only",
            "event_counts_or_dates": "Local file has 88 aggregate rows, not incident records",
            "prefix_availability": "No exact incident prefix lists in local aggregate",
            "asn_availability": "Aggregate country/pair fields, not enough incident metadata",
            "time_availability": "No exact incident times in local aggregate",
            "independent_labels": "No for incident-level confirmation",
            "label_method": "Aggregate BGPStream/LACNIC analysis",
            "cloudflare_dependence": "No direct dependence identified",
            "routeviews_dependence": "Likely through BGPStream",
            "ripe_ris_dependence": "Likely through BGPStream",
            "rpki_or_as_relationship_dependence": "Unknown",
            "raw_or_reconstructable_bgp_evidence": "Low at incident level",
            "routeviews_mappability": "Low without exact timestamps/prefixes/ASNs",
            "taxonomy_alignment": "Low for locked incident-level confirmation",
            "overlap_risk_with_existing_corpus": "Unknown",
            "label_source_dependence_risk": "Moderate",
            "v4_compatibility": "Low",
            "LABEL_INDEPENDENCE": "LOW",
            "FEATURE_SOURCE_INDEPENDENCE": "LOW",
            "TEMPORAL_COMPATIBILITY": "LOW",
            "ROUTEVIEWS_RECONSTRUCTABILITY": "LOW",
            "CLASS_COMPATIBILITY": "LOW",
            "OVERALL_USEFULNESS": "LOW",
            "rating_explanation": "Not suitable for locked incident-level confirmation unless raw event-level records are recovered.",
            "source_urls": "Local artifact: cloudflare_incidents/lacnic_bgpstream_route_leak_country_pair_aggregates.csv",
        },
    ]


def candidate_audit_md() -> str:
    return f"""
# Independent Dataset Candidate Audit v1

## Purpose

This audit identifies candidate external data sources for a future locked independent confirmation set. It does not download a new event roster, score any model, access Validation, or access/recompute Final Holdout.

## Main Finding

An independent confirmation set is feasible in principle, but not yet frozen. The best path is source-specific rather than a single universal replacement for Cloudflare:

- Hijack/Leak: RouteLLM's verified routing-anomaly benchmark is the strongest candidate if the released benchmark is accessible, licensed, and contains event-level time/ASN/prefix metadata.
- Outage: IODA outage events or the curated IODA outage/shutdown dataset are the strongest candidates, provided selected events are ASN/network scoped and not purely geographic or traffic annotations.
- Secondary/adjudication sources: MANRS/GRIP, operator postmortems, Kentik/ThousandEyes/BGPmon/RIPE reports, BGPStream-derived data, and GLBAD can support review or supplement sparse classes.

## Candidate Ranking

### Tier 1: Strongest Candidates

1. **RouteLLM verified routing-anomaly benchmark**
   - Strength: independent from Cloudflare and explicitly designed as a routing-anomaly benchmark.
   - Best classes: Hijack and Leak.
   - Key risk: the benchmark itself may use historical BGP, IRR, or RPKI evidence in validation; this is acceptable for label provenance but must be documented as evidence-source overlap.
   - Required next step: obtain the actual event-level dataset, verify license, count usable Hijack/Leak events, and deduplicate against the 1,419-event corpus.

2. **IODA outage events / curated IODA outage repository**
   - Strength: outage-focused and uses multiple signals beyond BGP.
   - Best class: Outage.
   - Key risk: some IODA events are geographic or Internet-shutdown events rather than ASN-scoped BGP-visible outages. These must be filtered to events with affected ASN/network scope and RouteViews reconstructability.
   - Required next step: select only events with precise times, ASN/network identity, and sufficient RouteViews coverage.

## Candidate Sources with Moderate Utility

### MANRS/GRIP

MANRS/GRIP is valuable for Hijack and Leak review, but the MANRS data-source documentation explicitly includes RIPE RIS, RPKI repositories, IRR records, and GRIP BGP-incident detection. That makes it less independent from the feature evidence base than RouteLLM/operator narratives. It is still useful as a secondary source or adjudicator.

### Operator Postmortems and Public Writeups

Operator and measurement-provider writeups are high-quality when they provide exact time intervals and ASN/prefix metadata, but the coverage is sparse and inconsistent. They are best used to supplement RouteLLM/IODA or to adjudicate disputed events rather than to define the entire confirmation set.

### BGPStream / Atlantic Council Incident Data

BGPStream provides excellent routing-evidence access and the Atlantic Council dataset is useful, but labels are close to the same public BGP evidence used in Behavioral features. This is acceptable for a diagnostic sensitivity set, but weaker as a strong independent-label confirmation set.

### GLBAD

GLBAD provides a compact literature-backed list covering Hijack, Leak, and Outage, but the reported count is only 20 events and exact metadata may require manual recovery. It is useful as a literature triangulation source, not as the main confirmation set.

## Sources Not Recommended as Primary Label Sources

- RIPE RIS/RIPEstat raw BGP updates: important evidence source, not an independent label source.
- LACNIC/BGPStream aggregate route-leak data: local artifacts are aggregate-level and lack event-level time/prefix/ASN fields.
- RPKI-only incident reports: useful targeted diagnostics but feature-source dependence is high because RPKI/ROV is one of the model feature families.

## Documentation Sources Consulted

- RouteLLM: {SOURCES['RouteLLM']}
- MANRS data sources: {SOURCES['MANRS data sources']}
- IODA API: {SOURCES['IODA API']}
- IODA overview: {SOURCES['IODA APNIC overview']}
- IODA curated outages: {SOURCES['IODA curated outages repo']}
- BGPStream data access: {SOURCES['BGPStream data access']}
- Atlantic Council BGP incident data: {SOURCES['Atlantic Council BGP incident data']}
- GLBAD paper: {SOURCES['GLBAD paper']}
- RIPE RIS raw dataset: {SOURCES['RIPE RIS raw dataset']}
- RIPEstat BGP Updates: {SOURCES['RIPEstat BGP Updates']}
"""


def overlap_rows() -> list[dict[str, object]]:
    return [
        {
            "candidate_source": "RouteLLM verified routing-anomaly benchmark",
            "candidate_record_scope": "Event-level benchmark reported by paper; not ingested in this audit",
            "local_artifacts_checked": "No local RouteLLM event roster found",
            "event_level_records_ingested": "0",
            "potential_overlap_basis": "Future comparison must use class, time overlap, affected ASN, prefix, event ID/text",
            "overlap_classification": "REVIEW_REQUIRED",
            "notes": "No event-level overlap can be calculated until the benchmark records are obtained.",
            "next_required_action": "Acquire dataset, verify license, normalize metadata, then compare to frozen 1,419-event corpus.",
        },
        {
            "candidate_source": "IODA outage events / curated outages",
            "candidate_record_scope": "IODA API/events and curated outage CSVs; independent clean roster not ingested here",
            "local_artifacts_checked": "cloudflare_incidents/cloudflare_manrs_ioda_matched_incidents_2021-2025.csv; cloudflare_incidents/cloudflare_manrs_ioda_audit_incidents_2021-2025.csv",
            "event_level_records_ingested": "0 new locked records",
            "potential_overlap_basis": "Prior local files include Cloudflare/IODA matching work, so some events are already same-event validations",
            "overlap_classification": "POSSIBLE_SAME_EVENT",
            "notes": "Matched local files are not a new independent confirmation roster; they show IODA has already overlapped Cloudflare for some outages.",
            "next_required_action": "Build a source-native IODA candidate set, remove any Cloudflare-matched records already in the final corpus.",
        },
        {
            "candidate_source": "MANRS/GRIP",
            "candidate_record_scope": "Potential route-leak/hijack incidents via MANRS API",
            "local_artifacts_checked": "manrs_incident_summaries_2021-2025.csv; manrs_route_leak_incident_summaries_2021-2025.csv; cloudflare_manrs_ioda_* files",
            "event_level_records_ingested": "0 usable local MANRS summary rows",
            "potential_overlap_basis": "Prior Cloudflare/MANRS match artifacts imply high same-event risk",
            "overlap_classification": "REVIEW_REQUIRED",
            "notes": "Local MANRS summary CSVs were empty; API-level extraction would be needed.",
            "next_required_action": "Use MANRS API only after freezing record-level fields and deduplication criteria.",
        },
        {
            "candidate_source": "Kentik / operator route-leak writeups",
            "candidate_record_scope": "Small local validation/candidate files",
            "local_artifacts_checked": "cloudflare_kentik_route_leak_validation_2024-2025.csv; external_route_leak_writeup_candidates_non_kentik.csv",
            "event_level_records_ingested": "3 Kentik validation rows and 25 candidate rows exist locally, not locked as confirmation set",
            "potential_overlap_basis": "Kentik validation rows were explicitly Cloudflare-matched; non-Kentik candidates need time/ASN/prefix dedup",
            "overlap_classification": "CONFIRMED_SAME_EVENT",
            "notes": "The three Kentik validation rows are useful evidence for Cloudflare correctness, not new independent events.",
            "next_required_action": "Filter out matched validation rows; manually review non-Kentik candidates with exact times.",
        },
        {
            "candidate_source": "BGPStream / Atlantic Council incident data",
            "candidate_record_scope": "Dataset not ingested in this audit",
            "local_artifacts_checked": "No source-native Atlantic Council dataset found locally",
            "event_level_records_ingested": "0",
            "potential_overlap_basis": "Compare first-five-months-2020 events by time/prefix/ASN/class",
            "overlap_classification": "REVIEW_REQUIRED",
            "notes": "Potentially usable diagnostic set, but BGPStream feature-source overlap is high.",
            "next_required_action": "Obtain dataset and perform event-level overlap audit before any use.",
        },
        {
            "candidate_source": "GLBAD historical anomaly list",
            "candidate_record_scope": "Paper-level seed list, not ingested",
            "local_artifacts_checked": "No GLBAD source-native roster found locally",
            "event_level_records_ingested": "0",
            "potential_overlap_basis": "Famous historical incidents are likely to overlap prior corpus or literature references",
            "overlap_classification": "REVIEW_REQUIRED",
            "notes": "Useful as literature-backed triangulation, not an immediate locked set.",
            "next_required_action": "Recover exact metadata from paper/supplement, then deduplicate.",
        },
        {
            "candidate_source": "RIPE RIS/RIPEstat raw BGP evidence",
            "candidate_record_scope": "Evidence-only source",
            "local_artifacts_checked": "Existing project uses RouteViews for features; RIPE not used as independent labels",
            "event_level_records_ingested": "0 labels",
            "potential_overlap_basis": "Not applicable because raw evidence has no labels",
            "overlap_classification": "REVIEW_REQUIRED",
            "notes": "Cannot serve as label confirmation set by itself.",
            "next_required_action": "Use only as corroborating evidence for externally labeled events.",
        },
    ]


OVERLAP_FIELDNAMES = [
    "candidate_source",
    "candidate_record_scope",
    "local_artifacts_checked",
    "event_level_records_ingested",
    "potential_overlap_basis",
    "overlap_classification",
    "notes",
    "next_required_action",
]


def confirmation_design_md() -> str:
    return """
# Locked Confirmation Set Design v1

## Design Objective

The confirmation set should test whether the frozen Praxis architecture generalizes to independently sourced labels whose provenance is not Cloudflare. It must be built and locked before first scoring. It must not replace or reinterpret the terminal Final Holdout result.

## Recommended Design

Use a source-separated, event-level confirmation set with two tiers:

1. **Primary confirmation cohort**
   - Hijack/Leak from RouteLLM if accessible and metadata-complete.
   - Outage from IODA curated/API events if ASN/network scoped.
   - Exclude any event that matches the existing 1,419-event corpus.

2. **Secondary adjudication cohort**
   - MANRS/GRIP, operator postmortems, Kentik/ThousandEyes/BGPmon/RIPE reports, BGPStream/Atlantic Council, and GLBAD records.
   - Use these mainly to resolve sparse classes, validate ambiguous cases, or provide descriptive sensitivity checks.

## Do Not Force 30/30/30

A 30/30/30 design is acceptable only if the source-native data supports it after quality filtering and overlap removal. If one class has fewer usable independent events, the confirmation set should preserve the defensible event count rather than padding with weaker records.

Preferred reporting:

- Natural/source-preserving confirmation cohort: all eligible independent events.
- Optional balanced diagnostic subset: only if at least 30 per class are available without weakening criteria.

## Inclusion Criteria

An event is eligible only if all criteria are met:

1. Source is not Cloudflare and not derived from a Cloudflare event ID.
2. Event class can be mapped prospectively to Hijack, Leak, or Outage.
3. Start time is available and UTC-normalizable.
4. End time or defensible active interval rule is available.
5. Affected ASN/network is available; affected prefix is required for Hijack and preferred for Leak.
6. RouteViews reconstruction is feasible over the event window.
7. Event does not overlap the final 1,419-event corpus by event ID, description, ASN/prefix/time, or source narrative.
8. License/access allows dissertation use.
9. Event metadata can be frozen before model scoring.

## Exclusion Criteria

Exclude or classify as review-only:

- Events with only a date and no usable time.
- Outages that are purely regional/geographic with no ASN/network mapping.
- Events that are the same real-world incident already in the Cloudflare corpus.
- Events whose class is inferred locally from the same V4 features rather than supplied by an external source.
- Events with RouteViews coverage failure after acquisition.
- Events requiring a post-hoc class-specific rule after predictions are seen.

## Deduplication Rules

Before scoring, compare every candidate against the 1,419 frozen incidents using:

- class/category;
- start/end temporal overlap;
- affected ASN(s);
- affected prefix(es);
- source event IDs;
- event descriptions and public reports;
- country/network/operator.

Classify each candidate as `NEW_INDEPENDENT_EVENT`, `POSSIBLE_SAME_EVENT`, `CONFIRMED_SAME_EVENT`, or `REVIEW_REQUIRED`. Only `NEW_INDEPENDENT_EVENT` records may enter the locked confirmation cohort.

## Confirmation Cohort Lock

The final cohort should be frozen as:

- source-native roster;
- normalized roster;
- overlap audit;
- RouteViews acquisition manifest;
- feature manifest;
- exclusion log;
- SHA-256 checksums.

Only after this freeze should the frozen model be applied.
"""


def hypotheses_md() -> str:
    return """
# Locked Hypothesis Specification v1

## H1: Final Classification and Ranking Performance

**Population.** All events in the locked independent confirmation cohort that pass predeclared metadata, overlap, RouteViews reconstruction, and V4 compatibility gates.

**Model.** Frozen XGBoost-to-XGBoost K1 architecture with no retraining, tuning, threshold selection, feature selection, or recalibration.

**Primary metric.** Incident-level Macro F1.

**Secondary metrics.** Top-1 accuracy, Top-2 accuracy, MRR, per-class precision/recall/F1, confusion matrix, and mean true-class rank.

**Minimum practical support rule.** H1 is supported if Macro F1 is at least 0.70 and the incident-level bootstrap 95% CI lower bound is at least 0.60, with Top-2 at least 0.85. These are practical confirmation floors, not a replacement for the terminal Final Holdout result.

**Statistical procedure.** Incident-level paired or unpaired bootstrap as applicable, 10,000 resamples, fixed seed 20260914, percentile 95% CI. The incident is the unit of inference.

**Decision rule.**

- `SUPPORTED`: primary floor and ranking floor pass.
- `SUPPORTED_WITH_CAVEAT`: point estimate passes but CI lower bound or a class-specific result requires review.
- `NOT_SUPPORTED`: primary point estimate falls below floor or a severe class-specific failure is observed.

## H2: Behavioral-Only vs Behavioral + CAIDA + RPKI/ROV

**Question.** Does the full V4 representation materially improve over Behavioral-only representation on an independent confirmation cohort?

**Comparator.** Behavioral-only frozen comparator may be used only if a pre-existing model/config can be reconstructed and locked before confirmation scoring. No new training may occur after confirmation labels are inspected.

**Primary metric.** Paired incident-level Macro F1 difference: V4 minus Behavioral-only.

**Minimum practical difference.** +0.03 Macro F1.

**Secondary metrics.** Top-2, MRR, Hijack F1, Leak F1, Outage F1.

**Statistical procedure.** Paired incident bootstrap over incidents, 10,000 resamples, fixed seed 20260914, percentile 95% CI.

**Execution gate.** If no artifact-equivalent Behavioral-only comparator can be frozen before scoring, H2 should be documented as not executable on the independent confirmation set without methodological change.

## H3: Mean Aggregation vs Temporal Stacking

**Question.** Does the K1 temporal stacker materially improve incident-level classification/ranking over mean probability aggregation on the same independent confirmation cohort?

**Comparator.** Mean class probability across eligible incident windows using the same frozen Level-1 predictions.

**Primary metric.** Paired incident-level Macro F1 difference: K1 stacker minus mean aggregation.

**Minimum practical difference.** +0.03 Macro F1 or +0.02 MRR, with no severe per-class regression.

**Secondary metrics.** Top-1, Top-2, MRR, per-class F1, and fold/source-specific sensitivity where sample size permits.

**Statistical procedure.** Paired incident bootstrap, 10,000 resamples, fixed seed 20260914, percentile 95% CI.

**Decision rule.**

- `SUPPORTED`: point estimate meets minimum practical difference and CI is not strongly negative.
- `SUPPORTED_WITH_CAVEAT`: improvement is small or class-specific degradation appears.
- `NOT_SUPPORTED`: mean aggregation matches/exceeds K1 or K1 has severe class-specific degradation.

## General Rules

- No Final Holdout access.
- No model updates after seeing confirmation performance.
- No post-hoc event exclusions except failures covered by the predeclared exclusion rules.
- All comparisons must use identical eligible incident denominators.
"""


def protocol_md() -> str:
    return """
# Independent Validation Protocol v1

## Status

This is a pre-execution protocol. No new confirmation set has been scored. The Final Holdout remains untouched.

## Frozen Inputs

### Model Artifacts

- Level-1 model/ensemble: `data/tti_pilot/reconstructed_level1_v1/` and `data/tti_pilot/level1_ensemble_manifest_v2.json`
- Level-1 schema: `data/tti_pilot/reconstructed_level1_v1/feature_schema_v4.json`
- Final candidate config: `config/k1_final_candidate_v1_1_deployable.yaml`
- K1 meta-feature schema: `config/k1_incident_meta_feature_schema_v1.yaml`
- K1 second-level config: `config/k1_second_level_xgb_final_v1.yaml`
- K1 implementation: `src/bgp_incident_detection/k1_incident_stacking.py`

### Feature Artifacts and Methodology

- Frozen V4 schema: 44 Behavioral + 14 CAIDA + 16 RPKI/ROV.
- Historical CAIDA snapshot selection must match the frozen TRAIN methodology.
- Historical RPKI/ROV snapshot selection must match the frozen TRAIN methodology.
- Feature order and missing-value policy must match the frozen V4 pipeline.
- Class order must remain Hijack, Leak, Outage.

## Confirmation Set Construction

1. Extract candidate events from preselected independent sources.
2. Normalize event class, source ID, source URL, affected ASN(s), affected prefix(es), start/end times, and description.
3. Remove events that overlap the frozen 1,419-event corpus.
4. Freeze the source-native and normalized candidate rosters.
5. Acquire RouteViews MRT data only for locked candidate events.
6. Generate frozen V4 features without modifying feature definitions.
7. Run compatibility/leakage gates.
8. Score only after all above artifacts are frozen.

## Incident Window Construction

The default confirmation design should use the same event-window logic as the final Praxis incident classification pipeline, not the TTI partial-horizon logic. For Hijack/Leak detector spans, event-active windows must follow the frozen incident-window policy. For Outage events, documented outage start/end intervals may be used when they are explicitly source-reported and ASN/network scoped.

## Scoring

- Level 1 produces class probabilities for each eligible five-minute window.
- Mean aggregation baseline uses mean class probability across eligible windows.
- K1 stacker constructs incident-level meta-features from the complete eligible incident window sequence and scores with the frozen Level-2 model.
- Ranking is descending probability over Hijack, Leak, Outage.

## Metrics

Primary:

- Incident Macro F1.

Secondary:

- Top-1 accuracy.
- Top-2 accuracy.
- MRR.
- Per-class precision/recall/F1.
- Confusion matrix.
- Mean true-class rank.
- Class/source-stratified descriptive summaries where sample size permits.

## Statistical Inference

- Unit: incident.
- Bootstrap: 10,000 incident-level resamples.
- Seed: 20260914.
- CI: percentile 95% confidence interval.
- Paired tests/comparisons use identical incident denominators.

## Failure and Exclusion Handling

Before scoring, classify each event as:

- `ELIGIBLE`
- `EXCLUDED_OVERLAPS_EXISTING_CORPUS`
- `EXCLUDED_MISSING_TIME`
- `EXCLUDED_MISSING_ASN_OR_PREFIX`
- `EXCLUDED_ROUTEVIEWS_RECONSTRUCTION_FAILURE`
- `EXCLUDED_V4_COMPATIBILITY_FAILURE`
- `EXCLUDED_LABEL_AMBIGUITY`
- `REVIEW_REQUIRED`

Do not create post-hoc exclusions after seeing predictions.

## Prohibited Actions

- No retraining.
- No tuning.
- No feature selection.
- No threshold selection.
- No recalibration.
- No architecture change.
- No Validation access for model decisions.
- No Final Holdout access.
- No peeking at confirmation predictions before the cohort and protocol are frozen.
- No post-hoc class-specific reinterpretation.

## Audit Logs Required for Execution

1. Source extraction log.
2. Deduplication/overlap log.
3. RouteViews acquisition log.
4. Feature-generation log.
5. V4 compatibility audit.
6. Scoring manifest.
7. Statistical output register.
8. Non-modification attestation.

## One-Time Rule

The locked confirmation set is evaluated once. After its results are observed, the model, features, event roster, exclusion rules, and metrics may not be changed and re-evaluated as if still confirmatory.
"""


def paired_plan_md() -> str:
    return """
# Paired Comparison Plan v1

## Purpose

This plan defines how to compare frozen alternatives on the same independent confirmation incidents without retraining or post-hoc selection.

## H2: Behavioral-Only vs Full V4

### Required Artifacts

- Frozen Behavioral-only comparator model or deterministic reconstruction spec.
- Frozen full V4 K1 model.
- Same eligible confirmation incidents for both systems.
- Same incident windows and class labels.

### Metrics

For every incident, compute predictions from both systems and record:

- true class;
- predicted class;
- class probabilities/ranking;
- true-class rank;
- correctness indicators.

Calculate paired differences for:

- Macro F1;
- Top-1;
- Top-2;
- MRR;
- Hijack F1;
- Leak F1;
- Outage F1.

### Decision

H2 is considered supported if V4 improves Macro F1 by at least +0.03 and the paired bootstrap interval does not indicate a clear negative effect. If the Behavioral-only model cannot be frozen without retraining, H2 is not executable as a confirmation claim.

## H3: Mean Aggregation vs K1 Temporal Stacker

### Required Artifacts

- Frozen Level-1 probabilities.
- Mean-aggregation incident predictions.
- Frozen K1 stacker predictions.

### Metrics

Use identical incident denominators and compute:

- Macro F1 difference;
- Top-1 difference;
- Top-2 difference;
- MRR difference;
- per-class F1 differences;
- number and percentage of incidents where K1 changes the Top-1 result compared with mean aggregation.

### Statistical Procedure

- Incident-level paired bootstrap.
- 10,000 resamples.
- Seed 20260914.
- Percentile 95% CI.

## Reporting

Report both point estimates and intervals. Do not use p-value-only language. Avoid causal wording such as "proved" or "caused"; use "was associated with" or "improved under the paired protocol."
"""


def stacker_audit_md() -> str:
    return """
# Temporal Stacker Causality Audit v1

## Question

Can the final K1 temporal stacker be interpreted as a causal/prospective early detector, or should it be evaluated as a retrospective/post-window incident classifier?

## Evidence Inspected

- `config/k1_incident_meta_feature_schema_v1.yaml`
- `config/k1_second_level_xgb_final_v1.yaml`
- `src/bgp_incident_detection/k1_incident_stacking.py`
- `src/bgp_incident_detection/k1_forensic_audit.py`

## Temporal Feature Construction

The K1 incident meta-feature schema uses deterministic chronological equal-count segmentation into EARLY, MIDDLE, and LATE thirds. The implementation sorts the complete window group by `window_start`, then computes:

- all-window mean class probabilities;
- probability quantiles;
- top-class proportions;
- EARLY/MIDDLE/LATE segment probability means;
- late-minus-early probability changes;
- linear probability slopes over the full incident sequence;
- observed temporal span from minimum `window_start` to maximum `window_end`.

These features require the complete eligible incident window sequence. The LATE segment, late-minus-early features, full-sequence slopes, and final observed temporal span cannot be known at the beginning or middle of a live event.

## Causality Classification

`RETROSPECTIVE`

The final K1 temporal stacker is a retrospective/post-window incident classifier and ranking model. It is appropriate for classifying an incident after the configured observation window has been assembled. It should not be described as a live causal detector or as the model responsible for sub-five-minute TTI.

## Consequence for Independent Confirmation

An independent confirmation set may evaluate K1 as a retrospective incident-classification system using complete eligible incident windows. That would be consistent with the final Praxis architecture and Final Holdout evaluation.

If the research question is prospective operational detection, a separate causal/online experiment is required. That experiment should use only evidence available up to each decision time and should not use K1's LATE-segment or full-sequence meta-features.

## Relationship to TTI

The existing TTI work correctly separates early-horizon evaluation from the final K1 architecture by using the verified Level-1 XGBoost ensemble only. This separation should be preserved in dissertation language:

- Final K1: retrospective/post-window incident classification and ranking.
- TTI: retrospective early-classification sensitivity using partial RouteViews evidence and Level-1 only.

## Disposition

The stacker is valid for the final retrospective architecture but not causal/prospective without redesign. Future independent confirmation should report this explicitly.
"""


def audit_json() -> None:
    manifest = {
        "audit": "independent_validation_audit_v1",
        "created_files": sorted(p.name for p in ROOT.iterdir() if p.is_file() and p.name != "build_independent_validation_audit_v1.py"),
        "source_urls": SOURCES,
        "non_destructive": True,
        "final_holdout_accessed_or_recomputed": False,
        "model_scoring_performed": False,
    }
    (ROOT / "audit_build_manifest_v1.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    write_text("current_frozen_study_inventory_v1.md", current_inventory())
    write_csv("independent_dataset_candidate_matrix_v1.csv", candidate_rows(), CANDIDATE_FIELDNAMES)
    write_text("independent_dataset_candidate_audit_v1.md", candidate_audit_md())
    write_csv("candidate_overlap_with_existing_corpus_v1.csv", overlap_rows(), OVERLAP_FIELDNAMES)
    write_text("locked_confirmation_set_design_v1.md", confirmation_design_md())
    write_text("locked_hypothesis_specification_v1.md", hypotheses_md())
    write_text("independent_validation_protocol_v1.md", protocol_md())
    write_text("paired_comparison_plan_v1.md", paired_plan_md())
    write_text("temporal_stacker_causality_audit_v1.md", stacker_audit_md())
    audit_json()

    checksums = []
    for path in sorted(ROOT.iterdir()):
        if path.is_file() and path.name != "checksums_v1.csv":
            checksums.append({"file": path.name, "sha256": sha256_file(path)})
    write_csv("checksums_v1.csv", checksums, ["file", "sha256"])


if __name__ == "__main__":
    main()
