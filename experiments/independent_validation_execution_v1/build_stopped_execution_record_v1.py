from __future__ import annotations

import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]
AUDIT = REPO / "experiments" / "independent_validation_audit_v1"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_csv(name: str, rows: list[dict[str, object]], fieldnames: list[str]) -> None:
    with (ROOT / name).open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_text(name: str, text: str) -> None:
    (ROOT / name).write_text(text.strip() + "\n", encoding="utf-8")


def main() -> None:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    checksum_rows = list(csv.DictReader((ROOT / "locked_artifact_checksum_verification_v1.csv").open()))
    checksum_matches = sum(row["status"] == "MATCH" for row in checksum_rows)

    roster_fields = [
        "confirmation_incident_id",
        "source",
        "source_event_id",
        "SOURCE_LABEL",
        "FINAL_ADJUDICATED_LABEL",
        "event_timestamp_utc",
        "prefix",
        "origin_or_affected_asn",
        "supporting_evidence",
        "adjudication_status",
        "overlap_status",
        "routeviews_availability",
        "inclusion_status",
        "inclusion_exclusion_reason",
    ]
    write_csv("independent_confirmation_roster_final_v1.csv", [], roster_fields)

    exclusion_rows = [
        {
            "source": "RouteLLM",
            "candidate_scope": "Primary locked Hijack/Leak source",
            "status": "NOT_ACQUIRED",
            "reason": "SOURCE_NATIVE_EVENT_ROSTER_NOT_FOUND",
            "protocol_effect": "STOP_BEFORE_SCORING",
            "details": "RouteLLM benchmark was reported in arXiv 2608.22812 as open-sourced, but this run found no local roster, no usable repository link in the arXiv source package, and exact GitHub repository searches returned zero matching repositories.",
        },
        {
            "source": "IODA",
            "candidate_scope": "Primary locked Outage source",
            "status": "NOT_ACQUIRED",
            "reason": "DEPENDENT_ON_ALL_CLASS_CONFIRMATION_SET_GATE",
            "protocol_effect": "STOP_BEFORE_SCORING",
            "details": "IODA may support Outage candidates, but scoring only Outage would violate the locked H1/H2/H3 all-class confirmation design after the primary Hijack/Leak source gate failed.",
        },
        {
            "source": "MANRS/GRIP/operator writeups",
            "candidate_scope": "Secondary corroboration/adjudication only",
            "status": "NOT_USED_AS_PRIMARY_REPLACEMENT",
            "reason": "LOCKED_SOURCE_HIERARCHY",
            "protocol_effect": "STOP_BEFORE_SCORING",
            "details": "The locked protocol permits these only as corroboration/adjudication sources, not as replacements for unavailable RouteLLM primary Hijack/Leak candidates.",
        },
    ]
    write_csv(
        "independent_confirmation_exclusion_ledger_v1.csv",
        exclusion_rows,
        ["source", "candidate_scope", "status", "reason", "protocol_effect", "details"],
    )

    independence_rows = [
        {
            "audit_item": "Existing 1,419-corpus overlap audit",
            "status": "NOT_EXECUTED",
            "reason": "No accepted independent candidate incidents were acquired before the source gate stopped execution.",
            "result": "No event-level overlap comparisons performed.",
        },
        {
            "audit_item": "RouteLLM availability",
            "status": "FAIL_GATE",
            "reason": "Source-native event roster unavailable in local workspace and not discoverable from inspected public paper/source metadata.",
            "result": "No Hijack/Leak confirmation roster could be constructed under the lock.",
        },
        {
            "audit_item": "Artifact checksum verification",
            "status": "PASS",
            "reason": "All locked artifacts recomputed before any scoring.",
            "result": f"{checksum_matches}/20 artifacts matched.",
        },
    ]
    write_csv(
        "independent_confirmation_independence_audit_v1.csv",
        independence_rows,
        ["audit_item", "status", "reason", "result"],
    )

    h1_rows = [
        {
            "metric": "incident_macro_f1",
            "value": "NA",
            "ci_lower": "NA",
            "ci_upper": "NA",
            "eligible_incidents": 0,
            "status": "NOT_EXECUTED_PROTOCOL_GATE_STOP",
            "decision": "INCONCLUSIVE",
            "notes": "No eligible independent confirmation roster was constructed because RouteLLM source-native events were unavailable.",
        },
        {
            "metric": "top1",
            "value": "NA",
            "ci_lower": "NA",
            "ci_upper": "NA",
            "eligible_incidents": 0,
            "status": "NOT_EXECUTED_PROTOCOL_GATE_STOP",
            "decision": "INCONCLUSIVE",
            "notes": "No scoring performed.",
        },
        {
            "metric": "top2",
            "value": "NA",
            "ci_lower": "NA",
            "ci_upper": "NA",
            "eligible_incidents": 0,
            "status": "NOT_EXECUTED_PROTOCOL_GATE_STOP",
            "decision": "INCONCLUSIVE",
            "notes": "Predefined H1 acceptance criterion not evaluated.",
        },
        {
            "metric": "mrr",
            "value": "NA",
            "ci_lower": "NA",
            "ci_upper": "NA",
            "eligible_incidents": 0,
            "status": "NOT_EXECUTED_PROTOCOL_GATE_STOP",
            "decision": "INCONCLUSIVE",
            "notes": "No scoring performed.",
        },
    ]
    write_csv(
        "independent_H1_results_v1.csv",
        h1_rows,
        ["metric", "value", "ci_lower", "ci_upper", "eligible_incidents", "status", "decision", "notes"],
    )

    paired_fields = [
        "comparison",
        "delta_macro_f1",
        "ci_lower",
        "ci_upper",
        "top1_difference",
        "top2_difference",
        "mrr_difference",
        "status",
        "decision",
        "notes",
    ]
    write_csv(
        "independent_H2_paired_results_v1.csv",
        [
            {
                "comparison": "Behavioral-only vs Behavioral+CAIDA+RPKI/ROV",
                "delta_macro_f1": "NA",
                "ci_lower": "NA",
                "ci_upper": "NA",
                "top1_difference": "NA",
                "top2_difference": "NA",
                "mrr_difference": "NA",
                "status": "NOT_EXECUTED_PROTOCOL_GATE_STOP",
                "decision": "INCONCLUSIVE",
                "notes": "H2 requires the same eligible independent incidents as H1; no confirmation roster was constructed.",
            }
        ],
        paired_fields,
    )
    write_csv(
        "independent_H3_paired_results_v1.csv",
        [
            {
                "comparison": "Mean aggregation vs RETROSPECTIVE temporal stacker",
                "delta_macro_f1": "NA",
                "ci_lower": "NA",
                "ci_upper": "NA",
                "top1_difference": "NA",
                "top2_difference": "NA",
                "mrr_difference": "NA",
                "status": "NOT_EXECUTED_PROTOCOL_GATE_STOP",
                "decision": "INCONCLUSIVE",
                "notes": "H3 requires the same eligible independent incidents as H1; no confirmation roster was constructed.",
            }
        ],
        paired_fields,
    )

    write_csv(
        "independent_per_class_metrics_v1.csv",
        [],
        ["class", "precision", "recall", "f1", "support", "status", "notes"],
    )
    write_csv(
        "independent_confusion_matrix_v1.csv",
        [],
        ["true_class", "predicted_hijack", "predicted_leak", "predicted_outage", "status"],
    )
    write_csv(
        "independent_incident_predictions_v1.csv",
        [],
        [
            "confirmation_incident_id",
            "true_class",
            "predicted_class",
            "hijack_probability",
            "leak_probability",
            "outage_probability",
            "top1",
            "top2",
            "true_class_rank",
            "source",
            "status",
        ],
    )
    write_csv(
        "independent_error_analysis_v1.csv",
        [],
        [
            "confirmation_incident_id",
            "true_class",
            "predicted_class",
            "source",
            "confidence_or_ranking_score",
            "true_class_rank",
            "prefix",
            "asn",
            "error_category",
            "limited_routeviews_visibility",
            "ambiguous_across_sources",
        ],
    )
    write_csv(
        "independent_source_specific_results_v1.csv",
        [
            {
                "source": "RouteLLM",
                "eligible_incidents": 0,
                "macro_f1": "NA",
                "top1": "NA",
                "top2": "NA",
                "mrr": "NA",
                "status": "NOT_EXECUTED_SOURCE_ROSTER_UNAVAILABLE",
                "notes": "Primary Hijack/Leak source roster unavailable.",
            },
            {
                "source": "IODA",
                "eligible_incidents": 0,
                "macro_f1": "NA",
                "top1": "NA",
                "top2": "NA",
                "mrr": "NA",
                "status": "NOT_EXECUTED_ALL_CLASS_GATE_STOP",
                "notes": "Outage-only acquisition would violate the locked all-class confirmation design after RouteLLM gate failed.",
            },
        ],
        ["source", "eligible_incidents", "macro_f1", "top1", "top2", "mrr", "status", "notes"],
    )
    write_csv(
        "independent_bootstrap_results_v1.csv",
        [],
        ["hypothesis", "comparison_or_metric", "bootstrap_iterations", "seed", "estimate", "ci_lower", "ci_upper", "status"],
    )

    for table_name, rows, fields in [
        (
            "table_A_independent_confirmation_dataset_composition_v1",
            [
                {
                    "source": "RouteLLM",
                    "role": "Primary Hijack/Leak",
                    "candidate_incidents": "NA",
                    "eligible_incidents": 0,
                    "status": "NOT_ACQUIRED_SOURCE_ROSTER_UNAVAILABLE",
                },
                {
                    "source": "IODA",
                    "role": "Primary Outage",
                    "candidate_incidents": "NA",
                    "eligible_incidents": 0,
                    "status": "NOT_ACQUIRED_ALL_CLASS_GATE_STOP",
                },
            ],
            ["source", "role", "candidate_incidents", "eligible_incidents", "status"],
        ),
        (
            "table_B_final_independent_H1_H2_H3_results_v1",
            [
                {"hypothesis": "H1", "primary_metric": "Incident Macro F1", "estimate": "NA", "ci": "NA", "decision": "INCONCLUSIVE"},
                {"hypothesis": "H2", "primary_metric": "Delta Macro F1", "estimate": "NA", "ci": "NA", "decision": "INCONCLUSIVE"},
                {"hypothesis": "H3", "primary_metric": "Delta Macro F1", "estimate": "NA", "ci": "NA", "decision": "INCONCLUSIVE"},
            ],
            ["hypothesis", "primary_metric", "estimate", "ci", "decision"],
        ),
        (
            "table_C_behavioral_only_vs_combined_feature_comparison_v1",
            [
                {
                    "comparison": "Behavioral-only vs Combined",
                    "delta_macro_f1": "NA",
                    "ci": "NA",
                    "decision": "INCONCLUSIVE",
                }
            ],
            ["comparison", "delta_macro_f1", "ci", "decision"],
        ),
        (
            "table_D_mean_aggregation_vs_retrospective_temporal_stacking_v1",
            [
                {
                    "comparison": "Mean aggregation vs RETROSPECTIVE temporal stacker",
                    "delta_macro_f1": "NA",
                    "ci": "NA",
                    "decision": "INCONCLUSIVE",
                }
            ],
            ["comparison", "delta_macro_f1", "ci", "decision"],
        ),
        (
            "table_E_independent_per_class_performance_v1",
            [],
            ["class", "precision", "recall", "f1", "support"],
        ),
        (
            "table_F_independent_error_analysis_summary_v1",
            [],
            ["error_mode", "count", "percent", "notes"],
        ),
    ]:
        write_csv(f"{table_name}.csv", rows, fields)
        md = ["|" + "|".join(fields) + "|", "|" + "|".join(["---"] * len(fields)) + "|"]
        for row in rows:
            md.append("|" + "|".join(str(row.get(f, "")) for f in fields) + "|")
        write_text(f"{table_name}.md", "\n".join(md))

    summary = f"""
# Independent Validation Execution Summary v1

## Status

`INDEPENDENT_VALIDATION_INCONCLUSIVE`

## Execution Boundary

This run followed the locked pre-evaluation protocol until a required source-availability gate failed. No model scoring was performed. No model was retrained, tuned, calibrated, or modified. No TRAIN, Validation, Final Holdout, TTI, provenance, prior-shift, manuscript, figure, table, or previous experimental artifact was modified.

## Pre-Scoring Checks

- Lock checksum verified: PASS.
- Locked artifact checksum verification: {checksum_matches}/20 MATCH.
- Validation accessed: NO.
- Final Holdout accessed or recomputed: NO.
- Model scoring performed: NO.

## Source Gate Outcome

The locked protocol requires RouteLLM as the primary independent Hijack/Leak source and IODA as the primary independent Outage source.

RouteLLM source-native event records were not available for construction of the confirmation roster:

- No local RouteLLM event roster was found.
- The arXiv paper/source package was inspected for repository/dataset links.
- The paper/source confirms a 232-event benchmark and open-source intent, but no usable event-roster URL was present in the inspected source package.
- Exact GitHub repository searches for the RouteLLM BGP benchmark returned zero matching repositories.

Because RouteLLM is the locked primary Hijack/Leak source, replacing it with MANRS/GRIP/operator writeups would deviate from the lock. Scoring only IODA Outage candidates would also violate the locked all-class H1/H2/H3 confirmation design.

## Result

The evaluation stopped before roster construction, RouteViews reconstruction, feature generation, and model scoring.

## Required Final Questions

1. How many genuinely independent incidents were evaluated? 0.
2. What sources supplied them? None; RouteLLM source-native event roster was unavailable and IODA was not acquired after the all-class gate failed.
3. Was any event duplicated from the existing 1,419-event corpus? No event-level comparison was possible because no accepted candidate roster was constructed.
4. Did all 20 frozen artifacts match the preregistered checksums? Yes, {checksum_matches}/20 matched.
5. Was H1 supported? Inconclusive; not executed.
6. Was H2 supported? Inconclusive; not executed.
7. Was H3 supported? Inconclusive; not executed.
8. What were the paired differences and 95% CIs? Not computed.
9. Which class generalized best? Not evaluated.
10. Which class generalized worst? Not evaluated.
11. What were the dominant error modes? Not evaluated.
12. Did performance materially change relative to the Cloudflare-derived evaluation? Not evaluated.
13. What does this imply about source dependence? No empirical conclusion can be drawn; the independent source roster could not be constructed under the lock.
14. What conclusions remain defensible? The frozen model/artifact lock is intact, and the protocol appropriately prevented a post-hoc source substitution.
15. What claims must be narrowed? Any claim of independent RouteLLM/IODA confirmation must not be made until the source-native event roster is acquired and evaluated under the locked rules.
"""
    write_text("independent_validation_execution_summary_v1.md", summary)

    disposition = """
# Independent Validation Final Disposition v1

Final disposition:

`INDEPENDENT_VALIDATION_INCONCLUSIVE`

Reason:

The required primary Hijack/Leak source, RouteLLM, could not be acquired as a source-native event roster during this execution. The locked protocol does not permit replacing RouteLLM with secondary sources after execution begins, and it does not permit an Outage-only IODA evaluation as the independent confirmation of H1/H2/H3.

No model scoring was performed. The existing Praxis results remain unchanged.
"""
    write_text("independent_validation_final_disposition_v1.md", disposition)

    manifest = {
        "created_utc": now,
        "status": "INDEPENDENT_VALIDATION_INCONCLUSIVE",
        "reason": "SOURCE_NATIVE_ROUTE_LLM_EVENT_ROSTER_UNAVAILABLE",
        "eligible_incidents": 0,
        "model_scoring_performed": False,
        "validation_accessed": False,
        "final_holdout_accessed_or_recomputed": False,
        "locked_artifact_matches": checksum_matches,
        "locked_artifact_total": len(checksum_rows),
        "outputs": [],
    }
    for p in sorted(ROOT.iterdir()):
        if p.is_file() and p.name not in {"independent_validation_result_manifest_v1.json", "independent_validation_result_checksums_v1.csv"}:
            manifest["outputs"].append(p.name)
    (ROOT / "independent_validation_result_manifest_v1.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    checksum_out = []
    for p in sorted(ROOT.iterdir()):
        if p.is_file() and p.name != "independent_validation_result_checksums_v1.csv":
            checksum_out.append({"file": p.name, "sha256": sha256(p)})
    write_csv("independent_validation_result_checksums_v1.csv", checksum_out, ["file", "sha256"])


if __name__ == "__main__":
    main()
