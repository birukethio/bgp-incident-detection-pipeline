from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path

try:
    from bgp_incident_detection.audit import asn_set, prefix_set, timestamp_status, write_csv
    from bgp_incident_detection.review_triage import load_csv, parse_listish, source_provenance
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import asn_set, prefix_set, timestamp_status, write_csv
    from src.bgp_incident_detection.review_triage import load_csv, parse_listish, source_provenance


ROSTER_V2_DIR = Path("data/roster_v2")
V2_ROSTER = ROSTER_V2_DIR / "balanced_incident_roster_v2.csv"
LOCAL_LEAK_ARTIFACTS = (
    Path("cloudflare_incidents/raw_leaks_all_available_to_2026-01_cloudflare.json"),
    Path("cloudflare_incidents/raw_leaks_2023-01_to_2026-01.json"),
    Path("cloudflare_incidents/raw_leaks_2026-02_to_2026-08_cloudflare.json"),
)
PREFIX_FIELDS = ("prefixes", "prefix", "affected_prefixes", "origin_prefixes", "nlri", "announcement_prefixes")
LEAK_PREFIX_DISPOSITION = "PASS_NOT_REQUIRED"


def load_v2_rows(path: Path = V2_ROSTER) -> list[dict[str, str]]:
    return load_csv(path)


def leak_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    return [row for row in rows if row["category"] == "Leak"]


def load_local_leak_prefix_index(paths: tuple[Path, ...] = LOCAL_LEAK_ARTIFACTS) -> tuple[dict[str, dict[str, object]], dict[str, object]]:
    prefix_index: dict[str, dict[str, object]] = {}
    inspected: list[dict[str, object]] = []
    for path in paths:
        with path.open(encoding="utf-8") as handle:
            records = json.load(handle)
        field_names = sorted(set().union(*(record.keys() for record in records[:1000]))) if records else []
        prefix_like_fields = [field for field in field_names if "prefix" in field.lower() or field.lower() in {"nlri"}]
        inspected.append(
            {
                "path": str(path),
                "record_count": len(records),
                "field_names_sample": field_names,
                "prefix_like_fields": prefix_like_fields,
            }
        )
        for record in records:
            incident_id = str(record.get("id", ""))
            for field in PREFIX_FIELDS:
                value = record.get(field)
                if value:
                    prefix_index[incident_id] = {"field": field, "value": value, "path": str(path)}
                    break
    return prefix_index, {"artifacts_inspected": inspected}


def leak_prefix_recovery_audit(rows: list[dict[str, str]]) -> tuple[list[dict[str, object]], dict[str, object]]:
    prefix_index, local_search = load_local_leak_prefix_index()
    output: list[dict[str, object]] = []
    for row in leak_rows(rows):
        incident_id = row["incident_id"]
        recovered = prefix_index.get(incident_id)
        existing_prefixes = prefix_set(row)
        exact_available = bool(existing_prefixes or recovered)
        output.append(
            {
                "incident_uid": row["incident_uid"],
                "leak_asn": row.get("primary_asn", ""),
                "prefix_count": row.get("prefix_count", ""),
                "exact_prefixes_available": exact_available,
                "prefix_source": "normalized_roster" if existing_prefixes else (recovered["path"] if recovered else ""),
                "recovery_status": "RECOVERED" if exact_available else "NOT_RECOVERABLE_FROM_LOCAL_CLOUDFLARE_ARTIFACTS",
                "notes": (
                    "exact affected prefix list found"
                    if exact_available
                    else "local Cloudflare leak artifacts expose prefix_count but not exact prefix/NLRI lists"
                ),
            }
        )
    return output, local_search


def write_policy(path: Path) -> None:
    text = """# Leak Event Identification Policy v1

This policy resolves the roster-level Leak prefix question before MRT acquisition. It does not modify Roster v2 and does not extract features.

## Decision

Exact affected prefix lists are not required to freeze the Leak incident roster because the incident can be identified at the event level using:

- verified event time bounds: `min_ts` or `detected_ts` through `max_ts`
- `leak_asn`
- `leak_seg`, the involved AS-path segment
- `origin_count`
- `prefix_count`
- `peer_count`
- countries and Cloudflare source event ID/provenance

The absence of exact prefix lists is an acceptable limitation for roster freezing, not a reason to invent prefixes.

## Incident Identification

For each Leak incident, use Cloudflare event identity and metadata to locate candidate BGP UPDATE evidence:

1. Search only within the incident's reviewed time window.
2. Filter candidate AS paths for the leak ASN and the involved `leak_seg`.
3. Use observed origin/path evidence in RouteViews/RIS updates to identify the leaked announcements.
4. Derive exact prefixes from matching MRT UPDATE NLRI during feature extraction.

## Feature Extraction

Feature extraction may compute prefix-level features from the prefixes observed in matching BGP updates. Those prefixes are derived evidence from MRT data, not original Cloudflare source labels.

## Ground-Truth Labeling

The ground-truth label remains the incident-level Cloudflare Leak event. A 5-minute bin should be labeled Leak only when leak-specific evidence is observed in or near that bin according to the later active-window policy. Long silent gaps remain UNKNOWN, not Leak.

## Guardrails

- Do not invent missing prefixes.
- Do not treat `prefix_count` as a prefix list.
- Do not label every prefix announced by the leak ASN as leaked.
- Keep the continuity/gap threshold parameterized until the MRT observation distribution is inspected.
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def readiness_report(rows: list[dict[str, str]], recovery_rows: list[dict[str, object]], local_search: dict[str, object]) -> list[dict[str, object]]:
    counts = Counter(row["category"] for row in rows)
    prefix_counts = {
        "Hijack": sum(1 for row in rows if row["category"] == "Hijack" and prefix_set(row)),
        "Leak": sum(1 for row in rows if row["category"] == "Leak" and prefix_set(row)),
        "Outage": sum(1 for row in rows if row["category"] == "Outage" and prefix_set(row)),
    }
    timestamp_bad = sum(1 for row in rows if timestamp_status(row)[0] != "PASS")
    asn_missing = sum(1 for row in rows if not asn_set(row))
    provenance_missing = sum(1 for row in rows if not source_provenance(row)["source_provenance_available"])
    leak_recovered = sum(1 for row in recovery_rows if row["exact_prefixes_available"])
    remaining_blockers = []
    if len(rows) != 1419 or any(counts[label] != 473 for label in ("Hijack", "Leak", "Outage")):
        remaining_blockers.append("class_count_or_total_count_failure")
    if timestamp_bad:
        remaining_blockers.append("timestamp_validity_failure")
    if asn_missing:
        remaining_blockers.append("asn_completeness_failure")
    if provenance_missing:
        remaining_blockers.append("provenance_failure")
    recommendation = "FREEZE" if not remaining_blockers and LEAK_PREFIX_DISPOSITION == "PASS_NOT_REQUIRED" else "DO_NOT_FREEZE"
    return [
        {
            "total_incidents": len(rows),
            "hijack_count": counts["Hijack"],
            "leak_count": counts["Leak"],
            "outage_count": counts["Outage"],
            "duplicate_status": "PASS_confirmed_true_duplicates_removed_and_replaced",
            "timestamp_status": "PASS" if timestamp_bad == 0 else "FAIL",
            "asn_completeness": "PASS" if asn_missing == 0 else "FAIL",
            "prefix_completeness_by_class": json.dumps(
                {
                    "Hijack": f"{prefix_counts['Hijack']}/473 required and present",
                    "Leak": f"{prefix_counts['Leak']}/473 exact source prefix lists; prefix_count available for all; exact prefixes to be derived from MRT evidence",
                    "Outage": f"{prefix_counts['Outage']}/473 not required before MRT",
                },
                sort_keys=True,
            ),
            "provenance_status": "PASS" if provenance_missing == 0 else "REVIEW",
            "leak_prefix_disposition": LEAK_PREFIX_DISPOSITION,
            "leak_prefix_recovered_count": leak_recovered,
            "local_artifacts_inspected": json.dumps(local_search["artifacts_inspected"], sort_keys=True),
            "remaining_blockers": ";".join(remaining_blockers) if remaining_blockers else "none",
            "recommendation": recommendation,
        }
    ]


def run_resolution(roster_path: Path = V2_ROSTER, output_dir: Path = ROSTER_V2_DIR) -> dict[str, object]:
    rows = load_v2_rows(roster_path)
    recovery_rows, local_search = leak_prefix_recovery_audit(rows)
    write_csv(
        output_dir / "leak_prefix_recovery_audit.csv",
        recovery_rows,
        ["incident_uid", "leak_asn", "prefix_count", "exact_prefixes_available", "prefix_source", "recovery_status", "notes"],
    )
    write_policy(output_dir / "leak_event_identification_policy_v1.md")
    readiness_rows = readiness_report(rows, recovery_rows, local_search)
    write_csv(
        output_dir / "roster_v2_freeze_readiness.csv",
        readiness_rows,
        [
            "total_incidents",
            "hijack_count",
            "leak_count",
            "outage_count",
            "duplicate_status",
            "timestamp_status",
            "asn_completeness",
            "prefix_completeness_by_class",
            "provenance_status",
            "leak_prefix_disposition",
            "leak_prefix_recovered_count",
            "local_artifacts_inspected",
            "remaining_blockers",
            "recommendation",
        ],
    )
    return {
        "rows": rows,
        "recovery_rows": recovery_rows,
        "readiness_rows": readiness_rows,
        "local_search": local_search,
    }


def print_report(results: dict[str, object]) -> None:
    recovery_counts = Counter(row["recovery_status"] for row in results["recovery_rows"])
    readiness = results["readiness_rows"][0]
    print("Leak prefix readiness resolution complete")
    print(f"Leak prefix recovery: {dict(recovery_counts)}")
    print(f"Leak prefix disposition: {readiness['leak_prefix_disposition']}")
    print(f"Remaining blockers: {readiness['remaining_blockers']}")
    print(f"Recommendation: {readiness['recommendation']}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Resolve Leak prefix readiness for proposed Roster v2.")
    parser.add_argument("--roster", type=Path, default=V2_ROSTER)
    parser.add_argument("--output-dir", type=Path, default=ROSTER_V2_DIR)
    args = parser.parse_args()
    results = run_resolution(args.roster, args.output_dir)
    print_report(results)


if __name__ == "__main__":
    main()
