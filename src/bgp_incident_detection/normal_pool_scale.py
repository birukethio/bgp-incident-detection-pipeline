from __future__ import annotations

import argparse
import csv
import json
import math
import subprocess
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    from bgp_incident_detection.audit import parse_listish, parse_utc, write_csv
    from bgp_incident_detection.mrt_acquisition import (
        DEFAULT_COLLECTOR,
        ceil_to_15_minutes,
        floor_to_15_minutes,
        iter_update_slots,
        routeviews_update_url,
    )
    from bgp_incident_detection.normal_baseline import related_incident_overlap, roster_index
    from bgp_incident_detection.normal_candidate_search_v3 import inspect_candidate_on_collector_quick
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import parse_listish, parse_utc, write_csv
    from src.bgp_incident_detection.mrt_acquisition import (
        DEFAULT_COLLECTOR,
        ceil_to_15_minutes,
        floor_to_15_minutes,
        iter_update_slots,
        routeviews_update_url,
    )
    from src.bgp_incident_detection.normal_baseline import related_incident_overlap, roster_index
    from src.bgp_incident_detection.normal_candidate_search_v3 import inspect_candidate_on_collector_quick


ROSTER = Path("data/roster_v2/frozen_incident_roster_v2.csv")
PARTITION_MANIFEST = Path("data/partitions_v2/frozen_partition_manifest_v2.csv")
OUTPUT_DIR = Path("data/normal_scale")
NOTEBOOK = Path("notebooks/19_normal_candidate_pool_scale_design.ipynb")

NORMAL_CANDIDATE_POOL = OUTPUT_DIR / "normal_candidate_pool_v1.csv"
NORMAL_ACQUISITION_ESTIMATE = OUTPUT_DIR / "normal_candidate_acquisition_estimate_v1.csv"
NORMAL_COVERAGE = OUTPUT_DIR / "normal_candidate_coverage_v1.csv"
NORMAL_POLICY = OUTPUT_DIR / "normal_pool_selection_policy_v3.md"
PRIOR_RIB_READY_FILES = (
    Path("data/pilot/normal_update_ready_candidates_v1.csv"),
    Path("data/pilot/normal_additional_replacement_candidates_v1.csv"),
)

ASSOCIATED_PER_CLASS = 20
OFFSETS_DAYS = (-1, 1, -3, 3, -7, 7, -14, 14, -21, 21, -30, 30)
MIN_DURATION_MINUTES = 30
EXCLUSION_BUFFER_MINUTES = 60
CONTEXT_BUFFER_MINUTES = 60
SPLIT_VERSION = "v2"
ROSTER_VERSION = "v2"
UNRESOLVED_CONTROL_UIDS = {"Hijack:97511"}

PRESCREEN_PASS = "RIB_PRESCREEN_PASS"
NO_OBSERVABILITY = "NO_OBSERVABILITY"
KNOWN_INCIDENT_OVERLAP = "KNOWN_INCIDENT_OVERLAP"
INELIGIBLE_DURATION = "INELIGIBLE_DURATION"
ORIGIN_UNSTABLE = "ORIGIN_UNSTABLE"
REVIEW = "REVIEW"


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def parse_required(value: str) -> datetime:
    parsed = parse_utc(value)
    if not parsed:
        raise ValueError(f"invalid UTC timestamp: {value}")
    return parsed


def isoformat_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def first_value(value: str | None) -> str:
    values = parse_listish(value)
    return values[0] if values else ""


def source_provenance(row: dict[str, str]) -> str:
    if row.get("source_url"):
        return row["source_url"]
    if "Cloudflare Radar" in row.get("notes", ""):
        return f"Cloudflare Radar event id {row['incident_id']}"
    return f"source record id {row.get('incident_id', '')}".strip()


def representative_asn(row: dict[str, str]) -> str:
    if row["category"] == "Leak":
        return row.get("primary_asn") or first_value(row.get("affected_asns"))
    if row["category"] == "Hijack":
        return first_value(row.get("affected_asns")) or row.get("primary_asn")
    return row.get("primary_asn") or first_value(row.get("affected_asns"))


def representative_prefix(row: dict[str, str]) -> str:
    return first_value(row.get("affected_prefixes"))


def duration_bucket(duration_minutes: str) -> str:
    try:
        duration = float(duration_minutes)
    except ValueError:
        return "unknown"
    if duration < 30:
        return "short_<30m"
    if duration < 360:
        return "medium_30m_6h"
    if duration < 1440:
        return "long_6h_24h"
    return "extreme_24h_plus"


def load_train_roster() -> list[dict[str, str]]:
    partitions = {row["incident_uid"]: row["partition"] for row in load_csv(PARTITION_MANIFEST)}
    rows: list[dict[str, str]] = []
    for row in load_csv(ROSTER):
        partition = partitions.get(row["incident_uid"], row.get("partition", ""))
        if partition != "train":
            continue
        if row["incident_uid"] in UNRESOLVED_CONTROL_UIDS:
            continue
        enriched = dict(row)
        enriched["partition"] = partition
        rows.append(enriched)
    return rows


def select_associated_networks(rows: list[dict[str, str]], per_class: int = ASSOCIATED_PER_CLASS) -> list[dict[str, str]]:
    selected: list[dict[str, str]] = []
    for category in ("Hijack", "Leak", "Outage"):
        pool = [row for row in rows if row["category"] == category and representative_asn(row)]
        for row in pool:
            start = parse_required(row["start_utc"])
            row["_selection_year"] = str(start.year)
            row["_selection_bucket"] = duration_bucket(row.get("duration_minutes", ""))
            row["_selection_asn"] = representative_asn(row)
            row["_selection_country"] = ",".join(parse_listish(row.get("countries"))[:2])
            row["_selection_prefix_available"] = "True" if representative_prefix(row) else "False"
            try:
                row["_selection_prefix_count"] = str(int(float(row.get("prefix_count") or 0)))
            except ValueError:
                row["_selection_prefix_count"] = "0"

        chosen: list[dict[str, str]] = []
        asn_count: Counter[str] = Counter()
        year_count: Counter[str] = Counter()
        bucket_count: Counter[str] = Counter()
        country_count: Counter[str] = Counter()
        while len(chosen) < per_class and pool:
            best = min(
                pool,
                key=lambda row: (
                    asn_count[row["_selection_asn"]],
                    year_count[row["_selection_year"]],
                    bucket_count[row["_selection_bucket"]],
                    country_count[row["_selection_country"]],
                    -int(row["_selection_prefix_count"]),
                    row["incident_uid"],
                ),
            )
            chosen.append(best)
            pool.remove(best)
            asn_count[best["_selection_asn"]] += 1
            year_count[best["_selection_year"]] += 1
            bucket_count[best["_selection_bucket"]] += 1
            country_count[best["_selection_country"]] += 1
        selected.extend(chosen)
    return selected


def candidate_period_id(row: dict[str, object]) -> str:
    safe_time = str(row["candidate_start"]).replace("-", "").replace(":", "")
    return f"{row['associated_incident_uid'].replace(':', '_')}_offset_{int(row['days_from_incident']):+d}_{safe_time}"


def build_candidate_periods(selected: list[dict[str, str]]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for incident in selected:
        incident_start = parse_required(incident["start_utc"])
        affected_asn = representative_asn(incident)
        affected_prefix = representative_prefix(incident)
        for offset in OFFSETS_DAYS:
            candidate_start = incident_start + timedelta(days=offset)
            candidate_end = candidate_start + timedelta(minutes=MIN_DURATION_MINUTES)
            row: dict[str, object] = {
                "candidate_period_id": "",
                "associated_incident_uid": incident["incident_uid"],
                "associated_category": incident["category"],
                "partition": incident["partition"],
                "affected_asn": affected_asn,
                "affected_prefix": affected_prefix,
                "candidate_start": isoformat_z(candidate_start),
                "candidate_end": isoformat_z(candidate_end),
                "duration_minutes": MIN_DURATION_MINUTES,
                "days_from_incident": offset,
                "collector": DEFAULT_COLLECTOR,
                "rib_visible_before": "False",
                "rib_visible_after": "False",
                "origin_stable": "False",
                "route_presence_stable": "False",
                "known_incident_overlap": "False",
                "prescreen_status": REVIEW,
                "selection_reason": "",
                "rib_before_timestamp": "",
                "rib_after_timestamp": "",
                "prefix_visible_before": "NOT_APPLICABLE" if not affected_prefix else "False",
                "prefix_visible_after": "NOT_APPLICABLE" if not affected_prefix else "False",
                "source_provenance": source_provenance(incident),
                "selection_year": parse_required(incident["start_utc"]).year,
                "selection_duration_bucket": duration_bucket(incident.get("duration_minutes", "")),
                "selection_country": ",".join(parse_listish(incident.get("countries"))[:2]),
            }
            row["candidate_period_id"] = candidate_period_id(row)
            rows.append(row)
    return rows


def prior_rib_prescreened_rows() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for path in PRIOR_RIB_READY_FILES:
        if not path.exists():
            continue
        for row in load_csv(path):
            status = row.get("final_prescreen_status") or row.get("prescreen_status")
            if status not in {"UPDATE_READY", PRESCREEN_PASS}:
                continue
            category = row.get("associated_category") or row.get("category")
            if row.get("associated_incident_uid") in UNRESOLVED_CONTROL_UIDS:
                continue
            start = parse_required(row["candidate_start"])
            end = parse_required(row["candidate_end"])
            duration = int(round((end - start).total_seconds() / 60))
            out: dict[str, object] = {
                "candidate_period_id": row.get("candidate_period_id") or "",
                "associated_incident_uid": row["associated_incident_uid"],
                "associated_category": category,
                "partition": "train",
                "affected_asn": row["affected_asn"],
                "affected_prefix": row.get("affected_prefix", ""),
                "candidate_start": isoformat_z(start),
                "candidate_end": isoformat_z(end),
                "duration_minutes": duration,
                "days_from_incident": row.get("days_from_incident", ""),
                "collector": row.get("collector") or DEFAULT_COLLECTOR,
                "rib_visible_before": row.get("rib_visible_before") or "True",
                "rib_visible_after": row.get("rib_visible_after") or "True",
                "origin_stable": row.get("origin_stable") or "True",
                "route_presence_stable": row.get("route_presence_stable") or "True",
                "known_incident_overlap": "False",
                "prescreen_status": PRESCREEN_PASS,
                "selection_reason": f"carried forward from prior TRAIN-only RIB pre-screen artifact {path}; no UPDATE download in this step",
                "rib_before_timestamp": row.get("rib_before_timestamp", ""),
                "rib_after_timestamp": row.get("rib_after_timestamp", ""),
                "prefix_visible_before": row.get("prefix_visible") or ("NOT_APPLICABLE" if not row.get("affected_prefix") else "True"),
                "prefix_visible_after": row.get("prefix_visible") or ("NOT_APPLICABLE" if not row.get("affected_prefix") else "True"),
                "source_provenance": f"prior RIB pre-screen artifact: {path}",
                "selection_year": start.year,
                "selection_duration_bucket": "prior_rib_prescreened_control",
                "selection_country": "",
            }
            if not out["candidate_period_id"]:
                out["candidate_period_id"] = candidate_period_id(out)
            rows.append(out)
    deduped: dict[str, dict[str, object]] = {}
    for row in rows:
        deduped[str(row["candidate_period_id"])] = row
    return list(deduped.values())


def attach_overlap(rows: list[dict[str, object]], roster_rows: list[dict[str, str]]) -> list[dict[str, object]]:
    known = roster_index(roster_rows)
    output: list[dict[str, object]] = []
    for row in rows:
        start = parse_required(str(row["candidate_start"]))
        end = parse_required(str(row["candidate_end"]))
        direct, direct_ids = related_incident_overlap(
            start,
            end,
            str(row["affected_asn"]),
            str(row["affected_prefix"]),
            known,
            str(row["associated_incident_uid"]),
            buffer_minutes=0,
        )
        buffered, buffer_ids = related_incident_overlap(
            start,
            end,
            str(row["affected_asn"]),
            str(row["affected_prefix"]),
            known,
            str(row["associated_incident_uid"]),
            buffer_minutes=EXCLUSION_BUFFER_MINUTES,
        )
        enriched = dict(row)
        enriched["known_incident_overlap"] = str(direct or buffered)
        enriched["selection_reason"] = (
            f"direct_overlap_ids={json.dumps(direct_ids, separators=(',', ':'))}; "
            f"buffer_overlap_ids={json.dumps(buffer_ids, separators=(',', ':'))}; "
            f"exclusion_buffer_minutes={EXCLUSION_BUFFER_MINUTES}"
        )
        output.append(enriched)
    return output


def strict_rib_status(row: dict[str, object]) -> dict[str, object]:
    if int(row["duration_minutes"]) < MIN_DURATION_MINUTES:
        return update_status(row, INELIGIBLE_DURATION, "candidate duration is below 30 minutes")
    if row["known_incident_overlap"] == "True":
        return update_status(row, KNOWN_INCIDENT_OVERLAP, str(row["selection_reason"]))

    rib_row = {
        "associated_incident_uid": str(row["associated_incident_uid"]),
        "category": str(row["associated_category"]),
        "affected_asn": str(row["affected_asn"]),
        "affected_prefix": str(row["affected_prefix"]),
        "candidate_start": str(row["candidate_start"]),
        "candidate_end": str(row["candidate_end"]),
        "days_from_incident": str(row["days_from_incident"]),
        "known_incident_overlap": str(row["known_incident_overlap"]),
    }
    result = inspect_candidate_on_collector_quick(rib_row, DEFAULT_COLLECTOR)
    enriched = dict(row)
    enriched.update(
        {
            "collector": DEFAULT_COLLECTOR,
            "rib_visible_before": result["asn_visible_before"],
            "rib_visible_after": result["asn_visible_after"],
            "origin_stable": result["origin_stable"],
            "route_presence_stable": result["route_presence_stable"],
            "rib_before_timestamp": result["rib_before_timestamp"],
            "rib_after_timestamp": result["rib_after_timestamp"],
            "prefix_visible_before": result["prefix_visible_before"],
            "prefix_visible_after": result["prefix_visible_after"],
        }
    )

    route_stable = result["route_presence_stable"] == "True"
    origin_stable = result["origin_stable"] == "True"
    visible = result["asn_visible_before"] == "True" and result["asn_visible_after"] == "True"
    if visible and route_stable and origin_stable:
        return update_status(
            enriched,
            PRESCREEN_PASS,
            "route-views2 RIB before/after confirms ASN visibility, route presence stability, and stable origin; UPDATE dry-run only",
        )
    if visible and route_stable and not origin_stable:
        return update_status(enriched, ORIGIN_UNSTABLE, "route-views2 RIB visible before/after but expected origin is not stable")
    if result["rib_visibility_status"] == "NO_OBSERVABILITY":
        return update_status(enriched, NO_OBSERVABILITY, "route-views2 RIB did not show adequate before/after observability")
    return update_status(enriched, REVIEW, "route-views2 quick RIB inspection requires manual review or targeted alternate collector evaluation")


def update_status(row: dict[str, object], status: str, reason: str) -> dict[str, object]:
    output = dict(row)
    output["prescreen_status"] = status
    output["selection_reason"] = reason
    return output


def run_prescreen(
    rows: list[dict[str, object]],
    max_rib_evaluations_per_associated: int,
) -> list[dict[str, object]]:
    evaluated_counts: Counter[str] = Counter()
    accepted_counts: Counter[str] = Counter()
    output: list[dict[str, object]] = []
    for row in rows:
        uid = str(row["associated_incident_uid"])
        status = None
        if int(row["duration_minutes"]) < MIN_DURATION_MINUTES:
            status = update_status(row, INELIGIBLE_DURATION, "candidate duration is below 30 minutes")
        elif row["known_incident_overlap"] == "True":
            status = update_status(row, KNOWN_INCIDENT_OVERLAP, str(row["selection_reason"]))
        elif evaluated_counts[uid] >= max_rib_evaluations_per_associated:
            status = update_status(
                row,
                REVIEW,
                "not RIB-parsed in controlled scale design after per-associated-network evaluation cap; no UPDATE acquisition planned",
            )
        else:
            status = strict_rib_status(row)
            evaluated_counts[uid] += 1
            if status["prescreen_status"] == PRESCREEN_PASS:
                accepted_counts[uid] += 1
        output.append(status)
    return output


def head_url(url: str, timeout_seconds: float = 12.0) -> tuple[bool, str, int, str]:
    request = Request(url, method="HEAD", headers={"User-Agent": "bgp-incident-detection-pipeline/0.1"})
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            return 200 <= response.status < 400, str(response.status), int(response.headers.get("Content-Length") or 0), "HEAD"
    except HTTPError as error:
        return False, str(error.code), 0, f"HTTPError: {error.reason}"
    except URLError as error:
        return False, "", 0, f"URLError: {error.reason}"


def acquisition_slots(row: dict[str, object]) -> list[datetime]:
    start = parse_required(str(row["candidate_start"])) - timedelta(minutes=CONTEXT_BUFFER_MINUTES)
    end = parse_required(str(row["candidate_end"])) + timedelta(minutes=CONTEXT_BUFFER_MINUTES)
    return iter_update_slots(floor_to_15_minutes(start), ceil_to_15_minutes(end))


def build_acquisition_estimate(rows: list[dict[str, object]], verify_update_heads: bool) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    for row in rows:
        if row["prescreen_status"] != PRESCREEN_PASS:
            continue
        slots = acquisition_slots(row)
        available_count = 0
        total_bytes = 0
        status_codes: Counter[str] = Counter()
        for slot in slots:
            url = routeviews_update_url(slot, str(row["collector"]))
            if verify_update_heads:
                available, status_code, content_length, _ = head_url(url)
                available_count += int(available)
                total_bytes += content_length if available else 0
                status_codes[status_code or "NO_STATUS"] += 1
            else:
                status_codes["NOT_CHECKED"] += 1
        output.append(
            {
                "candidate_period_id": row["candidate_period_id"],
                "associated_incident_uid": row["associated_incident_uid"],
                "associated_category": row["associated_category"],
                "affected_asn": row["affected_asn"],
                "collector": row["collector"],
                "candidate_start": row["candidate_start"],
                "candidate_end": row["candidate_end"],
                "collection_start": isoformat_z(slots[0]),
                "collection_end": isoformat_z(slots[-1]),
                "required_update_file_count": len(slots),
                "remote_availability_checked": str(verify_update_heads),
                "remote_available_file_count": available_count if verify_update_heads else "",
                "remote_availability_percent": round(100 * available_count / len(slots), 3) if verify_update_heads and slots else "",
                "estimated_compressed_bytes": total_bytes if verify_update_heads else "",
                "estimated_compressed_mib": round(total_bytes / 1024 / 1024, 3) if verify_update_heads else "",
                "expected_5_minute_window_count": math.ceil(float(row["duration_minutes"]) / 5),
                "status_code_counts": json.dumps(dict(status_codes), sort_keys=True),
                "notes": "UPDATE HEAD estimate only; no UPDATE MRT files downloaded",
            }
        )
    return output


def coverage_summary(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    for category in ("Hijack", "Leak", "Outage"):
        cat_rows = [row for row in rows if row["associated_category"] == category]
        status_counts = Counter(str(row["prescreen_status"]) for row in cat_rows)
        output.append(
            {
                "associated_category": category,
                "unique_associated_incidents": len({row["associated_incident_uid"] for row in cat_rows}),
                "unique_asns": len({row["affected_asn"] for row in cat_rows if row["affected_asn"]}),
                "candidate_periods": len(cat_rows),
                "rib_prescreen_pass": status_counts[PRESCREEN_PASS],
                "no_observability": status_counts[NO_OBSERVABILITY],
                "known_overlap": status_counts[KNOWN_INCIDENT_OVERLAP],
                "duration_fail": status_counts[INELIGIBLE_DURATION],
                "origin_unstable": status_counts[ORIGIN_UNSTABLE],
                "review": status_counts[REVIEW],
                "notes": "Counts are candidate periods, not NORMAL_VERIFIED labels.",
            }
        )
    return output


def write_policy(path: Path, max_rib_evaluations_per_associated: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                "# Normal Pool Selection Policy V3",
                "",
                "This policy defines a TRAIN-only, pre-acquisition candidate pool for stable BGP Normal controls.",
                "It does not create `NORMAL_VERIFIED` labels and does not download UPDATE MRT files.",
                "",
                "## Invariant Rules",
                "",
                f"- Use only frozen Roster v2 incidents in the TRAIN partition.",
                f"- Preserve the 60-minute known-incident exclusion buffer.",
                f"- Preserve the 30-minute sustained-stability requirement.",
                "- Use the same ASN/network as the associated incident; use the same prefix when a reliable prefix exists.",
                "- Reject candidate periods that overlap known Hijack, Leak, or Outage incidents involving the same ASN or prefix.",
                "- Require positive RIB visibility before UPDATE acquisition planning.",
                "- Require stable expected origin evidence in before/after RIBs.",
                "- Choose collectors from observability evidence, starting with `route-views2`.",
                "- Treat UNKNOWN or REVIEW periods as unlabeled, not Normal.",
                "- Do not require one matched Normal control for every incident.",
                "",
                "## Controlled Scale Design",
                "",
                "- Select approximately 20 Hijack-associated, 20 Leak-associated, and 20 Outage-associated TRAIN networks.",
                "- Generate offset candidates at -1, +1, -3, +3, -7, +7, -14, +14, -21, +21, -30, and +30 days.",
                f"- RIB parsing in this design pass is capped at {max_rib_evaluations_per_associated} evaluated candidates per associated incident/network.",
                "- Candidates beyond the cap remain REVIEW until a later expansion run evaluates them.",
                "",
                "## Leak-Specific Additions",
                "",
                "- Leak controls require leak ASN/network RIB visibility before and after the candidate period.",
                "- Leak controls require stable origin evidence even when exact affected prefix lists are unavailable.",
                "- Prefixes must not be invented. When no source prefix exists, the candidate is evaluated using ASN/path-origin evidence.",
                "- Obvious prefix deaggregation or path instability detected later in UPDATE behavior keeps a window UNKNOWN.",
                "",
                "## Diversity And Dominance",
                "",
                "- Candidate selection preserves year, ASN/network, country, duration, prefix count, and visibility diversity where possible.",
                "- A configurable maximum accepted-candidate count per ASN/network should be set after reviewing this scale-design distribution.",
                "- The maximum is intentionally not frozen in v3.",
                "",
                "## Matched-Control Exceptions",
                "",
                "- `Hijack:97511` remains `NORMAL_CONTROL_OBSERVABILITY_UNRESOLVED` and is not forced into the candidate pool.",
                "",
                "## Methodological Meaning",
                "",
                "A future Normal label must be positive evidence of stable route state, not simply absence of a known incident.",
                "RIB state establishes that the route existed and the expected origin was stable; UPDATE behavior is later used to reject suspicious instability.",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def write_notebook(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    notebook = {
        "cells": [
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": [
                    "# Normal Candidate Pool Scale Design\n",
                    "\n",
                    "Controlled TRAIN-only expansion of candidate Normal periods using RIB pre-screening. This notebook does not download UPDATE MRT files and does not create Normal labels.\n",
                ],
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": [
                    "from pathlib import Path\n",
                    "import pandas as pd\n",
                    "from bgp_incident_detection.normal_pool_scale import run\n",
                    "\n",
                    "summary = run(max_rib_evaluations_per_associated=0, verify_update_heads=True)\n",
                    "summary\n",
                ],
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": [
                    "pool = pd.read_csv('data/normal_scale/normal_candidate_pool_v1.csv')\n",
                    "coverage = pd.read_csv('data/normal_scale/normal_candidate_coverage_v1.csv')\n",
                    "estimate = pd.read_csv('data/normal_scale/normal_candidate_acquisition_estimate_v1.csv')\n",
                    "display(coverage)\n",
                    "display(pool.groupby(['associated_category', 'prescreen_status']).size().unstack(fill_value=0))\n",
                    "display(estimate.head())\n",
                ],
            },
        ],
        "metadata": {
            "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
            "language_info": {"name": "python", "pygments_lexer": "ipython3"},
        },
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    path.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")


POOL_FIELDS = [
    "candidate_period_id",
    "associated_incident_uid",
    "associated_category",
    "partition",
    "affected_asn",
    "affected_prefix",
    "candidate_start",
    "candidate_end",
    "duration_minutes",
    "days_from_incident",
    "collector",
    "rib_visible_before",
    "rib_visible_after",
    "origin_stable",
    "route_presence_stable",
    "known_incident_overlap",
    "prescreen_status",
    "selection_reason",
    "rib_before_timestamp",
    "rib_after_timestamp",
    "prefix_visible_before",
    "prefix_visible_after",
    "source_provenance",
    "selection_year",
    "selection_duration_bucket",
    "selection_country",
]

ESTIMATE_FIELDS = [
    "candidate_period_id",
    "associated_incident_uid",
    "associated_category",
    "affected_asn",
    "collector",
    "candidate_start",
    "candidate_end",
    "collection_start",
    "collection_end",
    "required_update_file_count",
    "remote_availability_checked",
    "remote_available_file_count",
    "remote_availability_percent",
    "estimated_compressed_bytes",
    "estimated_compressed_mib",
    "expected_5_minute_window_count",
    "status_code_counts",
    "notes",
]

COVERAGE_FIELDS = [
    "associated_category",
    "unique_associated_incidents",
    "unique_asns",
    "candidate_periods",
    "rib_prescreen_pass",
    "no_observability",
    "known_overlap",
    "duration_fail",
    "origin_unstable",
    "review",
    "notes",
]


def run(
    max_rib_evaluations_per_associated: int = 0,
    verify_update_heads: bool = True,
) -> dict[str, object]:
    train_rows = load_train_roster()
    selected = select_associated_networks(train_rows)
    candidates = build_candidate_periods(selected)
    candidates = attach_overlap(candidates, load_csv(ROSTER))
    pool = run_prescreen(candidates, max_rib_evaluations_per_associated)
    existing_ids = {str(row["candidate_period_id"]) for row in pool}
    for prior in prior_rib_prescreened_rows():
        if str(prior["candidate_period_id"]) not in existing_ids:
            pool.append(prior)
            existing_ids.add(str(prior["candidate_period_id"]))
    estimates = build_acquisition_estimate(pool, verify_update_heads)
    coverage = coverage_summary(pool)
    write_csv(NORMAL_CANDIDATE_POOL, pool, POOL_FIELDS)
    write_csv(NORMAL_ACQUISITION_ESTIMATE, estimates, ESTIMATE_FIELDS)
    write_csv(NORMAL_COVERAGE, coverage, COVERAGE_FIELDS)
    write_policy(NORMAL_POLICY, max_rib_evaluations_per_associated)
    write_notebook(NOTEBOOK)

    status_counts = Counter(str(row["prescreen_status"]) for row in pool)
    pass_by_category = Counter(str(row["associated_category"]) for row in pool if row["prescreen_status"] == PRESCREEN_PASS)
    asn_counts = Counter(str(row["affected_asn"]) for row in pool if row["prescreen_status"] == PRESCREEN_PASS)
    total_update_files = sum(int(row["required_update_file_count"]) for row in estimates)
    total_windows = sum(int(row["expected_5_minute_window_count"]) for row in estimates)
    return {
        "associated_train_networks_selected": len({row["incident_uid"] for row in selected}),
        "candidate_periods_generated": len(pool),
        "rib_prescreen_pass": status_counts[PRESCREEN_PASS],
        "prescreen_status_counts": dict(status_counts),
        "rib_prescreen_pass_by_associated_class": dict(pass_by_category),
        "unique_asns_in_pool": len({str(row["affected_asn"]) for row in pool if row["affected_asn"]}),
        "unique_asns_rib_pass": len(asn_counts),
        "top_pass_asns": asn_counts.most_common(10),
        "estimated_update_files_for_rib_pass": total_update_files,
        "estimated_5_minute_windows_for_rib_pass": total_windows,
        "verify_update_heads": verify_update_heads,
        "policy_minutes": {
            "minimum_duration": MIN_DURATION_MINUTES,
            "exclusion_buffer": EXCLUSION_BUFFER_MINUTES,
            "context_buffer": CONTEXT_BUFFER_MINUTES,
        },
        "outputs": [
            str(NORMAL_CANDIDATE_POOL),
            str(NORMAL_ACQUISITION_ESTIMATE),
            str(NORMAL_COVERAGE),
            str(NORMAL_POLICY),
            str(NOTEBOOK),
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build TRAIN-only scaled Normal candidate pool with RIB pre-screening")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--max-rib-evaluations-per-associated", type=int, default=0)
    parser.add_argument("--skip-update-heads", action="store_true")
    args = parser.parse_args()
    if not args.run:
        parser.error("choose --run")
    summary = run(
        max_rib_evaluations_per_associated=args.max_rib_evaluations_per_associated,
        verify_update_heads=not args.skip_update_heads,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
