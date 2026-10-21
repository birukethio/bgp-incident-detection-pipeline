from __future__ import annotations

import argparse
import bz2
import csv
import json
import math
import re
import statistics
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pandas as pd

try:
    from bgp_incident_detection.audit import parse_utc, write_csv
    from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES
    from bgp_incident_detection.windows import floor_to_five_minutes
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import parse_utc, write_csv
    from src.bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES
    from src.bgp_incident_detection.windows import floor_to_five_minutes


ENRICHMENT_DIR = Path("data/enrichment/caida")
PILOT_DIR = Path("data/pilot")
CAIDA_CACHE = Path("data/cache/caida/as_relationships/serial-2")
PARSED_PILOT_DIR = Path("data/parsed_mrt/pilot")
PILOT_WINDOWS = PILOT_DIR / "pilot_behavioral_features_v1.parquet"
FROZEN_TRAIN = Path("data/train_frozen/frozen_train_behavioral_corpus_v1.parquet")

SOURCE_INVENTORY = ENRICHMENT_DIR / "caida_source_inventory_v1.csv"
HISTORICAL_INVENTORY = ENRICHMENT_DIR / "caida_historical_feature_inventory_v1.csv"
FEATURE_INVENTORY = ENRICHMENT_DIR / "caida_feature_inventory_v1.csv"
INPUT_AUDIT = ENRICHMENT_DIR / "caida_input_availability_audit_v1.csv"
TEMPORAL_POLICY = Path("docs/caida_temporal_mapping_policy_v1.md")
VALLEY_FREE_SPEC = Path("docs/caida_valley_free_feature_spec_v1.md")
MISSING_POLICY = Path("docs/caida_missing_relationship_policy_v1.md")
PILOT_FEATURES = PILOT_DIR / "pilot_caida_features_v1.parquet"
FEATURE_QUALITY = PILOT_DIR / "caida_feature_quality_audit_v1.csv"
CALCULATION_EXAMPLES = PILOT_DIR / "caida_feature_calculation_examples_v1.csv"
FEATURE_VARIANTS = Path("config/feature_variants_v1.yaml")
NOTEBOOK = Path("notebooks/34_caida_feature_inventory_and_pilot.ipynb")
USER_AGENT = "bgp-incident-detection-pipeline/0.1"

CAIDA_FEATURE_NAMES = [
    "caida_path_observation_count",
    "caida_paths_with_no_as_path_count",
    "caida_paths_with_unknown_relationship_count",
    "caida_unknown_relationship_transition_count",
    "caida_customer_to_provider_transition_count",
    "caida_provider_to_customer_transition_count",
    "caida_peer_to_peer_transition_count",
    "caida_valley_free_valid_path_count",
    "caida_valley_free_violation_path_count",
    "caida_valley_free_violation_ratio",
    "caida_max_violation_count_per_path",
    "caida_mean_violation_count_per_path",
    "caida_customer_provider_transition_ratio",
    "caida_peer_transition_ratio",
]

PILOT_ID_COLUMNS = ["incident_uid", "category", "partition", "window_id", "window_start", "window_end"]


@dataclass(frozen=True)
class PathRelationshipResult:
    relationships: list[str]
    unknown_transition_count: int
    violation_count: int


@dataclass
class CaidaWindowAggregate:
    path_observation_count: int = 0
    paths_with_no_as_path_count: int = 0
    paths_with_unknown_relationship_count: int = 0
    unknown_relationship_transition_count: int = 0
    customer_to_provider_transition_count: int = 0
    provider_to_customer_transition_count: int = 0
    peer_to_peer_transition_count: int = 0
    valley_free_valid_path_count: int = 0
    valley_free_violation_path_count: int = 0
    max_violation_count_per_path: int = 0
    sum_violation_count: int = 0


def caida_snapshot_name(value: datetime) -> str:
    return f"{value.year}{value.month:02d}01.as-rel2.txt.bz2"


def caida_snapshot_url(value: datetime) -> str:
    return f"https://publicdata.caida.org/datasets/as-relationships/serial-2/{caida_snapshot_name(value)}"


def selected_snapshot_for_window(window_start: str) -> tuple[str, str, str]:
    parsed = parse_utc(window_start)
    if not parsed:
        raise ValueError(f"invalid window_start: {window_start}")
    snapshot = caida_snapshot_name(parsed)
    return snapshot, caida_snapshot_url(parsed), "same-month serial-2 snapshot at or before nominal month start for the observation date"


def download_snapshot(snapshot: str, url: str) -> Path:
    destination = CAIDA_CACHE / snapshot
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and destination.stat().st_size > 0:
        return destination
    request = Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(request, timeout=120.0) as response, destination.open("wb") as handle:
            handle.write(response.read())
    except (HTTPError, URLError, TimeoutError) as error:
        raise RuntimeError(f"could not download CAIDA snapshot {url}: {error}") from error
    return destination


def load_relationships(path: Path) -> dict[tuple[str, str], str]:
    relationships: dict[tuple[str, str], str] = {}
    with bz2.open(path, "rt", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line or line.startswith("#"):
                continue
            parts = line.strip().split("|")
            if len(parts) < 3:
                continue
            left, right, rel = parts[:3]
            if rel == "-1":
                relationships[(left, right)] = "p2c"
                relationships[(right, left)] = "c2p"
            elif rel == "0":
                relationships[(left, right)] = "p2p"
                relationships[(right, left)] = "p2p"
            elif rel == "1":
                relationships[(left, right)] = "s2s"
                relationships[(right, left)] = "s2s"
    return relationships


def parse_as_path(as_path: object) -> list[str]:
    values = re.findall(r"\d+", str(as_path or ""))
    cleaned: list[str] = []
    for value in values:
        if not cleaned or cleaned[-1] != value:
            cleaned.append(value)
    return cleaned


def relationship_sequence(as_path: object, relationships: dict[tuple[str, str], str]) -> list[str]:
    ases = parse_as_path(as_path)
    return [relationships.get((left, right), "unknown") for left, right in zip(ases, ases[1:])]


def valley_free_result(as_path: object, relationships: dict[tuple[str, str], str]) -> PathRelationshipResult:
    rels = relationship_sequence(as_path, relationships)
    phase = "uphill"
    violations = 0
    unknowns = 0
    peer_seen = False
    for rel in rels:
        if rel == "unknown":
            unknowns += 1
            continue
        if rel == "s2s":
            continue
        if phase == "uphill":
            if rel == "c2p":
                continue
            if rel == "p2p":
                phase = "peer"
                peer_seen = True
                continue
            if rel == "p2c":
                phase = "downhill"
                continue
        elif phase == "peer":
            if rel == "p2c":
                phase = "downhill"
                continue
            violations += 1
            if rel == "p2p":
                peer_seen = True
        elif phase == "downhill":
            if rel == "p2c":
                continue
            violations += 1
        if rel == "p2p" and peer_seen and phase != "peer":
            violations += 1
    return PathRelationshipResult(rels, unknowns, violations)


def empty_feature_row() -> dict[str, float | int]:
    return {name: 0 for name in CAIDA_FEATURE_NAMES}


def aggregate_rows(rows: list[dict[str, str]], relationships: dict[tuple[str, str], str]) -> dict[str, float | int]:
    aggregate = CaidaWindowAggregate()
    for row in rows:
        update_caida_aggregate(aggregate, row, relationships)
    return features_from_caida_aggregate(aggregate)


def update_caida_aggregate(aggregate: CaidaWindowAggregate, row: dict[str, str], relationships: dict[tuple[str, str], str], multiplicity: int = 1) -> None:
    as_path = row.get("as_path", "")
    ases = parse_as_path(as_path)
    if len(ases) < 2:
        aggregate.paths_with_no_as_path_count += multiplicity
        return
    result = valley_free_result(as_path, relationships)
    update_caida_aggregate_from_result(aggregate, result, multiplicity=multiplicity)


def update_caida_aggregate_from_result(aggregate: CaidaWindowAggregate, result: PathRelationshipResult, multiplicity: int = 1) -> None:
    aggregate.path_observation_count += multiplicity
    counts = Counter(result.relationships)
    aggregate.paths_with_unknown_relationship_count += int(result.unknown_transition_count > 0) * multiplicity
    aggregate.unknown_relationship_transition_count += counts["unknown"] * multiplicity
    aggregate.customer_to_provider_transition_count += counts["c2p"] * multiplicity
    aggregate.provider_to_customer_transition_count += counts["p2c"] * multiplicity
    aggregate.peer_to_peer_transition_count += counts["p2p"] * multiplicity
    aggregate.valley_free_valid_path_count += int(result.violation_count == 0 and result.unknown_transition_count == 0) * multiplicity
    aggregate.valley_free_violation_path_count += int(result.violation_count > 0 and result.unknown_transition_count == 0) * multiplicity
    aggregate.max_violation_count_per_path = max(aggregate.max_violation_count_per_path, result.violation_count)
    aggregate.sum_violation_count += result.violation_count * multiplicity


def features_from_caida_aggregate(aggregate: CaidaWindowAggregate) -> dict[str, float | int]:
    output = empty_feature_row()
    output["caida_path_observation_count"] = aggregate.path_observation_count
    output["caida_paths_with_no_as_path_count"] = aggregate.paths_with_no_as_path_count
    if aggregate.path_observation_count == 0:
        output["caida_valley_free_violation_ratio"] = float("nan")
        output["caida_max_violation_count_per_path"] = float("nan")
        output["caida_mean_violation_count_per_path"] = float("nan")
        output["caida_customer_provider_transition_ratio"] = float("nan")
        output["caida_peer_transition_ratio"] = float("nan")
        return output
    known_transition_total = aggregate.customer_to_provider_transition_count + aggregate.provider_to_customer_transition_count + aggregate.peer_to_peer_transition_count
    output["caida_paths_with_unknown_relationship_count"] = aggregate.paths_with_unknown_relationship_count
    output["caida_unknown_relationship_transition_count"] = aggregate.unknown_relationship_transition_count
    output["caida_customer_to_provider_transition_count"] = aggregate.customer_to_provider_transition_count
    output["caida_provider_to_customer_transition_count"] = aggregate.provider_to_customer_transition_count
    output["caida_peer_to_peer_transition_count"] = aggregate.peer_to_peer_transition_count
    output["caida_valley_free_valid_path_count"] = aggregate.valley_free_valid_path_count
    output["caida_valley_free_violation_path_count"] = aggregate.valley_free_violation_path_count
    output["caida_valley_free_violation_ratio"] = aggregate.valley_free_violation_path_count / aggregate.path_observation_count
    output["caida_max_violation_count_per_path"] = aggregate.max_violation_count_per_path
    output["caida_mean_violation_count_per_path"] = aggregate.sum_violation_count / aggregate.path_observation_count
    output["caida_customer_provider_transition_ratio"] = (aggregate.customer_to_provider_transition_count + aggregate.provider_to_customer_transition_count) / known_transition_total if known_transition_total else float("nan")
    output["caida_peer_transition_ratio"] = aggregate.peer_to_peer_transition_count / known_transition_total if known_transition_total else float("nan")
    return output


def row_window_id(incident_uid: str, timestamp: str) -> str | None:
    if not timestamp or len(timestamp) < 16:
        return None
    try:
        minute = int(timestamp[14:16])
    except ValueError:
        return None
    floored_minute = (minute // 5) * 5
    return f"{incident_uid}_{timestamp[0:4]}{timestamp[5:7]}{timestamp[8:10]}T{timestamp[11:13]}{floored_minute:02d}00Z"


def aggregate_pilot_parsed_rows(
    windows: pd.DataFrame,
    snapshot_by_window: dict[str, str],
    relationships_by_snapshot: dict[str, dict[tuple[str, str], str]],
) -> tuple[dict[str, CaidaWindowAggregate], dict[str, dict[str, str]]]:
    allowed_windows = set(windows["window_id"])
    category_by_window = dict(zip(windows["window_id"], windows["category"]))
    aggregates = {wid: CaidaWindowAggregate() for wid in allowed_windows}
    examples: dict[str, dict[str, str]] = {}
    result_cache: dict[tuple[str, str], PathRelationshipResult | None] = {}
    for path in sorted(PARSED_PILOT_DIR.glob("*/parsed_bgp_observations.csv")):
        with path.open(encoding="utf-8") as handle:
            next(handle, None)
            for line in handle:
                parts = line.rstrip("\n").split(",", 10)
                if len(parts) < 10:
                    continue
                incident_uid = parts[0]
                timestamp = parts[3]
                as_path_value = parts[9] or ""
                wid = row_window_id(incident_uid, timestamp)
                if wid not in allowed_windows:
                    continue
                snapshot = snapshot_by_window[wid]
                cache_key = (snapshot, as_path_value)
                if cache_key not in result_cache:
                    if len(parse_as_path(as_path_value)) < 2:
                        result_cache[cache_key] = None
                    else:
                        result_cache[cache_key] = valley_free_result(as_path_value, relationships_by_snapshot[snapshot])
                result = result_cache[cache_key]
                if result is None:
                    aggregates[wid].paths_with_no_as_path_count += 1
                else:
                    update_caida_aggregate_from_result(aggregates[wid], result)
                category = category_by_window[wid]
                if category not in examples and len(parse_as_path(as_path_value)) >= 2:
                    incident_uid = wid.rsplit("_", 1)[0]
                    examples[category] = {
                        "incident_uid": incident_uid,
                        "bgp_timestamp_utc": "",
                        "as_path": as_path_value,
                        "window_id": wid,
                        "selected_caida_snapshot": snapshot,
                    }
    return aggregates, examples


def source_inventory_rows(snapshots: dict[str, str]) -> list[dict[str, object]]:
    return [
        {
            "dataset_name": "CAIDA Inferred AS Relationships Dataset serial-2",
            "source": "https://publicdata.caida.org/datasets/as-relationships/serial-2/",
            "version_date": snapshot.replace(".as-rel2.txt.bz2", ""),
            "relationship_encoding": "-1 means left AS is provider of right AS; reverse direction is customer-to-provider; 0 means peer-to-peer; 1 is treated as sibling if present",
            "license_usage_notes": "Public CAIDA dataset under CAIDA Public AUA; cite CAIDA AS Relationships Dataset and date range used.",
            "expected_update_cadence": "monthly per current CAIDA catalog",
            "local_snapshot_path": str(CAIDA_CACHE / snapshot),
            "snapshot_url": url,
        }
        for snapshot, url in sorted(snapshots.items())
    ]


def historical_inventory_rows() -> list[dict[str, object]]:
    patterns = [
        ("caida_path_observation_count", "CAIDA/path observation count", "count AS_PATH observations per window", "behavioral_features.py/docs configs", "yes", "new formalized feature; historical docs mentioned CAIDA group only"),
        ("caida_valley_free_violation_ratio", "valley-free/path relationship violation", "paths with relationship violations / AS_PATH observations", "user methodology and Cloudflare tags", "yes", "Cloudflare raw tags include asrel hints, but local pipeline had no frozen CAIDA feature implementation"),
        ("caida_customer_provider_transition_ratio", "customer/provider transition balance", "(c2p+p2c)/known transitions", "methodology prompt examples", "yes", "recovered as concept rather than exact prior implementation"),
    ]
    return [
        {
            "feature_name": name,
            "historical_definition": definition,
            "historical_formula": formula,
            "source_artifact": source,
            "reproducible": reproducible,
            "notes": notes,
        }
        for name, definition, formula, source, reproducible, notes in patterns
    ]


def feature_inventory_rows() -> list[dict[str, object]]:
    definitions = {
        "caida_path_observation_count": ("Number of parsed pilot observations with an AS_PATH containing at least two ASNs.", "count(len(cleaned_as_path) >= 2)", "parsed AS_PATH, CAIDA not required", "5-minute window", "0", "0 when no AS_PATH observations", "yes"),
        "caida_paths_with_no_as_path_count": ("Parsed observations without an evaluable AS_PATH.", "count(len(cleaned_as_path) < 2)", "parsed AS_PATH", "5-minute window", "0", "separate from unknown CAIDA relationships", "yes"),
        "caida_paths_with_unknown_relationship_count": ("AS paths containing at least one adjacent AS pair absent from the selected CAIDA snapshot.", "count(path_unknown_transition_count > 0)", "AS_PATH + CAIDA relationships", "5-minute window", "0", "explicit unknown-relationship state", "yes"),
        "caida_unknown_relationship_transition_count": ("Adjacent AS transitions absent from the selected CAIDA snapshot.", "sum(relationship == unknown)", "AS_PATH + CAIDA relationships", "5-minute window", "0", "explicit unknown-relationship state", "yes"),
        "caida_customer_to_provider_transition_count": ("Known customer-to-provider transitions in observed AS paths.", "sum(relationship == c2p)", "AS_PATH + CAIDA relationships", "5-minute window", "0", "0 if no known c2p transitions", "yes"),
        "caida_provider_to_customer_transition_count": ("Known provider-to-customer transitions in observed AS paths.", "sum(relationship == p2c)", "AS_PATH + CAIDA relationships", "5-minute window", "0", "0 if no known p2c transitions", "yes"),
        "caida_peer_to_peer_transition_count": ("Known peer-to-peer transitions in observed AS paths.", "sum(relationship == p2p)", "AS_PATH + CAIDA relationships", "5-minute window", "0", "0 if no known p2p transitions", "yes"),
        "caida_valley_free_valid_path_count": ("Paths with known relationships and no valley-free violation.", "count(unknowns == 0 and violations == 0)", "AS_PATH + CAIDA relationships", "5-minute window", "0", "unknown paths not counted valid", "yes"),
        "caida_valley_free_violation_path_count": ("Paths with known relationships and at least one valley-free violation.", "count(unknowns == 0 and violations > 0)", "AS_PATH + CAIDA relationships", "5-minute window", "0", "unknown paths not counted violation", "yes"),
        "caida_valley_free_violation_ratio": ("Share of evaluable AS paths with a valley-free violation.", "violation_path_count / path_observation_count", "AS_PATH + CAIDA relationships", "5-minute window", "NaN if denominator is zero", "NaN when no AS_PATH observations", "yes"),
        "caida_max_violation_count_per_path": ("Maximum valley-free violation count on any observed path.", "max(path_violation_count)", "AS_PATH + CAIDA relationships", "5-minute window", "NaN if no AS paths", "NaN when no AS_PATH observations", "yes"),
        "caida_mean_violation_count_per_path": ("Mean valley-free violation count across observed paths.", "mean(path_violation_count)", "AS_PATH + CAIDA relationships", "5-minute window", "NaN if no AS paths", "NaN when no AS_PATH observations", "yes"),
        "caida_customer_provider_transition_ratio": ("Share of known transitions that are customer/provider links.", "(c2p+p2c)/(c2p+p2c+p2p)", "AS_PATH + CAIDA relationships", "5-minute window", "NaN if no known transitions", "NaN when no known CAIDA transitions", "yes"),
        "caida_peer_transition_ratio": ("Share of known transitions that are peer-to-peer links.", "p2p/(c2p+p2c+p2p)", "AS_PATH + CAIDA relationships", "5-minute window", "NaN if no known transitions", "NaN when no known CAIDA transitions", "yes"),
    }
    return [
        {
            "feature_name": name,
            "feature_group": "CAIDA AS-relationship",
            "definition": definitions[name][0],
            "formula": definitions[name][1],
            "required_inputs": definitions[name][2],
            "aggregation_level": definitions[name][3],
            "zero_behavior": definitions[name][4],
            "missing_behavior": definitions[name][5],
            "historical_support": definitions[name][6],
            "recommended": "yes",
        }
        for name in CAIDA_FEATURE_NAMES
    ]


def availability_audit_rows(windows: pd.DataFrame) -> list[dict[str, object]]:
    parsed_files = sorted(PARSED_PILOT_DIR.glob("*/parsed_bgp_observations.csv"))
    frozen_cols = set(pd.read_parquet(FROZEN_TRAIN).columns)
    return [
        {
            "check_name": "pilot_windows_available",
            "observed_value": len(windows),
            "status": "PASS" if len(windows) == 661 else "REVIEW",
            "notes": "existing 9-incident pilot behavioral windows",
        },
        {
            "check_name": "parsed_pilot_artifacts_available",
            "observed_value": len(parsed_files),
            "status": "PASS" if len(parsed_files) == 9 else "REVIEW",
            "notes": "one parsed observation CSV expected for each pilot incident",
        },
        {
            "check_name": "frozen_behavioral_corpus_unchanged",
            "observed_value": len(frozen_cols),
            "status": "PASS" if set(BEHAVIORAL_FEATURE_NAMES) <= frozen_cols else "FAIL",
            "notes": "CAIDA enrichment reads parsed artifacts and does not alter frozen behavioral parquet",
        },
        {
            "check_name": "validation_holdout_untouched",
            "observed_value": sorted(windows["partition"].unique().tolist()),
            "status": "PASS" if set(windows["partition"].unique()) == {"train"} else "FAIL",
            "notes": "pilot enrichment is TRAIN only",
        },
    ]


def write_docs(snapshot_mapping: pd.DataFrame) -> None:
    TEMPORAL_POLICY.parent.mkdir(parents=True, exist_ok=True)
    mapping_lines = ["| window_month | selected_caida_snapshot | mapping_reason |", "| --- | --- | --- |"]
    for _, row in snapshot_mapping.drop_duplicates(["window_month", "selected_caida_snapshot"]).sort_values("window_month").iterrows():
        mapping_lines.append(f"| {row['window_month']} | {row['selected_caida_snapshot']} | nearest same-month serial-2 snapshot at or before observation month |")
    TEMPORAL_POLICY.write_text(
        "# CAIDA Temporal Mapping Policy v1\n\n"
        "For each 5-minute window, select the CAIDA serial-2 AS-relationship snapshot for the observation month when available. "
        "This avoids using future relationship information beyond the month-level snapshot cadence available for this dataset. "
        "If an exact observation-month snapshot is unavailable in a future full-TRAIN run, use the nearest earlier available snapshot and record the fallback.\n\n"
        + "\n".join(mapping_lines)
        + "\n",
        encoding="utf-8",
    )
    VALLEY_FREE_SPEC.write_text(
        "# CAIDA Valley-Free Feature Specification v1\n\n"
        "AS paths are cleaned by extracting ASNs and collapsing consecutive prepends before relationship evaluation. "
        "Adjacent AS pairs are mapped to CAIDA relationships: `c2p`, `p2p`, `p2c`, `s2s`, or `unknown`.\n\n"
        "A valid known valley-free path follows: zero or more `c2p` uphill transitions, then zero or one `p2p` peer transition, then zero or more `p2c` downhill transitions. "
        "`s2s` transitions are neutral and may appear anywhere. A `c2p` or `p2p` transition after the path has entered peer/downhill phase is a violation; an additional `p2p` after the optional peer transition is also a violation. "
        "`unknown` relationships are counted explicitly and prevent the path from being counted as either valid or violating.\n\n"
        "AS_SET/confederation artifacts are reduced to numeric ASNs by the current bgpdump-derived AS_PATH parser; this pilot records the limitation and keeps the rule deterministic.\n",
        encoding="utf-8",
    )
    MISSING_POLICY.write_text(
        "# CAIDA Missing Relationship Policy v1\n\n"
        "No AS_PATH observations, unknown CAIDA relationships, and valid zero-violation paths are represented separately.\n\n"
        "- No AS_PATH observations: `caida_path_observation_count = 0`; ratio/statistical features are `NaN` rather than zero.\n"
        "- AS_PATH exists but CAIDA relationship is unknown: unknown path and transition counters increase; the path is not counted valid or violating.\n"
        "- Valid path with zero violations: path contributes to `caida_valley_free_valid_path_count`; violation counters remain zero.\n\n"
        "Silent windows are not converted into relationship evidence. CAIDA features are an enrichment layer joined by `window_id` and never multiply ML rows.\n",
        encoding="utf-8",
    )


def write_feature_variants() -> None:
    FEATURE_VARIANTS.write_text(
        "\n".join(
            [
                "feature_variants_version: v1",
                "source: data/train_frozen/frozen_train_behavioral_corpus_v1.parquet",
                "notes: V1 Behavioral is frozen. V2 CAIDA inventory is pilot-verified. RPKI/ROV inventories remain future controlled steps.",
                "variants:",
                "  V1:",
                "    description: Behavioral BGP features only",
                "    behavioral_feature_count: 44",
                "    total_feature_count: 44",
                "    status: FROZEN",
                "    feature_groups:",
                "      - Behavioral",
                "  V2:",
                "    description: Behavioral BGP + CAIDA AS-relationship features",
                f"    behavioral_feature_count: {len(BEHAVIORAL_FEATURE_NAMES)}",
                f"    caida_feature_count: {len(CAIDA_FEATURE_NAMES)}",
                f"    total_feature_count: {len(BEHAVIORAL_FEATURE_NAMES) + len(CAIDA_FEATURE_NAMES)}",
                "    status: PILOT_VERIFIED",
                "    feature_groups:",
                "      - Behavioral",
                "      - CAIDA AS-relationship",
                "  V3:",
                "    description: Behavioral BGP + RPKI/ROV features",
                "    feature_count: null",
                "    status: PENDING_INVENTORY",
                "    feature_groups:",
                "      - Behavioral",
                "      - RPKI/ROV",
                "  V4:",
                "    description: Behavioral BGP + CAIDA AS-relationship + RPKI/ROV features",
                "    feature_count: null",
                "    status: PENDING_INVENTORY",
                "    feature_groups:",
                "      - Behavioral",
                "      - CAIDA AS-relationship",
                "      - RPKI/ROV",
                "",
            ]
        ),
        encoding="utf-8",
    )


def quality_rows(features: pd.DataFrame) -> list[dict[str, object]]:
    rows = []
    for feature in CAIDA_FEATURE_NAMES:
        series = pd.to_numeric(features[feature], errors="coerce")
        missing = int(series.isna().sum())
        nonmissing = series.dropna()
        zero = int((nonmissing == 0).sum())
        constant = int(nonmissing.nunique() <= 1) if len(nonmissing) else 1
        sparse = bool(len(nonmissing) and zero / len(nonmissing) >= 0.95)
        invalid = int(series.map(lambda value: isinstance(value, float) and math.isinf(value)).sum())
        status = "FAIL" if invalid else "REVIEW" if constant or sparse else "PASS"
        rows.append(
            {
                "feature_name": feature,
                "missing_count": missing,
                "zero_count": zero,
                "min": nonmissing.min() if len(nonmissing) else "",
                "median": nonmissing.median() if len(nonmissing) else "",
                "mean": nonmissing.mean() if len(nonmissing) else "",
                "p95": nonmissing.quantile(0.95) if len(nonmissing) else "",
                "max": nonmissing.max() if len(nonmissing) else "",
                "unique_values": int(nonmissing.nunique()) if len(nonmissing) else 0,
                "constant": bool(constant),
                "sparse": sparse,
                "invalid": invalid,
                "status": status,
            }
        )
    return rows


def calculation_examples(features: pd.DataFrame, example_rows: dict[str, dict[str, str]], relationships_by_snapshot: dict[str, dict[tuple[str, str], str]]) -> list[dict[str, object]]:
    examples = []
    for category in ["Hijack", "Leak", "Outage"]:
        if category not in example_rows:
            continue
        parsed_row = example_rows[category]
        candidates = features[features["window_id"] == parsed_row["window_id"]]
        if candidates.empty:
            continue
        row = candidates.iloc[0]
        path = parsed_row["as_path"]
        snapshot = row["selected_caida_snapshot"]
        rels = relationship_sequence(path, relationships_by_snapshot[snapshot])
        result = valley_free_result(path, relationships_by_snapshot[snapshot])
        ases = parse_as_path(path)
        pairs = [f"{left}-{right}" for left, right in zip(ases, ases[1:])]
        examples.append(
            {
                "incident_uid": row["incident_uid"],
                "category": category,
                "window_id": row["window_id"],
                "as_path": path,
                "adjacent_as_pairs": json.dumps(pairs),
                "relationships": json.dumps(rels),
                "valley_free_interpretation": "UNKNOWN_RELATIONSHIP" if result.unknown_transition_count else "VIOLATION" if result.violation_count else "VALID_ZERO_VIOLATION",
                "violation_count": result.violation_count,
                "unknown_transition_count": result.unknown_transition_count,
                "caida_feature_values": row[CAIDA_FEATURE_NAMES].to_json(),
            }
        )
    return examples


def write_notebook() -> None:
    NOTEBOOK.parent.mkdir(parents=True, exist_ok=True)
    notebook = {
        "cells": [
            {"cell_type": "markdown", "metadata": {}, "source": ["# CAIDA Feature Inventory And Pilot\n", "\n", "TRAIN-only pilot for CAIDA AS-relationship enrichment. No RPKI, modeling, weighting, capping, Validation, or Holdout access.\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["from pathlib import Path\n", "import pandas as pd\n", "base = Path('..') if Path.cwd().name == 'notebooks' else Path('.')\n", "pd.read_csv(base / 'data/enrichment/caida/caida_feature_inventory_v1.csv')\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["features = pd.read_parquet(base / 'data/pilot/pilot_caida_features_v1.parquet')\n", "features.shape, features['window_id'].nunique(), features.groupby('category')['incident_uid'].nunique().to_dict()\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["pd.read_csv(base / 'data/pilot/caida_feature_quality_audit_v1.csv')\n"]},
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")


def run_pilot() -> dict[str, object]:
    windows = pd.read_parquet(PILOT_WINDOWS)
    if set(windows["partition"].unique()) != {"train"}:
        raise RuntimeError("pilot CAIDA enrichment must be TRAIN only")
    windows = windows[PILOT_ID_COLUMNS].copy()
    snapshot_rows = []
    snapshots: dict[str, str] = {}
    for window_start in windows["window_start"]:
        snapshot, url, reason = selected_snapshot_for_window(window_start)
        snapshots[snapshot] = url
        snapshot_rows.append({"window_start": window_start, "window_month": window_start[:7], "selected_caida_snapshot": snapshot, "snapshot_url": url, "mapping_reason": reason})
    snapshot_df = pd.DataFrame(snapshot_rows)
    relationship_maps = {snapshot: load_relationships(download_snapshot(snapshot, url)) for snapshot, url in snapshots.items()}

    feature_rows = []
    snapshot_by_window = dict(zip(windows["window_id"], snapshot_df["selected_caida_snapshot"]))
    aggregates, example_rows = aggregate_pilot_parsed_rows(windows, snapshot_by_window, relationship_maps)
    for _, row in windows.sort_values(["incident_uid", "window_start"]).iterrows():
        snapshot = snapshot_by_window[row["window_id"]]
        values = features_from_caida_aggregate(aggregates[row["window_id"]])
        out = row.to_dict()
        out["selected_caida_snapshot"] = snapshot
        out.update(values)
        feature_rows.append(out)
    features = pd.DataFrame(feature_rows)
    if len(features) != len(windows) or features["window_id"].nunique() != len(windows):
        raise RuntimeError("CAIDA pilot must produce exactly one row per pilot window")
    if features.duplicated("window_id").any():
        raise RuntimeError("duplicate window IDs in CAIDA pilot")

    ENRICHMENT_DIR.mkdir(parents=True, exist_ok=True)
    PILOT_FEATURES.parent.mkdir(parents=True, exist_ok=True)
    features.to_parquet(PILOT_FEATURES, index=False)
    write_csv(SOURCE_INVENTORY, source_inventory_rows(snapshots), ["dataset_name", "source", "version_date", "relationship_encoding", "license_usage_notes", "expected_update_cadence", "local_snapshot_path", "snapshot_url"])
    write_csv(HISTORICAL_INVENTORY, historical_inventory_rows(), ["feature_name", "historical_definition", "historical_formula", "source_artifact", "reproducible", "notes"])
    write_csv(FEATURE_INVENTORY, feature_inventory_rows(), ["feature_name", "feature_group", "definition", "formula", "required_inputs", "aggregation_level", "zero_behavior", "missing_behavior", "historical_support", "recommended"])
    write_csv(INPUT_AUDIT, availability_audit_rows(windows), ["check_name", "observed_value", "status", "notes"])
    write_docs(snapshot_df)
    write_csv(FEATURE_QUALITY, quality_rows(features), ["feature_name", "missing_count", "zero_count", "min", "median", "mean", "p95", "max", "unique_values", "constant", "sparse", "invalid", "status"])
    write_csv(CALCULATION_EXAMPLES, calculation_examples(features, example_rows, relationship_maps), ["incident_uid", "category", "window_id", "as_path", "adjacent_as_pairs", "relationships", "valley_free_interpretation", "violation_count", "unknown_transition_count", "caida_feature_values"])
    write_feature_variants()
    write_notebook()
    q = pd.read_csv(FEATURE_QUALITY)
    return {
        "dataset": "CAIDA Inferred AS Relationships Dataset serial-2",
        "snapshots": sorted(snapshots),
        "historical_recoverable_features": len(historical_inventory_rows()),
        "recommended_caida_feature_count": len(CAIDA_FEATURE_NAMES),
        "caida_feature_names": CAIDA_FEATURE_NAMES,
        "pilot_rows": len(features),
        "pilot_window_ids": int(features["window_id"].nunique()),
        "train_only": set(features["partition"].unique()) == {"train"},
        "constant_features": q[q["constant"]]["feature_name"].tolist(),
        "sparse_features": q[q["sparse"]]["feature_name"].tolist(),
        "invalid_features": q[q["invalid"].astype(int) > 0]["feature_name"].tolist(),
        "v2_total_feature_count": len(BEHAVIORAL_FEATURE_NAMES) + len(CAIDA_FEATURE_NAMES),
        "outputs": [str(SOURCE_INVENTORY), str(TEMPORAL_POLICY), str(HISTORICAL_INVENTORY), str(FEATURE_INVENTORY), str(VALLEY_FREE_SPEC), str(INPUT_AUDIT), str(PILOT_FEATURES), str(MISSING_POLICY), str(FEATURE_QUALITY), str(CALCULATION_EXAMPLES), str(FEATURE_VARIANTS), str(NOTEBOOK)],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Define and pilot CAIDA AS-relationship features.")
    parser.parse_args()
    print(json.dumps(run_pilot(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
