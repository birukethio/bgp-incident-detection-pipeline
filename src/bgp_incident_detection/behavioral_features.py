from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from statistics import mean, median, pstdev
from typing import Iterable

import pandas as pd

try:
    from bgp_incident_detection.audit import parse_utc, write_csv
    from bgp_incident_detection.mrt_parser import (
        PARSED_FIELDS,
        load_csv,
        match_relevance_prepared,
        parse_as_path,
        parse_as_path_set,
        prepare_relevance_metadata,
    )
    from bgp_incident_detection.windows import floor_to_five_minutes, format_utc, parsed_output_path, window_id
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import parse_utc, write_csv
    from src.bgp_incident_detection.mrt_parser import (
        PARSED_FIELDS,
        load_csv,
        match_relevance_prepared,
        parse_as_path,
        parse_as_path_set,
        prepare_relevance_metadata,
    )
    from src.bgp_incident_detection.windows import floor_to_five_minutes, format_utc, parsed_output_path, window_id


PILOT_DIR = Path("data/pilot")
CONFIG_DIR = Path("config")
WINDOW_COUNTS = PILOT_DIR / "five_minute_window_observation_counts_v1.csv"
PILOT_MANIFEST = PILOT_DIR / "mrt_pilot_incidents_v1.csv"
FEATURE_INVENTORY = PILOT_DIR / "behavioral_feature_inventory_v1.csv"
FEATURE_GROUP_SUMMARY = PILOT_DIR / "feature_group_summary_v1.csv"
MISSING_ZERO_POLICY = PILOT_DIR / "behavioral_feature_missing_zero_policy_v1.md"
CALCULATION_EXAMPLES = PILOT_DIR / "behavioral_feature_calculation_examples_v1.csv"
FEATURE_QUALITY_AUDIT = PILOT_DIR / "behavioral_feature_quality_audit_v1.csv"
FEATURE_PARQUET = PILOT_DIR / "pilot_behavioral_features_v1.parquet"
FEATURE_CSV_SUMMARY = PILOT_DIR / "pilot_behavioral_features_v1_summary.csv"
FEATURE_VARIANTS = CONFIG_DIR / "feature_variants_v1.yaml"

METADATA_COLUMNS = [
    "incident_uid",
    "incident_id",
    "category",
    "partition",
    "window_id",
    "window_start",
    "window_end",
    "temporal_status",
]

DIAGNOSTIC_COLUMNS = [
    "raw_observation_count",
    "has_relevant_observation",
]


@dataclass(frozen=True)
class FeatureDefinition:
    name: str
    group: str
    definition: str
    formula: str
    source_fields: str
    aggregation_method: str
    zero_window_behavior: str
    available_in_new_pipeline: str
    historical_source: str
    verification_status: str
    notes: str = ""


BEHAVIORAL_FEATURES: list[FeatureDefinition] = [
    FeatureDefinition("update_count", "Behavioral", "Incident-relevant prefix-level UPDATE observations in the window.", "announcements + withdrawals", "announcement_or_withdrawal", "count", "0", "yes", "locally reproducible from parsed RouteViews/bgpdump fields; no older implementation found", "REPRODUCIBLE"),
    FeatureDefinition("announcement_count", "Behavioral", "Incident-relevant announcement observations.", "count(type == announcement)", "announcement_or_withdrawal", "count", "0", "yes", "locally reproducible from parsed RouteViews/bgpdump fields; no older implementation found", "REPRODUCIBLE"),
    FeatureDefinition("withdrawal_count", "Behavioral", "Incident-relevant withdrawal observations.", "count(type == withdrawal)", "announcement_or_withdrawal", "count", "0", "yes", "locally reproducible from parsed RouteViews/bgpdump fields; no older implementation found", "REPRODUCIBLE"),
    FeatureDefinition("update_rate_per_minute", "Behavioral", "Incident-relevant UPDATE observation rate.", "update_count / 5", "announcement_or_withdrawal", "rate over 5 minutes", "0", "yes", "methodology artifacts call for 5-minute windows and UPDATE activity", "REPRODUCIBLE"),
    FeatureDefinition("announcement_rate_per_minute", "Behavioral", "Announcement observation rate.", "announcement_count / 5", "announcement_or_withdrawal", "rate over 5 minutes", "0", "yes", "methodology artifacts call for 5-minute windows and announcement dynamics", "REPRODUCIBLE"),
    FeatureDefinition("withdrawal_rate_per_minute", "Behavioral", "Withdrawal observation rate.", "withdrawal_count / 5", "announcement_or_withdrawal", "rate over 5 minutes", "0", "yes", "methodology artifacts call for 5-minute windows and withdrawal dynamics", "REPRODUCIBLE"),
    FeatureDefinition("announcement_ratio", "Behavioral", "Share of relevant observations that are announcements.", "announcement_count / update_count", "announcement_or_withdrawal", "ratio", "NaN when update_count=0", "yes", "derived from verified count fields", "REPRODUCIBLE"),
    FeatureDefinition("withdrawal_ratio", "Behavioral", "Share of relevant observations that are withdrawals.", "withdrawal_count / update_count", "announcement_or_withdrawal", "ratio", "NaN when update_count=0", "yes", "derived from verified count fields", "REPRODUCIBLE"),
    FeatureDefinition("announcement_to_withdrawal_ratio", "Behavioral", "Announcement-to-withdrawal balance.", "announcement_count / withdrawal_count", "announcement_or_withdrawal", "ratio", "NaN when withdrawal_count=0", "yes", "derived from verified count fields", "REPRODUCIBLE"),
    FeatureDefinition("unique_prefix_count", "Behavioral", "Distinct prefixes among incident-relevant observations.", "count_distinct(prefix)", "prefix", "distinct count", "0", "yes", "methodology artifacts call for prefix count and prefix dynamics", "REPRODUCIBLE"),
    FeatureDefinition("unique_announced_prefix_count", "Behavioral", "Distinct prefixes announced in relevant observations.", "count_distinct(prefix where type=announcement)", "prefix, announcement_or_withdrawal", "distinct count", "0", "yes", "derived from prefix announcement dynamics", "REPRODUCIBLE"),
    FeatureDefinition("unique_withdrawn_prefix_count", "Behavioral", "Distinct prefixes withdrawn in relevant observations.", "count_distinct(prefix where type=withdrawal)", "prefix, announcement_or_withdrawal", "distinct count", "0", "yes", "derived from prefix withdrawal dynamics", "REPRODUCIBLE"),
    FeatureDefinition("prefix_churn_count", "Behavioral", "Total distinct announced and withdrawn prefix activity.", "unique_announced_prefix_count + unique_withdrawn_prefix_count", "prefix, announcement_or_withdrawal", "derived count", "0", "yes", "derived from prefix dynamics", "REPRODUCIBLE"),
    FeatureDefinition("prefix_with_both_announce_withdraw_count", "Behavioral", "Prefixes both announced and withdrawn in the same window.", "count(prefix in announced_prefixes intersect withdrawn_prefixes)", "prefix, announcement_or_withdrawal", "set intersection", "0", "yes", "derived from prefix dynamics", "REPRODUCIBLE"),
    FeatureDefinition("unique_peer_asn_count", "Behavioral", "Distinct RouteViews peer ASNs seeing relevant observations.", "count_distinct(peer_asn)", "peer_asn", "distinct count", "0", "yes", "methodology artifacts call for peer count", "REPRODUCIBLE"),
    FeatureDefinition("unique_origin_asn_count", "Behavioral", "Distinct origin ASNs in relevant announcements.", "count_distinct(origin_asn)", "origin_asn, as_path", "distinct count", "0", "yes", "methodology artifacts call for origin behavior", "REPRODUCIBLE"),
    FeatureDefinition("origin_diversity_ratio", "Behavioral", "Origin diversity normalized by prefix count.", "unique_origin_asn_count / unique_prefix_count", "origin_asn, prefix", "ratio", "NaN when unique_prefix_count=0", "yes", "derived from origin diversity", "REPRODUCIBLE"),
    FeatureDefinition("moas_prefix_count", "Behavioral", "Prefixes with more than one observed origin ASN in the window.", "count(prefix where distinct origins > 1)", "prefix, origin_asn", "grouped distinct count", "0", "yes", "methodology artifacts mention MOAS-related behavior", "REPRODUCIBLE"),
    FeatureDefinition("moas_prefix_ratio", "Behavioral", "Share of prefixes with multiple origins.", "moas_prefix_count / unique_prefix_count", "prefix, origin_asn", "ratio", "NaN when unique_prefix_count=0", "yes", "derived from MOAS-related behavior", "REPRODUCIBLE"),
    FeatureDefinition("origin_change_event_count", "Behavioral", "Additional origin alternatives beyond one per prefix.", "sum(max(0, origin_count_per_prefix - 1))", "prefix, origin_asn", "grouped count", "0", "yes", "derived from origin changes", "REPRODUCIBLE"),
    FeatureDefinition("unique_as_path_count", "Behavioral", "Distinct AS_PATH strings in relevant announcements.", "count_distinct(as_path)", "as_path", "distinct count", "0", "yes", "methodology artifacts call for AS_PATH behavior", "REPRODUCIBLE"),
    FeatureDefinition("as_path_length_min", "Behavioral", "Minimum AS_PATH length.", "min(len(as_path))", "as_path", "summary statistic", "NaN when no AS_PATH exists", "yes", "methodology artifacts call for AS_PATH length", "REPRODUCIBLE"),
    FeatureDefinition("as_path_length_max", "Behavioral", "Maximum AS_PATH length.", "max(len(as_path))", "as_path", "summary statistic", "NaN when no AS_PATH exists", "yes", "methodology artifacts call for AS_PATH length", "REPRODUCIBLE"),
    FeatureDefinition("as_path_length_mean", "Behavioral", "Mean AS_PATH length.", "mean(len(as_path))", "as_path", "summary statistic", "NaN when no AS_PATH exists", "yes", "methodology artifacts call for AS_PATH length", "REPRODUCIBLE"),
    FeatureDefinition("as_path_length_median", "Behavioral", "Median AS_PATH length.", "median(len(as_path))", "as_path", "summary statistic", "NaN when no AS_PATH exists", "yes", "methodology artifacts call for AS_PATH length", "REPRODUCIBLE"),
    FeatureDefinition("as_path_length_std", "Behavioral", "Population standard deviation of AS_PATH length.", "pstdev(len(as_path))", "as_path", "summary statistic", "NaN when no AS_PATH exists", "yes", "methodology artifacts call for AS_PATH length", "REPRODUCIBLE"),
    FeatureDefinition("as_path_length_p95", "Behavioral", "95th percentile AS_PATH length.", "percentile_95(len(as_path))", "as_path", "summary statistic", "NaN when no AS_PATH exists", "yes", "methodology artifacts call for AS_PATH length", "REPRODUCIBLE"),
    FeatureDefinition("as_path_length_range", "Behavioral", "Range of AS_PATH lengths.", "max(len(as_path)) - min(len(as_path))", "as_path", "summary statistic", "NaN when no AS_PATH exists", "yes", "methodology artifacts call for AS_PATH length", "REPRODUCIBLE"),
    FeatureDefinition("path_prepending_observation_count", "Behavioral", "Relevant announcements whose AS_PATH contains repeated ASNs.", "count(path where len(path) > len(unique(path)))", "as_path", "count", "0", "yes", "methodology artifacts mention path prepending behavior", "REPRODUCIBLE"),
    FeatureDefinition("path_prepending_ratio", "Behavioral", "Share of relevant announcements with path prepending.", "path_prepending_observation_count / announcement_count", "as_path, announcement_or_withdrawal", "ratio", "NaN when announcement_count=0", "yes", "derived from path prepending behavior", "REPRODUCIBLE"),
    FeatureDefinition("prepended_asn_repetition_count", "Behavioral", "Total repeated ASN positions beyond unique ASNs across paths.", "sum(len(path) - len(unique(path)))", "as_path", "sum", "0", "yes", "derived from path prepending behavior", "REPRODUCIBLE"),
    FeatureDefinition("multi_path_prefix_count", "Behavioral", "Prefixes with more than one observed AS_PATH.", "count(prefix where distinct AS_PATHs > 1)", "prefix, as_path", "grouped distinct count", "0", "yes", "methodology artifacts mention AS_PATH changes/instability", "REPRODUCIBLE"),
    FeatureDefinition("path_diversity_mean_per_prefix", "Behavioral", "Average number of distinct AS_PATHs per prefix.", "mean(distinct_as_paths_per_prefix)", "prefix, as_path", "grouped mean", "NaN when no prefix/path exists", "yes", "derived from path diversity", "REPRODUCIBLE"),
    FeatureDefinition("peer_prefix_pair_count", "Behavioral", "Distinct peer ASN and prefix pairs.", "count_distinct(peer_asn, prefix)", "peer_asn, prefix", "distinct pair count", "0", "yes", "derived from peer/prefix visibility", "REPRODUCIBLE"),
    FeatureDefinition("peer_origin_pair_count", "Behavioral", "Distinct peer ASN and origin ASN pairs.", "count_distinct(peer_asn, origin_asn)", "peer_asn, origin_asn", "distinct pair count", "0", "yes", "derived from peer/origin visibility", "REPRODUCIBLE"),
    FeatureDefinition("peer_as_path_pair_count", "Behavioral", "Distinct peer ASN and AS_PATH pairs.", "count_distinct(peer_asn, as_path)", "peer_asn, as_path", "distinct pair count", "0", "yes", "derived from peer/path visibility", "REPRODUCIBLE"),
    FeatureDefinition("unique_next_hop_count", "Behavioral", "Distinct NEXT_HOP values in relevant announcements.", "count_distinct(next_hop)", "next_hop", "distinct count", "0", "yes", "bgpdump field available in parsed RouteViews output", "REPRODUCIBLE"),
    FeatureDefinition("community_observation_count", "Behavioral", "Relevant observations carrying at least one BGP community value.", "count(communities not empty)", "communities", "count", "0", "yes", "bgpdump field available in parsed RouteViews output", "REPRODUCIBLE"),
    FeatureDefinition("community_observation_ratio", "Behavioral", "Share of relevant observations carrying communities.", "community_observation_count / update_count", "communities", "ratio", "NaN when update_count=0", "yes", "bgpdump field available in parsed RouteViews output", "REPRODUCIBLE"),
    FeatureDefinition("unique_community_count", "Behavioral", "Distinct BGP community tokens observed.", "count_distinct(split(communities))", "communities", "distinct count", "0", "yes", "bgpdump field available in parsed RouteViews output", "REPRODUCIBLE"),
    FeatureDefinition("med_observation_count", "Behavioral", "Relevant announcements with MED populated.", "count(med not empty)", "med", "count", "0", "yes", "bgpdump field available in parsed RouteViews output", "REPRODUCIBLE"),
    FeatureDefinition("unique_med_count", "Behavioral", "Distinct MED values observed.", "count_distinct(med)", "med", "distinct count", "0", "yes", "bgpdump field available in parsed RouteViews output", "REPRODUCIBLE"),
    FeatureDefinition("local_pref_observation_count", "Behavioral", "Relevant announcements with LOCAL_PREF populated by parser.", "count(local_pref not empty)", "local_pref", "count", "0", "yes", "bgpdump field available when observable", "REPRODUCIBLE"),
    FeatureDefinition("atomic_aggregate_count", "Behavioral", "Relevant announcements carrying an atomic aggregate marker other than NAG/empty.", "count(atomic_aggregate not empty and != NAG)", "atomic_aggregate", "count", "0", "yes", "bgpdump field available in parsed RouteViews output", "REPRODUCIBLE"),
]

BEHAVIORAL_FEATURE_NAMES = [feature.name for feature in BEHAVIORAL_FEATURES]


@dataclass
class WindowAggregate:
    update_count: int = 0
    announcement_count: int = 0
    withdrawal_count: int = 0
    prefixes: set[str] = field(default_factory=set)
    announced_prefixes: set[str] = field(default_factory=set)
    withdrawn_prefixes: set[str] = field(default_factory=set)
    peer_asns: set[str] = field(default_factory=set)
    origin_asns: set[str] = field(default_factory=set)
    as_paths: set[str] = field(default_factory=set)
    next_hops: set[str] = field(default_factory=set)
    communities: set[str] = field(default_factory=set)
    prefix_origins: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    prefix_paths: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    peer_prefix_pairs: set[tuple[str, str]] = field(default_factory=set)
    peer_origin_pairs: set[tuple[str, str]] = field(default_factory=set)
    peer_path_pairs: set[tuple[str, str]] = field(default_factory=set)
    path_lengths: list[int] = field(default_factory=list)
    path_prepending_observation_count: int = 0
    prepended_asn_repetition_count: int = 0
    community_observation_count: int = 0
    med_observation_count: int = 0
    meds: set[str] = field(default_factory=set)
    local_pref_observation_count: int = 0
    atomic_aggregate_count: int = 0


def safe_ratio(numerator: int | float, denominator: int | float) -> float:
    return float("nan") if denominator == 0 else numerator / denominator


def percentile(values: list[int], q: float) -> float:
    if not values:
        return float("nan")
    ordered = sorted(values)
    position = (len(ordered) - 1) * q
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[int(position)])
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def parse_row(parts: list[str], incident_uid: str) -> dict[str, str] | None:
    if len(parts) != len(PARSED_FIELDS):
        return None
    return {
        "incident_uid": incident_uid,
        "bgp_timestamp_utc": parts[3],
        "peer_asn": parts[5],
        "announcement_or_withdrawal": parts[7],
        "prefix": parts[8],
        "as_path": parts[9],
        "origin_asn": parts[10],
        "next_hop": parts[11],
        "communities": parts[12],
        "med": parts[13],
        "local_pref": parts[14],
        "atomic_aggregate": parts[15],
    }


def update_aggregate(aggregate: WindowAggregate, observation: dict[str, str]) -> None:
    aggregate.update_count += 1
    prefix = observation["prefix"]
    peer_asn = observation["peer_asn"]
    origin_asn = observation["origin_asn"]
    as_path = observation["as_path"]
    obs_type = observation["announcement_or_withdrawal"]
    if obs_type == "announcement":
        aggregate.announcement_count += 1
        if prefix:
            aggregate.announced_prefixes.add(prefix)
    elif obs_type == "withdrawal":
        aggregate.withdrawal_count += 1
        if prefix:
            aggregate.withdrawn_prefixes.add(prefix)
    if prefix:
        aggregate.prefixes.add(prefix)
    if peer_asn:
        aggregate.peer_asns.add(peer_asn)
    if origin_asn:
        aggregate.origin_asns.add(origin_asn)
    if as_path:
        aggregate.as_paths.add(as_path)
        path = parse_as_path(as_path)
        if path:
            aggregate.path_lengths.append(len(path))
            repeated = len(path) - len(set(path))
            if repeated > 0:
                aggregate.path_prepending_observation_count += 1
                aggregate.prepended_asn_repetition_count += repeated
        if prefix:
            aggregate.prefix_paths[prefix].add(as_path)
        if peer_asn:
            aggregate.peer_path_pairs.add((peer_asn, as_path))
    if prefix and origin_asn:
        aggregate.prefix_origins[prefix].add(origin_asn)
    if peer_asn and prefix:
        aggregate.peer_prefix_pairs.add((peer_asn, prefix))
    if peer_asn and origin_asn:
        aggregate.peer_origin_pairs.add((peer_asn, origin_asn))
    if observation["next_hop"]:
        aggregate.next_hops.add(observation["next_hop"])
    communities = [item for item in observation["communities"].split() if item]
    if communities:
        aggregate.community_observation_count += 1
        aggregate.communities.update(communities)
    if observation["med"] != "":
        aggregate.med_observation_count += 1
        aggregate.meds.add(observation["med"])
    if observation["local_pref"] != "":
        aggregate.local_pref_observation_count += 1
    if observation["atomic_aggregate"] and observation["atomic_aggregate"] != "NAG":
        aggregate.atomic_aggregate_count += 1


def features_from_aggregate(aggregate: WindowAggregate) -> dict[str, float | int]:
    path_lengths = aggregate.path_lengths
    unique_prefix_count = len(aggregate.prefixes)
    moas_prefix_count = sum(1 for origins in aggregate.prefix_origins.values() if len(origins) > 1)
    prefix_path_counts = [len(paths) for paths in aggregate.prefix_paths.values()]
    path_min = min(path_lengths) if path_lengths else float("nan")
    path_max = max(path_lengths) if path_lengths else float("nan")
    return {
        "update_count": aggregate.update_count,
        "announcement_count": aggregate.announcement_count,
        "withdrawal_count": aggregate.withdrawal_count,
        "update_rate_per_minute": aggregate.update_count / 5,
        "announcement_rate_per_minute": aggregate.announcement_count / 5,
        "withdrawal_rate_per_minute": aggregate.withdrawal_count / 5,
        "announcement_ratio": safe_ratio(aggregate.announcement_count, aggregate.update_count),
        "withdrawal_ratio": safe_ratio(aggregate.withdrawal_count, aggregate.update_count),
        "announcement_to_withdrawal_ratio": safe_ratio(aggregate.announcement_count, aggregate.withdrawal_count),
        "unique_prefix_count": unique_prefix_count,
        "unique_announced_prefix_count": len(aggregate.announced_prefixes),
        "unique_withdrawn_prefix_count": len(aggregate.withdrawn_prefixes),
        "prefix_churn_count": len(aggregate.announced_prefixes) + len(aggregate.withdrawn_prefixes),
        "prefix_with_both_announce_withdraw_count": len(aggregate.announced_prefixes & aggregate.withdrawn_prefixes),
        "unique_peer_asn_count": len(aggregate.peer_asns),
        "unique_origin_asn_count": len(aggregate.origin_asns),
        "origin_diversity_ratio": safe_ratio(len(aggregate.origin_asns), unique_prefix_count),
        "moas_prefix_count": moas_prefix_count,
        "moas_prefix_ratio": safe_ratio(moas_prefix_count, unique_prefix_count),
        "origin_change_event_count": sum(max(0, len(origins) - 1) for origins in aggregate.prefix_origins.values()),
        "unique_as_path_count": len(aggregate.as_paths),
        "as_path_length_min": path_min,
        "as_path_length_max": path_max,
        "as_path_length_mean": mean(path_lengths) if path_lengths else float("nan"),
        "as_path_length_median": median(path_lengths) if path_lengths else float("nan"),
        "as_path_length_std": pstdev(path_lengths) if len(path_lengths) > 1 else (0 if len(path_lengths) == 1 else float("nan")),
        "as_path_length_p95": percentile(path_lengths, 0.95),
        "as_path_length_range": path_max - path_min if path_lengths else float("nan"),
        "path_prepending_observation_count": aggregate.path_prepending_observation_count,
        "path_prepending_ratio": safe_ratio(aggregate.path_prepending_observation_count, aggregate.announcement_count),
        "prepended_asn_repetition_count": aggregate.prepended_asn_repetition_count,
        "multi_path_prefix_count": sum(1 for paths in aggregate.prefix_paths.values() if len(paths) > 1),
        "path_diversity_mean_per_prefix": mean(prefix_path_counts) if prefix_path_counts else float("nan"),
        "peer_prefix_pair_count": len(aggregate.peer_prefix_pairs),
        "peer_origin_pair_count": len(aggregate.peer_origin_pairs),
        "peer_as_path_pair_count": len(aggregate.peer_path_pairs),
        "unique_next_hop_count": len(aggregate.next_hops),
        "community_observation_count": aggregate.community_observation_count,
        "community_observation_ratio": safe_ratio(aggregate.community_observation_count, aggregate.update_count),
        "unique_community_count": len(aggregate.communities),
        "med_observation_count": aggregate.med_observation_count,
        "unique_med_count": len(aggregate.meds),
        "local_pref_observation_count": aggregate.local_pref_observation_count,
        "atomic_aggregate_count": aggregate.atomic_aggregate_count,
    }


def load_window_metadata() -> dict[tuple[str, str], dict[str, str]]:
    return {
        (row["incident_uid"], row["window_id"]): row
        for row in load_csv(WINDOW_COUNTS)
    }


def incident_id_from_uid(incident_uid: str) -> str:
    return incident_uid.split(":", 1)[1] if ":" in incident_uid else incident_uid


def build_feature_rows(incident_uids: set[str] | None = None) -> list[dict[str, object]]:
    windows = load_window_metadata()
    if incident_uids is not None:
        windows = {key: row for key, row in windows.items() if key[0] in incident_uids}
    incidents = {row["incident_uid"]: row for row in load_csv(PILOT_MANIFEST)}
    if incident_uids is not None:
        incidents = {uid: row for uid, row in incidents.items() if uid in incident_uids}
    relevance_metadata = prepare_relevance_metadata(incidents)
    aggregates: dict[tuple[str, str], WindowAggregate] = {
        key: WindowAggregate()
        for key in windows
    }

    for incident_uid in sorted(incidents):
        path = parsed_output_path(incident_uid)
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.reader(handle)
            header = next(reader)
            if header != PARSED_FIELDS:
                raise ValueError(f"Unexpected parsed schema in {path}")
            for parts in reader:
                observation = parse_row(parts, incident_uid)
                if observation is None:
                    continue
                timestamp = parse_utc(observation["bgp_timestamp_utc"])
                if not timestamp:
                    continue
                start = floor_to_five_minutes(timestamp)
                wid = window_id(incident_uid, start)
                key = (incident_uid, wid)
                if key not in aggregates:
                    continue
                if not match_relevance_prepared(observation, relevance_metadata[incident_uid]):
                    continue
                update_aggregate(aggregates[key], observation)

    rows: list[dict[str, object]] = []
    for key, window in sorted(windows.items(), key=lambda item: (item[1]["incident_uid"], item[1]["window_start"])):
        incident_uid = window["incident_uid"]
        aggregate = aggregates[key]
        row: dict[str, object] = {
            "incident_uid": incident_uid,
            "incident_id": incident_id_from_uid(incident_uid),
            "category": window["category"],
            "partition": window["partition"],
            "window_id": window["window_id"],
            "window_start": window["window_start"],
            "window_end": window["window_end"],
            "temporal_status": window["temporal_status"],
            "raw_observation_count": int(window["raw_observation_count"]),
            "has_relevant_observation": aggregate.update_count > 0,
        }
        row.update(features_from_aggregate(aggregate))
        rows.append(row)
    return rows


def clean_for_csv(value: object) -> object:
    if isinstance(value, float) and math.isnan(value):
        return ""
    return value


def write_feature_inventory() -> None:
    rows = [
        {
            "feature_name": feature.name,
            "feature_group": feature.group,
            "definition": feature.definition,
            "formula": feature.formula,
            "source_fields": feature.source_fields,
            "aggregation_method": feature.aggregation_method,
            "zero_window_behavior": feature.zero_window_behavior,
            "available_in_new_pipeline": feature.available_in_new_pipeline,
            "historical_source": feature.historical_source,
            "verification_status": feature.verification_status,
            "notes": feature.notes,
        }
        for feature in BEHAVIORAL_FEATURES
    ]
    write_csv(
        FEATURE_INVENTORY,
        rows,
        [
            "feature_name",
            "feature_group",
            "definition",
            "formula",
            "source_fields",
            "aggregation_method",
            "zero_window_behavior",
            "available_in_new_pipeline",
            "historical_source",
            "verification_status",
            "notes",
        ],
    )
    group_rows = []
    for group in ["Behavioral", "CAIDA AS-relationship", "RPKI/ROV"]:
        group_features = [row for row in rows if row["feature_group"] == group]
        counts = Counter(row["verification_status"] for row in group_features)
        group_rows.append(
            {
                "feature_group": group,
                "feature_count": len(group_features),
                "verified_count": counts["VERIFIED"],
                "reproducible_count": counts["REPRODUCIBLE"],
                "review_count": counts["REVIEW"],
                "not_reproducible_count": counts["NOT_REPRODUCIBLE"],
            }
        )
    write_csv(
        FEATURE_GROUP_SUMMARY,
        group_rows,
        [
            "feature_group",
            "feature_count",
            "verified_count",
            "reproducible_count",
            "review_count",
            "not_reproducible_count",
        ],
    )


def write_missing_zero_policy() -> None:
    MISSING_ZERO_POLICY.write_text(
        "\n".join(
            [
                "# Behavioral Feature Missing and Zero Policy v1",
                "",
                "Scope: 9-incident TRAIN pilot behavioral BGP features only.",
                "",
                "A zero relevant-observation window is preserved as one ML feature row. It is not dropped and is not labeled Normal.",
                "",
                "Use numeric 0 when zero is semantically valid:",
                "",
                "- count features such as `announcement_count`, `withdrawal_count`, `unique_prefix_count`, and `unique_peer_asn_count`",
                "- rate features whose numerator is a count over the fixed 5-minute window",
                "",
                "Use missing/NaN when the statistic is mathematically undefined:",
                "",
                "- ratios with a zero denominator",
                "- AS_PATH summary statistics when no AS_PATH is present",
                "- per-prefix diversity summaries when no relevant prefix/path exists",
                "",
                "`has_relevant_observation` and `raw_observation_count` are diagnostic fields retained for audit. They are not counted as canonical behavioral features in v1.",
                "",
                "No model imputation is performed in this step.",
                "No `NORMAL` temporal status or Normal label is created in this step.",
                "",
            ]
        ),
        encoding="utf-8",
    )


def write_feature_variants() -> None:
    behavioral_count = len(BEHAVIORAL_FEATURES)
    FEATURE_VARIANTS.parent.mkdir(parents=True, exist_ok=True)
    FEATURE_VARIANTS.write_text(
        "\n".join(
            [
                "feature_variants_version: v1",
                "source: data/pilot/behavioral_feature_inventory_v1.csv",
                "notes: Counts are derived from locally verified/reproducible inventory only; CAIDA and RPKI/ROV enrichments remain future controlled steps.",
                "variants:",
                "  V1:",
                "    description: Behavioral BGP features only",
                f"    feature_count: {behavioral_count}",
                "    feature_groups:",
                "      - Behavioral",
                "  V2:",
                "    description: Behavioral BGP + CAIDA AS-relationship features",
                f"    feature_count: {behavioral_count}",
                "    feature_groups:",
                "      - Behavioral",
                "      - CAIDA AS-relationship",
                "    unresolved_external_feature_count: 0",
                "  V3:",
                "    description: Behavioral BGP + RPKI/ROV features",
                f"    feature_count: {behavioral_count}",
                "    feature_groups:",
                "      - Behavioral",
                "      - RPKI/ROV",
                "    unresolved_external_feature_count: 0",
                "  V4:",
                "    description: Behavioral BGP + CAIDA AS-relationship + RPKI/ROV features",
                f"    feature_count: {behavioral_count}",
                "    feature_groups:",
                "      - Behavioral",
                "      - CAIDA AS-relationship",
                "      - RPKI/ROV",
                "    unresolved_external_feature_count: 0",
                "",
            ]
        ),
        encoding="utf-8",
    )


def numeric_feature_values(rows: list[dict[str, object]], feature: str) -> list[float]:
    values = []
    for row in rows:
        value = row.get(feature)
        if value == "" or value is None:
            continue
        if isinstance(value, float) and math.isnan(value):
            continue
        values.append(float(value))
    return values


def feature_quality_audit(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    output = []
    row_count = len(rows)
    for feature in BEHAVIORAL_FEATURE_NAMES:
        raw_values = [row.get(feature) for row in rows]
        missing_count = sum(
            1
            for value in raw_values
            if value is None or value == "" or (isinstance(value, float) and math.isnan(value))
        )
        invalid_count = sum(
            1
            for value in raw_values
            if isinstance(value, float) and (math.isinf(value))
        )
        values = numeric_feature_values(rows, feature)
        zero_count = sum(1 for value in values if value == 0)
        unique_values = set(values)
        constant = len(unique_values) <= 1 if values else False
        sparse = (zero_count / row_count) >= 0.95 if row_count else False
        notes = []
        status = "PASS"
        if missing_count:
            notes.append("missing values are expected where denominator/statistic is undefined")
        if invalid_count:
            status = "FAIL"
            notes.append("infinite or invalid numeric values detected")
        if constant:
            status = "REVIEW" if status == "PASS" else status
            notes.append("constant feature in pilot")
        if sparse:
            status = "REVIEW" if status == "PASS" else status
            notes.append("extremely sparse in pilot")
        output.append(
            {
                "feature_name": feature,
                "row_count": row_count,
                "missing_count": missing_count,
                "missing_percent": round((missing_count / row_count) * 100, 3) if row_count else 0,
                "zero_count": zero_count,
                "zero_percent": round((zero_count / row_count) * 100, 3) if row_count else 0,
                "minimum": min(values) if values else "",
                "median": median(values) if values else "",
                "mean": mean(values) if values else "",
                "95th_percentile": percentile([int(value) if value.is_integer() else value for value in values], 0.95) if values else "",
                "maximum": max(values) if values else "",
                "unique_value_count": len(unique_values),
                "constant_feature": constant,
                "extremely_sparse": sparse,
                "invalid_value_count": invalid_count,
                "status": status,
                "notes": "; ".join(notes),
            }
        )
    return output


def select_examples(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    def first_match(category: str, status: str, needs_observation: bool | None = None) -> dict[str, object]:
        for row in rows:
            if row["category"] != category or row["temporal_status"] != status:
                continue
            has_obs = int(row["update_count"]) > 0
            if needs_observation is None or has_obs == needs_observation:
                return row
        raise ValueError(f"No example found for {category} {status} {needs_observation}")

    picked = [
        ("Hijack active window with observations", first_match("Hijack", "INCIDENT_ACTIVE", True)),
        ("Leak active window with observations", first_match("Leak", "INCIDENT_ACTIVE", True)),
        ("Outage active window with observations", first_match("Outage", "INCIDENT_ACTIVE", True)),
        ("Outage active window with zero relevant observations", first_match("Outage", "INCIDENT_ACTIVE", False)),
    ]
    fields = [
        "example_type",
        "incident_uid",
        "window_id",
        "window_start",
        "window_end",
        "raw_observation_count",
        "announcement_count",
        "withdrawal_count",
        "unique_prefix_count",
        "unique_peer_asn_count",
        "unique_origin_asn_count",
        "unique_as_path_count",
        "update_rate_per_minute",
        "withdrawal_ratio",
        "as_path_length_mean",
        "moas_prefix_count",
        "path_prepending_ratio",
        "notes",
    ]
    examples = []
    for label, row in picked:
        examples.append(
            {
                field: clean_for_csv(row.get(field, ""))
                for field in fields
                if field != "example_type" and field != "notes"
            }
            | {
                "example_type": label,
                "notes": "one incident-specific 5-minute window maps to one behavioral feature row",
            }
        )
    return [{field: example.get(field, "") for field in fields} for example in examples]


def write_feature_outputs(rows: list[dict[str, object]]) -> None:
    write_feature_inventory()
    write_missing_zero_policy()
    write_feature_variants()
    df = pd.DataFrame(rows)
    ordered_columns = METADATA_COLUMNS + DIAGNOSTIC_COLUMNS + BEHAVIORAL_FEATURE_NAMES
    df = df[ordered_columns]
    df.to_parquet(FEATURE_PARQUET, index=False)
    summary_rows = [
        {
            "metric": "feature_rows",
            "value": len(df),
        },
        {
            "metric": "behavioral_feature_count",
            "value": len(BEHAVIORAL_FEATURES),
        },
        {
            "metric": "zero_relevant_observation_windows",
            "value": int((df["update_count"] == 0).sum()),
        },
        {
            "metric": "outage_incident_active_zero_relevant_windows",
            "value": int(((df["category"] == "Outage") & (df["temporal_status"] == "INCIDENT_ACTIVE") & (df["update_count"] == 0)).sum()),
        },
    ]
    write_csv(FEATURE_CSV_SUMMARY, summary_rows, ["metric", "value"])
    examples = select_examples(rows)
    write_csv(
        CALCULATION_EXAMPLES,
        examples,
        [
            "example_type",
            "incident_uid",
            "window_id",
            "window_start",
            "window_end",
            "raw_observation_count",
            "announcement_count",
            "withdrawal_count",
            "unique_prefix_count",
            "unique_peer_asn_count",
            "unique_origin_asn_count",
            "unique_as_path_count",
            "update_rate_per_minute",
            "withdrawal_ratio",
            "as_path_length_mean",
            "moas_prefix_count",
            "path_prepending_ratio",
            "notes",
        ],
    )
    audit = feature_quality_audit(rows)
    write_csv(
        FEATURE_QUALITY_AUDIT,
        audit,
        [
            "feature_name",
            "row_count",
            "missing_count",
            "missing_percent",
            "zero_count",
            "zero_percent",
            "minimum",
            "median",
            "mean",
            "95th_percentile",
            "maximum",
            "unique_value_count",
            "constant_feature",
            "extremely_sparse",
            "invalid_value_count",
            "status",
            "notes",
        ],
    )


def print_example(rows: list[dict[str, object]]) -> None:
    examples = select_examples(rows)
    print(json.dumps(examples[0], indent=2, default=str))


def print_summary(rows: list[dict[str, object]]) -> None:
    df = pd.DataFrame(rows)
    print(f"feature_rows={len(df)}")
    print(f"behavioral_features={len(BEHAVIORAL_FEATURES)}")
    print(f"partitions={sorted(df['partition'].unique())}")
    print(f"temporal_statuses={sorted(df['temporal_status'].unique())}")
    print(f"zero_relevant_observation_windows={int((df['update_count'] == 0).sum())}")
    print(f"outage_active_zero_relevant_windows={int(((df['category'] == 'Outage') & (df['temporal_status'] == 'INCIDENT_ACTIVE') & (df['update_count'] == 0)).sum())}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract behavioral features for 5-minute TRAIN pilot windows.")
    parser.add_argument("--example-only", action="store_true")
    parser.add_argument("--incident-uid", action="append", default=None)
    args = parser.parse_args()
    incident_uids = set(args.incident_uid) if args.incident_uid else None
    rows = build_feature_rows(incident_uids)
    if args.example_only:
        print_example(rows)
        return
    write_feature_outputs(rows)
    print_summary(rows)


if __name__ == "__main__":
    main()
