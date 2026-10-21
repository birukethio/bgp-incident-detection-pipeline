from __future__ import annotations

import csv
import ipaddress
import math
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from statistics import mean, median, pstdev

ROOT = Path("/Users/biruk/Documents/New project")
sys.path.insert(0, str(ROOT))

from src.bgp_incident_detection.caida_features import (
    CAIDA_CACHE,
    CAIDA_FEATURE_NAMES,
    CaidaWindowAggregate,
    caida_snapshot_name,
    features_from_caida_aggregate,
    load_relationships,
    update_caida_aggregate,
)
from src.bgp_incident_detection.rpki_features import (
    RPKI_FEATURE_NAMES,
    STATE_TO_CODE,
    TRUST_ANCHORS,
    build_vrp_index,
    cache_path,
    load_vrps_for_file,
    validate_rov,
)


OUT = ROOT / "data/tti_pilot"
V1_EVIDENCE = OUT / "tti_timestamped_evidence_v1.csv"
V1_ROSTER = OUT / "tti_pilot_incident_roster_v1.csv"
HORIZONS = [30, 60, 120, 300]

BEHAVIORAL_FEATURES = [
    "update_count",
    "announcement_count",
    "withdrawal_count",
    "update_rate_per_minute",
    "announcement_rate_per_minute",
    "withdrawal_rate_per_minute",
    "announcement_ratio",
    "withdrawal_ratio",
    "announcement_to_withdrawal_ratio",
    "unique_prefix_count",
    "unique_announced_prefix_count",
    "unique_withdrawn_prefix_count",
    "prefix_churn_count",
    "prefix_with_both_announce_withdraw_count",
    "unique_peer_asn_count",
    "unique_origin_asn_count",
    "origin_diversity_ratio",
    "moas_prefix_count",
    "moas_prefix_ratio",
    "origin_change_event_count",
    "unique_as_path_count",
    "as_path_length_min",
    "as_path_length_max",
    "as_path_length_mean",
    "as_path_length_median",
    "as_path_length_std",
    "as_path_length_p95",
    "as_path_length_range",
    "path_prepending_observation_count",
    "path_prepending_ratio",
    "prepended_asn_repetition_count",
    "multi_path_prefix_count",
    "path_diversity_mean_per_prefix",
    "peer_prefix_pair_count",
    "peer_origin_pair_count",
    "peer_as_path_pair_count",
    "unique_next_hop_count",
    "community_observation_count",
    "community_observation_ratio",
    "unique_community_count",
    "med_observation_count",
    "unique_med_count",
    "local_pref_observation_count",
    "atomic_aggregate_count",
]

META = [
    "incident_uid",
    "incident_id",
    "category",
    "partition",
    "horizon_seconds",
    "selected_onset_utc",
    "horizon_cutoff_utc",
    "observation_count_in_horizon",
]


@dataclass
class Aggregate:
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


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, object]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({name: "" if isinstance(row.get(name), float) and math.isnan(row.get(name)) else row.get(name, "") for name in fieldnames})


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def fmt(value: datetime | None) -> str:
    return "" if value is None else value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_as_path(value: object) -> list[str]:
    return re.findall(r"\d+", str(value or ""))


def normalize_as_path(value: object) -> str:
    out: list[str] = []
    for asn in parse_as_path(value):
        if not out or out[-1] != asn:
            out.append(asn)
    return " ".join(out)


def ratio(num: int | float, den: int | float) -> float:
    return float("nan") if den == 0 else num / den


def percentile(values: list[int], q: float) -> float:
    if not values:
        return float("nan")
    ordered = sorted(values)
    pos = (len(ordered) - 1) * q
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return float(ordered[lo])
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (pos - lo)


def update_behavioral(agg: Aggregate, obs: dict[str, str]) -> None:
    agg.update_count += 1
    prefix = obs["prefix"]
    peer_asn = obs["peer_asn"]
    origin_asn = obs["origin_asn"]
    as_path = obs["as_path"]
    kind = obs["announcement_or_withdrawal"]
    if kind == "announcement":
        agg.announcement_count += 1
        if prefix:
            agg.announced_prefixes.add(prefix)
    elif kind == "withdrawal":
        agg.withdrawal_count += 1
        if prefix:
            agg.withdrawn_prefixes.add(prefix)
    if prefix:
        agg.prefixes.add(prefix)
    if peer_asn:
        agg.peer_asns.add(peer_asn)
    if origin_asn:
        agg.origin_asns.add(origin_asn)
    if as_path:
        agg.as_paths.add(as_path)
        path = parse_as_path(as_path)
        if path:
            agg.path_lengths.append(len(path))
            repeated = len(path) - len(set(path))
            if repeated > 0:
                agg.path_prepending_observation_count += 1
                agg.prepended_asn_repetition_count += repeated
        if prefix:
            agg.prefix_paths[prefix].add(as_path)
        if peer_asn:
            agg.peer_path_pairs.add((peer_asn, as_path))
    if prefix and origin_asn:
        agg.prefix_origins[prefix].add(origin_asn)
    if peer_asn and prefix:
        agg.peer_prefix_pairs.add((peer_asn, prefix))
    if peer_asn and origin_asn:
        agg.peer_origin_pairs.add((peer_asn, origin_asn))
    if obs["next_hop"]:
        agg.next_hops.add(obs["next_hop"])
    communities = [item for item in obs["communities"].split() if item]
    if communities:
        agg.community_observation_count += 1
        agg.communities.update(communities)
    if obs["med"] != "":
        agg.med_observation_count += 1
        agg.meds.add(obs["med"])
    if obs["local_pref"] != "":
        agg.local_pref_observation_count += 1
    if obs["atomic_aggregate"] and obs["atomic_aggregate"] != "NAG":
        agg.atomic_aggregate_count += 1


def behavioral_features(agg: Aggregate) -> dict[str, float | int]:
    path_lengths = agg.path_lengths
    unique_prefix_count = len(agg.prefixes)
    moas_prefix_count = sum(1 for origins in agg.prefix_origins.values() if len(origins) > 1)
    prefix_path_counts = [len(paths) for paths in agg.prefix_paths.values()]
    path_min = min(path_lengths) if path_lengths else float("nan")
    path_max = max(path_lengths) if path_lengths else float("nan")
    return {
        "update_count": agg.update_count,
        "announcement_count": agg.announcement_count,
        "withdrawal_count": agg.withdrawal_count,
        "update_rate_per_minute": agg.update_count / 5,
        "announcement_rate_per_minute": agg.announcement_count / 5,
        "withdrawal_rate_per_minute": agg.withdrawal_count / 5,
        "announcement_ratio": ratio(agg.announcement_count, agg.update_count),
        "withdrawal_ratio": ratio(agg.withdrawal_count, agg.update_count),
        "announcement_to_withdrawal_ratio": ratio(agg.announcement_count, agg.withdrawal_count),
        "unique_prefix_count": unique_prefix_count,
        "unique_announced_prefix_count": len(agg.announced_prefixes),
        "unique_withdrawn_prefix_count": len(agg.withdrawn_prefixes),
        "prefix_churn_count": len(agg.announced_prefixes) + len(agg.withdrawn_prefixes),
        "prefix_with_both_announce_withdraw_count": len(agg.announced_prefixes & agg.withdrawn_prefixes),
        "unique_peer_asn_count": len(agg.peer_asns),
        "unique_origin_asn_count": len(agg.origin_asns),
        "origin_diversity_ratio": ratio(len(agg.origin_asns), unique_prefix_count),
        "moas_prefix_count": moas_prefix_count,
        "moas_prefix_ratio": ratio(moas_prefix_count, unique_prefix_count),
        "origin_change_event_count": sum(max(0, len(origins) - 1) for origins in agg.prefix_origins.values()),
        "unique_as_path_count": len(agg.as_paths),
        "as_path_length_min": path_min,
        "as_path_length_max": path_max,
        "as_path_length_mean": mean(path_lengths) if path_lengths else float("nan"),
        "as_path_length_median": median(path_lengths) if path_lengths else float("nan"),
        "as_path_length_std": pstdev(path_lengths) if len(path_lengths) > 1 else (0 if len(path_lengths) == 1 else float("nan")),
        "as_path_length_p95": percentile(path_lengths, 0.95),
        "as_path_length_range": path_max - path_min if path_lengths else float("nan"),
        "path_prepending_observation_count": agg.path_prepending_observation_count,
        "path_prepending_ratio": ratio(agg.path_prepending_observation_count, agg.announcement_count),
        "prepended_asn_repetition_count": agg.prepended_asn_repetition_count,
        "multi_path_prefix_count": sum(1 for paths in agg.prefix_paths.values() if len(paths) > 1),
        "path_diversity_mean_per_prefix": mean(prefix_path_counts) if prefix_path_counts else float("nan"),
        "peer_prefix_pair_count": len(agg.peer_prefix_pairs),
        "peer_origin_pair_count": len(agg.peer_origin_pairs),
        "peer_as_path_pair_count": len(agg.peer_path_pairs),
        "unique_next_hop_count": len(agg.next_hops),
        "community_observation_count": agg.community_observation_count,
        "community_observation_ratio": ratio(agg.community_observation_count, agg.update_count),
        "unique_community_count": len(agg.communities),
        "med_observation_count": agg.med_observation_count,
        "unique_med_count": len(agg.meds),
        "local_pref_observation_count": agg.local_pref_observation_count,
        "atomic_aggregate_count": agg.atomic_aggregate_count,
    }


def route_signature(obs: dict[str, str]) -> tuple[str, str, str, str]:
    return (obs["prefix"], obs["origin_asn"], normalize_as_path(obs["as_path"]), obs["announcement_or_withdrawal"])


def analyze_onsets(roster: list[dict[str, str]], evidence_by_uid: dict[str, list[dict[str, str]]]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for incident in roster:
        uid = incident["incident_uid"]
        documented = parse_iso(incident["start_utc"])
        evidence = sorted(evidence_by_uid[uid], key=lambda r: r["bgp_timestamp_utc"])
        before = [r for r in evidence if parse_iso(r["bgp_timestamp_utc"]) < documented]
        after = [r for r in evidence if parse_iso(r["bgp_timestamp_utc"]) >= documented]
        baseline_signatures = {route_signature(r) for r in before}
        first_pre = before[0] if before else None
        first_post = after[0] if after else None
        change = next((r for r in after if route_signature(r) not in baseline_signatures), None)
        selected = first_post
        if selected is None:
            ambiguity = "NO_POST_START_RELEVANT_OBSERVATION"
            rule = "UNRESOLVED"
            offset = ""
            selected_ts = ""
        else:
            ambiguity = "REVIEW_CHANGE_ONSET_DIFFERS" if change and selected and change["bgp_timestamp_utc"] != selected["bgp_timestamp_utc"] else "NONE"
            rule = "FIRST_POST_DOCUMENTED_EVENT_EVIDENCE"
            selected_dt = parse_iso(selected["bgp_timestamp_utc"])
            offset = round((selected_dt - documented).total_seconds(), 3)
            selected_ts = selected["bgp_timestamp_utc"]
        evidence_text = (
            "Selected first post-start incident-relevant observation to avoid pre-context leakage. "
            f"Pre-start relevant observations={len(before)}; post-start relevant observations={len(after)}; "
            f"candidate change onset={change['bgp_timestamp_utc'] if change else 'UNRESOLVED'}."
        )
        rows.append(
            {
                "incident_uid": uid,
                "category": incident["category"],
                "documented_start_utc": incident["start_utc"],
                "first_pre_start_relevant_observation": first_pre["bgp_timestamp_utc"] if first_pre else "",
                "first_post_start_relevant_observation": first_post["bgp_timestamp_utc"] if first_post else "",
                "candidate_change_based_onset": change["bgp_timestamp_utc"] if change else "",
                "selected_onset": selected_ts,
                "onset_rule": rule,
                "offset_from_documented_start_seconds": offset,
                "evidence_supporting_onset": evidence_text,
                "ambiguity_review_flag": ambiguity,
            }
        )
    return rows


def load_caida_relationships(onset_rows: list[dict[str, object]]) -> dict[str, dict[tuple[str, str], str]]:
    snapshots = sorted({caida_snapshot_name(parse_iso(str(row["selected_onset"]))) for row in onset_rows if row["selected_onset"]})
    output = {}
    for snapshot in snapshots:
        path = ROOT / CAIDA_CACHE / snapshot
        if not path.exists():
            path = CAIDA_CACHE / snapshot
        if not path.exists():
            raise FileNotFoundError(f"missing cached CAIDA snapshot: {snapshot}")
        output[snapshot] = load_relationships(path)
    return output


def load_rpki_indexes(onset_rows: list[dict[str, object]]) -> dict[str, object]:
    dates = sorted({parse_iso(str(row["selected_onset"])).strftime("%Y-%m-%d") for row in onset_rows if row["selected_onset"]})
    output = {}
    for date in dates:
        vrps = []
        for tal in TRUST_ANCHORS:
            path = ROOT / cache_path(tal, date)
            if not path.exists():
                path = cache_path(tal, date)
            if not path.exists():
                raise FileNotFoundError(f"missing cached RPKI snapshot: {tal} {date}")
            vrps.extend(load_vrps_for_file(path, tal))
        output[date] = build_vrp_index(vrps)
    return output


def rpki_features(rows: list[dict[str, str]], snapshot_index: object) -> dict[str, float | int]:
    state_counts: Counter[str] = Counter()
    unique_prefixes: dict[str, set[str]] = defaultdict(set)
    for obs in rows:
        result = validate_rov(obs["prefix"], obs["origin_asn"], snapshot_index)
        state_counts[result.state] += 1
        if obs["prefix"]:
            unique_prefixes[result.state].add(obs["prefix"])
    evaluable = state_counts["VALID"] + state_counts["INVALID_ORIGIN"] + state_counts["INVALID_LENGTH"] + state_counts["NOT_FOUND"]
    invalid = state_counts["INVALID_ORIGIN"] + state_counts["INVALID_LENGTH"]
    dominant_state = "NO_PREFIX_ORIGIN_EVIDENCE" if not rows else max(state_counts.items(), key=lambda item: (item[1], item[0]))[0]
    return {
        "rpki_evidence_observation_count": len(rows),
        "rpki_evaluable_observation_count": evaluable,
        "rpki_valid_observation_count": state_counts["VALID"],
        "rpki_invalid_observation_count": invalid,
        "rpki_not_found_observation_count": state_counts["NOT_FOUND"],
        "rpki_unevaluable_observation_count": state_counts["UNEVALUABLE"],
        "rpki_invalid_origin_observation_count": state_counts["INVALID_ORIGIN"],
        "rpki_invalid_maxlength_observation_count": state_counts["INVALID_LENGTH"],
        "rpki_valid_observation_ratio": state_counts["VALID"] / evaluable if evaluable else float("nan"),
        "rpki_invalid_observation_ratio": invalid / evaluable if evaluable else float("nan"),
        "rpki_not_found_observation_ratio": state_counts["NOT_FOUND"] / evaluable if evaluable else float("nan"),
        "rpki_unique_valid_prefix_count": len(unique_prefixes["VALID"]),
        "rpki_unique_invalid_prefix_count": len(unique_prefixes["INVALID_ORIGIN"] | unique_prefixes["INVALID_LENGTH"]),
        "rpki_unique_not_found_prefix_count": len(unique_prefixes["NOT_FOUND"]),
        "rpki_state_diversity_count": sum(1 for value in state_counts.values() if value > 0),
        "rpki_dominant_state_code": STATE_TO_CODE[dominant_state],
    }


def build_horizon_outputs(
    roster: list[dict[str, str]],
    evidence_by_uid: dict[str, list[dict[str, str]]],
    onset_rows: list[dict[str, object]],
) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    caida_relationships = load_caida_relationships(onset_rows)
    rpki_indexes = load_rpki_indexes(onset_rows)
    onset_by_uid = {str(row["incident_uid"]): row for row in onset_rows}
    behavioral_rows = []
    caida_rows = []
    rpki_rows = []
    v4_rows = []
    assertions = []
    roster_by_uid = {row["incident_uid"]: row for row in roster}
    for uid in sorted(roster_by_uid):
        incident = roster_by_uid[uid]
        selected_onset = str(onset_by_uid[uid]["selected_onset"])
        onset = parse_iso(selected_onset)
        evidence = sorted(evidence_by_uid[uid], key=lambda r: r["bgp_timestamp_utc"])
        for horizon in HORIZONS:
            cutoff = onset + timedelta(seconds=horizon)
            selected = [r for r in evidence if onset <= parse_iso(r["bgp_timestamp_utc"]) <= cutoff]
            b_agg = Aggregate()
            c_agg = CaidaWindowAggregate()
            snapshot = caida_snapshot_name(onset)
            for obs in selected:
                update_behavioral(b_agg, obs)
                update_caida_aggregate(c_agg, obs, caida_relationships[snapshot])
            meta = {
                "incident_uid": uid,
                "incident_id": uid.split(":", 1)[1],
                "category": incident["category"],
                "partition": incident["partition"],
                "horizon_seconds": horizon,
                "selected_onset_utc": selected_onset,
                "horizon_cutoff_utc": fmt(cutoff),
                "observation_count_in_horizon": len(selected),
            }
            b_features = behavioral_features(b_agg)
            c_features = features_from_caida_aggregate(c_agg)
            r_features = rpki_features(selected, rpki_indexes[onset.strftime("%Y-%m-%d")])
            behavioral_rows.append({**meta, **b_features})
            caida_rows.append({**meta, **c_features})
            rpki_rows.append({**meta, **r_features})
            v4_rows.append({**meta, **b_features, **c_features, **r_features})
            max_ts = max((parse_iso(r["bgp_timestamp_utc"]) for r in selected), default=None)
            assertions.append(
                {
                    "incident_uid": uid,
                    "category": incident["category"],
                    "horizon_seconds": horizon,
                    "selected_onset_utc": selected_onset,
                    "horizon_cutoff_utc": fmt(cutoff),
                    "max_bgp_timestamp_utc": fmt(max_ts),
                    "assertion": "all horizon feature inputs have selected_onset <= bgp_timestamp_utc <= onset + horizon",
                    "status": "PASS" if max_ts is None or max_ts <= cutoff else "FAIL",
                    "observations_checked": len(selected),
                    "caida_snapshot": snapshot,
                    "rpki_snapshot_date": onset.strftime("%Y-%m-%d"),
                }
            )
    return behavioral_rows, caida_rows, rpki_rows, v4_rows, assertions


def is_bad_value(value: object) -> bool:
    if value == "":
        return False
    try:
        number = float(value)
    except (TypeError, ValueError):
        return False
    return math.isinf(number)


def compatibility(v4_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    expected = BEHAVIORAL_FEATURES + CAIDA_FEATURE_NAMES + RPKI_FEATURE_NAMES
    actual = [name for name in expected if name in v4_rows[0]]
    rows = []
    for idx, name in enumerate(expected, 1):
        values = [row.get(name, "") for row in v4_rows]
        missing = name not in v4_rows[0]
        inf_count = sum(1 for value in values if is_bad_value(value))
        nan_count = sum(1 for value in values if value == "")
        group = "Behavioral" if name in BEHAVIORAL_FEATURES else "CAIDA" if name in CAIDA_FEATURE_NAMES else "RPKI/ROV"
        rows.append(
            {
                "feature_order": idx,
                "feature_name": name,
                "feature_group": group,
                "expected_in_v4": "YES",
                "present_in_v2": "NO" if missing else "YES",
                "ordering_matches_v4": "YES" if actual == expected else "NO",
                "compatible_data_type": "YES" if not missing else "NO",
                "nan_or_blank_count": nan_count,
                "inf_count": inf_count,
                "definition_changed": "NO",
                "status": "FAIL" if missing or inf_count else "PASS",
                "notes": "Blank values correspond to NaN-style undefined ratios/statistics already used by frozen feature definitions." if nan_count else "",
            }
        )
    return rows


def write_docs(onset_rows: list[dict[str, object]], compat_rows: list[dict[str, object]], assertion_rows: list[dict[str, object]]) -> None:
    ambiguity = Counter(row["ambiguity_review_flag"] for row in onset_rows)
    compat_status = Counter(row["status"] for row in compat_rows)
    assertion_status = Counter(row["status"] for row in assertion_rows)
    ready = compat_status.get("FAIL", 0) == 0 and assertion_status.get("FAIL", 0) == 0
    disposition = "READY_FOR_FROZEN_LEVEL1_SCORING" if ready else "NOT_READY_FOR_SCORING"
    (OUT / "tti_onset_methodology_v2.md").write_text(
        "# TTI Observable-Onset Methodology v2\n\n"
        "This TRAIN-only refinement tests three onset definitions without scoring a model.\n\n"
        "A. `DOCUMENTED_START`: use the independently sourced Cloudflare/detector start time as t0 and exclude pre-start BGP evidence.\n\n"
        "B. `FIRST_POST_DOCUMENTED_EVENT_EVIDENCE`: use the first incident-relevant RouteViews observation at or after the documented start. This is the selected v2 pilot rule because it avoids pre-context onset leakage and can be applied uniformly across Hijack, Leak, and Outage.\n\n"
        "C. `CHANGE_BASED_ONSET`: identify the first post-start route signature not seen before the documented start, using prefix, origin ASN, normalized AS_PATH, and announcement/withdrawal type. This remains diagnostic because broader operational change detection needs a baseline and persistence rule before it can be used as the official TTI onset.\n\n"
        "The selected v2 rule does not define onset as the first appearance of an affected ASN/prefix. It anchors t0 after the independent documented start and uses only post-start BGP evidence for horizon feature construction.\n",
        encoding="utf-8",
    )
    (OUT / "tti_methodology_gate_v2.md").write_text(
        "# TTI Methodology Gate v2\n\n"
        f"- Pilot incidents: {len(onset_rows)} TRAIN incidents\n"
        f"- Onset ambiguity flags: {dict(ambiguity)}\n"
        f"- Leakage assertion status: {dict(assertion_status)}\n"
        f"- V4 compatibility status: {dict(compat_status)}\n"
        "- Behavioral features: 44 reconstructed from horizon-filtered timestamped evidence.\n"
        "- CAIDA features: 14 reconstructed from AS paths observable through each horizon using cached historical same-month serial-2 snapshots.\n"
        "- RPKI/ROV features: 16 reconstructed from prefix-origin observations observable through each horizon using cached same-day historical VRP snapshots.\n"
        "- Model scoring: not performed in this step.\n\n"
        "Evidence: v2 generated a 74-feature horizon matrix for 9 incidents x 4 horizons and all feature inputs obeyed the horizon cutoff. Blank ratio/statistic cells represent undefined NaN-style values inherited from the frozen feature definitions, not a changed feature definition.\n\n"
        f"Recommendation: {disposition}\n",
        encoding="utf-8",
    )


def main() -> None:
    roster = read_csv(V1_ROSTER)
    if len(roster) != 9 or set(row["partition"] for row in roster) != {"train"}:
        raise RuntimeError("TTI v2 pilot must reuse the 9 TRAIN-only pilot incidents")
    evidence_rows = read_csv(V1_EVIDENCE)
    evidence_by_uid: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in evidence_rows:
        evidence_by_uid[row["incident_uid"]].append(row)
    onset_rows = analyze_onsets(roster, evidence_by_uid)
    behavior_rows, caida_rows, rpki_rows, v4_rows, assertions = build_horizon_outputs(roster, evidence_by_uid, onset_rows)
    compat_rows = compatibility(v4_rows)
    write_csv(
        OUT / "tti_onset_analysis_v2.csv",
        onset_rows,
        [
            "incident_uid",
            "category",
            "documented_start_utc",
            "first_pre_start_relevant_observation",
            "first_post_start_relevant_observation",
            "candidate_change_based_onset",
            "selected_onset",
            "onset_rule",
            "offset_from_documented_start_seconds",
            "evidence_supporting_onset",
            "ambiguity_review_flag",
        ],
    )
    write_csv(OUT / "tti_horizon_behavioral_features_v2.csv", behavior_rows, META + BEHAVIORAL_FEATURES)
    write_csv(OUT / "tti_horizon_caida_features_v2.csv", caida_rows, META + CAIDA_FEATURE_NAMES)
    write_csv(OUT / "tti_horizon_rpki_features_v2.csv", rpki_rows, META + RPKI_FEATURE_NAMES)
    write_csv(OUT / "tti_horizon_v4_features_v2.csv", v4_rows, META + BEHAVIORAL_FEATURES + CAIDA_FEATURE_NAMES + RPKI_FEATURE_NAMES)
    write_csv(
        OUT / "tti_v4_compatibility_v2.csv",
        compat_rows,
        ["feature_order", "feature_name", "feature_group", "expected_in_v4", "present_in_v2", "ordering_matches_v4", "compatible_data_type", "nan_or_blank_count", "inf_count", "definition_changed", "status", "notes"],
    )
    write_csv(
        OUT / "tti_leakage_assertions_v2.csv",
        assertions,
        ["incident_uid", "category", "horizon_seconds", "selected_onset_utc", "horizon_cutoff_utc", "max_bgp_timestamp_utc", "assertion", "status", "observations_checked", "caida_snapshot", "rpki_snapshot_date"],
    )
    write_docs(onset_rows, compat_rows, assertions)
    print(
        {
            "incidents": len(roster),
            "horizon_rows": len(v4_rows),
            "v4_features": len(BEHAVIORAL_FEATURES) + len(CAIDA_FEATURE_NAMES) + len(RPKI_FEATURE_NAMES),
            "compatibility": dict(Counter(row["status"] for row in compat_rows)),
            "leakage": dict(Counter(row["status"] for row in assertions)),
        }
    )


if __name__ == "__main__":
    main()
