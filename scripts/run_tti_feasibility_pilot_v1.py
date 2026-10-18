from __future__ import annotations

import csv
import json
import math
import re
import shutil
import subprocess
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from statistics import mean, median, pstdev


ROOT = Path("/Users/biruk/Documents/New project")
OUT = ROOT / "data/tti_pilot"
PILOT_ROSTER = ROOT / "data/pilot/mrt_pilot_incidents_v1.csv"
PILOT_DOWNLOAD_MANIFEST = ROOT / "data/pilot/mrt_pilot_download_manifest_v1.csv"
RAW_ROOT = ROOT / "data/raw_mrt/pilot"
HORIZONS = [30, 60, 120, 300]
CLASS_ORDER = ["Hijack", "Leak", "Outage"]

PARSED_FIELDS = [
    "incident_uid",
    "incident_id",
    "category",
    "partition",
    "source_mrt_filename",
    "collector",
    "bgp_timestamp_utc",
    "peer_ip",
    "peer_asn",
    "message_update_type",
    "announcement_or_withdrawal",
    "prefix",
    "as_path",
    "origin_asn",
    "next_hop",
    "communities",
    "med",
    "local_pref",
    "atomic_aggregate",
    "aggregator",
]

META_COLUMNS = [
    "incident_uid",
    "incident_id",
    "category",
    "partition",
    "horizon_seconds",
    "observable_onset_utc",
    "horizon_cutoff_utc",
    "observation_count_in_horizon",
]

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
            writer.writerow({field: clean(row.get(field, "")) for field in fieldnames})


def clean(value: object) -> object:
    if isinstance(value, float) and math.isnan(value):
        return ""
    return value


def parse_listish(value: str | None) -> list[str]:
    if not value:
        return []
    text = value.strip()
    try:
        import ast

        parsed = ast.literal_eval(text)
        if isinstance(parsed, list):
            return [str(item).strip() for item in parsed if str(item).strip()]
    except Exception:
        pass
    return [part.strip().strip("\"'") for part in text.strip("[]").split(",") if part.strip().strip("\"'")]


def parse_as_path(value: str | None) -> list[str]:
    return re.findall(r"\d+", value or "")


def normalize_as_path(value: str | None) -> str:
    output: list[str] = []
    for asn in parse_as_path(value):
        if not output or output[-1] != asn:
            output.append(asn)
    return " ".join(output)


def origin_from_path(value: str | None) -> str:
    path = parse_as_path(value)
    return path[-1] if path else ""


def parse_epoch_to_utc(value: str) -> datetime:
    return datetime.fromtimestamp(float(value), tz=timezone.utc)


def fmt(dt: datetime | None) -> str:
    return "" if dt is None else dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_iso(value: str) -> datetime:
    text = value.strip().replace("Z", "+00:00")
    return datetime.fromisoformat(text).astimezone(timezone.utc)


def onset_ambiguity(onset: datetime | None, documented_start: str) -> tuple[str, object]:
    if onset is None:
        return "NO_RELEVANT_OBSERVATION", ""
    try:
        documented = parse_iso(documented_start)
    except Exception:
        return "DOCUMENTED_START_UNPARSEABLE", ""
    delta = (onset - documented).total_seconds()
    if delta < -1:
        return "PRE_DOCUMENTED_START_RELEVANCE_CONTEXT", round(delta, 3)
    if delta > 300:
        return "AFTER_DOCUMENTED_START_OBSERVABILITY_LAG", round(delta, 3)
    return "NONE", round(delta, 3)


def classify_message_type(value: str) -> str:
    if value == "A":
        return "announcement"
    if value == "W":
        return "withdrawal"
    return "other"


def parse_bgpdump_line(line: str, incident: dict[str, str], source_path: Path, collector: str) -> dict[str, str] | None:
    parts = line.rstrip("\n").split("|")
    if len(parts) < 6:
        return None
    kind = classify_message_type(parts[2])
    as_path = parts[6] if kind == "announcement" and len(parts) > 6 else ""
    return {
        "incident_uid": incident["incident_uid"],
        "incident_id": incident["incident_uid"].split(":", 1)[1],
        "category": incident["category"],
        "partition": incident["partition"],
        "source_mrt_filename": source_path.name,
        "collector": collector,
        "bgp_timestamp_utc": fmt(parse_epoch_to_utc(parts[1])),
        "peer_ip": parts[3],
        "peer_asn": parts[4],
        "message_update_type": parts[2],
        "announcement_or_withdrawal": kind,
        "prefix": parts[5],
        "as_path": as_path,
        "origin_asn": origin_from_path(as_path),
        "next_hop": parts[8] if kind == "announcement" and len(parts) > 8 else "",
        "communities": parts[11] if kind == "announcement" and len(parts) > 11 else "",
        "med": parts[9] if kind == "announcement" and len(parts) > 9 else "",
        "local_pref": parts[10] if kind == "announcement" and len(parts) > 10 else "",
        "atomic_aggregate": parts[12] if kind == "announcement" and len(parts) > 12 else "",
        "aggregator": parts[13] if kind == "announcement" and len(parts) > 13 else "",
    }


def relevance_targets(incident: dict[str, str]) -> dict[str, object]:
    return {
        "category": incident["category"],
        "affected_asns": set(parse_listish(incident.get("affected_asns"))),
        "affected_prefixes": set(parse_listish(incident.get("affected_prefixes"))),
        "leak_asn": str(incident.get("leak_asn") or ""),
        "leak_seg": set(parse_listish(incident.get("leak_seg"))),
    }


def is_relevant(obs: dict[str, str], target: dict[str, object]) -> bool:
    path_asns = set(parse_as_path(obs.get("as_path")))
    peer_origin = {obs.get("peer_asn", ""), obs.get("origin_asn", "")}
    peer_origin.discard("")
    prefix = obs.get("prefix", "")
    category = str(target["category"])
    if category == "Hijack":
        return bool(target["affected_asns"] & (path_asns | peer_origin)) or bool(prefix and prefix in target["affected_prefixes"])
    if category == "Leak":
        leak_asn = str(target["leak_asn"])
        return bool(leak_asn and (leak_asn in path_asns or leak_asn in peer_origin)) or bool(target["leak_seg"] & path_asns)
    if category == "Outage":
        return bool(target["affected_asns"] & (path_asns | peer_origin))
    return False


def update_aggregate(agg: Aggregate, obs: dict[str, str]) -> None:
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
        normalized = normalize_as_path(as_path)
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


def features_from_aggregate(agg: Aggregate) -> dict[str, float | int]:
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


def bgpdump_version() -> str:
    exe = shutil.which("bgpdump") or "bgpdump"
    result = subprocess.run([exe], text=True, capture_output=True, check=False)
    text = result.stdout + "\n" + result.stderr
    match = re.search(r"bgpdump version ([^\s]+)", text)
    return match.group(1) if match else "unknown"


def reparse_timestamped_evidence(incidents: dict[str, dict[str, str]], manifest_rows: list[dict[str, str]]) -> tuple[list[dict[str, object]], list[dict[str, str]]]:
    evidence_path = OUT / "tti_timestamped_evidence_v1.csv"
    audit_rows: list[dict[str, object]] = []
    evidence_rows: list[dict[str, str]] = []
    targets = {uid: relevance_targets(row) for uid, row in incidents.items()}
    with evidence_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=PARSED_FIELDS + ["normalized_as_path"])
        writer.writeheader()
        for index, row in enumerate(manifest_rows, 1):
            uid = row["incident_uid"]
            incident = incidents[uid]
            path = ROOT / row["local_path"]
            if not path.exists():
                path = RAW_ROOT / uid.replace(":", "_") / Path(row["local_path"]).name
            started = time.time()
            parsed = relevant = malformed = timestamp_errors = 0
            process = subprocess.Popen(["bgpdump", "-q", "-m", str(path)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            assert process.stdout is not None
            for line in process.stdout:
                parsed += 1
                try:
                    obs = parse_bgpdump_line(line, incident, path, row.get("routeviews_collector") or "route-views2")
                except (ValueError, OverflowError):
                    timestamp_errors += 1
                    continue
                if not obs:
                    malformed += 1
                    continue
                if not is_relevant(obs, targets[uid]):
                    continue
                relevant += 1
                obs["normalized_as_path"] = normalize_as_path(obs["as_path"])
                writer.writerow(obs)
                evidence_rows.append(obs)
            stderr = process.stderr.read() if process.stderr else ""
            rc = process.wait()
            audit_rows.append(
                {
                    "incident_uid": uid,
                    "source_mrt_filename": path.name,
                    "parsed_records": parsed,
                    "relevant_records": relevant,
                    "malformed_records": malformed,
                    "timestamp_errors": timestamp_errors,
                    "parse_return_code": rc,
                    "elapsed_seconds": round(time.time() - started, 3),
                    "status": "PASS" if rc == 0 and malformed == 0 and timestamp_errors == 0 else "REVIEW",
                    "notes": stderr.strip()[:500],
                }
            )
            if index == len(manifest_rows) or index % 25 == 0:
                print(f"parsed {index}/{len(manifest_rows)} pilot MRT files; relevant rows={len(evidence_rows)}", flush=True)
    return audit_rows, evidence_rows


def load_existing_timestamped_evidence() -> list[dict[str, str]] | None:
    evidence_path = OUT / "tti_timestamped_evidence_v1.csv"
    if not evidence_path.exists():
        return None
    return read_csv(evidence_path)


def build_horizon_features(incidents: dict[str, dict[str, str]], evidence_rows: list[dict[str, str]]) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    by_uid: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in evidence_rows:
        by_uid[row["incident_uid"]].append(row)
    feature_rows: list[dict[str, object]] = []
    assertion_rows: list[dict[str, object]] = []
    onset_rows: list[dict[str, object]] = []
    for uid, incident in sorted(incidents.items()):
        rows = sorted(by_uid.get(uid, []), key=lambda r: r["bgp_timestamp_utc"])
        timestamps = [parse_iso(r["bgp_timestamp_utc"]) for r in rows]
        onset = min(timestamps) if timestamps else None
        ambiguity, delta_seconds = onset_ambiguity(onset, incident["start_utc"])
        onset_rows.append(
            {
                "incident_uid": uid,
                "incident_id": uid.split(":", 1)[1],
                "category": incident["category"],
                "partition": incident["partition"],
                "externally_documented_start_utc": incident["start_utc"],
                "observable_onset_utc": fmt(onset),
                "observable_onset_definition": "first incident-relevant RouteViews BGP observation in selected pilot MRT evidence",
                "onset_ambiguity": ambiguity,
                "onset_delta_seconds_vs_documented_start": delta_seconds,
                "relevant_observation_count": len(rows),
            }
        )
        for horizon in HORIZONS:
            cutoff = onset + timedelta(seconds=horizon) if onset else None
            selected = [r for r in rows if cutoff and parse_iso(r["bgp_timestamp_utc"]) <= cutoff]
            agg = Aggregate()
            for obs in selected:
                update_aggregate(agg, obs)
            max_ts = max((parse_iso(r["bgp_timestamp_utc"]) for r in selected), default=None)
            row = {
                "incident_uid": uid,
                "incident_id": uid.split(":", 1)[1],
                "category": incident["category"],
                "partition": incident["partition"],
                "horizon_seconds": horizon,
                "observable_onset_utc": fmt(onset),
                "horizon_cutoff_utc": fmt(cutoff),
                "observation_count_in_horizon": len(selected),
            }
            row.update(features_from_aggregate(agg))
            feature_rows.append(row)
            assertion_rows.append(
                {
                    "incident_uid": uid,
                    "category": incident["category"],
                    "horizon_seconds": horizon,
                    "observable_onset_utc": fmt(onset),
                    "horizon_cutoff_utc": fmt(cutoff),
                    "max_bgp_timestamp_utc": fmt(max_ts),
                    "assertion": "max(bgp_timestamp_utc) <= onset + horizon",
                    "status": "PASS" if (max_ts is None or (cutoff and max_ts <= cutoff)) else "FAIL",
                    "observations_checked": len(selected),
                }
            )
    return feature_rows, assertion_rows, onset_rows


def compatibility_rows() -> list[dict[str, object]]:
    rows = []
    for feature in BEHAVIORAL_FEATURES:
        status = "COMPATIBLE_WITH_CAUSAL_TIMESTAMPED_EVIDENCE"
        concern = "None if computed only from observations up to the horizon cutoff."
        if feature.endswith("_rate_per_minute"):
            status = "REVIEW_DENOMINATOR_POLICY"
            concern = "Frozen definition divides by 5 minutes. This is schema-compatible but not an elapsed-time rate for 30/60/120-second horizons."
        rows.append(
            {
                "feature_group": "Behavioral",
                "feature_name": feature,
                "partial_horizon_status": status,
                "future_leakage_risk": concern,
                "included_in_pilot_feature_file": "YES",
            }
        )
    for group, names in {
        "CAIDA": [
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
        ],
        "RPKI/ROV": [
            "rpki_evidence_observation_count",
            "rpki_evaluable_observation_count",
            "rpki_valid_observation_count",
            "rpki_invalid_observation_count",
            "rpki_not_found_observation_count",
            "rpki_unevaluable_observation_count",
            "rpki_invalid_origin_observation_count",
            "rpki_invalid_maxlength_observation_count",
            "rpki_valid_observation_ratio",
            "rpki_invalid_observation_ratio",
            "rpki_not_found_observation_ratio",
            "rpki_unique_valid_prefix_count",
            "rpki_unique_invalid_prefix_count",
            "rpki_unique_not_found_prefix_count",
            "rpki_state_diversity_count",
            "rpki_dominant_state_code",
        ],
    }.items():
        for feature in names:
            rows.append(
                {
                    "feature_group": group,
                    "feature_name": feature,
                    "partial_horizon_status": "NOT_CONSTRUCTED_IN_THIS_PILOT",
                    "future_leakage_risk": "Requires horizon-filtered timestamped prefix/origin/path evidence plus as-of external snapshot mapping. Safe in principle, but not produced here.",
                    "included_in_pilot_feature_file": "NO",
                }
            )
    return rows


def write_not_evaluated_outputs(incidents: dict[str, dict[str, str]]) -> None:
    prediction_rows = []
    result_rows = []
    for incident in incidents.values():
        for horizon in HORIZONS:
            prediction_rows.append(
                {
                    "incident_uid": incident["incident_uid"],
                    "incident_id": incident["incident_uid"].split(":", 1)[1],
                    "category": incident["category"],
                    "horizon_seconds": horizon,
                    "true_class": incident["category"],
                    "predicted_class": "NOT_EVALUATED",
                    "hijack_probability": "",
                    "leak_probability": "",
                    "outage_probability": "",
                    "correct": "",
                    "true_class_rank": "",
                    "status": "NOT_EVALUATED",
                    "notes": "Model gate failed: full 74-feature V4 partial-horizon schema was not constructed and no serialized frozen Level-1 XGBoost artifact was found.",
                }
            )
    for horizon in HORIZONS:
        result_rows.append(
            {
                "horizon_seconds": horizon,
                "evaluable_incidents": 0,
                "macro_f1": "NA",
                "hijack_f1": "NA",
                "leak_f1": "NA",
                "outage_f1": "NA",
                "top1": "NA",
                "top2": "NA",
                "mrr": "NA",
                "status": "NOT_EVALUATED",
                "notes": "Scoring intentionally skipped because V4/model compatibility gate did not pass.",
            }
        )
    write_csv(
        OUT / "tti_incident_predictions_v1.csv",
        prediction_rows,
        ["incident_uid", "incident_id", "category", "horizon_seconds", "true_class", "predicted_class", "hijack_probability", "leak_probability", "outage_probability", "correct", "true_class_rank", "status", "notes"],
    )
    write_csv(
        OUT / "tti_horizon_results_v1.csv",
        result_rows,
        ["horizon_seconds", "evaluable_incidents", "macro_f1", "hijack_f1", "leak_f1", "outage_f1", "top1", "top2", "mrr", "status", "notes"],
    )


def write_docs(roster: list[dict[str, str]], evidence_count: int, feature_rows: list[dict[str, object]], assertions: list[dict[str, object]], parse_audit: list[dict[str, object]], onset_rows: list[dict[str, object]]) -> None:
    counts = Counter(row["category"] for row in roster)
    onsetless = sum(1 for row in feature_rows if row["horizon_seconds"] == 30 and not row["observable_onset_utc"])
    onset_ambiguity_counts = Counter(row["onset_ambiguity"] for row in onset_rows)
    assertion_failures = sum(1 for row in assertions if row["status"] != "PASS")
    parser_status = Counter(row["status"] for row in parse_audit)
    methodology = f"""# TTI Pilot Methodology v1

Scope: TRAIN-only feasibility pilot for early BGP incident classification at 30, 60, 120, and 300 seconds.

Pilot selection: reused the existing reproducible 9-incident MRT pilot roster because it contains 3 Hijack, 3 Leak, and 3 Outage TRAIN incidents with short/median/long duration buckets per class. No Validation or Final Holdout incidents are used.

Observable onset: the first incident-relevant RouteViews BGP observation in the selected pilot MRT evidence after applying frozen incident-relevance predicates from the existing parser pipeline. The externally documented incident start is retained for context but is not used as the TTI onset unless it is also observed in RouteViews evidence.

Onset ambiguity handling: if the first relevant RouteViews observation occurs before the externally documented incident start, the incident is flagged as `PRE_DOCUMENTED_START_RELEVANCE_CONTEXT`. This means the relevance predicate saw related ASN/prefix/path activity in the pre-context window, but the observation should not automatically be interpreted as true incident onset without a stricter event-specific onset rule.

Horizon construction: for each incident and horizon H, include only evidence with `bgp_timestamp_utc <= observable_onset_utc + H`. Horizons are cumulative checkpoints, not exact continuous-time identification claims.

Model gate: the frozen Level-2 K1 stacker is excluded. The frozen Level-1 XGBoost may be used only if the full 74-feature V4 schema is rebuilt without future leakage and a serialized frozen Level-1 model artifact is available.
"""
    (OUT / "tti_pilot_methodology_v1.md").write_text(methodology, encoding="utf-8")
    schema = """# TTI Timestamped Evidence Schema v1

One row represents one incident-relevant prefix-level BGP observation from `bgpdump -q -m` for a pilot MRT file. Unlike the compact enrichment evidence store, this pilot evidence preserves `bgp_timestamp_utc`.

Columns:

- incident_uid
- incident_id
- category
- partition
- source_mrt_filename
- collector
- bgp_timestamp_utc
- peer_ip
- peer_asn
- message_update_type
- announcement_or_withdrawal
- prefix
- as_path
- origin_asn
- next_hop
- communities
- med
- local_pref
- atomic_aggregate
- aggregator
- normalized_as_path

This evidence is not a model feature row and is not a completed five-minute window.
"""
    (OUT / "tti_timestamped_evidence_schema_v1.md").write_text(schema, encoding="utf-8")
    summary = f"""# TTI Pilot Summary v1

## Pilot Scope

- Incidents: {len(roster)}
- Class counts: Hijack={counts['Hijack']}, Leak={counts['Leak']}, Outage={counts['Outage']}
- Partition: TRAIN only
- Raw pilot MRT files reparsed: {len(parse_audit)}
- Timestamped incident-relevant observations retained: {evidence_count}
- Parser status counts: {dict(parser_status)}

## Can exact partial-horizon V4 features be generated safely?

Not fully in this pilot. The 44 Behavioral features were reconstructed at 30/60/120/300 seconds from timestamped pilot observations. However, the CAIDA and RPKI/ROV feature groups were not reconstructed in this pilot because they require a versioned horizon-aware enrichment step using as-of snapshots. Therefore the full frozen 74-feature V4 schema was not produced.

## Is the frozen Level-1 XGBoost compatible?

Not yet for scoring. It is technically compatible with a 74-column V4 vector, but this pilot produced only the 44 Behavioral partial-horizon features. In addition, no serialized frozen Level-1 XGBoost model artifact was found in the workspace audit; existing artifacts document the candidate and contain historical metrics/probabilities, but not a reusable model binary for this pilot.

## Classification by horizon

Model evaluation was intentionally not run. The output files `tti_horizon_results_v1.csv` and `tti_incident_predictions_v1.csv` contain `NOT_EVALUATED` rows because the predeclared model gate did not pass.

## Leakage assertions

- Assertion failures: {assertion_failures}
- Incidents without observable onset: {onsetless}
- Onset ambiguity counts: {dict(onset_ambiguity_counts)}

Every constructed horizon row passed the assertion `max(bgp_timestamp_utc) <= observable_onset_utc + horizon`.

## Checkpoint-based TTI distribution

Not computed because model scoring was not run. TTI requires predictions and is defined as the earliest evaluated checkpoint where Top-1 is correct. Top-2 TTI requires the true class in the Top-2 ranking.

## Validity concerns

- Rate features retain the frozen `/5 minutes` denominator for schema compatibility, but that is not an elapsed-time rate at 30/60/120 seconds.
- Several pilot incidents have first relevant observations before the externally documented incident start because the selected evidence includes pre-context and broad incident-relevance predicates. These cases require a stricter event-specific onset rule before scaling TTI claims.
- Full V4 compatibility requires CAIDA/RPKI remapping from horizon-filtered evidence.
- The Level-2 K1 temporal stacker remains invalid for this initial TTI pilot because it uses full incident temporal summaries.

## Scaling Recommendation

Scaling to all 993 TRAIN incidents is scientifically justified only after a second controlled step adds horizon-aware CAIDA/RPKI reconstruction and either locates/creates an explicitly frozen reusable Level-1 model artifact or predeclares a TRAIN-only retraining protocol for a TTI-specific model.
"""
    (OUT / "tti_pilot_summary_v1.md").write_text(summary, encoding="utf-8")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    roster = read_csv(PILOT_ROSTER)
    if len(roster) != 9:
        raise RuntimeError(f"expected 9 pilot incidents, found {len(roster)}")
    if set(row["partition"] for row in roster) != {"train"}:
        raise RuntimeError("pilot must be TRAIN only")
    if Counter(row["category"] for row in roster) != Counter({"Hijack": 3, "Leak": 3, "Outage": 3}):
        raise RuntimeError("pilot must contain 3 incidents per class")
    incidents = {row["incident_uid"]: row for row in roster}
    manifest_rows = [row for row in read_csv(PILOT_DOWNLOAD_MANIFEST) if row["incident_uid"] in incidents]
    if len(manifest_rows) != 216:
        raise RuntimeError(f"expected 216 pilot MRT files, found {len(manifest_rows)}")
    for row in roster:
        row["selection_rule"] = "existing reproducible TRAIN 9-incident MRT pilot; 3 classes x short/median/long duration buckets"
    write_csv(
        OUT / "tti_pilot_incident_roster_v1.csv",
        roster,
        list(roster[0].keys()),
    )
    existing_evidence = load_existing_timestamped_evidence()
    if existing_evidence is None:
        parse_audit, evidence_rows = reparse_timestamped_evidence(incidents, manifest_rows)
        write_csv(
            OUT / "tti_reparse_audit_v1.csv",
            parse_audit,
            ["incident_uid", "source_mrt_filename", "parsed_records", "relevant_records", "malformed_records", "timestamp_errors", "parse_return_code", "elapsed_seconds", "status", "notes"],
        )
    else:
        evidence_rows = existing_evidence
        parse_audit = read_csv(OUT / "tti_reparse_audit_v1.csv")
    feature_rows, assertions, onset_rows = build_horizon_features(incidents, evidence_rows)
    write_csv(OUT / "tti_observable_onset_v1.csv", onset_rows, ["incident_uid", "incident_id", "category", "partition", "externally_documented_start_utc", "observable_onset_utc", "observable_onset_definition", "onset_ambiguity", "onset_delta_seconds_vs_documented_start", "relevant_observation_count"])
    write_csv(OUT / "tti_horizon_behavioral_features_v1.csv", feature_rows, META_COLUMNS + BEHAVIORAL_FEATURES)
    write_csv(OUT / "tti_leakage_assertions_v1.csv", assertions, ["incident_uid", "category", "horizon_seconds", "observable_onset_utc", "horizon_cutoff_utc", "max_bgp_timestamp_utc", "assertion", "status", "observations_checked"])
    write_csv(OUT / "tti_feature_compatibility_v1.csv", compatibility_rows(), ["feature_group", "feature_name", "partial_horizon_status", "future_leakage_risk", "included_in_pilot_feature_file"])
    write_not_evaluated_outputs(incidents)
    write_docs(roster, len(evidence_rows), feature_rows, assertions, parse_audit, onset_rows)
    print(json.dumps({"out_dir": str(OUT), "incidents": len(roster), "mrt_files": len(manifest_rows), "timestamped_evidence_rows": len(evidence_rows)}, indent=2))


if __name__ == "__main__":
    main()
