from __future__ import annotations

import argparse
import json
import math
from collections import Counter, defaultdict
from datetime import timedelta
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

try:
    from bgp_incident_detection.audit import parse_utc
    from bgp_incident_detection.behavioral_features import (
        BEHAVIORAL_FEATURE_NAMES,
        WindowAggregate,
        features_from_aggregate,
        parse_as_path as behavioral_parse_as_path,
        percentile as behavioral_percentile,
        safe_ratio,
        update_aggregate,
    )
    from bgp_incident_detection.caida_features import (
        CAIDA_FEATURE_NAMES,
        CaidaWindowAggregate,
        caida_snapshot_name,
        caida_snapshot_url,
        features_from_caida_aggregate,
        load_relationships,
        parse_as_path as caida_parse_as_path,
        update_caida_aggregate_from_result,
        valley_free_result,
    )
    from bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT
    from bgp_incident_detection.rpki_features import (
        RPKI_FEATURE_NAMES,
        STATE_TO_CODE,
        TRUST_ANCHORS,
        build_vrp_index,
        cache_path,
        load_vrps,
        snapshot_date_for_observation,
        validate_rov,
    )
    from bgp_incident_detection.rpki_train_enrichment import selected_snapshot_by_observation_date
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import parse_utc
    from src.bgp_incident_detection.behavioral_features import (
        BEHAVIORAL_FEATURE_NAMES,
        WindowAggregate,
        features_from_aggregate,
        parse_as_path as behavioral_parse_as_path,
        percentile as behavioral_percentile,
        safe_ratio,
        update_aggregate,
    )
    from src.bgp_incident_detection.caida_features import (
        CAIDA_FEATURE_NAMES,
        CaidaWindowAggregate,
        caida_snapshot_name,
        caida_snapshot_url,
        features_from_caida_aggregate,
        load_relationships,
        parse_as_path as caida_parse_as_path,
        update_caida_aggregate_from_result,
        valley_free_result,
    )
    from src.bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT
    from src.bgp_incident_detection.rpki_features import (
        RPKI_FEATURE_NAMES,
        STATE_TO_CODE,
        TRUST_ANCHORS,
        build_vrp_index,
        cache_path,
        load_vrps,
        snapshot_date_for_observation,
        validate_rov,
    )
    from src.bgp_incident_detection.rpki_train_enrichment import selected_snapshot_by_observation_date


OUT_DIR = Path("data/tti_train_full_v2")
TRAIN_ROSTER = Path("data/partitions_v2/train_incidents_v2.csv")
QUALITY = Path("data/tti_timestamped_train_v1/tti_timestamped_train_quality_v1.csv")
MANIFEST = Path("data/tti_timestamped_train_v1/tti_timestamped_train_manifest_v1.csv")
EVIDENCE_DIR = Path("data/tti_timestamped_train_v1/evidence")
TRAIN_RPKI_MAPPING = Path("data/enrichment/rpki/train_rpki_snapshot_mapping_v1.csv")
ONSET_COLUMNS = [
    "bgp_timestamp_utc",
    "prefix",
    "origin_asn",
    "normalized_as_path",
    "announcement_or_withdrawal",
]
FEATURE_COLUMNS = [
    "bgp_timestamp_utc",
    "peer_asn",
    "announcement_or_withdrawal",
    "prefix",
    "as_path",
    "origin_asn",
    "next_hop",
    "communities",
    "med",
    "local_pref",
    "atomic_aggregate",
    "normalized_as_path",
]

EVALUABLE_COHORT = OUT_DIR / "tti_train_evaluable_cohort_v2.csv"
INSUFFICIENT_REVIEW = OUT_DIR / "tti_insufficient_evidence_review_v2.csv"
HORIZON_MANIFEST = OUT_DIR / "tti_train_horizon_manifest_v2.csv"
BEHAVIORAL_OUT = OUT_DIR / "tti_train_horizon_behavioral_v2.parquet"
CAIDA_OUT = OUT_DIR / "tti_train_horizon_caida_v2.parquet"
RPKI_OUT = OUT_DIR / "tti_train_horizon_rpki_v2.parquet"
V4_OUT = OUT_DIR / "tti_train_horizon_v4_v2.parquet"
COMPATIBILITY = OUT_DIR / "tti_train_horizon_compatibility_v2.csv"
LEAKAGE = OUT_DIR / "tti_train_horizon_leakage_v2.csv"
GATE = OUT_DIR / "tti_train_horizon_gate_v2.md"

HORIZONS = [30, 60, 120, 300]
EXPECTED_TRAIN = 993
EXPECTED_PASS = 984
EXPECTED_PASS_BY_CLASS = {"Hijack": 327, "Leak": 329, "Outage": 328}
EXPECTED_INSUFFICIENT = {
    "Hijack:3930",
    "Hijack:88054",
    "Hijack:125603",
    "Hijack:130023",
    "Leak:467171",
    "Leak:468388",
    "Outage:696",
    "Outage:1034",
    "Outage:1074",
}
HORIZON_FEATURE_VERSION = "v2"
ONSET_RULE = "FIRST_POST_DOCUMENTED_EVENT_EVIDENCE"
NOT_EVALUABLE = "TTI_NOT_EVALUABLE_INSUFFICIENT_ROUTEVIEWS_EVIDENCE"
NO_POST_START_EVIDENCE = "TTI_NOT_EVALUABLE_NO_POST_DOCUMENTED_EVENT_EVIDENCE"


def format_utc(value: pd.Timestamp) -> str:
    return value.tz_convert("UTC").isoformat(timespec="milliseconds").replace("+00:00", "Z")


def read_train_inputs() -> tuple[pd.DataFrame, pd.DataFrame]:
    roster = pd.read_csv(TRAIN_ROSTER, low_memory=False)
    quality = pd.read_csv(QUALITY, low_memory=False)
    if len(roster) != EXPECTED_TRAIN:
        raise ValueError(f"Expected 993 TRAIN incidents; found {len(roster)}")
    if set(roster["partition"].astype(str).str.lower()) != {"train"}:
        raise ValueError("TTI full horizon construction may use TRAIN incidents only")
    counts = roster["category"].value_counts().to_dict()
    if counts != {"Hijack": 331, "Leak": 331, "Outage": 331}:
        raise ValueError(f"Unexpected TRAIN class counts: {counts}")
    if len(quality) != EXPECTED_TRAIN:
        raise ValueError(f"Expected 993 reconstruction quality rows; found {len(quality)}")
    return roster, quality


def evidence_path(incident_uid: str) -> Path:
    return EVIDENCE_DIR / f"{incident_uid.replace(':', '_')}.parquet"


def build_insufficient_review(roster: pd.DataFrame, quality: pd.DataFrame) -> pd.DataFrame:
    q = quality.set_index("incident_uid", drop=False)
    rows: list[dict[str, Any]] = []
    for uid in sorted(EXPECTED_INSUFFICIENT):
        if uid not in q.index:
            raise ValueError(f"Missing expected insufficient-evidence incident in quality file: {uid}")
        qr = q.loc[uid]
        rr = roster.loc[roster["incident_uid"].eq(uid)].iloc[0].to_dict()
        status = str(qr.get("processing_status", ""))
        raw = int(float(qr.get("raw_records_inspected") or 0))
        relevant = int(float(qr.get("relevant_observations_retained") or 0))
        downloaded = int(float(qr.get("mrt_files_downloaded_or_reused") or 0))
        parsed = raw > 0
        confirmed = (
            status == "INSUFFICIENT_EVIDENCE"
            and downloaded > 0
            and parsed
            and relevant == 0
            and str(qr.get("review_reason", "")).lower().find("parser") < 0
        )
        rows.append(
            {
                "incident_uid": uid,
                "incident_id": rr.get("incident_id", uid.split(":", 1)[-1]),
                "category": rr.get("category", qr.get("category")),
                "partition": rr.get("partition", "train"),
                "required_mrt_files_acquired": downloaded > 0,
                "mrt_files_downloaded_or_reused": downloaded,
                "parsing_completed": parsed,
                "raw_records_inspected": raw,
                "incident_relevance_filtering_applied": True,
                "relevant_timestamped_observations_retained": relevant,
                "zero_retention_confirmed": relevant == 0,
                "download_failure": False,
                "parser_failure": False,
                "timestamp_failure": False,
                "implementation_failure": False,
                "final_tti_status": NOT_EVALUABLE if confirmed else "REVIEW_UNCONFIRMED",
                "notes": "MRT files were processed under the frozen relevance predicates; no incident-relevant RouteViews observations were retained.",
            }
        )
    return pd.DataFrame(rows)


def load_evidence(
    uid: str,
    columns: list[str] | None = None,
    start_utc: pd.Timestamp | None = None,
    end_utc: pd.Timestamp | None = None,
) -> pd.DataFrame:
    path = evidence_path(uid)
    if not path.exists():
        raise FileNotFoundError(path)
    filters = None
    if start_utc is not None or end_utc is not None:
        filters = []
        if start_utc is not None:
            filters.append(("bgp_timestamp_utc", ">=", pd.to_datetime(start_utc, utc=True).to_pydatetime()))
        if end_utc is not None:
            filters.append(("bgp_timestamp_utc", "<=", pd.to_datetime(end_utc, utc=True).to_pydatetime()))
    try:
        df = pd.read_parquet(path, columns=columns, filters=filters)
    except Exception:
        df = pd.read_parquet(path, columns=columns)
    df["bgp_timestamp_utc"] = pd.to_datetime(df["bgp_timestamp_utc"], utc=True, errors="coerce")
    if start_utc is not None:
        df = df[df["bgp_timestamp_utc"] >= pd.to_datetime(start_utc, utc=True)]
    if end_utc is not None:
        df = df[df["bgp_timestamp_utc"] <= pd.to_datetime(end_utc, utc=True)]
    df = df.dropna(subset=["bgp_timestamp_utc"]).sort_values("bgp_timestamp_utc").reset_index(drop=True)
    return df


def signature_frame(df: pd.DataFrame) -> pd.Series:
    return (
        df["prefix"].fillna("").astype(str)
        + "|"
        + df["origin_asn"].fillna("").astype(str)
        + "|"
        + df["normalized_as_path"].fillna("").astype(str)
        + "|"
        + df["announcement_or_withdrawal"].fillna("").astype(str)
    )


def as_text(value: object) -> str:
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError):
        pass
    text = str(value).strip()
    return "" if text.lower() in {"nan", "none", "<na>"} else text


def value_from_record(record: Any, name: str) -> Any:
    if hasattr(record, "get"):
        return record.get(name)
    return getattr(record, name, None)


def next_or_none(iterator: Any) -> Any:
    try:
        return next(iterator)
    except StopIteration:
        return None


def build_onset_and_cohort(roster: pd.DataFrame, quality: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    q = quality.set_index("incident_uid", drop=False)
    pass_uids = sorted(q[q["processing_status"].eq("TIMESTAMP_EVIDENCE_PASS")]["incident_uid"].tolist())
    if len(pass_uids) != EXPECTED_PASS:
        raise ValueError(f"Expected {EXPECTED_PASS} evaluable incidents; found {len(pass_uids)}")
    cohort_rows: list[dict[str, Any]] = []
    horizon_rows: list[dict[str, Any]] = []
    onset_failure_rows: list[dict[str, Any]] = []
    for uid in pass_uids:
        rr = roster.loc[roster["incident_uid"].eq(uid)].iloc[0].to_dict()
        qr = q.loc[uid]
        df = load_evidence(uid, columns=ONSET_COLUMNS)
        documented = pd.to_datetime(rr.get("start_utc"), utc=True, errors="coerce")
        if pd.isna(documented):
            raise ValueError(f"Missing/invalid documented start for {uid}")
        pre = df[df["bgp_timestamp_utc"] < documented]
        post = df[df["bgp_timestamp_utc"] >= documented]
        if post.empty:
            onset_failure_rows.append(
                {
                    "incident_uid": uid,
                    "incident_id": rr.get("incident_id", uid.split(":", 1)[-1]),
                    "category": rr.get("category"),
                    "partition": rr.get("partition"),
                    "required_mrt_files_acquired": int(float(qr.get("mrt_files_downloaded_or_reused") or 0)) > 0,
                    "mrt_files_downloaded_or_reused": int(float(qr.get("mrt_files_downloaded_or_reused") or 0)),
                    "parsing_completed": int(float(qr.get("raw_records_inspected") or 0)) > 0,
                    "raw_records_inspected": int(float(qr.get("raw_records_inspected") or 0)),
                    "incident_relevance_filtering_applied": True,
                    "relevant_timestamped_observations_retained": int(len(df)),
                    "zero_retention_confirmed": False,
                    "download_failure": False,
                    "parser_failure": False,
                    "timestamp_failure": False,
                    "implementation_failure": False,
                    "final_tti_status": NO_POST_START_EVIDENCE,
                    "notes": "Timestamped evidence was retained, but every retained observation precedes the documented incident start; the approved FIRST_POST_DOCUMENTED_EVENT_EVIDENCE onset rule cannot define t0 for this incident.",
                }
            )
            continue
        selected_onset = post["bgp_timestamp_utc"].min()
        pre_signatures = set(signature_frame(pre)) if len(pre) else set()
        post_with_sig = post.assign(_signature=signature_frame(post))
        novel_post = post_with_sig[~post_with_sig["_signature"].isin(pre_signatures)]
        candidate_change = novel_post["bgp_timestamp_utc"].min() if len(novel_post) else selected_onset
        flag = "NONE" if candidate_change == selected_onset else "REVIEW_CHANGE_ONSET_DIFFERS"
        offset = (selected_onset - documented).total_seconds()
        common = {
            "incident_uid": uid,
            "incident_id": rr.get("incident_id", uid.split(":", 1)[-1]),
            "category": rr.get("category"),
            "partition": rr.get("partition"),
            "documented_start_utc": format_utc(documented),
            "first_pre_start_relevant_observation": format_utc(pre["bgp_timestamp_utc"].min()) if len(pre) else "",
            "first_post_start_relevant_observation": format_utc(selected_onset),
            "candidate_change_based_onset": format_utc(candidate_change),
            "selected_onset_utc": format_utc(selected_onset),
            "onset_rule": ONSET_RULE,
            "offset_from_documented_start_seconds": round(offset, 3),
            "pre_start_relevant_observations": int(len(pre)),
            "post_start_relevant_observations": int(len(post)),
            "total_retained_timestamped_observations": int(len(df)),
            "ambiguity_review_flag": flag,
            "tti_evaluable_status": "TTI_EVALUABLE",
        }
        cohort_rows.append(common)
        for horizon in HORIZONS:
            cutoff = selected_onset + timedelta(seconds=horizon)
            in_horizon = df[(df["bgp_timestamp_utc"] >= selected_onset) & (df["bgp_timestamp_utc"] <= cutoff)]
            horizon_rows.append(
                {
                    **common,
                    "horizon_seconds": horizon,
                    "horizon_cutoff_utc": format_utc(cutoff),
                    "observation_count_in_horizon": int(len(in_horizon)),
                    "max_bgp_timestamp_utc": format_utc(in_horizon["bgp_timestamp_utc"].max()) if len(in_horizon) else "",
                }
            )
    cohort = pd.DataFrame(cohort_rows).sort_values(["category", "incident_uid"]).reset_index(drop=True)
    horizon_manifest = pd.DataFrame(horizon_rows).sort_values(["incident_uid", "horizon_seconds"]).reset_index(drop=True)
    onset_failures = pd.DataFrame(onset_failure_rows)
    if len(horizon_manifest) != len(cohort) * len(HORIZONS):
        raise ValueError("Unexpected horizon row count")
    return cohort, horizon_manifest, onset_failures


def observation_to_behavioral_dict(row: Any) -> dict[str, str]:
    return {
        "bgp_timestamp_utc": as_text(value_from_record(row, "bgp_timestamp_utc")),
        "peer_asn": as_text(value_from_record(row, "peer_asn")),
        "announcement_or_withdrawal": as_text(value_from_record(row, "announcement_or_withdrawal")),
        "prefix": as_text(value_from_record(row, "prefix")),
        "as_path": as_text(value_from_record(row, "as_path")) or as_text(value_from_record(row, "normalized_as_path")),
        "origin_asn": as_text(value_from_record(row, "origin_asn")),
        "next_hop": as_text(value_from_record(row, "next_hop")),
        "communities": as_text(value_from_record(row, "communities")),
        "med": as_text(value_from_record(row, "med")),
        "local_pref": as_text(value_from_record(row, "local_pref")),
        "atomic_aggregate": as_text(value_from_record(row, "atomic_aggregate")),
    }


def clean_string_series(frame: pd.DataFrame, column: str) -> pd.Series:
    if column not in frame.columns:
        return pd.Series([""] * len(frame), index=frame.index, dtype="object")
    return frame[column].map(as_text)


def behavioral_features_from_frame(frame: pd.DataFrame) -> dict[str, float | int]:
    if frame.empty:
        return features_from_aggregate(WindowAggregate())

    work = pd.DataFrame(index=frame.index)
    work["type"] = clean_string_series(frame, "announcement_or_withdrawal")
    work["prefix"] = clean_string_series(frame, "prefix")
    work["peer_asn"] = clean_string_series(frame, "peer_asn")
    work["origin_asn"] = clean_string_series(frame, "origin_asn")
    work["as_path"] = clean_string_series(frame, "as_path")
    normalized = clean_string_series(frame, "normalized_as_path")
    work.loc[work["as_path"].eq(""), "as_path"] = normalized[work["as_path"].eq("")]
    work["next_hop"] = clean_string_series(frame, "next_hop")
    work["communities"] = clean_string_series(frame, "communities")
    work["med"] = clean_string_series(frame, "med")
    work["local_pref"] = clean_string_series(frame, "local_pref")
    work["atomic_aggregate"] = clean_string_series(frame, "atomic_aggregate")

    announcements = work["type"].eq("announcement")
    withdrawals = work["type"].eq("withdrawal")
    prefixes = work.loc[work["prefix"].ne(""), "prefix"]
    announced_prefixes = work.loc[announcements & work["prefix"].ne(""), "prefix"]
    withdrawn_prefixes = work.loc[withdrawals & work["prefix"].ne(""), "prefix"]
    peer_asns = work.loc[work["peer_asn"].ne(""), "peer_asn"]
    origin_asns = work.loc[work["origin_asn"].ne(""), "origin_asn"]
    as_paths = work.loc[work["as_path"].ne(""), "as_path"]
    next_hops = work.loc[work["next_hop"].ne(""), "next_hop"]

    path_lists = [behavioral_parse_as_path(path) for path in as_paths]
    path_lengths = [len(path) for path in path_lists if path]
    repeated_counts = [len(path) - len(set(path)) for path in path_lists if path]

    prefix_origin = work[work["prefix"].ne("") & work["origin_asn"].ne("")]
    prefix_path = work[work["prefix"].ne("") & work["as_path"].ne("")]
    peer_prefix = work[work["peer_asn"].ne("") & work["prefix"].ne("")]
    peer_origin = work[work["peer_asn"].ne("") & work["origin_asn"].ne("")]
    peer_path = work[work["peer_asn"].ne("") & work["as_path"].ne("")]

    prefix_origin_counts = prefix_origin.groupby("prefix")["origin_asn"].nunique() if len(prefix_origin) else pd.Series(dtype=int)
    prefix_path_counts = prefix_path.groupby("prefix")["as_path"].nunique() if len(prefix_path) else pd.Series(dtype=int)

    unique_prefix_count = int(prefixes.nunique())
    announcement_count = int(announcements.sum())
    withdrawal_count = int(withdrawals.sum())
    update_count = int(len(work))
    community_rows = work[work["communities"].ne("")]["communities"]
    community_tokens: set[str] = set()
    for value in community_rows:
        community_tokens.update(item for item in value.split() if item)

    path_min = min(path_lengths) if path_lengths else float("nan")
    path_max = max(path_lengths) if path_lengths else float("nan")
    return {
        "update_count": update_count,
        "announcement_count": announcement_count,
        "withdrawal_count": withdrawal_count,
        "update_rate_per_minute": update_count / 5,
        "announcement_rate_per_minute": announcement_count / 5,
        "withdrawal_rate_per_minute": withdrawal_count / 5,
        "announcement_ratio": safe_ratio(announcement_count, update_count),
        "withdrawal_ratio": safe_ratio(withdrawal_count, update_count),
        "announcement_to_withdrawal_ratio": safe_ratio(announcement_count, withdrawal_count),
        "unique_prefix_count": unique_prefix_count,
        "unique_announced_prefix_count": int(announced_prefixes.nunique()),
        "unique_withdrawn_prefix_count": int(withdrawn_prefixes.nunique()),
        "prefix_churn_count": int(announced_prefixes.nunique()) + int(withdrawn_prefixes.nunique()),
        "prefix_with_both_announce_withdraw_count": int(len(set(announced_prefixes) & set(withdrawn_prefixes))),
        "unique_peer_asn_count": int(peer_asns.nunique()),
        "unique_origin_asn_count": int(origin_asns.nunique()),
        "origin_diversity_ratio": safe_ratio(int(origin_asns.nunique()), unique_prefix_count),
        "moas_prefix_count": int((prefix_origin_counts > 1).sum()),
        "moas_prefix_ratio": safe_ratio(int((prefix_origin_counts > 1).sum()), unique_prefix_count),
        "origin_change_event_count": int((prefix_origin_counts - 1).clip(lower=0).sum()) if len(prefix_origin_counts) else 0,
        "unique_as_path_count": int(as_paths.nunique()),
        "as_path_length_min": path_min,
        "as_path_length_max": path_max,
        "as_path_length_mean": float(np.mean(path_lengths)) if path_lengths else float("nan"),
        "as_path_length_median": float(np.median(path_lengths)) if path_lengths else float("nan"),
        "as_path_length_std": float(np.std(path_lengths)) if path_lengths else float("nan"),
        "as_path_length_p95": behavioral_percentile(path_lengths, 0.95),
        "as_path_length_range": path_max - path_min if path_lengths else float("nan"),
        "path_prepending_observation_count": int(sum(1 for value in repeated_counts if value > 0)),
        "path_prepending_ratio": safe_ratio(int(sum(1 for value in repeated_counts if value > 0)), announcement_count),
        "prepended_asn_repetition_count": int(sum(value for value in repeated_counts if value > 0)),
        "multi_path_prefix_count": int((prefix_path_counts > 1).sum()),
        "path_diversity_mean_per_prefix": float(prefix_path_counts.mean()) if len(prefix_path_counts) else float("nan"),
        "peer_prefix_pair_count": int(len(peer_prefix[["peer_asn", "prefix"]].drop_duplicates())) if len(peer_prefix) else 0,
        "peer_origin_pair_count": int(len(peer_origin[["peer_asn", "origin_asn"]].drop_duplicates())) if len(peer_origin) else 0,
        "peer_as_path_pair_count": int(len(peer_path[["peer_asn", "as_path"]].drop_duplicates())) if len(peer_path) else 0,
        "unique_next_hop_count": int(next_hops.nunique()),
        "community_observation_count": int(len(community_rows)),
        "community_observation_ratio": safe_ratio(int(len(community_rows)), update_count),
        "unique_community_count": int(len(community_tokens)),
        "med_observation_count": int(work["med"].ne("").sum()),
        "unique_med_count": int(work.loc[work["med"].ne(""), "med"].nunique()),
        "local_pref_observation_count": int(work["local_pref"].ne("").sum()),
        "atomic_aggregate_count": int((work["atomic_aggregate"].ne("") & work["atomic_aggregate"].ne("NAG")).sum()),
    }


def aggregate_behavioral(horizon_manifest: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for uid, group in horizon_manifest.groupby("incident_uid", sort=True):
        selected = pd.to_datetime(group["selected_onset_utc"].iloc[0], utc=True)
        ordered_group = group.sort_values("horizon_seconds")
        max_cutoff = pd.to_datetime(ordered_group["horizon_cutoff_utc"].iloc[-1], utc=True)
        df = load_evidence(uid, columns=FEATURE_COLUMNS, start_utc=selected, end_utc=max_cutoff)
        for meta in ordered_group.itertuples(index=False):
            cutoff = pd.to_datetime(meta.horizon_cutoff_utc, utc=True)
            subset = df[df["bgp_timestamp_utc"] <= cutoff]
            output = {
                "incident_uid": meta.incident_uid,
                "incident_id": meta.incident_id,
                "category": meta.category,
                "partition": meta.partition,
                "horizon_seconds": int(meta.horizon_seconds),
                "selected_onset_utc": meta.selected_onset_utc,
                "horizon_cutoff_utc": meta.horizon_cutoff_utc,
                "observation_count_in_horizon": int(len(subset)),
            }
            output.update(behavioral_features_from_frame(subset))
            rows.append(output)
    return pd.DataFrame(rows)


def ensure_caida_relationships(horizon_manifest: pd.DataFrame) -> dict[str, dict[tuple[str, str], str]]:
    snapshots: dict[str, Path] = {}
    for value in horizon_manifest["selected_onset_utc"].drop_duplicates():
        parsed = pd.to_datetime(value, utc=True).to_pydatetime()
        snapshot = caida_snapshot_name(parsed.replace(day=1, hour=0, minute=0, second=0, microsecond=0))
        path = Path("data/cache/caida_as_relationships") / snapshot
        if not path.exists():
            alt = Path("data/cache/caida/as_relationships/serial-2") / snapshot
            path = alt if alt.exists() else path
        if not path.exists() or path.stat().st_size <= 0:
            raise FileNotFoundError(f"Missing cached CAIDA snapshot {snapshot} ({caida_snapshot_url(parsed)})")
        snapshots[snapshot] = path
    return {snapshot: load_relationships(path) for snapshot, path in snapshots.items()}


def aggregate_caida(horizon_manifest: pd.DataFrame) -> pd.DataFrame:
    relationships = ensure_caida_relationships(horizon_manifest)
    result_cache: dict[tuple[str, str], Any] = {}
    rows: list[dict[str, Any]] = []
    for uid, group in horizon_manifest.groupby("incident_uid", sort=True):
        selected = pd.to_datetime(group["selected_onset_utc"].iloc[0], utc=True)
        ordered_group = group.sort_values("horizon_seconds")
        max_cutoff = pd.to_datetime(ordered_group["horizon_cutoff_utc"].iloc[-1], utc=True)
        df = load_evidence(uid, columns=FEATURE_COLUMNS, start_utc=selected, end_utc=max_cutoff)
        for meta in ordered_group.itertuples(index=False):
            cutoff = pd.to_datetime(meta.horizon_cutoff_utc, utc=True)
            snapshot_dt = selected.to_pydatetime().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            snapshot = caida_snapshot_name(snapshot_dt)
            subset = df[df["bgp_timestamp_utc"] <= cutoff]
            aggregate = CaidaWindowAggregate()
            if len(subset):
                as_paths = clean_string_series(subset, "normalized_as_path")
                raw_paths = clean_string_series(subset, "as_path")
                as_paths = as_paths.where(as_paths.ne(""), raw_paths)
                path_counts = as_paths.value_counts(dropna=False)
            else:
                path_counts = pd.Series(dtype=int)
            for as_path, multiplicity in path_counts.items():
                if len(caida_parse_as_path(as_path)) < 2:
                    aggregate.paths_with_no_as_path_count += int(multiplicity)
                    continue
                key = (snapshot, as_path)
                if key not in result_cache:
                    result_cache[key] = valley_free_result(as_path, relationships[snapshot])
                update_caida_aggregate_from_result(aggregate, result_cache[key], multiplicity=int(multiplicity))
            output = {
                "incident_uid": meta.incident_uid,
                "incident_id": meta.incident_id,
                "category": meta.category,
                "partition": meta.partition,
                "horizon_seconds": int(meta.horizon_seconds),
                "selected_onset_utc": meta.selected_onset_utc,
                "horizon_cutoff_utc": meta.horizon_cutoff_utc,
                "observation_count_in_horizon": int(len(subset)),
                "selected_caida_snapshot": snapshot,
            }
            output.update(features_from_caida_aggregate(aggregate))
            rows.append(output)
    return pd.DataFrame(rows)


class VrpIndexCache:
    def __init__(self, snapshot_by_observation_date: dict[str, str]) -> None:
        self.snapshot_by_observation_date = snapshot_by_observation_date
        self.cache: dict[str, Any] = {}

    def selected_snapshot(self, observation_timestamp: object) -> str:
        observation_date = snapshot_date_for_observation(format_utc(pd.to_datetime(observation_timestamp, utc=True)))
        snapshot = self.snapshot_by_observation_date.get(observation_date)
        if not snapshot:
            raise RuntimeError(f"Missing selected RPKI snapshot mapping for observation date {observation_date}")
        return snapshot

    def get(self, snapshot_date: str) -> Any:
        if snapshot_date not in self.cache:
            for tal in TRUST_ANCHORS:
                path = cache_path(tal, snapshot_date)
                if not path.exists() or path.stat().st_size <= 0:
                    raise FileNotFoundError(f"Missing cached RPKI snapshot {path}")
            self.cache[snapshot_date] = build_vrp_index(load_vrps(snapshot_date))
        return self.cache[snapshot_date]


def zero_rpki_features() -> dict[str, Any]:
    return {
        "rpki_evidence_observation_count": 0,
        "rpki_evaluable_observation_count": 0,
        "rpki_valid_observation_count": 0,
        "rpki_invalid_observation_count": 0,
        "rpki_not_found_observation_count": 0,
        "rpki_unevaluable_observation_count": 0,
        "rpki_invalid_origin_observation_count": 0,
        "rpki_invalid_maxlength_observation_count": 0,
        "rpki_valid_observation_ratio": float("nan"),
        "rpki_invalid_observation_ratio": float("nan"),
        "rpki_not_found_observation_ratio": float("nan"),
        "rpki_unique_valid_prefix_count": 0,
        "rpki_unique_invalid_prefix_count": 0,
        "rpki_unique_not_found_prefix_count": 0,
        "rpki_state_diversity_count": 0,
        "rpki_dominant_state_code": STATE_TO_CODE["NO_PREFIX_ORIGIN_EVIDENCE"],
    }


def load_train_rpki_mapping() -> dict[str, str]:
    if not TRAIN_RPKI_MAPPING.exists():
        raise FileNotFoundError(f"Missing frozen TRAIN RPKI snapshot mapping: {TRAIN_RPKI_MAPPING}")
    mapping = pd.read_csv(TRAIN_RPKI_MAPPING, low_memory=False)
    return selected_snapshot_by_observation_date(mapping)


def aggregate_rpki(horizon_manifest: pd.DataFrame) -> pd.DataFrame:
    cache = VrpIndexCache(load_train_rpki_mapping())
    validation_cache: dict[tuple[str, str, str], Any] = {}
    rows: list[dict[str, Any]] = []
    for uid, group in horizon_manifest.groupby("incident_uid", sort=True):
        selected = pd.to_datetime(group["selected_onset_utc"].iloc[0], utc=True)
        max_cutoff = pd.to_datetime(group["horizon_cutoff_utc"].max(), utc=True)
        df = load_evidence(uid, columns=["bgp_timestamp_utc", "prefix", "origin_asn"], start_utc=selected, end_utc=max_cutoff)
        post = df
        for meta in group.sort_values("horizon_seconds").itertuples(index=False):
            cutoff = pd.to_datetime(meta.horizon_cutoff_utc, utc=True)
            subset = post[post["bgp_timestamp_utc"] <= cutoff]
            state_counts: Counter[str] = Counter()
            unique_prefixes: dict[str, set[str]] = defaultdict(set)
            if len(subset):
                keyed = subset.assign(
                    prefix=subset["prefix"].map(as_text),
                    origin_asn=subset["origin_asn"].map(as_text),
                    snapshot_date=subset["bgp_timestamp_utc"].map(cache.selected_snapshot),
                )
                keyed = (
                    keyed.groupby(["snapshot_date", "prefix", "origin_asn"], dropna=False)
                    .size()
                    .reset_index(name="observation_count")
                )
            else:
                keyed = pd.DataFrame(columns=["snapshot_date", "prefix", "origin_asn", "observation_count"])
            for obs in keyed.itertuples(index=False):
                prefix = str(obs.prefix or "")
                origin = str(obs.origin_asn or "")
                snapshot_date = str(obs.snapshot_date)
                vrps = cache.get(snapshot_date)
                key = (snapshot_date, prefix, origin)
                if key not in validation_cache:
                    validation_cache[key] = validate_rov(prefix, origin, vrps)
                result = validation_cache[key]
                state_counts[result.state] += int(obs.observation_count)
                if prefix:
                    unique_prefixes[result.state].add(prefix)
            valid = state_counts["VALID"]
            invalid_origin = state_counts["INVALID_ORIGIN"]
            invalid_length = state_counts["INVALID_LENGTH"]
            invalid = invalid_origin + invalid_length
            not_found = state_counts["NOT_FOUND"]
            unevaluable = state_counts["UNEVALUABLE"]
            evaluable = valid + invalid + not_found
            total = evaluable + unevaluable
            dominant = "NO_PREFIX_ORIGIN_EVIDENCE" if total == 0 else max(
                ["VALID", "INVALID_ORIGIN", "INVALID_LENGTH", "NOT_FOUND", "UNEVALUABLE"],
                key=lambda state: (state_counts[state], state),
            )
            features = zero_rpki_features()
            features.update(
                {
                    "rpki_evidence_observation_count": total,
                    "rpki_evaluable_observation_count": evaluable,
                    "rpki_valid_observation_count": valid,
                    "rpki_invalid_observation_count": invalid,
                    "rpki_not_found_observation_count": not_found,
                    "rpki_unevaluable_observation_count": unevaluable,
                    "rpki_invalid_origin_observation_count": invalid_origin,
                    "rpki_invalid_maxlength_observation_count": invalid_length,
                    "rpki_valid_observation_ratio": valid / evaluable if evaluable else float("nan"),
                    "rpki_invalid_observation_ratio": invalid / evaluable if evaluable else float("nan"),
                    "rpki_not_found_observation_ratio": not_found / evaluable if evaluable else float("nan"),
                    "rpki_unique_valid_prefix_count": len(unique_prefixes["VALID"]),
                    "rpki_unique_invalid_prefix_count": len(unique_prefixes["INVALID_ORIGIN"] | unique_prefixes["INVALID_LENGTH"]),
                    "rpki_unique_not_found_prefix_count": len(unique_prefixes["NOT_FOUND"]),
                    "rpki_state_diversity_count": sum(1 for state in ["VALID", "INVALID_ORIGIN", "INVALID_LENGTH", "NOT_FOUND", "UNEVALUABLE"] if state_counts[state] > 0),
                    "rpki_dominant_state_code": STATE_TO_CODE[dominant],
                }
            )
            output = {
                "incident_uid": meta.incident_uid,
                "incident_id": meta.incident_id,
                "category": meta.category,
                "partition": meta.partition,
                "horizon_seconds": int(meta.horizon_seconds),
                "selected_onset_utc": meta.selected_onset_utc,
                "horizon_cutoff_utc": meta.horizon_cutoff_utc,
                "observation_count_in_horizon": int(len(subset)),
                "selected_rpki_snapshot_date": cache.selected_snapshot(meta.selected_onset_utc),
            }
            output.update(features)
            rows.append(output)
    return pd.DataFrame(rows)


def build_v4(behavioral: pd.DataFrame, caida: pd.DataFrame, rpki: pd.DataFrame) -> pd.DataFrame:
    keys = [
        "incident_uid",
        "incident_id",
        "category",
        "partition",
        "horizon_seconds",
        "selected_onset_utc",
        "horizon_cutoff_utc",
        "observation_count_in_horizon",
    ]
    v4 = behavioral.merge(caida[keys + CAIDA_FEATURE_NAMES], on=keys, how="left", validate="one_to_one")
    v4 = v4.merge(rpki[keys + RPKI_FEATURE_NAMES], on=keys, how="left", validate="one_to_one")
    feature_order = FEATURES_BY_VARIANT["V4"]
    if feature_order != BEHAVIORAL_FEATURE_NAMES + CAIDA_FEATURE_NAMES + RPKI_FEATURE_NAMES:
        raise ValueError("V4 feature-order source disagrees with feature-family inventories")
    return v4[keys + feature_order].sort_values(["incident_uid", "horizon_seconds"]).reset_index(drop=True)


def write_compatibility(v4: pd.DataFrame) -> pd.DataFrame:
    feature_order = FEATURES_BY_VARIANT["V4"]
    rows = []
    observed_order = [column for column in v4.columns if column in feature_order]
    for index, feature in enumerate(feature_order, start=1):
        series = pd.to_numeric(v4[feature], errors="coerce")
        inf_count = int(np.isinf(series.to_numpy(dtype=float, na_value=np.nan)).sum())
        rows.append(
            {
                "feature_order": index,
                "feature_name": feature,
                "feature_family": "Behavioral" if feature in BEHAVIORAL_FEATURE_NAMES else "CAIDA" if feature in CAIDA_FEATURE_NAMES else "RPKI_ROV",
                "present": feature in v4.columns,
                "expected_order_matches": observed_order[index - 1] == feature,
                "compatible_numeric_dtype": pd.api.types.is_numeric_dtype(v4[feature]),
                "missing_count": int(series.isna().sum()),
                "inf_count": inf_count,
                "status": "PASS" if feature in v4.columns and observed_order[index - 1] == feature and inf_count == 0 else "FAIL",
            }
        )
    out = pd.DataFrame(rows)
    out.to_csv(COMPATIBILITY, index=False)
    return out


def write_leakage(horizon_manifest: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for uid, group in horizon_manifest.groupby("incident_uid", sort=True):
        for meta in group.sort_values("horizon_seconds").itertuples(index=False):
            selected = pd.to_datetime(meta.selected_onset_utc, utc=True)
            cutoff = pd.to_datetime(meta.horizon_cutoff_utc, utc=True)
            max_ts = pd.to_datetime(meta.max_bgp_timestamp_utc, utc=True) if meta.max_bgp_timestamp_utc else pd.NaT
            count = int(meta.observation_count_in_horizon)
            ok = count == 0 or (pd.notna(max_ts) and max_ts <= cutoff)
            rows.append(
                {
                    "incident_uid": meta.incident_uid,
                    "incident_id": meta.incident_id,
                    "category": meta.category,
                    "partition": meta.partition,
                    "horizon_seconds": int(meta.horizon_seconds),
                    "selected_onset_utc": format_utc(selected),
                    "horizon_cutoff_utc": format_utc(cutoff),
                    "max_bgp_timestamp_utc": format_utc(max_ts) if pd.notna(max_ts) else "",
                    "assertion": "max(bgp_timestamp_utc) <= selected_onset + horizon",
                    "observations_checked": count,
                    "status": "PASS" if ok and str(meta.partition).lower() == "train" else "FAIL",
                }
            )
    out = pd.DataFrame(rows)
    out.to_csv(LEAKAGE, index=False)
    return out


def write_gate(
    cohort: pd.DataFrame,
    insufficient: pd.DataFrame,
    horizon_manifest: pd.DataFrame,
    compatibility: pd.DataFrame,
    leakage: pd.DataFrame,
    disposition: str,
) -> None:
    lines = [
        "# Full TRAIN TTI Horizon Feature Gate v2",
        "",
        "Scope: non-destructive TRAIN-only TTI horizon feature construction.",
        "",
        f"- TRAIN corpus incidents: {EXPECTED_TRAIN}",
        f"- TTI-evaluable TRAIN cohort: {len(cohort)}",
        f"- TTI-evaluable class counts: {dict(cohort['category'].value_counts())}",
        f"- Not evaluable / excluded from TTI metric denominators: {len(insufficient)}",
        f"- Not-evaluable status counts: {dict(insufficient['final_tti_status'].value_counts())}",
        f"- Horizon rows: {len(horizon_manifest)}",
        f"- Horizons: {HORIZONS}",
        f"- Onset rule: `{ONSET_RULE}`",
        "- Features: 44 Behavioral + 14 CAIDA + 16 RPKI/ROV = 74 V4 features",
        "- Validation accessed: NO",
        "- Final Holdout accessed: NO",
        "- Model scoring/retraining/tuning: NO",
        "",
        "## Gates",
        "",
        f"- V4 compatibility: {dict(compatibility['status'].value_counts())}",
        f"- Horizon leakage assertions: {dict(leakage['status'].value_counts())}",
        "- CAIDA alignment: same-month historical serial-2 snapshot selected from the onset month.",
        "- RPKI alignment: same-day historical VRP snapshot selected from each observation date.",
        "",
        "The non-evaluable incidents remain part of the 993-incident TRAIN corpus, but are excluded from TTI metric denominators because the approved onset/evidence gates cannot produce defensible partial-horizon inputs for them.",
        "",
        f"Recommendation: {disposition}",
    ]
    GATE.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run() -> str:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    roster, quality = read_train_inputs()
    insufficient = build_insufficient_review(roster, quality)
    if set(insufficient["final_tti_status"]) != {NOT_EVALUABLE}:
        raise RuntimeError("Insufficient-evidence review did not confirm all nine cases")

    cohort, horizon_manifest, onset_failures = build_onset_and_cohort(roster, quality)
    if len(onset_failures):
        insufficient = pd.concat([insufficient, onset_failures], ignore_index=True)
    insufficient.to_csv(INSUFFICIENT_REVIEW, index=False)
    cohort.to_csv(EVALUABLE_COHORT, index=False)
    horizon_manifest.to_csv(HORIZON_MANIFEST, index=False)

    behavioral = aggregate_behavioral(horizon_manifest)
    behavioral.to_parquet(BEHAVIORAL_OUT, index=False)
    caida = aggregate_caida(horizon_manifest)
    caida.to_parquet(CAIDA_OUT, index=False)
    rpki = aggregate_rpki(horizon_manifest)
    rpki.to_parquet(RPKI_OUT, index=False)
    v4 = build_v4(behavioral, caida, rpki)
    v4.to_parquet(V4_OUT, index=False)

    compatibility = write_compatibility(v4)
    leakage = write_leakage(horizon_manifest)
    disposition = (
        "FULL_TRAIN_TTI_FEATURES_READY_FOR_SCORING"
        if len(cohort) == EXPECTED_PASS
        and len(v4) == EXPECTED_PASS * len(HORIZONS)
        and compatibility["status"].eq("PASS").all()
        and leakage["status"].eq("PASS").all()
        and set(v4["partition"].astype(str).str.lower()) == {"train"}
        else "FULL_TRAIN_TTI_FEATURES_REQUIRE_REVIEW"
    )
    write_gate(cohort, insufficient, horizon_manifest, compatibility, leakage, disposition)
    return disposition


def main() -> None:
    parser = argparse.ArgumentParser(description="Construct full TRAIN TTI horizon V4 features without scoring.")
    parser.parse_args()
    print(run())


if __name__ == "__main__":
    main()
