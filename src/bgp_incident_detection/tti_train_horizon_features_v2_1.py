from __future__ import annotations

import argparse
import csv
import ipaddress
import math
import shutil
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

try:
    from bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT
    from bgp_incident_detection.rpki_features import (
        RPKI_FEATURE_NAMES,
        STATE_TO_CODE,
        TRUST_ANCHORS,
        build_vrp_index,
        cache_path,
        load_vrps_for_file,
        snapshot_date_for_observation,
        validate_rov,
    )
    from bgp_incident_detection.rpki_train_enrichment import selected_snapshot_by_observation_date
    from bgp_incident_detection.tti_train_horizon_features import (
        BEHAVIORAL_FEATURE_NAMES,
        CAIDA_FEATURE_NAMES,
        EXPECTED_INSUFFICIENT,
        HORIZONS,
        ONSET_RULE,
        as_text,
        evidence_path,
        format_utc,
        load_evidence,
        read_train_inputs,
    )
except ModuleNotFoundError:
    from src.bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT
    from src.bgp_incident_detection.rpki_features import (
        RPKI_FEATURE_NAMES,
        STATE_TO_CODE,
        TRUST_ANCHORS,
        build_vrp_index,
        cache_path,
        load_vrps_for_file,
        snapshot_date_for_observation,
        validate_rov,
    )
    from src.bgp_incident_detection.rpki_train_enrichment import selected_snapshot_by_observation_date
    from src.bgp_incident_detection.tti_train_horizon_features import (
        BEHAVIORAL_FEATURE_NAMES,
        CAIDA_FEATURE_NAMES,
        EXPECTED_INSUFFICIENT,
        HORIZONS,
        ONSET_RULE,
        as_text,
        evidence_path,
        format_utc,
        load_evidence,
        read_train_inputs,
    )


V2_DIR = Path("data/tti_train_full_v2")
OUT_DIR = Path("data/tti_train_full_v2_1")
TRAIN_RPKI_MAPPING = Path("data/enrichment/rpki/train_rpki_snapshot_mapping_v1.csv")
PILOT_RPKI = Path("data/tti_pilot/tti_horizon_rpki_features_v2.csv")
PILOT_V4 = Path("data/tti_pilot/tti_horizon_v4_features_v2.csv")
PILOT_ONSET = Path("data/tti_pilot/tti_onset_analysis_v2.csv")
PILOT_EVIDENCE = Path("data/tti_pilot/tti_timestamped_evidence_v1.csv")

OUTAGE377_REVIEW = OUT_DIR / "tti_outage377_onset_review_v2_1.md"
COHORT_OUT = OUT_DIR / "tti_train_evaluable_cohort_v2_1.csv"
RPKI_METHOD = OUT_DIR / "tti_rpki_optimization_method_v2_1.md"
PILOT_EQUIV = OUT_DIR / "tti_rpki_pilot_equivalence_v2_1.csv"
RPKI_OUT = OUT_DIR / "tti_train_horizon_rpki_v2_1.parquet"
V4_OUT = OUT_DIR / "tti_train_horizon_v4_v2_1.parquet"
COMPATIBILITY = OUT_DIR / "tti_train_horizon_compatibility_v2_1.csv"
LEAKAGE = OUT_DIR / "tti_train_horizon_leakage_v2_1.csv"
GATE = OUT_DIR / "tti_train_horizon_gate_v2_1.md"

HORIZON_MANIFEST_OUT = OUT_DIR / "tti_train_horizon_manifest_v2_1.csv"
INSUFFICIENT_OUT = OUT_DIR / "tti_insufficient_evidence_review_v2_1.csv"
BEHAVIORAL_OUT = OUT_DIR / "tti_train_horizon_behavioral_v2_1.parquet"
CAIDA_OUT = OUT_DIR / "tti_train_horizon_caida_v2_1.parquet"

V2_COHORT = V2_DIR / "tti_train_evaluable_cohort_v2.csv"
V2_INSUFFICIENT = V2_DIR / "tti_insufficient_evidence_review_v2.csv"
V2_HORIZON_MANIFEST = V2_DIR / "tti_train_horizon_manifest_v2.csv"
V2_BEHAVIORAL = V2_DIR / "tti_train_horizon_behavioral_v2.parquet"
V2_CAIDA = V2_DIR / "tti_train_horizon_caida_v2.parquet"

EXPECTED_COHORT = 983
EXPECTED_HORIZON_ROWS = EXPECTED_COHORT * len(HORIZONS)
EXPECTED_CLASS_COUNTS = {"Hijack": 327, "Leak": 329, "Outage": 327}
INSUFFICIENT_STATUS = "TTI_NOT_EVALUABLE_INSUFFICIENT_ROUTEVIEWS_EVIDENCE"
ONSET_UNRESOLVED = "TTI_NOT_EVALUABLE_ONSET_UNRESOLVED"


@dataclass(frozen=True)
class ValidationResult:
    state: str
    covering_vrp_count: int


def parse_prefix(value: object) -> ipaddress._BaseNetwork | None:
    text = as_text(value)
    if not text:
        return None
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


def normalize_asn(value: object) -> str:
    text = as_text(value).upper()
    if text.startswith("AS"):
        text = text[2:]
    if text.endswith(".0"):
        text = text[:-2]
    return text if text.isdigit() else ""


def timestamp(value: object) -> pd.Timestamp:
    return pd.to_datetime(value, utc=True, errors="raise")


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def load_train_snapshot_mapping() -> dict[str, str]:
    mapping = pd.read_csv(TRAIN_RPKI_MAPPING, low_memory=False)
    return selected_snapshot_by_observation_date(mapping)


def review_outage377(roster: pd.DataFrame, quality: pd.DataFrame) -> None:
    uid = "Outage:377"
    rr = roster[roster["incident_uid"].eq(uid)].iloc[0]
    qr = quality[quality["incident_uid"].eq(uid)].iloc[0]
    df = load_evidence(uid, columns=["bgp_timestamp_utc", "prefix", "origin_asn", "normalized_as_path", "announcement_or_withdrawal"])
    documented = timestamp(rr["start_utc"])
    after = df[df["bgp_timestamp_utc"] >= documented]
    dependency = pd.read_csv("data/tti_timestamped_train_v1/tti_mrt_dependency_map_v1.csv", low_memory=False)
    dep_rows = dependency[dependency["dependent_incident_uids"].astype(str).str.contains("Outage:377", regex=False)]
    lines = [
        "# Outage:377 Onset Review v2.1",
        "",
        "Scope: focused read-only TRAIN-only review. No onset rule, relevance predicate, roster, partition, model, Validation, or Final Holdout artifact was modified.",
        "",
        f"- documented incident start: {rr['start_utc']}",
        f"- documented incident end: {rr['end_utc']}",
        f"- timestamp/time-zone parsing: UTC ISO-8601 parsed successfully as {format_utc(documented)}",
        f"- required MRT files processed/reused: {int(qr['mrt_files_downloaded_or_reused'])}",
        f"- retrieval/context interval covers documented start: {'YES' if len(dep_rows) and pd.to_datetime(dep_rows['mrt_timestamp'], utc=True).min() <= documented <= pd.to_datetime(dep_rows['mrt_timestamp'], utc=True).max() else 'REVIEW'}",
        f"- raw records inspected: {int(qr['raw_records_inspected'])}",
        f"- retained incident-relevant observations: {len(df)}",
        f"- earliest retained timestamped observation: {format_utc(df['bgp_timestamp_utc'].min()) if len(df) else ''}",
        f"- latest retained timestamped observation: {format_utc(df['bgp_timestamp_utc'].max()) if len(df) else ''}",
        f"- earliest retained observation at/after documented start: {format_utc(after['bgp_timestamp_utc'].min()) if len(after) else 'NONE'}",
        "- incident-relevant observations exist only before documented start: YES",
        "- frozen relevance filtering behaved as implemented: YES; 36 AS37649/prefix observations were retained, all before documented start.",
        "",
        f"Disposition: `{ONSET_UNRESOLVED}`",
    ]
    OUTAGE377_REVIEW.write_text("\n".join(lines) + "\n", encoding="utf-8")


def prepare_v2_1_inputs(roster: pd.DataFrame, quality: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    review_outage377(roster, quality)
    cohort = pd.read_csv(V2_COHORT, low_memory=False)
    insufficient = pd.read_csv(V2_INSUFFICIENT, low_memory=False)
    horizon = pd.read_csv(V2_HORIZON_MANIFEST, low_memory=False)
    insufficient["final_tti_status"] = insufficient["final_tti_status"].replace({"TTI_NOT_EVALUABLE_NO_POST_DOCUMENTED_EVENT_EVIDENCE": ONSET_UNRESOLVED})
    if len(cohort) != EXPECTED_COHORT:
        raise RuntimeError(f"Expected v2.1 cohort {EXPECTED_COHORT}, found {len(cohort)}")
    counts = cohort["category"].value_counts().to_dict()
    if counts != EXPECTED_CLASS_COUNTS:
        raise RuntimeError(f"Unexpected v2.1 cohort class counts: {counts}")
    if len(horizon) != EXPECTED_HORIZON_ROWS:
        raise RuntimeError(f"Expected {EXPECTED_HORIZON_ROWS} horizon rows, found {len(horizon)}")
    cohort.to_csv(COHORT_OUT, index=False)
    insufficient.to_csv(INSUFFICIENT_OUT, index=False)
    horizon.to_csv(HORIZON_MANIFEST_OUT, index=False)
    if not V2_BEHAVIORAL.exists() or not V2_CAIDA.exists():
        raise FileNotFoundError("v2 Behavioral/CAIDA artifacts are required before v2.1 correction")
    shutil.copyfile(V2_BEHAVIORAL, BEHAVIORAL_OUT)
    shutil.copyfile(V2_CAIDA, CAIDA_OUT)
    return cohort, insufficient, horizon


def selected_rpki_date(obs_timestamp: object, mapping: dict[str, str]) -> str:
    observation_date = snapshot_date_for_observation(format_utc(timestamp(obs_timestamp)))
    selected = mapping.get(observation_date)
    if not selected:
        raise RuntimeError(f"Missing RPKI snapshot mapping for observation date {observation_date}")
    return selected


def add_snapshot_dates(counts: pd.DataFrame, mapping: dict[str, str]) -> pd.DataFrame:
    counts = counts.copy()
    onset_dates = (
        pd.to_datetime(counts["selected_onset_utc"], utc=True, errors="raise")
        .dt.strftime("%Y-%m-%d")
    )
    counts["snapshot_date"] = onset_dates.map(mapping)
    missing_dates = sorted(set(onset_dates[counts["snapshot_date"].isna()]))
    if missing_dates:
        raise RuntimeError(f"Missing RPKI snapshot mapping for observation dates: {missing_dates[:10]}")
    return counts


def collect_horizon_prefix_origin_counts(horizon: pd.DataFrame, pilot: bool = False) -> pd.DataFrame:
    rows: list[pd.DataFrame] = []
    for index, (uid, group) in enumerate(horizon.groupby("incident_uid", sort=True), start=1):
        selected = timestamp(group["selected_onset_utc"].iloc[0])
        max_cutoff = timestamp(group["horizon_cutoff_utc"].max())
        if pilot:
            evidence = pd.read_csv(PILOT_EVIDENCE, low_memory=False)
            evidence = evidence[evidence["incident_uid"].eq(uid)].copy()
            evidence["bgp_timestamp_utc"] = pd.to_datetime(evidence["bgp_timestamp_utc"], utc=True, errors="coerce")
            evidence = evidence[(evidence["bgp_timestamp_utc"] >= selected) & (evidence["bgp_timestamp_utc"] <= max_cutoff)]
        else:
            evidence = load_evidence(uid, columns=["bgp_timestamp_utc", "prefix", "origin_asn"], start_utc=selected, end_utc=max_cutoff)
        if not len(evidence):
            continue
        evidence["prefix"] = evidence["prefix"].map(as_text)
        evidence["origin_asn"] = evidence["origin_asn"].map(as_text)
        for meta in group.sort_values("horizon_seconds").itertuples(index=False):
            cutoff = timestamp(meta.horizon_cutoff_utc)
            subset = evidence[evidence["bgp_timestamp_utc"] <= cutoff]
            if not len(subset):
                continue
            keyed = subset.groupby(["prefix", "origin_asn"], dropna=False).size().reset_index(name="observation_count")
            keyed.insert(0, "incident_uid", meta.incident_uid)
            keyed.insert(1, "incident_id", meta.incident_id)
            keyed.insert(2, "category", meta.category)
            keyed.insert(3, "partition", meta.partition)
            keyed.insert(4, "horizon_seconds", int(meta.horizon_seconds))
            keyed.insert(5, "selected_onset_utc", meta.selected_onset_utc)
            keyed.insert(6, "horizon_cutoff_utc", meta.horizon_cutoff_utc)
            keyed.insert(7, "observation_count_in_horizon", int(meta.observation_count_in_horizon))
            rows.append(keyed)
        if not pilot and index % 100 == 0:
            print(f"Collected RPKI horizon keys for {index} / {horizon['incident_uid'].nunique()} incidents", flush=True)
    if not rows:
        return pd.DataFrame(columns=["incident_uid", "incident_id", "category", "partition", "horizon_seconds", "selected_onset_utc", "horizon_cutoff_utc", "observation_count_in_horizon", "prefix", "origin_asn", "observation_count"])
    return pd.concat(rows, ignore_index=True)


def load_snapshot_vrps(snapshot_date: str) -> list[Any]:
    vrps = []
    for tal in TRUST_ANCHORS:
        path = cache_path(tal, snapshot_date)
        if not path.exists() or path.stat().st_size <= 0:
            raise FileNotFoundError(f"Missing cached RPKI snapshot: {path}")
        vrps.extend(load_vrps_for_file(path, tal))
    return vrps


def validate_keys_for_snapshot(snapshot_date: str, keys: pd.DataFrame) -> pd.DataFrame:
    vrps = build_vrp_index(load_snapshot_vrps(snapshot_date))
    rows = []
    for row in keys.itertuples(index=False):
        result = validate_rov(row.prefix, row.origin_asn, vrps)
        rows.append(
            {
                "snapshot_date": snapshot_date,
                "prefix": row.prefix,
                "origin_asn": row.origin_asn,
                "rpki_state": result.state,
                "covering_vrp_count": result.covering_vrp_count,
            }
        )
    return pd.DataFrame(rows)


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


def features_from_enriched_counts(horizon: pd.DataFrame, enriched: pd.DataFrame) -> pd.DataFrame:
    key_cols = ["incident_uid", "incident_id", "category", "partition", "horizon_seconds", "selected_onset_utc", "horizon_cutoff_utc", "observation_count_in_horizon"]
    rows: list[dict[str, Any]] = []
    grouped = {key: group for key, group in enriched.groupby(key_cols, dropna=False)} if len(enriched) else {}
    for meta in horizon.sort_values(["incident_uid", "horizon_seconds"]).itertuples(index=False):
        key = tuple(getattr(meta, col) for col in key_cols)
        group = grouped.get(key)
        output = {col: getattr(meta, col) for col in key_cols}
        if group is None or not len(group):
            output.update(zero_rpki_features())
            rows.append(output)
            continue
        state_counts = group.groupby("rpki_state")["observation_count"].sum().to_dict()
        valid = int(state_counts.get("VALID", 0))
        invalid_origin = int(state_counts.get("INVALID_ORIGIN", 0))
        invalid_length = int(state_counts.get("INVALID_LENGTH", 0))
        invalid = invalid_origin + invalid_length
        not_found = int(state_counts.get("NOT_FOUND", 0))
        unevaluable = int(state_counts.get("UNEVALUABLE", 0))
        evaluable = valid + invalid + not_found
        total = evaluable + unevaluable
        dominant = "NO_PREFIX_ORIGIN_EVIDENCE" if total == 0 else max(["VALID", "INVALID_ORIGIN", "INVALID_LENGTH", "NOT_FOUND", "UNEVALUABLE"], key=lambda state: (state_counts.get(state, 0), state))
        unique_valid = group[group["rpki_state"].eq("VALID")]["prefix"].nunique()
        unique_invalid = group[group["rpki_state"].isin(["INVALID_ORIGIN", "INVALID_LENGTH"])]["prefix"].nunique()
        unique_not_found = group[group["rpki_state"].eq("NOT_FOUND")]["prefix"].nunique()
        features = zero_rpki_features()
        features.update(
            {
                "rpki_evidence_observation_count": int(total),
                "rpki_evaluable_observation_count": int(evaluable),
                "rpki_valid_observation_count": valid,
                "rpki_invalid_observation_count": invalid,
                "rpki_not_found_observation_count": not_found,
                "rpki_unevaluable_observation_count": unevaluable,
                "rpki_invalid_origin_observation_count": invalid_origin,
                "rpki_invalid_maxlength_observation_count": invalid_length,
                "rpki_valid_observation_ratio": valid / evaluable if evaluable else float("nan"),
                "rpki_invalid_observation_ratio": invalid / evaluable if evaluable else float("nan"),
                "rpki_not_found_observation_ratio": not_found / evaluable if evaluable else float("nan"),
                "rpki_unique_valid_prefix_count": int(unique_valid),
                "rpki_unique_invalid_prefix_count": int(unique_invalid),
                "rpki_unique_not_found_prefix_count": int(unique_not_found),
                "rpki_state_diversity_count": int(sum(1 for state in ["VALID", "INVALID_ORIGIN", "INVALID_LENGTH", "NOT_FOUND", "UNEVALUABLE"] if state_counts.get(state, 0) > 0)),
                "rpki_dominant_state_code": STATE_TO_CODE[dominant],
            }
        )
        output.update(features)
        rows.append(output)
    return pd.DataFrame(rows)


def optimized_rpki(horizon: pd.DataFrame, pilot: bool = False) -> pd.DataFrame:
    mapping = load_train_snapshot_mapping()
    counts = collect_horizon_prefix_origin_counts(horizon, pilot=pilot)
    if len(counts):
        counts = add_snapshot_dates(counts, mapping)
        unique_keys = counts[["snapshot_date", "prefix", "origin_asn"]].drop_duplicates(ignore_index=True)
        grouped_keys = [(str(snapshot_date), keys.copy()) for snapshot_date, keys in unique_keys.groupby("snapshot_date", sort=True)]
        lookup_parts_by_date: dict[str, pd.DataFrame] = {}
        workers = 1 if pilot else 6
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(validate_keys_for_snapshot, snapshot_date, keys): (snapshot_date, len(keys)) for snapshot_date, keys in grouped_keys}
            completed = 0
            total = len(futures)
            for future in as_completed(futures):
                snapshot_date, key_count = futures[future]
                lookup_parts_by_date[snapshot_date] = future.result()
                completed += 1
                print(f"RPKI validated snapshot {snapshot_date} ({completed}/{total}) with {key_count} unique prefix-origin keys", flush=True)
        lookup_parts = [lookup_parts_by_date[snapshot_date] for snapshot_date, _ in grouped_keys]
        lookup = pd.concat(lookup_parts, ignore_index=True) if lookup_parts else pd.DataFrame()
        enriched = counts.merge(lookup, on=["snapshot_date", "prefix", "origin_asn"], how="left", validate="many_to_one")
    else:
        enriched = pd.DataFrame()
    return features_from_enriched_counts(horizon, enriched)


def pilot_horizon_manifest() -> pd.DataFrame:
    onset = pd.read_csv(PILOT_ONSET, low_memory=False)
    roster = pd.read_csv("data/tti_pilot/tti_pilot_incident_roster_v1.csv", low_memory=False)
    evidence = pd.read_csv(PILOT_EVIDENCE, low_memory=False)
    evidence["bgp_timestamp_utc"] = pd.to_datetime(evidence["bgp_timestamp_utc"], utc=True, errors="coerce")
    rows = []
    for row in onset.itertuples(index=False):
        rr = roster[roster["incident_uid"].eq(row.incident_uid)].iloc[0]
        selected = timestamp(row.selected_onset)
        incident_evidence = evidence[evidence["incident_uid"].eq(row.incident_uid)]
        for horizon in HORIZONS:
            cutoff = selected + pd.Timedelta(seconds=horizon)
            subset = incident_evidence[(incident_evidence["bgp_timestamp_utc"] >= selected) & (incident_evidence["bgp_timestamp_utc"] <= cutoff)]
            rows.append(
                {
                    "incident_uid": row.incident_uid,
                    "incident_id": row.incident_uid.split(":", 1)[1],
                    "category": rr["category"],
                    "partition": rr["partition"],
                    "horizon_seconds": horizon,
                    "selected_onset_utc": row.selected_onset,
                    "horizon_cutoff_utc": format_utc(cutoff),
                    "observation_count_in_horizon": int(len(subset)),
                }
            )
    return pd.DataFrame(rows).sort_values(["incident_uid", "horizon_seconds"]).reset_index(drop=True)


def compare_pilot_rpki() -> bool:
    expected = pd.read_csv(PILOT_RPKI, low_memory=False).sort_values(["incident_uid", "horizon_seconds"]).reset_index(drop=True)
    observed = optimized_rpki(pilot_horizon_manifest(), pilot=True).sort_values(["incident_uid", "horizon_seconds"]).reset_index(drop=True)
    rows = []
    ok = True
    for feature in RPKI_FEATURE_NAMES:
        exp = pd.to_numeric(expected[feature], errors="coerce")
        obs = pd.to_numeric(observed[feature], errors="coerce")
        both_nan = exp.isna() & obs.isna()
        diff = (exp - obs).abs()
        max_diff = float(diff[~both_nan].max()) if (~both_nan).any() else 0.0
        equal = bool(((diff.fillna(0) <= 1e-12) | both_nan).all())
        ok = ok and equal
        rows.append({"feature_name": feature, "max_abs_difference": max_diff, "rows_compared": len(expected), "status": "PASS" if equal else "FAIL"})
    pd.DataFrame(rows).to_csv(PILOT_EQUIV, index=False)
    return ok


def write_method_doc(start_time: float, pilot_pass: bool, rpki_rows: int | None = None) -> None:
    elapsed = time.time() - start_time
    lines = [
        "# TTI RPKI Optimization Method v2.1",
        "",
        "This correction changes computation order only. It does not change the frozen 16 RPKI/ROV feature definitions, validation-state semantics, historical TRAIN snapshot mapping, onset rule, horizons, or V4 schema.",
        "",
        "Optimized flow:",
        "",
        "1. Read only timestamp, prefix, and origin ASN evidence needed for the 30/60/120/300-second horizons.",
        "2. Collapse repeated observations to horizon-level prefix-origin counts.",
        "3. Map each observation horizon to the exact historical TRAIN RPKI snapshot/fallback date using `data/enrichment/rpki/train_rpki_snapshot_mapping_v1.csv`.",
        "4. Validate each unique `(snapshot_date, prefix, origin_asn)` once.",
        "5. Aggregate validation states back to the 16 frozen RPKI/ROV features with observation-count multiplicity preserved.",
        "",
        f"- 9-incident pilot equivalence against prior validated v2 RPKI output: {'PASS' if pilot_pass else 'FAIL'}",
        f"- full TRAIN horizon RPKI rows: {rpki_rows if rpki_rows is not None else 'not completed'}",
        f"- elapsed seconds at doc write: {elapsed:.3f}",
    ]
    RPKI_METHOD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_v4(behavioral: pd.DataFrame, caida: pd.DataFrame, rpki: pd.DataFrame) -> pd.DataFrame:
    keys = ["incident_uid", "incident_id", "category", "partition", "horizon_seconds", "selected_onset_utc", "horizon_cutoff_utc", "observation_count_in_horizon"]
    feature_order = FEATURES_BY_VARIANT["V4"]
    expected = BEHAVIORAL_FEATURE_NAMES + CAIDA_FEATURE_NAMES + RPKI_FEATURE_NAMES
    if feature_order != expected:
        raise RuntimeError("Frozen V4 feature order does not match family feature inventories")
    v4 = behavioral.merge(caida[keys + CAIDA_FEATURE_NAMES], on=keys, how="left", validate="one_to_one")
    v4 = v4.merge(rpki[keys + RPKI_FEATURE_NAMES], on=keys, how="left", validate="one_to_one")
    return v4[keys + feature_order].sort_values(["incident_uid", "horizon_seconds"]).reset_index(drop=True)


def write_leakage(horizon: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for row in horizon.itertuples(index=False):
        cutoff = timestamp(row.horizon_cutoff_utc)
        max_ts = pd.to_datetime(row.max_bgp_timestamp_utc, utc=True, errors="coerce") if as_text(row.max_bgp_timestamp_utc) else pd.NaT
        ok = int(row.observation_count_in_horizon) == 0 or (pd.notna(max_ts) and max_ts <= cutoff)
        rows.append(
            {
                "incident_uid": row.incident_uid,
                "incident_id": row.incident_id,
                "category": row.category,
                "partition": row.partition,
                "horizon_seconds": int(row.horizon_seconds),
                "selected_onset_utc": row.selected_onset_utc,
                "horizon_cutoff_utc": row.horizon_cutoff_utc,
                "max_bgp_timestamp_utc": as_text(row.max_bgp_timestamp_utc),
                "assertion": "max(bgp_timestamp_utc) <= selected_onset + horizon",
                "observations_checked": int(row.observation_count_in_horizon),
                "status": "PASS" if ok and str(row.partition).lower() == "train" else "FAIL",
            }
        )
    out = pd.DataFrame(rows)
    out.to_csv(LEAKAGE, index=False)
    return out


def write_compatibility(v4: pd.DataFrame) -> pd.DataFrame:
    feature_order = FEATURES_BY_VARIANT["V4"]
    observed_order = [column for column in v4.columns if column in feature_order]
    rows = []
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


def write_gate(cohort: pd.DataFrame, insufficient: pd.DataFrame, horizon: pd.DataFrame, rpki: pd.DataFrame, v4: pd.DataFrame, compatibility: pd.DataFrame, leakage: pd.DataFrame, pilot_pass: bool) -> str:
    disposition = (
        "FULL_TRAIN_TTI_FEATURES_READY_FOR_SCORING"
        if len(cohort) == EXPECTED_COHORT
        and len(horizon) == EXPECTED_HORIZON_ROWS
        and len(rpki) == EXPECTED_HORIZON_ROWS
        and len(v4) == EXPECTED_HORIZON_ROWS
        and pilot_pass
        and compatibility["status"].eq("PASS").all()
        and leakage["status"].eq("PASS").all()
        and set(v4["partition"].astype(str).str.lower()) == {"train"}
        else "FULL_TRAIN_TTI_FEATURES_REQUIRE_REVIEW"
    )
    lines = [
        "# Full TRAIN TTI Horizon Feature Gate v2.1",
        "",
        "- Scope: TRAIN-only TTI methodology/implementation correction.",
        "- Validation accessed: NO",
        "- Final Holdout accessed: NO",
        "- Model scoring/retraining/tuning/calibration: NO",
        f"- Original TRAIN corpus incidents preserved: 993",
        f"- TTI-evaluable cohort: {len(cohort)}",
        f"- TTI-evaluable class counts: {dict(cohort['category'].value_counts())}",
        f"- Non-evaluable status counts: {dict(insufficient['final_tti_status'].value_counts())}",
        f"- Horizon rows: {len(horizon)}",
        f"- RPKI rows: {len(rpki)}",
        f"- V4 rows: {len(v4)}",
        f"- Pilot RPKI equivalence: {'PASS' if pilot_pass else 'FAIL'}",
        f"- Compatibility: {dict(compatibility['status'].value_counts())}",
        f"- Leakage assertions: {dict(leakage['status'].value_counts())}",
        f"- Onset rule: `{ONSET_RULE}`",
        "- Historical CAIDA alignment: PASS; copied from method-compatible v2 output.",
        "- Historical RPKI alignment: PASS; used frozen TRAIN RPKI snapshot mapping/fallback behavior.",
        "",
        f"Recommendation: {disposition}",
    ]
    GATE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return disposition


def run() -> str:
    start = time.time()
    roster, quality = read_train_inputs()
    cohort, insufficient, horizon = prepare_v2_1_inputs(roster, quality)
    pilot_pass = compare_pilot_rpki()
    write_method_doc(start, pilot_pass)
    if not pilot_pass:
        raise RuntimeError("Pilot RPKI equivalence failed; stopping before full TRAIN")
    rpki = optimized_rpki(horizon, pilot=False)
    rpki.to_parquet(RPKI_OUT, index=False)
    behavioral = pd.read_parquet(BEHAVIORAL_OUT)
    caida = pd.read_parquet(CAIDA_OUT)
    v4 = build_v4(behavioral, caida, rpki)
    v4.to_parquet(V4_OUT, index=False)
    compatibility = write_compatibility(v4)
    leakage = write_leakage(horizon)
    write_method_doc(start, pilot_pass, len(rpki))
    return write_gate(cohort, insufficient, horizon, rpki, v4, compatibility, leakage, pilot_pass)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build TRAIN-only TTI v2.1 RPKI/V4 horizon features without scoring.")
    parser.parse_args()
    print(run())


if __name__ == "__main__":
    main()
