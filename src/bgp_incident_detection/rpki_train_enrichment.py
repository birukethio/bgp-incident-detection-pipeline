from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import math
from collections import Counter, OrderedDict, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd

try:
    from bgp_incident_detection.audit import write_csv
    from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES
    from bgp_incident_detection.caida_features import CAIDA_FEATURE_NAMES
    from bgp_incident_detection.caida_train_enrichment import train_batches
    from bgp_incident_detection.rpki_features import (
        FEATURE_INVENTORY,
        RPKI_FEATURE_NAMES,
        STATE_TO_CODE,
        TRUST_ANCHORS,
        build_vrp_index,
        cache_path,
        download_snapshot,
        feature_inventory_rows,
        load_vrps,
        snapshot_date_for_observation,
        snapshot_url,
        utc_now,
        validate_rov,
        write_static_outputs,
    )
    from bgp_incident_detection.train_batch_engine import source_commit
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import write_csv
    from src.bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES
    from src.bgp_incident_detection.caida_features import CAIDA_FEATURE_NAMES
    from src.bgp_incident_detection.caida_train_enrichment import train_batches
    from src.bgp_incident_detection.rpki_features import (
        FEATURE_INVENTORY,
        RPKI_FEATURE_NAMES,
        STATE_TO_CODE,
        TRUST_ANCHORS,
        build_vrp_index,
        cache_path,
        download_snapshot,
        feature_inventory_rows,
        load_vrps,
        snapshot_date_for_observation,
        snapshot_url,
        utc_now,
        validate_rov,
        write_static_outputs,
    )
    from src.bgp_incident_detection.train_batch_engine import source_commit


FROZEN_V1 = Path("data/train_frozen/frozen_train_behavioral_corpus_v1.parquet")
FROZEN_V2 = Path("data/train_frozen/frozen_train_v2_behavioral_caida_v1.parquet")
EVIDENCE_DIR = Path("data/enrichment/evidence/train_v1")
EVIDENCE_MANIFEST = Path("data/enrichment/evidence/train_evidence_manifest_v1.csv")
RPKI_DIR = Path("data/enrichment/rpki")
RPKI_BATCH_DIR = RPKI_DIR / "train_features_v1"
TRAIN_RPKI_MAPPING = RPKI_DIR / "train_rpki_snapshot_mapping_v1.csv"
TRAIN_RPKI_FEATURES = RPKI_DIR / "train_rpki_features_v1.parquet"
RPKI_SCHEMA = Path("config/rpki_feature_schema_v1.yaml")
FEATURE_VARIANTS = Path("config/feature_variants_v1.yaml")
TRAIN_ENRICHED_DIR = Path("data/train_enriched")
TRAIN_V3 = TRAIN_ENRICHED_DIR / "train_behavioral_rpki_v1.parquet"
TRAIN_V4 = TRAIN_ENRICHED_DIR / "train_behavioral_caida_rpki_v1.parquet"
V1_V3_AUDIT = TRAIN_ENRICHED_DIR / "v1_v3_behavioral_integrity_audit_v1.csv"
V2_V4_AUDIT = TRAIN_ENRICHED_DIR / "v2_v4_integrity_audit_v1.csv"
RPKI_QUALITY = TRAIN_ENRICHED_DIR / "train_rpki_feature_quality_audit_v1.csv"
RPKI_COVERAGE = TRAIN_ENRICHED_DIR / "train_rpki_validation_coverage_v1.csv"
V3_AUDIT = TRAIN_ENRICHED_DIR / "train_v3_rpki_corpus_audit_v1.csv"
V4_AUDIT = TRAIN_ENRICHED_DIR / "train_v4_caida_rpki_corpus_audit_v1.csv"
FROZEN_V3 = Path("data/train_frozen/frozen_train_v3_behavioral_rpki_v1.parquet")
FROZEN_V4 = Path("data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1.parquet")
FROZEN_V3_AUDIT = Path("data/train_frozen/frozen_train_v3_behavioral_rpki_audit_v1.csv")
FROZEN_V4_AUDIT = Path("data/train_frozen/frozen_train_v4_behavioral_caida_rpki_audit_v1.csv")
NOTEBOOK = Path("notebooks/37_full_train_rpki_enrichment.ipynb")

ID_COLUMNS = ["incident_uid", "incident_id", "category", "partition", "window_id", "window_start", "window_end", "temporal_status"]
RPKI_FEATURE_VERSION = "v1"
EXPECTED_ROWS = 68031
EXPECTED_INCIDENTS = 993
EXPECTED_CLASS_INCIDENTS = {"Hijack": 331, "Leak": 331, "Outage": 331}


class VrpIndexCache:
    def __init__(self, max_size: int = 4):
        self.max_size = max_size
        self.cache: OrderedDict[str, object] = OrderedDict()

    def get(self, snapshot_date: str):
        if snapshot_date in self.cache:
            value = self.cache.pop(snapshot_date)
            self.cache[snapshot_date] = value
            return value
        value = build_vrp_index(load_vrps(snapshot_date))
        self.cache[snapshot_date] = value
        while len(self.cache) > self.max_size:
            self.cache.popitem(last=False)
        return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cached_snapshot_usable(path: Path) -> bool:
    if not path.exists() or path.stat().st_size <= 0:
        return False
    try:
        with lzma.open(path, "rt", encoding="utf-8", errors="replace") as handle:
            handle.readline()
        return True
    except (lzma.LZMAError, EOFError, OSError):
        return False


def evidence_batch_path(batch_id: str) -> Path:
    numeric = batch_id.rsplit("_", 1)[-1]
    return EVIDENCE_DIR / f"batch_{numeric}.parquet"


def rpki_batch_path(batch_id: str) -> Path:
    numeric = batch_id.rsplit("_", 1)[-1]
    return RPKI_BATCH_DIR / f"batch_{numeric}.parquet"


def write_rpki_schema() -> None:
    rows = feature_inventory_rows()
    lines = [
        "rpki_feature_version: v1",
        "rpki_feature_count: 16",
        "source_inventory: data/enrichment/rpki/rpki_feature_inventory_v1.csv",
        "row_grain: one row per frozen TRAIN 5-minute window_id",
        "validation_states:",
        "  VALID: covering VRP authorizes origin ASN and prefix length",
        "  INVALID_ORIGIN: covering VRP exists but origin ASN is not authorized",
        "  INVALID_LENGTH: origin ASN is authorized but observed prefix exceeds maxLength",
        "  NOT_FOUND: no covering VRP exists",
        "  UNEVALUABLE: missing or malformed prefix/origin evidence",
        "features:",
    ]
    for index, row in enumerate(rows, start=1):
        lines.extend(
            [
                f"  - order: {index}",
                f"    name: {row['feature_name']}",
                f"    definition: {json.dumps(row['definition'])}",
                f"    formula: {json.dumps(row['formula'])}",
                f"    required_inputs: {json.dumps(row['required_inputs'])}",
                f"    aggregation_method: {json.dumps(row['aggregation_method'])}",
                f"    zero_behavior: {json.dumps(row['zero_behavior'])}",
                f"    missing_behavior: {json.dumps(row['missing_behavior'])}",
            ]
        )
    RPKI_SCHEMA.parent.mkdir(parents=True, exist_ok=True)
    RPKI_SCHEMA.write_text("\n".join(lines) + "\n", encoding="utf-8")


def load_frozen_v1() -> pd.DataFrame:
    df = pd.read_parquet(FROZEN_V1)
    validate_train_corpus(df, expected_features=BEHAVIORAL_FEATURE_NAMES)
    return df


def load_frozen_v2() -> pd.DataFrame:
    df = pd.read_parquet(FROZEN_V2)
    validate_train_corpus(df, expected_features=BEHAVIORAL_FEATURE_NAMES + CAIDA_FEATURE_NAMES)
    return df


def validate_train_corpus(df: pd.DataFrame, expected_features: list[str]) -> None:
    if len(df) != EXPECTED_ROWS:
        raise ValueError(f"expected {EXPECTED_ROWS} TRAIN rows, found {len(df)}")
    if df["incident_uid"].nunique() != EXPECTED_INCIDENTS:
        raise ValueError(f"expected {EXPECTED_INCIDENTS} TRAIN incidents, found {df['incident_uid'].nunique()}")
    if set(df["partition"].astype(str)) != {"train"}:
        raise ValueError("TRAIN corpus contains Validation/Holdout rows")
    counts = Counter(df.drop_duplicates("incident_uid")["category"])
    if counts != EXPECTED_CLASS_INCIDENTS:
        raise ValueError(f"unexpected class incident counts: {dict(counts)}")
    missing = [feature for feature in expected_features if feature not in df.columns]
    if missing:
        raise ValueError(f"missing expected features: {missing}")


def build_train_snapshot_mapping(frozen: pd.DataFrame) -> pd.DataFrame:
    tasks = []
    dates = sorted({snapshot_date_for_observation(value) for value in frozen["window_start"]})
    for date in dates:
        for tal in TRUST_ANCHORS:
            path = cache_path(tal, date)
            status_before = "CACHED" if cached_snapshot_usable(path) else "MISSING"
            if path.exists() and status_before == "MISSING":
                path.unlink()
            tasks.append((date, tal, status_before))
    rows = []
    completed = 0
    with ThreadPoolExecutor(max_workers=12) as executor:
        futures = {executor.submit(download_snapshot, tal, date): (date, tal, status_before) for date, tal, status_before in tasks}
        for future in as_completed(futures):
            date, tal, status_before = futures[future]
            result = future.result()
            local_path = Path(str(result["local_path"]))
            checksum = sha256(local_path) if cached_snapshot_usable(local_path) else ""
            status = str(result["status"]) if checksum else "FAIL:invalid_or_incomplete_xz"
            rows.append(
                {
                    "observation_date": date,
                    "selected_rpki_snapshot": date,
                    "trust_anchor": tal,
                    "mapping_type": "EXACT_DATE",
                    "fallback_used": "NO",
                    "source_url": snapshot_url(tal, date),
                    "local_path": str(local_path),
                    "checksum": checksum,
                    "download_timestamp": result["download_timestamp"],
                    "status": status,
                    "cache_state_before": status_before,
                    "bytes": local_path.stat().st_size if local_path.exists() else 0,
                }
            )
            completed += 1
            if completed == len(tasks) or completed % 250 == 0:
                print(f"RPKI snapshots checked/cached {completed} / {len(tasks)}", flush=True)
    rows = apply_nearest_earlier_fallbacks(rows)
    rows = sorted(rows, key=lambda row: (row["observation_date"], row["trust_anchor"]))
    TRAIN_RPKI_MAPPING.parent.mkdir(parents=True, exist_ok=True)
    write_csv(
        TRAIN_RPKI_MAPPING,
        rows,
        ["observation_date", "selected_rpki_snapshot", "trust_anchor", "mapping_type", "fallback_used", "source_url", "local_path", "checksum", "download_timestamp", "status", "cache_state_before", "bytes"],
    )
    failures = [row for row in rows if str(row["status"]).startswith("FAIL")]
    if failures:
        raise RuntimeError(f"RPKI snapshot failures: {len(failures)}")
    return pd.DataFrame(rows)


def apply_nearest_earlier_fallbacks(rows: list[dict[str, object]], max_days_back: int = 30) -> list[dict[str, object]]:
    resolved = []
    for row in rows:
        if not str(row["status"]).startswith("FAIL"):
            resolved.append(row)
            continue
        observation_date = str(row["observation_date"])
        tal = str(row["trust_anchor"])
        parsed = datetime.strptime(observation_date, "%Y-%m-%d").date()
        replacement = dict(row)
        for days_back in range(1, max_days_back + 1):
            fallback_date = (parsed - timedelta(days=days_back)).isoformat()
            fallback_path = cache_path(tal, fallback_date)
            status_before = "CACHED" if cached_snapshot_usable(fallback_path) else "MISSING"
            if fallback_path.exists() and status_before == "MISSING":
                fallback_path.unlink()
            result = download_snapshot(tal, fallback_date)
            local_path = Path(str(result["local_path"]))
            if not cached_snapshot_usable(local_path):
                continue
            replacement.update(
                {
                    "selected_rpki_snapshot": fallback_date,
                    "mapping_type": "NEAREST_EARLIER",
                    "fallback_used": "YES",
                    "source_url": snapshot_url(tal, fallback_date),
                    "local_path": str(local_path),
                    "checksum": sha256(local_path),
                    "download_timestamp": result["download_timestamp"],
                    "status": str(result["status"]),
                    "cache_state_before": status_before,
                    "bytes": local_path.stat().st_size,
                }
            )
            break
        resolved.append(replacement)
    return resolved


def selected_snapshot_by_observation_date(mapping: pd.DataFrame) -> dict[str, str]:
    selected = {}
    for date, group in mapping.groupby("observation_date"):
        snapshots = sorted(set(group["selected_rpki_snapshot"].astype(str)))
        if len(snapshots) != 1:
            raise RuntimeError(f"mixed trust-anchor fallback dates for {date}: {snapshots}")
        selected[str(date)] = snapshots[0]
    return selected


def empty_window_feature_rows(windows: pd.DataFrame) -> pd.DataFrame:
    outputs = []
    for _, meta in windows.sort_values(["incident_uid", "window_start"]).iterrows():
        output = {column: meta[column] for column in ID_COLUMNS if column in windows.columns}
        output.update(zero_feature_values())
        outputs.append(output)
    return pd.DataFrame(outputs)


def zero_feature_values() -> dict[str, object]:
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


def validate_unique_keys(keys: pd.DataFrame, index_cache: VrpIndexCache) -> pd.DataFrame:
    rows = []
    for date, group in keys.groupby("snapshot_date", sort=True):
        vrps = index_cache.get(str(date))
        for _, row in group.iterrows():
            prefix = str(row["prefix"] or "")
            origin = str(row["origin_asn"] or "")
            result = validate_rov(prefix, origin, vrps)
            rows.append(
                {
                    "snapshot_date": date,
                    "prefix": prefix,
                    "origin_asn": origin,
                    "rpki_state": result.state,
                    "covering_vrp_count": result.covering_vrp_count,
                }
            )
    return pd.DataFrame(rows)


def aggregate_rpki_batch(batch_id: str, batch_uids: list[str], frozen: pd.DataFrame, index_cache: VrpIndexCache, snapshot_by_observation_date: dict[str, str] | None = None) -> dict[str, object]:
    windows = frozen[frozen["incident_uid"].isin(batch_uids)].copy()
    evidence_path = evidence_batch_path(batch_id)
    if not evidence_path.exists():
        raise RuntimeError(f"missing evidence batch: {evidence_path}")
    columns = ["window_id", "incident_uid", "window_start", "prefix", "origin_asn", "observation_count"]
    evidence = pd.read_parquet(evidence_path, columns=columns)
    evidence = evidence[evidence["window_id"].isin(set(windows["window_id"]))]
    if len(evidence):
        evidence["prefix"] = evidence["prefix"].fillna("").astype(str)
        evidence["origin_asn"] = evidence["origin_asn"].fillna("").astype(str)
        observation_dates = evidence["window_start"].map(snapshot_date_for_observation)
        if snapshot_by_observation_date:
            evidence["snapshot_date"] = observation_dates.map(snapshot_by_observation_date)
        else:
            evidence["snapshot_date"] = observation_dates
        if evidence["snapshot_date"].isna().any():
            raise RuntimeError("missing selected RPKI snapshot date for at least one evidence row")
        keys = evidence[["snapshot_date", "prefix", "origin_asn"]].drop_duplicates(ignore_index=True)
        lookup = validate_unique_keys(keys, index_cache)
        enriched_evidence = evidence.merge(lookup, on=["snapshot_date", "prefix", "origin_asn"], how="left", validate="many_to_one")
    else:
        keys = pd.DataFrame(columns=["snapshot_date", "prefix", "origin_asn"])
        enriched_evidence = pd.DataFrame(columns=columns + ["snapshot_date", "rpki_state", "covering_vrp_count"])

    features = empty_window_feature_rows(windows)
    if len(enriched_evidence):
        state_sum = (
            enriched_evidence.groupby(["window_id", "rpki_state"], dropna=False)["observation_count"]
            .sum()
            .unstack(fill_value=0)
            .reset_index()
        )
        for state in ["VALID", "INVALID_ORIGIN", "INVALID_LENGTH", "NOT_FOUND", "UNEVALUABLE"]:
            if state not in state_sum.columns:
                state_sum[state] = 0
        prefix_states = enriched_evidence[["window_id", "prefix", "rpki_state"]].drop_duplicates()
        unique_counts = (
            prefix_states.groupby(["window_id", "rpki_state"], dropna=False)["prefix"]
            .nunique()
            .unstack(fill_value=0)
            .reset_index()
        )
        for state in ["VALID", "INVALID_ORIGIN", "INVALID_LENGTH", "NOT_FOUND", "UNEVALUABLE"]:
            if state not in unique_counts.columns:
                unique_counts[state] = 0
        merged = features[["window_id"]].merge(state_sum, on="window_id", how="left").merge(unique_counts, on="window_id", how="left", suffixes=("_obs", "_prefix"))
        merged = merged.fillna(0)
        for state in ["VALID", "INVALID_ORIGIN", "INVALID_LENGTH", "NOT_FOUND", "UNEVALUABLE"]:
            merged[f"{state}_obs"] = pd.to_numeric(merged.get(f"{state}_obs", 0), errors="coerce").fillna(0)
            merged[f"{state}_prefix"] = pd.to_numeric(merged.get(f"{state}_prefix", 0), errors="coerce").fillna(0)
        valid = merged["VALID_obs"]
        invalid_origin = merged["INVALID_ORIGIN_obs"]
        invalid_length = merged["INVALID_LENGTH_obs"]
        invalid = invalid_origin + invalid_length
        not_found = merged["NOT_FOUND_obs"]
        unevaluable = merged["UNEVALUABLE_obs"]
        evaluable = valid + invalid + not_found
        total = evaluable + unevaluable
        features["rpki_evidence_observation_count"] = total.astype("int64")
        features["rpki_evaluable_observation_count"] = evaluable.astype("int64")
        features["rpki_valid_observation_count"] = valid.astype("int64")
        features["rpki_invalid_observation_count"] = invalid.astype("int64")
        features["rpki_not_found_observation_count"] = not_found.astype("int64")
        features["rpki_unevaluable_observation_count"] = unevaluable.astype("int64")
        features["rpki_invalid_origin_observation_count"] = invalid_origin.astype("int64")
        features["rpki_invalid_maxlength_observation_count"] = invalid_length.astype("int64")
        features["rpki_valid_observation_ratio"] = valid.where(evaluable > 0) / evaluable.where(evaluable > 0)
        features["rpki_invalid_observation_ratio"] = invalid.where(evaluable > 0) / evaluable.where(evaluable > 0)
        features["rpki_not_found_observation_ratio"] = not_found.where(evaluable > 0) / evaluable.where(evaluable > 0)
        features["rpki_unique_valid_prefix_count"] = merged["VALID_prefix"].astype("int64")
        features["rpki_unique_invalid_prefix_count"] = (merged["INVALID_ORIGIN_prefix"] + merged["INVALID_LENGTH_prefix"]).astype("int64")
        features["rpki_unique_not_found_prefix_count"] = merged["NOT_FOUND_prefix"].astype("int64")
        state_presence = pd.concat([valid > 0, invalid_origin > 0, invalid_length > 0, not_found > 0, unevaluable > 0], axis=1)
        features["rpki_state_diversity_count"] = state_presence.sum(axis=1).astype("int64")
        dominant_codes = []
        states = ["VALID", "INVALID_ORIGIN", "INVALID_LENGTH", "NOT_FOUND", "UNEVALUABLE"]
        state_frame = pd.DataFrame({state: merged[f"{state}_obs"] for state in states})
        for _, row in state_frame.iterrows():
            if row.sum() == 0:
                dominant_codes.append(STATE_TO_CODE["NO_PREFIX_ORIGIN_EVIDENCE"])
            else:
                dominant_codes.append(STATE_TO_CODE[max(states, key=lambda state: (row[state], state))])
        features["rpki_dominant_state_code"] = dominant_codes

    RPKI_BATCH_DIR.mkdir(parents=True, exist_ok=True)
    features.to_parquet(rpki_batch_path(batch_id), index=False)
    return {
        "batch_id": batch_id,
        "incident_count": len(batch_uids),
        "window_count": len(windows),
        "evidence_rows": len(evidence),
        "raw_observations_represented": int(evidence["observation_count"].sum()) if len(evidence) else 0,
        "unique_lookup_keys": len(keys),
        "feature_rows": len(features),
        "status": "PASS" if len(features) == len(windows) else "FAIL",
    }


def combine_rpki_batches() -> pd.DataFrame:
    paths = sorted(RPKI_BATCH_DIR.glob("batch_*.parquet"))
    if not paths:
        raise RuntimeError("no full TRAIN RPKI batch files found")
    df = pd.concat([pd.read_parquet(path) for path in paths], ignore_index=True)
    if len(df) != EXPECTED_ROWS:
        raise RuntimeError(f"expected {EXPECTED_ROWS} RPKI rows, found {len(df)}")
    if df["window_id"].nunique() != EXPECTED_ROWS or df.duplicated("window_id").any():
        raise RuntimeError("RPKI features must have exactly one row per TRAIN window_id")
    TRAIN_RPKI_FEATURES.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(TRAIN_RPKI_FEATURES, index=False)
    return df


def write_quality_audit(features: pd.DataFrame) -> list[dict[str, object]]:
    rows = []
    row_count = len(features)
    for feature in RPKI_FEATURE_NAMES:
        series = pd.to_numeric(features[feature], errors="coerce")
        missing_count = int(series.isna().sum())
        finite = series.dropna()
        invalid = int(series.map(lambda value: isinstance(value, float) and math.isinf(value)).sum())
        zero_count = int((finite == 0).sum()) if len(finite) else 0
        unique_values = int(finite.nunique()) if len(finite) else 0
        sparse = bool(len(finite) and zero_count / len(finite) >= 0.95)
        constant = bool(unique_values <= 1)
        status = "FAIL" if invalid else "REVIEW" if constant or sparse else "PASS"
        rows.append(
            {
                "feature_name": feature,
                "row_count": row_count,
                "missing_count": missing_count,
                "missing_rate": round(missing_count / row_count * 100, 3) if row_count else 0,
                "zero_count": zero_count,
                "zero_rate": round(zero_count / len(finite) * 100, 3) if len(finite) else "",
                "min": finite.min() if len(finite) else "",
                "median": finite.median() if len(finite) else "",
                "mean": finite.mean() if len(finite) else "",
                "p95": finite.quantile(0.95) if len(finite) else "",
                "max": finite.max() if len(finite) else "",
                "unique_values": unique_values,
                "constant": str(constant),
                "sparse": str(sparse),
                "invalid": invalid,
                "status": status,
            }
        )
    write_csv(
        RPKI_QUALITY,
        rows,
        ["feature_name", "row_count", "missing_count", "missing_rate", "zero_count", "zero_rate", "min", "median", "mean", "p95", "max", "unique_values", "constant", "sparse", "invalid", "status"],
    )
    return rows


def write_validation_coverage(features: pd.DataFrame) -> None:
    rows = []
    for category, group in features.groupby("category"):
        evidence = pd.to_numeric(group["rpki_evidence_observation_count"], errors="coerce").fillna(0)
        valid = pd.to_numeric(group["rpki_valid_observation_count"], errors="coerce").fillna(0)
        invalid = pd.to_numeric(group["rpki_invalid_observation_count"], errors="coerce").fillna(0)
        not_found = pd.to_numeric(group["rpki_not_found_observation_count"], errors="coerce").fillna(0)
        invalid_origin = pd.to_numeric(group["rpki_invalid_origin_observation_count"], errors="coerce").fillna(0)
        invalid_length = pd.to_numeric(group["rpki_invalid_maxlength_observation_count"], errors="coerce").fillna(0)
        unevaluable = pd.to_numeric(group["rpki_unevaluable_observation_count"], errors="coerce").fillna(0)
        denominator = valid.sum() + invalid.sum() + not_found.sum()
        rows.append(
            {
                "category": category,
                "window_rows": len(group),
                "observations_represented": int(evidence.sum()),
                "valid_count": int(valid.sum()),
                "valid_percent": round(valid.sum() / denominator * 100, 3) if denominator else "",
                "invalid_count": int(invalid.sum()),
                "invalid_percent": round(invalid.sum() / denominator * 100, 3) if denominator else "",
                "not_found_count": int(not_found.sum()),
                "not_found_percent": round(not_found.sum() / denominator * 100, 3) if denominator else "",
                "origin_mismatch_invalid": int(invalid_origin.sum()),
                "maxlength_invalid": int(invalid_length.sum()),
                "malformed_unevaluable": int(unevaluable.sum()),
                "unique_prefixes_proxy": int(group[["rpki_unique_valid_prefix_count", "rpki_unique_invalid_prefix_count", "rpki_unique_not_found_prefix_count"]].sum(axis=1).sum()),
                "unique_origin_asns": "",
            }
        )
    write_csv(
        RPKI_COVERAGE,
        rows,
        ["category", "window_rows", "observations_represented", "valid_count", "valid_percent", "invalid_count", "invalid_percent", "not_found_count", "not_found_percent", "origin_mismatch_invalid", "maxlength_invalid", "malformed_unevaluable", "unique_prefixes_proxy", "unique_origin_asns"],
    )


def write_integrity_audit(path: Path, rows: list[dict[str, object]], fields: list[str]) -> str:
    status = "PASS" if all(row["status"] == "PASS" for row in rows) else "FAIL"
    write_csv(path, rows, fields)
    return status


def compare_features(left: pd.DataFrame, right: pd.DataFrame, features: list[str], label: str) -> list[dict[str, object]]:
    rows = []
    for feature in features:
        l = left[["window_id", feature]].sort_values("window_id").reset_index(drop=True)
        r = right[["window_id", feature]].sort_values("window_id").reset_index(drop=True)
        same = l.equals(r)
        rows.append({"feature_group": label, "feature_name": feature, "values_unchanged": str(same), "status": "PASS" if same else "FAIL"})
    return rows


def join_and_audit(v1: pd.DataFrame, v2: pd.DataFrame, rpki: pd.DataFrame, quality_rows: list[dict[str, object]]) -> tuple[pd.DataFrame, pd.DataFrame, dict[str, object], dict[str, object]]:
    rpki_cols = ["window_id"] + RPKI_FEATURE_NAMES
    v3 = v1.merge(rpki[rpki_cols], on="window_id", how="left", validate="one_to_one")
    v4 = v2.merge(rpki[rpki_cols], on="window_id", how="left", validate="one_to_one")
    TRAIN_ENRICHED_DIR.mkdir(parents=True, exist_ok=True)
    v3.to_parquet(TRAIN_V3, index=False)
    v4.to_parquet(TRAIN_V4, index=False)

    v1_v3_rows = compare_features(v1, v3, BEHAVIORAL_FEATURE_NAMES, "Behavioral")
    v1_v3_status = write_integrity_audit(V1_V3_AUDIT, v1_v3_rows, ["feature_group", "feature_name", "values_unchanged", "status"])
    v2_v4_rows = compare_features(v2, v4, BEHAVIORAL_FEATURE_NAMES, "Behavioral") + compare_features(v2, v4, CAIDA_FEATURE_NAMES, "CAIDA")
    v2_v4_status = write_integrity_audit(V2_V4_AUDIT, v2_v4_rows, ["feature_group", "feature_name", "values_unchanged", "status"])
    v3_audit = corpus_audit(v3, "v3", len(BEHAVIORAL_FEATURE_NAMES), 0, len(RPKI_FEATURE_NAMES), v1_v3_status, quality_rows)
    v4_audit = corpus_audit(v4, "v4", len(BEHAVIORAL_FEATURE_NAMES), len(CAIDA_FEATURE_NAMES), len(RPKI_FEATURE_NAMES), v2_v4_status, quality_rows)
    write_csv(V3_AUDIT, [v3_audit], list(v3_audit.keys()))
    write_csv(V4_AUDIT, [v4_audit], list(v4_audit.keys()))
    return v3, v4, v3_audit, v4_audit


def corpus_audit(df: pd.DataFrame, version: str, behavioral_count: int, caida_count: int, rpki_count: int, integrity_status: str, quality_rows: list[dict[str, object]]) -> dict[str, object]:
    class_counts = Counter(df["category"])
    incident_counts = Counter(df.drop_duplicates("incident_uid")["category"])
    missing_rpki_rows = int(df[RPKI_FEATURE_NAMES].isna().all(axis=1).sum())
    contamination = sorted(set(df["partition"].astype(str)) - {"train"})
    status = "PASS"
    notes = []
    if len(df) != EXPECTED_ROWS:
        status = "FAIL"
        notes.append("row count mismatch")
    if df["incident_uid"].nunique() != EXPECTED_INCIDENTS or incident_counts != EXPECTED_CLASS_INCIDENTS:
        status = "FAIL"
        notes.append("incident/class count mismatch")
    if df["window_id"].duplicated().any():
        status = "FAIL"
        notes.append("duplicate window IDs")
    if contamination:
        status = "FAIL"
        notes.append("Validation/Holdout contamination")
    if missing_rpki_rows:
        status = "FAIL"
        notes.append("missing all RPKI features")
    if integrity_status != "PASS":
        status = "FAIL"
        notes.append("prior feature values changed")
    if any(row["status"] == "FAIL" for row in quality_rows):
        status = "FAIL"
        notes.append("RPKI feature quality failure")
    return {
        "corpus_version": version,
        "expected_rows": EXPECTED_ROWS,
        "observed_rows": len(df),
        "expected_incidents": EXPECTED_INCIDENTS,
        "observed_incidents": df["incident_uid"].nunique(),
        "hijack_rows": class_counts.get("Hijack", 0),
        "leak_rows": class_counts.get("Leak", 0),
        "outage_rows": class_counts.get("Outage", 0),
        "hijack_incidents": incident_counts.get("Hijack", 0),
        "leak_incidents": incident_counts.get("Leak", 0),
        "outage_incidents": incident_counts.get("Outage", 0),
        "behavioral_feature_count": behavioral_count,
        "caida_feature_count": caida_count,
        "rpki_feature_count": rpki_count,
        "total_model_feature_count": behavioral_count + caida_count + rpki_count,
        "duplicate_window_ids": int(df["window_id"].duplicated().sum()),
        "validation_contamination": int((df["partition"].astype(str) == "validation").sum()),
        "holdout_contamination": int((df["partition"].astype(str) == "holdout").sum()),
        "missing_rpki_feature_rows": missing_rpki_rows,
        "integrity_status": integrity_status,
        "overall_status": status,
        "notes": ";".join(notes),
        "source_commit": source_commit(),
        "audit_timestamp": utc_now(),
    }


def freeze_corpus(df: pd.DataFrame, destination: Path, audit_path: Path, version: str, feature_counts: dict[str, int], audit: dict[str, object]) -> bool:
    if audit["overall_status"] != "PASS":
        return False
    frozen = df.copy()
    frozen["train_corpus_version"] = version
    frozen["corpus_status"] = "FROZEN"
    frozen["freeze_date"] = utc_now()
    frozen["source_commit"] = source_commit()
    destination.parent.mkdir(parents=True, exist_ok=True)
    frozen.to_parquet(destination, index=False)
    row = {
        "frozen_path": str(destination),
        "rows": len(frozen),
        "incidents": frozen["incident_uid"].nunique(),
        "behavioral_features": feature_counts.get("behavioral", 0),
        "caida_features": feature_counts.get("caida", 0),
        "rpki_features": feature_counts.get("rpki", 0),
        "total_model_features": sum(feature_counts.values()),
        "status": "PASS",
        "freeze_date": frozen["freeze_date"].iloc[0],
        "source_commit": frozen["source_commit"].iloc[0],
    }
    write_csv(audit_path, [row], list(row.keys()))
    return True


def update_feature_variants(v3_status: str, v4_status: str) -> None:
    FEATURE_VARIANTS.write_text(
        "\n".join(
            [
                "feature_variants_version: v1",
                "source: data/train_frozen/frozen_train_behavioral_corpus_v1.parquet",
                "notes: All four feature variants are frozen only after full TRAIN audits pass. No weighting, p95 cap, modeling, or ablation is applied here.",
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
                "    behavioral_feature_count: 44",
                "    caida_feature_count: 14",
                "    total_feature_count: 58",
                "    status: FROZEN",
                "    feature_groups:",
                "      - Behavioral",
                "      - CAIDA AS-relationship",
                "  V3:",
                "    description: Behavioral BGP + RPKI/ROV features",
                "    behavioral_feature_count: 44",
                "    rpki_feature_count: 16",
                "    total_feature_count: 60",
                f"    status: {v3_status}",
                "    feature_groups:",
                "      - Behavioral",
                "      - RPKI/ROV",
                "  V4:",
                "    description: Behavioral BGP + CAIDA AS-relationship + RPKI/ROV features",
                "    behavioral_feature_count: 44",
                "    caida_feature_count: 14",
                "    rpki_feature_count: 16",
                "    total_feature_count: 74",
                f"    status: {v4_status}",
                "    feature_groups:",
                "      - Behavioral",
                "      - CAIDA AS-relationship",
                "      - RPKI/ROV",
                "",
            ]
        ),
        encoding="utf-8",
    )


def write_notebook() -> None:
    NOTEBOOK.parent.mkdir(parents=True, exist_ok=True)
    notebook = {
        "cells": [
            {"cell_type": "markdown", "metadata": {}, "source": ["# Full TRAIN RPKI/ROV Enrichment\n", "\n", "Runs full TRAIN RPKI enrichment from the compact evidence store only. No MRT reparse, Validation/Holdout access, weighting, p95 cap, modeling, or ablation.\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["from bgp_incident_detection.rpki_train_enrichment import run_full_train\n", "# run_full_train()\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["import pandas as pd\n", "pd.read_csv('../data/train_enriched/train_v4_caida_rpki_corpus_audit_v1.csv')\n"]},
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")


def run_full_train() -> dict[str, object]:
    write_static_outputs()
    write_rpki_schema()
    write_notebook()
    v1 = load_frozen_v1()
    v2 = load_frozen_v2()
    mapping = build_train_snapshot_mapping(v1)
    batches = train_batches()
    evidence_manifest = pd.read_csv(EVIDENCE_MANIFEST)
    if set(evidence_manifest["status"].astype(str)) != {"PASS"}:
        raise RuntimeError("compact evidence manifest is not fully PASS")
    index_cache = VrpIndexCache(max_size=4)
    batch_rows = []
    for index, (batch_id, uids) in enumerate(batches.items(), start=1):
        result = aggregate_rpki_batch(batch_id, uids, v1, index_cache, selected_snapshot_by_observation_date(mapping))
        batch_rows.append(result)
        print(f"{batch_id} RPKI enrichment {index}/{len(batches)}: {result['feature_rows']} windows, {result['evidence_rows']} evidence rows, {result['unique_lookup_keys']} unique lookups", flush=True)
    write_csv(RPKI_DIR / "train_rpki_batch_manifest_v1.csv", batch_rows, ["batch_id", "incident_count", "window_count", "evidence_rows", "raw_observations_represented", "unique_lookup_keys", "feature_rows", "status"])
    rpki = combine_rpki_batches()
    quality_rows = write_quality_audit(rpki)
    write_validation_coverage(rpki)
    v3, v4, v3_audit, v4_audit = join_and_audit(v1, v2, rpki, quality_rows)
    v3_frozen = freeze_corpus(v3, FROZEN_V3, FROZEN_V3_AUDIT, "v3", {"behavioral": 44, "rpki": 16}, v3_audit)
    v4_frozen = freeze_corpus(v4, FROZEN_V4, FROZEN_V4_AUDIT, "v4", {"behavioral": 44, "caida": 14, "rpki": 16}, v4_audit)
    update_feature_variants("FROZEN" if v3_frozen else "REVIEW", "FROZEN" if v4_frozen else "REVIEW")
    status_counts = Counter(row["status"] for row in quality_rows)
    reused = int((mapping["cache_state_before"] == "CACHED").sum())
    downloaded = int((mapping["cache_state_before"] != "CACHED").sum())
    return {
        "required_vrp_files": len(mapping),
        "unique_snapshot_dates": mapping["observation_date"].nunique(),
        "reused_snapshot_files": reused,
        "newly_downloaded_snapshot_files": downloaded,
        "full_mrt_reparse_avoided": "YES",
        "compact_evidence_rows_evaluated": int(sum(row["evidence_rows"] for row in batch_rows)),
        "raw_observations_represented": int(sum(row["raw_observations_represented"] for row in batch_rows)),
        "rpki_feature_rows": len(rpki),
        "rpki_feature_count": len(RPKI_FEATURE_NAMES),
        "quality_status_counts": dict(status_counts),
        "v3_audit_status": v3_audit["overall_status"],
        "v4_audit_status": v4_audit["overall_status"],
        "v3_frozen": v3_frozen,
        "v4_frozen": v4_frozen,
        "outputs": [
            str(RPKI_SCHEMA),
            str(TRAIN_RPKI_MAPPING),
            str(TRAIN_RPKI_FEATURES),
            str(TRAIN_V3),
            str(TRAIN_V4),
            str(V1_V3_AUDIT),
            str(V2_V4_AUDIT),
            str(RPKI_QUALITY),
            str(RPKI_COVERAGE),
            str(V3_AUDIT),
            str(V4_AUDIT),
            str(FROZEN_V3),
            str(FROZEN_V4),
            str(NOTEBOOK),
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run full TRAIN RPKI/ROV enrichment from compact evidence")
    parser.add_argument("--run-full-train", action="store_true")
    args = parser.parse_args()
    if args.run_full_train:
        print(json.dumps(run_full_train(), indent=2, sort_keys=True))
        return
    parser.error("choose --run-full-train")


if __name__ == "__main__":
    main()
