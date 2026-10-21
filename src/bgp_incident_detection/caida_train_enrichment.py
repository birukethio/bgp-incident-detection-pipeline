from __future__ import annotations

import argparse
import bz2
import csv
import hashlib
import json
import math
import shutil
import subprocess
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pandas as pd

try:
    from bgp_incident_detection.audit import parse_utc, write_csv
    from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES
    from bgp_incident_detection.caida_features import (
        CAIDA_FEATURE_NAMES,
        CaidaWindowAggregate,
        caida_snapshot_name,
        caida_snapshot_url,
        feature_inventory_rows,
        features_from_caida_aggregate,
        load_relationships,
        parse_as_path,
        update_caida_aggregate_from_result,
        valley_free_result,
    )
    from bgp_incident_detection.full_train_execution import group_by
    from bgp_incident_detection.mrt_parser import parse_bgpdump_line
    from bgp_incident_detection.train_batch_engine import VOLUME_BATCH_PLAN, free_bytes, required_free_bytes, source_commit
    from bgp_incident_detection.train_incident_scale import ACQUISITION_PLAN, MANIFEST, compression_ok, copy_or_download, load_csv, relevance_targets, relevant_with_targets
    from bgp_incident_detection.windows import floor_to_five_minutes, format_utc, window_id
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import parse_utc, write_csv
    from src.bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES
    from src.bgp_incident_detection.caida_features import (
        CAIDA_FEATURE_NAMES,
        CaidaWindowAggregate,
        caida_snapshot_name,
        caida_snapshot_url,
        feature_inventory_rows,
        features_from_caida_aggregate,
        load_relationships,
        parse_as_path,
        update_caida_aggregate_from_result,
        valley_free_result,
    )
    from src.bgp_incident_detection.full_train_execution import group_by
    from src.bgp_incident_detection.mrt_parser import parse_bgpdump_line
    from src.bgp_incident_detection.train_batch_engine import VOLUME_BATCH_PLAN, free_bytes, required_free_bytes, source_commit
    from src.bgp_incident_detection.train_incident_scale import ACQUISITION_PLAN, MANIFEST, compression_ok, copy_or_download, load_csv, relevance_targets, relevant_with_targets
    from src.bgp_incident_detection.windows import floor_to_five_minutes, format_utc, window_id


FROZEN_TRAIN = Path("data/train_frozen/frozen_train_behavioral_corpus_v1.parquet")
FROZEN_TRAIN_V2 = Path("data/train_frozen/frozen_train_v2_behavioral_caida_v1.parquet")
CAIDA_SCHEMA = Path("config/caida_feature_schema_v1.yaml")
FEATURE_VARIANTS = Path("config/feature_variants_v1.yaml")
CAIDA_CACHE = Path("data/cache/caida_as_relationships")
CAIDA_ENRICHMENT_DIR = Path("data/enrichment/caida")
CAIDA_BATCH_DIR = CAIDA_ENRICHMENT_DIR / "train_features_v1"
EVIDENCE_DIR = Path("data/enrichment/evidence/train_v1")
EVIDENCE_MANIFEST = Path("data/enrichment/evidence/train_evidence_manifest_v1.csv")
SNAPSHOT_MAPPING = CAIDA_ENRICHMENT_DIR / "train_caida_snapshot_mapping_v1.csv"
SNAPSHOT_CACHE_AUDIT = CAIDA_ENRICHMENT_DIR / "train_caida_snapshot_cache_audit_v1.csv"
TRAIN_CAIDA_FEATURES = CAIDA_ENRICHMENT_DIR / "train_caida_features_v1.parquet"
TRAIN_ENRICHED_DIR = Path("data/train_enriched")
TRAIN_ENRICHED = TRAIN_ENRICHED_DIR / "train_behavioral_caida_v1.parquet"
INTEGRITY_AUDIT = TRAIN_ENRICHED_DIR / "v1_v2_behavioral_integrity_audit_v1.csv"
FEATURE_QUALITY = TRAIN_ENRICHED_DIR / "train_caida_feature_quality_audit_v1.csv"
RELATIONSHIP_COVERAGE = TRAIN_ENRICHED_DIR / "train_caida_relationship_coverage_v1.csv"
CORPUS_AUDIT = TRAIN_ENRICHED_DIR / "train_v2_caida_corpus_audit_v1.csv"
FROZEN_AUDIT = Path("data/train_frozen/frozen_train_v2_behavioral_caida_audit_v1.csv")
NOTEBOOK = Path("notebooks/35_full_train_caida_enrichment.ipynb")
RAW_BATCH_ROOT = Path("data/raw_mrt/caida_train_batches")
USER_AGENT = "bgp-incident-detection-pipeline/0.1"
PARSER_NAME = "bgpdump"
PARSER_COMMAND = "bgpdump -q -m <mrt_file>"
BEHAVIORAL_FEATURE_VERSION = "v1"
CAIDA_FEATURE_VERSION = "v1"

ID_COLUMNS = ["incident_uid", "incident_id", "category", "partition", "window_id", "window_start", "window_end", "temporal_status"]
V2_METADATA = {
    "train_corpus_version": "v2",
    "corpus_status": "FROZEN",
}


def safe_batch_path(batch_id: str, url: str) -> Path:
    return RAW_BATCH_ROOT / batch_id / Path(url).name


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def append_rows(path: Path, rows: list[dict[str, object]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    exists = path.exists() and path.stat().st_size > 0
    with path.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        if not exists:
            writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def load_frozen_train() -> pd.DataFrame:
    df = pd.read_parquet(FROZEN_TRAIN)
    if len(df) != 68031:
        raise ValueError(f"unexpected frozen TRAIN row count: {len(df)}")
    if df["incident_uid"].nunique() != 993:
        raise ValueError(f"unexpected frozen TRAIN incident count: {df['incident_uid'].nunique()}")
    if set(df["partition"].dropna().astype(str)) != {"train"}:
        raise ValueError("frozen TRAIN corpus contains non-train partitions")
    counts = Counter(df.drop_duplicates("incident_uid")["category"])
    if counts != {"Hijack": 331, "Leak": 331, "Outage": 331}:
        raise ValueError(f"unexpected frozen TRAIN class counts: {dict(counts)}")
    missing_behavioral = [feature for feature in BEHAVIORAL_FEATURE_NAMES if feature not in df.columns]
    if missing_behavioral:
        raise ValueError(f"missing frozen behavioral features: {missing_behavioral}")
    return df


def month_start(value: str) -> datetime:
    parsed = parse_utc(value)
    if not parsed:
        raise ValueError(f"invalid timestamp: {value}")
    return parsed.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def build_snapshot_mapping(windows: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, row in windows[["window_id", "incident_uid", "category", "window_start"]].iterrows():
        snapshot_dt = month_start(str(row["window_start"]))
        snapshot = caida_snapshot_name(snapshot_dt)
        rows.append(
            {
                "window_id": row["window_id"],
                "incident_uid": row["incident_uid"],
                "category": row["category"],
                "window_start": row["window_start"],
                "window_date": str(row["window_start"])[:10],
                "window_month": str(row["window_start"])[:7],
                "selected_caida_snapshot": snapshot,
                "selected_caida_snapshot_date": snapshot[:8],
                "mapping_type": "SAME_MONTH",
                "source_url": caida_snapshot_url(snapshot_dt),
            }
        )
    mapping = pd.DataFrame(rows)
    SNAPSHOT_MAPPING.parent.mkdir(parents=True, exist_ok=True)
    mapping.to_csv(SNAPSHOT_MAPPING, index=False)
    return mapping


def download_snapshot(snapshot: str, url: str) -> dict[str, object]:
    CAIDA_CACHE.mkdir(parents=True, exist_ok=True)
    destination = CAIDA_CACHE / snapshot
    started = time.perf_counter()
    if destination.exists() and destination.stat().st_size > 0 and compression_ok(destination):
        return {
            "snapshot_date": snapshot[:8],
            "snapshot_file": snapshot,
            "source_url": url,
            "local_path": str(destination),
            "checksum": sha256(destination),
            "download_timestamp": utc_now(),
            "status": "CACHED",
            "elapsed_seconds": 0,
        }
    request = Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(request, timeout=180.0) as response, destination.open("wb") as handle:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                handle.write(chunk)
    except (HTTPError, URLError, TimeoutError) as error:
        return {
            "snapshot_date": snapshot[:8],
            "snapshot_file": snapshot,
            "source_url": url,
            "local_path": str(destination),
            "checksum": "",
            "download_timestamp": utc_now(),
            "status": f"FAIL:{error}",
            "elapsed_seconds": round(time.perf_counter() - started, 3),
        }
    return {
        "snapshot_date": snapshot[:8],
        "snapshot_file": snapshot,
        "source_url": url,
        "local_path": str(destination),
        "checksum": sha256(destination),
        "download_timestamp": utc_now(),
        "status": "DOWNLOADED",
        "elapsed_seconds": round(time.perf_counter() - started, 3),
    }


def ensure_caida_snapshots(mapping: pd.DataFrame) -> dict[str, dict[tuple[str, str], str]]:
    snapshots = mapping.drop_duplicates("selected_caida_snapshot")[["selected_caida_snapshot", "source_url"]]
    audit_rows = []
    relationships = {}
    for _, row in snapshots.sort_values("selected_caida_snapshot").iterrows():
        snapshot = str(row["selected_caida_snapshot"])
        audit = download_snapshot(snapshot, str(row["source_url"]))
        audit_rows.append(audit)
        if str(audit["status"]).split(":", 1)[0] not in {"CACHED", "DOWNLOADED"}:
            continue
        relationships[snapshot] = load_relationships(Path(str(audit["local_path"])))
    write_csv(
        SNAPSHOT_CACHE_AUDIT,
        audit_rows,
        ["snapshot_date", "snapshot_file", "source_url", "local_path", "checksum", "download_timestamp", "status", "elapsed_seconds"],
    )
    if len(relationships) != len(snapshots):
        raise RuntimeError("not all required CAIDA snapshots are available")
    return relationships


def write_caida_schema() -> None:
    rows = feature_inventory_rows()
    lines = [
        "schema_version: v1",
        "feature_group: CAIDA AS-relationship",
        "source_inventory: data/enrichment/caida/caida_feature_inventory_v1.csv",
        "feature_count: 14",
        "row_grain: one row per frozen TRAIN 5-minute window_id",
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
                f"    zero_behavior: {json.dumps(row['zero_behavior'])}",
                f"    missing_behavior: {json.dumps(row['missing_behavior'])}",
            ]
        )
    CAIDA_SCHEMA.parent.mkdir(parents=True, exist_ok=True)
    CAIDA_SCHEMA.write_text("\n".join(lines) + "\n", encoding="utf-8")


def batch_feature_path(batch_id: str) -> Path:
    return CAIDA_BATCH_DIR / f"{batch_id}.parquet"


def train_batches() -> dict[str, list[str]]:
    rows = load_csv(VOLUME_BATCH_PLAN)
    if not rows:
        raise RuntimeError(f"missing volume batch plan: {VOLUME_BATCH_PLAN}")
    batches: dict[str, list[str]] = defaultdict(list)
    for row in rows:
        batches[row["volume_batch_id"]].append(row["incident_uid"])
    return {batch_id: sorted(set(uids)) for batch_id, uids in sorted(batches.items())}


def normalize_as_path_string(as_path: object) -> str:
    return " ".join(parse_as_path(as_path))


def evidence_key(parsed: dict[str, str], window: str, collector: str) -> tuple[str, str, str, str, str]:
    return (
        window,
        str(parsed.get("prefix", "") or ""),
        str(parsed.get("origin_asn", "") or ""),
        normalize_as_path_string(parsed.get("as_path", "")),
        collector,
    )


def evidence_batch_path(batch_id: str) -> Path:
    numeric = batch_id.rsplit("_", 1)[-1]
    return EVIDENCE_DIR / f"batch_{numeric}.parquet"


def evidence_rows_from_counts(
    evidence_counts: dict[tuple[str, str, str, str, str], int],
    evidence_source_files: dict[tuple[str, str, str, str, str], set[str]],
    window_meta: dict[str, dict[str, object]],
    batch_id: str,
) -> pd.DataFrame:
    rows = []
    commit = source_commit()
    for (wid, prefix, origin_asn, normalized_path, collector), count in evidence_counts.items():
        meta = window_meta[wid]
        rows.append(
            {
                "window_id": wid,
                "incident_uid": meta["incident_uid"],
                "window_start": meta["window_start"],
                "window_end": meta["window_end"],
                "prefix": prefix,
                "origin_asn": origin_asn,
                "normalized_as_path": normalized_path,
                "observation_count": count,
                "collector": collector,
                "source_mrt_count": len(evidence_source_files[(wid, prefix, origin_asn, normalized_path, collector)]),
                "processing_batch_id": batch_id,
                "parser": PARSER_NAME,
                "parser_command": PARSER_COMMAND,
                "source_commit": commit,
                "behavioral_feature_version": BEHAVIORAL_FEATURE_VERSION,
                "caida_feature_version": CAIDA_FEATURE_VERSION,
            }
        )
    return pd.DataFrame(rows)


def fast_relevance_prefilter(parts: list[str], target_asns: set[str], target_prefixes: set[str], leak_seg: list[str]) -> bool:
    prefix = parts[5].strip() if len(parts) > 5 else ""
    if prefix and prefix in target_prefixes:
        return True
    peer_asn = parts[4].strip() if len(parts) > 4 else ""
    as_path = parts[6] if len(parts) > 6 else ""
    parsed_path = parse_as_path(as_path)
    path_asns = set(parsed_path)
    origin_asn = parsed_path[-1] if parsed_path else ""
    if target_asns & (path_asns | {peer_asn, origin_asn}):
        return True
    if leak_seg and all(asn in path_asns for asn in leak_seg):
        return True
    return False


def recovery_override(row: dict[str, str]) -> dict[str, str]:
    if row.get("incident_uid") == "Outage:605" and row.get("mrt_timestamp", "").startswith("2023-10-17T06:00:00"):
        fixed = dict(row)
        fixed["routeviews_collector"] = "route-views.sg"
        fixed["collector"] = "route-views.sg"
        fixed["mrt_url"] = "https://archive.routeviews.org/route-views.sg/bgpdata/2023.10/UPDATES/updates.20231017.0600.bz2"
        fixed["local_path"] = "data/raw_mrt/train_recovery/Outage_605/route-views.sg/updates.20231017.0600.bz2"
        return fixed
    return row


def download_batch_files(batch_id: str, rows: list[dict[str, str]], workers: int = 8) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    from concurrent.futures import ThreadPoolExecutor, as_completed

    by_url: dict[str, dict[str, str]] = {}
    for row in rows:
        fixed = recovery_override(row)
        by_url.setdefault(fixed["mrt_url"], fixed)
    unique_inputs = []
    for url, row in sorted(by_url.items()):
        download_row = dict(row)
        download_row["batch_id"] = batch_id
        if Path(str(download_row.get("local_path", ""))).exists() and "train_recovery" in str(download_row.get("local_path", "")):
            pass
        else:
            download_row["local_path"] = str(safe_batch_path(batch_id, url))
        unique_inputs.append(download_row)

    unique_downloads: list[dict[str, object]] = []
    completed = 0
    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        futures = {executor.submit(copy_or_download, row): row for row in unique_inputs}
        for future in as_completed(futures):
            unique_downloads.append(future.result())
            completed += 1
            if completed == len(unique_inputs) or completed % 100 == 0:
                print(f"{batch_id} CAIDA enrichment downloaded/cached {completed} / {len(unique_inputs)} unique MRT files", flush=True)

    status_by_url = {str(row["mrt_url"]): row for row in unique_downloads}
    expanded = []
    for row in rows:
        fixed = recovery_override(row)
        status = status_by_url[fixed["mrt_url"]]
        expanded_row = dict(fixed)
        expanded_row.update(
            {
                "batch_id": batch_id,
                "local_path": status["local_path"],
                "download_status": status["download_status"],
                "file_size": status["file_size"],
                "checksum": status["checksum"],
                "download_seconds": status["download_seconds"],
            }
        )
        expanded.append(expanded_row)
    return unique_downloads, expanded


def aggregate_caida_batch(
    batch_id: str,
    batch_uids: list[str],
    frozen: pd.DataFrame,
    manifest_by_uid: dict[str, dict[str, str]],
    plan_rows: list[dict[str, str]],
    snapshot_by_window: dict[str, str],
    relationships_by_snapshot: dict[str, dict[tuple[str, str], str]],
    download_workers: int,
) -> dict[str, object]:
    started = time.perf_counter()
    windows = frozen[frozen["incident_uid"].isin(batch_uids)].copy()
    allowed_windows_by_uid = {uid: set(group["window_id"]) for uid, group in windows.groupby("incident_uid")}
    aggregates = {wid: CaidaWindowAggregate() for wid in windows["window_id"]}
    window_meta = {
        row["window_id"]: {
            "incident_uid": row["incident_uid"],
            "window_start": row["window_start"],
            "window_end": row["window_end"],
        }
        for _, row in windows[["window_id", "incident_uid", "window_start", "window_end"]].iterrows()
    }
    evidence_counts: dict[tuple[str, str, str, str, str], int] = defaultdict(int)
    evidence_source_files: dict[tuple[str, str, str, str, str], set[str]] = defaultdict(set)
    targets = {}
    for uid in batch_uids:
        target_asns, target_prefixes, leak_seg = relevance_targets(manifest_by_uid[uid])
        targets[uid] = {
            "target_asns": target_asns,
            "target_prefixes": target_prefixes,
            "leak_seg": leak_seg,
        }

    unique_downloads, expanded = download_batch_files(batch_id, plan_rows, workers=download_workers)
    rows_by_url = group_by([{key: str(value) for key, value in row.items()} for row in expanded], "mrt_url")
    result_cache: dict[tuple[str, str], object] = {}
    stats = {
        "raw_observations": 0,
        "relevant_observations": 0,
        "parse_failures": 0,
        "malformed_records": 0,
    }

    for file_index, (url, group) in enumerate(sorted(rows_by_url.items()), start=1):
        download_row = group[0]
        if download_row.get("download_status") not in {"200", "CACHED", "REUSED_FROM_PILOT"}:
            stats["parse_failures"] += 1
            continue
        path = Path(str(download_row["local_path"]))
        candidate_uids = sorted({row["incident_uid"] for row in group})
        slot_candidate_cache: dict[datetime, list[str]] = {}
        process = subprocess.Popen(["bgpdump", "-q", "-m", str(path)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert process.stdout is not None
        for line in process.stdout:
            parts = line.rstrip("\n").split("|")
            if len(parts) < 6:
                stats["malformed_records"] += 1
                continue
            try:
                raw_ts = datetime.fromtimestamp(float(parts[1]), tz=timezone.utc)
                raw_slot = floor_to_five_minutes(raw_ts)
            except (ValueError, OverflowError):
                stats["malformed_records"] += 1
                continue
            if raw_slot not in slot_candidate_cache:
                slot_candidate_cache[raw_slot] = [
                    uid for uid in candidate_uids if window_id(uid, raw_slot) in allowed_windows_by_uid.get(uid, set())
                ]
            slot_uids = slot_candidate_cache[raw_slot]
            if not slot_uids:
                continue
            stats["raw_observations"] += len(slot_uids)
            for uid in slot_uids:
                wid = window_id(uid, raw_slot)
                if not fast_relevance_prefilter(parts, targets[uid]["target_asns"], targets[uid]["target_prefixes"], targets[uid]["leak_seg"]):
                    continue
                parsed = parse_bgpdump_line(line, uid, path, str(download_row.get("routeviews_collector") or download_row.get("collector") or "route-views2"))
                if not parsed:
                    stats["malformed_records"] += 1
                    continue
                if not relevant_with_targets(parsed, targets[uid]["target_asns"], targets[uid]["target_prefixes"], targets[uid]["leak_seg"]):
                    continue
                stats["relevant_observations"] += 1
                collector = str(download_row.get("routeviews_collector") or download_row.get("collector") or "route-views2")
                key = evidence_key(parsed, wid, collector)
                evidence_counts[key] += 1
                evidence_source_files[key].add(path.name)
        stderr = process.stderr.read() if process.stderr else ""
        if process.wait() != 0:
            stats["parse_failures"] += 1
            if stderr:
                print(stderr, flush=True)
        if file_index == len(rows_by_url) or file_index % 100 == 0:
            print(f"{batch_id} CAIDA enrichment parsed {file_index} / {len(rows_by_url)} unique MRT files once", flush=True)

    evidence = evidence_rows_from_counts(evidence_counts, evidence_source_files, window_meta, batch_id)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    evidence.to_parquet(evidence_batch_path(batch_id), index=False)
    evidence_observation_total = int(evidence["observation_count"].sum()) if len(evidence) else 0
    if evidence_observation_total != stats["relevant_observations"]:
        raise RuntimeError(f"evidence observation count mismatch in {batch_id}")
    if len(evidence):
        for _, ev in evidence.iterrows():
            wid = str(ev["window_id"])
            count = int(ev["observation_count"])
            as_path = str(ev["normalized_as_path"] or "")
            if len(parse_as_path(as_path)) < 2:
                aggregates[wid].paths_with_no_as_path_count += count
                continue
            snapshot = snapshot_by_window[wid]
            cache_key = (snapshot, as_path)
            if cache_key not in result_cache:
                result_cache[cache_key] = valley_free_result(as_path, relationships_by_snapshot[snapshot])
            update_caida_aggregate_from_result(aggregates[wid], result_cache[cache_key], multiplicity=count)

    feature_rows = []
    for _, row in windows.sort_values(["incident_uid", "window_start"]).iterrows():
        values = features_from_caida_aggregate(aggregates[row["window_id"]])
        output = {column: row[column] for column in ID_COLUMNS if column in row}
        output["selected_caida_snapshot"] = snapshot_by_window[row["window_id"]]
        output.update(values)
        feature_rows.append(output)
    CAIDA_BATCH_DIR.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(feature_rows).to_parquet(batch_feature_path(batch_id), index=False)
    raw_dir = RAW_BATCH_ROOT / batch_id
    recovered = 0
    if raw_dir.exists():
        recovered = sum(member.stat().st_size for member in raw_dir.rglob("*") if member.is_file())
        shutil.rmtree(raw_dir)
    return {
        "batch_id": batch_id,
        "incident_count": len(batch_uids),
        "feature_rows": len(feature_rows),
        "unique_mrt_files": len(unique_downloads),
        "download_bytes": sum(int(row.get("file_size") or 0) for row in unique_downloads),
        "raw_observations": stats["raw_observations"],
        "relevant_observations": stats["relevant_observations"],
        "evidence_rows": len(evidence),
        "evidence_parquet_size_bytes": evidence_batch_path(batch_id).stat().st_size if evidence_batch_path(batch_id).exists() else 0,
        "evidence_status": "PASS" if evidence_batch_path(batch_id).exists() and evidence_observation_total == stats["relevant_observations"] else "FAIL",
        "parse_failures": stats["parse_failures"],
        "malformed_records": stats["malformed_records"],
        "disk_recovered_bytes": recovered,
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "status": "PASS" if stats["parse_failures"] == 0 else "REVIEW",
    }


def combine_caida_batches(expected_rows: int) -> pd.DataFrame:
    paths = sorted(CAIDA_BATCH_DIR.glob("volume_batch_*.parquet"))
    if not paths:
        raise RuntimeError("no CAIDA batch feature files found")
    df = pd.concat([pd.read_parquet(path) for path in paths], ignore_index=True)
    if len(df) != expected_rows:
        raise RuntimeError(f"expected {expected_rows} CAIDA rows, found {len(df)}")
    if df["window_id"].nunique() != expected_rows or df.duplicated("window_id").any():
        raise RuntimeError("CAIDA features must have exactly one row per frozen TRAIN window_id")
    TRAIN_CAIDA_FEATURES.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(TRAIN_CAIDA_FEATURES, index=False)
    return df


def write_quality_audit(features: pd.DataFrame) -> list[dict[str, object]]:
    rows = []
    row_count = len(features)
    for feature in CAIDA_FEATURE_NAMES:
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
        FEATURE_QUALITY,
        rows,
        ["feature_name", "row_count", "missing_count", "missing_rate", "zero_count", "zero_rate", "min", "median", "mean", "p95", "max", "unique_values", "constant", "sparse", "invalid", "status"],
    )
    return rows


def write_relationship_coverage(features: pd.DataFrame) -> None:
    rows = []
    for category, group in features.groupby("category"):
        obs = pd.to_numeric(group["caida_path_observation_count"], errors="coerce").fillna(0)
        unknown_paths = pd.to_numeric(group["caida_paths_with_unknown_relationship_count"], errors="coerce").fillna(0)
        transitions = pd.to_numeric(group["caida_unknown_relationship_transition_count"], errors="coerce").fillna(0)
        rows.append(
            {
                "category": category,
                "window_rows": len(group),
                "windows_with_caida_path_observations": int((obs > 0).sum()),
                "windows_without_caida_path_observations": int((obs == 0).sum()),
                "path_observation_total": int(obs.sum()),
                "paths_with_unknown_relationship_total": int(unknown_paths.sum()),
                "unknown_relationship_transition_total": int(transitions.sum()),
                "unknown_path_percent": round(unknown_paths.sum() / obs.sum() * 100, 3) if obs.sum() else "",
            }
        )
    write_csv(
        RELATIONSHIP_COVERAGE,
        rows,
        ["category", "window_rows", "windows_with_caida_path_observations", "windows_without_caida_path_observations", "path_observation_total", "paths_with_unknown_relationship_total", "unknown_relationship_transition_total", "unknown_path_percent"],
    )


def join_and_audit(frozen: pd.DataFrame, caida: pd.DataFrame, quality_rows: list[dict[str, object]]) -> tuple[pd.DataFrame, dict[str, object]]:
    caida_cols = ["window_id", "selected_caida_snapshot"] + CAIDA_FEATURE_NAMES
    enriched = frozen.merge(caida[caida_cols], on="window_id", how="left", validate="one_to_one")
    TRAIN_ENRICHED.parent.mkdir(parents=True, exist_ok=True)
    enriched.to_parquet(TRAIN_ENRICHED, index=False)

    integrity_rows = []
    unchanged = True
    for feature in BEHAVIORAL_FEATURE_NAMES:
        left = frozen[["window_id", feature]].sort_values("window_id").reset_index(drop=True)
        right = enriched[["window_id", feature]].sort_values("window_id").reset_index(drop=True)
        same = left.equals(right)
        unchanged = unchanged and same
        integrity_rows.append({"feature_name": feature, "behavioral_values_unchanged": str(same), "status": "PASS" if same else "FAIL"})
    write_csv(INTEGRITY_AUDIT, integrity_rows, ["feature_name", "behavioral_values_unchanged", "status"])

    class_counts = Counter(enriched["category"])
    incident_counts = Counter(enriched.drop_duplicates("incident_uid")["category"])
    missing_caida_rows = int(enriched[CAIDA_FEATURE_NAMES].isna().all(axis=1).sum())
    feature_count = len(BEHAVIORAL_FEATURE_NAMES) + len(CAIDA_FEATURE_NAMES)
    status = "PASS"
    notes = []
    if len(enriched) != 68031:
        status = "FAIL"
        notes.append("row count mismatch")
    if enriched["incident_uid"].nunique() != 993 or incident_counts != {"Hijack": 331, "Leak": 331, "Outage": 331}:
        status = "FAIL"
        notes.append("incident/class count mismatch")
    if missing_caida_rows:
        status = "FAIL"
        notes.append("some windows missing all CAIDA features")
    if not unchanged:
        status = "FAIL"
        notes.append("frozen behavioral features changed during join")
    if any(row["status"] == "FAIL" for row in quality_rows):
        status = "FAIL"
        notes.append("CAIDA feature quality failure")
    row = {
        "expected_rows": 68031,
        "observed_rows": len(enriched),
        "expected_incidents": 993,
        "observed_incidents": enriched["incident_uid"].nunique(),
        "hijack_rows": class_counts.get("Hijack", 0),
        "leak_rows": class_counts.get("Leak", 0),
        "outage_rows": class_counts.get("Outage", 0),
        "hijack_incidents": incident_counts.get("Hijack", 0),
        "leak_incidents": incident_counts.get("Leak", 0),
        "outage_incidents": incident_counts.get("Outage", 0),
        "behavioral_feature_count": len(BEHAVIORAL_FEATURE_NAMES),
        "caida_feature_count": len(CAIDA_FEATURE_NAMES),
        "total_model_feature_count": feature_count,
        "missing_caida_feature_rows": missing_caida_rows,
        "validation_holdout_contamination": str(set(enriched["partition"].astype(str)) - {"train"}),
        "overall_status": status,
        "notes": ";".join(notes),
        "source_commit": source_commit(),
        "audit_timestamp": utc_now(),
    }
    write_csv(
        CORPUS_AUDIT,
        [row],
        ["expected_rows", "observed_rows", "expected_incidents", "observed_incidents", "hijack_rows", "leak_rows", "outage_rows", "hijack_incidents", "leak_incidents", "outage_incidents", "behavioral_feature_count", "caida_feature_count", "total_model_feature_count", "missing_caida_feature_rows", "validation_holdout_contamination", "overall_status", "notes", "source_commit", "audit_timestamp"],
    )
    return enriched, row


def freeze_if_pass(enriched: pd.DataFrame, corpus_audit: dict[str, object]) -> bool:
    if corpus_audit.get("overall_status") != "PASS":
        return False
    frozen = enriched.copy()
    frozen["train_corpus_version"] = V2_METADATA["train_corpus_version"]
    frozen["corpus_status"] = V2_METADATA["corpus_status"]
    frozen["freeze_date"] = utc_now()
    frozen["source_commit"] = source_commit()
    FROZEN_TRAIN_V2.parent.mkdir(parents=True, exist_ok=True)
    frozen.to_parquet(FROZEN_TRAIN_V2, index=False)
    write_csv(
        FROZEN_AUDIT,
        [
            {
                "frozen_path": str(FROZEN_TRAIN_V2),
                "rows": len(frozen),
                "incidents": frozen["incident_uid"].nunique(),
                "behavioral_features": len(BEHAVIORAL_FEATURE_NAMES),
                "caida_features": len(CAIDA_FEATURE_NAMES),
                "total_model_features": len(BEHAVIORAL_FEATURE_NAMES) + len(CAIDA_FEATURE_NAMES),
                "status": "PASS",
                "freeze_date": frozen["freeze_date"].iloc[0],
                "source_commit": frozen["source_commit"].iloc[0],
            }
        ],
        ["frozen_path", "rows", "incidents", "behavioral_features", "caida_features", "total_model_features", "status", "freeze_date", "source_commit"],
    )
    return True


def update_feature_variants(status: str) -> None:
    FEATURE_VARIANTS.write_text(
        "\n".join(
            [
                "feature_variants_version: v1",
                "source: data/train_frozen/frozen_train_behavioral_corpus_v1.parquet",
                "notes: V1 Behavioral is frozen. V2 Behavioral+CAIDA is full-TRAIN verified/frozen only when the v2 corpus audit passes. RPKI/ROV inventories remain future controlled steps.",
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
                f"    status: {status}",
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


def write_notebook() -> None:
    NOTEBOOK.parent.mkdir(parents=True, exist_ok=True)
    notebook = {
        "cells": [
            {"cell_type": "markdown", "metadata": {}, "source": ["# Full TRAIN CAIDA Enrichment\n", "\n", "Controlled TRAIN-only V2 enrichment: 44 frozen behavioral features plus 14 CAIDA AS-relationship features. No Validation/Holdout, RPKI, Normal labeling, capping, weighting, ablation, or model training.\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["from bgp_incident_detection.caida_train_enrichment import preflight_summary\n", "preflight_summary()\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["from bgp_incident_detection.caida_train_enrichment import run_full_train_caida\n", "# run_full_train_caida(resume=True)  # Downloads/reparses TRAIN RouteViews MRT batch-by-batch when needed.\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["import pandas as pd\n", "pd.read_csv('../data/train_enriched/train_v2_caida_corpus_audit_v1.csv')\n"]},
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")


def write_evidence_store_doc() -> None:
    path = Path("docs/enrichment_evidence_store_v1.md")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "# Enrichment Evidence Store v1\n\n"
        "This dataset is the reusable compact evidence layer between RouteViews MRT parsing and enrichment feature calculation. "
        "It is generated during TRAIN-only streaming parses and is intended to prevent reparsing the full RouteViews MRT corpus for later CAIDA recalculation or RPKI/ROV enrichment.\n\n"
        "## Row Grain\n\n"
        "One row represents aggregated incident-relevant BGP evidence for one frozen 5-minute TRAIN window and one unique `(prefix, origin_asn, normalized_as_path, collector)` tuple. "
        "It is not one raw BGP UPDATE message and it is not one final model feature row. Repeated matching observations are collapsed into `observation_count`.\n\n"
        "## Schema\n\n"
        "- `window_id`: frozen TRAIN window identifier, unchanged from the V1 behavioral corpus.\n"
        "- `incident_uid`: source incident UID inherited from the frozen TRAIN corpus.\n"
        "- `window_start`, `window_end`: UTC 5-minute window bounds.\n"
        "- `prefix`: announced or withdrawn prefix/NLRI when available.\n"
        "- `origin_asn`: origin ASN extracted from the normalized AS_PATH when available.\n"
        "- `normalized_as_path`: numeric AS path with consecutive prepending collapsed.\n"
        "- `observation_count`: multiplicity of collapsed matching observations.\n"
        "- `collector`: RouteViews collector that produced the source evidence.\n"
        "- `source_mrt_count`: number of distinct MRT files contributing to the collapsed row.\n"
        "- `processing_batch_id`: volume-aware TRAIN processing batch.\n"
        "- `parser`, `parser_command`: parser provenance.\n"
        "- `source_commit`: code commit used to create the evidence file.\n"
        "- `behavioral_feature_version`, `caida_feature_version`: feature-version provenance.\n\n"
        "## Reuse\n\n"
        "CAIDA AS-relationship features use `normalized_as_path + window timestamp` to map AS transitions against the temporally selected CAIDA snapshot. "
        "Future RPKI/ROV enrichment can use the same evidence store because ROA validation is driven by `timestamp/window + prefix + origin_asn`. "
        "RPKI/ROV features are not created in this step.\n\n"
        "## Partition Boundary\n\n"
        "The evidence store is TRAIN-only for this phase. Validation and Final Holdout incidents are not accessed.\n",
        encoding="utf-8",
    )


def preflight_summary() -> dict[str, object]:
    frozen = load_frozen_train()
    months = sorted(pd.to_datetime(frozen["window_start"], utc=True).dt.strftime("%Y%m01").unique().tolist())
    plan = load_csv(ACQUISITION_PLAN)
    batches = train_batches()
    unique_urls = {row["mrt_url"]: int(row.get("estimated_content_length") or 0) for row in plan}
    return {
        "required_caida_snapshot_count": len(months),
        "required_caida_snapshots": months,
        "as_path_source_availability": "REQUIRES_REGENERATION_FROM_TRAIN_MRT_PLAN",
        "reason": "frozen behavioral corpus contains 44 behavioral features and window IDs, not raw AS_PATH observations",
        "expected_train_windows": len(frozen),
        "expected_train_incidents": frozen["incident_uid"].nunique(),
        "expected_behavioral_features": len(BEHAVIORAL_FEATURE_NAMES),
        "expected_caida_features": len(CAIDA_FEATURE_NAMES),
        "expected_v2_model_features": len(BEHAVIORAL_FEATURE_NAMES) + len(CAIDA_FEATURE_NAMES),
        "acquisition_plan_rows": len(plan),
        "unique_routeviews_urls": len(unique_urls),
        "volume_batch_count": len(batches),
        "estimated_unique_compressed_routeviews_bytes": sum(unique_urls.values()),
        "current_free_bytes": free_bytes(Path(".")),
        "largest_batch_required_free_bytes": max(
            required_free_bytes(sum({row["mrt_url"]: int(row.get("estimated_content_length") or 0) for row in plan if row["incident_uid"] in set(uids)}.values()))
            for uids in batches.values()
        ),
    }


def run_full_train_caida(resume: bool = True, max_batches: int | None = None, download_workers: int = 8) -> dict[str, object]:
    write_notebook()
    write_caida_schema()
    write_evidence_store_doc()
    frozen = load_frozen_train()
    mapping = build_snapshot_mapping(frozen)
    relationships_by_snapshot = ensure_caida_snapshots(mapping)
    snapshot_by_window = dict(zip(mapping["window_id"], mapping["selected_caida_snapshot"]))
    manifest_rows = load_csv(MANIFEST)
    manifest_by_uid = {row["incident_uid"]: row for row in manifest_rows}
    plan_by_uid = group_by([recovery_override(row) for row in load_csv(ACQUISITION_PLAN)], "incident_uid")
    batches = train_batches()
    batch_ids = sorted(batches)
    if max_batches is not None:
        batch_ids = batch_ids[:max_batches]

    batch_summary_fields = ["batch_id", "incident_count", "feature_rows", "unique_mrt_files", "download_bytes", "raw_observations", "relevant_observations", "evidence_rows", "evidence_parquet_size_bytes", "evidence_status", "parse_failures", "malformed_records", "disk_recovered_bytes", "elapsed_seconds", "status"]
    batch_summary_path = CAIDA_ENRICHMENT_DIR / "train_caida_batch_execution_summary_v1.csv"
    if not resume and batch_summary_path.exists():
        batch_summary_path.unlink()
    summaries = []
    for batch_id in batch_ids:
        feature_exists = batch_feature_path(batch_id).exists() and batch_feature_path(batch_id).stat().st_size > 0
        evidence_exists = evidence_batch_path(batch_id).exists() and evidence_batch_path(batch_id).stat().st_size > 0
        if resume and feature_exists and evidence_exists:
            print(f"{batch_id} CAIDA features/evidence already exist; skipping", flush=True)
            continue
        uids = batches[batch_id]
        rows = [row for uid in uids for row in plan_by_uid.get(uid, [])]
        summary = aggregate_caida_batch(batch_id, uids, frozen, manifest_by_uid, rows, snapshot_by_window, relationships_by_snapshot, download_workers)
        append_rows(batch_summary_path, [summary], batch_summary_fields)
        append_rows(
            EVIDENCE_MANIFEST,
            [
                {
                    "batch_id": batch_id,
                    "incident_count": summary["incident_count"],
                    "window_count": summary["feature_rows"],
                    "raw_relevant_observations": summary["relevant_observations"],
                    "evidence_rows": summary["evidence_rows"],
                    "parquet_size_bytes": summary["evidence_parquet_size_bytes"],
                    "status": summary["evidence_status"],
                }
            ],
            ["batch_id", "incident_count", "window_count", "raw_relevant_observations", "evidence_rows", "parquet_size_bytes", "status"],
        )
        summaries.append(summary)
        if summary["status"] == "FAIL":
            raise RuntimeError(f"stopping after CAIDA batch failure: {batch_id}")

    all_expected_batches = sorted(batches)
    completed_batch_files = [batch_feature_path(batch_id) for batch_id in all_expected_batches if batch_feature_path(batch_id).exists()]
    if len(completed_batch_files) < len(all_expected_batches):
        return {
            "partial_run": True,
            "completed_batch_count": len(completed_batch_files),
            "expected_batch_count": len(all_expected_batches),
            "new_batch_summaries": summaries,
            "batch_summaries_written": str(batch_summary_path),
            "evidence_manifest": str(EVIDENCE_MANIFEST),
            "note": "Full V2 corpus assembly/freeze waits until every TRAIN CAIDA batch exists.",
        }

    caida_features = combine_caida_batches(len(frozen))
    quality = write_quality_audit(caida_features)
    write_relationship_coverage(caida_features)
    enriched, corpus = join_and_audit(frozen, caida_features, quality)
    frozen_written = freeze_if_pass(enriched, corpus)
    update_feature_variants("FULL_TRAIN_VERIFIED_FROZEN" if frozen_written else "FULL_TRAIN_REVIEW")
    return {
        "caida_snapshot_count": mapping["selected_caida_snapshot"].nunique(),
        "train_windows": len(caida_features),
        "train_incidents": caida_features["incident_uid"].nunique(),
        "caida_feature_count": len(CAIDA_FEATURE_NAMES),
        "v2_model_feature_count": len(BEHAVIORAL_FEATURE_NAMES) + len(CAIDA_FEATURE_NAMES),
        "corpus_audit_status": corpus["overall_status"],
        "frozen_v2_written": frozen_written,
        "batch_summaries_written": str(batch_summary_path),
        "outputs": [
            str(CAIDA_SCHEMA),
            str(SNAPSHOT_MAPPING),
            str(SNAPSHOT_CACHE_AUDIT),
            str(TRAIN_CAIDA_FEATURES),
            str(TRAIN_ENRICHED),
            str(INTEGRITY_AUDIT),
            str(FEATURE_QUALITY),
            str(RELATIONSHIP_COVERAGE),
            str(CORPUS_AUDIT),
            str(FROZEN_TRAIN_V2) if frozen_written else "",
            str(NOTEBOOK),
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Full TRAIN-only CAIDA enrichment for frozen behavioral corpus")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--no-resume", action="store_true")
    parser.add_argument("--max-batches", type=int)
    parser.add_argument("--download-workers", type=int, default=8)
    args = parser.parse_args()
    if args.preflight:
        print(json.dumps(preflight_summary(), indent=2, sort_keys=True))
        return
    if args.run:
        print(json.dumps(run_full_train_caida(resume=not args.no_resume, max_batches=args.max_batches, download_workers=args.download_workers), indent=2, sort_keys=True))
        return
    parser.error("choose --preflight or --run")


if __name__ == "__main__":
    main()
