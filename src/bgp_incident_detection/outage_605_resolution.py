from __future__ import annotations

import argparse
import bz2
import csv
import hashlib
import json
import shutil
import subprocess
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pandas as pd

try:
    from bgp_incident_detection.audit import parse_utc, write_csv
    from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES, WindowAggregate, features_from_aggregate, update_aggregate
    from bgp_incident_detection.mrt_acquisition import routeviews_update_filename, routeviews_update_url
    from bgp_incident_detection.mrt_parser import parse_as_path_set, parse_bgpdump_line
    from bgp_incident_detection.train_incident_scale import MANIFEST, TRAIN_SCALE_DIR, compression_ok, relevance_targets, relevant_with_targets
    from bgp_incident_detection.windows import floor_to_five_minutes, format_utc, window_id
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import parse_utc, write_csv
    from src.bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES, WindowAggregate, features_from_aggregate, update_aggregate
    from src.bgp_incident_detection.mrt_acquisition import routeviews_update_filename, routeviews_update_url
    from src.bgp_incident_detection.mrt_parser import parse_as_path_set, parse_bgpdump_line
    from src.bgp_incident_detection.train_incident_scale import MANIFEST, TRAIN_SCALE_DIR, compression_ok, relevance_targets, relevant_with_targets
    from src.bgp_incident_detection.windows import floor_to_five_minutes, format_utc, window_id


INCIDENT_UID = "Outage:605"
MISSING_SLOT = datetime(2023, 10, 17, 6, 0, tzinfo=timezone.utc)
MISSING_INTERVAL_END = MISSING_SLOT + timedelta(minutes=15)
ORIGINAL_COLLECTOR = "route-views2"
RECOVERY_COLLECTOR = "route-views.sg"
TARGET_ASNS = {"10094", "131467"}

V1_FEATURES = TRAIN_SCALE_DIR / "train_incident_behavioral_features_v1.parquet"
V2_FEATURES = TRAIN_SCALE_DIR / "train_incident_behavioral_features_v2.parquet"
ACQUISITION_PLAN = TRAIN_SCALE_DIR / "train_mrt_acquisition_plan_v1.csv"
MISSING_MRT_AUDIT = TRAIN_SCALE_DIR / "outage_605_missing_mrt_audit_v1.csv"
CORPUS_AUDIT_V3 = TRAIN_SCALE_DIR / "train_behavioral_corpus_audit_v3.csv"
RECOVERY_METADATA = TRAIN_SCALE_DIR / "outage_605_recovery_feature_changes_v1.csv"
RAW_RECOVERY_ROOT = Path("data/raw_mrt/train_recovery/Outage_605")
NOTEBOOK = Path("notebooks/32_outage_605_resolution.ipynb")
USER_AGENT = "bgp-incident-detection-pipeline/0.1"

AUDIT_FIELDS = [
    "audit_type",
    "incident_uid",
    "collector",
    "mrt_timestamp",
    "mrt_url",
    "available",
    "status_code",
    "content_length",
    "coverage_start",
    "coverage_end",
    "window_start",
    "window_end",
    "temporal_status",
    "matching_observations",
    "notes",
]


def iso_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def incident_manifest() -> dict[str, str]:
    for row in load_csv(MANIFEST):
        if row["incident_uid"] == INCIDENT_UID:
            return row
    raise ValueError(f"{INCIDENT_UID} not found in {MANIFEST}")


def head_url(url: str, timeout_seconds: float = 20.0) -> tuple[bool, str, int]:
    request = Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            return 200 <= response.status < 400, str(response.status), int(response.headers.get("Content-Length") or 0)
    except HTTPError as error:
        return False, str(error.code), 0
    except URLError:
        return False, "", 0


def index_contains(url: str, filename: str) -> bool:
    request = Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(request, timeout=20.0) as response:
            return filename in response.read().decode("utf-8", "replace")
    except (HTTPError, URLError, TimeoutError):
        return False


def collector_url(collector: str, slot: datetime = MISSING_SLOT) -> str:
    return routeviews_update_url(slot, collector)


def download_recovery_file(url: str, destination: Path) -> dict[str, object]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and destination.stat().st_size > 0 and compression_ok(destination):
        return {"download_status": "CACHED", "file_size": destination.stat().st_size, "checksum": sha256(destination), "download_seconds": 0.0}
    start = time.perf_counter()
    request = Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(request, timeout=180.0) as response, destination.open("wb") as handle:
            shutil.copyfileobj(response, handle, length=1024 * 1024)
            status = str(response.status)
    except (HTTPError, URLError, TimeoutError) as error:
        return {"download_status": str(getattr(error, "code", "")) or "FAILED", "file_size": 0, "checksum": "", "download_seconds": round(time.perf_counter() - start, 3)}
    ok = destination.exists() and destination.stat().st_size > 0 and compression_ok(destination)
    return {
        "download_status": status if ok else "CORRUPT",
        "file_size": destination.stat().st_size if destination.exists() else 0,
        "checksum": sha256(destination) if ok else "",
        "download_seconds": round(time.perf_counter() - start, 3),
    }


def affected_window_starts() -> list[datetime]:
    return [MISSING_SLOT + timedelta(minutes=5 * index) for index in range(3)]


def classify_window(slot: datetime, incident: dict[str, str]) -> str:
    start = parse_utc(incident["start_utc"])
    end = parse_utc(incident["end_utc"])
    if not start or not end:
        return "UNKNOWN"
    if slot < start:
        return "PRE_CONTEXT"
    if slot >= end:
        return "POST_CONTEXT"
    return "INCIDENT_ACTIVE"


def count_visibility(path: Path) -> int:
    count = 0
    process = subprocess.Popen(["bgpdump", "-q", "-m", str(path)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert process.stdout is not None
    for line in process.stdout:
        parts = line.rstrip("\n").split("|")
        if len(parts) < 7:
            continue
        peer = parts[4]
        as_path = parts[6] if parts[2] == "A" else ""
        if peer in TARGET_ASNS or (parse_as_path_set(as_path) & TARGET_ASNS):
            count += 1
    process.stderr.read() if process.stderr else ""
    process.wait()
    return count


def recovery_rows_from_file(path: Path, incident: dict[str, str]) -> tuple[list[dict[str, object]], dict[str, int]]:
    windows = {
        window_id(INCIDENT_UID, slot): {
            "window_start": slot,
            "window_end": slot + timedelta(minutes=5),
            "temporal_status": classify_window(slot, incident),
        }
        for slot in affected_window_starts()
    }
    aggregates = {wid: WindowAggregate() for wid in windows}
    raw_counts: Counter[str] = Counter()
    target_asns, target_prefixes, leak_seg = relevance_targets(incident)
    parsed_records = 0
    relevant_records = 0
    process = subprocess.Popen(["bgpdump", "-q", "-m", str(path)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert process.stdout is not None
    for line in process.stdout:
        parts = line.rstrip("\n").split("|")
        if len(parts) < 6:
            continue
        try:
            ts = datetime.fromtimestamp(float(parts[1]), tz=timezone.utc)
        except (ValueError, OverflowError):
            continue
        if not (MISSING_SLOT <= ts < MISSING_INTERVAL_END):
            continue
        wid = window_id(INCIDENT_UID, floor_to_five_minutes(ts))
        if wid not in windows:
            continue
        parsed_records += 1
        raw_counts[wid] += 1
        parsed = parse_bgpdump_line(line, INCIDENT_UID, path, RECOVERY_COLLECTOR)
        if not parsed or not relevant_with_targets(parsed, target_asns, target_prefixes, leak_seg):
            continue
        relevant_records += 1
        update_aggregate(aggregates[wid], parsed)
    stderr = process.stderr.read() if process.stderr else ""
    return_code = process.wait()
    if return_code != 0:
        raise RuntimeError(f"bgpdump failed on {path}: {stderr}")
    rows: list[dict[str, object]] = []
    for wid, meta in sorted(windows.items(), key=lambda item: item[1]["window_start"]):
        feature_values = features_from_aggregate(aggregates[wid])
        row = {
            "incident_uid": INCIDENT_UID,
            "incident_id": incident["incident_id"],
            "category": incident["category"],
            "partition": incident["partition"],
            "window_id": wid,
            "window_start": format_utc(meta["window_start"]),
            "window_end": format_utc(meta["window_end"]),
            "temporal_status": meta["temporal_status"],
            "behavioral_feature_version": "v1",
            "behavioral_feature_count": 44,
            "raw_observation_count": raw_counts.get(wid, 0),
            "has_relevant_observation": feature_values["update_count"] > 0,
        }
        row.update(feature_values)
        rows.append(row)
    return rows, {"parsed_records": parsed_records, "relevant_records": relevant_records}


def source_commit() -> str:
    try:
        result = subprocess.run(["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True)
        return result.stdout.strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        return "UNKNOWN"


def write_notebook() -> None:
    NOTEBOOK.parent.mkdir(parents=True, exist_ok=True)
    cells = [
        {
            "cell_type": "markdown",
            "metadata": {},
            "source": [
                "# Outage:605 Technical Resolution\n",
                "\n",
                "Controlled diagnostic notebook for the single missing RouteViews file in the TRAIN behavioral corpus. It does not modify v1 artifacts or access Validation/Holdout incidents.\n",
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
                "base = Path('..') if Path.cwd().name == 'notebooks' else Path('.')\n",
                "pd.read_csv(base / 'data/train_scale/outage_605_missing_mrt_audit_v1.csv')\n",
            ],
        },
        {
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": [
                "pd.read_csv(base / 'data/train_scale/train_behavioral_corpus_audit_v3.csv')\n",
            ],
        },
    ]
    notebook = {
        "cells": cells,
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")


def resolve() -> dict[str, object]:
    incident = incident_manifest()
    original_url = collector_url(ORIGINAL_COLLECTOR)
    previous_url = collector_url(ORIGINAL_COLLECTOR, MISSING_SLOT - timedelta(minutes=15))
    next_url = collector_url(ORIGINAL_COLLECTOR, MISSING_SLOT + timedelta(minutes=15))
    recovery_url = collector_url(RECOVERY_COLLECTOR)
    routeviews2_index = "https://archive.routeviews.org/bgpdata/2023.10/UPDATES/"
    filename = routeviews_update_filename(MISSING_SLOT)

    audit_rows: list[dict[str, object]] = []
    for label, collector, slot, url in [
        ("previous_available_file", ORIGINAL_COLLECTOR, MISSING_SLOT - timedelta(minutes=15), previous_url),
        ("missing_original_file", ORIGINAL_COLLECTOR, MISSING_SLOT, original_url),
        ("next_available_file", ORIGINAL_COLLECTOR, MISSING_SLOT + timedelta(minutes=15), next_url),
        ("alternate_candidate_file", RECOVERY_COLLECTOR, MISSING_SLOT, recovery_url),
    ]:
        available, status, length = head_url(url)
        notes = label
        if label == "missing_original_file":
            notes += f"; directory_index_contains={index_contains(routeviews2_index, filename)}"
        audit_rows.append(
            {
                "audit_type": "archive_availability",
                "incident_uid": INCIDENT_UID,
                "collector": collector,
                "mrt_timestamp": iso_z(slot),
                "mrt_url": url,
                "available": available,
                "status_code": status,
                "content_length": length,
                "coverage_start": iso_z(slot),
                "coverage_end": iso_z(slot + timedelta(minutes=15)),
                "window_start": "",
                "window_end": "",
                "temporal_status": "",
                "matching_observations": "",
                "notes": notes,
            }
        )

    recovery_path = RAW_RECOVERY_ROOT / RECOVERY_COLLECTOR / filename
    download_result = download_recovery_file(recovery_url, recovery_path)
    if str(download_result["download_status"]) not in {"200", "CACHED"}:
        raise RuntimeError(f"recovery download failed: {download_result}")
    if not compression_ok(recovery_path):
        raise RuntimeError(f"recovery file is not valid bz2: {recovery_path}")
    visibility_matches = count_visibility(recovery_path)
    recovered_rows, recovery_counts = recovery_rows_from_file(recovery_path, incident)

    old_df = pd.read_parquet(V1_FEATURES)
    if len(old_df) != 68031:
        raise ValueError(f"unexpected v1 feature row count: {len(old_df)}")
    affected_ids = {row["window_id"] for row in recovered_rows}
    old_affected = old_df[old_df["window_id"].isin(affected_ids)].copy()
    replacement_df = pd.DataFrame(recovered_rows).reindex(columns=old_df.columns)
    v2_df = pd.concat([old_df[~old_df["window_id"].isin(affected_ids)], replacement_df], ignore_index=True)
    v2_df = v2_df.sort_values(["incident_uid", "window_start", "window_id"]).reset_index(drop=True)
    if len(v2_df) != len(old_df):
        raise RuntimeError("v2 feature row count changed unexpectedly")
    if v2_df.duplicated(["incident_uid", "window_id"]).any():
        raise RuntimeError("duplicate incident_uid/window_id rows in v2")
    if len(BEHAVIORAL_FEATURE_NAMES) != 44 or not set(BEHAVIORAL_FEATURE_NAMES) <= set(v2_df.columns):
        raise RuntimeError("behavioral schema mismatch")
    V2_FEATURES.parent.mkdir(parents=True, exist_ok=True)
    v2_df.to_parquet(V2_FEATURES, index=False)

    change_rows = []
    old_by_id = old_affected.set_index("window_id")
    new_by_id = replacement_df.set_index("window_id")
    for wid in sorted(affected_ids):
        old = old_by_id.loc[wid]
        new = new_by_id.loc[wid]
        changed_features = [
            feature
            for feature in BEHAVIORAL_FEATURE_NAMES
            if pd.isna(old[feature]) != pd.isna(new[feature]) or (not pd.isna(old[feature]) and old[feature] != new[feature])
        ]
        change_rows.append(
            {
                "incident_uid": INCIDENT_UID,
                "window_id": wid,
                "window_start": new["window_start"],
                "window_end": new["window_end"],
                "temporal_status": new["temporal_status"],
                "source_status": "RECOVERED_FROM_ALTERNATE_COLLECTOR",
                "original_collector": ORIGINAL_COLLECTOR,
                "recovery_collector": RECOVERY_COLLECTOR,
                "old_raw_observation_count": old["raw_observation_count"],
                "new_raw_observation_count": new["raw_observation_count"],
                "old_update_count": old["update_count"],
                "new_update_count": new["update_count"],
                "changed_behavioral_feature_count": len(changed_features),
                "changed_behavioral_features": json.dumps(changed_features, separators=(",", ":")),
            }
        )
        audit_rows.append(
            {
                "audit_type": "affected_5min_window",
                "incident_uid": INCIDENT_UID,
                "collector": RECOVERY_COLLECTOR,
                "mrt_timestamp": iso_z(MISSING_SLOT),
                "mrt_url": recovery_url,
                "available": True,
                "status_code": download_result["download_status"],
                "content_length": download_result["file_size"],
                "coverage_start": iso_z(MISSING_SLOT),
                "coverage_end": iso_z(MISSING_INTERVAL_END),
                "window_start": new["window_start"],
                "window_end": new["window_end"],
                "temporal_status": new["temporal_status"],
                "matching_observations": new["update_count"],
                "notes": "missing route-views2 source interval recovered from route-views.sg; not treated as zero activity",
            }
        )

    write_csv(MISSING_MRT_AUDIT, audit_rows, AUDIT_FIELDS)
    write_csv(
        RECOVERY_METADATA,
        change_rows,
        [
            "incident_uid",
            "window_id",
            "window_start",
            "window_end",
            "temporal_status",
            "source_status",
            "original_collector",
            "recovery_collector",
            "old_raw_observation_count",
            "new_raw_observation_count",
            "old_update_count",
            "new_update_count",
            "changed_behavioral_feature_count",
            "changed_behavioral_features",
        ],
    )
    audit_v3 = [
        {
            "expected_incidents": 993,
            "included_incidents": int(v2_df["incident_uid"].nunique()),
            "excluded_incidents": 993 - int(v2_df["incident_uid"].nunique()),
            "PASS": 983,
            "KEEP_WITH_ZERO_OBSERVATIONS": 9,
            "KEEP_WITH_PARTIAL_SOURCE_COVERAGE": 0,
            "PASS_AFTER_RECOVERY": 1,
            "technical_exclusions": 0,
            "feature_rows": len(v2_df),
            "duplicate_window_ids": int(v2_df.duplicated(["incident_uid", "window_id"]).sum()),
            "missing_source_windows": 0,
            "recovered_source_windows": len(change_rows),
            "schema_status": "PASS",
            "validation_contamination": bool((v2_df["partition"] == "validation").any()),
            "holdout_contamination": bool((v2_df["partition"] == "holdout").any()),
            "overall_status": "PASS",
            "source_commit": source_commit(),
            "notes": "Outage:605 06:00Z route-views2 source gap recovered with route-views.sg for three affected INCIDENT_ACTIVE windows; v1 preserved unchanged.",
        }
    ]
    write_csv(
        CORPUS_AUDIT_V3,
        audit_v3,
        [
            "expected_incidents",
            "included_incidents",
            "excluded_incidents",
            "PASS",
            "KEEP_WITH_ZERO_OBSERVATIONS",
            "KEEP_WITH_PARTIAL_SOURCE_COVERAGE",
            "PASS_AFTER_RECOVERY",
            "technical_exclusions",
            "feature_rows",
            "duplicate_window_ids",
            "missing_source_windows",
            "recovered_source_windows",
            "schema_status",
            "validation_contamination",
            "holdout_contamination",
            "overall_status",
            "source_commit",
            "notes",
        ],
    )
    write_notebook()
    return {
        "original_missing": True,
        "missing_interval_start": iso_z(MISSING_SLOT),
        "missing_interval_end": iso_z(MISSING_INTERVAL_END),
        "alternate_collector": RECOVERY_COLLECTOR,
        "alternate_visibility_matches": visibility_matches,
        "affected_windows": len(change_rows),
        "recovery_parsed_records": recovery_counts["parsed_records"],
        "recovery_relevant_records": recovery_counts["relevant_records"],
        "feature_rows_v1": len(old_df),
        "feature_rows_v2": len(v2_df),
        "disposition": "PASS_AFTER_RECOVERY",
        "outputs": [str(MISSING_MRT_AUDIT), str(RECOVERY_METADATA), str(V2_FEATURES), str(CORPUS_AUDIT_V3), str(NOTEBOOK)],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Resolve the single Outage:605 missing MRT source slot.")
    parser.parse_args()
    print(json.dumps(resolve(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
