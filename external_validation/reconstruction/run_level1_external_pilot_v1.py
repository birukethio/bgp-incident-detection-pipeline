from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import re
import shutil
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import joblib
import numpy as np
import pandas as pd

from src.bgp_incident_detection.audit import parse_utc
from src.bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES
from src.bgp_incident_detection.caida_features import (
    CAIDA_FEATURE_NAMES,
    aggregate_rows as aggregate_caida_rows,
    caida_snapshot_name,
    caida_snapshot_url,
    load_relationships,
)
from src.bgp_incident_detection.mrt_acquisition import (
    ceil_to_15_minutes,
    floor_to_15_minutes,
    iter_update_slots,
    routeviews_update_filename,
    routeviews_update_url,
)
from src.bgp_incident_detection.rpki_features import (
    RPKI_FEATURE_NAMES,
    STATE_TO_CODE,
    TRUST_ANCHORS,
    build_vrp_index,
    cache_path as rpki_cache_path,
    load_vrps,
    snapshot_url as rpki_snapshot_url,
    validate_rov,
)
import src.bgp_incident_detection.train_incident_scale as frozen


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "external_validation/reconstruction/pilot_v1"
RAW = OUT / "raw_mrt"
PARSED = OUT / "parsed"
CAIDA_CACHE = ROOT / "data/cache/caida/as_relationships/serial-2"
MODEL_DIR = ROOT / "data/tti_pilot/reconstructed_level1_v1"
MANIFEST = ROOT / "external_validation/pilot/external_reconstruction_pilot_manifest_v1.csv"
GATE = ROOT / "external_validation/pilot/pilot_timestamp_normalization_gate_v1.csv"
COLLECTOR = "route-views2"
USER_AGENT = "bgp-incident-detection-pipeline/external-pilot-v1"
LABELS = ["Hijack", "Leak", "Outage"]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_csv(path: Path, rows: list[dict], fields: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fields is None:
        fields = list(rows[0]) if rows else []
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def extract_asns(*values: object) -> list[str]:
    output: list[str] = []
    for value in values:
        for token in re.findall(r"\bAS\s*\(?([0-9]{1,10})\)?", str(value or ""), flags=re.I):
            if token not in output:
                output.append(token)
    return output


def extract_prefixes(value: object) -> list[str]:
    output: list[str] = []
    for token in re.findall(r"[0-9A-Fa-f:.]+/[0-9]{1,3}", str(value or "")):
        try:
            prefix = str(ipaddress.ip_network(token, strict=False))
        except ValueError:
            continue
        if prefix not in output:
            output.append(prefix)
    return output


def load_incidents() -> tuple[list[dict], list[dict]]:
    candidates = {row["candidate_id"]: row for row in csv.DictReader(MANIFEST.open(encoding="utf-8"))}
    gates = list(csv.DictReader(GATE.open(encoding="utf-8")))
    passed: list[dict] = []
    review: list[dict] = []
    for gate in gates:
        source = candidates[gate["candidate_id"]]
        if gate["timestamp_gate"] != "PASS":
            review.append({**gate, "reconstruction_status": "EXCLUDED_TIMESTAMP_REVIEW"})
            continue
        category = source["iec_label"]
        asns = extract_asns(source.get("affected_asn"), source.get("origin_asn_where_applicable"))
        prefixes = extract_prefixes(source.get("prefixes_available_from_source"))
        passed.append(
            {
                "incident_uid": gate["candidate_id"],
                "incident_id": gate["candidate_id"],
                "category": category,
                "partition": "EXTERNAL_ENGINEERING_PILOT",
                "start_utc": gate["normalized_start_utc"],
                "end_utc": gate["normalized_end_utc"],
                "affected_asns": json.dumps(asns),
                "affected_prefixes": json.dumps(prefixes),
                "primary_asn": asns[0] if asns else "",
                "leak_asn": asns[0] if category == "Leak" and asns else "",
                "leak_seg": json.dumps(asns[:3] if category == "Leak" else []),
                "source_url": source.get("primary_source_url_or_reference", ""),
                "timestamp_gate": "PASS",
            }
        )
    if len(passed) != 8 or Counter(row["category"] for row in passed) != {"Hijack": 2, "Leak": 3, "Outage": 3}:
        raise RuntimeError("pilot gate does not resolve to exactly 8 PASS incidents (2/3/3)")
    if {row["candidate_id"] for row in review} != {"V2-HIJACK-008"}:
        raise RuntimeError("unexpected timestamp REVIEW membership")
    return passed, review


def acquisition_plan(incidents: list[dict]) -> list[dict]:
    rows: list[dict] = []
    for incident in incidents:
        seen: set[str] = set()
        for segment_id, start, end, note in frozen.active_segments(incident):
            collection_start = floor_to_15_minutes(start - timedelta(minutes=frozen.CONTEXT_BUFFER_MINUTES))
            collection_end = ceil_to_15_minutes(end + timedelta(minutes=frozen.CONTEXT_BUFFER_MINUTES))
            for slot in iter_update_slots(collection_start, collection_end):
                stamp = slot.isoformat().replace("+00:00", "Z")
                if stamp in seen:
                    continue
                seen.add(stamp)
                filename = routeviews_update_filename(slot)
                rows.append(
                    {
                        "incident_uid": incident["incident_uid"],
                        "category": incident["category"],
                        "segment_id": segment_id,
                        "segment_start": start.isoformat().replace("+00:00", "Z"),
                        "segment_end": end.isoformat().replace("+00:00", "Z"),
                        "collection_start": collection_start.isoformat().replace("+00:00", "Z"),
                        "collection_end": collection_end.isoformat().replace("+00:00", "Z"),
                        "collector": COLLECTOR,
                        "mrt_timestamp": stamp,
                        "mrt_url": routeviews_update_url(slot, COLLECTOR),
                        "local_path": str(RAW / incident["incident_uid"] / filename),
                        "segment_note": note,
                    }
                )
    return rows


def fetch(row: dict) -> dict:
    path = Path(row["local_path"])
    path.parent.mkdir(parents=True, exist_ok=True)
    status = "CACHED" if path.exists() and path.stat().st_size else ""
    if not status:
        request = Request(row["mrt_url"], headers={"User-Agent": USER_AGENT})
        try:
            with urlopen(request, timeout=180) as response, path.open("wb") as handle:
                shutil.copyfileobj(response, handle, 1024 * 1024)
            # Preserve the frozen parser's successful-download status vocabulary.
            status = "200" if path.stat().st_size else "ZERO_BYTE"
        except (HTTPError, URLError, TimeoutError, OSError) as error:
            status = f"FAIL:{getattr(error, 'code', '') or type(error).__name__}"
    return {**row, "download_status": status, "file_size": path.stat().st_size if path.exists() else 0, "sha256": sha256(path) if path.exists() and path.stat().st_size else ""}


def archive_index_fallback(rows: list[dict]) -> list[dict]:
    """Resolve archive-era non-quarter-hour filenames after standard URL failure."""
    output: list[dict] = []
    by_uid: defaultdict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_uid[row["incident_uid"]].append(row)
    for uid, group in by_uid.items():
        if not group or not all(str(row["download_status"]).startswith("FAIL:404") for row in group):
            output.extend(group)
            continue
        start = min(parse_utc(row["collection_start"]) for row in group)
        end = max(parse_utc(row["collection_end"]) for row in group)
        assert start and end
        months = sorted({parse_utc(row["mrt_timestamp"]).strftime("%Y.%m") for row in group if parse_utc(row["mrt_timestamp"])})
        replacements: list[dict] = []
        for month in months:
            index_url = f"https://archive.routeviews.org/bgpdata/{month}/UPDATES/"
            with urlopen(Request(index_url, headers={"User-Agent": USER_AGENT}), timeout=120) as response:
                html = response.read().decode("utf-8", errors="replace")
            filenames = sorted(set(re.findall(r"updates\.(\d{8})\.(\d{4})\.bz2", html)))
            candidates = []
            for day, hm in filenames:
                stamp = datetime.strptime(day + hm, "%Y%m%d%H%M").replace(tzinfo=timezone.utc)
                candidates.append((stamp, f"updates.{day}.{hm}.bz2"))
            selected = [(stamp, name) for stamp, name in candidates if start - timedelta(minutes=20) <= stamp <= end]
            for stamp, name in selected:
                template = group[0]
                replacements.append(
                    {
                        **template,
                        "mrt_timestamp": stamp.isoformat().replace("+00:00", "Z"),
                        "mrt_url": index_url + name,
                        "local_path": str(RAW / uid / name),
                        "segment_note": str(template["segment_note"]) + "; generic archive-index fallback",
                        "archive_resolution": "INDEX_FALLBACK_NONALIGNED_FILENAME",
                    }
                )
        output.extend(fetch(row) for row in replacements)
    return output


def ensure_caida(window_start: str) -> tuple[Path | None, str]:
    dt = parse_utc(window_start)
    assert dt
    name = caida_snapshot_name(dt)
    path = CAIDA_CACHE / name
    if path.exists() and path.stat().st_size:
        return path, "CACHED"
    request = Request(caida_snapshot_url(dt), headers={"User-Agent": USER_AGENT})
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with urlopen(request, timeout=180) as response, path.open("wb") as handle:
            shutil.copyfileobj(response, handle, 1024 * 1024)
        return path, "DOWNLOADED"
    except (HTTPError, URLError, TimeoutError, OSError) as error:
        if path.exists() and path.stat().st_size == 0:
            path.unlink()
        return None, f"UNAVAILABLE:{getattr(error, 'code', '') or type(error).__name__}"


def ensure_rpki(snapshot_date: str) -> tuple[bool, str]:
    statuses = []
    for tal in TRUST_ANCHORS:
        path = rpki_cache_path(tal, snapshot_date)
        if path.exists() and path.stat().st_size:
            statuses.append("CACHED")
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        request = Request(rpki_snapshot_url(tal, snapshot_date), headers={"User-Agent": USER_AGENT})
        try:
            with urlopen(request, timeout=180) as response, path.open("wb") as handle:
                shutil.copyfileobj(response, handle, 1024 * 1024)
            statuses.append("DOWNLOADED")
        except (HTTPError, URLError, TimeoutError, OSError) as error:
            if path.exists() and path.stat().st_size == 0:
                path.unlink()
            statuses.append(f"FAIL:{getattr(error, 'code', '') or type(error).__name__}")
    return all(item in {"CACHED", "DOWNLOADED"} for item in statuses), ";".join(statuses)


def parsed_evidence() -> pd.DataFrame:
    frames = []
    for path in PARSED.glob("*/parsed_relevant_bgp_observations.csv"):
        frame = pd.read_csv(path, dtype=str).fillna("")
        if len(frame):
            frame["window_start"] = pd.to_datetime(frame["bgp_timestamp_utc"], utc=True).dt.floor("5min").dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            frame["window_id"] = frame["incident_uid"] + "__" + frame["window_start"].str.replace(":", "", regex=False).str.replace("-", "", regex=False)
            frames.append(frame)
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def rpki_features(windows: pd.DataFrame, evidence: pd.DataFrame) -> tuple[pd.DataFrame, list[dict]]:
    records: list[dict] = []
    audits: list[dict] = []
    for date, date_windows in windows.groupby(windows["window_start"].str[:10]):
        available, status = ensure_rpki(date)
        audits.append({"snapshot_type": "RPKI", "snapshot": date, "status": status, "exact_available": available})
        index = build_vrp_index(load_vrps(date)) if available else None
        for _, meta in date_windows.iterrows():
            group = evidence[evidence["window_id"] == meta["window_id"]] if len(evidence) else pd.DataFrame()
            counts: Counter[str] = Counter()
            prefixes: defaultdict[str, set[str]] = defaultdict(set)
            for _, ev in group.iterrows():
                result = validate_rov(ev["prefix"], ev["origin_asn"], index) if index is not None else None
                if result is None:
                    continue
                counts[result.state] += 1
                if ev["prefix"]:
                    prefixes[result.state].add(ev["prefix"])
            evaluable = counts["VALID"] + counts["INVALID_ORIGIN"] + counts["INVALID_LENGTH"] + counts["NOT_FOUND"]
            invalid = counts["INVALID_ORIGIN"] + counts["INVALID_LENGTH"]
            dominant = "NO_PREFIX_ORIGIN_EVIDENCE" if not sum(counts.values()) else max(counts.items(), key=lambda x: (x[1], x[0]))[0]
            vals = {
                "rpki_evidence_observation_count": len(group), "rpki_evaluable_observation_count": evaluable,
                "rpki_valid_observation_count": counts["VALID"], "rpki_invalid_observation_count": invalid,
                "rpki_not_found_observation_count": counts["NOT_FOUND"], "rpki_unevaluable_observation_count": counts["UNEVALUABLE"],
                "rpki_invalid_origin_observation_count": counts["INVALID_ORIGIN"], "rpki_invalid_maxlength_observation_count": counts["INVALID_LENGTH"],
                "rpki_valid_observation_ratio": counts["VALID"] / evaluable if evaluable else np.nan,
                "rpki_invalid_observation_ratio": invalid / evaluable if evaluable else np.nan,
                "rpki_not_found_observation_ratio": counts["NOT_FOUND"] / evaluable if evaluable else np.nan,
                "rpki_unique_valid_prefix_count": len(prefixes["VALID"]),
                "rpki_unique_invalid_prefix_count": len(prefixes["INVALID_ORIGIN"] | prefixes["INVALID_LENGTH"]),
                "rpki_unique_not_found_prefix_count": len(prefixes["NOT_FOUND"]),
                "rpki_state_diversity_count": sum(v > 0 for v in counts.values()), "rpki_dominant_state_code": STATE_TO_CODE[dominant],
            }
            records.append({"window_id": meta["window_id"], **vals, "rpki_snapshot_available": available})
    return pd.DataFrame(records), audits


def run(download: bool) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    frozen.RAW_TRAIN_DIR = RAW
    frozen.PARSED_TRAIN_DIR = PARSED
    incidents, review = load_incidents()
    write_csv(OUT / "pilot_incidents_normalized_v1.csv", incidents)
    write_csv(OUT / "pilot_timestamp_review_exclusions_v1.csv", review)
    plan = acquisition_plan(incidents)
    if download:
        downloads = [fetch(row) for row in plan]
        downloads = archive_index_fallback(downloads)
    else:
        downloads = [{**row, "download_status": "NOT_DOWNLOADED", "file_size": 0, "sha256": ""} for row in plan]
    write_csv(OUT / "routeviews_acquisition_manifest_v1.csv", downloads)
    if not download:
        print(json.dumps({"incidents": len(incidents), "mrt_assignments": len(plan), "unique_urls": len({r['mrt_url'] for r in plan})}, indent=2))
        return

    by_uid: defaultdict[str, list[dict]] = defaultdict(list)
    for row in downloads:
        by_uid[row["incident_uid"]].append(row)
    feature_frames = []
    recon = []
    for incident in incidents:
        rows, stats = frozen.parse_and_feature_incident(incident, by_uid[incident["incident_uid"]])
        feature_frames.append(pd.DataFrame(rows))
        download_ok = bool(by_uid[incident["incident_uid"]]) and all(row["download_status"] in {"200", "CACHED", "REUSED_FROM_PILOT"} for row in by_uid[incident["incident_uid"]])
        recon.append({"incident_uid": incident["incident_uid"], "category": incident["category"], "mrt_files": stats.raw_mrt_files,
                      "raw_observations": stats.raw_bgp_observations, "relevant_observations": stats.relevant_observations,
                      "parse_failures": stats.parse_failures, "window_rows": len(rows),
                      "behavioral_status": "PASS" if download_ok and stats.parse_failures == 0 and stats.raw_bgp_observations > 0 else "FAIL"})
    behavioral = pd.concat(feature_frames, ignore_index=True)
    behavioral.to_parquet(OUT / "pilot_behavioral_features_v1.parquet", index=False)
    evidence = parsed_evidence()

    caida_records, snapshot_audit = [], []
    for month, group in behavioral.groupby(behavioral["window_start"].str[:7]):
        path, status = ensure_caida(group.iloc[0]["window_start"])
        snapshot_audit.append({"snapshot_type": "CAIDA", "snapshot": month, "status": status, "exact_available": bool(path)})
        relationships = load_relationships(path) if path else None
        for _, meta in group.iterrows():
            ev = evidence[evidence["window_id"] == meta["window_id"]].to_dict("records") if len(evidence) else []
            vals = aggregate_caida_rows(ev, relationships) if relationships is not None else {name: np.nan for name in CAIDA_FEATURE_NAMES}
            caida_records.append({"window_id": meta["window_id"], **vals, "caida_snapshot_available": bool(path)})
    caida = pd.DataFrame(caida_records)
    rpki, rpki_audit = rpki_features(behavioral, evidence)
    snapshot_audit.extend(rpki_audit)
    write_csv(OUT / "historical_snapshot_audit_v1.csv", snapshot_audit)
    caida.to_parquet(OUT / "pilot_caida_features_v1.parquet", index=False)
    rpki.to_parquet(OUT / "pilot_rpki_features_v1.parquet", index=False)

    v4 = behavioral.merge(caida.drop(columns=["caida_snapshot_available"]), on="window_id", validate="one_to_one")
    v4 = v4.merge(rpki.drop(columns=["rpki_snapshot_available"]), on="window_id", validate="one_to_one")
    schema = json.loads((MODEL_DIR / "feature_schema_v4.json").read_text())
    schema_hash = sha256(MODEL_DIR / "feature_schema_v4.json")
    v4.to_parquet(OUT / "pilot_v4_features_v1.parquet", index=False)
    exact_snapshots = {row["snapshot"]: str(row["exact_available"]) == "True" or row["exact_available"] is True for row in snapshot_audit}
    model_hashes = json.loads((MODEL_DIR / "sha256_checksums.json").read_text())
    models_ok = all(sha256(ROOT / path) == expected for path, expected in model_hashes.items())
    compatibility = []
    predictions = []
    models = [joblib.load(MODEL_DIR / f"level1_xgb_fold_{fold}_hist_njobs_minus1.joblib") for fold in range(1, 6)] if models_ok else []
    for incident in incidents:
        group = v4[v4["incident_uid"] == incident["incident_uid"]]
        months = {value[:7] for value in group["window_start"]}
        dates = {value[:10] for value in group["window_start"]}
        enrich_ok = all(exact_snapshots.get(item, False) for item in months | dates)
        schema_ok = len(schema) == 74 and schema == BEHAVIORAL_FEATURE_NAMES + CAIDA_FEATURE_NAMES + RPKI_FEATURE_NAMES and all(name in group for name in schema)
        status = "PASS" if schema_ok and enrich_ok and models_ok else "REVIEW"
        compatibility.append({"incident_uid": incident["incident_uid"], "category": incident["category"], "feature_count": len(schema),
                              "feature_names_order_exact": schema_ok, "schema_sha256": schema_hash, "historical_enrichment_exact": enrich_ok,
                              "model_checksums_exact": models_ok, "status": status})
        if status == "PASS":
            probs = np.stack([model.predict_proba(group[schema]) for model in models]).mean(axis=0)
            for (_, meta), prob in zip(group.iterrows(), probs):
                predictions.append({"incident_uid": incident["incident_uid"], "window_id": meta["window_id"], "window_start": meta["window_start"],
                                    "hijack_probability": prob[0], "leak_probability": prob[1], "outage_probability": prob[2]})
    pred = pd.DataFrame(predictions)
    if len(pred):
        pred.to_parquet(OUT / "pilot_level1_window_predictions_v1.parquet", index=False)
        means = pred.groupby("incident_uid")[["hijack_probability", "leak_probability", "outage_probability"]].mean().reset_index()
        means["predicted_class"] = means[["hijack_probability", "leak_probability", "outage_probability"]].idxmax(axis=1).str.replace("_probability", "").str.title()
        means.to_csv(OUT / "pilot_mean_incident_aggregation_v1.csv", index=False)
    write_csv(OUT / "pilot_reconstruction_audit_v1.csv", recon)
    write_csv(OUT / "pilot_v4_schema_equivalence_v1.csv", compatibility)
    print(json.dumps({"incidents_attempted": 8, "behavioral_pass": sum(r['behavioral_status'] == 'PASS' for r in recon),
                      "v4_exact_pass": sum(r['status'] == 'PASS' for r in compatibility), "scored_incidents": pred['incident_uid'].nunique() if len(pred) else 0}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--download", action="store_true")
    args = parser.parse_args()
    run(args.download)
