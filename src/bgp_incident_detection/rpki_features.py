from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import lzma
import math
import shutil
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pandas as pd

try:
    from bgp_incident_detection.audit import parse_utc, write_csv
    from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import parse_utc, write_csv
    from src.bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES


RPKI_DIR = Path("data/enrichment/rpki")
PILOT_DIR = Path("data/pilot")
EVIDENCE_DIR = Path("data/enrichment/evidence/train_v1")
RPKI_CACHE = Path("data/cache/rpki_vrps")
PILOT_WINDOWS = PILOT_DIR / "pilot_behavioral_features_v1.parquet"
FROZEN_V2 = Path("data/train_frozen/frozen_train_v2_behavioral_caida_v1.parquet")
FEATURE_VARIANTS = Path("config/feature_variants_v1.yaml")
NOTEBOOK = Path("notebooks/36_rpki_feature_inventory_and_pilot.ipynb")

SOURCE_INVENTORY = RPKI_DIR / "rpki_source_inventory_v1.csv"
HISTORICAL_FEATURE_INVENTORY = RPKI_DIR / "rpki_historical_feature_inventory_v1.csv"
FEATURE_INVENTORY = RPKI_DIR / "rpki_feature_inventory_v1.csv"
INPUT_AUDIT = RPKI_DIR / "rpki_input_availability_audit_v1.csv"
SNAPSHOT_MAPPING = RPKI_DIR / "pilot_rpki_snapshot_mapping_v1.csv"
SNAPSHOT_CACHE_AUDIT = RPKI_DIR / "pilot_rpki_snapshot_cache_audit_v1.csv"
TEMPORAL_POLICY = Path("docs/rpki_temporal_mapping_policy_v1.md")
VALIDATION_SPEC = Path("docs/rpki_rov_validation_spec_v1.md")
MISSING_ZERO_POLICY = Path("docs/rpki_missing_zero_policy_v1.md")

PILOT_RPKI_FEATURES = PILOT_DIR / "pilot_rpki_features_v1.parquet"
CALCULATION_EXAMPLES = PILOT_DIR / "rpki_feature_calculation_examples_v1.csv"
FEATURE_QUALITY = PILOT_DIR / "rpki_feature_quality_audit_v1.csv"
VALIDATION_COVERAGE = PILOT_DIR / "rpki_validation_coverage_v1.csv"

TRUST_ANCHORS = ["afrinic.tal", "apnic.tal", "arin.tal", "lacnic.tal", "ripencc.tal"]
USER_AGENT = "bgp-incident-detection-pipeline/0.1"
RPKI_FEATURE_VERSION = "v1"

RPKI_FEATURE_NAMES = [
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
]

STATE_TO_CODE = {
    "NO_PREFIX_ORIGIN_EVIDENCE": 0,
    "VALID": 1,
    "INVALID_ORIGIN": 2,
    "INVALID_LENGTH": 3,
    "NOT_FOUND": 4,
    "UNEVALUABLE": 5,
}


@dataclass(frozen=True)
class Vrp:
    prefix: ipaddress._BaseNetwork
    origin_asn: str
    max_length: int
    trust_anchor: str
    source_uri: str = ""


@dataclass(frozen=True)
class RovResult:
    state: str
    reason: str
    covering_vrp_count: int
    matching_vrp: Vrp | None = None


VrpIndex = dict[int, dict[int, dict[ipaddress._BaseNetwork, list[Vrp]]]]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def normalize_asn(value: object) -> str:
    text = str(value or "").strip().upper()
    if not text or text in {"NAN", "NONE"}:
        return ""
    if text.startswith("AS"):
        text = text[2:]
    if text.endswith(".0"):
        text = text[:-2]
    return text if text.isdigit() else ""


def parse_prefix(value: object) -> ipaddress._BaseNetwork | None:
    text = str(value or "").strip()
    if not text or text.lower() in {"nan", "none"}:
        return None
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


def snapshot_date_for_observation(window_start: str) -> str:
    parsed = parse_utc(window_start)
    if not parsed:
        raise ValueError(f"invalid window_start: {window_start}")
    return parsed.strftime("%Y-%m-%d")


def snapshot_url(trust_anchor: str, snapshot_date: str) -> str:
    year, month, day = snapshot_date.split("-")
    return f"https://ftp.ripe.net/rpki/{trust_anchor}/{year}/{month}/{day}/roas.csv.xz"


def cache_path(trust_anchor: str, snapshot_date: str) -> Path:
    year, month, day = snapshot_date.split("-")
    return RPKI_CACHE / trust_anchor / year / month / day / "roas.csv.xz"


def download_snapshot(trust_anchor: str, snapshot_date: str) -> dict[str, object]:
    destination = cache_path(trust_anchor, snapshot_date)
    url = snapshot_url(trust_anchor, snapshot_date)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and destination.stat().st_size > 0:
        return {"snapshot_date": snapshot_date, "trust_anchor": trust_anchor, "source_url": url, "local_path": str(destination), "status": "CACHED", "bytes": destination.stat().st_size, "download_timestamp": utc_now()}
    request = Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(request, timeout=120.0) as response, destination.open("wb") as handle:
            shutil.copyfileobj(response, handle, length=1024 * 1024)
    except (HTTPError, URLError, TimeoutError) as error:
        if destination.exists():
            destination.unlink()
        return {"snapshot_date": snapshot_date, "trust_anchor": trust_anchor, "source_url": url, "local_path": str(destination), "status": f"FAIL:{getattr(error, 'code', '') or error}", "bytes": 0, "download_timestamp": utc_now()}
    return {"snapshot_date": snapshot_date, "trust_anchor": trust_anchor, "source_url": url, "local_path": str(destination), "status": "DOWNLOADED", "bytes": destination.stat().st_size, "download_timestamp": utc_now()}


def load_vrps_for_file(path: Path, trust_anchor: str) -> list[Vrp]:
    vrps: list[Vrp] = []
    with lzma.open(path, "rt", encoding="utf-8", errors="replace") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            lower = {key.lower().strip(): value for key, value in row.items()}
            prefix_value = lower.get("ip prefix") or lower.get("prefix") or lower.get("ip_prefix")
            asn_value = lower.get("asn") or lower.get("origin") or lower.get("origin_asn")
            max_length_value = lower.get("max length") or lower.get("maxlength") or lower.get("max_length") or ""
            prefix = parse_prefix(prefix_value)
            origin = normalize_asn(asn_value)
            if not prefix or not origin:
                continue
            try:
                max_length = int(str(max_length_value).strip()) if str(max_length_value).strip() else prefix.prefixlen
            except ValueError:
                max_length = prefix.prefixlen
            vrps.append(Vrp(prefix=prefix, origin_asn=origin, max_length=max_length, trust_anchor=trust_anchor, source_uri=lower.get("uri", "")))
    return vrps


def load_vrps(snapshot_date: str) -> list[Vrp]:
    output: list[Vrp] = []
    for tal in TRUST_ANCHORS:
        path = cache_path(tal, snapshot_date)
        if path.exists() and path.stat().st_size > 0:
            output.extend(load_vrps_for_file(path, tal))
    return output


def build_vrp_index(vrps: list[Vrp]) -> VrpIndex:
    index: VrpIndex = {4: defaultdict(dict), 6: defaultdict(dict)}
    for vrp in vrps:
        version_index = index[vrp.prefix.version]
        bucket = version_index.setdefault(vrp.prefix.prefixlen, defaultdict(list))
        bucket[vrp.prefix].append(vrp)
    return index


def applicable_vrps(prefix: ipaddress._BaseNetwork, vrps_or_index: list[Vrp] | VrpIndex) -> list[Vrp]:
    if isinstance(vrps_or_index, list):
        return [vrp for vrp in vrps_or_index if vrp.prefix.version == prefix.version and prefix.subnet_of(vrp.prefix)]
    output: list[Vrp] = []
    version_index = vrps_or_index.get(prefix.version, {})
    for prefixlen in range(0, prefix.prefixlen + 1):
        bucket = version_index.get(prefixlen)
        if not bucket:
            continue
        supernet = prefix.supernet(new_prefix=prefixlen)
        output.extend(bucket.get(supernet, []))
    return output


def validate_rov(prefix_value: object, origin_value: object, vrps: list[Vrp] | VrpIndex) -> RovResult:
    prefix = parse_prefix(prefix_value)
    origin = normalize_asn(origin_value)
    if not prefix or not origin:
        return RovResult("UNEVALUABLE", "missing_or_malformed_prefix_or_origin", 0)
    covering = applicable_vrps(prefix, vrps)
    if not covering:
        return RovResult("NOT_FOUND", "no_covering_vrp", 0)
    for vrp in covering:
        if vrp.origin_asn == origin and prefix.prefixlen <= vrp.max_length:
            return RovResult("VALID", "matching_origin_and_maxlength", len(covering), vrp)
    if any(vrp.origin_asn == origin for vrp in covering):
        return RovResult("INVALID_LENGTH", "origin_matches_but_prefixlen_exceeds_maxlength", len(covering), None)
    return RovResult("INVALID_ORIGIN", "covering_vrp_exists_but_origin_mismatch", len(covering), None)


def source_inventory_rows() -> list[dict[str, object]]:
    return [
        {
            "dataset_name": "RIPE NCC historical RPKI repository archive",
            "source_archive": "https://ftp.ripe.net/rpki/",
            "archive_mechanism": "daily directories per trust anchor containing roas.csv.xz VRP exports",
            "date_coverage": "daily historical archive; TRAIN pilot dates are checked during caching",
            "snapshot_cadence": "daily",
            "vrp_fields": "ASN, IP Prefix, Max Length, URI when present",
            "validation_semantics": "Route Origin Validation per RFC 6811-style VALID/INVALID/NOT_FOUND using covering VRP, origin ASN, and maxLength",
            "license_usage_notes": "Use RIPE NCC archive terms and cite RIPE NCC RPKI repository archive; ARIN TAL data may be subject to ARIN relying-party terms.",
        }
    ]


def historical_feature_rows() -> list[dict[str, object]]:
    return [
        {
            "feature_name": "RPKI/ROV feature group placeholder",
            "historical_definition": "Earlier local methodology referenced approximately 3 RPKI/ROV features but did not define a reproducible inventory.",
            "historical_formula": "",
            "source_artifact": "README.md; docs/model_baseline_and_ablation_plan_v1.md; config/feature_variants_v1.yaml",
            "reproducible": "no",
            "notes": "This controlled step defines the first reproducible RPKI/ROV inventory from historical VRP data and compact BGP evidence.",
        }
    ]


def feature_inventory_rows() -> list[dict[str, object]]:
    definitions = {
        "rpki_evidence_observation_count": ("Underlying incident-relevant BGP observations represented by compact evidence rows.", "sum(observation_count)", "window evidence", "observation-weighted sum", "0 when no evidence", "0 means no prefix/origin evidence in the window", "volume/visibility baseline for RPKI aggregation"),
        "rpki_evaluable_observation_count": ("Observation-weighted count with parseable prefix and origin ASN.", "valid+invalid+not_found", "prefix, origin_asn, observation_count", "observation-weighted sum", "0 when no evaluable evidence", "not equivalent to VALID", "denominator for RPKI ratios"),
        "rpki_valid_observation_count": ("Observation-weighted count classified VALID.", "sum(observation_count where state=VALID)", "prefix, origin_asn, VRPs", "observation-weighted sum", "0 if no VALID observations", "0 can mean no evidence or all non-VALID; use denominator features", "authorized route-origin evidence"),
        "rpki_invalid_observation_count": ("Observation-weighted count classified INVALID.", "INVALID_ORIGIN + INVALID_LENGTH", "prefix, origin_asn, VRPs", "observation-weighted sum", "0 if no INVALID observations", "0 is meaningful only with evaluable denominator", "ROV anomaly signal"),
        "rpki_not_found_observation_count": ("Observation-weighted count with no covering VRP.", "sum(observation_count where state=NOT_FOUND)", "prefix, origin_asn, VRPs", "observation-weighted sum", "0 if no NOT_FOUND observations", "NOT_FOUND is not VALID", "coverage/ROA adoption signal"),
        "rpki_unevaluable_observation_count": ("Observation-weighted count with missing/malformed prefix or origin.", "sum(observation_count where state=UNEVALUABLE)", "prefix, origin_asn", "observation-weighted sum", "0 if all evidence evaluable", "separate from NOT_FOUND", "data-quality signal"),
        "rpki_invalid_origin_observation_count": ("Observation-weighted INVALID caused by origin mismatch.", "sum(observation_count where state=INVALID_ORIGIN)", "prefix, origin_asn, VRPs", "observation-weighted sum", "0 if no origin mismatch invalids", "separate from maxLength violation", "hijack/leak-relevant signal"),
        "rpki_invalid_maxlength_observation_count": ("Observation-weighted INVALID caused by maxLength violation.", "sum(observation_count where state=INVALID_LENGTH)", "prefix, origin_asn, VRPs", "observation-weighted sum", "0 if no maxLength invalids", "separate from origin mismatch", "more-specific announcement signal"),
        "rpki_valid_observation_ratio": ("Share of evaluable observations classified VALID.", "valid/evaluable", "RPKI counts", "ratio", "NaN if denominator zero", "NaN when no evaluable evidence", "normalized authorization signal"),
        "rpki_invalid_observation_ratio": ("Share of evaluable observations classified INVALID.", "invalid/evaluable", "RPKI counts", "ratio", "NaN if denominator zero", "NaN when no evaluable evidence", "normalized anomaly signal"),
        "rpki_not_found_observation_ratio": ("Share of evaluable observations classified NOT_FOUND.", "not_found/evaluable", "RPKI counts", "ratio", "NaN if denominator zero", "NaN when no evaluable evidence", "normalized lack-of-ROA signal"),
        "rpki_unique_valid_prefix_count": ("Unique prefixes with at least one VALID observation.", "nunique(prefix where state=VALID)", "prefix, ROV state", "prefix-unique count", "0 if none", "prefix-unique, not observation-weighted", "breadth of valid evidence"),
        "rpki_unique_invalid_prefix_count": ("Unique prefixes with at least one INVALID observation.", "nunique(prefix where state starts INVALID)", "prefix, ROV state", "prefix-unique count", "0 if none", "prefix-unique, not observation-weighted", "breadth of invalid evidence"),
        "rpki_unique_not_found_prefix_count": ("Unique prefixes with at least one NOT_FOUND observation.", "nunique(prefix where state=NOT_FOUND)", "prefix, ROV state", "prefix-unique count", "0 if none", "prefix-unique, not observation-weighted", "breadth of not-found evidence"),
        "rpki_state_diversity_count": ("Number of distinct RPKI states seen in the window.", "count distinct VALID/INVALID_ORIGIN/INVALID_LENGTH/NOT_FOUND/UNEVALUABLE with count > 0", "RPKI states", "window distinct count", "0 if no evidence", "captures mixed state windows", "state heterogeneity signal"),
        "rpki_dominant_state_code": ("Numeric code for the most common observation-weighted RPKI state.", "argmax state count mapped to code", "RPKI states", "categorical code", "0 if no evidence", "codes documented in missing/zero policy", "compact dominant-state signal"),
    }
    return [
        {
            "feature_name": name,
            "definition": definitions[name][0],
            "formula": definitions[name][1],
            "required_inputs": definitions[name][2],
            "aggregation_method": definitions[name][3],
            "zero_behavior": definitions[name][4],
            "missing_behavior": definitions[name][5],
            "operational_interpretation": definitions[name][6],
            "historical_support": "new reproducible inventory; older local docs had only placeholders",
            "recommended": "yes",
        }
        for name in RPKI_FEATURE_NAMES
    ]


def write_docs() -> None:
    TEMPORAL_POLICY.parent.mkdir(parents=True, exist_ok=True)
    TEMPORAL_POLICY.write_text(
        "# RPKI Temporal Mapping Policy v1\n\n"
        "For each BGP evidence row, use the historical VRP snapshot for the UTC observation date when available. "
        "The selected source is the RIPE NCC historical RPKI repository archive at `https://ftp.ripe.net/rpki/`, where each trust-anchor/date directory exposes `roas.csv.xz` VRP data. "
        "If an exact date is unavailable, the acceptable fallback is the nearest earlier available snapshot. Future VRP state must not be used.\n\n"
        "Pilot mapping uses the same-day snapshot for every pilot window date. Any fallback is recorded explicitly in the mapping table.\n",
        encoding="utf-8",
    )
    VALIDATION_SPEC.write_text(
        "# RPKI/ROV Validation Specification v1\n\n"
        "Each compact evidence row is validated using `prefix + origin_asn + observation date` against the selected historical VRP set.\n\n"
        "- `VALID`: at least one covering VRP has the same origin ASN and the observed prefix length is less than or equal to the VRP `maxLength`.\n"
        "- `INVALID_ORIGIN`: one or more covering VRPs exist, but none authorize the observed origin ASN.\n"
        "- `INVALID_LENGTH`: a covering VRP authorizes the observed origin ASN, but the observed prefix is more specific than the permitted `maxLength`.\n"
        "- `NOT_FOUND`: no covering VRP exists for the observed prefix.\n"
        "- `UNEVALUABLE`: prefix or origin ASN is missing, malformed, AS_SET-like, or otherwise unparseable. Private/reserved origins are not silently rewritten; if they are syntactically parseable, they are evaluated against the historical VRP state and their outcome remains auditable.\n\n"
        "IPv4 and IPv6 are evaluated separately. Multiple covering VRPs are handled permissively: any valid authorization makes the observation VALID. NOT_FOUND is never treated as VALID.\n",
        encoding="utf-8",
    )
    MISSING_ZERO_POLICY.write_text(
        "# RPKI Missing And Zero Policy v1\n\n"
        "The pilot distinguishes four cases:\n\n"
        "A. A window contains no prefix/origin evidence: evidence counts are zero and ratio features are `NaN`.\n"
        "B. Evidence exists but all prefixes are `NOT_FOUND`: not-found counts equal evaluable counts; VALID/INVALID counts are zero.\n"
        "C. Evidence exists and zero INVALID observations occur: invalid counts are zero with positive evaluable denominator.\n"
        "D. Evidence cannot be evaluated because origin or prefix is malformed/missing: unevaluable counts are positive and excluded from VALID/INVALID/NOT_FOUND denominators.\n\n"
        "`observation_count` preserves multiplicity from the compact evidence store. Prefix-unique metrics count unique prefixes and are not observation-weighted.\n",
        encoding="utf-8",
    )


def write_static_outputs() -> None:
    RPKI_DIR.mkdir(parents=True, exist_ok=True)
    write_csv(SOURCE_INVENTORY, source_inventory_rows(), ["dataset_name", "source_archive", "archive_mechanism", "date_coverage", "snapshot_cadence", "vrp_fields", "validation_semantics", "license_usage_notes"])
    write_csv(HISTORICAL_FEATURE_INVENTORY, historical_feature_rows(), ["feature_name", "historical_definition", "historical_formula", "source_artifact", "reproducible", "notes"])
    write_csv(FEATURE_INVENTORY, feature_inventory_rows(), ["feature_name", "definition", "formula", "required_inputs", "aggregation_method", "zero_behavior", "missing_behavior", "operational_interpretation", "historical_support", "recommended"])
    write_docs()


def load_pilot_windows() -> pd.DataFrame:
    df = pd.read_parquet(PILOT_WINDOWS, columns=["incident_uid", "category", "partition", "window_id", "window_start", "window_end"])
    if len(df) != 661:
        raise ValueError(f"expected 661 pilot windows, found {len(df)}")
    if set(df["partition"].astype(str)) != {"train"}:
        raise ValueError("pilot RPKI run must be TRAIN only")
    if df["incident_uid"].nunique() != 9:
        raise ValueError("expected 9 pilot incidents")
    return df


def load_pilot_evidence(window_ids: set[str]) -> pd.DataFrame:
    frames = []
    columns = ["window_id", "incident_uid", "window_start", "window_end", "prefix", "origin_asn", "normalized_as_path", "observation_count", "collector", "source_mrt_count"]
    for path in sorted(EVIDENCE_DIR.glob("batch_*.parquet")):
        frame = pd.read_parquet(path, columns=columns)
        frame = frame[frame["window_id"].isin(window_ids)]
        if len(frame):
            frames.append(frame)
    if not frames:
        return pd.DataFrame(columns=columns)
    return pd.concat(frames, ignore_index=True)


def write_snapshot_mapping(windows: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for date in sorted({snapshot_date_for_observation(value) for value in windows["window_start"]}):
        for tal in TRUST_ANCHORS:
            rows.append(
                {
                    "observation_date": date,
                    "selected_rpki_snapshot": date,
                    "trust_anchor": tal,
                    "mapping_type": "SAME_DAY",
                    "mapping_reason": "same-day historical RIPE RPKI archive VRP snapshot; no future state used",
                    "source_url": snapshot_url(tal, date),
                }
            )
    mapping = pd.DataFrame(rows)
    mapping.to_csv(SNAPSHOT_MAPPING, index=False)
    return mapping


def ensure_snapshots(mapping: pd.DataFrame) -> None:
    rows = []
    for _, row in mapping.iterrows():
        rows.append(download_snapshot(str(row["trust_anchor"]), str(row["selected_rpki_snapshot"])))
    write_csv(SNAPSHOT_CACHE_AUDIT, rows, ["snapshot_date", "trust_anchor", "source_url", "local_path", "status", "bytes", "download_timestamp"])
    failures = [row for row in rows if str(row["status"]).startswith("FAIL")]
    if failures:
        raise RuntimeError(f"RPKI snapshot download failures: {len(failures)}")


def aggregate_window_features(windows: pd.DataFrame, evidence: pd.DataFrame) -> tuple[pd.DataFrame, list[dict[str, object]], pd.DataFrame]:
    vrps_by_date = {date: build_vrp_index(load_vrps(date)) for date in sorted({snapshot_date_for_observation(value) for value in windows["window_start"]})}
    rows = []
    validation_rows = []
    example_rows_by_category: dict[str, dict[str, object]] = {}
    evidence_by_window = {wid: group for wid, group in evidence.groupby("window_id")} if len(evidence) else {}
    meta_by_window = {row["window_id"]: row for _, row in windows.iterrows()}
    validation_cache: dict[tuple[str, str, str], RovResult] = {}
    for wid, meta in meta_by_window.items():
        group = evidence_by_window.get(wid)
        state_counts: Counter[str] = Counter()
        unique_prefixes: dict[str, set[str]] = defaultdict(set)
        evidence_total = 0
        if group is not None:
            snapshot_date = snapshot_date_for_observation(str(meta["window_start"]))
            vrps = vrps_by_date[snapshot_date]
            for _, ev in group.iterrows():
                count = int(ev["observation_count"])
                evidence_total += count
                prefix = str(ev.get("prefix", "") or "")
                origin = str(ev.get("origin_asn", "") or "")
                key = (snapshot_date, prefix, origin)
                if key not in validation_cache:
                    validation_cache[key] = validate_rov(prefix, origin, vrps)
                result = validation_cache[key]
                state_counts[result.state] += count
                if prefix:
                    unique_prefixes[result.state].add(prefix)
                category = str(meta["category"])
                if category not in example_rows_by_category:
                    example_rows_by_category[category] = (
                        {
                            "incident_uid": meta["incident_uid"],
                            "category": category,
                            "window_id": wid,
                            "prefix": prefix,
                            "origin_asn": origin,
                            "observation_count": count,
                            "matching_covering_vrp": str(result.matching_vrp.prefix) if result.matching_vrp else "",
                            "vrp_origin_asn": result.matching_vrp.origin_asn if result.matching_vrp else "",
                            "vrp_max_length": result.matching_vrp.max_length if result.matching_vrp else "",
                            "validation_state": result.state,
                            "final_window_feature_values": "",
                        }
                    )
        evaluable = state_counts["VALID"] + state_counts["INVALID_ORIGIN"] + state_counts["INVALID_LENGTH"] + state_counts["NOT_FOUND"]
        invalid = state_counts["INVALID_ORIGIN"] + state_counts["INVALID_LENGTH"]
        dominant_state = "NO_PREFIX_ORIGIN_EVIDENCE" if evidence_total == 0 else max(state_counts.items(), key=lambda item: (item[1], item[0]))[0]
        feature_values = {
            "rpki_evidence_observation_count": evidence_total,
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
        output = {column: meta[column] for column in ["incident_uid", "category", "partition", "window_id", "window_start", "window_end"]}
        output.update(feature_values)
        rows.append(output)
        validation_rows.append(
            {
                "incident_uid": meta["incident_uid"],
                "category": meta["category"],
                "evidence_observations_evaluated": evaluable,
                "valid_observations": state_counts["VALID"],
                "invalid_observations": invalid,
                "not_found_observations": state_counts["NOT_FOUND"],
                "malformed_unevaluable": state_counts["UNEVALUABLE"],
                "unique_prefixes_evaluated": len(set().union(*unique_prefixes.values())) if unique_prefixes else 0,
                "unique_origin_asns_evaluated": group["origin_asn"].nunique() if group is not None and len(group) else 0,
            }
        )
    features = pd.DataFrame(rows)
    example_rows = list(example_rows_by_category.values())
    for example in example_rows:
        values = features[features["window_id"] == example["window_id"]].iloc[0][RPKI_FEATURE_NAMES].to_json()
        example["final_window_feature_values"] = values
    return features, example_rows, pd.DataFrame(validation_rows)


def write_quality(features: pd.DataFrame) -> list[dict[str, object]]:
    rows = []
    row_count = len(features)
    for feature in RPKI_FEATURE_NAMES:
        series = pd.to_numeric(features[feature], errors="coerce")
        missing = int(series.isna().sum())
        finite = series.dropna()
        zero = int((finite == 0).sum()) if len(finite) else 0
        unique = int(finite.nunique()) if len(finite) else 0
        invalid = int(series.map(lambda value: isinstance(value, float) and math.isinf(value)).sum())
        sparse = bool(len(finite) and zero / len(finite) >= 0.95)
        constant = bool(unique <= 1)
        status = "FAIL" if invalid else "REVIEW" if constant or sparse else "PASS"
        rows.append(
            {
                "feature_name": feature,
                "missing_count": missing,
                "missing_rate": round(missing / row_count * 100, 3) if row_count else 0,
                "zero_count": zero,
                "zero_rate": round(zero / len(finite) * 100, 3) if len(finite) else "",
                "min": finite.min() if len(finite) else "",
                "median": finite.median() if len(finite) else "",
                "mean": finite.mean() if len(finite) else "",
                "p95": finite.quantile(0.95) if len(finite) else "",
                "max": finite.max() if len(finite) else "",
                "unique_values": unique,
                "constant": str(constant),
                "sparse": str(sparse),
                "invalid": invalid,
                "status": status,
            }
        )
    write_csv(FEATURE_QUALITY, rows, ["feature_name", "missing_count", "missing_rate", "zero_count", "zero_rate", "min", "median", "mean", "p95", "max", "unique_values", "constant", "sparse", "invalid", "status"])
    return rows


def write_input_audit(windows: pd.DataFrame, evidence: pd.DataFrame) -> None:
    rows = [
        {"check_name": "pilot_train_only", "observed_value": sorted(windows["partition"].unique().tolist()), "status": "PASS" if set(windows["partition"]) == {"train"} else "FAIL", "notes": "Validation/Holdout not accessed"},
        {"check_name": "pilot_window_count", "observed_value": len(windows), "status": "PASS" if len(windows) == 661 else "FAIL", "notes": "one row expected per pilot window"},
        {"check_name": "evidence_has_bgp_origin_asn", "observed_value": "origin_asn column from compact evidence", "status": "PASS" if "origin_asn" in evidence.columns else "FAIL", "notes": "origin_asn was extracted from observed AS_PATH during MRT parse, not incident metadata"},
        {"check_name": "full_mrt_reparse_required", "observed_value": "NO", "status": "PASS", "notes": "window_start/window_id + prefix + origin_asn + observation_count are sufficient for recommended RPKI features"},
        {"check_name": "frozen_v2_available", "observed_value": FROZEN_V2.exists(), "status": "PASS" if FROZEN_V2.exists() else "FAIL", "notes": "V2 is read only; not modified"},
    ]
    write_csv(INPUT_AUDIT, rows, ["check_name", "observed_value", "status", "notes"])


def write_coverage(coverage: pd.DataFrame) -> None:
    rows = []
    for category, group in coverage.groupby("category"):
        rows.append(
            {
                "category": category,
                "evidence_observations_evaluated": int(group["evidence_observations_evaluated"].sum()),
                "valid_observations": int(group["valid_observations"].sum()),
                "invalid_observations": int(group["invalid_observations"].sum()),
                "not_found_observations": int(group["not_found_observations"].sum()),
                "malformed_unevaluable": int(group["malformed_unevaluable"].sum()),
                "unique_prefixes_evaluated": int(group["unique_prefixes_evaluated"].sum()),
                "unique_origin_asns_evaluated": int(group["unique_origin_asns_evaluated"].sum()),
            }
        )
    write_csv(VALIDATION_COVERAGE, rows, ["category", "evidence_observations_evaluated", "valid_observations", "invalid_observations", "not_found_observations", "malformed_unevaluable", "unique_prefixes_evaluated", "unique_origin_asns_evaluated"])


def update_feature_variants() -> None:
    FEATURE_VARIANTS.write_text(
        "\n".join(
            [
                "feature_variants_version: v1",
                "source: data/train_frozen/frozen_train_behavioral_corpus_v1.parquet",
                "notes: V1 and V2 are frozen. V3 RPKI inventory is pilot-verified only; V4 waits for full TRAIN RPKI.",
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
                "    status: FULL_TRAIN_VERIFIED_FROZEN",
                "    feature_groups:",
                "      - Behavioral",
                "      - CAIDA AS-relationship",
                "  V3:",
                "    description: Behavioral BGP + RPKI/ROV features",
                "    behavioral_feature_count: 44",
                f"    rpki_feature_count: {len(RPKI_FEATURE_NAMES)}",
                f"    total_feature_count: {44 + len(RPKI_FEATURE_NAMES)}",
                "    status: PILOT_VERIFIED",
                "    feature_groups:",
                "      - Behavioral",
                "      - RPKI/ROV",
                "  V4:",
                "    description: Behavioral BGP + CAIDA AS-relationship + RPKI/ROV features",
                "    behavioral_feature_count: 44",
                "    caida_feature_count: 14",
                f"    rpki_feature_count: {len(RPKI_FEATURE_NAMES)}",
                f"    total_feature_count: {58 + len(RPKI_FEATURE_NAMES)}",
                "    status: PENDING_FULL_TRAIN_RPKI",
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
            {"cell_type": "markdown", "metadata": {}, "source": ["# RPKI Feature Inventory And Pilot\n", "\n", "TRAIN-only RPKI/ROV pilot using the compact enrichment evidence store. No MRT reparse, Validation/Holdout access, CAIDA/V1 modification, modeling, weighting, capping, or ablation.\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["from bgp_incident_detection.rpki_features import run_pilot\n", "# run_pilot()  # downloads historical VRP snapshots for the 9-incident pilot only\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["import pandas as pd\n", "pd.read_csv('../data/enrichment/rpki/rpki_feature_inventory_v1.csv')\n"]},
            {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": ["features = pd.read_parquet('../data/pilot/pilot_rpki_features_v1.parquet')\n", "features.shape, features.groupby('category')['incident_uid'].nunique().to_dict()\n"]},
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")


def run_pilot() -> dict[str, object]:
    write_static_outputs()
    write_notebook()
    windows = load_pilot_windows()
    mapping = write_snapshot_mapping(windows)
    ensure_snapshots(mapping)
    evidence = load_pilot_evidence(set(windows["window_id"]))
    write_input_audit(windows, evidence)
    features, examples, coverage = aggregate_window_features(windows, evidence)
    if len(features) != 661 or features["window_id"].nunique() != 661:
        raise RuntimeError("RPKI pilot must produce exactly one row per pilot window")
    if set(features["partition"].astype(str)) != {"train"}:
        raise RuntimeError("RPKI pilot includes non-train data")
    PILOT_RPKI_FEATURES.parent.mkdir(parents=True, exist_ok=True)
    features.to_parquet(PILOT_RPKI_FEATURES, index=False)
    write_csv(CALCULATION_EXAMPLES, examples, ["incident_uid", "category", "window_id", "prefix", "origin_asn", "observation_count", "matching_covering_vrp", "vrp_origin_asn", "vrp_max_length", "validation_state", "final_window_feature_values"])
    quality = write_quality(features)
    write_coverage(coverage)
    update_feature_variants()
    return {
        "recommended_rpki_feature_count": len(RPKI_FEATURE_NAMES),
        "pilot_rows": len(features),
        "pilot_incidents": features["incident_uid"].nunique(),
        "pilot_class_incidents": features.groupby("category")["incident_uid"].nunique().to_dict(),
        "evidence_rows_used": len(evidence),
        "evidence_observations_represented": int(evidence["observation_count"].sum()) if len(evidence) else 0,
        "feature_quality_status_counts": dict(Counter(row["status"] for row in quality)),
        "full_mrt_reparse_required": "NO",
        "outputs": [
            str(SOURCE_INVENTORY),
            str(HISTORICAL_FEATURE_INVENTORY),
            str(FEATURE_INVENTORY),
            str(INPUT_AUDIT),
            str(PILOT_RPKI_FEATURES),
            str(CALCULATION_EXAMPLES),
            str(FEATURE_QUALITY),
            str(VALIDATION_COVERAGE),
            str(NOTEBOOK),
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Define and pilot RPKI/ROV feature inventory from compact TRAIN evidence")
    parser.add_argument("--run-pilot", action="store_true")
    args = parser.parse_args()
    if args.run_pilot:
        print(json.dumps(run_pilot(), indent=2, sort_keys=True))
        return
    parser.error("choose --run-pilot")


if __name__ == "__main__":
    main()
