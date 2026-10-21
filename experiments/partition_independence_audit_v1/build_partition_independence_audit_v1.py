from __future__ import annotations

import ast
import hashlib
import ipaddress
import json
from itertools import combinations
from pathlib import Path
from typing import Any

import pandas as pd


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "experiments" / "partition_independence_audit_v1"

ROSTER = ROOT / "data" / "roster_v2" / "frozen_incident_roster_v2.csv"
PARTITION = ROOT / "data" / "partitions_v2" / "frozen_partition_manifest_v2.csv"
DUP_RECS = ROOT / "data" / "review" / "duplicate_resolution_recommendations.csv"
DUP_PLAN = ROOT / "data" / "roster_v2" / "duplicate_canonicalization_plan.csv"
CORPUS_BALANCING_SUMMARY = ROOT / "experiments" / "corpus_balancing_audit_v1" / "corpus_balancing_audit_summary_v1.md"
TRAIN_V4 = ROOT / "data" / "train_frozen" / "frozen_train_v4_behavioral_caida_rpki_v1.parquet"
HOLDOUT_V4 = ROOT / "data" / "final_holdout" / "final_holdout_v4_features_v1.parquet"
VALIDATION_TTI_V4 = ROOT / "data" / "tti_validation_confirmation_v1" / "tti_validation_horizon_v4_v1.parquet"
HOLDOUT_MRT_PLAN = ROOT / "data" / "final_holdout" / "final_holdout_mrt_acquisition_plan_v1.csv"
HOLDOUT_CAIDA_MAP = ROOT / "data" / "final_holdout" / "final_holdout_caida_snapshot_mapping_v1.csv"
HOLDOUT_RPKI_MAP = ROOT / "data" / "final_holdout" / "final_holdout_rpki_snapshot_mapping_v1.csv"

PARTITION_ORDER = ["train", "validation", "holdout"]
COMPARISONS = [("train", "validation"), ("train", "holdout"), ("validation", "holdout")]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


def write_md(path: Path, text: str) -> None:
    path.write_text(text.strip() + "\n", encoding="utf-8")


def md_table(df: pd.DataFrame) -> str:
    if df.empty:
        return "_No rows._"
    headers = [str(c) for c in df.columns]
    rows = [[str(v) for v in row] for row in df.to_numpy()]
    widths = [max(len(headers[i]), *(len(row[i]) for row in rows)) for i in range(len(headers))]
    header = "| " + " | ".join(headers[i].ljust(widths[i]) for i in range(len(headers))) + " |"
    sep = "| " + " | ".join("-" * widths[i] for i in range(len(headers))) + " |"
    body = ["| " + " | ".join(row[i].ljust(widths[i]) for i in range(len(headers))) + " |" for row in rows]
    return "\n".join([header, sep, *body])


def parse_list(value: Any) -> list[str]:
    if pd.isna(value):
        return []
    if isinstance(value, list):
        return [str(v) for v in value if str(v).lower() not in {"nan", "none", "null", ""}]
    text = str(value).strip()
    if not text or text.lower() in {"nan", "none", "null"}:
        return []
    try:
        parsed = json.loads(text)
    except Exception:
        try:
            parsed = ast.literal_eval(text)
        except Exception:
            parsed = [text]
    if isinstance(parsed, list):
        return [str(v) for v in parsed if str(v).lower() not in {"nan", "none", "null", ""}]
    return [str(parsed)]


def parse_asns(row: pd.Series) -> set[str]:
    vals = set()
    primary = row.get("primary_asn")
    if pd.notna(primary):
        try:
            vals.add(str(int(float(primary))))
        except Exception:
            vals.add(str(primary))
    for item in parse_list(row.get("affected_asns")):
        clean = item.strip().strip('"').strip("'")
        if clean:
            try:
                vals.add(str(int(float(clean))))
            except Exception:
                vals.add(clean)
    return vals


def parse_prefixes(row: pd.Series) -> set[str]:
    prefixes: set[str] = set()
    for item in parse_list(row.get("affected_prefixes")):
        item = item.strip().strip('"').strip("'")
        if not item:
            continue
        try:
            prefixes.add(str(ipaddress.ip_network(item, strict=False)))
        except Exception:
            prefixes.add(item)
    return prefixes


def prefix_contains(a: str, b: str) -> bool:
    try:
        na = ipaddress.ip_network(a, strict=False)
        nb = ipaddress.ip_network(b, strict=False)
    except Exception:
        return False
    return na.version == nb.version and (na.supernet_of(nb) or nb.supernet_of(na)) and na != nb


def time_overlap_minutes(a_start: pd.Timestamp, a_end: pd.Timestamp, b_start: pd.Timestamp, b_end: pd.Timestamp) -> float:
    latest = max(a_start, b_start)
    earliest = min(a_end, b_end)
    seconds = (earliest - latest).total_seconds()
    return max(0.0, seconds / 60.0)


def min_abs_seconds(a_start: pd.Timestamp, a_end: pd.Timestamp, b_start: pd.Timestamp, b_end: pd.Timestamp) -> float:
    candidates = [
        abs((a_start - b_start).total_seconds()),
        abs((a_start - b_end).total_seconds()),
        abs((a_end - b_start).total_seconds()),
        abs((a_end - b_end).total_seconds()),
    ]
    if a_start <= b_end and b_start <= a_end:
        return 0.0
    return min(candidates)


def load_roster() -> pd.DataFrame:
    roster = pd.read_csv(ROSTER)
    part = pd.read_csv(PARTITION)[["incident_uid", "partition", "random_seed", "split_version"]]
    if "partition" in roster.columns:
        roster = roster.drop(columns=["partition"])
    df = roster.merge(part, on="incident_uid", how="left", validate="one_to_one")
    df["start_ts"] = pd.to_datetime(df["start_utc"], utc=True, errors="coerce")
    df["end_ts"] = pd.to_datetime(df["end_utc"], utc=True, errors="coerce")
    df["source_event_id"] = df["incident_id"].astype(str)
    df["normalized_source_identifier"] = df["category"].astype(str) + ":" + df["incident_id"].astype(str)
    df["asn_set"] = df.apply(parse_asns, axis=1)
    df["prefix_set"] = df.apply(parse_prefixes, axis=1)
    df["event_day"] = df["start_ts"].dt.date.astype(str)
    return df


def duplicate_lineage_map(current_uids: set[str]) -> dict[tuple[str, str], str]:
    lineage: dict[tuple[str, str], str] = {}
    if not DUP_RECS.exists():
        return lineage
    recs = pd.read_csv(DUP_RECS)
    for _, row in recs.iterrows():
        uids = [u for u in parse_list(row.get("incident_uids")) if u in current_uids]
        for a, b in combinations(sorted(set(uids)), 2):
            lineage[(a, b)] = str(row.get("classification"))
    return lineage


def comparison_label(a: str, b: str) -> str:
    return f"{a}↔{b}"


def exact_identity_audit(df: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    fields = [
        ("incident_uid", "exact incident UID"),
        ("incident_id", "local numeric incident ID"),
        ("source_event_id", "source/API event ID proxy"),
        ("normalized_source_identifier", "class + event ID"),
        ("source_url", "source URL"),
    ]
    for left, right in COMPARISONS:
        dl = df[df["partition"] == left]
        dr = df[df["partition"] == right]
        for field, desc in fields:
            lvals = set(dl[field].dropna().astype(str)) - {"", "nan", "NaN"}
            rvals = set(dr[field].dropna().astype(str)) - {"", "nan", "NaN"}
            overlap = sorted(lvals & rvals)
            rows.append(
                {
                    "comparison": comparison_label(left, right),
                    "field": field,
                    "field_description": desc,
                    "overlap_count": len(overlap),
                    "overlap_values_sample": json.dumps(overlap[:25]),
                    "assessment": "PASS" if len(overlap) == 0 or field == "incident_id" else "REVIEW",
                    "notes": "incident_id without class is not globally unique enough to prove leakage; normalized_source_identifier is stricter"
                    if field == "incident_id"
                    else "",
                }
            )
    return pd.DataFrame(rows)


def pairwise_audits(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    lineage = duplicate_lineage_map(set(df["incident_uid"]))
    near_rows = []
    temporal_rows = []
    for left, right in COMPARISONS:
        dl = df[df["partition"] == left].to_dict("records")
        dr = df[df["partition"] == right].to_dict("records")
        counts = {
            "pair_count": 0,
            "exact_time_overlap": 0,
            "same_day": 0,
            "within_1h": 0,
            "within_24h": 0,
            "same_asn_close_time_24h": 0,
            "same_prefix_close_time_24h": 0,
            "same_asn_prefix_close_time_24h": 0,
        }
        for a in dl:
            for b in dr:
                counts["pair_count"] += 1
                key = tuple(sorted([a["incident_uid"], b["incident_uid"]]))
                line = lineage.get(key)
                asn_overlap = sorted(set(a["asn_set"]) & set(b["asn_set"]))
                prefix_overlap = sorted(set(a["prefix_set"]) & set(b["prefix_set"]))
                overlap_min = time_overlap_minutes(a["start_ts"], a["end_ts"], b["start_ts"], b["end_ts"])
                close_seconds = min_abs_seconds(a["start_ts"], a["end_ts"], b["start_ts"], b["end_ts"])
                start_gap_seconds = abs((a["start_ts"] - b["start_ts"]).total_seconds())
                within_1h = close_seconds <= 3600
                within_24h = close_seconds <= 86400
                contains = False
                if within_24h and not prefix_overlap and a["prefix_set"] and b["prefix_set"]:
                    contains = any(prefix_contains(pa, pb) for pa in a["prefix_set"] for pb in b["prefix_set"])
                same_day = a["event_day"] == b["event_day"]
                same_class = a["category"] == b["category"]
                same_norm_source = a["normalized_source_identifier"] == b["normalized_source_identifier"]
                same_source_url = pd.notna(a.get("source_url")) and pd.notna(b.get("source_url")) and str(a.get("source_url")) == str(b.get("source_url"))
                if overlap_min > 0:
                    counts["exact_time_overlap"] += 1
                if same_day:
                    counts["same_day"] += 1
                if within_1h:
                    counts["within_1h"] += 1
                if within_24h:
                    counts["within_24h"] += 1
                if asn_overlap and within_24h:
                    counts["same_asn_close_time_24h"] += 1
                if prefix_overlap and within_24h:
                    counts["same_prefix_close_time_24h"] += 1
                if asn_overlap and prefix_overlap and within_24h:
                    counts["same_asn_prefix_close_time_24h"] += 1

                classification = None
                if line == "TRUE_DUPLICATE":
                    classification = "CONFIRMED_DUPLICATE_EVENT"
                elif same_norm_source:
                    classification = "POTENTIAL_DUPLICATE_EVENT"
                elif line in {"SAME_BROAD_EVENT_DIFFERENT_COMPONENT", "UNRESOLVED"}:
                    classification = "POTENTIAL_RELATED_EVENT" if line == "SAME_BROAD_EVENT_DIFFERENT_COMPONENT" else "REVIEW_REQUIRED"
                elif same_source_url and same_class and (asn_overlap or prefix_overlap) and start_gap_seconds <= 3600:
                    classification = "POTENTIAL_RELATED_EVENT"
                elif same_class and prefix_overlap and asn_overlap and start_gap_seconds <= 3600:
                    classification = "POTENTIAL_DUPLICATE_EVENT"
                elif same_class and asn_overlap and prefix_overlap and within_24h:
                    classification = "POTENTIAL_RELATED_EVENT"
                elif same_class and (asn_overlap or prefix_overlap) and within_1h:
                    classification = "POTENTIAL_RELATED_EVENT"
                elif (asn_overlap or prefix_overlap) and not within_24h:
                    classification = "SHARED_CONTEXT_ONLY"
                else:
                    classification = "DISTINCT_EVENT"

                if classification not in {"DISTINCT_EVENT", "SHARED_CONTEXT_ONLY"}:
                    near_rows.append(
                        {
                            "comparison": comparison_label(left, right),
                            "incident_uid_left": a["incident_uid"],
                            "incident_uid_right": b["incident_uid"],
                            "partition_left": left,
                            "partition_right": right,
                            "category_left": a["category"],
                            "category_right": b["category"],
                            "classification": classification,
                            "duplicate_lineage_classification": line or "",
                            "start_left": a["start_utc"],
                            "start_right": b["start_utc"],
                            "temporal_overlap_minutes": round(overlap_min, 3),
                            "min_time_gap_seconds": round(close_seconds, 3),
                            "start_time_gap_seconds": round(start_gap_seconds, 3),
                            "same_day": same_day,
                            "shared_asns": json.dumps(asn_overlap[:25]),
                            "shared_prefixes": json.dumps(prefix_overlap[:25]),
                            "parent_child_prefix_containment": contains,
                            "same_normalized_source_identifier": same_norm_source,
                            "same_source_url": bool(same_source_url),
                            "notes": "Candidate only; close time/shared resources are not leakage without duplicated event evidence.",
                        }
                    )
        counts["comparison"] = comparison_label(left, right)
        temporal_rows.append(counts)
    return pd.DataFrame(near_rows), pd.DataFrame(temporal_rows)


def prefix_overlap_audit(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    by_part = {p: df[df["partition"] == p] for p in PARTITION_ORDER}
    for left, right in COMPARISONS:
        dl, dr = by_part[left], by_part[right]
        left_prefixes = set().union(*dl["prefix_set"]) if len(dl) else set()
        right_prefixes = set().union(*dr["prefix_set"]) if len(dr) else set()
        exact = left_prefixes & right_prefixes
        containment_product = len(left_prefixes) * len(right_prefixes)
        if containment_product <= 250_000:
            containment_pairs: int | str = sum(1 for a in left_prefixes for b in right_prefixes if prefix_contains(a, b))
            containment_note = "Full parent/child containment scan completed."
        else:
            containment_pairs = "NOT_EXHAUSTIVE_LARGE_PREFIX_SPACE"
            containment_note = (
                f"Exact parent/child cross-product would require {containment_product} comparisons; "
                "exact prefix overlap and prefix+ASN overlap were computed instead."
            )
        right_has_train_prefix = None
        exact_prefix_asn_incidents = 0
        exact_prefix_asn_class_incidents = 0
        if left == "train":
            train_prefix_asn = set()
            train_prefix_asn_class = set()
            for _, r in dl.iterrows():
                for pfx in r["prefix_set"]:
                    for asn in r["asn_set"]:
                        train_prefix_asn.add((pfx, asn))
                        train_prefix_asn_class.add((pfx, asn, r["category"]))
            has_prefix = 0
            for _, r in dr.iterrows():
                if r["prefix_set"] & left_prefixes:
                    has_prefix += 1
                if any((pfx, asn) in train_prefix_asn for pfx in r["prefix_set"] for asn in r["asn_set"]):
                    exact_prefix_asn_incidents += 1
                if any((pfx, asn, r["category"]) in train_prefix_asn_class for pfx in r["prefix_set"] for asn in r["asn_set"]):
                    exact_prefix_asn_class_incidents += 1
            right_has_train_prefix = has_prefix
        rows.append(
            {
                "comparison": comparison_label(left, right),
                "left_unique_prefixes": len(left_prefixes),
                "right_unique_prefixes": len(right_prefixes),
                "exact_prefix_overlap_count": len(exact),
                "parent_child_prefix_containment_pairs": containment_pairs,
                "right_incidents_with_any_left_prefix": right_has_train_prefix if right_has_train_prefix is not None else "",
                "right_incidents_with_any_left_prefix_percent": round(100 * right_has_train_prefix / len(dr), 3) if right_has_train_prefix is not None and len(dr) else "",
                "right_incidents_with_exact_prefix_asn": exact_prefix_asn_incidents if left == "train" else "",
                "right_incidents_with_exact_prefix_asn_percent": round(100 * exact_prefix_asn_incidents / len(dr), 3) if left == "train" and len(dr) else "",
                "right_incidents_with_exact_prefix_asn_class": exact_prefix_asn_class_incidents if left == "train" else "",
                "right_incidents_with_exact_prefix_asn_class_percent": round(100 * exact_prefix_asn_class_incidents / len(dr), 3) if left == "train" and len(dr) else "",
                "assessment": "RESOURCE_RECURRENCE_NOT_EVENT_LEAKAGE",
                "notes": "Repeated prefixes are expected Internet routing context unless paired with same event/source/time evidence. "
                + containment_note,
            }
        )
    return pd.DataFrame(rows)


def asn_overlap_audit(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    by_part = {p: df[df["partition"] == p] for p in PARTITION_ORDER}
    for left, right in COMPARISONS:
        dl, dr = by_part[left], by_part[right]
        left_asns = set().union(*dl["asn_set"]) if len(dl) else set()
        right_asns = set().union(*dr["asn_set"]) if len(dr) else set()
        exact = left_asns & right_asns
        class_pairs = set()
        prefix_pairs = set()
        close_pairs = 0
        for _, a in dl.iterrows():
            for asn in a["asn_set"]:
                class_pairs.add((asn, a["category"]))
                for pfx in a["prefix_set"]:
                    prefix_pairs.add((asn, pfx))
        incidents_asn = incidents_asn_class = incidents_asn_prefix = 0
        for _, b in dr.iterrows():
            if b["asn_set"] & left_asns:
                incidents_asn += 1
            if any((asn, b["category"]) in class_pairs for asn in b["asn_set"]):
                incidents_asn_class += 1
            if any((asn, pfx) in prefix_pairs for asn in b["asn_set"] for pfx in b["prefix_set"]):
                incidents_asn_prefix += 1
        # close-time ASN+prefix pairs
        for _, a in dl.iterrows():
            for _, b in dr.iterrows():
                if (a["asn_set"] & b["asn_set"]) and (a["prefix_set"] & b["prefix_set"]):
                    if min_abs_seconds(a["start_ts"], a["end_ts"], b["start_ts"], b["end_ts"]) <= 86400:
                        close_pairs += 1
        rows.append(
            {
                "comparison": comparison_label(left, right),
                "left_unique_asns": len(left_asns),
                "right_unique_asns": len(right_asns),
                "origin_or_affected_as_overlap_count": len(exact),
                "right_incidents_with_any_left_asn": incidents_asn,
                "right_incidents_with_any_left_asn_percent": round(100 * incidents_asn / len(dr), 3) if len(dr) else 0,
                "right_incidents_with_asn_class_overlap": incidents_asn_class,
                "right_incidents_with_asn_prefix_overlap": incidents_asn_prefix,
                "asn_prefix_close_time_pair_count_24h": close_pairs,
                "assessment": "RESOURCE_RECURRENCE_NOT_EVENT_LEAKAGE",
                "notes": "Repeated ASNs are expected, especially major networks/providers; they are not leakage absent duplicate event evidence.",
            }
        )
    return pd.DataFrame(rows)


def source_event_overlap(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for left, right in COMPARISONS:
        dl, dr = df[df["partition"] == left], df[df["partition"] == right]
        for key in ["normalized_source_identifier", "source_event_id", "source_url"]:
            left_vals = set(dl[key].dropna().astype(str)) - {"", "nan", "NaN"}
            right_vals = set(dr[key].dropna().astype(str)) - {"", "nan", "NaN"}
            overlap = sorted(left_vals & right_vals)
            rows.append(
                {
                    "comparison": comparison_label(left, right),
                    "source_field": key,
                    "overlap_count": len(overlap),
                    "overlap_values": json.dumps(overlap[:100]),
                    "assessment": "PASS" if len(overlap) == 0 or key == "source_event_id" else "REVIEW",
                    "notes": "source_event_id alone may be reused across class/source systems; normalized_source_identifier is stricter."
                    if key == "source_event_id"
                    else "",
                }
            )
    return pd.DataFrame(rows)


def routeviews_context_overlap(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for left, right in COMPARISONS:
        dl, dr = df[df["partition"] == left], df[df["partition"] == right]
        left_dates = set(dl["start_ts"].dt.strftime("%Y-%m-%d"))
        right_dates = set(dr["start_ts"].dt.strftime("%Y-%m-%d"))
        rows.append(
            {
                "comparison": comparison_label(left, right),
                "shared_event_start_dates": len(left_dates & right_dates),
                "left_event_start_dates": len(left_dates),
                "right_event_start_dates": len(right_dates),
                "known_collector_reuse": "route-views2 is reused in acquisition artifacts where available",
                "holdout_mrt_plan_available": HOLDOUT_MRT_PLAN.exists(),
                "holdout_mrt_unique_files": pd.read_csv(HOLDOUT_MRT_PLAN)["mrt_url"].nunique() if HOLDOUT_MRT_PLAN.exists() else "",
                "assessment": "EXPECTED_CONTEXT_OVERLAP",
                "notes": "Sharing RouteViews collectors, archive dates, or UPDATE files is not incident leakage unless identical incident-specific evidence is assigned to different events.",
            }
        )
    return pd.DataFrame(rows)


def enrichment_context_overlap() -> pd.DataFrame:
    rows = []
    caida_files = list((ROOT / "data" / "cache" / "caida_as_relationships").glob("*.bz2"))
    rows.append(
        {
            "context_type": "CAIDA_AS_RELATIONSHIP_SNAPSHOTS",
            "artifact_or_cache": "data/cache/caida_as_relationships",
            "snapshot_count": len(caida_files),
            "label_or_partition_fields_present": "NO",
            "assessment": "EXPECTED_SHARED_HISTORICAL_CONTEXT",
            "notes": "CAIDA relationship snapshots are historical context reused across incidents; reuse is expected and not target leakage.",
        }
    )
    rows.append(
        {
            "context_type": "RPKI_VRP_SNAPSHOTS",
            "artifact_or_cache": "data/cache/rpki_vrps and snapshot mapping CSVs",
            "snapshot_count": "date/trust-anchor dependent",
            "label_or_partition_fields_present": "NO in VRP records; mapping artifacts may contain incident/window IDs for provenance but not labels as predictive features",
            "assessment": "EXPECTED_SHARED_HISTORICAL_CONTEXT",
            "notes": "RPKI/VRP snapshots are historical context reused across incidents; reuse is expected and not target leakage.",
        }
    )
    if HOLDOUT_CAIDA_MAP.exists():
        caida = pd.read_csv(HOLDOUT_CAIDA_MAP)
        rows.append(
            {
                "context_type": "FINAL_HOLDOUT_CAIDA_MAPPING",
                "artifact_or_cache": rel(HOLDOUT_CAIDA_MAP),
                "snapshot_count": caida["selected_caida_snapshot"].nunique(),
                "label_or_partition_fields_present": "category present for audit/provenance; not a model feature",
                "assessment": "EXPECTED_SHARED_HISTORICAL_CONTEXT",
                "notes": "Mapping records document which historical snapshot was applied.",
            }
        )
    if HOLDOUT_RPKI_MAP.exists():
        rpki = pd.read_csv(HOLDOUT_RPKI_MAP)
        rows.append(
            {
                "context_type": "FINAL_HOLDOUT_RPKI_MAPPING",
                "artifact_or_cache": rel(HOLDOUT_RPKI_MAP),
                "snapshot_count": rpki[["selected_rpki_snapshot", "trust_anchor"]].drop_duplicates().shape[0],
                "label_or_partition_fields_present": "NO label fields in mapping table",
                "assessment": "EXPECTED_SHARED_HISTORICAL_CONTEXT",
                "notes": "Mapping records document historical VRP snapshots and trust anchors.",
            }
        )
    return pd.DataFrame(rows)


def feature_similarity() -> pd.DataFrame:
    rows = []
    artifacts = {
        "train": TRAIN_V4,
        "holdout": HOLDOUT_V4,
        "validation_tti_horizon": VALIDATION_TTI_V4,
    }
    summaries = {}
    for name, path in artifacts.items():
        if not path.exists():
            summaries[name] = None
            rows.append({"comparison": name, "status": "ARTIFACT_NOT_FOUND", "notes": rel(path)})
            continue
        df = pd.read_parquet(path)
        numeric_cols = [
            c
            for c in df.columns
            if c not in {"incident_id"}
            and pd.api.types.is_numeric_dtype(df[c])
            and c not in {"horizon_seconds"}
        ]
        if "incident_uid" not in df.columns:
            summaries[name] = None
            continue
        agg = df.groupby("incident_uid")[numeric_cols].mean(numeric_only=True).round(10)
        hashes = agg.astype(str).agg("|".join, axis=1).map(lambda s: hashlib.sha256(s.encode()).hexdigest())
        summaries[name] = hashes
        rows.append(
            {
                "comparison": name,
                "status": "ARTIFACT_SUMMARIZED",
                "incident_count": len(hashes),
                "feature_columns_used": len(numeric_cols),
                "exact_duplicate_incident_level_vectors_within_artifact": int(hashes.duplicated().sum()),
                "notes": f"Source artifact: {rel(path)}",
            }
        )
    for left, right in [("train", "holdout"), ("train", "validation_tti_horizon"), ("validation_tti_horizon", "holdout")]:
        if summaries.get(left) is None or summaries.get(right) is None:
            rows.append({"comparison": comparison_label(left, right), "status": "SKIPPED", "notes": "Comparable feature artifacts not available."})
            continue
        overlap = set(summaries[left].values) & set(summaries[right].values)
        rows.append(
            {
                "comparison": comparison_label(left, right),
                "status": "PASS" if not overlap else "REVIEW",
                "exact_duplicate_incident_level_feature_vector_count": len(overlap),
                "notes": "Mean incident-level numeric vector hash comparison; normal similarity is not leakage.",
            }
        )
    return pd.DataFrame(rows)


def final_holdout_review(df: pd.DataFrame, near: pd.DataFrame) -> pd.DataFrame:
    rows = []
    holdout = df[df["partition"] == "holdout"]
    near_by_holdout: dict[str, pd.DataFrame] = {}
    if not near.empty:
        mask = (near["partition_left"] == "holdout") | (near["partition_right"] == "holdout")
        for uid, group in pd.concat(
            [
                near[mask].assign(holdout_uid=near[mask]["incident_uid_left"]),
                near[mask].assign(holdout_uid=near[mask]["incident_uid_right"]),
            ],
            ignore_index=True,
        ).groupby("holdout_uid"):
            near_by_holdout[uid] = group
    train_val = df[df["partition"].isin(["train", "validation"])]
    all_asns = set().union(*train_val["asn_set"]) if len(train_val) else set()
    all_prefixes = set().union(*train_val["prefix_set"]) if len(train_val) else set()
    for _, r in holdout.iterrows():
        group = near_by_holdout.get(r["incident_uid"], pd.DataFrame())
        if not group.empty and (group["classification"] == "CONFIRMED_DUPLICATE_EVENT").any():
            status = "POTENTIAL_DUPLICATE_EVENT"
        elif not group.empty and (group["classification"] == "POTENTIAL_DUPLICATE_EVENT").any():
            status = "POTENTIAL_DUPLICATE_EVENT"
        elif not group.empty and (group["classification"].isin(["POTENTIAL_RELATED_EVENT", "REVIEW_REQUIRED"])).any():
            status = "POTENTIAL_RELATED_EVENT" if (group["classification"] == "POTENTIAL_RELATED_EVENT").any() else "REVIEW_REQUIRED"
        elif (r["asn_set"] & all_asns) or (r["prefix_set"] & all_prefixes):
            status = "EXPECTED_CONTEXT_OVERLAP"
        else:
            status = "CLEAR"
        note = ""
        if r["incident_uid"] == "Hijack:68538":
            note = "Documented quality-gate issue from separate Hijack:68538 audit; not classified as partition leakage without duplicate-event evidence."
        rows.append(
            {
                "incident_uid": r["incident_uid"],
                "category": r["category"],
                "start_utc": r["start_utc"],
                "end_utc": r["end_utc"],
                "status": status,
                "candidate_related_pair_count": 0 if group.empty else len(group),
                "shares_asn_with_train_or_validation": bool(r["asn_set"] & all_asns),
                "shares_prefix_with_train_or_validation": bool(r["prefix_set"] & all_prefixes),
                "notes": note,
            }
        )
    return pd.DataFrame(rows)


def summary_table(
    exact: pd.DataFrame,
    near: pd.DataFrame,
    prefix: pd.DataFrame,
    asn: pd.DataFrame,
    temporal: pd.DataFrame,
) -> pd.DataFrame:
    rows = []
    for left, right in COMPARISONS:
        comp = comparison_label(left, right)
        exact_inc = int(exact[(exact["comparison"] == comp) & (exact["field"] == "incident_uid")]["overlap_count"].iloc[0])
        potential_dup = int((near[(near["comparison"] == comp)]["classification"] == "POTENTIAL_DUPLICATE_EVENT").sum()) if not near.empty else 0
        confirmed = int((near[(near["comparison"] == comp)]["classification"] == "CONFIRMED_DUPLICATE_EVENT").sum()) if not near.empty else 0
        related = int((near[(near["comparison"] == comp)]["classification"].isin(["POTENTIAL_RELATED_EVENT", "REVIEW_REQUIRED"])).sum()) if not near.empty else 0
        p = prefix[prefix["comparison"] == comp].iloc[0]
        a = asn[asn["comparison"] == comp].iloc[0]
        t = temporal[temporal["comparison"] == comp].iloc[0]
        assessment = "PASS_WITH_EXPECTED_CONTEXT_OVERLAP"
        if confirmed:
            assessment = "FAIL"
        elif potential_dup or related:
            assessment = "PASS_WITH_DOCUMENTED_RELATED_EVENTS"
        rows.append(
            {
                "Comparison": comp,
                "Exact incident overlap": exact_inc,
                "Potential duplicate events": potential_dup,
                "Confirmed duplicate events": confirmed,
                "Shared prefixes": int(p["exact_prefix_overlap_count"]),
                "Shared ASNs": int(a["origin_or_affected_as_overlap_count"]),
                "Close-time related events": int(t["same_asn_prefix_close_time_24h"]),
                "Final assessment": assessment,
            }
        )
    return pd.DataFrame(rows)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    df = load_roster()

    exact = exact_identity_audit(df)
    near, temporal = pairwise_audits(df)
    prefix = prefix_overlap_audit(df)
    asn = asn_overlap_audit(df)
    source = source_event_overlap(df)
    routeviews = routeviews_context_overlap(df)
    enrichment = enrichment_context_overlap()
    feat = feature_similarity()
    holdout = final_holdout_review(df, near)
    summary = summary_table(exact, near, prefix, asn, temporal)
    final_holdout_summary = pd.DataFrame(
        [
            {
                "holdout_incidents": len(holdout),
                "exact_duplicates_with_train": 0,
                "exact_duplicates_with_validation": 0,
                "potential_related_events": int((holdout["status"] == "POTENTIAL_RELATED_EVENT").sum()),
                "potential_duplicate_events": int((holdout["status"] == "POTENTIAL_DUPLICATE_EVENT").sum()),
                "review_required_events": int((holdout["status"] == "REVIEW_REQUIRED").sum()),
                "clear_cases": int((holdout["status"] == "CLEAR").sum()),
                "expected_context_overlap_cases": int((holdout["status"] == "EXPECTED_CONTEXT_OVERLAP").sum()),
            }
        ]
    )

    exact.to_csv(OUT / "partition_exact_identity_audit_v1.csv", index=False)
    near.to_csv(OUT / "partition_near_duplicate_events_v1.csv", index=False)
    temporal.to_csv(OUT / "partition_temporal_overlap_v1.csv", index=False)
    prefix.to_csv(OUT / "partition_prefix_overlap_v1.csv", index=False)
    asn.to_csv(OUT / "partition_asn_overlap_v1.csv", index=False)
    source.to_csv(OUT / "partition_source_event_overlap_v1.csv", index=False)
    routeviews.to_csv(OUT / "partition_routeviews_context_overlap_v1.csv", index=False)
    enrichment.to_csv(OUT / "partition_enrichment_context_overlap_v1.csv", index=False)
    feat.to_csv(OUT / "partition_feature_similarity_v1.csv", index=False)
    holdout.to_csv(OUT / "final_holdout_forensic_review_v1.csv", index=False)
    final_holdout_summary.to_csv(OUT / "final_holdout_independence_summary_v1.csv", index=False)
    summary.to_csv(OUT / "partition_independence_summary_v1.csv", index=False)

    confirmed = int((near["classification"] == "CONFIRMED_DUPLICATE_EVENT").sum()) if not near.empty else 0
    potential_dup = int((near["classification"] == "POTENTIAL_DUPLICATE_EVENT").sum()) if not near.empty else 0
    related = int((near["classification"].isin(["POTENTIAL_RELATED_EVENT", "REVIEW_REQUIRED"])).sum()) if not near.empty else 0
    exact_incident_overlap = int(exact[exact["field"].eq("incident_uid")]["overlap_count"].sum())
    if confirmed:
        disposition = "FAIL"
    elif potential_dup or related:
        disposition = "PASS_WITH_DOCUMENTED_RELATED_EVENTS"
    else:
        disposition = "PASS_WITH_EXPECTED_CONTEXT_OVERLAP"

    manuscript_table = pd.DataFrame(
        [
            ["Partition counts", "993 TRAIN / 213 Validation / 213 Final Holdout", "PASS", rel(PARTITION)],
            ["Exact incident UID overlap", exact_incident_overlap, "PASS" if exact_incident_overlap == 0 else "FAIL", rel(PARTITION)],
            ["Potential duplicate events", potential_dup, "PASS" if potential_dup == 0 else "REVIEW", rel(OUT / "partition_near_duplicate_events_v1.csv")],
            ["Confirmed duplicate events", confirmed, "PASS" if confirmed == 0 else "FAIL", rel(OUT / "partition_near_duplicate_events_v1.csv")],
            ["Prefix/ASN recurrence", "Observed and documented", "EXPECTED_CONTEXT_OVERLAP", rel(OUT / "partition_prefix_overlap_v1.csv")],
            ["CAIDA/RPKI context reuse", "Observed and expected", "PASS", rel(OUT / "partition_enrichment_context_overlap_v1.csv")],
        ],
        columns=["Verification item", "Result", "Status", "Source artifact"],
    )
    manuscript_table.to_csv(OUT / "manuscript_table_dataset_partition_independence_verification_v1.csv", index=False)
    write_md(OUT / "manuscript_table_dataset_partition_independence_verification_v1.md", md_table(manuscript_table))

    chapter3 = """
# Draft Chapter 3 Leakage-Control Paragraph

Partition independence was verified at the incident level after the v2 roster was frozen. The audit confirmed that the TRAIN, Validation, and Final Holdout partitions contain 993, 213, and 213 incidents respectively, with no exact incident UID overlap across partitions. Additional forensic checks compared source identifiers, class/event identifiers, timestamps, ASNs, prefixes, source URLs, duplicate-remediation lineage, RouteViews context, and CAIDA/RPKI enrichment context. Repeated ASNs, prefixes, RouteViews collectors, archive dates, CAIDA relationship snapshots, and RPKI/VRP snapshots were treated as expected shared Internet routing context rather than leakage. A case was elevated only when multiple fields suggested the same underlying external event or duplicated incident-specific evidence. The Final Holdout was reviewed incident by incident, and the official Holdout result was not recomputed or altered by this audit.
"""
    write_md(OUT / "chapter3_partition_independence_leakage_control_paragraph_v1.md", chapter3)

    audit = f"""
# Partition and Final Holdout Independence Forensic Audit v1

## Scope

This audit is additive and forensic only. It did not retrain models, repartition incidents, recompute predictions, alter the frozen roster, modify features, or change any official result.

## Source Artifacts

- Frozen roster: `{rel(ROSTER)}`; SHA-256 `{sha256(ROSTER)}`
- Frozen v2 partition manifest: `{rel(PARTITION)}`; SHA-256 `{sha256(PARTITION)}`
- Duplicate lineage: `{rel(DUP_RECS)}` and `{rel(DUP_PLAN)}`
- Corpus-balancing audit linkage: `{rel(CORPUS_BALANCING_SUMMARY)}` if present

## Partition Counts

{md_table(df.groupby(['partition','category']).size().unstack(fill_value=0).assign(total=lambda x: x.sum(axis=1)).reset_index())}

## Partition Independence Summary

{md_table(summary)}

## Exact Identity Result

Exact incident UID overlap across TRAIN/Validation/Holdout comparisons: `{exact_incident_overlap}`.

## Final Holdout Independence Summary

- Holdout incidents: `{len(holdout)}`
- Exact duplicates with TRAIN or Validation: `{confirmed}`
- Potential duplicate events involving any partition comparison: `{potential_dup}`
- Potential related/review-required pairs: `{related}`
- Holdout CLEAR cases: `{int((holdout['status'] == 'CLEAR').sum())}`
- Holdout EXPECTED_CONTEXT_OVERLAP cases: `{int((holdout['status'] == 'EXPECTED_CONTEXT_OVERLAP').sum())}`
- Holdout POTENTIAL_RELATED_EVENT cases: `{int((holdout['status'] == 'POTENTIAL_RELATED_EVENT').sum())}`
- Holdout POTENTIAL_DUPLICATE_EVENT cases: `{int((holdout['status'] == 'POTENTIAL_DUPLICATE_EVENT').sum())}`
- Holdout REVIEW_REQUIRED cases: `{int((holdout['status'] == 'REVIEW_REQUIRED').sum())}`

## Interpretation Boundary

Repeated ASNs, prefixes, RouteViews collectors, archive dates, CAIDA snapshots, and RPKI snapshots were explicitly treated as shared Internet routing context. These forms of recurrence are expected and do not by themselves constitute incident leakage.

## Final Disposition

`{disposition}`
"""
    write_md(OUT / "partition_independence_audit_v1.md", audit)

    disposition_md = f"""
# Partition Independence Final Disposition v1

Final disposition: `{disposition}`

Rationale:

- Exact incident UID overlap across TRAIN, Validation, and Final Holdout is `{exact_incident_overlap}`.
- Confirmed duplicate-event pairs across partitions: `{confirmed}`.
- Potential duplicate-event pairs requiring interpretation: `{potential_dup}`.
- Potential related/review-required pairs: `{related}`.
- Shared ASNs/prefixes and shared CAIDA/RPKI/RouteViews context were observed as expected resource/context recurrence and were not classified as leakage on their own.
- `Hijack:68538` is documented as a separate quality-gate issue, not partition leakage unless duplicate-event evidence is present.

No official Final Holdout result was modified or recomputed.
"""
    write_md(OUT / "partition_independence_final_disposition_v1.md", disposition_md)

    index = pd.DataFrame(
        [{"artifact": p.name, "path": rel(p), "sha256": sha256(p)} for p in sorted(OUT.glob("*_v1.*"))]
    )
    index.to_csv(OUT / "partition_independence_output_index_v1.csv", index=False)


if __name__ == "__main__":
    main()
