from __future__ import annotations

import pandas as pd
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection import caida_train_enrichment as enrich  # noqa: E402
from bgp_incident_detection.caida_features import CAIDA_FEATURE_NAMES  # noqa: E402


def test_build_snapshot_mapping_is_same_month_and_one_row_per_window(tmp_path, monkeypatch):
    monkeypatch.setattr(enrich, "SNAPSHOT_MAPPING", tmp_path / "mapping.csv")
    windows = pd.DataFrame(
        [
            {
                "window_id": "Hijack:1_20240101T000000Z",
                "incident_uid": "Hijack:1",
                "category": "Hijack",
                "window_start": "2024-01-01T00:00:00Z",
            },
            {
                "window_id": "Leak:2_20240229T235500Z",
                "incident_uid": "Leak:2",
                "category": "Leak",
                "window_start": "2024-02-29T23:55:00Z",
            },
        ]
    )

    mapping = enrich.build_snapshot_mapping(windows)

    assert len(mapping) == 2
    assert mapping["window_id"].is_unique
    assert mapping["mapping_type"].tolist() == ["SAME_MONTH", "SAME_MONTH"]
    assert mapping["selected_caida_snapshot"].tolist() == [
        "20240101.as-rel2.txt.bz2",
        "20240201.as-rel2.txt.bz2",
    ]


def test_schema_writer_preserves_verified_caida_feature_order(tmp_path, monkeypatch):
    schema = tmp_path / "caida_feature_schema_v1.yaml"
    monkeypatch.setattr(enrich, "CAIDA_SCHEMA", schema)

    enrich.write_caida_schema()

    text = schema.read_text(encoding="utf-8")
    assert "feature_count: 14" in text
    positions = [text.index(f"name: {feature}") for feature in CAIDA_FEATURE_NAMES]
    assert positions == sorted(positions)


def test_join_and_audit_preserves_behavioral_values(tmp_path, monkeypatch):
    monkeypatch.setattr(enrich, "TRAIN_ENRICHED", tmp_path / "train_behavioral_caida_v1.parquet")
    monkeypatch.setattr(enrich, "INTEGRITY_AUDIT", tmp_path / "integrity.csv")
    monkeypatch.setattr(enrich, "CORPUS_AUDIT", tmp_path / "corpus.csv")
    monkeypatch.setattr(enrich, "BEHAVIORAL_FEATURE_NAMES", ["update_count", "announcement_count"])

    frozen = pd.DataFrame(
        {
            "incident_uid": ["Hijack:1", "Leak:2", "Outage:3"],
            "incident_id": ["1", "2", "3"],
            "category": ["Hijack", "Leak", "Outage"],
            "partition": ["train", "train", "train"],
            "window_id": ["w1", "w2", "w3"],
            "window_start": ["2024-01-01T00:00:00Z"] * 3,
            "window_end": ["2024-01-01T00:05:00Z"] * 3,
            "temporal_status": ["INCIDENT_ACTIVE"] * 3,
            "update_count": [1, 2, 3],
            "announcement_count": [4, 5, 6],
        }
    )
    caida = pd.DataFrame({"window_id": ["w1", "w2", "w3"], "selected_caida_snapshot": ["20240101.as-rel2.txt.bz2"] * 3})
    for feature in CAIDA_FEATURE_NAMES:
        caida[feature] = [0, 1, 2]
    quality_rows = [{"feature_name": feature, "status": "PASS"} for feature in CAIDA_FEATURE_NAMES]

    enriched, audit = enrich.join_and_audit(frozen, caida, quality_rows)

    assert len(enriched) == 3
    assert enriched["update_count"].tolist() == [1, 2, 3]
    assert enriched["announcement_count"].tolist() == [4, 5, 6]
    assert audit["behavioral_feature_count"] == 2
    assert audit["caida_feature_count"] == 14
    assert audit["total_model_feature_count"] == 16
    assert (tmp_path / "integrity.csv").exists()


def test_evidence_rows_collapse_duplicate_observations_and_preserve_multiplicity():
    parsed = {
        "prefix": "203.0.113.0/24",
        "origin_asn": "64500",
        "as_path": "64496 64497 64497 64500",
    }
    key = enrich.evidence_key(parsed, "w1", "route-views2")
    counts = {key: 3}
    source_files = {key: {"updates.20240101.0000.bz2", "updates.20240101.0015.bz2"}}
    meta = {"w1": {"incident_uid": "Leak:1", "window_start": "2024-01-01T00:00:00Z", "window_end": "2024-01-01T00:05:00Z"}}

    rows = enrich.evidence_rows_from_counts(counts, source_files, meta, "volume_batch_001")

    assert len(rows) == 1
    row = rows.iloc[0]
    assert row["window_id"] == "w1"
    assert row["incident_uid"] == "Leak:1"
    assert row["normalized_as_path"] == "64496 64497 64500"
    assert row["observation_count"] == 3
    assert row["source_mrt_count"] == 2


def test_evidence_key_keeps_window_id_unchanged():
    parsed = {"prefix": "", "origin_asn": "", "as_path": "1 2 2 3"}
    key = enrich.evidence_key(parsed, "Hijack:1_20240101T000000Z", "route-views2")
    assert key[0] == "Hijack:1_20240101T000000Z"
    assert key[3] == "1 2 3"


def test_fast_relevance_prefilter_uses_structured_fields():
    parts = ["BGP4MP", "1704067200", "A", "192.0.2.1", "64496", "203.0.113.0/24", "64510 64511 64512"]

    assert enrich.fast_relevance_prefilter(parts, {"64512"}, set(), [])
    assert enrich.fast_relevance_prefilter(parts, set(), {"203.0.113.0/24"}, [])
    assert enrich.fast_relevance_prefilter(parts, set(), set(), ["64510", "64512"])
    assert not enrich.fast_relevance_prefilter(parts, {"65000"}, {"198.51.100.0/24"}, ["64510", "65000"])
