from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection import rpki_features as rpki  # noqa: E402
from bgp_incident_detection import rpki_train_enrichment as train_rpki  # noqa: E402


def test_rpki_schema_preserves_verified_feature_inventory(tmp_path, monkeypatch):
    schema = tmp_path / "rpki_feature_schema_v1.yaml"
    monkeypatch.setattr(train_rpki, "RPKI_SCHEMA", schema)

    train_rpki.write_rpki_schema()

    text = schema.read_text(encoding="utf-8")
    assert "rpki_feature_version: v1" in text
    assert "rpki_feature_count: 16" in text
    for name in rpki.RPKI_FEATURE_NAMES:
        assert f"name: {name}" in text


def test_validate_train_corpus_rejects_non_train_partition():
    df = pd.DataFrame(
        {
            "incident_uid": [f"Hijack:{idx}" for idx in range(993)],
            "category": ["Hijack"] * 331 + ["Leak"] * 331 + ["Outage"] * 331,
            "partition": ["train"] * 992 + ["holdout"],
            "window_id": [f"w{idx}" for idx in range(993)],
            "window_start": ["2025-01-01T00:00:00.000Z"] * 993,
            **{name: [0] * 993 for name in rpki.BEHAVIORAL_FEATURE_NAMES},
        }
    )
    df = pd.concat([df] * 69, ignore_index=True).iloc[:68031].copy()
    df["window_id"] = [f"w{idx}" for idx in range(len(df))]

    try:
        train_rpki.validate_train_corpus(df, rpki.BEHAVIORAL_FEATURE_NAMES)
    except ValueError as error:
        assert "Validation/Holdout" in str(error)
    else:
        raise AssertionError("non-TRAIN partition must fail validation")


def test_snapshot_mapping_is_deterministic_exact_date():
    assert rpki.snapshot_date_for_observation("2024-07-29T23:55:00.000Z") == "2024-07-29"
    assert rpki.snapshot_url("ripencc.tal", "2024-07-29").endswith("/ripencc.tal/2024/07/29/roas.csv.xz")


def test_aggregate_batch_uses_observation_count_and_one_row_per_window(tmp_path, monkeypatch):
    frozen = pd.DataFrame(
        [
            {
                "incident_uid": "Hijack:1",
                "incident_id": "1",
                "category": "Hijack",
                "partition": "train",
                "window_id": "w1",
                "window_start": "2025-01-01T00:00:00.000Z",
                "window_end": "2025-01-01T00:05:00.000Z",
                "temporal_status": "ACTIVE",
            }
        ]
    )
    evidence = pd.DataFrame(
        [
            {
                "window_id": "w1",
                "incident_uid": "Hijack:1",
                "window_start": "2025-01-01T00:00:00.000Z",
                "prefix": "203.0.113.0/24",
                "origin_asn": "64500",
                "observation_count": 7,
            },
            {
                "window_id": "w1",
                "incident_uid": "Hijack:1",
                "window_start": "2025-01-01T00:00:00.000Z",
                "prefix": "198.51.100.0/24",
                "origin_asn": "64599",
                "observation_count": 3,
            },
        ]
    )
    evidence_path = tmp_path / "batch_001.parquet"
    evidence.to_parquet(evidence_path, index=False)
    out_dir = tmp_path / "features"
    monkeypatch.setattr(train_rpki, "evidence_batch_path", lambda batch_id: evidence_path)
    monkeypatch.setattr(train_rpki, "RPKI_BATCH_DIR", out_dir)

    class Cache:
        def get(self, snapshot_date):
            return rpki.build_vrp_index(
                [
                    rpki.Vrp(prefix=rpki.parse_prefix("203.0.113.0/24"), origin_asn="64500", max_length=24, trust_anchor="test"),
                    rpki.Vrp(prefix=rpki.parse_prefix("198.51.100.0/24"), origin_asn="64501", max_length=24, trust_anchor="test"),
                ]
            )

    result = train_rpki.aggregate_rpki_batch("volume_batch_001", ["Hijack:1"], frozen, Cache())
    output = pd.read_parquet(out_dir / "batch_001.parquet")

    assert result["feature_rows"] == 1
    assert output.iloc[0]["rpki_valid_observation_count"] == 7
    assert output.iloc[0]["rpki_invalid_origin_observation_count"] == 3
    assert output.iloc[0]["rpki_evidence_observation_count"] == 10


def test_compare_features_detects_changed_values():
    left = pd.DataFrame({"window_id": ["w1"], "feature_a": [1]})
    right = pd.DataFrame({"window_id": ["w1"], "feature_a": [2]})

    rows = train_rpki.compare_features(left, right, ["feature_a"], "Behavioral")

    assert rows[0]["status"] == "FAIL"


def test_full_train_rpki_artifacts_when_present():
    if not train_rpki.TRAIN_RPKI_FEATURES.exists():
        return
    features = pd.read_parquet(train_rpki.TRAIN_RPKI_FEATURES)

    assert len(features) == 68031
    assert features["window_id"].nunique() == 68031
    assert features["incident_uid"].nunique() == 993
    assert set(features["partition"].astype(str)) == {"train"}
    assert all(name in features.columns for name in rpki.RPKI_FEATURE_NAMES)
    assert len(rpki.RPKI_FEATURE_NAMES) == 16


def test_v3_v4_frozen_artifacts_when_present():
    if not train_rpki.FROZEN_V3.exists() or not train_rpki.FROZEN_V4.exists():
        return
    v3 = pd.read_parquet(train_rpki.FROZEN_V3)
    v4 = pd.read_parquet(train_rpki.FROZEN_V4)

    assert len(v3) == 68031
    assert len(v4) == 68031
    assert len([name for name in rpki.BEHAVIORAL_FEATURE_NAMES if name in v3.columns]) == 44
    assert len([name for name in rpki.RPKI_FEATURE_NAMES if name in v3.columns]) == 16
    assert len([name for name in rpki.BEHAVIORAL_FEATURE_NAMES if name in v4.columns]) == 44
    assert len([name for name in train_rpki.CAIDA_FEATURE_NAMES if name in v4.columns]) == 14
    assert len([name for name in rpki.RPKI_FEATURE_NAMES if name in v4.columns]) == 16
    assert set(v3["partition"].astype(str)) == {"train"}
    assert set(v4["partition"].astype(str)) == {"train"}
