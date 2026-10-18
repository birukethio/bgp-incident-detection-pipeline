from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection import rpki_features as rpki  # noqa: E402


def test_validate_rov_valid_invalid_and_not_found():
    vrps = [
        rpki.Vrp(prefix=rpki.parse_prefix("203.0.113.0/24"), origin_asn="64500", max_length=24, trust_anchor="test"),
        rpki.Vrp(prefix=rpki.parse_prefix("198.51.100.0/24"), origin_asn="64501", max_length=24, trust_anchor="test"),
        rpki.Vrp(prefix=rpki.parse_prefix("192.0.2.0/24"), origin_asn="64502", max_length=24, trust_anchor="test"),
    ]

    assert rpki.validate_rov("203.0.113.0/24", "64500", vrps).state == "VALID"
    assert rpki.validate_rov("198.51.100.0/24", "64599", vrps).state == "INVALID_ORIGIN"
    assert rpki.validate_rov("192.0.2.128/25", "64502", vrps).state == "INVALID_LENGTH"
    assert rpki.validate_rov("10.0.0.0/24", "64500", vrps).state == "NOT_FOUND"
    assert rpki.validate_rov("", "64500", vrps).state == "UNEVALUABLE"


def test_indexed_vrp_lookup_matches_list_lookup():
    vrps = [
        rpki.Vrp(prefix=rpki.parse_prefix("203.0.113.0/24"), origin_asn="64500", max_length=24, trust_anchor="test"),
        rpki.Vrp(prefix=rpki.parse_prefix("203.0.112.0/23"), origin_asn="64501", max_length=24, trust_anchor="test"),
    ]
    index = rpki.build_vrp_index(vrps)

    assert rpki.validate_rov("203.0.113.0/24", "64500", vrps).state == rpki.validate_rov("203.0.113.0/24", "64500", index).state
    assert rpki.validate_rov("203.0.113.0/24", "64599", vrps).state == rpki.validate_rov("203.0.113.0/24", "64599", index).state


def test_snapshot_mapping_uses_observation_date_without_future_state():
    assert rpki.snapshot_date_for_observation("2025-03-31T23:55:00.000Z") == "2025-03-31"
    assert rpki.snapshot_url("arin.tal", "2025-03-31").endswith("/arin.tal/2025/03/31/roas.csv.xz")


def test_observation_count_weights_window_features(monkeypatch):
    windows = pd.DataFrame(
        [
            {
                "incident_uid": "Hijack:1",
                "category": "Hijack",
                "partition": "train",
                "window_id": "w1",
                "window_start": "2025-01-01T00:00:00.000Z",
                "window_end": "2025-01-01T00:05:00.000Z",
            }
        ]
    )
    evidence = pd.DataFrame(
        [
            {
                "window_id": "w1",
                "incident_uid": "Hijack:1",
                "window_start": "2025-01-01T00:00:00.000Z",
                "window_end": "2025-01-01T00:05:00.000Z",
                "prefix": "203.0.113.0/24",
                "origin_asn": "64500",
                "normalized_as_path": "64496 64500",
                "observation_count": 500,
                "collector": "route-views2",
                "source_mrt_count": 1,
            }
        ]
    )
    monkeypatch.setattr(rpki, "load_vrps", lambda date: [rpki.Vrp(prefix=rpki.parse_prefix("203.0.113.0/24"), origin_asn="64500", max_length=24, trust_anchor="test")])

    features, _, _ = rpki.aggregate_window_features(windows, evidence)

    row = features.iloc[0]
    assert row["partition"] == "train"
    assert row["window_id"] == "w1"
    assert row["rpki_evidence_observation_count"] == 500
    assert row["rpki_valid_observation_count"] == 500
    assert row["rpki_valid_observation_ratio"] == 1.0


def test_zero_evidence_window_is_not_forced_to_valid(monkeypatch):
    windows = pd.DataFrame(
        [
            {
                "incident_uid": "Leak:1",
                "category": "Leak",
                "partition": "train",
                "window_id": "w1",
                "window_start": "2025-01-01T00:00:00.000Z",
                "window_end": "2025-01-01T00:05:00.000Z",
            }
        ]
    )
    evidence = pd.DataFrame(columns=["window_id", "incident_uid", "prefix", "origin_asn", "observation_count"])
    monkeypatch.setattr(rpki, "load_vrps", lambda date: [])

    features, _, _ = rpki.aggregate_window_features(windows, evidence)

    row = features.iloc[0]
    assert row["rpki_evidence_observation_count"] == 0
    assert row["rpki_valid_observation_count"] == 0
    assert pd.isna(row["rpki_valid_observation_ratio"])
    assert row["rpki_dominant_state_code"] == rpki.STATE_TO_CODE["NO_PREFIX_ORIGIN_EVIDENCE"]


def test_pilot_window_loader_rejects_validation_or_holdout(tmp_path, monkeypatch):
    bad_windows = pd.DataFrame(
        [
            {
                "incident_uid": f"Hijack:{idx}",
                "category": "Hijack",
                "partition": "train" if idx else "validation",
                "window_id": f"w{idx}",
                "window_start": "2025-01-01T00:00:00.000Z",
                "window_end": "2025-01-01T00:05:00.000Z",
            }
            for idx in range(661)
        ]
    )
    path = tmp_path / "bad_pilot.parquet"
    bad_windows.to_parquet(path, index=False)
    monkeypatch.setattr(rpki, "PILOT_WINDOWS", path)

    try:
        rpki.load_pilot_windows()
    except ValueError as error:
        assert "TRAIN only" in str(error)
    else:
        raise AssertionError("Validation/Holdout rows must be rejected")


def test_recommended_feature_count_is_not_historical_placeholder():
    assert len(rpki.RPKI_FEATURE_NAMES) == 16
    assert "rpki_invalid_origin_observation_count" in rpki.RPKI_FEATURE_NAMES
