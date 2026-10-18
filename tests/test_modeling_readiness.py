from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection import modeling_readiness as mr  # noqa: E402
from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES  # noqa: E402
from bgp_incident_detection.caida_features import CAIDA_FEATURE_NAMES  # noqa: E402
from bgp_incident_detection.rpki_features import RPKI_FEATURE_NAMES  # noqa: E402


def test_normal_feature_variant_counts_when_present():
    expected = {
        mr.NORMAL_V1: 44,
        mr.NORMAL_V2: 58,
        mr.NORMAL_V3: 60,
        mr.NORMAL_V4: 74,
    }
    for path, feature_count in expected.items():
        if not path.exists():
            continue
        df = pd.read_parquet(path)
        features = [name for name in BEHAVIORAL_FEATURE_NAMES + CAIDA_FEATURE_NAMES + RPKI_FEATURE_NAMES if name in df.columns]
        assert len(df) == 516
        assert len(features) == feature_count
        assert set(df["partition"].astype(str)) == {"train"}


def test_feature_order_matches_expected_variants_when_present():
    for variant, (_, normal_path, expected_features) in mr.VARIANT_SPECS.items():
        if not normal_path.exists():
            continue
        df = pd.read_parquet(normal_path)
        observed = [column for column in df.columns if column in expected_features]
        assert observed == expected_features, variant


def test_model_grouping_keeps_normal_controls_with_associated_incident_family(tmp_path, monkeypatch):
    normal = pd.DataFrame(
        [
            {
                "candidate_period_id": "control_a",
                "associated_incident_uid": "Hijack:1",
                "window_id": "control_a_20250101T000000Z",
            },
            {
                "candidate_period_id": "control_a",
                "associated_incident_uid": "Hijack:1",
                "window_id": "control_a_20250101T000500Z",
            },
        ]
    )
    output = tmp_path / "grouping.csv"
    monkeypatch.setattr(mr, "GROUPING_AUDIT", output)

    grouping = mr.model_grouping(normal)

    assert len(grouping) == 1
    row = grouping.iloc[0]
    assert row["group_id"] == "control_a"
    assert row["model_group_id"] == "Hijack:1"
    assert row["windows"] == 2


def test_manifest_paths_are_variant_specific():
    assert mr.manifest_path("stage1", "V1").name == "stage1_v1_development_manifest_v1.csv"
    assert mr.manifest_path("stage2", "V4").name == "stage2_v4_development_manifest_v1.csv"


def test_experiment_matrix_registers_without_training(tmp_path, monkeypatch):
    path = tmp_path / "model_experiment_matrix_v1.yaml"
    monkeypatch.setattr(mr, "EXPERIMENT_MATRIX", path)

    mr.write_experiment_matrix()

    text = path.read_text(encoding="utf-8")
    assert "REGISTERED_UNEXECUTED" in text
    assert "applied: false" in text
    assert "executed: false" in text
    assert "Final Holdout remains untouched" in text
