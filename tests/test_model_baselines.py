from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection import model_baselines as mb  # noqa: E402
from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES  # noqa: E402


def test_rf_hyperparameters_are_i0_natural():
    assert mb.RF_HYPERPARAMETERS["class_weight"] is None
    assert mb.RF_HYPERPARAMETERS["random_state"] == mb.SEED
    assert len(BEHAVIORAL_FEATURE_NAMES) == 44


def test_loaded_v1_dataset_has_no_caida_or_rpki_when_available():
    if not mb.NORMAL_V1.exists() or not mb.INCIDENT_V1.exists():
        return
    df = mb.load_v1_dataset()

    assert len(df) == 68547
    assert len(BEHAVIORAL_FEATURE_NAMES) == 44
    assert set(df["partition"].astype(str)) == {"train"}
    assert not any(column.startswith("caida_") for column in df.columns)
    assert not any(column.startswith("rpki_") for column in df.columns)


def test_grouped_folds_keep_model_group_together_when_available():
    if not mb.NORMAL_V1.exists() or not mb.INCIDENT_V1.exists():
        return
    df = mb.load_v1_dataset()
    assignments = mb.create_grouped_folds(df)

    assert assignments.groupby("model_group_id")["fold"].nunique().max() == 1
    assert assignments["fold"].nunique() == 5
    assert set(assignments["imbalance_condition"]) == {"I0"}
    assert set(assignments["feature_variant"]) == {"V1"}


def test_normal_associated_incident_grouping_is_preserved_when_available():
    if not mb.NORMAL_V1.exists():
        return
    df = mb.load_v1_dataset()
    normal = df[df["label"] == "NORMAL"]

    assert (normal["group_id"] == normal["candidate_period_id"]).all()
    assert (normal["model_group_id"] == normal["associated_incident_uid"]).all()


def test_registry_records_xgboost_unavailable_without_substitution(tmp_path, monkeypatch):
    registry = tmp_path / "registry.csv"
    monkeypatch.setattr(mb, "REGISTRY", registry)
    mb.write_registry("UNAVAILABLE_XGBOOST_NOT_INSTALLED")
    df = pd.read_csv(registry)

    xgb = df[df["experiment_id"] == "BASE_V1_I0_XGB_SINGLE"].iloc[0]
    assert xgb["status"] == "UNAVAILABLE_XGBOOST_NOT_INSTALLED"
    assert xgb["result_artifact"] == "xgboost_not_installed"
