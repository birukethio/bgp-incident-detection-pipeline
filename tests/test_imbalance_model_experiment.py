from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection import imbalance_model_experiment as imb  # noqa: E402
from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES  # noqa: E402


def test_loaded_phase_b_dataset_is_v1_train_only_when_available():
    if not imb.NORMAL_V1.exists() or not imb.INCIDENT_V1.exists():
        return
    df = imb.load_v1_dataset_with_time()

    assert len(df) == 68547
    assert len(BEHAVIORAL_FEATURE_NAMES) == 44
    assert set(df["partition"].astype(str)) == {"train"}
    assert not any(column.startswith("caida_") for column in df.columns)
    assert not any(column.startswith("rpki_") for column in df.columns)


def test_phase_b_reuses_existing_phase_a_grouped_folds_when_available():
    if not imb.NORMAL_V1.exists() or not imb.INCIDENT_V1.exists() or not imb.CV_ASSIGNMENTS.exists():
        return
    df = imb.load_v1_dataset_with_time()
    assignments = imb.load_phase_a_assignments(df)

    assert assignments["fold"].nunique() == 5
    merged = df[["window_id", "model_group_id"]].merge(assignments, on="window_id", how="left", validate="one_to_one")
    assert merged.groupby("model_group_id")["fold"].nunique().max() == 1


def test_group_aware_weights_equalize_aggregate_group_influence():
    df = pd.DataFrame(
        {
            "window_id": [f"w{i}" for i in range(8)],
            "model_group_id": ["a", "a", "a", "b", "c", "c", "c", "c"],
        }
    )
    weights = imb.group_aware_weights(df)
    df["weight"] = weights
    aggregate = df.groupby("model_group_id")["weight"].sum()

    assert np.allclose(aggregate.to_numpy(), np.ones(len(aggregate)))


def test_temporal_cap_group_preserves_first_last_and_cap():
    rows = 200
    df = pd.DataFrame(
        {
            "window_id": [f"w{i:03d}" for i in range(rows)],
            "window_start_ts": pd.date_range("2025-01-01", periods=rows, freq="5min", tz="UTC"),
            "model_group_id": ["g"] * rows,
        }
    )
    capped = imb.temporal_cap_group(df, cap=164)

    assert len(capped) == 164
    assert capped["window_start_ts"].min() == df["window_start_ts"].min()
    assert capped["window_start_ts"].max() == df["window_start_ts"].max()


def test_i2_training_subset_caps_only_training_rows():
    rows = 180
    train = pd.DataFrame(
        {
            "window_id": [f"w{i:03d}" for i in range(rows)],
            "window_start_ts": pd.date_range("2025-01-01", periods=rows, freq="5min", tz="UTC"),
            "model_group_id": ["g"] * rows,
            "label": ["HIJACK"] * rows,
        }
    )
    capped, weights, audit_rows = imb.training_subset(train, "I2", "RF_SINGLE", fold=1)

    assert len(capped) == 164
    assert len(weights) == 164
    assert audit_rows[0]["discarded_rows"] == 16
    assert capped.groupby("model_group_id").size().max() <= 164
