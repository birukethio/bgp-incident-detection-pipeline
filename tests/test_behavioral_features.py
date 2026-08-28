from __future__ import annotations

import csv
import math
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.behavioral_features import (  # noqa: E402
    BEHAVIORAL_FEATURE_NAMES,
    DIAGNOSTIC_COLUMNS,
    METADATA_COLUMNS,
)


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _features() -> pd.DataFrame:
    return pd.read_parquet(ROOT / "data/pilot/pilot_behavioral_features_v1.parquet")


def test_exactly_one_feature_row_per_window() -> None:
    df = _features()
    windows = _read_csv(ROOT / "data/pilot/five_minute_window_observation_counts_v1.csv")

    assert len(df) == 661
    assert len(windows) == 661
    assert df["window_id"].is_unique
    assert set(df["window_id"]) == {row["window_id"] for row in windows}


def test_stable_feature_names_and_ordering() -> None:
    df = _features()

    assert list(df.columns) == METADATA_COLUMNS + DIAGNOSTIC_COLUMNS + BEHAVIORAL_FEATURE_NAMES
    assert len(BEHAVIORAL_FEATURE_NAMES) == 44


def test_incident_uid_and_partition_are_preserved_train_only() -> None:
    df = _features()

    assert df["incident_uid"].str.contains(":").all()
    assert set(df["partition"]) == {"train"}
    assert Counter(df["category"]) == {"Outage": 318, "Hijack": 185, "Leak": 158}


def test_no_normal_label_or_status_created() -> None:
    df = _features()

    assert "NORMAL" not in set(df["temporal_status"])
    assert "Normal" not in set(df["category"])
    assert set(df["temporal_status"]) == {"INCIDENT_ACTIVE", "PRE_CONTEXT", "POST_CONTEXT", "UNKNOWN"}


def test_count_features_are_nonnegative() -> None:
    df = _features()
    count_features = [name for name in BEHAVIORAL_FEATURE_NAMES if name.endswith("_count") or name == "update_count"]

    assert count_features
    assert (df[count_features] >= 0).all().all()


def test_ratio_features_are_valid_or_missing() -> None:
    df = _features()
    ratio_features = [name for name in BEHAVIORAL_FEATURE_NAMES if name.endswith("_ratio")]

    for feature in ratio_features:
        values = df[feature].dropna()
        assert ((values >= 0) & (values <= values.max())).all()
    bounded = ["announcement_ratio", "withdrawal_ratio", "moas_prefix_ratio", "path_prepending_ratio", "community_observation_ratio"]
    for feature in bounded:
        values = df[feature].dropna()
        assert ((values >= 0) & (values <= 1)).all()


def test_no_infinite_values() -> None:
    df = _features()
    numeric = df.select_dtypes(include="number")

    assert not numeric.isin([math.inf, -math.inf]).any().any()


def test_zero_observation_windows_are_preserved() -> None:
    df = _features()

    zero = df[df["update_count"] == 0]
    assert len(zero) == 175
    assert zero["has_relevant_observation"].eq(False).all()
    assert zero["announcement_count"].eq(0).all()
    assert zero["withdrawal_count"].eq(0).all()
    assert zero["unique_prefix_count"].eq(0).all()
    assert zero["as_path_length_mean"].isna().all()


def test_outage_active_zero_observation_windows_are_preserved() -> None:
    df = _features()
    rows = df[
        (df["category"] == "Outage")
        & (df["temporal_status"] == "INCIDENT_ACTIVE")
        & (df["update_count"] == 0)
    ]

    assert len(rows) == 72


def test_inventory_and_group_summary_match_feature_table() -> None:
    inventory = _read_csv(ROOT / "data/pilot/behavioral_feature_inventory_v1.csv")
    groups = _read_csv(ROOT / "data/pilot/feature_group_summary_v1.csv")

    assert [row["feature_name"] for row in inventory] == BEHAVIORAL_FEATURE_NAMES
    assert {row["verification_status"] for row in inventory} == {"REPRODUCIBLE"}
    behavioral = next(row for row in groups if row["feature_group"] == "Behavioral")
    assert behavioral["feature_count"] == "44"
    assert behavioral["reproducible_count"] == "44"
    assert next(row for row in groups if row["feature_group"] == "CAIDA AS-relationship")["feature_count"] == "0"
    assert next(row for row in groups if row["feature_group"] == "RPKI/ROV")["feature_count"] == "0"


def test_feature_quality_audit_has_no_failures() -> None:
    audit = _read_csv(ROOT / "data/pilot/behavioral_feature_quality_audit_v1.csv")

    assert len(audit) == 44
    assert "FAIL" not in {row["status"] for row in audit}
    assert Counter(row["status"] for row in audit) == {"PASS": 42, "REVIEW": 2}


def test_no_validation_or_holdout_incidents_used() -> None:
    df = _features()

    assert not df["partition"].isin(["validation", "holdout"]).any()


def test_frozen_roster_and_partition_files_remain_unchanged() -> None:
    result = subprocess.run(
        [
            "git",
            "diff",
            "--quiet",
            "--",
            "data/roster_v2/frozen_incident_roster_v2.csv",
            "data/partitions_v2/frozen_partition_manifest_v2.csv",
        ],
        cwd=ROOT,
        check=False,
    )

    assert result.returncode == 0
