from __future__ import annotations

import csv
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_execution_manifest_contains_exactly_8_train_candidates() -> None:
    rows = _read_csv(ROOT / "data/pilot/normal_second_pilot_execution_manifest_v1.csv")

    assert len(rows) == 8
    assert {row["partition"] for row in rows} == {"train"}
    assert {row["pilot_version"] for row in rows} == {"normal_second_pilot_v1"}
    assert {row["known_incident_overlap"] for row in rows} == {"False"}
    assert {row["exclusion_buffer_pass"] for row in rows} == {"True"}
    assert "Hijack:97511" not in {row["associated_incident_uid"] for row in rows}


def test_download_audit_has_91_successful_files() -> None:
    audit = _read_csv(ROOT / "data/pilot/normal_second_pilot_download_audit_v1.csv")
    status = _read_csv(ROOT / "data/pilot/normal_second_pilot_download_file_status_v1.csv")

    assert len(status) == 91
    assert sum(int(row["planned_files"]) for row in audit) == 91
    assert sum(int(row["downloaded_files"]) for row in audit) == 91
    assert {row["status"] for row in audit} == {"PASS"}
    assert {row["download_status"] for row in status} == {"PASS"}


def test_behavioral_feature_table_uses_frozen_44_features_and_one_row_per_window() -> None:
    features = pd.read_parquet(ROOT / "data/pilot/normal_second_pilot_behavioral_features_v1.parquet")
    windows = _read_csv(ROOT / "data/pilot/normal_second_pilot_window_counts_v1.csv")

    assert len(features) == 48
    assert len(windows) == 48
    assert [name for name in BEHAVIORAL_FEATURE_NAMES if name in features.columns] == BEHAVIORAL_FEATURE_NAMES
    assert len(BEHAVIORAL_FEATURE_NAMES) == 44


def test_qualification_keeps_unknown_distinct_and_does_not_force_normal() -> None:
    rows = _read_csv(ROOT / "data/pilot/normal_second_pilot_qualification_results_v1.csv")
    counts = Counter(row["final_state"] for row in rows)

    assert counts["NORMAL_VERIFIED"] == 24
    assert counts["UNKNOWN"] == 24
    assert {row["final_state"] for row in rows} == {"NORMAL_VERIFIED", "UNKNOWN"}
    assert any(row["suspicious_update_detected"] == "True" and row["final_state"] == "UNKNOWN" for row in rows)
    assert all(row["final_state"] == "UNKNOWN" for row in rows if row["suspicious_update_detected"] == "True")


def test_zero_update_activity_can_qualify_with_rib_stability() -> None:
    rows = _read_csv(ROOT / "data/pilot/normal_second_pilot_qualification_results_v1.csv")

    qualifying_silence = [
        row for row in rows
        if int(row["relevant_update_count"]) == 0
        and row["stable_silence"] == "True"
        and row["rib_route_confirmed"] == "True"
        and row["rib_origin_stable"] == "True"
        and row["final_state"] == "NORMAL_VERIFIED"
    ]
    assert qualifying_silence


def test_policy_constants_remain_unchanged() -> None:
    from bgp_incident_detection.normal_second_pilot import EXCLUSION_BUFFER_MINUTES, MIN_STABILITY_MINUTES, MIN_STABLE_WINDOWS

    assert MIN_STABILITY_MINUTES == 30
    assert MIN_STABLE_WINDOWS == 6
    assert EXCLUSION_BUFFER_MINUTES == 60


def test_frozen_roster_and_partitions_remain_unchanged() -> None:
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
