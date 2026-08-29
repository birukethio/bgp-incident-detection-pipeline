from __future__ import annotations

import csv
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES  # noqa: E402


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_selected_normal_pilot_periods_are_train_only_and_balanced() -> None:
    rows = _read_csv(ROOT / "data/pilot/normal_mrt_pilot_periods_v1.csv")

    assert len(rows) == 6
    assert {row["partition"] for row in rows} == {"train"}
    assert Counter(row["associated_category"] for row in rows) == {"Hijack": 2, "Leak": 2, "Outage": 2}
    assert all(row["known_incident_overlap"] == "False" for row in rows)
    assert {"-7d", "-1d", "+3d", "+7d"}.issubset({row["candidate_offset"] for row in rows})


def test_normal_pilot_manifest_downloads_only_selected_periods() -> None:
    periods = _read_csv(ROOT / "data/pilot/normal_mrt_pilot_periods_v1.csv")
    manifest = _read_csv(ROOT / "data/pilot/normal_mrt_pilot_download_manifest_v1.csv")

    selected_ids = {row["candidate_period_id"] for row in periods}
    assert len(manifest) == 77
    assert {row["candidate_period_id"] for row in manifest} == selected_ids
    assert {row["remote_available"] for row in manifest} == {"True"}
    assert all(row["mrt_url"].startswith("https://archive.routeviews.org/bgpdata/") for row in manifest)


def test_normal_pilot_download_and_parse_audits_pass() -> None:
    audit = _read_csv(ROOT / "data/pilot/normal_mrt_pilot_download_audit_v1.csv")
    counts = _read_csv(ROOT / "data/pilot/normal_pilot_raw_bgp_counts_v1.csv")

    assert len(audit) == 6
    assert {row["status"] for row in audit} == {"PASS"}
    assert sum(int(row["planned_files"]) for row in audit) == 77
    assert sum(int(row["downloaded_files"]) for row in audit) == 77
    assert all(int(row["parse_failures"]) == 0 for row in counts)


def test_normal_pilot_features_use_same_44_behavioral_features() -> None:
    df = pd.read_parquet(ROOT / "data/pilot/normal_pilot_behavioral_features_v1.parquet")

    assert len(BEHAVIORAL_FEATURE_NAMES) == 44
    for feature_name in BEHAVIORAL_FEATURE_NAMES:
        assert feature_name in df.columns
    assert set(df["category"]) == {"Normal"}
    assert set(df["partition"]) == {"train"}
    assert not df["partition"].isin(["validation", "holdout"]).any()


def test_one_normal_feature_row_per_five_minute_window() -> None:
    df = pd.read_parquet(ROOT / "data/pilot/normal_pilot_behavioral_features_v1.parquet")
    counts = _read_csv(ROOT / "data/pilot/normal_pilot_window_counts_v1.csv")

    assert len(df) == 63
    assert len(counts) == 63
    assert df["window_id"].is_unique
    assert set(df["window_id"]) == {row["window_id"] for row in counts}


def test_unknown_remains_distinct_and_failed_candidates_are_not_forced_normal() -> None:
    qualification = _read_csv(ROOT / "data/pilot/normal_pilot_qualification_results_v1.csv")

    assert {row["final_state"] for row in qualification} == {"UNKNOWN"}
    assert "NORMAL_VERIFIED" not in {row["final_state"] for row in qualification}
    assert all(row["qualification_checks_failed"] != "[]" for row in qualification)


def test_normal_pilot_relevance_is_required_for_trustworthy_normal() -> None:
    relevance = _read_csv(ROOT / "data/pilot/normal_pilot_relevance_summary_v1.csv")
    df = pd.read_parquet(ROOT / "data/pilot/normal_pilot_behavioral_features_v1.parquet")

    assert len(relevance) == 6
    assert sum(int(row["directly_matching_observations"]) for row in relevance) == int(df["update_count"].sum())
    assert int(df["has_relevant_observation"].sum()) == 4
    assert int((~df["has_relevant_observation"]).sum()) == 59


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
