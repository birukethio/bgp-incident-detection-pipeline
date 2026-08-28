from __future__ import annotations

import csv
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.active_windows import (  # noqa: E402
    THRESHOLDS_MINUTES,
    run,
)


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_active_window_outputs_use_hijack_and_leak_only() -> None:
    results = run()

    assert Counter(row["category"] for row in results["observations"]) == {"Hijack": 6, "Leak": 9}
    assert {row["category"] for row in results["bins"]} == {"Hijack", "Leak"}
    assert {row["activity_status"] for row in results["bins"]} == {"ACTIVE", "SILENT"}
    assert len(results["gap_analysis"]) == 6


def test_observation_timeline_marks_boundary_only_source_limitation() -> None:
    rows = _read_csv(ROOT / "data/pilot/pilot_event_observation_timeline_v1.csv")

    assert len(rows) == 15
    assert all("detector_boundary" in row["observation_type"] for row in rows)
    assert not any(row["category"] == "Outage" for row in rows)


def test_gap_analysis_identifies_sparse_boundary_evidence() -> None:
    rows = _read_csv(ROOT / "data/pilot/pilot_active_gap_analysis_v1.csv")
    by_uid = {row["incident_uid"]: row for row in rows}

    assert by_uid["Hijack:125889"]["silent_5min_bin_count"] == "3992"
    assert by_uid["Leak:426483"]["silent_5min_bin_count"] == "2573"
    assert {
        row["evidence_limitation"]
        for row in rows
    } == {"boundary_only_source_record; dense event observation timestamps unavailable locally"}


def test_threshold_sensitivity_covers_all_candidate_thresholds() -> None:
    rows = _read_csv(ROOT / "data/pilot/pilot_active_window_threshold_sensitivity_v1.csv")

    assert len(rows) == 6 * len(THRESHOLDS_MINUTES)
    assert {int(row["threshold_minutes"]) for row in rows} == set(THRESHOLDS_MINUTES)
    assert all(row["gap_rule"].startswith("max_gap_between_active_bins<=") for row in rows)


def test_volume_comparison_shows_reduction_but_keeps_caution() -> None:
    rows = _read_csv(ROOT / "data/pilot/pilot_active_window_volume_comparison_v1.csv")
    by_uid = {row["incident_uid"]: row for row in rows}

    assert len(rows) == 6
    assert by_uid["Hijack:125889"]["active_window_planned_file_count"] == "20"
    assert by_uid["Leak:426483"]["active_window_planned_file_count"] == "20"
    assert sum(int(row["original_planned_file_count"]) for row in rows) == 2565
    assert sum(int(row["active_window_planned_file_count"]) for row in rows) == 111
    assert all("not a final label-window decision" in row["caution"] for row in rows)
