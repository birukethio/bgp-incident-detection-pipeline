from __future__ import annotations

import json
import sys
import csv
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.mrt_acquisition import (  # noqa: E402
    build_acquisition_plan_rows,
    build_pilot_manifest_rows,
    iter_update_slots,
    load_train_roster,
    routeviews_update_url,
    select_pilot_incidents,
)


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_pilot_selects_three_train_incidents_per_class() -> None:
    selected = select_pilot_incidents(load_train_roster())

    assert len(selected) == 9
    assert Counter(row["category"] for row in selected) == {"Hijack": 3, "Leak": 3, "Outage": 3}
    assert {row["partition"] for row in selected} == {"train"}
    assert Counter(row["pilot_duration_bucket"] for row in selected) == {
        "short": 3,
        "median": 3,
        "long": 3,
    }


def test_routeviews_url_pattern_for_route_views2() -> None:
    slot = datetime(2025, 3, 31, 7, 45, tzinfo=timezone.utc)

    assert routeviews_update_url(slot) == (
        "https://archive.routeviews.org/bgpdata/2025.03/UPDATES/updates.20250331.0745.bz2"
    )


def test_plan_uses_15_minute_update_slots_and_no_holdout() -> None:
    selected = select_pilot_incidents(load_train_roster())
    plan = build_acquisition_plan_rows(selected)

    assert len(plan) == 9
    assert {row["partition"] for row in plan} == {"train"}
    assert all(row["collector"] == "route-views2" for row in plan)
    assert all(row["expected_file_count"] == len(json.loads(row["mrt_urls"])) for row in plan)
    assert all(row["availability_check_status"] == "not_checked_dry_run" for row in plan)


def test_iter_update_slots_includes_end_boundary() -> None:
    start = datetime(2025, 3, 31, 7, 45, tzinfo=timezone.utc)
    end = datetime(2025, 3, 31, 8, 15, tzinfo=timezone.utc)

    assert iter_update_slots(start, end) == [
        datetime(2025, 3, 31, 7, 45, tzinfo=timezone.utc),
        datetime(2025, 3, 31, 8, 0, tzinfo=timezone.utc),
        datetime(2025, 3, 31, 8, 15, tzinfo=timezone.utc),
    ]


def test_pilot_manifest_preserves_leak_segment_without_inventing_prefixes() -> None:
    selected = select_pilot_incidents(load_train_roster())
    rows = build_pilot_manifest_rows(selected)
    leak_rows = [row for row in rows if row["category"] == "Leak"]

    assert all(row["leak_asn"] for row in leak_rows)
    assert all(row["leak_seg"] == row["affected_asns"] for row in leak_rows)
    assert all(row["affected_prefixes"] == "" for row in leak_rows)


def test_remote_availability_outputs_cover_all_planned_urls() -> None:
    availability = _read_csv(ROOT / "data/pilot/mrt_pilot_remote_availability_v1.csv")
    summary = _read_csv(ROOT / "data/pilot/mrt_pilot_remote_availability_summary_v1.csv")
    planned_total = sum(int(row["planned_file_count"]) for row in summary)

    assert len(availability) == planned_total == 2670
    assert {row["available"] for row in availability} == {"True"}
    assert {row["status"] for row in summary} == {"PASS"}
    assert sum(int(row["available_file_count"]) for row in summary) == 2670


def test_window_size_analysis_identifies_volume_dominance() -> None:
    rows = _read_csv(ROOT / "data/pilot/mrt_pilot_window_size_analysis_v1.csv")
    by_uid = {row["incident_uid"]: row for row in rows}

    assert len(rows) == 9
    assert by_uid["Hijack:125889"]["expected_file_count"] == "1341"
    assert by_uid["Hijack:125889"]["percent_of_total_pilot_files"] == "50.225"
    assert by_uid["Leak:426483"]["expected_file_count"] == "868"
    assert by_uid["Leak:426483"]["percent_of_total_pilot_files"] == "32.509"
    assert by_uid["Outage:207"]["detector_span_caution"] == "False"
