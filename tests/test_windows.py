from __future__ import annotations

import csv
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.windows import (  # noqa: E402
    floor_to_five_minutes,
    format_utc,
    temporal_status,
    window_id,
)


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def test_exact_five_minute_alignment() -> None:
    timestamp = datetime(2025, 10, 30, 14, 7, 59, 999000, tzinfo=timezone.utc)

    assert floor_to_five_minutes(timestamp) == datetime(2025, 10, 30, 14, 5, tzinfo=timezone.utc)


def test_stable_window_ids_preserve_incident_uid() -> None:
    start = datetime(2025, 10, 30, 14, 5, tzinfo=timezone.utc)

    assert window_id("Leak:426871", start) == "Leak:426871_20251030T140500Z"
    assert window_id("Leak:426871", start) == window_id("Leak:426871", start)


def test_temporal_status_assignment() -> None:
    active = [
        (
            datetime(2025, 1, 1, 1, 0, tzinfo=timezone.utc),
            datetime(2025, 1, 1, 1, 10, tzinfo=timezone.utc),
        ),
        (
            datetime(2025, 1, 1, 2, 0, tzinfo=timezone.utc),
            datetime(2025, 1, 1, 2, 5, tzinfo=timezone.utc),
        ),
    ]

    assert temporal_status(datetime(2025, 1, 1, 0, 55, tzinfo=timezone.utc), active) == "PRE_CONTEXT"
    assert temporal_status(datetime(2025, 1, 1, 1, 0, tzinfo=timezone.utc), active) == "INCIDENT_ACTIVE"
    assert temporal_status(datetime(2025, 1, 1, 1, 30, tzinfo=timezone.utc), active) == "UNKNOWN"
    assert temporal_status(datetime(2025, 1, 1, 2, 5, tzinfo=timezone.utc), active) == "POST_CONTEXT"


def test_window_table_counts_and_no_normal_labels() -> None:
    rows = _read_csv(ROOT / "data/pilot/five_minute_window_observation_counts_v1.csv")

    assert len(rows) == 661
    assert Counter(row["temporal_status"] for row in rows) == {
        "INCIDENT_ACTIVE": 250,
        "POST_CONTEXT": 150,
        "UNKNOWN": 149,
        "PRE_CONTEXT": 112,
    }
    assert "NORMAL" not in {row["temporal_status"] for row in rows}
    assert Counter(row["category"] for row in rows) == {"Outage": 318, "Hijack": 185, "Leak": 158}
    assert {row["partition"] for row in rows} == {"train"}
    assert sum(int(row["raw_observation_count"]) for row in rows) == 58065989
    assert sum(int(row["relevant_observation_count"]) for row in rows) == 775320
    assert sum(1 for row in rows if int(row["relevant_observation_count"]) == 0) == 175


def test_no_overlapping_windows_per_incident() -> None:
    rows = _read_csv(ROOT / "data/pilot/five_minute_window_observation_counts_v1.csv")
    by_uid: dict[str, list[tuple[datetime, datetime]]] = defaultdict(list)
    for row in rows:
        start = _parse(row["window_start"])
        end = _parse(row["window_end"])
        assert end - start == timedelta(minutes=5)
        assert start.minute % 5 == 0
        by_uid[row["incident_uid"]].append((start, end))

    for windows in by_uid.values():
        ordered = sorted(windows)
        for (_, left_end), (right_start, _) in zip(ordered, ordered[1:]):
            assert left_end <= right_start


def test_window_id_matches_incident_and_start() -> None:
    rows = _read_csv(ROOT / "data/pilot/five_minute_window_observation_counts_v1.csv")

    assert len({row["window_id"] for row in rows}) == len(rows)
    for row in rows:
        assert row["window_id"] == window_id(row["incident_uid"], _parse(row["window_start"]))
        assert row["incident_uid"] in row["window_id"]


def test_announcement_withdrawal_counts_are_relevant_observations() -> None:
    rows = _read_csv(ROOT / "data/pilot/five_minute_window_observation_counts_v1.csv")

    for row in rows:
        relevant = int(row["relevant_observation_count"])
        announcements = int(row["announcement_count"])
        withdrawals = int(row["withdrawal_count"])
        assert announcements + withdrawals == relevant
        assert relevant <= int(row["raw_observation_count"])


def test_incident_coverage_all_active_windows_represented() -> None:
    rows = _read_csv(ROOT / "data/pilot/five_minute_incident_coverage_v1.csv")

    assert len(rows) == 9
    assert {row["partition"] for row in rows} == {"train"}
    assert {row["observations_visible_during_expected_active_window"] for row in rows} == {"YES"}
    assert {row["routeviews_supports_candidate_active_segments"] for row in rows} == {"YES"}
    assert sum(int(row["active_windows_with_zero_relevant_observations"]) for row in rows) == 72
