from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.outage_605_resolution import (  # noqa: E402
    INCIDENT_UID,
    MISSING_INTERVAL_END,
    MISSING_SLOT,
    RECOVERY_COLLECTOR,
    TARGET_ASNS,
    affected_window_starts,
    classify_window,
    collector_url,
)


def test_outage_605_constants_target_one_incident_and_one_slot():
    assert INCIDENT_UID == "Outage:605"
    assert MISSING_SLOT == datetime(2023, 10, 17, 6, 0, tzinfo=timezone.utc)
    assert MISSING_INTERVAL_END == datetime(2023, 10, 17, 6, 15, tzinfo=timezone.utc)
    assert RECOVERY_COLLECTOR == "route-views.sg"
    assert TARGET_ASNS == {"10094", "131467"}


def test_affected_windows_are_three_five_minute_slots():
    starts = affected_window_starts()
    assert [slot.minute for slot in starts] == [0, 5, 10]
    assert all(slot.hour == 6 for slot in starts)


def test_missing_slot_is_inside_outage_active_interval():
    incident = {
        "start_utc": "2023-10-17T03:45:00.000Z",
        "end_utc": "2023-10-17T16:45:03.000Z",
    }
    assert {classify_window(slot, incident) for slot in affected_window_starts()} == {"INCIDENT_ACTIVE"}


def test_collector_url_uses_routeviews_archive_pattern():
    url = collector_url("route-views.sg")
    assert url == "https://archive.routeviews.org/route-views.sg/bgpdata/2023.10/UPDATES/updates.20231017.0600.bz2"
