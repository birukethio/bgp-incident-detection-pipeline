from __future__ import annotations

import csv
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.normal_pool_scale import EXCLUSION_BUFFER_MINUTES, MIN_DURATION_MINUTES, PRESCREEN_PASS  # noqa: E402
from bgp_incident_detection.normal_rib_batch50 import (  # noqa: E402
    APPROVED_POOL_V2,
    FILL_PLAN,
    PERFORMANCE,
    PRESCREEN_50,
    RIB_DATA_REQUIRED,
    UPDATE_ESTIMATE_V3,
    classify_from_index,
    screen_candidate,
    select_next_50,
)


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def make_queue_rows() -> list[dict[str, str]]:
    rows = []
    for category, count in {"Hijack": 20, "Leak": 20, "Outage": 20}.items():
        for idx in range(count):
            rows.append(
                {
                    "candidate_period_id": f"{category}_{idx}",
                    "associated_incident_uid": f"{category}:{idx}",
                    "associated_category": category,
                    "partition": "train",
                    "affected_asn": str(64500 + idx),
                    "affected_prefix": "",
                    "candidate_start": "2025-01-01T00:00:00Z",
                    "candidate_end": "2025-01-01T00:30:00Z",
                    "duration_minutes": "30",
                    "rib_before_timestamp": "2025-01-01T00:00:00Z",
                    "rib_after_timestamp": "2025-01-01T02:00:00Z",
                    "rib_before_url": "https://example.invalid/before.bz2",
                    "rib_after_url": "https://example.invalid/after.bz2",
                }
            )
    return rows


def test_select_next_50_balances_class_and_train_only(monkeypatch):
    monkeypatch.setattr("bgp_incident_detection.normal_rib_batch50.previously_screened_ids", lambda: set())
    rows = make_queue_rows() + [{**make_queue_rows()[0], "candidate_period_id": "holdout", "partition": "holdout"}]
    selected = select_next_50(rows)
    assert len(selected) == 50
    assert all(row["partition"] == "train" for row in selected)
    assert Counter(row["associated_category"] for row in selected) == {"Hijack": 17, "Leak": 17, "Outage": 16}
    assert max(Counter(row["affected_asn"] for row in selected).values()) == 3


def test_missing_index_becomes_rib_data_required_not_no_observability():
    candidate = make_queue_rows()[0]
    result, timings, metrics = screen_candidate(None, candidate, indexed=set())
    assert result["prescreen_status"] == RIB_DATA_REQUIRED
    assert "not yet available" in result["reason"]
    assert timings == []
    assert metrics["indexed_lookups"] == 0


def test_origin_and_route_stability_required_for_pass():
    candidate = make_queue_rows()[0]
    before = [{"origin_asn": "64500", "prefix": "203.0.113.0/24", "peer_asn": "64496", "as_path": "64496 64500"}]
    after = [{"origin_asn": "64501", "prefix": "203.0.113.0/24", "peer_asn": "64496", "as_path": "64496 64501"}]
    unstable = classify_from_index(candidate, before, after)
    assert unstable["prescreen_status"] != PRESCREEN_PASS
    after[0]["origin_asn"] = "64500"
    stable = classify_from_index(candidate, before, after)
    assert stable["prescreen_status"] == PRESCREEN_PASS


def test_batch50_run_outputs_guardrails():
    rows = load_csv(PRESCREEN_50)
    assert len(rows) == 50
    assert all(float(row["candidate_end"][:4]) >= 2021 for row in rows)
    assert all(float(row.get("duration_minutes") or 30) >= MIN_DURATION_MINUTES for row in load_csv(APPROVED_POOL_V2) if row.get("duration_minutes"))
    assert all(row["prescreen_status"] != "NORMAL_VERIFIED" for row in rows)
    assert all(row["prescreen_status"] != "NO_OBSERVABILITY" or row["reason"].startswith("complete indexed") for row in rows)
    assert {row["prescreen_status"] for row in rows} == {RIB_DATA_REQUIRED}
    fill_rows = load_csv(FILL_PLAN)
    assert len(fill_rows) >= 1
    assert set(fill_rows[0]).issuperset({"collector", "rib_timestamp", "already_cached", "already_indexed", "download_required"})
    performance = {row["metric"]: row["value"] for row in load_csv(PERFORMANCE)}
    assert performance["minimum_duration_minutes_preserved"] == str(MIN_DURATION_MINUTES)
    assert performance["exclusion_buffer_minutes_preserved"] == str(EXCLUSION_BUFFER_MINUTES)
    assert UPDATE_ESTIMATE_V3.exists()
