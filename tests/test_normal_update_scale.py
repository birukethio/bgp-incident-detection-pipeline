from __future__ import annotations

import csv
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES  # noqa: E402
from bgp_incident_detection.normal_pool_scale import CONTEXT_BUFFER_MINUTES, EXCLUSION_BUFFER_MINUTES  # noqa: E402
from bgp_incident_detection.normal_update_scale import (  # noqa: E402
    BEHAVIORAL_FEATURE_COUNT,
    EXECUTION_MANIFEST,
    MIN_STABLE_WINDOWS,
    NORMAL_METHOD_VERSION,
    candidate_windows,
    freeze_execution_manifest,
    path_instability,
    prepare_summary,
    qualify,
)


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_prepare_manifest_has_exact_45_train_candidates():
    summary = prepare_summary(check_remote=False)
    rows = load_csv(EXECUTION_MANIFEST)
    assert summary["execution_candidates"] == 45
    assert summary["candidate_class_counts"] == {"Hijack": 14, "Leak": 17, "Outage": 14}
    assert len(rows) == 45
    assert {row["partition"] for row in rows} == {"train"}
    assert {row["normal_method_version"] for row in rows} == {NORMAL_METHOD_VERSION}


def test_feature_count_and_policy_constants_are_frozen():
    assert len(BEHAVIORAL_FEATURE_NAMES) == BEHAVIORAL_FEATURE_COUNT
    assert MIN_STABLE_WINDOWS == 6
    assert CONTEXT_BUFFER_MINUTES == 60
    assert EXCLUSION_BUFFER_MINUTES == 60


def test_one_row_per_five_minute_window():
    candidate = {
        "candidate_period_id": "candidate_1",
        "candidate_start": "2025-01-01T00:00:00Z",
        "candidate_end": "2025-01-01T00:30:00Z",
    }
    assert len(candidate_windows(candidate)) == 6


def test_zero_update_windows_can_be_normal_when_sustained_and_rib_stable():
    execution = [
        {
            "candidate_period_id": "candidate_1",
            "associated_incident_uid": "Hijack:1",
            "associated_category": "Hijack",
            "origin_stable": "True",
            "route_presence_stable": "True",
            "affected_prefix": "",
        }
    ]
    feature_rows = []
    for idx in range(6):
        feature_rows.append(
            {
                "candidate_period_id": "candidate_1",
                "associated_incident_uid": "Hijack:1",
                "associated_category": "Hijack",
                "window_id": f"w{idx}",
                "window_start": f"2025-01-01T00:{idx * 5:02d}:00Z",
                "window_end": f"2025-01-01T00:{idx * 5 + 5:02d}:00Z",
                "update_count": 0,
                "announcement_count": 0,
                "withdrawal_count": 0,
                "origin_change_event_count": 0,
                "unique_as_path_count": 0,
                "multi_path_prefix_count": 0,
                "unique_prefix_count": 0,
                "moas_prefix_count": 0,
            }
        )
    qualification, summary = qualify(feature_rows, execution)
    assert {row["final_state"] for row in qualification} == {"NORMAL_VERIFIED"}
    assert summary[0]["candidate_status"] == "PASS"


def test_suspicious_update_blocks_normal():
    assert path_instability({"update_count": 1, "unique_as_path_count": 3, "multi_path_prefix_count": 2}) == "HIGH"
