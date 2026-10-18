from __future__ import annotations

import csv
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES  # noqa: E402
from bgp_incident_detection.train_incident_scale import (  # noqa: E402
    BEHAVIORAL_FEATURE_COUNT,
    DEFAULT_BATCH_SIZE,
    MANIFEST,
    batch_rows,
    manifest_rows,
    prepare,
    temporal_windows,
)


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_train_manifest_has_exact_expected_counts():
    summary = prepare(check_remote=False)
    rows = load_csv(ROOT / MANIFEST)
    assert summary["manifest_incidents"] == 993
    assert summary["manifest_counts"] == {"Hijack": 331, "Leak": 331, "Outage": 331}
    assert len(rows) == 993
    assert Counter(row["category"] for row in rows) == {"Hijack": 331, "Leak": 331, "Outage": 331}
    assert {row["partition"] for row in rows} == {"train"}


def test_batch_plan_is_reproducible_and_not_started():
    rows = batch_rows(manifest_rows(), batch_size=DEFAULT_BATCH_SIZE)
    assert len(rows) == 993
    assert len({row["batch_id"] for row in rows}) == 20
    assert {row["processing_status"] for row in rows} == {"NOT_STARTED"}
    assert Counter(row["category"] for row in rows[:50]) == {"Hijack": 17, "Leak": 17, "Outage": 16}


def test_behavioral_schema_is_unchanged():
    assert len(BEHAVIORAL_FEATURE_NAMES) == BEHAVIORAL_FEATURE_COUNT == 44


def test_temporal_windows_preserve_context_and_active_rows_without_normal_label():
    incident = {
        "incident_uid": "Hijack:test",
        "category": "Hijack",
        "start_utc": "2025-01-01T00:00:00Z",
        "end_utc": "2025-01-01T00:10:00Z",
    }
    windows = temporal_windows(incident)
    statuses = {row["temporal_status"] for row in windows.values()}
    assert statuses == {"PRE_CONTEXT", "INCIDENT_ACTIVE", "POST_CONTEXT"}
    assert "NORMAL" not in statuses


def test_no_window_cap_or_weight_columns_in_manifest():
    rows = manifest_rows()
    forbidden = {"max_windows_per_incident", "sample_weight", "weight"}
    assert forbidden.isdisjoint(rows[0].keys())
