from __future__ import annotations

import csv
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES  # noqa: E402
from bgp_incident_detection.full_train_execution import (  # noqa: E402
    BEHAVIORAL_FEATURE_COUNT,
    batch_feature_path,
    preflight_summary,
    safe_batch_path,
    validate_train_manifest,
)
from bgp_incident_detection.train_batch_engine import VOLUME_BATCH_PLAN  # noqa: E402
from bgp_incident_detection.train_incident_scale import MANIFEST  # noqa: E402


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_full_train_preflight_uses_authoritative_train_only_manifest():
    rows = load_csv(ROOT / MANIFEST)
    validate_train_manifest(rows)
    assert len(rows) == 993
    assert Counter(row["category"] for row in rows) == {"Hijack": 331, "Leak": 331, "Outage": 331}
    assert {row["partition"] for row in rows} == {"train"}


def test_preflight_uses_volume_aware_batches():
    summary = preflight_summary()
    volume_rows = load_csv(ROOT / VOLUME_BATCH_PLAN)
    assert summary["volume_aware_batch_count"] == len({row["volume_batch_id"] for row in volume_rows}) == 19
    assert summary["train_counts"] == {"Hijack": 331, "Leak": 331, "Outage": 331}
    assert summary["incident_membership_rows"] == 993


def test_shared_cache_paths_are_batch_scoped_and_deduplicated():
    path_a = safe_batch_path("volume_batch_001", "https://archive.routeviews.org/bgpdata/2024.01/UPDATES/updates.20240101.0000.bz2")
    path_b = safe_batch_path("volume_batch_001", "https://archive.routeviews.org/bgpdata/2024.01/UPDATES/updates.20240101.0000.bz2")
    assert path_a == path_b
    assert "train_batches/volume_batch_001" in str(path_a)


def test_batch_feature_outputs_are_versioned_not_one_rewritten_file():
    assert str(batch_feature_path("volume_batch_001")).endswith("data/train_scale/features_v1/volume_batch_001.parquet")


def test_behavioral_schema_has_no_cap_weight_or_normal_label():
    assert len(BEHAVIORAL_FEATURE_NAMES) == BEHAVIORAL_FEATURE_COUNT == 44
    forbidden = {"max_windows_per_incident", "sample_weight", "weight", "normal_label"}
    assert forbidden.isdisjoint(set(BEHAVIORAL_FEATURE_NAMES))
