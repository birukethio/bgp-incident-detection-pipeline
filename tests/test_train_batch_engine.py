from __future__ import annotations

import csv
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES  # noqa: E402
from bgp_incident_detection.train_batch_engine import (  # noqa: E402
    BEHAVIORAL_FEATURE_COUNT,
    DiskPolicy,
    STATUS_VALUES,
    build_plans,
    required_free_bytes,
    selected_benchmark_incidents,
)


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_disk_gate_formula_includes_compressed_temp_features_and_reserve():
    policy = DiskPolicy(parser_temp_factor=1.25, feature_output_factor=0.02, safety_reserve_bytes=100)
    assert required_free_bytes(1000, policy) == 2370


def test_build_plans_preserves_full_train_incident_count():
    summary = build_plans()
    manifest = load_csv(ROOT / "data/train_scale/train_incident_processing_manifest_v1.csv")
    assert len(manifest) == 993
    assert summary["existing_50_incident_batches"] == 20
    assert summary["url_dedup_saved_file_downloads"] >= 0
    assert {row["partition"] for row in manifest} == {"train"}


def test_volume_aware_batch_plan_does_not_remove_scientific_rows():
    rows = load_csv(ROOT / "data/train_scale/train_volume_aware_batch_plan_v1.csv")
    assert len(rows) == 993
    assert {row["processing_status"] for row in rows} <= set(STATUS_VALUES)
    assert {"max_windows_per_incident", "sample_weight", "weight"}.isdisjoint(rows[0].keys())


def test_benchmark_selection_uses_train_incidents_only():
    selected = set(selected_benchmark_incidents(limit=3))
    train = {row["incident_uid"] for row in load_csv(ROOT / "data/train_scale/train_incident_processing_manifest_v1.csv")}
    assert len(selected) == 3
    assert selected <= train


def test_feature_schema_stays_frozen():
    assert len(BEHAVIORAL_FEATURE_NAMES) == BEHAVIORAL_FEATURE_COUNT == 44
