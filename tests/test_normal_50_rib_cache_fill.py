from __future__ import annotations

import csv
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.normal_50_rib_cache_fill import (  # noqa: E402
    BATCH_SIZE,
    missing_workload,
    targets_by_rib,
)
from bgp_incident_detection.normal_rib_batch50 import RIB_DATA_REQUIRED  # noqa: E402


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_missing_workload_matches_50_candidate_fill_plan():
    rows = missing_workload()
    assert len(rows) == 98
    assert all(row["index_required"] == "True" for row in rows)
    assert all(row["execution_status"] == "PENDING" for row in rows)


def test_plan_uses_five_batches_without_downloading():
    rows = missing_workload()
    assert len(rows) == 98
    assert [len(rows[index : index + BATCH_SIZE]) for index in range(0, len(rows), BATCH_SIZE)] == [20, 20, 20, 20, 18]
    assert BATCH_SIZE == 20


def test_targets_by_rib_uses_original_50_candidates():
    candidates = load_csv(ROOT / "data/normal_scale/normal_rib_prescreen_50_v1.csv")
    assert len(candidates) == 50
    assert {row["prescreen_status"] for row in candidates} == {RIB_DATA_REQUIRED}
    targets = targets_by_rib(candidates)
    assert len(targets) == 99
    assert all(target_list for target_list in targets.values())


def test_no_update_mrt_paths_in_cache_fill_outputs():
    output_names = [
        "normal_50_rib_cache_fill_execution_manifest_v1.csv",
        "normal_50_rib_cache_fill_audit_v1.csv",
        "normal_rib_prescreen_50_complete_v1.csv",
    ]
    assert all("update" not in name.lower() for name in output_names)
