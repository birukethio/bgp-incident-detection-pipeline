from __future__ import annotations

import csv
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_duration_ineligible_candidates_do_not_become_update_ready() -> None:
    ineligible = _read_csv(ROOT / "data/pilot/normal_replacement_duration_disposition_v1.csv")
    ready = _read_csv(ROOT / "data/pilot/normal_update_ready_candidates_v1.csv")

    ineligible_ids = {row["candidate_period_id"] for row in ineligible}
    ready_ids = {row["candidate_period_id"] for row in ready}

    assert len(ineligible) == 12
    assert {row["duration_status"] for row in ineligible} == {"INELIGIBLE_DURATION"}
    assert all(int(row["candidate_duration_minutes"]) < 30 for row in ineligible)
    assert ineligible_ids.isdisjoint(ready_ids)


def test_rib_visibility_is_required_before_update_ready() -> None:
    visibility = _read_csv(ROOT / "data/pilot/normal_replacement_rib_visibility_v1.csv")
    ready = _read_csv(ROOT / "data/pilot/normal_update_ready_candidates_v1.csv")

    visible_ids = {
        row["candidate_period_id"]
        for row in visibility
        if row["rib_visibility_status"] == "PASS"
        and row["asn_visible_before"] == "True"
        and row["asn_visible_after"] == "True"
        and row["route_presence_stable"] == "True"
    }
    ready_ids = {row["candidate_period_id"] for row in ready}

    assert len(visibility) == 4
    assert len(ready) == 4
    assert ready_ids == visible_ids
    assert {row["final_prescreen_status"] for row in ready} == {"UPDATE_READY"}


def test_replacement_candidates_are_train_only_and_overlap_free() -> None:
    ready = _read_csv(ROOT / "data/pilot/normal_update_ready_candidates_v1.csv")

    assert ready
    assert all(row["known_incident_overlap"] == "False" for row in ready)
    assert all(row["exclusion_buffer_pass"] == "True" for row in ready)
    assert "validation" not in (ROOT / "data/pilot/normal_update_ready_candidates_v1.csv").read_text(encoding="utf-8").lower()
    assert "holdout" not in (ROOT / "data/pilot/normal_update_ready_candidates_v1.csv").read_text(encoding="utf-8").lower()


def test_collector_selection_is_observability_based_only() -> None:
    selection = _read_csv(ROOT / "data/pilot/normal_replacement_collector_selection_v1.csv")

    assert len(selection) == 4
    assert {row["selected"] for row in selection} == {"True"}
    assert {row["collector"] for row in selection} == {"route-views2"}
    assert all(row["asn_visible"] == "True" for row in selection)
    assert all("positive RIB ASN/origin visibility" in row["selection_reason"] for row in selection)


def test_update_plan_is_dry_run_only_and_downloads_no_update_files() -> None:
    plan = _read_csv(ROOT / "data/pilot/normal_update_ready_acquisition_plan_v1.csv")

    assert len(plan) == 44
    assert {row["remote_available"] for row in plan} == {"True"}
    assert all("/UPDATES/" in row["mrt_url"] for row in plan)
    assert all("dry-run only, no UPDATE download" in row["notes"] for row in plan)
    assert not (ROOT / "data/raw_mrt/normal_update_ready").exists()


def test_frozen_roster_and_partitions_remain_unchanged() -> None:
    result = subprocess.run(
        [
            "git",
            "diff",
            "--quiet",
            "--",
            "data/roster_v2/frozen_incident_roster_v2.csv",
            "data/partitions_v2/frozen_partition_manifest_v2.csv",
        ],
        cwd=ROOT,
        check=False,
    )

    assert result.returncode == 0
