from __future__ import annotations

import csv
import subprocess
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_additional_candidates_are_for_unresolved_train_controls_only() -> None:
    rows = _read_csv(ROOT / "data/pilot/normal_additional_replacement_candidates_v1.csv")
    uids = {row["associated_incident_uid"] for row in rows}

    assert uids == {"Hijack:58159", "Hijack:97511", "Leak:426483"}
    assert all(int(row["candidate_duration_minutes"]) >= 30 for row in rows)
    assert "validation" not in (ROOT / "data/pilot/normal_additional_replacement_candidates_v1.csv").read_text(encoding="utf-8").lower()
    assert "holdout" not in (ROOT / "data/pilot/normal_additional_replacement_candidates_v1.csv").read_text(encoding="utf-8").lower()


def test_update_ready_requires_rib_visibility_and_no_overlap() -> None:
    rows = _read_csv(ROOT / "data/pilot/normal_additional_replacement_candidates_v1.csv")
    ready = [row for row in rows if row["prescreen_status"] == "UPDATE_READY"]

    assert len(ready) == 4
    assert all(row["collector"] == "route-views2" for row in ready)
    assert all(row["rib_visible_before"] == "True" for row in ready)
    assert all(row["rib_visible_after"] == "True" for row in ready)
    assert all(row["route_presence_stable"] == "True" for row in ready)
    assert all(row["known_incident_overlap"] == "False" for row in ready)
    assert all(row["duration_pass"] == "True" for row in ready)


def test_status_counts_capture_unresolved_visibility() -> None:
    rows = _read_csv(ROOT / "data/pilot/normal_additional_replacement_candidates_v1.csv")
    counts = Counter(row["prescreen_status"] for row in rows)
    by_uid = Counter(row["associated_incident_uid"] for row in rows if row["prescreen_status"] == "UPDATE_READY")

    assert counts["UPDATE_READY"] == 4
    assert counts["RIB_REVIEW"] == 37
    assert counts["KNOWN_INCIDENT_OVERLAP"] == 2
    assert by_uid["Hijack:58159"] == 3
    assert by_uid["Leak:426483"] == 1
    assert by_uid["Hijack:97511"] == 0


def test_second_pilot_manifest_combines_existing_and_new_ready_candidates() -> None:
    rows = _read_csv(ROOT / "data/pilot/normal_second_pilot_candidate_manifest_v1.csv")
    by_uid = Counter(row["associated_incident_uid"] for row in rows)

    assert len(rows) == 8
    assert {row["prescreen_status"] for row in rows} == {"UPDATE_READY"}
    assert by_uid["Leak:291102"] == 4
    assert by_uid["Hijack:58159"] == 3
    assert by_uid["Leak:426483"] == 1
    assert by_uid["Hijack:97511"] == 0


def test_second_pilot_acquisition_plan_is_dry_run_only() -> None:
    rows = _read_csv(ROOT / "data/pilot/normal_second_pilot_acquisition_plan_v1.csv")
    by_uid = Counter(row["associated_incident_uid"] for row in rows)

    assert len(rows) == 91
    assert {row["remote_available"] for row in rows} == {"True"}
    assert all("/UPDATES/" in row["mrt_url"] for row in rows)
    assert all("dry-run only, no UPDATE download" in row["notes"] for row in rows)
    assert by_uid["Leak:291102"] == 44
    assert by_uid["Hijack:58159"] == 36
    assert by_uid["Leak:426483"] == 11


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
