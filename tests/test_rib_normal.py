from __future__ import annotations

import csv
import subprocess
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.rib_normal import stable_periods_by_sustained_requirement  # noqa: E402


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_rib_plan_reuses_train_only_normal_pilot_periods() -> None:
    periods = _read_csv(ROOT / "data/pilot/normal_mrt_pilot_periods_v1.csv")
    plan = _read_csv(ROOT / "data/pilot/normal_rib_acquisition_plan_v1.csv")

    assert len(plan) == 6
    assert {row["candidate_period_id"] for row in plan} == {row["candidate_period_id"] for row in periods}
    assert {row["partition"] for row in periods} == {"train"}
    assert all(row["remote_available"] == "True" for row in plan)


def test_rib_download_audit_has_only_verified_rib_files() -> None:
    audit = _read_csv(ROOT / "data/pilot/normal_rib_download_audit_v1.csv")

    assert len(audit) == 12
    assert all(row["downloaded"] == "True" for row in audit)
    assert all(int(row["file_size_bytes"]) > 0 for row in audit)
    assert all(row["sha256"] for row in audit)
    assert all(row["compression_valid"] == "True" for row in audit)


def test_rib_stability_visibility_is_required() -> None:
    stability = _read_csv(ROOT / "data/pilot/normal_rib_stability_v1.csv")
    by_period = {}
    for row in stability:
        by_period.setdefault(row["candidate_period_id"], set()).add(row["route_presence_stable"])

    visible = {period for period, statuses in by_period.items() if "True" in statuses}
    not_visible = {period for period, statuses in by_period.items() if statuses == {"False"}}
    assert len(visible) == 5
    assert "Hijack_97511_offset_+3_20250515T185500Z" in not_visible


def test_zero_update_count_can_be_verified_when_rib_state_is_stable() -> None:
    rows = _read_csv(ROOT / "data/pilot/normal_rib_update_qualification_results_v1.csv")
    verified_silence = [
        row for row in rows
        if row["final_state"] == "NORMAL_VERIFIED"
        and row["relevant_update_count"] == "0"
        and row["stable_silence"] == "True"
    ]

    assert len(verified_silence) == 52


def test_unknown_remains_distinct_from_normal_verified() -> None:
    rows = _read_csv(ROOT / "data/pilot/normal_rib_update_qualification_results_v1.csv")

    assert Counter(row["final_state"] for row in rows) == {"NORMAL_VERIFIED": 53, "UNKNOWN": 10}
    assert any(row["final_state"] == "UNKNOWN" for row in rows)


def test_sustained_stability_sensitivity_outputs_15_30_60_minutes() -> None:
    rows = _read_csv(ROOT / "data/pilot/normal_rib_sustained_stability_sensitivity_v1.csv")

    assert {row["sustained_stability_minutes"] for row in rows} == {"15", "30", "60"}
    assert next(row for row in rows if row["sustained_stability_minutes"] == "15")["verified_windows"] == "58"
    assert next(row for row in rows if row["sustained_stability_minutes"] == "30")["verified_windows"] == "53"
    assert next(row for row in rows if row["sustained_stability_minutes"] == "60")["verified_windows"] == "53"


def test_method_comparison_shows_update_only_false_rejection_risk() -> None:
    rows = _read_csv(ROOT / "data/pilot/normal_method_comparison_v1.csv")
    by_method = {row["method"]: row for row in rows}

    assert by_method["A_UPDATE_EVIDENCE_ONLY"]["verified_normal_windows"] == "0"
    assert by_method["A_UPDATE_EVIDENCE_ONLY"]["false_rejection_risk"] == "HIGH"
    assert by_method["B_RIB_STATE_PLUS_UPDATE_ACTIVITY"]["verified_normal_windows"] == "53"


def test_stability_helper_requires_consecutive_windows() -> None:
    rows = [
        {"candidate_period_id": "a", "window_start": "1", "qualification_status": "PASS_RIB_STABLE_SILENCE"},
        {"candidate_period_id": "a", "window_start": "2", "qualification_status": "UNKNOWN_RIB_ROUTE_NOT_CONFIRMED"},
        {"candidate_period_id": "a", "window_start": "3", "qualification_status": "PASS_RIB_STABLE_SILENCE"},
        {"candidate_period_id": "a", "window_start": "4", "qualification_status": "PASS_RIB_STABLE_SILENCE"},
    ]

    assert stable_periods_by_sustained_requirement(rows, 2) == {"a"}
    assert stable_periods_by_sustained_requirement(rows, 3) == set()


def test_frozen_roster_and_partition_files_remain_unchanged() -> None:
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
