from __future__ import annotations

import csv
import subprocess
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.normal_pool_scale import (  # noqa: E402
    EXCLUSION_BUFFER_MINUTES,
    MIN_DURATION_MINUTES,
    NORMAL_ACQUISITION_ESTIMATE,
    NORMAL_CANDIDATE_POOL,
    NORMAL_COVERAGE,
    PRESCREEN_PASS,
)


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_scaled_normal_pool_is_train_only_and_balanced_by_associated_class() -> None:
    rows = _read_csv(ROOT / NORMAL_CANDIDATE_POOL)
    counts = Counter(row["associated_category"] for row in rows)

    assert len(rows) >= 720
    assert counts["Hijack"] >= 240
    assert counts["Leak"] >= 240
    assert counts["Outage"] >= 240
    assert {row["partition"] for row in rows} == {"train"}
    assert "validation" not in (ROOT / NORMAL_CANDIDATE_POOL).read_text(encoding="utf-8").lower()
    assert "holdout" not in (ROOT / NORMAL_CANDIDATE_POOL).read_text(encoding="utf-8").lower()


def test_policy_constants_and_unresolved_hijack_exception_are_preserved() -> None:
    rows = _read_csv(ROOT / NORMAL_CANDIDATE_POOL)

    assert MIN_DURATION_MINUTES == 30
    assert EXCLUSION_BUFFER_MINUTES == 60
    assert "Hijack:97511" not in {row["associated_incident_uid"] for row in rows}
    assert all(int(row["duration_minutes"]) >= 30 for row in rows)


def test_rib_prescreen_pass_requires_positive_visibility_and_stable_origin() -> None:
    rows = _read_csv(ROOT / NORMAL_CANDIDATE_POOL)
    passed = [row for row in rows if row["prescreen_status"] == PRESCREEN_PASS]

    assert passed
    assert all(row["known_incident_overlap"] == "False" for row in passed)
    assert all(row["rib_visible_before"] == "True" for row in passed)
    assert all(row["rib_visible_after"] == "True" for row in passed)
    assert all(row["route_presence_stable"] == "True" for row in passed)
    assert all(row["origin_stable"] == "True" for row in passed)


def test_no_candidate_is_automatically_labeled_normal() -> None:
    text = (ROOT / NORMAL_CANDIDATE_POOL).read_text(encoding="utf-8")

    assert "NORMAL_VERIFIED" not in text
    assert "RIB_PRESCREEN_PASS" in text


def test_acquisition_estimate_is_update_head_only_and_not_download_manifest() -> None:
    rows = _read_csv(ROOT / NORMAL_ACQUISITION_ESTIMATE)

    assert rows
    assert all(row["remote_availability_checked"] == "True" for row in rows)
    assert all("no UPDATE MRT files downloaded" in row["notes"] for row in rows)
    assert all(int(row["required_update_file_count"]) > 0 for row in rows)


def test_coverage_reports_three_associated_classes() -> None:
    rows = _read_csv(ROOT / NORMAL_COVERAGE)

    assert {row["associated_category"] for row in rows} == {"Hijack", "Leak", "Outage"}
    assert all(int(row["unique_associated_incidents"]) >= 20 for row in rows)
    assert all(int(row["candidate_periods"]) >= 240 for row in rows)


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
