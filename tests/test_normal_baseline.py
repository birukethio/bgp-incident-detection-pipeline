from __future__ import annotations

import csv
import subprocess
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.normal_baseline import (  # noqa: E402
    BEHAVIORAL_FEATURE_COUNT,
    DATE_OFFSETS,
    interval_overlaps,
)


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_normal_candidates_are_train_only_and_preserve_metadata() -> None:
    rows = _read_csv(ROOT / "data/pilot/normal_candidate_periods_v1.csv")

    assert len(rows) == 112
    assert {row["category"] for row in rows} == {"Hijack", "Leak", "Outage"}
    assert all(row["incident_uid"] for row in rows)
    assert all(row["affected_asn"] for row in rows)
    assert all(row["same_time_of_day"] == "True" for row in rows)
    assert {int(row["days_from_incident"]) for row in rows} == set(DATE_OFFSETS)


def test_no_validation_or_holdout_used_in_normal_plan() -> None:
    plan = _read_csv(ROOT / "data/pilot/normal_mrt_acquisition_plan_v1.csv")
    summary = _read_csv(ROOT / "data/pilot/normal_baseline_candidate_summary_v1.csv")

    assert {row["associated_partition"] for row in plan} == {"train"}
    assert len(summary) == 9
    assert {row["status"] for row in summary} == {"PASS"}


def test_known_incident_overlaps_are_rejected() -> None:
    rows = _read_csv(ROOT / "data/pilot/normal_candidate_periods_v1.csv")
    counts = Counter(row["candidate_status"] for row in rows)

    assert counts["NORMAL_CANDIDATE"] == 105
    assert counts["REJECT_KNOWN_INCIDENT_OVERLAP"] == 7
    assert all(row["known_incident_overlap"] == "True" for row in rows if row["candidate_status"] == "REJECT_KNOWN_INCIDENT_OVERLAP")


def test_exclusion_buffer_sensitivity_keeps_unknown_distinct_from_normal() -> None:
    rows = _read_csv(ROOT / "data/pilot/normal_exclusion_buffer_sensitivity_v1.csv")

    assert {row["incident_exclusion_buffer_minutes"] for row in rows} == {"30", "60", "120"}
    assert next(row for row in rows if row["incident_exclusion_buffer_minutes"] == "60")["recommendation"] == "PROVISIONAL_NORMAL_PILOT"
    assert all("UNKNOWN" in row["notes"] for row in rows)


def test_sustained_stability_sensitivity_has_provisional_30_minutes() -> None:
    rows = _read_csv(ROOT / "data/pilot/normal_sustained_stability_sensitivity_v1.csv")

    assert {row["minimum_consecutive_stable_windows"] for row in rows} == {"3", "6", "12"}
    chosen = next(row for row in rows if row["minimum_consecutive_stable_windows"] == "6")
    assert chosen["minimum_stable_minutes"] == "30"
    assert chosen["recommendation"] == "PROVISIONAL_NORMAL_PILOT"


def test_no_normal_verified_labels_are_created_yet() -> None:
    rows = _read_csv(ROOT / "data/pilot/normal_candidate_periods_v1.csv")

    statuses = {row["candidate_status"] for row in rows}
    assert "NORMAL_VERIFIED" not in statuses
    assert "NORMAL_CANDIDATE" in statuses


def test_behavioral_schema_freeze_contains_44_features() -> None:
    rows = _read_csv(ROOT / "data/pilot/behavioral_feature_schema_freeze_v1.csv")
    yaml_text = (ROOT / "config/behavioral_feature_schema_v1.yaml").read_text(encoding="utf-8")

    assert len(rows) == BEHAVIORAL_FEATURE_COUNT
    assert rows[0]["feature_order"] == "1"
    assert {row["behavioral_feature_version"] for row in rows} == {"v1"}
    assert {row["behavioral_feature_count"] for row in rows} == {"44"}
    assert "definition:" in yaml_text
    assert "formula:" in yaml_text
    assert "moas_prefix_count" in yaml_text
    assert "origin_change_event_count" in yaml_text


def test_acquisition_plan_is_dry_run_and_routeviews2() -> None:
    rows = _read_csv(ROOT / "data/pilot/normal_mrt_acquisition_plan_v1.csv")

    assert len(rows) == 1622
    assert {row["routeviews_collector"] for row in rows} == {"route-views2"}
    assert all(row["mrt_url"].startswith("https://archive.routeviews.org/bgpdata/") for row in rows)
    assert all("no Normal MRT download" in row["notes"] for row in rows)
    assert Counter(row["remote_available"] for row in rows)["True"] >= 1


def test_interval_overlap_helper() -> None:
    start = datetime(2025, 1, 1, 0, 0, tzinfo=timezone.utc)
    end = start + timedelta(minutes=10)

    assert interval_overlaps(start, end, start + timedelta(minutes=5), end + timedelta(minutes=5))
    assert not interval_overlaps(start, end, end, end + timedelta(minutes=5))


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
