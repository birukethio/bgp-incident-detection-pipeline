from __future__ import annotations

import csv
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.normal_rib_scale import (  # noqa: E402
    EXPANDED_RESULTS,
    EXPANDED_SUMMARY,
    RIB_CACHE_INDEX,
    UPDATE_ESTIMATE_V2,
)
from bgp_incident_detection.normal_pool_scale import EXCLUSION_BUFFER_MINUTES, MIN_DURATION_MINUTES, PRESCREEN_PASS  # noqa: E402


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_expanded_rib_prescreen_is_train_only_and_has_required_schema() -> None:
    rows = _read_csv(ROOT / EXPANDED_RESULTS)

    assert rows
    required = {
        "candidate_period_id",
        "associated_incident_uid",
        "associated_category",
        "affected_asn",
        "candidate_start",
        "candidate_end",
        "collector",
        "prescreen_status",
        "reason",
    }
    assert required.issubset(rows[0])
    text = (ROOT / EXPANDED_RESULTS).read_text(encoding="utf-8").lower()
    assert "validation" not in text
    assert "holdout" not in text


def test_no_normal_verified_labels_and_policy_constants_unchanged() -> None:
    text = (ROOT / EXPANDED_RESULTS).read_text(encoding="utf-8")

    assert "NORMAL_VERIFIED" not in text
    assert MIN_DURATION_MINUTES == 30
    assert EXCLUSION_BUFFER_MINUTES == 60


def test_rib_pass_requires_visibility_and_stable_origin() -> None:
    rows = _read_csv(ROOT / EXPANDED_RESULTS)
    passed = [row for row in rows if row["prescreen_status"] == PRESCREEN_PASS]

    for row in passed:
        assert row["asn_visible_before"] == "True"
        assert row["asn_visible_after"] == "True"
        assert row["route_presence_stable"] == "True"
        assert row["origin_stable"] == "True"


def test_cache_index_is_keyed_by_collector_timestamp_and_url() -> None:
    rows = _read_csv(ROOT / RIB_CACHE_INDEX)
    keys = [(row["collector"], row["rib_timestamp"], row["source_url"]) for row in rows]

    assert rows
    assert len(keys) == len(set(keys))
    assert all(row["local_path"].startswith("data/cache/routeviews_rib/") for row in rows)


def test_update_estimate_is_head_only_and_no_update_download_manifest() -> None:
    rows = _read_csv(ROOT / UPDATE_ESTIMATE_V2)

    assert rows
    assert {row["remote_availability_checked"] for row in rows} <= {"True", "False"}
    assert all("no UPDATE MRT files downloaded" in row["notes"] for row in rows)


def test_summary_reports_three_classes() -> None:
    rows = _read_csv(ROOT / EXPANDED_SUMMARY)

    assert {row["associated_category"] for row in rows} == {"Hijack", "Leak", "Outage"}


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
