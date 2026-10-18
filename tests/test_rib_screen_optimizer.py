from __future__ import annotations

import csv
import subprocess
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.normal_pool_scale import EXCLUSION_BUFFER_MINUTES, MIN_DURATION_MINUTES  # noqa: E402
from bgp_incident_detection.rib_screen_optimizer import (  # noqa: E402
    CACHE_PERFORMANCE,
    FAILURE_DIAGNOSIS,
    OPTIMIZATION_COMPARISON,
    PRIORITY_QUEUE,
)


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_failure_diagnosis_explains_previous_screening_rows() -> None:
    rows = _read_csv(ROOT / FAILURE_DIAGNOSIS)

    assert len(rows) >= 8
    assert all(row["exact_failure_reason"] for row in rows)
    assert {"RIB_REVIEW", "ROUTE_PRESENCE_UNSTABLE"} & {row["status"] for row in rows}


def test_priority_queue_is_train_only_and_uses_no_future_normal_result() -> None:
    rows = _read_csv(ROOT / PRIORITY_QUEUE)
    text = (ROOT / PRIORITY_QUEUE).read_text(encoding="utf-8")

    assert rows
    assert {row["partition"] for row in rows} == {"train"}
    assert "NORMAL_VERIFIED" not in text
    assert "validation" not in text.lower()
    assert "holdout" not in text.lower()


def test_priority_queue_respects_asn_cap_and_class_diversity() -> None:
    rows = _read_csv(ROOT / PRIORITY_QUEUE)
    counts = Counter(row["affected_asn"] for row in rows)

    assert all(count <= 3 for count in counts.values())
    assert {row["associated_category"] for row in rows} == {"Hijack", "Leak", "Outage"}
    assert Counter(row["associated_category"] for row in rows[:12]) == {"Hijack": 4, "Leak": 4, "Outage": 4}


def test_cache_performance_records_reuse_or_miss_without_update_downloads() -> None:
    rows = _read_csv(ROOT / CACHE_PERFORMANCE)

    assert rows
    assert all("/RIBS/" in row["source_url"] for row in rows)


def test_optimization_comparison_has_previous_and_benchmark_runs() -> None:
    rows = _read_csv(ROOT / OPTIMIZATION_COMPARISON)

    assert {row["run_label"] for row in rows} == {"previous_screening", "optimized_benchmark_screening"}


def test_policy_constants_remain_unchanged() -> None:
    assert MIN_DURATION_MINUTES == 30
    assert EXCLUSION_BUFFER_MINUTES == 60


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
