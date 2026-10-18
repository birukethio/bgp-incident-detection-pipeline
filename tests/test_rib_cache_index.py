from __future__ import annotations

import csv
import subprocess
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.rib_cache_index import (  # noqa: E402
    COMPARISON,
    FILL_PLAN,
    INDEX_PERFORMANCE,
    MANIFEST,
    RESULTS,
)


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_exact_fixed_12_candidate_manifest() -> None:
    rows = _read_csv(ROOT / MANIFEST)

    assert len(rows) == 12
    assert Counter(row["associated_category"] for row in rows) == {"Hijack": 4, "Leak": 4, "Outage": 4}
    assert len({row["affected_asn"] for row in rows}) == 12
    assert [int(row["benchmark_order"]) for row in rows] == list(range(1, 13))


def test_duplicate_rib_downloads_are_avoided() -> None:
    rows = _read_csv(ROOT / FILL_PLAN)
    keys = {(row["collector"], row["rib_timestamp"], row["rib_url"]) for row in rows}

    assert len(rows) == len(keys)
    assert sum(int(row["required_by_candidate_count"]) for row in rows) == 24


def test_index_performance_records_reusable_indexes() -> None:
    rows = _read_csv(ROOT / INDEX_PERFORMANCE)

    assert len(rows) == 24
    assert all(row["index_path"].startswith("data/cache/routeviews_rib/indexed/") for row in rows)


def test_results_do_not_create_normal_labels_or_update_downloads() -> None:
    text = (ROOT / RESULTS).read_text(encoding="utf-8")

    assert "NORMAL_VERIFIED" not in text


def test_comparison_has_before_and_after_cache_fill() -> None:
    rows = _read_csv(ROOT / COMPARISON)

    assert {row["run_label"] for row in rows} == {"before_cache_fill", "after_cache_fill"}


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
