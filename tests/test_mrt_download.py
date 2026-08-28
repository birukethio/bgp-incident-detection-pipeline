from __future__ import annotations

import csv
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.mrt_download import build_download_manifest_rows, compression_ok  # noqa: E402


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_refined_download_manifest_has_expected_counts() -> None:
    rows = _read_csv(ROOT / "data/pilot/mrt_pilot_download_manifest_v1.csv")

    assert len(rows) == 216
    assert Counter(row["category"] for row in rows) == {"Hijack": 60, "Leak": 51, "Outage": 105}
    assert {row["routeviews_collector"] for row in rows} == {"route-views2"}
    assert {row["expected_status"] for row in rows} == {"available"}
    assert len({row["local_path"] for row in rows}) == 216


def test_manifest_generation_is_reproducible_without_downloading() -> None:
    generated = build_download_manifest_rows()
    existing = _read_csv(ROOT / "data/pilot/mrt_pilot_download_manifest_v1.csv")

    generated_keys = [(row["incident_uid"], row["mrt_timestamp"], row["mrt_url"]) for row in generated]
    existing_keys = [(row["incident_uid"], row["mrt_timestamp"], row["mrt_url"]) for row in existing]
    assert generated_keys == existing_keys


def test_download_file_status_has_checksums_and_nonzero_sizes() -> None:
    rows = _read_csv(ROOT / "data/pilot/mrt_pilot_download_file_status_v1.csv")

    assert len(rows) == 216
    assert {row["downloaded"] for row in rows} == {"True"}
    assert all(int(row["file_size_bytes"]) > 0 for row in rows)
    assert all(len(row["sha256"]) == 64 for row in rows)


def test_download_audit_passes_for_all_pilot_incidents() -> None:
    rows = _read_csv(ROOT / "data/pilot/mrt_pilot_download_audit_v1.csv")

    assert len(rows) == 9
    assert {row["status"] for row in rows} == {"PASS"}
    assert sum(int(row["planned_files"]) for row in rows) == 216
    assert sum(int(row["downloaded_files"]) for row in rows) == 216
    assert sum(int(row["missing_files"]) for row in rows) == 0
    assert sum(int(row["corrupted_files"]) for row in rows) == 0
    assert sum(int(row["duplicate_files"]) for row in rows) == 0


def test_downloaded_files_have_bzip2_headers() -> None:
    rows = _read_csv(ROOT / "data/pilot/mrt_pilot_download_file_status_v1.csv")

    assert all(compression_ok(ROOT / row["local_path"]) for row in rows)
