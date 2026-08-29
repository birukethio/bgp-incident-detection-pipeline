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


def test_failed_controls_are_diagnosed_not_relabelled() -> None:
    diagnosis = _read_csv(ROOT / "data/pilot/normal_failure_diagnosis_v1.csv")
    qualification = _read_csv(ROOT / "data/pilot/normal_rib_update_qualification_results_v1.csv")

    diagnosed_ids = {row["candidate_period_id"] for row in diagnosis}
    failed_hijack_leak_ids = {
        row["candidate_period_id"]
        for row in qualification
        if row["candidate_period_id"].startswith(("Hijack_", "Leak_")) and row["final_state"] == "UNKNOWN"
    }
    assert len(diagnosis) == 4
    assert diagnosed_ids == failed_hijack_leak_ids


def test_failure_types_distinguish_observability_from_abnormality() -> None:
    diagnosis = _read_csv(ROOT / "data/pilot/normal_failure_diagnosis_v1.csv")
    counts = Counter(row["failure_class"] for row in diagnosis)

    assert counts["INSUFFICIENT_OBSERVABILITY"] == 1
    assert counts["INSUFFICIENT_STABILITY_DURATION"] == 2
    assert counts["EVIDENCE_OF_NON_NORMAL_BEHAVIOR"] == 1
    observability = next(row for row in diagnosis if row["failure_class"] == "INSUFFICIENT_OBSERVABILITY")
    assert observability["failure_type"] == "NO_RIB_VISIBILITY"
    assert "abnormal" not in observability["failure_reason"].lower()


def test_existing_successful_outage_controls_remain_unchanged() -> None:
    diagnosis = _read_csv(ROOT / "data/pilot/normal_failure_diagnosis_v1.csv")
    qualification = _read_csv(ROOT / "data/pilot/normal_rib_update_qualification_results_v1.csv")

    assert {row["category"] for row in diagnosis} == {"Hijack", "Leak"}
    outage_verified = [
        row for row in qualification
        if row["candidate_period_id"].startswith("Outage_") and row["final_state"] == "NORMAL_VERIFIED"
    ]
    assert len(outage_verified) == 53


def test_collector_visibility_is_based_on_historical_availability_only_for_alternates() -> None:
    rows = _read_csv(ROOT / "data/pilot/normal_collector_visibility_v1.csv")

    assert len(rows) == 48
    assert {row["historical_availability"] for row in rows} == {"True"}
    alternate_rows = [row for row in rows if row["collector"] != "route-views2"]
    assert alternate_rows
    assert {row["asn_visible"] for row in alternate_rows} == {"UNKNOWN_NOT_PARSED"}
    assert all("observability only" in row["notes"] for row in rows)


def test_replacement_candidates_are_prescreened_before_update_acquisition() -> None:
    rows = _read_csv(ROOT / "data/pilot/normal_replacement_candidates_v1.csv")
    counts = Counter(row["pre_screen_status"] for row in rows)

    assert len(rows) == 16
    assert counts["RIB_AVAILABLE_NEEDS_VISIBILITY_PARSE"] == 4
    assert counts["REVIEW_TOO_SHORT_FOR_30M_RULE"] == 12
    assert all(int(row["estimated_update_file_count"]) > 0 for row in rows)
    assert all(row["rib_visible"] == "UNKNOWN_NEEDS_RIB_VISIBILITY_PARSE" for row in rows)


def test_known_incident_overlaps_are_not_accepted_as_replacements() -> None:
    rows = _read_csv(ROOT / "data/pilot/normal_replacement_candidates_v1.csv")

    assert all(row["known_incident_overlap"] == "False" for row in rows)


def test_policy_v2_documents_positive_evidence_requirement() -> None:
    text = (ROOT / "data/pilot/normal_candidate_selection_policy_v2.md").read_text(encoding="utf-8")

    assert "NORMAL is not inferred from absence of a known incident" in text
    assert "Pre-screen RIB availability before downloading UPDATE files" in text
    assert "never choose a collector because it produces the desired label" in text


def test_no_validation_or_holdout_access_in_v2_candidate_outputs() -> None:
    for path in [
        ROOT / "data/pilot/normal_failure_diagnosis_v1.csv",
        ROOT / "data/pilot/normal_replacement_candidates_v1.csv",
    ]:
        text = path.read_text(encoding="utf-8").lower()
        assert "validation" not in text
        assert "holdout" not in text


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
