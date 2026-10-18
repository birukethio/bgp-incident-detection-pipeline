from __future__ import annotations

import csv
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES  # noqa: E402
from bgp_incident_detection.normal_corpus_expansion import (  # noqa: E402
    BEHAVIORAL_FEATURE_COUNT,
    MAX_CANDIDATES_PER_ASN,
    MIN_STABLE_WINDOWS,
    TARGET_CANDIDATES,
    TARGET_CLASS_COUNTS,
    load_csv,
    prepare_summary,
    selected_or_existing_manifest,
)
from bgp_incident_detection.normal_pool_scale import CONTEXT_BUFFER_MINUTES, EXCLUSION_BUFFER_MINUTES  # noqa: E402


def test_prepare_selects_train_only_balanced_expansion_batch():
    summary = prepare_summary()
    rows = load_csv(ROOT / "data/normal_scale/normal_expansion_candidate_manifest_v1.csv")
    assert summary["selected_candidate_count"] == TARGET_CANDIDATES
    assert summary["selected_class_distribution"] == TARGET_CLASS_COUNTS
    assert len(rows) == TARGET_CANDIDATES
    assert {row["partition"] for row in rows} == {"train"}
    assert Counter(row["associated_category"] for row in rows) == TARGET_CLASS_COUNTS


def test_selection_preserves_asn_diversity_cap():
    selected = selected_or_existing_manifest()
    asn_counts = Counter(row["affected_asn"] for row in selected)
    assert max(asn_counts.values()) <= MAX_CANDIDATES_PER_ASN
    assert len(asn_counts) >= 50


def test_policy_constants_remain_unchanged():
    assert len(BEHAVIORAL_FEATURE_NAMES) == BEHAVIORAL_FEATURE_COUNT == 44
    assert MIN_STABLE_WINDOWS == 6
    assert CONTEXT_BUFFER_MINUTES == 60
    assert EXCLUSION_BUFFER_MINUTES == 60


def test_existing_verified_normal_corpus_is_unchanged_source():
    rows = load_csv(ROOT / "data/normal_scale/normal_qualification_results_v1.csv")
    verified = [row for row in rows if row["final_state"] == "NORMAL_VERIFIED"]
    assert len(verified) == 194
    assert len({row["window_id"] for row in verified}) == 194


def test_no_validation_or_holdout_in_existing_normal_artifacts():
    paths = [
        ROOT / "data/normal_scale/normal_qualification_results_v1.csv",
        ROOT / "data/normal_scale/normal_rib_approved_pool_v3.csv",
    ]
    for path in paths:
        rows = load_csv(path)
        partitions = {row.get("partition", "train") for row in rows if row}
        assert partitions <= {"train", ""}
