from __future__ import annotations

from pathlib import Path

import pandas as pd

from bgp_incident_detection.feature_ablation import FEATURES_BY_VARIANT
from bgp_incident_detection.validation_confirmation import (
    LABELS,
    VALIDATION_AUDIT,
    VALIDATION_INCIDENT_RANKINGS,
    VALIDATION_RESULTS,
    VALIDATION_V4,
    incident_weights,
    mrr,
    top2_accuracy,
    verify_protocol,
)


def test_phase_j_protocol_locks_refined_xgb_candidate() -> None:
    verified = verify_protocol()
    candidate = verified["candidate"]

    assert candidate["candidate_id"] == "XGB_REFINED_TRAIN_CANDIDATE"
    assert candidate["recommendation"] == "PROMOTE_PHASE_I2_XGB"
    assert candidate["xgboost_version"] == "3.4.1"
    assert candidate["feature_variant"] == "V4"
    assert candidate["feature_count"] == 74
    assert len(FEATURES_BY_VARIANT["V4"]) == 74


def test_incident_weights_sum_to_one_per_incident() -> None:
    rows = pd.DataFrame(
        {
            "incident_uid": ["a", "a", "b", "b", "b"],
            "window_id": ["a-1", "a-2", "b-1", "b-2", "b-3"],
        }
    )

    rows["weight"] = incident_weights(rows)

    assert rows.groupby("incident_uid")["weight"].sum().round(10).to_dict() == {
        "a": 1.0,
        "b": 1.0,
    }


def test_top2_and_mrr_use_descending_incident_probabilities() -> None:
    probs = pd.DataFrame(
        [
            {"HIJACK": 0.7, "LEAK": 0.2, "OUTAGE": 0.1},
            {"HIJACK": 0.2, "LEAK": 0.5, "OUTAGE": 0.3},
            {"HIJACK": 0.2, "LEAK": 0.3, "OUTAGE": 0.5},
        ],
        columns=LABELS,
    )

    assert top2_accuracy(["HIJACK", "OUTAGE", "HIJACK"], probs) == 2 / 3
    assert mrr(["HIJACK", "OUTAGE", "HIJACK"], probs) == (1.0 + 0.5 + (1 / 3)) / 3


def test_phase_j_outputs_preserve_validation_scope_when_present() -> None:
    if not Path(VALIDATION_V4).exists():
        return

    validation = pd.read_parquet(VALIDATION_V4)
    incidents = validation.drop_duplicates("incident_uid")

    assert validation["partition"].eq("validation").all()
    assert incidents["incident_uid"].nunique() == 213
    assert incidents["category"].value_counts().to_dict() == {
        "Hijack": 71,
        "Leak": 71,
        "Outage": 71,
    }
    assert len(FEATURES_BY_VARIANT["V4"]) == 74


def test_phase_j_confirmation_results_and_holdout_seal_when_present() -> None:
    if not Path(VALIDATION_RESULTS).exists() or not Path(VALIDATION_AUDIT).exists():
        return

    results = pd.read_csv(VALIDATION_RESULTS)
    audit = pd.read_csv(VALIDATION_AUDIT)

    assert results.loc[0, "candidate"] == "XGB_REFINED_TRAIN_CANDIDATE"
    assert results.loc[0, "validation_incidents"] == 213
    assert results.loc[0, "formal_disposition"] == "VALIDATION_CONFIRMATION_PASS"
    assert results.loc[0, "final_holdout_status"] == "SEALED"
    assert audit.set_index("check").loc["holdout_sealed", "status"] == "PASS"


def test_phase_j_incident_rankings_cover_validation_once_when_present() -> None:
    if not Path(VALIDATION_INCIDENT_RANKINGS).exists():
        return

    rankings = pd.read_csv(VALIDATION_INCIDENT_RANKINGS)

    assert len(rankings) == 213
    assert rankings["incident_uid"].is_unique
    assert set(rankings["true_class"]) == set(LABELS)
