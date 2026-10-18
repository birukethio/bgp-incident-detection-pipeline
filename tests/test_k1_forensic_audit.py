from __future__ import annotations

import pandas as pd

import bgp_incident_detection.k1_forensic_audit as k2
from bgp_incident_detection.k1_forensic_audit import (
    B0,
    K2_SEEDS,
    SELECTED,
    first_level_leakage_audit,
    fold_distribution,
    meta_feature_leakage_audit,
    second_level_leakage_audit,
    topology_audit,
    uniqueness_audit,
)


def toy_data() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "incident_uid": ["a", "a", "b", "b", "c", "c"],
            "window_id": ["a1", "a2", "b1", "b2", "c1", "c2"],
            "fold": [1, 1, 2, 2, 3, 3],
            "partition": ["train"] * 6,
            "label": ["HIJACK", "HIJACK", "LEAK", "LEAK", "OUTAGE", "OUTAGE"],
        }
    )


def toy_meta() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "incident_uid": ["a", "b", "c"],
            "fold": [1, 2, 3],
            "true_class": ["HIJACK", "LEAK", "OUTAGE"],
        }
    )


def test_k2_selected_and_reference_candidates_are_fixed() -> None:
    assert SELECTED == "K1-M2_XGB_K1-TEMPORAL"
    assert B0 == "K1-B0_MEAN_PROBABILITY"
    assert K2_SEEDS == [20260828, 20260829, 20260830, 20260831, 20260901]


def redirect_outputs(monkeypatch, tmp_path) -> None:
    for name in [
        "FIRST_LEVEL_AUDIT",
        "SECOND_LEVEL_AUDIT",
        "TOPOLOGY_AUDIT",
        "META_LEAKAGE_AUDIT",
        "UNIQUENESS_AUDIT",
        "FOLD_DISTRIBUTION",
    ]:
        monkeypatch.setattr(k2, name, tmp_path / f"{name.lower()}.csv")


def test_first_level_leakage_audit_detects_zero_overlap_for_grouped_folds(monkeypatch, tmp_path) -> None:
    redirect_outputs(monkeypatch, tmp_path)
    audit = first_level_leakage_audit(toy_data())

    assert audit["incident_seen_by_first_level_model"].eq(False).all()
    assert audit["window_overlap_count"].eq(0).all()
    assert audit["status"].eq("PASS").all()


def test_second_level_leakage_audit_detects_zero_outer_overlap(monkeypatch, tmp_path) -> None:
    redirect_outputs(monkeypatch, tmp_path)
    audit = second_level_leakage_audit(toy_meta())

    assert audit["train_test_incident_overlap_count"].eq(0).all()
    assert audit["preprocessing_fit_on_outer_test"].eq(False).all()
    assert audit["hyperparameter_selection_used_outer_test"].eq(False).all()
    assert audit["status"].eq("PASS").all()


def test_uniqueness_audit_requires_one_incident_row(monkeypatch, tmp_path) -> None:
    redirect_outputs(monkeypatch, tmp_path)
    meta = pd.DataFrame(
        {
            "incident_uid": [f"h{i}" for i in range(331)] + [f"l{i}" for i in range(331)] + [f"o{i}" for i in range(331)],
            "true_class": ["HIJACK"] * 331 + ["LEAK"] * 331 + ["OUTAGE"] * 331,
        }
    )
    audit = uniqueness_audit(meta)

    assert audit["status"].eq("PASS").all()


def test_topology_audit_states_outer_test_cannot_influence(monkeypatch, tmp_path) -> None:
    redirect_outputs(monkeypatch, tmp_path)
    audit = topology_audit()

    assert audit["can_outer_test_influence"].eq(False).all()
    assert audit["status"].eq("PASS").all()


def test_meta_feature_leakage_flags_label_like_names(monkeypatch, tmp_path) -> None:
    redirect_outputs(monkeypatch, tmp_path)
    inventory = pd.DataFrame(
        {
            "meta_feature_name": ["hijack_prob_mean", "true_class_copy"],
            "source": ["OOF probability", "bad"],
        }
    )
    audit = meta_feature_leakage_audit(inventory)

    assert audit.set_index("meta_feature").loc["hijack_prob_mean", "status"] == "PASS"
    assert audit.set_index("meta_feature").loc["true_class_copy", "status"] == "FAIL"


def test_fold_distribution_reports_train_and_test_counts(monkeypatch, tmp_path) -> None:
    redirect_outputs(monkeypatch, tmp_path)
    audit = fold_distribution(toy_meta())

    assert set(audit["meta_test_incident_count"]) == {1}
    assert set(audit["meta_training_incident_count"]) == {2}
