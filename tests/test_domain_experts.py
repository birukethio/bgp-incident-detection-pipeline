from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection import domain_experts as de  # noqa: E402


def test_incident_data_is_train_only_and_incident_only():
    data = de.load_incident_data()

    assert len(data) == 68031
    assert set(data["partition"].astype(str)) == {"train"}
    assert set(data["label"].unique()) == set(de.INCIDENT_LABELS)
    assert data.groupby("model_group_id")["fold"].nunique().max() == 1


def test_domain_inventory_uses_frozen_v4_features_only():
    inventory = de.domain_expert_inventory()

    assert set(inventory["feature_name"]) == set(de.FEATURES_BY_VARIANT["V4"])
    assert set(inventory["expert_name"]) == {"E_HIJACK", "E_LEAK", "E_OUTAGE"}
    assert inventory.groupby(["expert_name", "feature_name"]).size().max() == 1


def test_f1_expert_feature_sets_are_predeclared_and_nonempty():
    inventory = de.domain_expert_inventory()

    for expert in de.INCIDENT_LABELS:
        features = de.features_for_expert(expert, "F1_DOMAIN_EXPERTS", inventory)
        assert features
        assert set(features).issubset(set(de.FEATURES_BY_VARIANT["V4"]))
        assert set(inventory[inventory["expert_name"] == f"E_{expert}"].query("included")["feature_family"]) == de.F1_FAMILIES[expert]


def test_f0_uses_all_v4_features():
    inventory = de.domain_expert_inventory()

    for expert in de.INCIDENT_LABELS:
        assert de.features_for_expert(expert, "F0_FULL_V4_EXPERTS", inventory) == de.FEATURES_BY_VARIANT["V4"]


def test_fuse_scores_normalized_and_softmax_sum_to_one():
    scores = pd.DataFrame({"HIJACK": [0.2, 0.0], "LEAK": [0.3, 0.0], "OUTAGE": [0.5, 0.0]})

    norm = de.fuse_scores(scores, "R1_NORMALIZED")
    soft = de.fuse_scores(scores, "R2_SOFTMAX")

    assert (norm.sum(axis=1).round(6) == 1.0).all()
    assert (soft.sum(axis=1).round(6) == 1.0).all()


def test_ranking_orders_scores_correctly():
    scores = pd.DataFrame(
        {
            "window_id": ["w1"],
            "incident_uid": ["i1"],
            "true_class": ["LEAK"],
            "fold": [1],
            "expert_configuration": ["F0_FULL_V4_EXPERTS"],
            "architecture": ["ONE_VS_REST_EXPERTS"],
            "fusion_method": ["R0_DIRECT"],
            "p_hijack": [0.2],
            "p_leak": [0.7],
            "p_outage": [0.1],
        }
    )
    ranked = de.ranked_frame(scores)

    assert ranked["rank_1_class"].iloc[0] == "LEAK"
    assert ranked["true_class_rank"].iloc[0] == 1


def test_incident_aggregation_uses_mean_probabilities():
    scores = pd.DataFrame(
        {
            "expert_configuration": ["S2_BASE", "S2_BASE"],
            "architecture": ["S2_BASE", "S2_BASE"],
            "fusion_method": ["R1_NORMALIZED", "R1_NORMALIZED"],
            "incident_uid": ["i1", "i1"],
            "true_class": ["HIJACK", "HIJACK"],
            "fold": [1, 1],
            "p_hijack": [0.2, 0.6],
            "p_leak": [0.3, 0.2],
            "p_outage": [0.5, 0.2],
        }
    )
    aggregated = de.aggregate_incident_scores(scores)

    assert aggregated["p_hijack"].iloc[0] == 0.4


def test_no_validation_holdout_stage1_threshold_or_shap_symbols():
    assert not hasattr(de, "VALIDATION")
    assert not hasattr(de, "HOLDOUT")
    assert not hasattr(de, "threshold_grid")
    assert not hasattr(de, "SHAP")
