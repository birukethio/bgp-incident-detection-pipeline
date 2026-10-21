from __future__ import annotations

import yaml

from bgp_incident_detection.k1_final_model_freeze import (
    M2_PARAM_GRID,
    TIE_TOLERANCE,
    candidate_inventory,
    hash_to_params,
    load_second_level_evidence,
    select_candidate,
    write_selection_rule,
)


def test_l0_recovers_only_previously_defined_k1_grid_configs() -> None:
    evidence = load_second_level_evidence()
    allowed = set(hash_to_params())

    assert set(evidence["parameter_hash"]).issubset(allowed)
    assert evidence["parameter_hash"].nunique() <= len(M2_PARAM_GRID)


def test_l0_candidate_inventory_has_recovered_configurations() -> None:
    inventory = candidate_inventory()

    assert inventory["parameter_hash"].nunique() == 8
    assert inventory["exact_hyperparameters_json"].notna().all()
    assert "incident_macro_f1_mean" in inventory.columns


def test_l0_selection_rule_is_frozen_before_selection() -> None:
    write_selection_rule()

    with open("config/k1_second_level_selection_rule_v1.yaml", encoding="utf-8") as handle:
        rule = yaml.safe_load(handle)

    assert rule["status"] == "FROZEN_BEFORE_FINAL_SELECTION"
    assert rule["tie_tolerance_macro_f1"] == TIE_TOLERANCE
    assert rule["validation_used"] is False
    assert rule["final_holdout_accessed"] is False


def test_l0_selection_returns_one_previously_evaluated_hash() -> None:
    inventory = candidate_inventory()
    selected = select_candidate(inventory)

    assert selected["parameter_hash"] in set(inventory["parameter_hash"])
    assert selected["candidate_id"].startswith("K1_SECOND_LEVEL_XGB_")
