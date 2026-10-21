from __future__ import annotations

import pandas as pd

from bgp_incident_detection.k25_architecture_comparator import (
    ARCHITECTURES,
    RF_FIRST_LEVEL_PARAMS,
    RF_SECOND_LEVEL_PARAMS,
    load_schema,
    predicted_labels,
    recover_k1_xgb_params,
)


def test_k25_compares_exactly_four_architectures() -> None:
    assert ARCHITECTURES == {
        "A0_XGB_TO_XGB": ("XGB", "XGB"),
        "A1_XGB_TO_RF": ("XGB", "RF"),
        "A2_RF_TO_XGB": ("RF", "XGB"),
        "A3_RF_TO_RF": ("RF", "RF"),
    }


def test_k25_rf_configs_are_fixed() -> None:
    assert RF_FIRST_LEVEL_PARAMS["n_estimators"] == 1200
    assert RF_FIRST_LEVEL_PARAMS["criterion"] == "log_loss"
    assert RF_FIRST_LEVEL_PARAMS["bootstrap"] is False
    assert RF_SECOND_LEVEL_PARAMS == {
        "n_estimators": 500,
        "max_depth": 8,
        "max_features": "sqrt",
        "min_samples_leaf": 3,
        "min_samples_split": 5,
        "bootstrap": True,
        "criterion": "log_loss",
        "class_weight": None,
    }


def test_k25_loads_frozen_k1_meta_schema() -> None:
    schema = load_schema()

    assert len(schema) == 74
    assert schema[0] == "window_count"
    assert "early_hijack_prob_mean" in schema
    assert "hijack_prob_linear_slope" in schema


def test_k25_recovers_k1_second_level_xgb_params() -> None:
    params = recover_k1_xgb_params()

    assert params
    assert all("n_estimators" in value for value in params.values())
    assert all("max_depth" in value for value in params.values())


def test_predicted_labels_uses_descending_probability_argmax() -> None:
    frame = pd.DataFrame(
        {
            "incident_uid": ["a", "b", "c"],
            "true_class": ["HIJACK", "LEAK", "OUTAGE"],
            "p_hijack": [0.7, 0.1, 0.2],
            "p_leak": [0.2, 0.8, 0.3],
            "p_outage": [0.1, 0.1, 0.5],
        }
    )

    assert predicted_labels(frame)["predicted_class"].tolist() == ["HIJACK", "LEAK", "OUTAGE"]
