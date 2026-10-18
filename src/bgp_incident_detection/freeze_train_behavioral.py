from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

try:
    from bgp_incident_detection.audit import write_csv
    from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES
except ModuleNotFoundError:
    from src.bgp_incident_detection.audit import write_csv
    from src.bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES


SOURCE_V2_CORPUS = Path("data/train_scale/train_incident_behavioral_features_v2.parquet")
SOURCE_V1_CORPUS = Path("data/train_scale/train_incident_behavioral_features_v1.parquet")
OUTAGE_605_CHANGES = Path("data/train_scale/outage_605_recovery_feature_changes_v1.csv")
TRAIN_FROZEN_DIR = Path("data/train_frozen")
FROZEN_CORPUS = TRAIN_FROZEN_DIR / "frozen_train_behavioral_corpus_v1.parquet"
FROZEN_MANIFEST = TRAIN_FROZEN_DIR / "frozen_train_behavioral_manifest_v1.csv"
FROZEN_AUDIT = TRAIN_FROZEN_DIR / "frozen_train_behavioral_audit_v1.csv"
IMBALANCE_CONFIG = Path("config/imbalance_strategies_v1.yaml")
FEATURE_VARIANTS = Path("config/feature_variants_v1.yaml")
CORPUS_DOC = Path("docs/train_behavioral_corpus_v1.md")
MODEL_PLAN_DOC = Path("docs/model_baseline_and_ablation_plan_v1.md")
NOTEBOOK = Path("notebooks/33_freeze_train_behavioral_corpus_v1.ipynb")

TRAIN_CORPUS_VERSION = "v1"
CORPUS_STATUS = "FROZEN"
EXPECTED_ROWS = 68031
EXPECTED_INCIDENTS = 993
EXPECTED_CLASS_COUNTS = {"Hijack": 331, "Leak": 331, "Outage": 331}
EXPECTED_FEATURE_COUNT = 44
P95_WINDOW_CAP = 164

METADATA_COLUMNS = [
    "incident_uid",
    "incident_id",
    "category",
    "partition",
    "window_id",
    "window_start",
    "window_end",
    "temporal_status",
    "train_corpus_version",
    "behavioral_feature_version",
    "corpus_status",
    "freeze_date",
    "source_commit",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def source_commit() -> str:
    try:
        result = subprocess.run(["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True)
        return result.stdout.strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        return "UNKNOWN"


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_source() -> pd.DataFrame:
    if not SOURCE_V2_CORPUS.exists():
        raise FileNotFoundError(f"resolved source corpus missing: {SOURCE_V2_CORPUS}")
    return pd.read_parquet(SOURCE_V2_CORPUS)


def validate_source(df: pd.DataFrame) -> list[dict[str, object]]:
    class_counts = df.groupby("category")["incident_uid"].nunique().to_dict()
    duplicate_windows = int(df.duplicated(["incident_uid", "window_id"]).sum())
    partitions = set(df["partition"].astype(str))
    feature_count_ok = len(BEHAVIORAL_FEATURE_NAMES) == EXPECTED_FEATURE_COUNT
    missing_features = [feature for feature in BEHAVIORAL_FEATURE_NAMES if feature not in df.columns]
    feature_values = df[BEHAVIORAL_FEATURE_NAMES].apply(pd.to_numeric, errors="coerce")
    invalid_values = int(feature_values.map(lambda value: isinstance(value, float) and math.isinf(value)).sum().sum())
    outage_605_recovered = OUTAGE_605_CHANGES.exists() and not pd.read_csv(OUTAGE_605_CHANGES).empty

    checks = [
        ("row_count", len(df), "PASS" if len(df) == EXPECTED_ROWS else "FAIL", f"expected {EXPECTED_ROWS} rows"),
        ("incident_count", df["incident_uid"].nunique(), "PASS" if df["incident_uid"].nunique() == EXPECTED_INCIDENTS else "FAIL", f"expected {EXPECTED_INCIDENTS} incidents"),
        ("class_counts", class_counts, "PASS" if class_counts == EXPECTED_CLASS_COUNTS else "FAIL", f"expected {EXPECTED_CLASS_COUNTS}"),
        ("behavioral_feature_count", len(BEHAVIORAL_FEATURE_NAMES), "PASS" if feature_count_ok and not missing_features else "FAIL", f"missing_features={missing_features}"),
        ("duplicate_window_ids", duplicate_windows, "PASS" if duplicate_windows == 0 else "FAIL", "expected zero duplicate incident_uid/window_id pairs"),
        ("invalid_feature_values", invalid_values, "PASS" if invalid_values == 0 else "FAIL", "infinite numeric feature values are invalid; NaN is allowed where denominators are zero"),
        ("validation_contamination", int((df["partition"] == "validation").sum()), "PASS" if "validation" not in partitions else "FAIL", "expected no Validation rows"),
        ("holdout_contamination", int((df["partition"] == "holdout").sum()), "PASS" if "holdout" not in partitions else "FAIL", "expected no Holdout rows"),
        ("train_only_partition", sorted(partitions), "PASS" if partitions == {"train"} else "FAIL", "expected train only"),
        ("outage_605_recovery_incorporated", outage_605_recovered, "PASS" if outage_605_recovered else "FAIL", "requires Outage:605 recovery metadata"),
        ("source_v1_preserved", SOURCE_V1_CORPUS.exists(), "PASS" if SOURCE_V1_CORPUS.exists() else "REVIEW", "v1 source artifact must remain available"),
        ("no_weight_or_cap_columns", sorted(set(df.columns) & {"sample_weight", "row_weight", "window_cap", "cap_strategy"}), "PASS" if not (set(df.columns) & {"sample_weight", "row_weight", "window_cap", "cap_strategy"}) else "FAIL", "frozen corpus must not bake in imbalance correction"),
        ("no_caida_rpki_columns", sorted([col for col in df.columns if col.startswith(("caida_", "rpki_", "rov_"))]), "PASS" if not [col for col in df.columns if col.startswith(("caida_", "rpki_", "rov_"))] else "FAIL", "CAIDA/RPKI enrichment is pending"),
    ]
    return [
        {
            "check_name": name,
            "observed_value": json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else value,
            "status": status,
            "notes": notes,
        }
        for name, value, status, notes in checks
    ]


def add_freeze_metadata(df: pd.DataFrame, freeze_date: str, commit: str) -> pd.DataFrame:
    frozen = df.copy()
    frozen["train_corpus_version"] = TRAIN_CORPUS_VERSION
    frozen["corpus_status"] = CORPUS_STATUS
    frozen["freeze_date"] = freeze_date
    frozen["source_commit"] = commit
    return frozen


def assert_feature_values_unchanged(source: pd.DataFrame, frozen: pd.DataFrame) -> None:
    compare_columns = [col for col in source.columns if col in frozen.columns]
    source_sorted = source.sort_values(["incident_uid", "window_id"]).reset_index(drop=True)
    frozen_sorted = frozen[compare_columns].sort_values(["incident_uid", "window_id"]).reset_index(drop=True)
    pd.testing.assert_frame_equal(source_sorted[compare_columns], frozen_sorted, check_dtype=False, check_like=False)


def write_configs_and_docs() -> None:
    IMBALANCE_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    IMBALANCE_CONFIG.write_text(
        "\n".join(
            [
                "imbalance_strategies_version: v1",
                "status: DOCUMENTED_NOT_APPLIED",
                "derived_from: TRAIN behavioral corpus only",
                "notes: These are future modeling configurations; none are baked into the frozen corpus.",
                "strategies:",
                "  natural:",
                "    description: Use all 68,031 TRAIN behavioral rows as observed.",
                "    row_count: 68031",
                "    applied_to_frozen_corpus: false",
                "  incident_aware_weighting:",
                "    description: Retain all rows while assigning each incident approximately equal aggregate influence.",
                "    applied_to_frozen_corpus: false",
                "  p95_cap_plus_incident_weighting:",
                "    description: Future modeling variant using a TRAIN-derived p95 cap plus incident-aware weights.",
                f"    p95_window_cap: {P95_WINDOW_CAP}",
                "    p95_window_cap_derived_from: TRAIN distribution only",
                "    applied_to_frozen_corpus: false",
                "",
            ]
        ),
        encoding="utf-8",
    )
    FEATURE_VARIANTS.parent.mkdir(parents=True, exist_ok=True)
    FEATURE_VARIANTS.write_text(
        "\n".join(
            [
                "feature_variants_version: v1",
                "source: data/train_frozen/frozen_train_behavioral_corpus_v1.parquet",
                "notes: V1 Behavioral is frozen. CAIDA and RPKI/ROV inventories remain future controlled steps; their feature counts are not assumed.",
                "variants:",
                "  V1:",
                "    description: Behavioral BGP features only",
                "    feature_count: 44",
                "    status: FROZEN",
                "    feature_groups:",
                "      - Behavioral",
                "  V2:",
                "    description: Behavioral BGP + CAIDA AS-relationship features",
                "    feature_count: null",
                "    status: PENDING_INVENTORY",
                "    feature_groups:",
                "      - Behavioral",
                "      - CAIDA AS-relationship",
                "  V3:",
                "    description: Behavioral BGP + RPKI/ROV features",
                "    feature_count: null",
                "    status: PENDING_INVENTORY",
                "    feature_groups:",
                "      - Behavioral",
                "      - RPKI/ROV",
                "  V4:",
                "    description: Behavioral BGP + CAIDA AS-relationship + RPKI/ROV features",
                "    feature_count: null",
                "    status: PENDING_INVENTORY",
                "    feature_groups:",
                "      - Behavioral",
                "      - CAIDA AS-relationship",
                "      - RPKI/ROV",
                "",
            ]
        ),
        encoding="utf-8",
    )
    CORPUS_DOC.parent.mkdir(parents=True, exist_ok=True)
    CORPUS_DOC.write_text(
        """# TRAIN Behavioral Corpus v1

This document freezes the resolved TRAIN behavioral baseline before CAIDA/RPKI enrichment or modeling.

Pipeline:

993 independent TRAIN incidents -> RouteViews MRT UPDATE data -> prefix-level observations -> incident-relevant filtering -> non-overlapping 5-minute windows -> 44 behavioral features -> 68,031 behavioral feature rows.

Definitions:

- Incident = independent experimental unit.
- 5-minute window = ML analytical observation.
- One window = one feature row.
- UPDATE volume affects feature values, not row count.
- Zero-observation windows are preserved when source data coverage exists.
- Missing source data is not interpreted as zero activity.
- No imbalance correction is baked into the frozen corpus.

Frozen artifact:

- `data/train_frozen/frozen_train_behavioral_corpus_v1.parquet`

Scope:

- TRAIN only.
- 331 Hijack, 331 Leak, and 331 Outage incidents.
- Validation and Final Holdout remain untouched.
- CAIDA AS-relationship features are not present.
- RPKI/ROV features are not present.
- Weights and window caps are documented as future modeling configurations only.
""",
        encoding="utf-8",
    )
    MODEL_PLAN_DOC.write_text(
        """# Model Baseline And Ablation Plan v1

This is a planning document only. No model has been trained, no thresholds have been tuned, and no ablation results are generated here.

Future model baselines:

- Single-stage Random Forest.
- Single-stage XGBoost.
- Two-stage hierarchical Random Forest.

Future imbalance conditions:

- Natural: use the frozen 68,031 TRAIN rows as observed.
- Incident-aware weighting: retain all rows while each incident receives approximately equal aggregate influence.
- p95 cap + incident-aware weighting: use the TRAIN-derived p95 cap of 164 windows per incident, then apply incident-aware weighting.

Feature ablation variants:

- V1 Behavioral = 44 features, frozen.
- V2 Behavioral + CAIDA = pending exact inventory.
- V3 Behavioral + RPKI = pending exact inventory.
- V4 Behavioral + CAIDA + RPKI = pending exact inventory.

Later feature-family removal experiments should evaluate:

- Withdrawal/activity features.
- AS-path/path-instability features.
- Origin-change features.
- CAIDA relationship features.
- RPKI/ROV features.

Primary evaluation metrics:

- Macro F1.
- Top-2 Accuracy.
- MRR.

Final Holdout protection:

The Final Holdout must not be used for feature selection, feature ablation decisions, Normal-rule threshold tuning, class/window balancing decisions, hyperparameter tuning, Stage 1 threshold selection, or model selection. It is used only after the complete pipeline is frozen.
""",
        encoding="utf-8",
    )


def write_notebook() -> None:
    NOTEBOOK.parent.mkdir(parents=True, exist_ok=True)
    notebook = {
        "cells": [
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": [
                    "# Freeze TRAIN Behavioral Corpus v1\n",
                    "\n",
                    "Controlled freeze of the resolved 68,031-row TRAIN behavioral corpus. No CAIDA/RPKI enrichment, weighting, capping, Normal labeling, Validation access, Holdout access, or modeling occurs here.\n",
                ],
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": [
                    "from pathlib import Path\n",
                    "import pandas as pd\n",
                    "base = Path('..') if Path.cwd().name == 'notebooks' else Path('.')\n",
                    "df = pd.read_parquet(base / 'data/train_frozen/frozen_train_behavioral_corpus_v1.parquet')\n",
                    "df.shape, df['incident_uid'].nunique(), df.groupby('category')['incident_uid'].nunique().to_dict()\n",
                ],
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": [
                    "pd.read_csv(base / 'data/train_frozen/frozen_train_behavioral_audit_v1.csv')\n",
                ],
            },
        ],
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}, "language_info": {"name": "python", "pygments_lexer": "ipython3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(notebook, indent=2) + "\n", encoding="utf-8")


def freeze() -> dict[str, object]:
    source = load_source()
    audit_rows = validate_source(source)
    if any(row["status"] == "FAIL" for row in audit_rows):
        write_csv(FROZEN_AUDIT, audit_rows, ["check_name", "observed_value", "status", "notes"])
        raise RuntimeError("source corpus failed freeze validation")

    freeze_date = utc_now()
    commit = source_commit()
    frozen = add_freeze_metadata(source, freeze_date, commit)
    assert_feature_values_unchanged(source, frozen)

    TRAIN_FROZEN_DIR.mkdir(parents=True, exist_ok=True)
    frozen.to_parquet(FROZEN_CORPUS, index=False)
    manifest = frozen[METADATA_COLUMNS].copy()
    manifest.to_csv(FROZEN_MANIFEST, index=False)
    write_csv(FROZEN_AUDIT, audit_rows, ["check_name", "observed_value", "status", "notes"])
    write_configs_and_docs()
    write_notebook()

    return {
        "frozen_successfully": True,
        "row_count": len(frozen),
        "incident_count": int(frozen["incident_uid"].nunique()),
        "class_incident_counts": frozen.groupby("category")["incident_uid"].nunique().to_dict(),
        "behavioral_feature_count": len(BEHAVIORAL_FEATURE_NAMES),
        "duplicate_window_ids": int(frozen.duplicated(["incident_uid", "window_id"]).sum()),
        "feature_values_unchanged": True,
        "source_v2_sha256": file_sha256(SOURCE_V2_CORPUS),
        "frozen_corpus_sha256": file_sha256(FROZEN_CORPUS),
        "outputs": [
            str(FROZEN_CORPUS),
            str(FROZEN_MANIFEST),
            str(FROZEN_AUDIT),
            str(IMBALANCE_CONFIG),
            str(FEATURE_VARIANTS),
            str(CORPUS_DOC),
            str(MODEL_PLAN_DOC),
            str(NOTEBOOK),
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Freeze resolved TRAIN behavioral corpus v1.")
    parser.parse_args()
    print(json.dumps(freeze(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
