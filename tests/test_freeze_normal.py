from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bgp_incident_detection.behavioral_features import BEHAVIORAL_FEATURE_NAMES  # noqa: E402
from bgp_incident_detection.freeze_normal import (  # noqa: E402
    EXPECTED_WINDOWS,
    FROZEN_CORPUS,
    FROZEN_MANIFEST,
    METHOD_CONFIG,
    MIN_STABLE_WINDOWS,
    SOURCE_CORPUS,
    freeze,
)
from bgp_incident_detection.normal_pool_scale import EXCLUSION_BUFFER_MINUTES  # noqa: E402
from bgp_incident_detection.normal_update_scale import BEHAVIORAL_FEATURE_COUNT  # noqa: E402


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def test_freeze_creates_exact_516_train_only_rows_without_changing_source():
    before = sha256(ROOT / SOURCE_CORPUS)
    summary = freeze()
    after = sha256(ROOT / SOURCE_CORPUS)
    frozen = pd.read_parquet(ROOT / FROZEN_CORPUS)
    assert before == after
    assert summary["source_corpus_unchanged"] is True
    assert len(frozen) == EXPECTED_WINDOWS == 516
    assert set(frozen["partition"]) == {"train"}
    assert set(frozen["final_state"]) == {"NORMAL_VERIFIED"}
    assert set(frozen["corpus_status"]) == {"FROZEN_FOR_DEVELOPMENT"}


def test_frozen_corpus_preserves_feature_schema_and_window_ids():
    frozen = pd.read_parquet(ROOT / FROZEN_CORPUS)
    assert len(BEHAVIORAL_FEATURE_NAMES) == BEHAVIORAL_FEATURE_COUNT == 44
    assert all(name in frozen.columns for name in BEHAVIORAL_FEATURE_NAMES)
    assert frozen["window_id"].nunique() == len(frozen)
    assert frozen["window_id"].duplicated().sum() == 0


def test_manifest_one_row_per_normal_window():
    manifest = pd.read_csv(ROOT / FROZEN_MANIFEST)
    frozen = pd.read_parquet(ROOT / FROZEN_CORPUS)
    assert len(manifest) == len(frozen) == 516
    assert manifest["window_id"].nunique() == 516
    assert set(manifest["normal_corpus_version"]) == {"v1"}


def test_normal_method_parameters_unchanged():
    text = (ROOT / METHOD_CONFIG).read_text(encoding="utf-8")
    assert "window_minutes: 5" in text
    assert "incident_exclusion_buffer_minutes: 60" in text
    assert "minimum_consecutive_stable_windows: 6" in text
    assert "minimum_stability_minutes: 30" in text
    assert MIN_STABLE_WINDOWS == 6
    assert EXCLUSION_BUFFER_MINUTES == 60


def test_no_validation_or_holdout_in_frozen_normal_corpus():
    frozen = pd.read_parquet(ROOT / FROZEN_CORPUS)
    values = set(frozen["partition"].astype(str))
    assert "validation" not in values
    assert "holdout" not in values
