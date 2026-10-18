"""Lock the approved external cohort before reconstruction or inference."""

from __future__ import annotations

import csv
import hashlib
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "external_validation/proposed_cohort_v1/proposed_final_external_cohort_v1.csv"
FREEZE = ROOT / "external_validation/protocol_frozen_v1/external_level1_protocol_freeze_manifest_v1.json"
OUT = ROOT / "external_validation/final_execution_v1"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    cohort = pd.read_csv(SOURCE, dtype=str).fillna("")
    assert len(cohort) == 18
    assert cohort["external_id"].is_unique
    assert cohort["true_class"].value_counts().to_dict() == {"Outage": 10, "Leak": 5, "Hijack": 3}
    assert set(cohort["archive_eligibility"]) == {"ELIGIBLE"}
    assert set(cohort["original_corpus_overlap"]) == {"NO"}
    assert set(cohort["pilot_overlap"]) == {"NO"}

    locked = OUT / "final_external_cohort_locked_v1.csv"
    shutil.copyfile(SOURCE, locked)
    freeze = json.loads(FREEZE.read_text(encoding="utf-8"))
    lock_time = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    git_head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()

    artifacts = {
        "locked_cohort": {"path": str(locked.relative_to(ROOT)), "sha256": sha256(locked)},
        "protocol": freeze["protocol"],
        "reconstruction_runner": freeze["reconstruction_runner"],
        "inference_finalization_runner": freeze["inference_finalization_runner"],
        "feature_schema": freeze["feature_schema"],
        "level1_models": freeze["level1_models"],
        "level1_model_metadata": freeze["level1_model_metadata"],
    }
    manifest = {
        "lock_version": "final_external_cohort_locked_v1",
        "lock_timestamp_utc": lock_time,
        "git_head_at_lock": git_head,
        "protocol_freeze_timestamp_utc": freeze["freeze_timestamp_utc"],
        "protocol_git_head_at_freeze": freeze["git_head_at_freeze"],
        "statement": "The final prospective external-validation cohort was locked before reconstruction, feature generation, model inference, prediction inspection, or performance calculation.",
        "selection_statement": "No incident was selected, removed, replaced, or relabeled using model output, feature values, prediction confidence, or expected classifier performance.",
        "scope": freeze["scope"],
        "level2_external_validation": False,
        "cohort_counts": {"total": 18, "Hijack": 3, "Leak": 5, "Outage": 10},
        "artifacts": artifacts,
    }
    manifest_path = OUT / "final_external_cohort_lock_manifest_v1.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    rows = []
    flat = [artifacts["locked_cohort"], artifacts["protocol"], artifacts["reconstruction_runner"], artifacts["inference_finalization_runner"], artifacts["feature_schema"]]
    flat += artifacts["level1_models"] + artifacts["level1_model_metadata"]
    for item in flat:
        path = ROOT / item["path"]
        actual = sha256(path)
        rows.append({"artifact": item["path"], "expected_sha256": item["sha256"], "actual_sha256": actual,
                     "checksum_match": actual == item["sha256"], "bytes": path.stat().st_size,
                     "lock_timestamp_utc": lock_time})
    rows.append({"artifact": str(manifest_path.relative_to(ROOT)), "expected_sha256": sha256(manifest_path),
                 "actual_sha256": sha256(manifest_path), "checksum_match": True,
                 "bytes": manifest_path.stat().st_size, "lock_timestamp_utc": lock_time})
    pd.DataFrame(rows).to_csv(OUT / "final_external_cohort_lock_checksums_v1.csv", index=False, quoting=csv.QUOTE_MINIMAL)
    if not all(row["checksum_match"] for row in rows):
        raise RuntimeError("lock gate failed: frozen artifact checksum mismatch")
    print(json.dumps({"locked": 18, "counts": manifest["cohort_counts"], "lock_timestamp_utc": lock_time,
                      "git_head": git_head, "locked_sha256": sha256(locked)}, indent=2))


if __name__ == "__main__":
    main()
