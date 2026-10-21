"""Execution adapter for the frozen Level-1 external-validation runner.

Only cohort input and output paths are adapted. All scientific functions are
loaded from the checksum-locked reconstruction runner without modification.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
EXEC = ROOT / "external_validation/final_execution_v1"
WORK = EXEC / "work"
LOCKED = EXEC / "final_external_cohort_locked_v1.csv"
LOCK_MANIFEST = EXEC / "final_external_cohort_lock_manifest_v1.json"
FROZEN_RUNNER = ROOT / "external_validation/protocol_frozen_v1/runners/external_level1_reconstruction_runner_frozen_v1.py"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_frozen_module():
    spec = importlib.util.spec_from_file_location("frozen_external_reconstruction_v1", FROZEN_RUNNER)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load frozen reconstruction runner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def locked_incidents(module) -> tuple[list[dict], list[dict]]:
    manifest = json.loads(LOCK_MANIFEST.read_text(encoding="utf-8"))
    expected = manifest["artifacts"]["locked_cohort"]["sha256"]
    if sha256(LOCKED) != expected:
        raise RuntimeError("locked cohort checksum mismatch")
    rows = pd.read_csv(LOCKED, dtype=str).fillna("")
    if len(rows) != 18 or rows["true_class"].value_counts().to_dict() != {"Outage": 10, "Leak": 5, "Hijack": 3}:
        raise RuntimeError("locked cohort membership/count mismatch")
    incidents = []
    for _, row in rows.iterrows():
        asns = module.extract_asns(row["affected_asn"])
        prefixes = module.extract_prefixes(row["affected_prefix"])
        incidents.append({
            "incident_uid": row["external_id"],
            "incident_id": row["external_id"],
            "category": row["true_class"],
            "partition": "PROSPECTIVE_EXTERNAL_LEVEL1_V1",
            "start_utc": row["event_start_utc"],
            "end_utc": row["event_end_utc"],
            "affected_asns": json.dumps(asns),
            "affected_prefixes": json.dumps(prefixes),
            "primary_asn": asns[0] if asns else "",
            "leak_asn": asns[0] if row["true_class"] == "Leak" and asns else "",
            "leak_seg": json.dumps(asns[:3] if row["true_class"] == "Leak" else []),
            "source_url": row["source_url"],
            "timestamp_gate": "PASS",
        })
    return incidents, []


def main(download: bool) -> None:
    module = load_frozen_module()
    freeze = json.loads((ROOT / "external_validation/protocol_frozen_v1/external_level1_protocol_freeze_manifest_v1.json").read_text())
    if sha256(FROZEN_RUNNER) != freeze["reconstruction_runner"]["sha256"]:
        raise RuntimeError("frozen reconstruction runner checksum mismatch")

    WORK.mkdir(parents=True, exist_ok=True)
    module.ROOT = ROOT
    module.OUT = WORK
    module.RAW = WORK / "raw_mrt"
    module.PARSED = WORK / "parsed"
    module.CAIDA_CACHE = ROOT / "data/cache/caida/as_relationships/serial-2"
    module.MODEL_DIR = ROOT / "data/tti_pilot/reconstructed_level1_v1"
    module.load_incidents = lambda: locked_incidents(module)
    module.run(download)

    change = {
        "change_id": "FINAL-EXEC-INFRA-001",
        "recorded_before_prediction_inspection": True,
        "scope": "generic cohort input and output path adapter",
        "frozen_runner_sha256": sha256(FROZEN_RUNNER),
        "adapter_sha256": sha256(Path(__file__)),
        "scientific_method_changed": False,
        "details": "Imports checksum-locked functions; replaces only pilot roster cardinality/input path and execution output paths.",
    }
    (EXEC / "final_external_execution_adapter_manifest_v1.json").write_text(json.dumps(change, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--download", action="store_true")
    args = parser.parse_args()
    main(args.download)
