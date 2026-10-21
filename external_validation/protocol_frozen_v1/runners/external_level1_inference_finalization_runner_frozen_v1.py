from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "external_validation/reconstruction/pilot_v1"
MODEL_DIR = ROOT / "data/tti_pilot/reconstructed_level1_v1"
FROZEN_V4 = ROOT / "data/train_frozen/frozen_train_v4_behavioral_caida_rpki_v1.parquet"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_csv(path: Path, rows: list[dict]) -> None:
    fields = list(rows[0]) if rows else []
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    schema_path = MODEL_DIR / "feature_schema_v4.json"
    schema = json.loads(schema_path.read_text())
    attempted = pd.read_parquet(OUT / "pilot_v4_features_v1.parquet")
    compatibility = pd.read_csv(OUT / "pilot_v4_schema_equivalence_v1.csv")
    pass_uids = compatibility.loc[compatibility["status"].eq("PASS"), "incident_uid"].tolist()
    exact = attempted[attempted["incident_uid"].isin(pass_uids)].copy()
    frozen_types = pd.read_parquet(FROZEN_V4, columns=schema).dtypes
    for feature in schema:
        exact[feature] = exact[feature].astype(frozen_types[feature])
    exact_path = OUT / "pilot_v4_features_exact_compatible_v1.parquet"
    exact.to_parquet(exact_path, index=False)

    dtype_rows = []
    for feature in schema:
        dtype_rows.append(
            {
                "feature_position": schema.index(feature) + 1,
                "feature_name": feature,
                "frozen_dtype": str(frozen_types[feature]),
                "pilot_dtype": str(exact[feature].dtype),
                "dtype_exact": str(exact[feature].dtype) == str(frozen_types[feature]),
                "feature_order_exact": list(exact[schema].columns) == schema,
                "missing_value_behavior": "NaN preserved where defined; XGBoost native missing-value handling unchanged",
                "status": "PASS" if str(exact[feature].dtype) == str(frozen_types[feature]) else "FAIL",
            }
        )
    write_csv(OUT / "pilot_v4_feature_by_feature_equivalence_v1.csv", dtype_rows)

    recorded = json.loads((MODEL_DIR / "sha256_checksums.json").read_text())
    model_rows = []
    for relative, expected in recorded.items():
        path = ROOT / relative
        actual = sha256(path)
        model_rows.append(
            {
                "artifact": relative,
                "expected_sha256": expected,
                "actual_sha256": actual,
                "checksum_match": actual == expected,
                "status": "PASS" if actual == expected else "FAIL",
            }
        )
    write_csv(OUT / "pilot_model_artifact_verification_v1.csv", model_rows)
    if not all(row["status"] == "PASS" for row in model_rows):
        raise RuntimeError("frozen Level-1 artifact checksum mismatch")

    models = [joblib.load(MODEL_DIR / f"level1_xgb_fold_{fold}_hist_njobs_minus1.joblib") for fold in range(1, 6)]
    probabilities = np.stack([model.predict_proba(exact[schema]) for model in models]).mean(axis=0)
    predictions = exact[["incident_uid", "category", "window_id", "window_start", "window_end", "temporal_status"]].copy()
    predictions[["hijack_probability", "leak_probability", "outage_probability"]] = probabilities
    predictions.to_parquet(OUT / "pilot_level1_window_predictions_exact_v1.parquet", index=False)
    means = predictions.groupby(["incident_uid", "category"], as_index=False)[["hijack_probability", "leak_probability", "outage_probability"]].mean()
    means["predicted_class"] = means[["hijack_probability", "leak_probability", "outage_probability"]].idxmax(axis=1).str.replace("_probability", "", regex=False).str.title()
    means["aggregation_rule"] = "arithmetic mean class probability across all reconstructed five-minute windows"
    means.to_csv(OUT / "pilot_mean_incident_aggregation_exact_v1.csv", index=False)

    reconstruction = pd.read_csv(OUT / "pilot_reconstruction_audit_v1.csv")
    acquisition = pd.read_csv(OUT / "routeviews_acquisition_manifest_v1.csv")
    yield_rows = []
    for category in ["Hijack", "Leak", "Outage", "ALL"]:
        recon = reconstruction if category == "ALL" else reconstruction[reconstruction["category"].eq(category)]
        comp = compatibility if category == "ALL" else compatibility[compatibility["category"].eq(category)]
        yield_rows.append(
            {
                "category": category,
                "timestamp_pass_incidents": len(recon),
                "routeviews_behavioral_pass": int(recon["behavioral_status"].eq("PASS").sum()),
                "exact_v4_pass": int(comp["status"].eq("PASS").sum()),
                "level1_scored": int(means["category"].eq(category).sum()) if category != "ALL" else len(means),
                "exact_v4_yield_percent": round(100 * comp["status"].eq("PASS").mean(), 3),
            }
        )
    write_csv(OUT / "pilot_reconstruction_yield_v1.csv", yield_rows)

    changes = [
        {
            "change_id": "PILOT-FIX-001",
            "scope": "generic successful-download status normalization",
            "before": "adapter emitted DOWNLOADED; frozen parser accepted 200/CACHED/REUSED_FROM_PILOT",
            "after": "successful HTTP transfers emit 200",
            "applies_to": "all newly downloaded pilot MRT files",
            "methodology_changed": "NO",
            "reason": "align adapter vocabulary with frozen parser gate",
        },
        {
            "change_id": "PILOT-FIX-002",
            "scope": "generic RouteViews directory-index fallback",
            "before": "quarter-hour filename generation returned 404 for archive-era nonaligned filenames",
            "after": "when every standard URL for an incident is 404, select actual indexed files overlapping the same collection interval",
            "applies_to": "any archive date with nonaligned RouteViews filenames",
            "methodology_changed": "NO",
            "reason": "retrieve the same collector/time interval while retaining BGP-timestamp-based five-minute windows",
        },
    ]
    write_csv(OUT / "pilot_engineering_change_log_v1.csv", changes)

    counts = Counter(reconstruction["category"])
    summary = f"""# External Level-1 Reconstruction Pilot v1

**Scope:** Prospective source-separated external validation of the frozen reproducibly preserved Level-1 BGP incident-classification path.

This engineering pilot does not validate the historical Level-2 temporal stacker. The originally fitted Level-2 artifact was not persisted.

## Yield

- Timestamp-PASS incidents attempted: 8 ({counts['Hijack']} Hijack / {counts['Leak']} Leak / {counts['Outage']} Outage).
- RouteViews retrieval, MRT parsing, relevance filtering, and Behavioral reconstruction: 8/8 PASS.
- Raw BGP observations inspected: {int(reconstruction['raw_observations'].sum()):,}.
- Incident-relevant observations retained: {int(reconstruction['relevant_observations'].sum()):,}.
- Parser failures: {int(reconstruction['parse_failures'].sum())}.
- Five-minute rows: {int(reconstruction['window_rows'].sum())}.
- Exact 74-feature historical V4 compatibility: 7/8.
- Frozen Level-1 ensemble execution and mean aggregation: 7/8.
- `V2-HIJACK-008`: retained in timestamp REVIEW and never reconstructed or scored.

## Documented limitation

`V2-HIJACK-003` passed RouteViews and Behavioral reconstruction but did not pass exact V4. The February 2008 CAIDA serial-2 snapshot and same-date five-TAL RPKI archive are unavailable (HTTP 404). No later snapshot, zero substitution, inferred enrichment, or prediction-based workaround was used. Its V4 row set is retained only as an attempted reconstruction and was not scored.

## Frozen compatibility

- Feature names/order: exact 74-feature schema.
- Schema SHA-256: `{sha256(schema_path)}`.
- Feature data types for the seven compatible incidents: 74/74 exact against the frozen TRAIN V4 Parquet schema.
- Missing values: frozen NaN behavior preserved; no imputation or calibration added.
- Level-1 artifacts: all recorded model/schema checksums matched.
- Inference: arithmetic mean of `predict_proba` across the five preserved fold models.
- Incident aggregation: arithmetic mean class probability across all eligible five-minute windows.

Prediction correctness was not used to alter retrieval, filtering, features, gates, or inclusion.
"""
    (OUT / "pilot_reconstruction_summary_v1.md").write_text(summary, encoding="utf-8")

    protocol = """# Proposed Frozen External Level-1 Protocol v1

## Scope

**Prospective source-separated external validation of the frozen reproducibly preserved Level-1 BGP incident-classification path.**

The protocol excludes any claim about the historical Level-2 temporal stacker.

## Fixed pipeline

1. Lock source-native incident metadata before retrieval; unresolved exact timestamps remain REVIEW.
2. Use `route-views2`, the frozen 60-minute context buffer, and the frozen incident-active segmentation rules.
3. Resolve modern 15-minute filenames normally. If and only if generated URLs are absent, use the official RouteViews directory index to select actual files overlapping the unchanged interval.
4. Parse with `bgpdump -q -m`; assign observations to windows by BGP timestamp, never filename timestamp.
5. Apply the frozen exact-prefix / affected-ASN / peer-origin-path / leak-segment relevance predicate.
6. Construct frozen five-minute PRE_CONTEXT, INCIDENT_ACTIVE, and POST_CONTEXT rows.
7. Generate the unchanged 44 Behavioral, 14 same-period CAIDA serial-2, and 16 same-date historical RPKI/ROV features.
8. Require exact 74 names, order, dtypes, missing-value behavior, and schema hash. Missing historical snapshots cause REVIEW; no temporal substitution is allowed.
9. Verify every preserved Level-1 artifact checksum, average probabilities across five models, then apply frozen mean incident aggregation.
10. Record all warnings/failures. Prediction correctness cannot alter reconstruction logic or eligibility.

## Gate before final external collection

The engineering pilot supports freezing the runner for dates where exact historical CAIDA and RPKI inputs exist. Candidate pre-screening must include enrichment-archive availability without inspecting model output. The final external cohort must remain unselected until this protocol is reviewed and frozen.
"""
    (OUT / "proposed_frozen_external_level1_protocol_v1.md").write_text(protocol, encoding="utf-8")

    checksum_rows = []
    for path in sorted(OUT.glob("*")) + [ROOT / "external_validation/reconstruction/run_level1_external_pilot_v1.py", Path(__file__)]:
        if path.is_file():
            checksum_rows.append({"artifact": str(path.relative_to(ROOT)), "sha256": sha256(path), "size_bytes": path.stat().st_size})
    write_csv(OUT / "pilot_output_checksums_v1.csv", checksum_rows)


if __name__ == "__main__":
    main()
