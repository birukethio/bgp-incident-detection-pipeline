# Time-to-Identify Audit Report v1

## Scope

This audit addresses the advisor's Time to Identify (TTI) concern without modifying frozen data, models, Validation artifacts, Final Holdout artifacts, Chapter 3/4 results, or any existing experiment. No TTI experiment was executed.

The current final Praxis architecture uses completed non-overlapping five-minute analytical windows. Therefore, the final reported model performance is a completed-window incident classification/ranking result, not a measurement of how quickly the system can identify an incident after the first observable BGP evidence.

## Short Answer

The existing compact TRAIN evidence store is not sufficient to reconstruct exact frozen V4-compatible features at 30, 60, 120, or 300 seconds without reparsing or having retained timestamped observations. It stores `window_start` and `window_end`, but not the original `bgp_timestamp_utc` for each observation. It also omits several parser fields needed for the 44 Behavioral features.

The pilot and normal parsed CSV artifacts do contain per-observation timestamps, so they can support a small code-level proof of concept. They do not cover the full frozen TRAIN corpus.

## Existing Timestamp-Level Evidence

The parser emits `bgp_timestamp_utc` at prefix-level observation grain from `bgpdump -q -m`. This timestamp is available in parsed pilot and normal-candidate CSVs under `data/parsed_mrt/`.

For the full TRAIN feature corpus, the retained durable evidence is mostly at completed five-minute grain:

- frozen behavioral feature rows contain `window_start` and `window_end`;
- compact enrichment evidence contains `window_start`, `window_end`, `prefix`, `origin_asn`, `normalized_as_path`, `observation_count`, and collector/provenance fields;
- CAIDA and RPKI feature batches are already aggregated to one row per frozen five-minute `window_id`.

The full raw parsed TRAIN observation corpus was intentionally not retained, and no raw TRAIN MRT `.bz2` files were found under `data/raw_mrt/train/` during this audit.

## Proposed Observable-Onset Definition

Use a RouteViews-observable onset, not the source-reported incident start alone.

`observable_onset_utc = the earliest BGP UPDATE timestamp from the predeclared RouteViews collector/acquisition interval that satisfies the incident-specific relevance predicate.`

The relevance predicate must use only frozen incident metadata:

- Hijack: affected prefix when known, victim ASN, hijacker ASN, and origin/path evidence tied to the incident.
- Leak: `leak_asn`, `leak_seg`, observed origin/path evidence tied to the leak event, and affected prefix only when actually available.
- Outage: affected ASN/network and BGP-visible withdrawals/announcements involving affected networks.

If no matching RouteViews observation exists, TTI is not measurable for that incident from RouteViews alone. The source start time may be retained as documented incident onset, but it should not be substituted for BGP-observable onset in an early-classification experiment.

## Feature Safety at Partial Horizons

The companion table `docs/tti_feature_horizon_safety_v1.csv` classifies all 74 V4 features.

Summary:

- 44 Behavioral features: not recoverable exactly at partial horizons from the current compact evidence store or frozen completed-window features. They are computable if timestamped parsed observations are available and the aggregation filters strictly to `timestamp <= observable_onset_utc + horizon`.
- 14 CAIDA features: can be remapped at partial horizons only if timestamped prefix/path evidence exists. Use the nearest CAIDA snapshot available at or before the horizon time.
- 16 RPKI/ROV features: can be remapped at partial horizons only if timestamped prefix/origin evidence exists. Use VRP data available at or before the horizon time.

Completed five-minute values must not be reused for a 30/60/120-second horizon because that would include observations from the future part of the window.

## Frozen Level-1 Versus K1

The frozen Level-1 XGBoost model can technically consume a 74-column V4-compatible vector at each horizon if the feature order and preprocessing are preserved. That would evaluate robustness of the completed-window model under censored partial evidence. It is not the same as a model trained specifically for early classification.

The frozen K1 incident-level temporal stacker should not be used directly for the first TTI experiment. Its meta-features summarize a sequence of window probabilities, including early/middle/late thirds, slopes, and full incident-level probability distribution summaries. Applying those summaries to partial evidence would either be undefined or would leak future windows unless the stacker were redesigned as a causal prefix-only architecture.

## Recommended Early-Classification Experiment

Recommended first experiment after review:

1. Keep the final frozen model artifacts untouched.
2. Build a small TRAIN-only pilot using existing parsed pilot/normal CSVs to validate horizon aggregation logic.
3. Create a new timestamped evidence store version, for example `data/enrichment/evidence_timestamped/train_tti_v1/`, that preserves `bgp_timestamp_utc`, `announcement_or_withdrawal`, `peer_asn`, `prefix`, `origin_asn`, `normalized_as_path`, optional attributes needed by Behavioral features, collector, MRT filename/checksum, and incident UID.
4. Define `observable_onset_utc` per incident from the first relevant RouteViews observation.
5. For each horizon `h in {30, 60, 120, 300}` seconds, aggregate only observations in `[observable_onset_utc, observable_onset_utc + h]`.
6. Recompute the 74 V4 columns with no future observations.
7. Evaluate the frozen Level-1 XGBoost candidate first, reporting that this is a no-retraining partial-horizon robustness/TTI audit.
8. Treat a trained TTI-specific model or causal K1-prefix stacker as a separate future experiment requiring TRAIN-only development and a predeclared evaluation protocol.

## Is Retraining Scientifically Required?

For an initial advisor-facing diagnostic, retraining is not required if the question is: "How does the frozen completed-window Level-1 model behave when only early evidence is provided?"

For a scientifically optimized early-classification system, retraining is likely required because the feature distribution changes materially. Partial windows have lower counts, different rates, more missing ratios, and less stable path/prefix diversity than completed five-minute windows. A retrained model would need TRAIN-only development and should not reuse Validation or Final Holdout for tuning.

## Risks and Limitations

- The current compact evidence store cannot determine whether an observation occurred in the first 30 seconds or the last 30 seconds of a five-minute window.
- Completed-window features would leak future observations into early-horizon claims.
- Rate features need a predeclared denominator policy. Using `/5` preserves frozen-model scale but under-represents elapsed-time intensity; using `/horizon_minutes` creates a materially different representation.
- CAIDA and RPKI temporal alignment must use snapshots available at or before the horizon time.
- Outage BGP-observable onset may lag the documented Cloudflare outage start.
- Incidents with no relevant RouteViews observation near onset cannot receive a defensible TTI from RouteViews alone.
- K1 should remain a final incident-level classifier/ranker unless a causal early-prefix stacker is separately designed and trained.

## Audit Disposition

Disposition: `REVIEW_DESIGN_REQUIRED_BEFORE_TTI_EXECUTION`.

The experiment is feasible, but not from the current compact evidence store alone. The safest next step is to create a versioned timestamped evidence layer or perform a targeted TRAIN-only reparse for a small TTI pilot, then review the observed onset and horizon-feature behavior before any Validation or Holdout access.
