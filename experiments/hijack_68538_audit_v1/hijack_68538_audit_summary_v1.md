# Hijack:68538 Audit Summary v1

Generated UTC: 2026-09-14T23:51:22.958361+00:00

## Main Finding

`Hijack:68538` entered the corpus from a preserved Cloudflare Radar BGP hijack event and was placed in the frozen Final Holdout. The source-side evidence is explicit, but the final Holdout RouteViews processing found zero incident-relevant observations. This is best classified as `ROUTING_DATA_PRESENT_BUT_NO_INCIDENT_RELEVANT_MATCH`, not `NO_ROUTING_DATA`.

## RouteViews Evidence

- MRT files inspected: 21
- BGP observations parsed: 5254545
- Incident-relevant observations: 0
- Relevant announcements: 0
- Relevant withdrawals: 0
- Resulting analytical windows: 52

## Feature Forensics

- Behavioral V1 rows: 52
- V4 rows: 52
- CAIDA rows: 52; CAIDA path observation count sum: 0
- RPKI rows: 52; RPKI evidence observation count sum: 0
- V4 numeric NaN count: 1196
- V4 numeric Inf count: 0

## Frozen Prediction

- True class: HIJACK
- Predicted class: HIJACK
- H/L/O scores: 0.721245 / 0.251850 / 0.026905
- True-class rank: 1
- Correctly classified: True

## Post-hoc Exclusion Sensitivity

This sensitivity recomputed metrics from existing frozen incident-level predictions only. It did not rerun inference and does not modify the official Final Holdout result.

- Original N: 213; Without Hijack:68538 N: 212
- Original Macro F1: 0.920177; Without: 0.919582; Delta: -0.000595
- Original Top-1: 0.920188; Without: 0.919811; Delta: -0.000376
- Original Top-2: 0.990610; Without: 0.990566; Delta: -0.000044
- Original MRR: 0.958529; Without: 0.958333; Delta: -0.000196

Final disposition: `QUALITY_GATE_INCONSISTENCY`

No model was retrained. The official Final Holdout result was not changed.
