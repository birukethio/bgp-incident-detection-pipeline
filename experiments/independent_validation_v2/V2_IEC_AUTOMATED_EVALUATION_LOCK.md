# V2 IEC Automated Evaluation Lock

Generated UTC: 2026-09-15T14:39:33.777256+00:00

This lock freezes the source-separated IEC roster and evaluation protocol before any model scoring.

## Frozen Items
- IEC roster rows: 63
- Hijack: 16
- Leak: 17
- Outage: 30
- Source-native labels: frozen in `v2_IEC_final_source_separated_roster.csv`.
- Mapping rules: frozen in `v2_IEC_source_label_mapping_rules.csv`.
- Exclusions: frozen in `v2_IEC_automatic_exclusion_ledger.csv`.
- Model artifacts and feature schemas: no changes permitted; verification/scoring must use the existing frozen Praxis artifacts.
- Hypotheses: H1/H2/H3 source-separated IEC confirmation, feature-enrichment delta, and retrospective Level-2 comparison.
- Bootstrap procedure: incident-level paired bootstrap with predeclared seed(s) from the scoring protocol.
- Acceptance rules: no event replacement, tuning, retraining, recalibration, thresholding, or roster edits after scoring.

## Checksums
- `v2_IEC_source_label_mapping_rules.csv`: `cbe1f792e2edacceacf34c6723a6493ef0c9c9c9305b8dfb41702a5268d5f218`
- `v2_IEC_source_native_verification.csv`: `652b662dbcdba6f3b1bbd3f8a1c6f52993ea20219c87389416e4c4fbb3789961`
- `v2_IEC_automatic_exclusion_ledger.csv`: `8a1166ef077049272e4d36df568e2427bd35d28be745c994c032c167cd0f87dd`
- `v2_IEC_final_source_separated_roster.csv`: `33008ecbfb3fe2f0208dc08f39e88a823374809222b93e2625b9d2c731fce28b`
- `v2_IEC_source_separated_prelock_report.md`: `cb7b53832bc2834fba1e25c55364353722c74eec27cfded3b0d361fabaff51b4`

Status: `IEC_ROSTER_AND_PROTOCOL_LOCKED_BEFORE_SCORING`
