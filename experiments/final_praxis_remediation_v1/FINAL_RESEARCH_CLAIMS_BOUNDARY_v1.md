# Final Research Claims Boundary v1

This document is the authoritative boundary for the final Praxis revision. Experimental development is closed. No additional modeling, tuning, validation, or result replacement should be performed unless a demonstrable implementation error is discovered.

## Directly Supported Claims

- The final frozen K1 architecture achieved strong incident-level classification and ranking on the untouched Final Holdout: Macro F1 0.920177, Top-1 0.920188, Top-2 0.990610, and MRR 0.958529.
- The final corpus contains 1,419 balanced incidents, 473 each for Hijack, Leak, and Outage, with frozen TRAIN, Validation, and Final Holdout partitions of 993, 213, and 213 incidents.
- The final V4 representation contains 74 features: 44 Behavioral, 14 historical CAIDA AS-relationship, and 16 historical RPKI/ROV features.
- The final system is best described as an H/L/O incident classification and ranking system, not a definitive root-cause oracle.
- The true class appeared in the Top-2 for 211 of 213 Final Holdout incidents.
- Outage was the strongest final class and Hijack remained the most difficult final class.
- Direct target leakage was not detected in the 74-feature schema.
- Exact incident UID overlap and confirmed duplicate-event overlap across partitions were zero.
- The early-horizon TTI analysis supports retrospective Level-1 classification evidence at 30 to 900 second checkpoints, with five minutes supported as a practical analytical tradeoff point.

## Supported With Caveat

- Cloudflare labels are externally sourced to this project, but Cloudflare's underlying detection evidence may use public routing data conceptually related to model features.
- Cross-source validation supports label agreement among matched, unambiguous same-event cases, but coverage is limited and heavily skewed toward Outage.
- Natural-prior sensitivity evaluates collected-source class proportions, not global Internet incident prevalence.
- Calibration diagnostics support careful use of normalized class probabilities/scores, but not a claim that all outputs are calibrated probabilities.
- The K1 Level-2 stacker is procedurally specified and historically evaluated, but the original trained Level-2 binary was not persisted.

## Interpretive Claims

- Incident-level temporal stacking materially improved the TRAIN-side incident-level aggregation results compared with mean probability aggregation.
- RPKI/ROV features contributed useful signal for Hijack and CAIDA/peer visibility features contributed useful context for Leak/Outage where supported by ablation evidence.
- Ranking utility is operationally meaningful because most Final Holdout Top-1 errors were recovered in Top-2.

## Claims Not Permitted

- Do not claim true causal root-cause determination.
- Do not claim live enterprise deployment or live operational TTI.
- Do not claim universal cross-enterprise generalization.
- Do not claim global Internet-wide incident prevalence.
- Do not claim source-separated external validation of Level 2.
- Do not claim source-separated external Level-1 performance because the Level-1 IEC execution was inconclusive and no IEC incidents were scored.
- Do not claim externally confirmed H3.
- Do not describe K1 as Validation-confirmed; K1 was developed after Phase J Validation and before Final Holdout.
