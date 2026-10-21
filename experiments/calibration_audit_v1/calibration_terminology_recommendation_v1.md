# Calibration Terminology Recommendation v1

Recommendation: `PROBABILITY_TERMINOLOGY_SUPPORTED_WITH_CALIBRATION_LIMITATION`

## Option A — Probability terminology with limitation

The classifier emits normalized class probabilities from the frozen XGBoost-based incident-level architecture. These outputs were used for class ranking and incident-level Top-1/Top-2/MRR evaluation. A post-hoc calibration audit found that the scores are suitable for ranking but are not perfectly calibrated; therefore, probability terminology should be accompanied by an explicit calibration limitation and should not be interpreted as operationally calibrated event likelihood.

## Option B — Conservative terminology

To avoid overclaiming calibration, refer to the three outputs as model scores, class scores, or class-ranking scores. Under this wording, Top-1, Top-2, and MRR remain valid ranking metrics, while Brier score, log loss, and ECE are reported as diagnostic evidence that the scores are not guaranteed to be calibrated probabilities.

## Recommended wording

Use Option A when describing the mathematical model output in methodology, but use Option B in operational or defense-facing claims. Suggested wording: “The final classifier produces normalized class scores used for ranking Hijack, Leak, and Outage. Although these scores are probability-like and sum to one, post-hoc reliability analysis showed imperfect calibration; therefore, the Praxis interprets them primarily as class-ranking scores rather than calibrated operational probabilities.”
