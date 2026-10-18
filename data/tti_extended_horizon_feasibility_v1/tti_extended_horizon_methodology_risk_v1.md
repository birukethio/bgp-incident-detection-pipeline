# Extended TTI Horizon Methodology Risk Audit v1

This memo evaluates whether adding 600s and 900s after observing the 30/60/120/300 Validation TTI results is scientifically defensible.

## Finding

Technically, the extension is feasible. Methodologically, it is post-hoc relative to the frozen TTI protocol and the one-time Validation TTI confirmation already observed.

## Risk Assessment

- The originally frozen TTI protocol predeclared 30s, 60s, 120s, and 300s checkpoints only.
- The Validation TTI result has already been observed at those checkpoints.
- Adding 600s and 900s now could be perceived as post-hoc expansion of the analysis space, especially if the added horizons are used to strengthen the main Validation conclusion.
- The risk is lower if the extension is framed as an explicitly labeled exploratory/sensitivity analysis motivated by advisor feedback and temporal-curve characterization, not as a replacement for the terminal predeclared Validation TTI result.
- The risk is materially higher if 600s/900s are folded into the same terminal Validation confirmation without clearly marking that they were added after the original Validation results were known.

## Defensible Use Conditions

If executed, the extension should be documented as `POST-HOC EXPLORATORY TEMPORAL-HORIZON SENSITIVITY`, not as the pre-specified terminal TTI result. The frozen 30/60/120/300 Validation result should remain the primary confirmatory analysis. The extension should use unchanged onset, evidence, feature, class-order, model, and metric rules; no threshold or model changes should be permitted; Final Holdout should remain untouched unless a separate protocol is later approved.

## Recommendation

Do not modify the frozen TTI protocol retroactively. If the added horizons are needed for Chapter 5 discussion or advisor-requested sensitivity, create a new versioned exploratory protocol and explicitly separate it from the already completed one-time Validation TTI confirmation.

Methodology disposition: technically feasible, but confirmatory-freeze risk exists unless labeled exploratory.
