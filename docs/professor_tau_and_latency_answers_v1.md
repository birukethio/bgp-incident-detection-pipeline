# Professor Tau and Latency Answers v1

No manually selected tau is used in the final Hijack/Leak/Outage K1 classifier. Tau belonged to the experimental Stage 1 NORMAL-vs-INCIDENT gate, which remains `UNRESOLVED_EXPERIMENTAL_AUXILIARY`.

The final K1 system waits for non-overlapping five-minute incident windows to be available, computes 44 Behavioral + 14 CAIDA + 16 RPKI features, scores windows with the first-level XGBoost ensemble, builds 74 K1 incident meta-features, and ranks Hijack/Leak/Outage with the second-level XGBoost configuration hash `40df040321ef`.

Temporal requirement: `deterministic chronological equal-count EARLY/MIDDLE/LATE thirds`. Minimum representation note: 1 window is computationally representable; with 1-2 windows the deterministic segmentation falls back to EARLY/LATE, while the frozen schema is designed for complete incident observation windows.

Concise answer: after the required five-minute observation windows and their features are available, the warm K1 computational classification/ranking step is measured in milliseconds per incident on the TRAIN fixture. Operational diagnosis time should be described as post-window incident classification rather than instant detection, because feature availability depends on collecting the configured observation interval.
