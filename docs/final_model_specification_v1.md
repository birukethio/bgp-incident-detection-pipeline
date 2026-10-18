# Final Model Specification v1

- Praxis title: An Artificial Intelligence–Based Classification and Ranking System for Border Gateway Protocol Incidents in Enterprise Networks
- Final architecture: A0 XGBoost first level to XGBoost K1 incident stacker.
- First-level strategy: crossfit ensemble first level.
- Second-level model: K1 final second-level XGBoost.
- Second-level hash: `40df040321ef`.
- Feature schema: V4, 74 frozen features.
- Training evidence: TRAIN nested CV only after Phase J.
- Final evaluation: one-time Final Holdout, 213 incidents.
- Stage 1: UNRESOLVED_EXPERIMENTAL_AUXILIARY.
