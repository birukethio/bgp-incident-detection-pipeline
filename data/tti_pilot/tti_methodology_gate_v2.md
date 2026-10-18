# TTI Methodology Gate v2

- Pilot incidents: 9 TRAIN incidents
- Onset ambiguity flags: {'NONE': 6, 'REVIEW_CHANGE_ONSET_DIFFERS': 3}
- Leakage assertion status: {'PASS': 36}
- V4 compatibility status: {'PASS': 74}
- Behavioral features: 44 reconstructed from horizon-filtered timestamped evidence.
- CAIDA features: 14 reconstructed from AS paths observable through each horizon using cached historical same-month serial-2 snapshots.
- RPKI/ROV features: 16 reconstructed from prefix-origin observations observable through each horizon using cached same-day historical VRP snapshots.
- Model scoring: not performed in this step.

Evidence: v2 generated a 74-feature horizon matrix for 9 incidents x 4 horizons and all feature inputs obeyed the horizon cutoff. Blank ratio/statistic cells represent undefined NaN-style values inherited from the frozen feature definitions, not a changed feature definition.

Recommendation: READY_FOR_FROZEN_LEVEL1_SCORING
