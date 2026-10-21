# Section 4.4 Paper Figure Text v1

These text blocks are separated from the high-resolution chart-only JPG so the dissertation document can control headings, captions, spacing, and source notes directly.

## Figure 4.x Incident Imbalance and Weighting Results

Title: Incident Imbalance and Weighting Results

Subtitle: TRAIN-only grouped cross-validation comparison of I0, I1, and I2. I1 was retained because it equalized incident influence while preserving all available windows.

Under-figure note: I1 is marked as the selected strategy because it preserved all observations while reducing long-incident dominance through incident-aware weights.

Caption: This figure compares the three predeclared imbalance strategies. I0 used the natural five-minute window representation, I1 retained all windows with incident-aware weighting, and I2 applied incident-aware weighting plus a 164-window p95 temporal cap. Although I2 produced the highest incident Macro F1 among these three rows, the recorded decision retained I1 because: "Incident is the independent unit; weighting reduces long-incident dominance without data removal."

Source: `data/modeling/imbalance_strategy_model_comparison_v1.csv`

Decision source: `data/modeling/experiment_decision_ledger_v1.csv`

Image: `figures/chapter4/figure_4_incident_imbalance_comparison_v1_highres_chart_only.jpg`
