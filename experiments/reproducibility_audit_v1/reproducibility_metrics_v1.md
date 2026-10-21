# Evaluation Metrics Reproducibility v1

## Primary Metrics

Incident-level Macro F1, Top-1 accuracy, Top-2 accuracy, and MRR are the principal metrics. Per-class precision, recall, and F1 are reported for Hijack, Leak, and Outage. Window-level metrics are development diagnostics only and must not be mixed with incident-level uncertainty.

## Ranking

Class ranking is descending score for Hijack, Leak, and Outage. Because calibration diagnostics found imperfect calibration, the scores should be interpreted primarily as class-ranking scores rather than operationally calibrated probabilities.

## Terminal Final Holdout

Final Holdout: N=213, Macro F1=0.9201769450076779, 95% CI=[0.8801170994295882, 0.9544024249379308], Top-1=0.92018779342723, Top-2=0.9906103286384976, MRR=0.9585289514866979. Source: `config/final_praxis_result_v1.yaml`.
