# Advisor Feedback and Technical Remediation Slide v1

Use this as one readable defense slide.

| Concern | Action | Result |
| --- | --- | --- |
| Label provenance/source dependence | Cloudflare label-entry trace, label provenance audit, cross-source validation | Direct target leakage not detected; source dependence documented. |
| Class balancing | Corpus balancing audit and prior-shift sensitivity | 473/class is controlled design; observed-prior sensitivity reported separately. |
| TTI/five-minute horizon | Retrospective early-horizon Level-1 experiment | Five minutes supported as practical tradeoff, not mathematical optimum. |
| Partition independence | Partition forensic audit | Zero UID overlap and zero confirmed duplicate-event cross-partition pairs. |
| Calibration | Frozen prediction calibration audit | Use normalized class probabilities/scores with calibration caveat. |
| Reproducibility | Full reproducibility audit and artifact maps | Method procedurally documented; Level-2 binary limitation disclosed. |
| Error analysis | Final incident-level error analysis | 17 Holdout Top-1 errors; 15/17 recovered by Top-2. |
| External validation | IEC V1/V2 construction and closure | Source-separated model validation inconclusive; no unsupported external claim. |
