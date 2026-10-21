# Final Defense Evidence Map v1

## Slide 1 — Problem
- Objective: Explain BGP incidents and enterprise risk.
- Bullets: BGP events disrupt reachability and attribution; operators need ranked incident-type support; public routing evidence is noisy.
- Table/Figure: Motivation diagram
- Likely question: Why not manual analysis?
- Defense response: Manual analysis is slow and inconsistent at historical scale.

## Slide 2 — Research gap
- Objective: Position against existing work.
- Bullets: Prior work often focuses on one incident type; few integrate Behavioral+CAIDA+RPKI; fewer report incident-level ranked H/L/O evaluation.
- Table/Figure: Literature gap table
- Likely question: What is new?
- Defense response: Integration, incident-level ranking, reproducibility, and final holdout evidence.

## Slide 3 — Research questions and hypotheses
- Objective: State final narrowed claims.
- Bullets: H/L/O classification; enriched features; incident-level ranking; retrospective TTI sensitivity.
- Table/Figure: RQ/H table
- Likely question: Were all hypotheses externally confirmed?
- Defense response: No; external Level-2 confirmation was not executed and is documented.

## Slide 4 — Dataset
- Objective: Show corpus construction.
- Bullets: 1,419 incidents; 473/class; TRAIN/Validation/Holdout; Cloudflare source provenance and audits.
- Table/Figure: Corpus table
- Likely question: Why balanced?
- Defense response: Controlled per-class scientific comparison; observed-prior sensitivity is separate.

## Slide 5 — Feature architecture
- Objective: Summarize V4.
- Bullets: 44 Behavioral, 14 CAIDA, 16 RPKI/ROV; historical alignment; no direct target leakage.
- Table/Figure: Feature diagram
- Likely question: Feature leakage?
- Defense response: Direct target leakage was audited and not detected.

## Slide 6 — Model architecture
- Objective: Explain final K1.
- Bullets: Level-1 XGBoost windows; retrospective Level-2 temporal stacker; incident-level ranking.
- Table/Figure: K1 topology
- Likely question: Is it real time?
- Defense response: No; final K1 is retrospective over configured observation windows.

## Slide 7 — Experimental controls
- Objective: Defend evaluation integrity.
- Bullets: Frozen partitions; grouped/nested CV; holdout sealed; no post-holdout changes.
- Table/Figure: Access chronology
- Likely question: Did Validation guide K1?
- Defense response: K1 was post-Validation TRAIN development; final holdout is independent estimate.

## Slide 8 — Final performance
- Objective: Show headline results.
- Bullets: Macro F1 0.920177; Top-2 0.990610; MRR 0.958529; CI [0.880117, 0.954402].
- Table/Figure: Holdout performance figure
- Likely question: How robust?
- Defense response: Bootstrap CI and no post-holdout model changes.

## Slide 9 — Error and ranking analysis
- Objective: Explain failures honestly.
- Bullets: 17 Top-1 errors; 15/17 Top-2 rescued; Hijack-to-Leak dominant confusion.
- Table/Figure: Confusion/error figures
- Likely question: Most difficult class?
- Defense response: Hijack remained hardest.

## Slide 10 — TTI
- Objective: Answer time-to-identify concern.
- Bullets: Checkpoint TTI: Top-1 by 300s 92.57%; performance improves through five minutes then small/inconsistent gains.
- Table/Figure: TTI curves
- Likely question: Is this live TTI?
- Defense response: No; retrospective RouteViews-observable checkpoint TTI.

## Slide 11 — Advisor remediation
- Objective: Show concerns were handled.
- Bullets: Provenance, balancing, TTI, independence, calibration, reproducibility, error analysis, external validation.
- Table/Figure: Concern-action-result slide
- Likely question: What remains limited?
- Defense response: External source-separated model validation and live enterprise deployment.

## Slide 12 — Label provenance
- Objective: Explain source dependence.
- Bullets: Cloudflare label-entry trace; cross-source agreement among matched events; direct target leakage not found.
- Table/Figure: Provenance figure
- Likely question: Are labels independent?
- Defense response: External to this project, but underlying evidence overlap is documented.

## Slide 13 — Limitations
- Objective: Preempt overclaiming.
- Bullets: Public RouteViews perspective; Cloudflare/source dependence; retrospective Level-2; calibration; IEC inconclusive.
- Table/Figure: Limitations table
- Likely question: Does this invalidate results?
- Defense response: No; it defines the proper scope.

## Slide 14 — Future architecture
- Objective: Show next step.
- Bullets: BMP/Kafka streaming, incremental features, prospective TTSC, enterprise-local telemetry, external validation.
- Table/Figure: Future architecture
- Likely question: What would deployment need?
- Defense response: Live telemetry, prospective labels, monitoring and calibration.

## Slide 15 — Contributions
- Objective: Close cleanly.
- Bullets: Reproducible corpus and features; integrated V4; incident-level stacking/ranking; rigorous audits and final holdout.
- Table/Figure: Contribution list
- Likely question: Main takeaway?
- Defense response: A strong retrospective ranking system with transparent limits.
