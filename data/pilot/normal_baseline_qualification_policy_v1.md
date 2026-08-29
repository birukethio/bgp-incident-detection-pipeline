# Normal Baseline Qualification Policy v1

NORMAL examples are required to provide Stage 1 with trustworthy examples of ordinary, stable BGP behavior. Stage 1 will later learn NORMAL versus INCIDENT, where Hijack, Leak, and Outage windows are INCIDENT examples.

Absence of a known incident is not enough to declare a window NORMAL. PRE_CONTEXT, POST_CONTEXT, and UNKNOWN windows remain unchanged unless they independently pass this separate Normal qualification workflow.

Candidate periods are selected from TRAIN incidents only, using the same representative ASN/network and, where available, representative prefix. Candidate dates preserve the incident time of day and evaluate offsets of 1, 3, 7, and 14 days before and after the incident-active period.

Candidates overlapping any known frozen Roster v2 Hijack, Leak, or Outage involving the same ASN/network or prefix are rejected. A parameterized incident exclusion buffer is applied around related known incidents. The pilot recommends 60 minutes provisionally; rejected buffer-adjacent windows remain UNKNOWN.

Future qualification must use the 44 behavioral features with baseline-relative checks, such as median, IQR, MAD, and percentile comparisons from TRAIN-only candidate controls. The rules should check origin stability, announcement/withdrawal bursts, AS_PATH instability, prefix deaggregation, MOAS/origin-diversity anomalies, path prepending/path-change anomalies, and sustained stability across consecutive windows.

A single isolated 5-minute window should not qualify as NORMAL by itself. The pilot evaluates 3, 6, and 12 consecutive 5-minute windows and recommends 6 windows, or 30 minutes, as the provisional Normal MRT pilot requirement.

Normal qualification rules are dataset-construction rules only. They must not become live inference logic. During inference, the trained ML classifier predicts NORMAL or INCIDENT from the feature vector.

This dry-run creates NORMAL_CANDIDATE periods and an MRT acquisition plan only. It does not download Normal MRT data and does not create NORMAL_VERIFIED labels.
