# Detection vs Classification Scope v1

Question: Is this NORMAL or INCIDENT?

Status: `UNRESOLVED_EXPERIMENTAL_AUXILIARY`.

Question: Given an observed BGP incident, what incident type is most likely?

Output: ranked `Hijack / Leak / Outage` probabilities from the final K1 system.

The final primary system should not be described as proving general abnormal-event detection. It is a supervised incident-type classifier/ranker for already observed BGP incident windows.

Final K1 decision rule: Top-1 is `argmax P(class)`. Ranking is descending `P(Hijack), P(Leak), P(Outage)`. No manually selected tau is used.
