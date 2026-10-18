# Label-Provenance Audit Summary

Table. Compact summary of the final label-provenance and leakage audit.

|Audit Item|Count|Interpretation|
|---|---|---|
|Total incidents audited|1,419|Final balanced corpus: 473 Hijack, 473 Leak, 473 Outage|
|PARTIAL_EVIDENCE_OVERLAP|1,419|Expected conceptual overlap between Cloudflare source evidence and routing/security model features|
|POTENTIAL_CIRCULAR_LABELING|0|No case found where the local pipeline inferred the class directly from the same variables supplied as model features|
|DIRECT_TARGET_LEAKAGE|0|No class label, source event type, provider, incident ID, or source classification included as a model feature|
|REVIEW_REQUIRED|0|No remaining provenance-review cases in the final audit|
|Final disposition|PASS_WITH_DOCUMENTED_EVIDENCE_SOURCE_OVERLAP|Labels are externally sourced, with documented evidence-source overlap rather than full evidence independence|
