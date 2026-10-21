# Label Provenance and Leakage Audit

- Labels externally sourced from Cloudflare Radar.
- Hijack / Leak: BGP-specific Cloudflare event feeds.
- Outage: Cloudflare Internet outage annotations (`eventType = OUTAGE`).
- 1,419/1,419 incidents showed expected evidence-source overlap.
- 0 circular labeling cases.
- 0 direct target leakage cases.
- No class label, source event type, provider, incident ID, or source classification included in the 74-feature V4 input.
- Final disposition: `PASS_WITH_DOCUMENTED_EVIDENCE_SOURCE_OVERLAP`.

Presenter note: Evidence overlap is expected because both the external detector and the ML model observe manifestations of the same routing event. The audit distinguishes that conceptual overlap from direct target leakage.
