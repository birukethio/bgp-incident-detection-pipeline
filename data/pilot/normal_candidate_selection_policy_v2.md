# Normal Candidate Selection Policy v2

This policy is diagnostic and provisional. It does not create final Normal labels and does not alter the frozen incident roster or partitions.

## Principle

NORMAL is not inferred from absence of a known incident. A Normal control window requires positive evidence of stable routing state plus absence of suspicious routing changes.

## Selection Order

1. Start from an associated TRAIN incident/network only.
2. Generate candidate control dates using calendar offsets, preserving similar time-of-day where practical.
3. Reject candidates overlapping any known incident or incident exclusion buffer.
4. Require the candidate period to support at least 30 minutes of sustained stability under the provisional rule.
5. Identify nearest before/after RouteViews RIB snapshots for the historical date.
6. Pre-screen RIB availability before downloading UPDATE files.
7. Confirm RIB visibility for the exact prefix when available; otherwise confirm ASN/network visibility.
8. Confirm expected origin stability across before/after RIB snapshots.
9. Select the collector deterministically by observability:
   - try the preferred collector first,
   - if the ASN/prefix is not visible, try historically available alternate collectors,
   - record the collector used and the reason,
   - never choose a collector because it produces the desired label.
10. Only after the RIB pre-screen passes, acquire UPDATE files for the candidate period.
11. Apply RIB + UPDATE stability qualification.
12. Assign `NORMAL_VERIFIED` only when positive stability evidence is present; otherwise keep `UNKNOWN`.

## Current Pilot Interpretation

The prior UPDATE-only method rejected stable silence because UPDATE archives record route changes, not persistent route state. The RIB-assisted method is the correct methodological direction. The remaining work before scaling is operational: use indexed or compiled RIB inspection and improve candidate selection for Hijack/Leak controls, especially when original candidate periods are shorter than 30 minutes.
