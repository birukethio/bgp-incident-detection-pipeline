# Pilot Active-Window Policy Recommendation v1

## Evidence Status

- Hijack/Leak pilot incidents analyzed: `6`
- Incidents with boundary-only local detector observations: `6`
- Maximum observed first-to-last boundary gap: `19964.777` minutes
- The local Cloudflare raw records expose first/last event evidence and aggregate counts, but not dense per-message observation timelines for these six pilot events.
- ACTIVE means detector-supported incident activity. SILENT/UNKNOWN does not mean Normal.

## Threshold Recommendation

- Do not freeze a final `max_gap_between_active_bins` from this boundary-only pilot evidence.
- For the next download pilot, use the 60-minute context buffer unchanged.
- Before scaling acquisition, recover or derive dense event-specific observations from MRT parsing or a detector detail source, then re-evaluate candidate thresholds of 5, 10, 15, 30, and 60 minutes.
- If a provisional threshold is needed only for acquisition scoping, `60 minutes` is the least fragmented tested rule, but it remains provisional and should not become a training label rule yet.

## Acquisition Volume Effect at 60-Minute Candidate Rule

- Original planned Hijack/Leak files: `2565`
- Candidate active-window files: `111`
- Absolute reduction: `2454` files
- Percentage reduction: `95.673%`

## Decision

- Outage windows remain acceptable as documented Cloudflare intervals.
- Hijack/Leak active-window extraction is not fully defensible from the current local detector records alone because all six pilot timelines are boundary-only.
- Recommended next action: either download a very small MRT subset for the short/median incidents first, or acquire enough MRT around the boundary-supported active bins to derive dense observation evidence before downloading the full long spans.

## Threshold Rows Generated

- Sensitivity rows by threshold: `{5: 6, 10: 6, 15: 6, 30: 6, 60: 6}`
