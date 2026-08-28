# Active Window Policy v1

This policy defines label-window construction for roster v2. It is not applied to raw BGP data yet.

## Outage

- Use `label_start = startDate`.
- Use `label_end = endDate`.
- Treat the interval as the documented outage interval unless an individual outage has a quality flag requiring review.
- Preserve one real-world outage as one incident.

## Hijack

`min_hijack_ts -> max_hijack_ts` is a first/last hijack-specific detector-evidence span, not proof of continuous hijack activity.

For feature labeling, use event-specific hijack observations:

- Divide the bounding interval into 5-minute bins.
- Mark a bin active only if hijack-specific detector observations occur in or sufficiently near that bin.
- Merge consecutive active bins into incident-active segments.
- Do not automatically label long silent gaps as Hijack.
- Silent gaps should remain `UNKNOWN` until a continuity threshold is justified from observed detector-message distributions.
- Keep the gap/continuity threshold parameterized for analysis, for example `max_silent_gap_bins`.

## Leak

`min_ts/detected_ts -> max_ts` is a route-leak detector observation span, not proof of continuous leaking.

For feature labeling, use event-specific leak observations:

- Divide the bounding interval into 5-minute bins.
- Mark a bin active only if leak-specific detector observations occur in or sufficiently near that bin.
- Merge consecutive active bins into leak-active segments.
- Do not automatically label long silent gaps as Leak.
- Silent gaps should remain `UNKNOWN`.
- Keep the gap/continuity threshold parameterized and select it only after inspecting observation density/gap distributions.
