# RPKI Temporal Mapping Policy v1

For each BGP evidence row, use the historical VRP snapshot for the UTC observation date when available. The selected source is the RIPE NCC historical RPKI repository archive at `https://ftp.ripe.net/rpki/`, where each trust-anchor/date directory exposes `roas.csv.xz` VRP data. If an exact date is unavailable, the acceptable fallback is the nearest earlier available snapshot. Future VRP state must not be used.

Pilot mapping uses the same-day snapshot for every pilot window date. Any fallback is recorded explicitly in the mapping table.
