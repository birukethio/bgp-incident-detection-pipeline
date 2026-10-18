# V2 Hijack/Leak Expansion Feasibility Summary
Generated: 2026-09-14T22:02:15.116561+00:00
Scope: additive Hijack/Leak source expansion only under `experiments/independent_validation_audit_v2/`. No model scoring, no Validation access, no Final Holdout access, and no Outage search were performed.
## Counts
- Hijack: accepted/new independent = 18; RouteViews-available = 18; target >=15 = YES; preferred >=20 = NO
- Leak: accepted/new independent = 25; RouteViews-available = 25; target >=15 = YES; preferred >=20 = YES
- Outage: accepted/new independent = 30; RouteViews-available = 30; target >=15 = YES; preferred >=20 = YES
- Total independent candidates including existing 30 Outage records: 73
- Total RouteViews-available accepted candidates including Outage: 73

## Source Distribution By Class
- Hijack: BGPHorizon incident analysis = 1
- Hijack: GitHub evidence archive and NANOG thread = 1
- Hijack: MANRS 2017 year-in-review = 3
- Hijack: MANRS BGP Security in 2021 = 6
- Hijack: MANRS incident analysis = 3
- Hijack: Qrator Labs Radar article = 1
- Hijack: Qrator Labs Radar article index = 1
- Hijack: Qrator Labs blog = 1
- Hijack: RouteCause reproducible demo using RIPE RIS/RouteViews raw MRT = 1
- Leak: Internet Society / MANRS article = 1
- Leak: Kentik route leak analysis = 1
- Leak: MANRS / Oracle Internet Intelligence incident analysis = 1
- Leak: MANRS 2017 year-in-review = 2
- Leak: MANRS BGP Security in 2021 = 6
- Leak: MANRS incident analysis = 2
- Leak: Qrator Labs Q3 2024 BGP incident overview = 1
- Leak: Qrator Labs Radar archive = 1
- Leak: Qrator Labs Radar article = 3
- Leak: Qrator Labs blog = 3
- Leak: Qrator Labs quarterly BGP incidents report = 1
- Leak: Qrator_Radar social feed mirror = 3

## Lock Readiness
The expanded set reaches the minimum target of 15 accepted Hijack and 15 accepted Leak candidates, and Leak reaches the preferred 20+ target. Hijack remains below the preferred 20+ target. Several accepted events are prefix-count candidates whose public source text did not expose the full affected-prefix list; these are usable for expert adjudication but should be tightened before a final evaluation lock.

Final disposition: `READY_FOR_V2_LOCK_WITH_LIMITATIONS`
