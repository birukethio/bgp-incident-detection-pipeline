# Hijack/Leak Targeted Cross-Source Expansion v1

This additive search targeted only the 473 Cloudflare Hijack and 473 Cloudflare Leak incidents in the frozen corpus. Outages were not searched. The original v1 cross-source result was not altered.

## Frozen matching rule retained

The expansion used the existing event-matching and deterministic label-mapping rules:

- exact or strong same-event evidence required;
- non-Cloudflare primary source required;
- source-native Hijack/Leak terminology required;
- exact ASN plus prefix/path plus date/time evidence prioritized;
- aggregate month/country references excluded;
- raw BGP observations excluded as independent classification;
- Cloudflare excluded as corroboration.

## Result

- Additional Hijack matches: 0
- Additional Leak matches: 0
- Agreement/disagreement among additional matches: not applicable; no additional accepted matches
- Revised Hijack corroboration count: 0
- Revised Leak corroboration count: 1
- Revised overall v1 agreement: 1.000000

## Notes on searched evidence

The targeted local and web search recovered the already-counted Kentik Voxility/Lumen AS3223/AS3356 route-leak match (`Leak:291677`). MANRS republishes the Kentik analysis as a guest post, so it was reviewed but not counted as an independent new label source. RIPEstat and RouteViews/RIPE RIS style raw observations were excluded because they are routing evidence rather than source-native event classifications. MANRS monthly-country summaries were excluded because they are aggregate context rather than deterministic same-event matches.

## Disposition

No additional high-quality same-event Hijack or Leak matches were found under the frozen rules.
