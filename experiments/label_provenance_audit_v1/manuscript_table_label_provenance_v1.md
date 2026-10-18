# Incident Label Provenance and Leakage Assessment by Class

Table. This table summarizes how Cloudflare Radar labels entered the final corpus and how the audit separated external label provenance from evidence-source overlap.

|Incident Class|External Label Source|Cloudflare Feed Endpoint|Local Label Assignment|Evidence Source Overlap|Direct Target Leakage|
|---|---|---|---|---|---|
|Hijack|Cloudflare Radar BGP Hijack Events feed|/radar/bgp/hijacks/events|Assigned Hijack because event came from the hijack feed|Documented overlap with public BGP, RPKI/IRR, AS-path, and AS-relationship evidence|None detected|
|Leak|Cloudflare Radar BGP Route Leak Events feed|/radar/bgp/leaks/events|Assigned Leak because event came from the route leak feed|Documented overlap with BGP AS-path and AS-relationship/valley-free evidence|None detected|
|Outage|Cloudflare Radar outage annotations|/radar/annotations/outages with eventType = OUTAGE|Assigned Outage because record was an outage annotation and passed local ASN/network quality filters|Broader Internet outage annotation; not a BGP-specific outage detector|None detected|
