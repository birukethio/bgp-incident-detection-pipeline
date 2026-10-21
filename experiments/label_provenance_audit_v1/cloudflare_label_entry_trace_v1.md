# Cloudflare Label Entry Trace Audit v1

Scope: trace how the final 1,419 incident labels entered the corpus from Cloudflare Radar, and distinguish external label provenance from underlying evidence-source independence.

This audit is read-only. No labels, datasets, models, partitions, results, manuscript files, figures, or tables were modified.

## Executive Finding

The final labels are externally sourced from Cloudflare Radar endpoints, but the degree of underlying evidence independence differs by class.

| Class | Final Count | Label Entry Finding | Underlying Evidence Independence |
|---|---:|---|---|
| Hijack | 473 | Cloudflare Radar BGP hijack endpoint supplies hijack events; local code assigns `category = Hijack` because records came from that endpoint. | Not fully independent from routing/RPKI/AS-relationship model features. Cloudflare methodology uses BGP updates and auxiliary routing datasets. |
| Leak | 473 | Cloudflare Radar BGP route leak endpoint supplies leak events; local code assigns `category = Leak` because records came from that endpoint. | Not fully independent from AS-path/AS-relationship model features. Cloudflare methodology uses BGP updates and valley-free/AS-relationship evidence. |
| Outage | 473 | Cloudflare Radar outage annotations endpoint supplies `eventType = OUTAGE` annotations; local code assigns `category = Outage` after quality filtering. | This is an Internet outage/anomaly annotation feed, not a BGP-specific outage detector. It may include ASN/network evidence, but equivalence to BGP routing outage must not be assumed. |

Overall disposition: **PASS_WITH_DOCUMENTED_EVIDENCE_SOURCE_OVERLAP**.

## Local Code Path Summary

### Initial Cloudflare Fetch

Local script:

`cloudflare_incidents/fetch_cloudflare_all_incidents_to_2026_01.mjs`

Endpoint map:

```javascript
const ENDPOINTS = {
  leaks: "/radar/bgp/leaks/events",
  hijacks: "/radar/bgp/hijacks/events",
  outages: "/radar/annotations/outages",
};
```

Observed code behavior:

| Class | Cloudflare Endpoint | Response Container | Raw Local Output |
|---|---|---|---|
| Hijack | `/radar/bgp/hijacks/events` | `result.events` | `cloudflare_incidents/raw_hijacks_all_available_to_2026-01_cloudflare.json` |
| Leak | `/radar/bgp/leaks/events` | `result.events` | `cloudflare_incidents/raw_leaks_all_available_to_2026-01_cloudflare.json` |
| Outage | `/radar/annotations/outages` | `result.annotations` | `cloudflare_incidents/raw_outages_all_available_to_2026-01_cloudflare.json` |

The script pages over leaks/hijacks through `fetchPagedEvents(kind)` and outages through `fetchOutages()`. It saves raw Cloudflare objects before subsequent normalization and quality filtering.

## Hijack Label Trace

### Cloudflare API

Endpoint:

`GET https://api.cloudflare.com/client/v4/radar/bgp/hijacks/events`

Cloudflare API documentation identifies this endpoint as the BGP hijack events endpoint and returns an `events` array. Documented response fields include:

`id`, `confidence_score`, `duration`, `event_type`, `hijack_msgs_count`, `hijacker_asn`, `hijacker_country`, `is_stale`, `max_hijack_ts`, `max_msg_ts`, `min_hijack_ts`, `on_going_count`, `peer_asns`, `peer_ip_count`, `prefixes`, `tags`, `victim_asns`, and `victim_countries`.

### Event Identifier

Cloudflare field:

`id`

Local use:

`incident_id = String(e.id)`

### Event Type Field

Cloudflare field:

`event_type`

Local use:

Preserved in notes/metadata. It is not used to infer the local label.

### Local Label Conversion

Local script:

`cloudflare_incidents/build_training_ready_all_cloudflare_roster.mjs`

Function:

`normalizeHijack(e)`

Local category assignment:

```javascript
category: "Hijack"
```

Important: the local pipeline does not infer Hijack from model-like features such as origin changes, RPKI state, or AS path behavior. It selects Cloudflare objects from the hijack endpoint/file and normalizes them as Hijack.

The stratified sampling script follows the same endpoint-derived logic:

`cloudflare_incidents/build_stratified_quality_leak_hijack_samples.mjs`

Function:

`normalizeHijack(e)`

Local category assignment:

```javascript
category: "Hijack"
```

### Supplied vs Inferred

Conclusion: **Hijack is supplied by the selected Cloudflare Radar BGP hijack events endpoint.**

The final class is locally assigned from endpoint provenance, not inferred from the 74 model features.

## Leak Label Trace

### Cloudflare API

Endpoint:

`GET https://api.cloudflare.com/client/v4/radar/bgp/leaks/events`

Cloudflare API documentation identifies this endpoint as the BGP route leak events endpoint and returns an `events` array. Documented response fields include:

`id`, `countries`, `detected_ts`, `finished`, `leak_asn`, `leak_count`, `leak_seg`, `leak_type`, `max_ts`, `min_ts`, `origin_count`, `peer_count`, and `prefix_count`.

Cloudflare Radar BGP anomaly documentation describes the route leak table fields. In particular, `leak_asn` identifies the ASN believed to have caused the leak, `leak_seg` is the AS-path segment believed to represent the leak, `min_ts` and `max_ts` are earliest/latest timestamps of leak announcements, and `leak_count`, `peer_count`, `prefix_count`, and `origin_count` summarize observed leak announcements.

### Event Identifier

Cloudflare field:

`id`

Local use:

`incident_id = String(e.id)`

### Event Type Field

Cloudflare field:

`leak_type`

Local use:

Preserved in notes/metadata. It is not used to infer the local label.

### Local Label Conversion

Local script:

`cloudflare_incidents/build_training_ready_all_cloudflare_roster.mjs`

Function:

`normalizeLeak(e)`

Local category assignment:

```javascript
category: "Leak"
```

The stratified sampling script follows the same endpoint-derived logic:

`cloudflare_incidents/build_stratified_quality_leak_hijack_samples.mjs`

Function:

`normalizeLeak(e)`

Local category assignment:

```javascript
category: "Leak"
```

### Supplied vs Inferred

Conclusion: **Leak is supplied by the selected Cloudflare Radar BGP route leak events endpoint.**

The final class is locally assigned from endpoint provenance, not inferred from the 74 model features.

## Outage Label Trace

### Cloudflare API

Endpoint:

`GET https://api.cloudflare.com/client/v4/radar/annotations/outages`

Cloudflare API documentation describes this endpoint as retrieving latest Internet outages and anomalies, returning an `annotations` array.

Documented response fields include:

`id`, `asns`, `asnsDetails`, `dataSource`, `description`, `endDate`, `eventType`, `linkedUrl`, `locations`, `locationsDetails`, `origins`, `originsDetails`, `outage`, `scope`, and `startDate`.

The `outage` object includes:

`outageCause` and `outageType`.

In the local raw Cloudflare outage artifact, sampled records show:

```json
{
  "eventType": "OUTAGE",
  "dataSource": "ALL",
  "outage": {
    "outageCause": "...",
    "outageType": "..."
  }
}
```

### Event Identifier

Cloudflare field:

`id`

Local use:

`incident_id = String(e.id)`

### Event Type Field

Cloudflare field:

`eventType`

Typical local value:

`OUTAGE`

Additional category fields:

`outage.outageType`, `outage.outageCause`, `dataSource`, `scope`

### Local Label Conversion

Initial normalization script:

`cloudflare_incidents/build_training_ready_all_cloudflare_roster.mjs`

Function:

`normalizeOutage(e)`

Local category assignment:

```javascript
category: "Outage"
```

Quality-controlled outage roster script:

`cloudflare_incidents/build_quality_controlled_outage_roster.mjs`

Local category assignment:

```javascript
category: "outage"
```

Clean outage ASN roster script:

`cloudflare_incidents/build_clean_outage_asn_roster.mjs`

Final pool requirement:

```javascript
verification_status === "verified"
affected_asns.length > 0
source_url
```

### Is This a BGP Routing Outage Label?

Conclusion: **No, not directly.**

The Cloudflare endpoint used for Outage is not under `/radar/bgp/...`. It is the Radar outage annotations endpoint:

`/radar/annotations/outages`

Cloudflare describes this resource as Internet outages and anomalies. Cloudflare Radar outage documentation presents the Outage Center as tracking outages around the world and shows annotation fields such as `eventType`, `outageCause`, `outageType`, `scope`, `dataSource`, ASNs, locations, and linked references. The documentation also notes that outage data can be examined through NetFlows and HTTP data.

Therefore, the source label is best described as:

**Cloudflare Internet outage/anomaly annotation with ASN/network metadata where available.**

It should not be described as:

**Cloudflare BGP routing-outage detector output**

unless additional event-level evidence proves the particular outage was specifically a BGP routing outage.

The local Praxis pipeline later selected outage annotations with usable timing, source, and ASN/network evidence so that RouteViews features could be extracted, but that local selection does not transform the Cloudflare source category into a BGP-specific outage label.

## Cloudflare Published Detection Methodology Trace

### Shared BGP Data Sources

Cloudflare Radar documents its BGP data collection as primarily using:

- RIPE RIS
- University of Oregon RouteViews

Cloudflare states that these sources are used for routing statistics, anomaly detection, and announced address-space graphs. It also states that dynamic route leaks and hijacks are detected by processing BGP update files, and that newer near-real-time services can use streams such as RIS Live and OpenBMP.

### Hijack Methodology

Cloudflare published methodology describes origin hijack detection as a pipeline that detects prefix-origin changes from BGP updates, scores candidate events, and uses supporting checks.

Documented supporting datasets and checks include:

- RPKI validated ROA payloads
- IRR records
- bogon prefix/ASN lists
- AS relationship datasets, including CAIDA/UCSD AS2org/AS2rel, BGPKIT AS2rel, PeeringDB AS organization data, and Cloudflare per-prefix AS relationship data
- AS path and origin-change evidence

Interpretation:

Cloudflare Hijack labels are external to the local model-training pipeline, but their underlying evidence sources overlap conceptually with model feature families such as Behavioral origin changes, RPKI/ROV, and AS-relationship context.

### Leak Methodology

Cloudflare published methodology describes route leak detection as operating over BGP announcements from RouteViews and RIPE RIS. The detection module estimates route-leak likelihood for BGP announcements, using valley-free routing assumptions and AS relationship inference.

Documented supporting evidence includes:

- public BGP updates from RouteViews and RIPE RIS
- AS path structure
- valley-free routing model
- CAIDA/UCSD AS relationship dataset
- Cloudflare in-house AS relationship dataset

Interpretation:

Cloudflare Leak labels are external to the local model-training pipeline, but their underlying evidence sources overlap conceptually with Behavioral AS-path features and CAIDA/AS-relationship features.

### Outage Methodology

The endpoint used locally is Cloudflare Radar outage annotations, not a BGP endpoint. Cloudflare Radar outage documentation describes the Outage Center as tracking Internet outages and anomalies. Its API fields include `dataSource`, `scope`, affected ASNs/locations/origins, `outageCause`, and `outageType`.

Cloudflare Radar documentation shows outage analysis can involve traffic-oriented data views such as HTTP and NetFlows, plus annotations and linked references.

Interpretation:

Outage label provenance is external Cloudflare outage annotation. Underlying evidence can include Cloudflare-observed Internet traffic signals and annotations, not necessarily BGP routing evidence. Therefore, outage labels are not automatically equivalent to BGP control-plane outage labels, though the local final roster retained outage records with identifiable ASN/network evidence for RouteViews-based modeling.

## External Label Provenance vs Evidence-Source Independence

| Question | Hijack | Leak | Outage |
|---|---|---|---|
| Did Cloudflare supply the source event category? | Yes, via BGP hijack endpoint. | Yes, via BGP leak endpoint. | Yes, via outage annotation endpoint and `eventType=OUTAGE`. |
| Did local code infer the class from the 74 feature values? | No. | No. | No. |
| Does Cloudflare methodology use evidence conceptually similar to model features? | Yes. | Yes. | Partly/uncertain; outage source is broader Internet outage annotation. |
| Is there direct target leakage into features? | Not shown by this trace. | Not shown by this trace. | Not shown by this trace. |
| Is there underlying evidence-source independence? | Limited, because public BGP/RPKI/AS-relationship evidence overlaps conceptually. | Limited, because BGP AS-path and AS-relationship evidence overlaps conceptually. | Stronger with respect to BGP-specific features, but outage labels are not BGP-specific by default. |

The critical distinction is:

- **External label provenance:** all three labels originate from Cloudflare Radar records selected before local feature extraction.
- **Underlying evidence-source independence:** Hijack and Leak Cloudflare labels are produced from evidence sources that overlap with routing features used by the model. This is legitimate predictive association unless source event type or label identity is included as a model feature, but it should be disclosed as documented evidence-source overlap.

## Direct Target Leakage Check From This Trace

This trace found no evidence that the local final 74-feature model inputs include:

- Cloudflare `id`
- Cloudflare endpoint name
- Cloudflare source provider
- `event_type`
- `leak_type`
- `eventType`
- `outageType`
- `outageCause`
- local `category`
- label text
- source URL
- incident identifier

Those fields were used for label/provenance, roster construction, filtering, or audit metadata rather than as final model predictors.

This audit does not replace a feature-matrix column-level leakage audit; it establishes the label-entry path and provenance relationship.

## Source Links

- Cloudflare Radar API: BGP Hijacks Events: https://developers.cloudflare.com/api/resources/radar/subresources/bgp/subresources/hijacks/methods/events/
- Cloudflare Radar API: BGP Leaks Events: https://developers.cloudflare.com/api/resources/radar/subresources/bgp/subresources/leaks/methods/events/
- Cloudflare Radar API: Outage Annotations: https://developers.cloudflare.com/api/resources/radar/subresources/annotations/subresources/outages/methods/get/
- Cloudflare Radar Routing / BGP docs: https://developers.cloudflare.com/radar/investigate/routing/
- Cloudflare Radar Outages docs: https://developers.cloudflare.com/radar/investigate/outages/
- Cloudflare blog, route leak detection: https://blog.cloudflare.com/route-leak-detection/
- Cloudflare blog, BGP origin hijack detection: https://blog.cloudflare.com/how-cloudflare-detects-bgp-origin-hijacks/

