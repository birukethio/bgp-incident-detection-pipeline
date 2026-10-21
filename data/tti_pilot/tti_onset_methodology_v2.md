# TTI Observable-Onset Methodology v2

This TRAIN-only refinement tests three onset definitions without scoring a model.

A. `DOCUMENTED_START`: use the independently sourced Cloudflare/detector start time as t0 and exclude pre-start BGP evidence.

B. `FIRST_POST_DOCUMENTED_EVENT_EVIDENCE`: use the first incident-relevant RouteViews observation at or after the documented start. This is the selected v2 pilot rule because it avoids pre-context onset leakage and can be applied uniformly across Hijack, Leak, and Outage.

C. `CHANGE_BASED_ONSET`: identify the first post-start route signature not seen before the documented start, using prefix, origin ASN, normalized AS_PATH, and announcement/withdrawal type. This remains diagnostic because broader operational change detection needs a baseline and persistence rule before it can be used as the official TTI onset.

The selected v2 rule does not define onset as the first appearance of an affected ASN/prefix. It anchors t0 after the independent documented start and uses only post-start BGP evidence for horizon feature construction.
