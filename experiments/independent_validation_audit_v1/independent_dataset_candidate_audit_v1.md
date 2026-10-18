# Independent Dataset Candidate Audit v1

## Purpose

This audit identifies candidate external data sources for a future locked independent confirmation set. It does not download a new event roster, score any model, access Validation, or access/recompute Final Holdout.

## Main Finding

An independent confirmation set is feasible in principle, but not yet frozen. The best path is source-specific rather than a single universal replacement for Cloudflare:

- Hijack/Leak: RouteLLM's verified routing-anomaly benchmark is the strongest candidate if the released benchmark is accessible, licensed, and contains event-level time/ASN/prefix metadata.
- Outage: IODA outage events or the curated IODA outage/shutdown dataset are the strongest candidates, provided selected events are ASN/network scoped and not purely geographic or traffic annotations.
- Secondary/adjudication sources: MANRS/GRIP, operator postmortems, Kentik/ThousandEyes/BGPmon/RIPE reports, BGPStream-derived data, and GLBAD can support review or supplement sparse classes.

## Candidate Ranking

### Tier 1: Strongest Candidates

1. **RouteLLM verified routing-anomaly benchmark**
   - Strength: independent from Cloudflare and explicitly designed as a routing-anomaly benchmark.
   - Best classes: Hijack and Leak.
   - Key risk: the benchmark itself may use historical BGP, IRR, or RPKI evidence in validation; this is acceptable for label provenance but must be documented as evidence-source overlap.
   - Required next step: obtain the actual event-level dataset, verify license, count usable Hijack/Leak events, and deduplicate against the 1,419-event corpus.

2. **IODA outage events / curated IODA outage repository**
   - Strength: outage-focused and uses multiple signals beyond BGP.
   - Best class: Outage.
   - Key risk: some IODA events are geographic or Internet-shutdown events rather than ASN-scoped BGP-visible outages. These must be filtered to events with affected ASN/network scope and RouteViews reconstructability.
   - Required next step: select only events with precise times, ASN/network identity, and sufficient RouteViews coverage.

## Candidate Sources with Moderate Utility

### MANRS/GRIP

MANRS/GRIP is valuable for Hijack and Leak review, but the MANRS data-source documentation explicitly includes RIPE RIS, RPKI repositories, IRR records, and GRIP BGP-incident detection. That makes it less independent from the feature evidence base than RouteLLM/operator narratives. It is still useful as a secondary source or adjudicator.

### Operator Postmortems and Public Writeups

Operator and measurement-provider writeups are high-quality when they provide exact time intervals and ASN/prefix metadata, but the coverage is sparse and inconsistent. They are best used to supplement RouteLLM/IODA or to adjudicate disputed events rather than to define the entire confirmation set.

### BGPStream / Atlantic Council Incident Data

BGPStream provides excellent routing-evidence access and the Atlantic Council dataset is useful, but labels are close to the same public BGP evidence used in Behavioral features. This is acceptable for a diagnostic sensitivity set, but weaker as a strong independent-label confirmation set.

### GLBAD

GLBAD provides a compact literature-backed list covering Hijack, Leak, and Outage, but the reported count is only 20 events and exact metadata may require manual recovery. It is useful as a literature triangulation source, not as the main confirmation set.

## Sources Not Recommended as Primary Label Sources

- RIPE RIS/RIPEstat raw BGP updates: important evidence source, not an independent label source.
- LACNIC/BGPStream aggregate route-leak data: local artifacts are aggregate-level and lack event-level time/prefix/ASN fields.
- RPKI-only incident reports: useful targeted diagnostics but feature-source dependence is high because RPKI/ROV is one of the model feature families.

## Documentation Sources Consulted

- RouteLLM: https://arxiv.org/abs/2608.22812
- MANRS data sources: https://manrs.org/manrs-observatory/data-sources/
- IODA API: https://api.ioda.inetintel.cc.gatech.edu/v2/
- IODA overview: https://blog.apnic.net/2024/09/11/ioda-internet-outage-detection-and-analysis/
- IODA curated outages: https://github.com/InetIntel/internet_outages
- BGPStream data access: https://bgpstream.caida.org/docs/overview/data-access
- Atlantic Council BGP incident data: https://www.atlanticcouncil.org/resources/bgp-incident-data/
- GLBAD paper: https://www.mdpi.com/2079-9292/14/24/4940
- RIPE RIS raw dataset: https://labs.ripe.net/datarepository/data-sets/routing-information-service-ris-raw-dataset/
- RIPEstat BGP Updates: https://stat.ripe.net/docs/data-api/api-endpoints/bgp-updates
