# Frozen Prospective External Level-1 Validation Protocol v1

**Frozen UTC:** 2026-09-18T21:36:20Z  
**Repository HEAD:** `b3974dfcfad28cb1ccc9132414761fcda502d724`

## Scope

**Prospective source-separated external validation of the frozen reproducibly preserved Level-1 BGP incident-classification path.**

This prospective extension evaluates external generalization of the reproducibly preserved Level-1 classification path with frozen mean incident aggregation. It does not externally validate the historical retrospective Level-2 temporal stacker.

The original 1,419-incident Praxis corpus, Validation partition, Final Holdout, models, and reported results remain immutable and outside this extension.

## Frozen path

`RouteViews route-views2 reconstruction -> frozen five-minute windows -> 44 Behavioral + 14 historical CAIDA + 16 historical RPKI/ROV features -> preserved five-model Level-1 XGBoost ensemble -> arithmetic mean incident aggregation`

The reconstruction, feature-generation, historical-enrichment, frozen Level-1 inference, and mean incident-aggregation procedures were frozen before selection of the final prospective external-validation cohort.

## Eligibility

### Source and label

The primary/deciding label source must be non-Cloudflare and human-readable. Priority is: primary operator report; official organization statement; RIPE NCC/RIPE Labs; Internet Society/Pulse/MANRS; Kentik; Qrator; recognized routing-security organization; peer-reviewed paper; established research dataset; NANOG-equivalent operator material. Search summaries and LLM output are not ground truth.

Deterministic mappings:

- **HIJACK:** explicit BGP/prefix hijack, unauthorized or forged origin, or documented more-specific hijack.
- **LEAK:** explicit route leak, unintended export/transit, or propagation outside intended routing-policy scope.
- **OUTAGE:** explicit routing/connectivity outage, routing-related reachability loss, shutdown/disconnection, or externally observable reachability loss tied to the event.
- Mixed or unclear cases are `LABEL_AMBIGUOUS`.

### Historical-enrichment eligibility

Historical-enrichment eligibility. A candidate external incident is eligible for the final external-validation cohort only if the frozen pipeline can reproduce all three required evidence families using historically appropriate inputs consistent with the original methodology: Behavioral BGP evidence, CAIDA serial-2 AS-relationship context, and historical RPKI/ROV context. Archive availability is assessed before model inference and without reference to model predictions. If a required historical enrichment artifact is unavailable, the candidate is recorded as ARCHIVAL_COVERAGE_INELIGIBLE or REVIEW and is not made eligible through later-snapshot substitution, zero filling, inferred enrichment, or any prediction-dependent workaround.

Because exact historical enrichment is required, the prospective external-validation population is limited to incidents for which the frozen historical CAIDA and RPKI/ROV inputs remain reproducibly available. This is an archival data-availability boundary and may reduce representation of older incidents. It must not be interpreted as model failure.

## Frozen reconstruction rules

- Collector: `route-views2` only.
- Context: 60 minutes before and after each frozen active segment.
- Active segments: Outage uses documented start/end; Hijack/Leak spans at most 60 minutes remain one segment; longer spans use the first and last five-minute boundary segments, leaving the silent interior unknown.
- Retrieval: standard RouteViews filename generation; when standard URLs are absent, the official directory index may resolve actual nonaligned filenames overlapping the unchanged interval.
- Parsing: `bgpdump -q -m`; BGP timestamps determine five-minute membership.
- Relevance: exact affected prefix, affected/primary/leak ASN in peer/origin/AS_PATH, or complete leak-segment presence in AS_PATH.
- Features: exact frozen 44 Behavioral, 14 CAIDA serial-2, and 16 historical RPKI/ROV definitions.
- Schema: exactly 74 names/order/dtypes with schema SHA-256 `38ca70a2aa50a39172f2a90d1c893fdd08dfa38a49b3e5945b19d9cab2a202f3`.
- Missing values: frozen NaN behavior and native XGBoost missing-value handling; no new imputation.
- Inference: arithmetic mean class probabilities from the five preserved Level-1 fold models.
- Incident aggregation: arithmetic mean class probability across all eligible reconstructed five-minute windows.

## Pilot engineering corrections

Pilot engineering corrections were limited to retrieval-layer compatibility and did not alter incident labels, event intervals, relevance predicates, analytical windows, feature definitions, enrichment rules, model parameters, aggregation rules, or prediction-based eligibility.

- `PILOT-FIX-001`: generic successful-download status normalization.
- `PILOT-FIX-002`: generic official-directory index fallback for legacy nonaligned RouteViews filenames; observations remain assigned by BGP timestamp.

## Fixed dispositions

`ACCEPTED`, `TIMESTAMP_REVIEW`, `LABEL_AMBIGUOUS`, `SOURCE_INSUFFICIENT`, `ORIGINAL_CORPUS_OVERLAP`, `PILOT_EXCLUDED`, `ARCHIVAL_COVERAGE_INELIGIBLE`, `RECONSTRUCTION_FAILED`, `SCHEMA_MISMATCH`, `INFERENCE_FAILED`.

No new scientific disposition may be created after model predictions are viewed.

## Reporting denominators

- **Source-screening yield:** accepted external incidents / candidate incidents reviewed.
- **Exact reconstruction yield:** incidents achieving exact 74-feature V4 reconstruction / accepted locked incidents.
- **Inference yield:** incidents reaching frozen Level-1 inference / accepted locked incidents.

Classification metrics apply only to incidents reaching inference; every failure remains visible.

## Post-freeze change prohibition

After protocol freeze, the reconstruction or inference pipeline may not be scientifically modified for a specific final-cohort incident. No feature rule, relevance predicate, historical-snapshot rule, observation interval, label mapping, or model behavior may be altered after the final cohort is locked. Unexpected failures remain reported failures.

Pure infrastructure recovery is permitted only when it is generic, does not change the scientific mapping, is documented separately, and is applied consistently to every applicable incident.

## Cohort construction boundary

No pilot incident or original-corpus incident is eligible. Membership depends only on source independence, label clarity, timestamp adequacy, overlap checks, historical archive availability, and reconstruction eligibility. Model output, feature values, predicted class, confidence, probability, and score margin are prohibited from cohort selection.
