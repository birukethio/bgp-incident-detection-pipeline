# Figure 3.1 Title and Caption Options

## Recommended

**Figure 3.1. End-to-End Methodological Pipeline for BGP Incident Classification and Ranking**

Caption: This figure summarizes the final Praxis methodology from incident-label curation through RouteViews MRT acquisition, five-minute BGP window construction, Behavioral/CAIDA/RPKI feature engineering, TRAIN-only model development, K1 incident-level temporal stacking, and final ranked classification of Hijack, Leak, and Outage incidents. The figure also highlights the incident-level leakage controls that separate TRAIN, Validation, and Final Holdout evidence.

Best use: Chapter 3 opening methodology figure.

## Option A

**Figure 3.1. End-to-End Research Pipeline for Leakage-Safe BGP Incident Classification**

Caption: The pipeline treats each incident as the independent experimental unit while five-minute windows serve as lower-level feature observations. All windows inherit the frozen incident partition, preventing cross-partition leakage during model development and evaluation.

Best use: If you want the figure title to emphasize experimental rigor.

## Option B

**Figure 3.1. From RouteViews Observations to Ranked BGP Incident Diagnosis**

Caption: Historical RouteViews UPDATE observations are transformed into five-minute V4 feature windows, enriched with AS-relationship and RPKI/ROV context, and aggregated through the K1 temporal stacking architecture to rank likely incident classes.

Best use: If you want the title to emphasize the data-processing story.

## Option C

**Figure 3.1. Final Praxis Methodology for Hijack, Route Leak, and Outage Classification**

Caption: The final methodology integrates labeled BGP incident evidence, RouteViews-derived behavioral features, CAIDA relationship context, and historical RPKI/ROV validation into a leakage-safe incident-level classification and ranking workflow.

Best use: If you want the title to be concrete and class-specific.
