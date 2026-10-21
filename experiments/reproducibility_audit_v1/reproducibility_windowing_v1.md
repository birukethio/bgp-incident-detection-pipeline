# Five Minute Windowing Reproducibility v1

## Analytical Unit

The model input unit is a five-minute incident-relevant BGP window. The independent experimental unit remains the incident; all windows inherit their incident partition and label.

## Window Construction

RouteViews UPDATE observations are assigned to UTC five-minute windows using BGP timestamps. Hijack and Leak active windows are derived from detector-supported observations; Outage intervals use documented Cloudflare outage start and end intervals. Silent gaps are not automatically treated as Normal.

## Row Counts

The frozen TRAIN V4 corpus contains 68,031 rows. The Final Holdout V4 corpus contains 14,906 rows. The final Holdout evaluation remains terminal and immutable.

## TTI Boundary

The retrospective early-classification/TTI work is a separate post-hoc analysis and does not replace the primary five-minute Level-1 plus Level-2 temporal stacking architecture.
