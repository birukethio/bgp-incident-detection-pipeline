# CAIDA Temporal Mapping Policy v1

For each 5-minute window, select the CAIDA serial-2 AS-relationship snapshot for the observation month when available. This avoids using future relationship information beyond the month-level snapshot cadence available for this dataset. If an exact observation-month snapshot is unavailable in a future full-TRAIN run, use the nearest earlier available snapshot and record the fallback.

| window_month | selected_caida_snapshot | mapping_reason |
| --- | --- | --- |
| 2022-03 | 20220301.as-rel2.txt.bz2 | nearest same-month serial-2 snapshot at or before observation month |
| 2023-08 | 20230801.as-rel2.txt.bz2 | nearest same-month serial-2 snapshot at or before observation month |
| 2024-07 | 20240701.as-rel2.txt.bz2 | nearest same-month serial-2 snapshot at or before observation month |
| 2024-09 | 20240901.as-rel2.txt.bz2 | nearest same-month serial-2 snapshot at or before observation month |
| 2025-03 | 20250301.as-rel2.txt.bz2 | nearest same-month serial-2 snapshot at or before observation month |
| 2025-05 | 20250501.as-rel2.txt.bz2 | nearest same-month serial-2 snapshot at or before observation month |
| 2025-10 | 20251001.as-rel2.txt.bz2 | nearest same-month serial-2 snapshot at or before observation month |
| 2025-11 | 20251101.as-rel2.txt.bz2 | nearest same-month serial-2 snapshot at or before observation month |
| 2025-12 | 20251201.as-rel2.txt.bz2 | nearest same-month serial-2 snapshot at or before observation month |
