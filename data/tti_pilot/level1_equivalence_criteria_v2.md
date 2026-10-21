# Level-1 Equivalence Criteria v2

These tolerances were fixed before computing the final reconstruction comparison.

| Criterion | Tolerance |
|---|---:|
| `predicted_class_agreement_min` | `1.0` |
| `max_abs_probability_difference_max` | `1e-06` |
| `mean_abs_probability_difference_max` | `1e-08` |
| `median_abs_probability_difference_max` | `1e-08` |
| `per_class_probability_correlation_min` | `0.999999999` |
| `incident_macro_f1_abs_difference_max` | `1e-08` |

Primary equivalence evidence is probability-level reproduction against preserved TRAIN OOF fingerprints.
Similar aggregate Macro F1 alone is not sufficient for acceptance.
The reconstruction may serialize models only after one candidate passes these criteria.
