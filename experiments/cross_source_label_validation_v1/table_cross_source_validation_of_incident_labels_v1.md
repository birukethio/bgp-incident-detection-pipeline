| metric                                          | class   |        value | notes                                                                                      |
|:------------------------------------------------|:--------|-------------:|:-------------------------------------------------------------------------------------------|
| original_incidents_searched                     | ALL     | 1419         | Frozen roster v2 incident count.                                                           |
| independently_corroborated_incidents            | ALL     |   59         | Unique Cloudflare incidents with accepted same-event non-Cloudflare source-native label.   |
| corroboration_rate                              | ALL     |    0.0415786 | Corroborated / searched.                                                                   |
| overall_exact_label_agreement                   | ALL     |    1         | Agreement among accepted corroborated incidents only.                                      |
| cohens_kappa                                    | ALL     |    1         | Cloudflare label versus deterministic independent-source mapped label.                     |
| multi_non_cloudflare_source_supported_incidents | ALL     |    2         | Counts accepted incidents whose source packet records more than one non-Cloudflare source. |