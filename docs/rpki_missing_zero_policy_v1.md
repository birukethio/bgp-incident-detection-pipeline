# RPKI Missing And Zero Policy v1

The pilot distinguishes four cases:

A. A window contains no prefix/origin evidence: evidence counts are zero and ratio features are `NaN`.
B. Evidence exists but all prefixes are `NOT_FOUND`: not-found counts equal evaluable counts; VALID/INVALID counts are zero.
C. Evidence exists and zero INVALID observations occur: invalid counts are zero with positive evaluable denominator.
D. Evidence cannot be evaluated because origin or prefix is malformed/missing: unevaluable counts are positive and excluded from VALID/INVALID/NOT_FOUND denominators.

`observation_count` preserves multiplicity from the compact evidence store. Prefix-unique metrics count unique prefixes and are not observation-weighted.
