# RPKI/ROV Validation Specification v1

Each compact evidence row is validated using `prefix + origin_asn + observation date` against the selected historical VRP set.

- `VALID`: at least one covering VRP has the same origin ASN and the observed prefix length is less than or equal to the VRP `maxLength`.
- `INVALID_ORIGIN`: one or more covering VRPs exist, but none authorize the observed origin ASN.
- `INVALID_LENGTH`: a covering VRP authorizes the observed origin ASN, but the observed prefix is more specific than the permitted `maxLength`.
- `NOT_FOUND`: no covering VRP exists for the observed prefix.
- `UNEVALUABLE`: prefix or origin ASN is missing, malformed, AS_SET-like, or otherwise unparseable. Private/reserved origins are not silently rewritten; if they are syntactically parseable, they are evaluated against the historical VRP state and their outcome remains auditable.

IPv4 and IPv6 are evaluated separately. Multiple covering VRPs are handled permissively: any valid authorization makes the observation VALID. NOT_FOUND is never treated as VALID.
