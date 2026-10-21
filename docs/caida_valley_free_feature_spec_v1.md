# CAIDA Valley-Free Feature Specification v1

AS paths are cleaned by extracting ASNs and collapsing consecutive prepends before relationship evaluation. Adjacent AS pairs are mapped to CAIDA relationships: `c2p`, `p2p`, `p2c`, `s2s`, or `unknown`.

A valid known valley-free path follows: zero or more `c2p` uphill transitions, then zero or one `p2p` peer transition, then zero or more `p2c` downhill transitions. `s2s` transitions are neutral and may appear anywhere. A `c2p` or `p2p` transition after the path has entered peer/downhill phase is a violation; an additional `p2p` after the optional peer transition is also a violation. `unknown` relationships are counted explicitly and prevent the path from being counted as either valid or violating.

AS_SET/confederation artifacts are reduced to numeric ASNs by the current bgpdump-derived AS_PATH parser; this pilot records the limitation and keeps the rule deterministic.
