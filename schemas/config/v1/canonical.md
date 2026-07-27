# config/v1 Canonical Identity

Captured source bytes retain their exact SHA-256 identities. The source reader
does not rewrite rich KDL and there is no canonical source encoder.

Evaluation produces a canonical typed document. Its binary preimage begins with
`malm-canonical-typed-document\0`, followed by the fixed IR version, tagged root
value, sorted captured source identities and digests, ordered include/module
edge provenance, and path-sorted value provenance. Counts and byte strings use
big-endian 64-bit lengths. Integers and finite float bits use big-endian 64-bit
values; signed zero is normalized. Lists and composition edges preserve
semantic order, while records and keyed collections use canonical key order.

`canonical_typed_document_digest_v1` is SHA-256 over that complete bounded
preimage. Transform request and response identities are separately domain
separated as specified in [transform.md](transform.md). The golden fixtures in
`fixtures/golden/` pin the typed document and built-in transform results.
