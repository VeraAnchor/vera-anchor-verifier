# Verification semantics — design baseline

Each supported check has one of five normalized outcomes: `pass`, `fail`, `indeterminate`,
`unsupported`, `skipped`. `fail` requires a demonstrated contradiction or violated explicit
requirement. Missing evidence, service outages, and missing decryption material are not contradictions.

Triangulation relationship states are separately `consistent`, `conflict`, and `incomplete`.
Policy decisions (`allow`, `deny`, `review`) are separate from evidence findings.

Verification intent MUST be caller-controlled (including relevant network and subject identity).
An untrusted receipt cannot define its own sufficient acceptance threshold.

Assurance dimensions include artifact integrity, subject binding, ledger corroboration,
ledger authentication, identity/execution provenance, recoverability, and policy acceptance.
A SHA3-512 match does not prove ledger authentication or factual truth. HCS standards registration
is a declaration, not evidence that code actually executed.

Only invariant terminology is documented here; exact schemas, digest encodings, and check IDs
remain pending the source audit.
