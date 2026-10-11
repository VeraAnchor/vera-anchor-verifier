# Conformance plan

Phase 0 will collect sanitized **real** positive and negative vectors from the Core producer,
Explorer and HF SDKs: SHA3-512 artifact bytes, Merkle proof siblings and roots, Dataset and
Ingest publications, and one SAGE execution with actual binding, acceptance, and results.

Fixture manifests must describe: exact evidence profile/version, supported algorithm,
source provenance/commit, network, expected subject and digest, required checks and expected
outcomes, offline vs online requirements, and whether any observation is service-assisted.

Missing fixture material must never be filled in with fabricated successful observations.
The public fixture directory will contain no production secrets or private tenant data.
