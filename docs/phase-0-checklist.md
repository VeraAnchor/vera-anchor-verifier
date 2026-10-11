# Phase 0 checklist — audit before code extraction

- [ ] 0A. Audit Core producer, Explorer verifier, HF JS and Python SDKs, service boundaries, and actual tests.
- [ ] 0B. Draft versioned VerificationRequest, EvidenceObservation, Finding, Report, Package, and Resolver contracts.
- [ ] 0C. Define assurance dimensions, source dependencies, and non-circular corroboration.
- [ ] 0D. Distinguish evidence time, observation time, verification time, and policy-evaluation time.
- [ ] 0E. Complete threat model and per-threat adversarial tests.
- [ ] 0F. Collect authorized sanitized positive, contradictory, incomplete, and unsupported fixtures.
- [ ] 0G. Verify npm scope control; freeze minimal dependency and export boundaries; enable GitHub hardening.
- [ ] Reconcile producer hashing and Merkle algorithm versions against actual Core implementations.
- [ ] Document differences between source producer behavior and Explorer/HF verification behavior.
- [ ] Demonstrate typecheck, lint/format, tests, build, package dry-run, and CI using a committed lockfile.
- [ ] Approve an audit-derived extraction plan before Phase 1 implementations.

**Exit:** every initial verification claim has a defined authority requirement; first offline
artifact/Merkle paths have real reproducible fixtures; outstanding ambiguities are documented
and resolved; CI is green. This is not the public v1 contract freeze.
