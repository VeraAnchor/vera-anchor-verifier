# Changelog

All notable changes to `@veraanchor/verifier` are documented here.

## [0.1.0] - 2026-11-03

Initial public release.

### Added

- Deterministic Dataset and Ingest verification, including source, bundle and receipt checks.
- Explicit public triangulation through Vera Anchor Explorer and Hedera Mirror observations.
- SAGE execution verification with caller-controlled execution scope.
- Pinned HCS-1, HCS-2, HCS-11, HCS-13, HCS-14 and HCS-26 verification.
- HCS-26 canonical manifest verification and integrity verification of manifest-declared HCS-1 files.
- Canonical portable verification reports and deterministic report validation.
- Relying-party policy evaluation with `allow`, `review` and `deny` decisions.
- `vera-anchor` CLI for offline, public, standards, report and policy workflows.

### Assurance boundary

The v0.1 release provides deterministic integrity verification and supported Mirror corroboration. It does not claim Hedera consensus-signature authentication, DID-controller or publisher-key authentication, historical account ownership, factual truth, or independent cryptographic binding of Explorer-assisted decrypted plaintext to publication ciphertext.
