# Changelog

All notable changes to `@veraanchor/verifier` are documented here.

## [Unreleased]

### Added

- Authenticated Dataset and Ingest verification through caller-authorized Vera Anchor Core acquisition, local recomputation, and independent Hedera Mirror corroboration.
- `AuthProviderV1` and `createStaticBearerAuthProviderV1` for explicit authenticated evidence acquisition.
- Authenticated Dataset and Ingest portable-report and policy workflows.
- Hermetic authenticated integration coverage for authorization failure, Mirror unavailability, Core/Hedera conflicts, local commitment contradictions, and credential isolation.
- Offline, policy, and authenticated Ingest examples, plus an authenticated Dataset example.

### Security

- Authenticated credentials are scoped to the configured Core resolver and are not forwarded to Hedera Mirror, Vera Anchor Explorer, redirects, or evidence-selected URLs.
- Core authorization, service-assisted decryption, and server verification fields are not treated as verification proof.
- Authenticated portable reports exclude authorization credentials and raw decrypted payloads.

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
