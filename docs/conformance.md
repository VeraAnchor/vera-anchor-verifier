# Conformance

The verifier is qualified against deterministic fixtures and live public observations. Conformance exists to demonstrate that the SDK reproduces supported Vera Anchor commitment contracts and preserves the same verification semantics across offline and networked workflows.

## Current v0.1 coverage

Release qualification includes:

- Dataset offline recomputation and mainnet public triangulation;
- Ingest offline recomputation and mainnet public triangulation;
- SAGE execution verification using pinned mainnet evidence;
- independent HCS standards resolution for supported HCS-1, HCS-2, HCS-11, HCS-13, HCS-14 and HCS-26 references;
- HCS-26 manifest and declared-file integrity resolution;
- explicit network-scope and no-fallback behavior;
- Vera Anchor Explorer public-record resolution;
- Hedera Mirror corroboration;
- portable report validation and policy evaluation;
- positive and adversarial cases for supported commitment and resolver boundaries.

Live tests depend on external public services and therefore validate both the verifier and the continued availability of the pinned public evidence. A live service outage is not treated as a successful verification result.

## Fixture requirements

Conformance fixtures must identify the relevant evidence profile/version, source provenance, Hedera network, independently expected subject or digest, required checks and expected outcomes, and whether a test is deterministic/offline or depends on live public services.

Fixtures must not contain production credentials, private tenant evidence or other confidential material. Missing fixture data must never be replaced with fabricated successful observations.

## Reproducibility

Offline fixtures are expected to produce deterministic results from the same bytes and caller-supplied intent. Networked conformance uses exact references and explicit network selection; it must not silently substitute a different Hedera network, latest registry state or unrelated public record.

The repository test suite is part of release qualification:

```sh
npm test
```

A release also requires the package build and external-consumer checks described in the repository release process.
