# Security Policy

## Supported versions

Security fixes are provided for the latest published release line of `@vera-anchor/verifier`. Users should upgrade to the latest available patch release before reporting a security issue that may already have been corrected.

Pre-release branches, unpublished commits and local development builds are not supported release artifacts.

## Reporting a vulnerability

Do not open a public issue containing exploit details, credentials, private evidence, customer data or an undisclosed vulnerability.

Use GitHub private vulnerability reporting for this repository when available. If private reporting is unavailable, contact Vera Anchor through an established, verified organizational channel and provide only the minimum information needed to establish a private reporting path.

Public GitHub issues are appropriate for non-sensitive defects, documentation problems and feature requests that do not disclose security-sensitive information.

## Security scope

The verifier processes untrusted evidence and, in explicitly selected public workflows, untrusted network responses. Security reports involving parser boundaries, resource exhaustion, path handling, resolver origin controls, redirect handling, network-scope enforcement, commitment verification, policy bypass or incorrect verification outcomes are in scope.

A successful integrity or Mirror-corroboration result is not a claim of factual truth, publisher ownership, DID-controller authentication or Hedera consensus-signature authentication. See [docs/verification-semantics.md](docs/verification-semantics.md) for the supported assurance model.
