# Vera Anchor Verifier SDK

`@veraanchor/verifier` is an open-source, read-only verifier for Vera Anchor evidence and supported HCS-backed execution references.

The SDK is local-first. Offline workflows recompute commitments from caller-supplied evidence and source material without Vera Anchor credentials. Explicit public workflows can resolve Vera Anchor Explorer records and independently corroborate supported Hedera observations using caller-selected network configuration.

The verifier is designed for relying parties that need deterministic verification results they can evaluate under their own acceptance policy.

## What it verifies

The current surface includes:

- Dataset and Ingest bundle, receipt, source-binding, and commitment recomputation.
- Public Dataset and Ingest triangulation across local evidence, Vera Anchor Explorer publication records, and Hedera Mirror observations.
- Authenticated Dataset and Ingest verification through caller-authorized Vera Anchor Core acquisition, local recomputation, and independent Hedera Mirror corroboration.
- SAGE execution verification with independently supplied execution scope and expected program and result constraints.
- Pinned HCS-1, HCS-2, HCS-11, HCS-13, HCS-14, and HCS-26 verification.
- HCS-26 historical discovery and version resolution, canonical manifest verification, and integrity verification of manifest-declared HCS-1 files.
- Canonical portable verification reports with deterministic report digests.
- Explicit relying-party policies that convert verification findings into `allow`, `review`, or `deny` decisions.

## Assurance boundaries

Verification results are intentionally scoped.

A successful integrity check does not establish factual truth, publisher ownership, or code execution. Hedera Mirror observations provide independent corroboration of supported ledger data; they are not authenticated Hedera consensus proofs.

The SDK does not claim DID-controller authentication, historical account ownership, consensus-signature authentication, or independent cryptographic proof that service-assisted decrypted plaintext originated from a particular publication ciphertext.

Caller-controlled intent is part of the trust boundary. Subject identifiers, expected commitments, Hedera network selection, execution scope, and policy requirements must come from the relying party's trusted context rather than being copied from untrusted evidence.

See [Verification semantics](docs/verification-semantics.md) and the [Threat model](docs/threat-model.md) for the precise distinctions used by the SDK.

## Installation

```sh
npm install @veraanchor/verifier
```

The package is ESM-only and has no runtime dependencies.

Node.js 24 is recommended for the full feature set. The supported runtime range is defined by the package metadata.

## Library quickstart

Verification primitives are available from the package root:

```js
import { verifyDatasetV1Bundle } from "@veraanchor/verifier";

const result = verifyDatasetV1Bundle(bundle);

if (!result.ok) {
  console.error(result.mismatches);
}
```

Higher-level APIs add independently supplied verification intent, public resolution, HCS standards verification, portable reporting, and policy evaluation.

Public workflows perform network I/O only when explicitly selected.

## CLI quickstart

The package also exposes the `vera-anchor` CLI.

After installing the package:

```sh
npm exec -- vera-anchor --help
```

Offline Dataset verification from original local source bytes:

```sh
npm exec -- vera-anchor verify dataset \
  --bundle bundle.json \
  --sources sources.json \
  --source-root ./source-files \
  --intent intent.json \
  --policy policy.json
```

Explicit public verification of a Dataset publication and Hedera Mirror evidence:

```sh
npm exec -- vera-anchor verify dataset \
  --mode public \
  --explorer-url https://explorer.veraanchor.com \
  --bundle bundle.json \
  --sources sources.json \
  --source-root ./source-files \
  --intent public-intent.json \
  --policy public-policy.json
```

Offline SAGE execution verification:

```sh
npm exec -- vera-anchor verify execution \
  --evidence execution.json \
  --intent intent.json \
  --policy policy.json
```

Independent HCS standards verification:

```sh
npm exec -- vera-anchor verify standards \
  --evidence execution.json \
  --intent intent.json \
  --policy standards-policy.json
```

Portable report validation and policy assessment:

```sh
npm exec -- vera-anchor report validate \
  --report report.json

npm exec -- vera-anchor policy assess \
  --report report.json \
  --policy policy.json
```

The CLI also supports Ingest verification and explicit public execution verification.

See the [CLI reference](docs/cli.md) for command options, JSON inputs, policy examples, and exit codes.

## Verification model

The SDK keeps evidence findings, cross-source consistency, and application decisions separate:

```text
source and evidence recomputation
            |
            v
public record and HCS resolution when requested
            |
            v
independent Mirror corroboration where supported
            |
            v
verification findings and observations
            |
            v
portable verification report
            |
            v
caller-supplied policy
            |
            v
allow / review / deny
```

Missing evidence and service outages do not become successful checks. Demonstrated contradictions fail. Unsupported operations remain explicit.

The verifier never silently changes Hedera networks or selects a latest execution result when an exact result is required.

## Offline, public, and authenticated verification

Offline verification performs no resolver network requests. It operates only on caller-supplied evidence, source material, verification intent, and policy.

Public workflows are explicit. Resolver origins are controlled by the caller rather than by untrusted evidence. Supported resolvers use bounded requests, reject redirects, and do not silently fall back to another Hedera network.

Vera Anchor Explorer publication resolution and Hedera Mirror corroboration are distinct observations. An original HCS anchor is not interpreted as a public publication receipt.

Authenticated workflows are also explicit. They use caller-supplied authorization to acquire permitted private evidence through Vera Anchor Core while keeping authentication outside the deterministic verification kernel.

Core remains authoritative for access control and service-assisted private-evidence recovery. The verifier independently recomputes supported Dataset or Ingest checks and, where required, separately corroborates the referenced HCS message through Hedera Mirror.

Credentials are scoped to the configured Core resolver and are not forwarded to Mirror, Explorer, or evidence-selected URLs. Credentials and raw decrypted payloads are excluded from portable reports.

See [Authenticated verification](docs/authenticated-verification.md) for the supported library workflow and security boundaries.

## HCS standards verification

The standards surface supports pinned verification behavior for:

- HCS-1 content integrity and bounded file reconstruction.
- HCS-2 historical registry entries.
- HCS-11 AI-agent profile integrity and supported reference relationships.
- HCS-13 schema registration and canonical schema integrity.
- HCS-14 DID-backed UAID structural binding.
- HCS-26 historical discovery and version registration, canonical skill manifests, and manifest-declared HCS-1 file integrity.

Standards registration establishes only the supported properties of the observed records. It does not establish that associated software executed, that a publisher currently controls a key, or that the underlying claims are factually true.

## SAGE execution verification

The execution verification surface supports deterministic verification of supported SAGE evidence using independently supplied intent.

Public execution workflows can additionally resolve the selected execution record through Vera Anchor Explorer and corroborate supported Hedera observations.

Independent standards verification resolves supported HCS references separately from Explorer-based public execution triangulation. Successful public triangulation does not implicitly complete HCS standards verification, and successful HCS standards resolution does not independently prove that the referenced software executed.

## Portable reports

The SDK can produce `va.portable-verification-report.v1` reports containing deterministic, digest-bound verification results and supported context.

Validating a saved report checks its structure and internal digests. It does not recompute the original evidence or authenticate the report's origin.

Accordingly, a saved report cannot promote itself into a fresh SDK-computed `allow` decision. Decisions requiring verification of the underlying evidence should be produced by rerunning the appropriate workflow with independently supplied intent and policy.

## Policy decisions

Policy evaluation keeps application acceptance separate from verification mechanics:

- `allow` means the requirements selected by the relying party were satisfied.
- `deny` means a required condition was contradicted or the policy requires denial.
- `review` means the evidence remains unresolved under a policy that delegates unresolved cases for review.

Verification intent and policy must be supplied independently by the relying party. Untrusted evidence cannot define its own sufficient acceptance threshold.

The current public assurance dimension is `mirror_corroboration`. It must not be interpreted as consensus-signature, account-control, publisher-key, or DID-controller authentication.

## Conformance

The verifier is exercised against deterministic fixtures and live public observations covering supported Dataset, Ingest, SAGE execution, HCS standards, Explorer, Hedera Mirror, network-scope, portable-report, and policy workflows.

Live conformance depends on external public services. Service unavailability is not converted into successful verification.

See [Conformance](docs/conformance.md) for the current coverage and reproducibility requirements.

## Documentation

- [CLI reference](docs/cli-v0.1.md)
- [Authenticated verification](docs/authenticated-verification.md)
- [Verification semantics](docs/verification-semantics.md)
- [Threat model](docs/threat-model.md)
- [Conformance](docs/conformance.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

## Development

Install the locked development dependencies:

```sh
npm ci
```

Run the repository qualification checks:

```sh
npm run check
npm run typecheck
npm test
npm run build
npm pack --dry-run --json
```

`npm run format` modifies files and is intended for local formatting work.

Release qualification additionally includes package-content inspection, clean external-consumer installation, CLI and library smoke tests, and live conformance checks.

## Security

Treat all evidence, resolver responses, source material, and references as hostile input.

Do not include credentials, private tenant evidence, customer data, or undisclosed vulnerabilities in public issues.

See [SECURITY.md](SECURITY.md) for vulnerability reporting guidance.

## Contributing

Changes to public schemas, commitment algorithms, verification semantics, reason codes, resolver trust boundaries, or policy behavior require careful review because downstream applications may rely on their deterministic meaning.

See [CONTRIBUTING.md](CONTRIBUTING.md) for development and contribution requirements.

## License

Licensed under the MIT License.

See [LICENSE](LICENSE) and [NOTICE](NOTICE).
