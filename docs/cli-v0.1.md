# Vera Anchor Verifier CLI (v0.1)

The `vera-anchor` executable is installed with `@veraanchor/verifier`.

After installing the package, run commands with `npx vera-anchor`. Contributors working from a source checkout may build the package with `npm run build` and invoke `node dist/cli.js` directly.

Dataset verification defaults to **offline**. Public verification is always explicit. Ingest and SAGE execution support both offline and public workflows, while independent SAGE HCS standards verification is a separate networked workflow.

## Commands

```text
npx vera-anchor verify dataset --bundle BUNDLE.json --sources SOURCES.json --source-root DIRECTORY --intent INTENT.json --policy POLICY.json [--receipt RECEIPT.json] [--mode offline] [--report-out REPORT.json]

npx vera-anchor verify dataset --mode public --explorer-url https://explorer.veraanchor.com --bundle BUNDLE.json --sources SOURCES.json --source-root DIRECTORY --intent INTENT.json --policy PUBLIC_POLICY.json [--receipt RECEIPT.json] [--mirror-url https://mainnet-public.mirrornode.hedera.com/api/v1] [--report-out REPORT.json]

npx vera-anchor verify ingest --bundle BUNDLE.json --material MATERIAL.json --intent INTENT.json --policy POLICY.json [--receipt RECEIPT.json] [--source-root DIRECTORY] [--mode offline] [--report-out REPORT.json]

npx vera-anchor verify ingest --mode public --explorer-url https://explorer.veraanchor.com --anchor-request-id CORE_ANCHOR_UUID --bundle BUNDLE.json --material MATERIAL.json --intent INTENT.json --policy PUBLIC_POLICY.json [--receipt RECEIPT.json] [--source-root DIRECTORY] [--mirror-url https://mainnet-public.mirrornode.hedera.com/api/v1] [--report-out REPORT.json]

npx vera-anchor verify execution --evidence EVIDENCE.json --intent INTENT.json --policy POLICY.json [--verification-material MATERIAL.json] [--mode offline] [--report-out REPORT.json]

npx vera-anchor verify execution --mode public --explorer-url https://explorer.veraanchor.com --evidence EVIDENCE.json --intent INTENT.json --policy PUBLIC_POLICY.json [--verification-material MATERIAL.json] [--mirror-url https://mainnet-public.mirrornode.hedera.com/api/v1] [--report-out REPORT.json]

npx vera-anchor verify standards --evidence SAGE_EVIDENCE.json --intent INTENT.json --policy STANDARDS_POLICY.json [--verification-material MATERIAL.json] [--mirror-url https://mainnet-public.mirrornode.hedera.com/api/v1] [--report-out REPORT.json]

npx vera-anchor report validate --report SAVED_REPORT.json

npx vera-anchor policy assess --report SAVED_REPORT.json --policy POLICY.json
```

## Verification intent and policy

`INTENT.json` contains caller-controlled verification intent. Subject identifiers, network selection and expected commitments must come from the relying party's trusted context rather than being copied from the evidence being verified.

`POLICY.json` uses the `va.verification-policy.v1` contract. Policy requirements determine which checks and assurance are required for an `allow`, `review` or `deny` decision.

An untrusted receipt, bundle, execution record or standards projection cannot define its own sufficient acceptance threshold.

## Portable reports

All four `verify` commands accept `--report-out REPORT.json`.

The output file contains only the native `va.portable-verification-report.v1` report. The CLI still writes its normal result envelope to stdout and preserves the policy exit code.

The destination must be a new file in an existing writable directory. Report export uses a temporary sibling file and exclusive final creation so an existing output is not overwritten. Protect exported reports according to the sensitivity of their metadata.

`report validate` checks report structure and internal digests. It does **not** authenticate the report or recompute the original evidence.

`policy assess` treats a saved report as unauthenticated and therefore does not promote it into a fresh SDK-authorized `allow`. When a relying party needs a decision over the underlying evidence, rerun the corresponding verification workflow with independently supplied intent and policy.

## Dataset verification

### Offline Dataset verification

Offline Dataset verification recomputes supported source, bundle and receipt relationships without resolver network requests.

The Dataset source manifest supplied with `--sources` contains producer-relative paths. Those paths must correspond to the paths committed by the Dataset bundle; they are not inferred from local filesystem names.

Example policy:

```json
{
  "schema_version": "va.verification-policy.v1",
  "subject": { "kind": "dataset", "id": "07be0cf7-4cab-40ca-aa70-87840df4d3e7.example.verification.demo.v1" },
  "report_kind": "verification",
  "required_checks": [
    "dataset.source_binding",
    "dataset.bundle_consistency"
  ],
  "on_unresolved": "review"
}
```

### Public Dataset verification

Public Dataset verification requires an independently selected Hedera network in both intent and policy. The policy must use `report_kind: "public_triangulation"`.

Example:

```json
{
  "schema_version": "va.verification-policy.v1",
  "subject": {
    "kind": "dataset",
    "id": "07be0cf7-4cab-40ca-aa70-87840df4d3e7.example.verification.demo.v1",
    "hedera_network": "mainnet"
  },
  "report_kind": "public_triangulation",
  "required_checks": [
    "dataset.source_binding",
    "dataset.bundle_consistency",
    "triangulation.public_record_hedera.message_sha3_512"
  ],
  "required_assurance": ["mirror_corroboration"],
  "on_unresolved": "review"
}
```

The public workflow recomputes local evidence, resolves the selected Vera Anchor Explorer publication record and independently queries Hedera Mirror for supported ledger observations.

A consistent ciphertext digest is not proof of independently authenticated decrypted plaintext, Hedera consensus signatures or publisher ownership.

## Ingest verification

`verify ingest` accepts one bounded `--material MATERIAL.json` descriptor. The descriptor represents original material supplied for recomputation, not an authenticated claim about its fingerprint.

Supported forms include:

```json
{"kind":"json","value":{"measurement":42}}
```

```json
{"kind":"text","text":"sample text","media_type":"text/plain"}
```

```json
{"kind":"file","path_rel":"measurement.csv"}
```

```json
{"kind":"file_set","paths":["sample.csv","subdir/notes.txt"]}
```

For `file` and `file_set`, provide `--source-root DIRECTORY`. Paths must remain under the selected root and may not traverse symlinks.

Public Ingest verification additionally requires an independently selected `--anchor-request-id` for the Core Merkle anchor request. This identifier is distinct from the ingest object key, a Dataset identifier and tenant-side Hash Factory anchors.

Example public policy:

```json
{
  "schema_version": "va.verification-policy.v1",
  "subject": {
    "kind": "ingest",
    "id": "hf.first-ingest.demo",
    "hedera_network": "mainnet"
  },
  "report_kind": "public_triangulation",
  "required_checks": [
    "ingest.source_binding",
    "ingest.bundle_consistency",
    "triangulation.public_record_hedera.message_sha3_512"
  ],
  "required_assurance": ["mirror_corroboration"],
  "on_unresolved": "review"
}
```

## SAGE execution verification

Offline execution verification uses `subject.kind: "execution"`, the exact job UUID and `report_kind: "execution"`.

The policy's `execution_scope` supplies the independently expected profile, program and optional exact result UUID. The verifier does not silently select a latest result.

Example public execution policy:

```json
{
  "schema_version": "va.verification-policy.v1",
  "subject": {
    "kind": "execution",
    "id": "4e4f624d-25b6-577f-93c6-075292e722d6",
    "hedera_network": "mainnet"
  },
  "report_kind": "execution_triangulation",
  "required_checks": ["binding.digest_recomputed"],
  "required_assurance": ["mirror_corroboration"],
  "execution_scope": {
    "profile": "sage-standards-v1",
    "expected_program": "sage",
    "requested_result_id": null
  },
  "on_unresolved": "review"
}
```

Public execution triangulation covers its supported Explorer/Hedera relationships. It does not implicitly complete independent HCS standards verification.

## Independent SAGE HCS standards verification

`verify standards` is networked and uses Hedera Mirror only. It does not use Explorer and does not accept `--mode` or `--explorer-url`.

The workflow resolves supported exact historical HCS references for the independently selected network. v0.1 supports HCS-1, HCS-2, HCS-11, HCS-13, HCS-14 and HCS-26 verification through the SDK's pinned contracts.

Example policy:

```json
{
  "schema_version": "va.verification-policy.v1",
  "subject": {
    "kind": "execution",
    "id": "4e4f624d-25b6-577f-93c6-075292e722d6",
    "hedera_network": "mainnet"
  },
  "report_kind": "independent_standards",
  "required_checks": [
    "binding.digest_recomputed",
    "standards.references_resolved"
  ],
  "required_assurance": ["mirror_corroboration"],
  "execution_scope": {
    "profile": "sage-standards-v1",
    "expected_program": "sage",
    "requested_result_id": null
  },
  "on_unresolved": "review"
}
```

HCS-26 resolution verifies the selected historical discovery/version path, canonical skill manifest and integrity of manifest-declared HCS-1 files within the SDK's resource bounds.

Standards resolution does not authenticate Hedera consensus signatures, DID-controller ownership, historical account ownership or publisher-key control, and it does not prove that referenced software executed.

HCS-1 Zstandard decoding uses Node's built-in `zstdDecompressSync`. Use Node 24 or Node 22.15+ for the full standards workflow. Older runtimes are outside the v0.1 supported engine range.

## Resolver configuration

`--explorer-url` is required only for public Explorer workflows. `--mirror-url` is optional; when omitted, the SDK uses its network-specific Hedera Mirror default.

Resolver origins are caller-controlled configuration and are never taken from evidence or publication contents. Supported resolvers reject redirects, bound response sizes and timeouts, and do not silently probe another Hedera network.

HTTPS is required except for HTTP loopback development endpoints.

## CLI result and exit codes

The CLI writes one JSON object to stdout using `schema_version: "va.verifier-cli-result.v1"`. Successful command execution returns either `{command,result}` or `{error:{code}}` according to the CLI contract. Raw source bytes and credentials are not included in the result envelope.

Exit codes:

- `0` — `allow`, or a valid saved report for `report validate`.
- `1` — `deny`, or an invalid saved report.
- `2` — `review`.
- `64` — malformed command or input.
- `70` — operational failure.

No CLI mode asserts Hedera consensus-signature authentication, DID-controller ownership or independent cryptographic binding of Explorer-assisted decrypted publication plaintext to its ciphertext.