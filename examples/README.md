# Examples

These examples use the public `@veraanchor/verifier` package API and are intentionally small.

They treat evidence as untrusted input. Dataset or Ingest identity, network selection, expected scope and policy must come from the relying party's trusted context.

From a repository checkout, run `npm ci` and `npm run build` first. The package self-reference resolves the same public entry point that consumers import after installation.

## Offline Dataset verification

```sh
node examples/dataset-offline.mjs \
  bundle.json \
  receipt.json \
  source-file.json \
  verification_demo/source-file.json \
  07be0cf7-4cab-40ca-aa70-87840df4d3e7.example.verification.demo.v1 \
  mainnet
```

The source path argument is the producer-relative path committed by the Dataset, not merely the local filename.

## Fresh policy decision

```sh
node examples/dataset-policy.mjs \
  bundle.json \
  receipt.json \
  source-file.json \
  verification_demo/source-file.json \
  intent.json \
  policy.json
```

The intent and policy files must be supplied independently by the relying party. Do not construct them by copying expectations from the untrusted evidence being verified.

## Authenticated Dataset verification

Authenticated examples require an explicitly configured Vera Anchor Core origin and a caller-provided API key:

```sh
VERA_ANCHOR_CORE_URL=https://example-core.invalid \
VERA_ANCHOR_API_KEY=your-api-key \
node examples/authorized-dataset-policy.mjs \
  bundle.json \
  receipt.json \
  source-file.json \
  verification_demo/source-file.json \
  intent.json \
  policy.json \
  123@0.0.456
```

Do not commit production credentials to the repository. The Core origin, authorization material, verification intent, Hedera network, HCS reference, and policy must come from trusted application configuration.

The authenticated workflow uses Core only for authorized private-evidence acquisition. The SDK independently recomputes supported Dataset checks and independently resolves supported Hedera observations before producing its policy decision.

## Authenticated Ingest verification

The Ingest example accepts JSON or text source material:

```sh
VERA_ANCHOR_CORE_URL=https://example-core.invalid \
VERA_ANCHOR_API_KEY=your-api-key \
node examples/authorized-ingest-policy.mjs \
  bundle.json \
  material.json \
  intent.json \
  policy.json \
  123@0.0.456
```

The example intentionally keeps source handling small. Applications using file or file-set Ingest material should construct the corresponding library input with bounded caller-controlled source paths.

Authentication controls acquisition only. Core authorization, service-assisted decryption, and server verification fields are not accepted as verification proof.
