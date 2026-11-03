# Examples

These examples use the public `@vera-anchor/verifier` package API and are intentionally small.

They treat evidence as untrusted input. Dataset identity, network selection, expected scope and policy must come from the relying party's trusted context.

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
