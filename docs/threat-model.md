# Threat model

The verifier treats supplied bytes, JSON documents, source paths, evidence references and network responses as hostile input. Its purpose is to establish bounded verification claims without allowing untrusted evidence to define the relying party's trust policy.

## Security boundaries

| Threat | v0.1 boundary |
| --- | --- |
| Replayed evidence bound to the wrong subject | Verification intent is independently supplied and subject/commitment mismatches fail. |
| Cross-network substitution | Hedera network selection is explicit and checked; resolvers do not silently fall back to another network. |
| Fabricated corroboration | Observations retain source/resolver identity and triangulation compares independently acquired facts rather than accepting producer summaries as proof. |
| Resolver redirection or arbitrary evidence URLs | Public resolver origins are caller-controlled configuration. Supported resolvers reject redirects and do not obtain resolver authority from evidence. |
| Oversized or adversarial inputs | Parsers, JSON structures, source sets, proof paths, HCS chunks, decompression and network responses are bounded at implementation-specific limits. |
| Stale or substituted registry state | Standards workflows use exact historical locators where required and do not silently select a latest entry. |
| Ledger-assurance overclaim | Hedera Mirror observations are reported as corroboration, not consensus-signature authentication. |
| Saved-report overclaim | Portable report validation checks structure and digests; a saved report does not authenticate itself or independently authorize `allow`. |
| Local path traversal or symlink substitution | CLI source workflows validate relative paths and constrain reads to the selected source root. |
| Leakage of private evidence | Offline workflows do not perform network requests; public network access is explicit. Reports and CLI output exclude raw source bytes and credentials. |
| Dependency compromise | The package has no runtime dependencies; development and release installs are lockfile-driven and validated in CI/release qualification. |

## Trust assumptions

The relying party is responsible for independently selecting verification intent, expected subject identifiers, Hedera network, resolver origins and acceptance policy. Values copied from untrusted evidence do not become trustworthy merely because they are supplied to the verifier as expectations.

Vera Anchor Explorer and Hedera Mirror are distinct observation sources. A successful Explorer or Mirror lookup establishes only the claim represented by that resolver's documented result. Mirror REST data is not an authenticated Hedera consensus proof.

## Out of scope for v0.1

The verifier does not establish:

- factual truth or quality of the underlying content;
- DID-controller ownership or publisher control solely from a DID/UAID declaration;
- authenticated Hedera consensus signatures from Mirror REST responses;
- historical account ownership beyond the exact evidence the supported standards expose;
- independent cryptographic binding of Explorer-assisted decrypted plaintext to publication ciphertext.

These boundaries are intentional. Unsupported or unavailable assurance must remain explicit rather than being inferred from successful integrity checks.
