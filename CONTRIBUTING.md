# Contributing

Contributions that improve correctness, interoperability, security, documentation and developer usability are welcome.

Changes to public schemas, commitment algorithms, verification semantics, reason codes, resolver trust boundaries or policy behavior require explicit review because downstream users may rely on their deterministic meaning.

## Development checks

Before submitting a pull request, run:

```sh
npm ci
npm run check
npm run typecheck
npm test
npm run build
```

Do not commit credentials, private customer evidence, production configuration, proprietary Vera Anchor service code or other material that is not explicitly authorized for public release.

## Verification and cryptographic changes

Changes to cryptographic or verification behavior should include:

- deterministic positive coverage;
- at least one relevant tampered or negative case;
- explicit algorithm and contract versions where applicable;
- clear authority and trust-boundary semantics;
- reproducible conformance material when the change affects interoperability.

An established historical commitment algorithm must not be changed in place. A behavior change that would alter previously valid commitments requires an explicit new version and migration analysis.

Networked resolver changes must preserve caller-controlled network selection, bounded I/O and the rule that untrusted evidence cannot choose resolver authority.
