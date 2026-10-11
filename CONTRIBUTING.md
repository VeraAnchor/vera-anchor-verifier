# Contributing

The project is in Phase 0. Please discuss changes to public schemas, cryptographic algorithms,
verification claims, or resolver trust boundaries before proposing an implementation.

Run `npm ci`, `npm run check`, `npm run typecheck`, `npm test`, and `npm run build` before submitting a PR.
Do not submit credentials, private customer evidence, production configuration, or proprietary
Core/Explorer code unless it is explicitly authorized for open-source release.

Cryptographic changes require real conformance vectors, at least one tampered/negative vector,
explicit algorithm versions, clear authority claims, and deterministic reproducibility.
No change to an established historical commitment algorithm is permitted without an explicit
new version and migration analysis.
