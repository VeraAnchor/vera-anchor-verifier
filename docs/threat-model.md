# Threat model — initial inventory

All supplied bytes, JSON documents, resolver responses, and evidence references are hostile inputs.

| Threat | Required boundary | Planned negative test |
| --- | --- | --- |
| Replayed valid proof bound to wrong subject | Explicit caller subject and commitments | Valid digest, wrong dataset/version |
| Cross-network substitution | Network included in relevant bindings | Testnet proof used for mainnet claim |
| Fabricated independent corroboration | Observation provenance and shared dependencies | Two aliases of the same assertion |
| Malicious URL, redirect, or SSRF | Fixed resolver allowlists, redirect checks, DNS/IP restrictions | Loopback/private address attempts |
| Oversized JSON / archives / proof paths | Input, recursion, expansion, and concurrency budgets | Depth, byte, and decompression bombs |
| Poisoned cache / stale registry | Immutable identity and explicit freshness | Expired mutable registry observation |
| Ledger evidence overclaim | Distinguish mirror reads and authenticated proofs | Mirror only cannot pass authenticated claim |
| Leakage of tenant evidence | Explicit private adapters, no automatic public fallback | Private material not in logs or reports |
| Dependency compromise | Lockfile, constrained CI permissions, immutable action pins | CI policy inspection |

Concrete size limits and enforcement sites must be decided from realistic fixture sizes in Phase 0.
