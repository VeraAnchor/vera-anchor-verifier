# Authoritative-source audit

**Status: Not started. No implementation provenance claimed by the scaffold.**

Record each source with a commit SHA, path, exact symbol/function, contract version, algorithm
and domain separation, dependencies, focused tests, negative vectors, and public reuse rights.

| Capability | Producer source | Current verifier source | Tests / fixtures | Trust boundary | Decision |
| --- | --- | --- | --- | --- | --- |
| Artifact SHA3-512 / canonicalization | Audit Core and HF | Audit Explorer and HF | Pending | Raw bytes vs declared digest | Pending |
| Merkle leaf/root proof | Audit Core producer | Audit Explorer/HF | Pending | Core root != HF request | Pending |
| Dataset / ingest bindings | Audit registries | Audit Explorer adapters | Pending | Subject/network and publication | Pending |
| SAGE execution | Audit Core execution binding | Audit Explorer execution modules | Pending | Declared execution vs independently verified evidence | Pending |
| HCS receipts | Audit Core receipt builder | Audit public HCS verification | Pending | Original anchor != publication receipt | Pending |
| External triangulation | Audit ledger data sources | Audit Explorer triangulation | Pending | Mirror corroboration != ledger authentication | Pending |

Do not copy proprietary files or raw production rows into this public repository during the audit.
