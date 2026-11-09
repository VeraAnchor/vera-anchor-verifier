# Verification semantics

The verifier separates evidence findings, cross-source consistency and relying-party decisions. These layers are related but are not interchangeable.

## Finding outcomes

Every supported verification check has one of five normalized outcomes:

- `pass` — the available evidence satisfies the exact check.
- `fail` — the verifier demonstrated a contradiction or violation of an explicit requirement.
- `indeterminate` — the check could not be established because required evidence or an external observation was unavailable.
- `unsupported` — the requested material or operation is outside the verifier's supported contract or bounded implementation.
- `skipped` — the check was intentionally not applicable or not requested in the selected workflow.

Missing evidence and service outages are not contradictions and therefore must not be converted into `fail` unless an explicit requirement itself is violated.

## Triangulation

Cross-source relationship states are:

- `consistent` — the compared independently acquired facts agree for all required comparisons;
- `conflict` — at least one required comparison demonstrates a contradiction;
- `incomplete` — the relationship cannot be fully established because required observations are missing, indeterminate or unsupported.

Consistency is not factual truth. It means the compared evidence sources agree on the supported facts that were actually checked.

## Policy decisions

Policy decisions are separate from verification findings:

- `allow` — all requirements selected by the relying party are satisfied under the policy.
- `deny` — a required condition is contradicted or the policy otherwise requires denial.
- `review` — the evidence is unresolved under a policy that delegates unresolved cases for review.

Verification intent and policy must be controlled by the relying party. An untrusted receipt, bundle, execution record or standards projection cannot define its own sufficient acceptance threshold.

## Assurance

The current policy assurance dimension is `mirror_corroboration`. It means the relevant supported fact was independently observed through the SDK's Hedera Mirror resolver path. It does not mean that the SDK authenticated Hedera consensus signatures or established control of an account, DID or publisher key.

The SDK also performs deterministic integrity and binding checks where the underlying contract supports recomputation. Those checks are represented through findings rather than being silently promoted into a broader authentication claim.

## Supported standards interpretation

The standards path supports pinned verification behavior for HCS-1, HCS-2, HCS-11, HCS-13, HCS-14 and HCS-26 as exposed by the SDK. Standards registration or profile publication is evidence of the declared record and its supported integrity relationships; it is not evidence that associated software executed, that a publisher currently controls a key, or that a claim is factually true.

HCS-26 verification resolves the selected historical discovery/version path, verifies the canonical manifest, and verifies integrity for the manifest-declared HCS-1 files within the SDK's resource bounds.

## Portable reports

`va.portable-verification-report.v1` is a deterministic, digest-bound representation of a verification result and its supported context. Validating a saved portable report checks its structure and internal digests. It does not recompute the underlying evidence and does not authenticate the report's origin.

Accordingly, a saved report cannot elevate itself into an SDK-authenticated `allow` decision. Fresh verification with independently supplied intent and policy is required when a relying party needs an SDK-computed decision over the underlying evidence.

## Authentication boundary

Authentication determines which private evidence the verifier may acquire. It does not determine whether that evidence verifies.

Vera Anchor Core remains authoritative for authentication, tenant authorization, and permitted private-evidence retrieval. The verifier does not reproduce Core access-control logic.

When Core performs service-assisted decryption, the returned plaintext remains untrusted evidence. The SDK independently recomputes every supported Dataset or Ingest check rather than treating Core authorization, `verified` fields, hash-match fields, or other server assertions as verification proof.

Authenticated evidence retains explicit `authorized_service` provenance. That provenance is not itself an integrity or assurance result.

Where supported, the verifier separately resolves the selected Hedera message through its Mirror path and compares independently acquired message commitments with the Core-provided message binding.

Accordingly, authenticated acquisition does not by itself establish:

- Hedera consensus-signature authentication;
- DID-controller or publisher-key authentication;
- historical ownership of an account;
- factual truth of the verified content;
- independent cryptographic proof that service-assisted plaintext decryption corresponds to a particular publication ciphertext.

These properties require separate explicit evidence or assurance. They must not be inferred from successful authorization, decryption, integrity checks, or Mirror corroboration.
