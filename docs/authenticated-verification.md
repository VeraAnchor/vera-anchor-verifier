# Authenticated verification

The Vera Anchor Verifier SDK supports optional authenticated acquisition of private Dataset and Ingest evidence through Vera Anchor Core.

Authentication controls evidence acquisition. It does not determine whether acquired evidence verifies.

The authenticated workflow preserves the same separation used elsewhere in the verifier:

```text
caller-controlled intent and policy
            |
            v
authorized Core evidence acquisition
            |
            v
local recomputation of supported evidence
            |
            v
independent Hedera Mirror corroboration
            |
            v
triangulation and portable report
            |
            v
allow / review / deny
```

## Security model

Vera Anchor Core remains authoritative for authentication, tenant authorization, and access to private evidence.

The verifier does not reproduce Core authorization logic. A successful authenticated request establishes only that Core permitted the caller to retrieve the requested evidence.

Core may also perform service-assisted decryption. Decrypted evidence remains untrusted input. The verifier independently recomputes supported Dataset or Ingest checks rather than accepting Core fields such as `verified` or `hash.match` as verification proof.

Authenticated evidence retains `authorized_service` provenance. That provenance does not by itself satisfy an integrity, consistency, or assurance requirement.

Where supported, the verifier separately resolves the referenced Hedera message through its Mirror resolver and compares the independently acquired message commitment with the Core-provided message binding.

## Credentials

Authenticated workflows use an `AuthProviderV1`.

For the current Vera Anchor bearer-token/API-key contract, applications can use `createStaticBearerAuthProviderV1`.

```js
import { createStaticBearerAuthProviderV1 } from "@veraanchor/verifier";

const apiKey = process.env.VERA_ANCHOR_API_KEY;

if (!apiKey) {
  throw new Error("VERA_ANCHOR_API_KEY is required");
}

const authProvider = createStaticBearerAuthProviderV1(apiKey);
```

Applications must obtain credentials from an appropriate secret-management mechanism. Do not commit API keys or other production credentials to source control.

Authorization material is scoped to the configured Core request. Supported authenticated resolution does not forward credentials to Hedera Mirror, Vera Anchor Explorer, redirects, or evidence-selected URLs.

Credentials are not included in portable verification reports.

## Authenticated Dataset verification

`triangulateAuthorizedDatasetWithPolicyV1` combines:

- local Dataset source and commitment recomputation;
- caller-authorized retrieval of the private Dataset Registry event;
- comparison of locally recomputed Dataset identity and fingerprint with the authorized registry evidence;
- independent Hedera Mirror corroboration of the referenced HCS message;
- portable report creation;
- relying-party policy evaluation.

The caller must independently supply the Dataset subject, Hedera network, HCS reference, and policy.

See `examples/authorized-dataset-policy.mjs`.

## Authenticated Ingest verification

`triangulateAuthorizedIngestWithPolicyV1` combines:

- local Ingest material and commitment recomputation;
- caller-authorized retrieval of the private Ingest receipt;
- verification of the receipt's supported deterministic contract;
- comparison of locally recomputed commitments with the authorized receipt;
- independent Hedera Mirror corroboration of the referenced HCS message;
- portable report creation;
- relying-party policy evaluation.

Supported comparisons include the Ingest object key, fingerprint, bundle digest, Merkle root, idempotency key, item count, and total bytes where available under the selected contract.

See `examples/authorized-ingest-policy.mjs`.

## Policy behavior

Authenticated policy workflows preserve the normal verifier decisions:

- `allow` means the required verification checks, authenticated evidence relationships, and requested assurance were established.
- `deny` means a required condition was contradicted or the policy otherwise requires denial.
- `review` means required evidence remains unresolved under a policy that delegates unresolved cases for review.

Authorization failure, service unavailability, or missing Mirror evidence does not become a successful verification result.

Policies using `on_unresolved: "deny"` can require unresolved evidence to fail closed instead of returning `review`.

## Portable reports

Authenticated workflows produce the same digest-bound portable report contract used by the rest of the SDK.

Raw decrypted payloads and authorization credentials are not included in portable reports.

A saved portable report remains unauthenticated input when loaded later. Validating its structure and digest does not recreate the authenticated acquisition step, so a saved report cannot independently promote itself into a fresh SDK-authorized `allow`.

## Service-assisted decryption boundary

The current authenticated workflow uses Core for authorized private-evidence recovery where required.

The verifier independently checks supported content and commitment relationships after acquisition, but it does not claim an independent cryptographic proof that Core's returned plaintext was decrypted from a particular ciphertext.

Authenticated acquisition therefore provides authorized private-evidence access and cross-source verification without changing the meaning of existing integrity or Mirror-assurance claims.

## Network and resolver boundaries

Authenticated verification requires an explicit Hedera network.

The verifier does not silently try another network if evidence cannot be resolved.

Core origin configuration belongs to the caller. Evidence cannot redirect the authenticated resolver to an arbitrary service.

Hedera Mirror remains a separate observation source and does not receive Core authorization material.

## CLI support

The authenticated verification surface is currently exposed through the library API.

The existing CLI continues to support offline, public, execution, and standards workflows without accepting private Vera Anchor credentials.
