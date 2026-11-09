import { describe, expect, it, vi } from "vitest";
import {
  createStaticBearerAuthProviderV1,
  resolveAuthorizedHcsEvidenceV1,
  type AuthProviderV1,
} from "../../src/index.js";

const CORE = "https://core.example.test";
const NETWORK = "testnet" as const;
const MESSAGE_ID = "5@0.0.12345";
const TX_ID = "0.0.77@1234567890.123456789";
const HASH = "a".repeat(128);

function success(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    ok: true,
    hedera_network: NETWORK,
    mode: "decrypt_only",
    verified: null,
    topic: { name: "dataset_publication", topic_id: "0.0.12345", key_version: 3 },
    encryption: { topic_key_version: 3, user_key_version: 2 },
    tx: {
      id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      message_id: MESSAGE_ID,
      transaction_id: TX_ID,
      sequence_number: 5,
      consensus_timestamp: "1234567890.123456789",
      status: "confirmed",
      mirror_verified: true,
      mirror_verified_at: "2026-11-04T12:00:00.000Z",
    },
    hash: { expected: HASH, computed: HASH, match: null },
    message_binding: {
      schema_version: "vera.hcs-message-binding.v1",
      algorithm: "sha3-512",
      message_sha3_512: HASH,
      message_bytes: 512,
    },
    payload: { schema: "example:v1", value: 7 },
    ...overrides,
  };
}

function response(value: unknown, status = 200): Response {
  return Response.json(value, { status });
}

describe("authorized Core HCS resolver v1", () => {
  it("retrieves service-assisted evidence through one fixed authenticated Core POST", async () => {
    const requests: Array<{
      url: string;
      init: RequestInit | undefined;
    }> = [];
    const fetchImpl = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      requests.push({ url: String(url), init });
      return response(success());
    }) as typeof fetch;

    const out = await resolveAuthorizedHcsEvidenceV1({
      base_url: CORE,
      auth_provider: createStaticBearerAuthProviderV1("test-api-key"),
      fetch_impl: fetchImpl,
    }, {
      network: NETWORK,
      message_id: MESSAGE_ID,
      include_decrypted: true,
    });

    expect(out.status).toBe("resolved");
    expect(out.evidence?.acquisition).toEqual({
      resolver_id: "core.authorized-hcs.v1",
      access_context: "authorized",
      retrieval_provider: "vera_anchor_core",
      decryption_method: "service_assisted",
      recoverability: "service_dependent",
    });
    expect(out.evidence?.payload).toEqual({ schema: "example:v1", value: 7 });
    expect(out.evidence?.message_binding.message_sha3_512).toBe(HASH);
    expect(out.evidence).not.toHaveProperty("verified");
    expect(out.evidence?.core_hash_observation).not.toHaveProperty("match");
    expect(requests).toHaveLength(1);
    expect(requests[0]?.url).toBe(`${CORE}/v1/hcs/verify-decrypt`);
    expect(requests[0]?.init?.redirect).toBe("error");
    expect(requests[0]?.init?.credentials).toBe("omit");
    expect((requests[0]?.init?.headers as Record<string, string>).Authorization).toBe("Bearer test-api-key");
    expect(JSON.parse(String(requests[0]?.init?.body))).toEqual({
      hedera_network: NETWORK,
      message_id: MESSAGE_ID,
      mode: "decrypt_only",
      include_decrypted: true,
    });
  });

  it("requires explicit plaintext disclosure and rejects a server disclosure mismatch", async () => {
    const fetchImpl = vi.fn(async () => response(success())) as typeof fetch;
    const out = await resolveAuthorizedHcsEvidenceV1({
      base_url: CORE,
      auth_provider: createStaticBearerAuthProviderV1("test-api-key"),
      fetch_impl: fetchImpl,
    }, { network: NETWORK, message_id: MESSAGE_ID });
    expect(out.status).toBe("invalid");
    expect(out.reason_code).toBe("CORE_AUTHORIZED_DISCLOSURE_MISMATCH");
  });

  it("fails closed on network, locator, or decrypt-only contract drift", async () => {
    const examples = [
      success({ hedera_network: "mainnet" }),
      success({ tx: { ...(success().tx as Record<string, unknown>), message_id: "6@0.0.12345" } }),
      success({ mode: "decrypt_and_verify", verified: true, hash: { expected: HASH, computed: HASH, match: true } }),
    ];
    for (const example of examples) {
      const out = await resolveAuthorizedHcsEvidenceV1({
        base_url: CORE,
        auth_provider: createStaticBearerAuthProviderV1("test-api-key"),
        fetch_impl: vi.fn(async () => response(example)) as typeof fetch,
      }, { network: NETWORK, message_id: MESSAGE_ID, include_decrypted: true });
      expect(out.status).toBe("invalid");
      expect(out.evidence).toBeNull();
    }
  });

  it("maps authorization and availability failures without retry or public fallback", async () => {
    const cases = [
      [401, "unauthorized", "CORE_AUTH_REQUIRED"],
      [403, "forbidden", "CORE_AUTH_FORBIDDEN"],
      [404, "not_found", "CORE_AUTHORIZED_EVIDENCE_NOT_FOUND"],
      [429, "rate_limited", "CORE_RATE_LIMITED"],
      [503, "unavailable", "CORE_AUTHORIZED_HTTP_UNAVAILABLE"],
    ] as const;
    for (const [status, expectedStatus, reason] of cases) {
      const fetchImpl = vi.fn(async () => response({ error: "x" }, status)) as typeof fetch;
      const out = await resolveAuthorizedHcsEvidenceV1({
        base_url: CORE,
        auth_provider: createStaticBearerAuthProviderV1("test-api-key"),
        fetch_impl: fetchImpl,
      }, { network: NETWORK, transaction_id: TX_ID });
      expect(out.status).toBe(expectedStatus);
      expect(out.reason_code).toBe(reason);
      expect(fetchImpl).toHaveBeenCalledTimes(1);
    }
  });


  it("treats provider execution failures as unavailable but rejects malformed provider output", async () => {
    const unavailable: AuthProviderV1 = {
      authorize: async () => { throw new TypeError("identity provider fetch failed"); },
    };
    const notCalled = vi.fn(async () => response(success())) as typeof fetch;
    const out = await resolveAuthorizedHcsEvidenceV1({
      base_url: CORE,
      auth_provider: unavailable,
      fetch_impl: notCalled,
    }, { network: NETWORK, message_id: MESSAGE_ID });
    expect(out.status).toBe("unavailable");
    expect(out.reason_code).toBe("AUTH_PROVIDER_UNAVAILABLE");
    expect(notCalled).not.toHaveBeenCalled();

    const malformed: AuthProviderV1 = {
      authorize: () => ({ authorization: "Bearer good\r\nx-evil: yes" }),
    };
    await expect(resolveAuthorizedHcsEvidenceV1({
      base_url: CORE,
      auth_provider: malformed,
    }, { network: NETWORK, message_id: MESSAGE_ID })).rejects.toThrow(/invalid authorization/);
  });

  it("matches the existing Core/HF 256-byte identifier bound", async () => {
    await expect(resolveAuthorizedHcsEvidenceV1({
      base_url: CORE,
      auth_provider: createStaticBearerAuthProviderV1("test-api-key"),
    }, { network: NETWORK, message_id: "x".repeat(257) })).rejects.toThrow(/Invalid message_id/);
  });

  it("rejects unsafe origins, ambiguous locators, invalid authorization material, and oversized responses", async () => {
    const safe = createStaticBearerAuthProviderV1("test-api-key");
    await expect(resolveAuthorizedHcsEvidenceV1({ base_url: "http://core.example.test", auth_provider: safe }, {
      network: NETWORK, message_id: MESSAGE_ID,
    })).rejects.toThrow(/fixed HTTPS origin/);
    await expect(resolveAuthorizedHcsEvidenceV1({ base_url: `${CORE}/v1`, auth_provider: safe }, {
      network: NETWORK, message_id: MESSAGE_ID,
    })).rejects.toThrow(/fixed HTTPS origin/);
    await expect(resolveAuthorizedHcsEvidenceV1({ base_url: CORE, auth_provider: safe }, {
      network: NETWORK, message_id: MESSAGE_ID, transaction_id: TX_ID,
    })).rejects.toThrow(/Exactly one/);

    const badAuth: AuthProviderV1 = { authorize: () => ({ authorization: "Bearer good\r\nx-evil: yes" }) };
    await expect(resolveAuthorizedHcsEvidenceV1({ base_url: CORE, auth_provider: badAuth }, {
      network: NETWORK, message_id: MESSAGE_ID,
    })).rejects.toThrow(/invalid authorization/);

    const fetchImpl = vi.fn(async () => new Response("{}", {
      status: 200,
      headers: { "content-type": "application/json", "content-length": "3000000" },
    })) as typeof fetch;
    const out = await resolveAuthorizedHcsEvidenceV1({
      base_url: CORE,
      auth_provider: safe,
      fetch_impl: fetchImpl,
    }, { network: NETWORK, message_id: MESSAGE_ID });
    expect(out.status).toBe("invalid");
    expect(out.reason_code).toBe("CORE_AUTHORIZED_RESPONSE_TOO_LARGE");
  });
});
