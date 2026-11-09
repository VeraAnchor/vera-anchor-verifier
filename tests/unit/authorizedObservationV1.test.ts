import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  createStaticBearerAuthProviderV1,
  resolveAuthorizedHcsObservationsV1,
  type AuthorizedHcsEvidenceV1,
} from "../../src/index.js";

const CORE = "https://core.example.test";
const MIRROR = "https://mirror.example.test/api/v1";
const NETWORK = "testnet" as const;
const TOPIC = "0.0.12345";
const SEQUENCE = 5;
const MESSAGE = Buffer.from("authorized-encrypted-message", "utf8");
const DIGEST = createHash("sha3-512").update(MESSAGE).digest("hex");
const SUBJECT = Object.freeze({ kind: "dataset" as const, id: "research.dataset", hedera_network: NETWORK });

function evidence(): AuthorizedHcsEvidenceV1 {
  return Object.freeze({
    acquisition: Object.freeze({
      resolver_id: "core.authorized-hcs.v1",
      access_context: "authorized",
      retrieval_provider: "vera_anchor_core",
      decryption_method: "service_assisted",
      recoverability: "service_dependent",
    }),
    hedera_network: NETWORK,
    topic: Object.freeze({ name: "dataset_private", topic_id: TOPIC, key_version: 3 }),
    encryption: Object.freeze({ topic_key_version: 3, user_key_version: 2 }),
    tx: Object.freeze({
      id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      message_id: `${SEQUENCE}@${TOPIC}`,
      transaction_id: null,
      sequence_number: SEQUENCE,
      consensus_timestamp: "1234567890.123456789",
      status: "confirmed",
      mirror_verified: false,
      mirror_verified_at: null,
    }),
    core_hash_observation: Object.freeze({ expected: "a".repeat(128), computed: "a".repeat(128) }),
    message_binding: Object.freeze({
      schema_version: "vera.hcs-message-binding.v1",
      algorithm: "sha3-512",
      message_sha3_512: DIGEST,
      message_bytes: MESSAGE.length,
    }),
    payload_included: true,
    payload: Object.freeze({ secret: "not-a-report-fact" }),
  });
}

function coreResponse() {
  const e = evidence();
  return {
    ok: true,
    hedera_network: NETWORK,
    mode: "decrypt_only",
    verified: null,
    topic: { name: e.topic.name, topic_id: e.topic.topic_id, key_version: e.topic.key_version },
    encryption: { topic_key_version: e.encryption.topic_key_version, user_key_version: e.encryption.user_key_version },
    tx: { ...e.tx },
    hash: { expected: e.core_hash_observation.expected, computed: e.core_hash_observation.computed, match: null },
    message_binding: { ...e.message_binding },
    payload: e.payload,
  };
}

describe("authorized HCS observation normalization", () => {
  it("marks Core evidence as authorized_service and never copies plaintext into report facts", async () => {
    const coreFetch = vi.fn(async () => Response.json(coreResponse())) as typeof fetch;
    const out = await resolveAuthorizedHcsObservationsV1({
      core: {
        base_url: CORE,
        auth_provider: createStaticBearerAuthProviderV1("test-api-key"),
        fetch_impl: coreFetch,
      },
      mirror: false,
    }, {
      subject: SUBJECT,
      request: { network: NETWORK, message_id: `${SEQUENCE}@${TOPIC}`, include_decrypted: true },
    });
    expect(out.core.status).toBe("resolved");
    expect(out.authorized_observation?.source).toBe("authorized_service");
    expect(out.authorized_observation?.resolver_id).toBe("core.authorized-hcs.v1");
    expect(out.authorized_observation?.facts.find((fact) => fact.key === "publication.message_sha3_512"))
      .toMatchObject({ state: "available", value: DIGEST });
    expect(out.authorized_observation?.facts.some((fact) => JSON.stringify(fact).includes("not-a-report-fact"))).toBe(false);
    expect(out.mirror_resolution).toBe("not_requested");
  });

  it("rejects subject/network substitution before making an authenticated Core request", async () => {
    const coreFetch = vi.fn(async () => Response.json(coreResponse())) as typeof fetch;
    await expect(resolveAuthorizedHcsObservationsV1({
      core: {
        base_url: CORE,
        auth_provider: createStaticBearerAuthProviderV1("test-api-key"),
        fetch_impl: coreFetch,
      },
    }, {
      subject: { ...SUBJECT, hedera_network: "mainnet" },
      request: { network: NETWORK, message_id: `${SEQUENCE}@${TOPIC}`, include_decrypted: true },
    })).rejects.toThrow(/exact network-bound subject/);
    expect(coreFetch).not.toHaveBeenCalled();
  });

  it("resolves Core and Mirror as separate observations without declaring a verification verdict", async () => {
    const coreFetch = vi.fn(async () => Response.json(coreResponse())) as typeof fetch;
    const mirrorFetch = vi.fn(async (url: string | URL | Request) => {
      const parsed = new URL(String(url));
      expect(parsed.origin).toBe("https://mirror.example.test");
      expect(parsed.pathname).toBe(`/api/v1/topics/${TOPIC}/messages/${SEQUENCE}`);
      return Response.json({
        topic_id: TOPIC,
        sequence_number: SEQUENCE,
        consensus_timestamp: "1234567890.123456789",
        message: MESSAGE.toString("base64"),
      });
    }) as typeof fetch;

    const out = await resolveAuthorizedHcsObservationsV1({
      core: {
        base_url: CORE,
        auth_provider: createStaticBearerAuthProviderV1("test-api-key"),
        fetch_impl: coreFetch,
      },
      mirror: { base_urls: { testnet: MIRROR }, fetch_impl: mirrorFetch },
    }, {
      subject: SUBJECT,
      request: { network: NETWORK, message_id: `${SEQUENCE}@${TOPIC}`, include_decrypted: true },
    });

    expect(out.core.status).toBe("resolved");
    expect(out.authorized_observation?.source).toBe("authorized_service");
    expect(out.mirror_resolution).toBe("resolved");
    expect(out.mirror?.observation?.source).toBe("hedera_mirror");
    expect(out.mirror?.observation?.facts.find((fact) => fact.key === "publication.message_sha3_512"))
      .toMatchObject({ state: "available", value: DIGEST });
    expect(coreFetch).toHaveBeenCalledTimes(1);
    expect(mirrorFetch).toHaveBeenCalledTimes(1);
  });

  it("can explicitly disable Mirror resolution without changing Core acquisition", async () => {
    const coreFetch = vi.fn(async () => Response.json(coreResponse())) as typeof fetch;
    const out = await resolveAuthorizedHcsObservationsV1({
      core: {
        base_url: CORE,
        auth_provider: createStaticBearerAuthProviderV1("test-api-key"),
        fetch_impl: coreFetch,
      },
      mirror: false,
    }, {
      subject: SUBJECT,
      request: { network: NETWORK, message_id: `${SEQUENCE}@${TOPIC}`, include_decrypted: true },
    });
    expect(out.core.status).toBe("resolved");
    expect(out.authorized_observation?.source).toBe("authorized_service");
    expect(out.mirror).toBeNull();
    expect(out.mirror_resolution).toBe("not_requested");
  });
});
