
import { createHash } from "node:crypto";
import { compress as zstdCompress, decompress as zstdDecompress } from "@mongodb-js/zstd";
import { describe, expect, it, vi } from "vitest";
import { resolveHcs11ProfileV1, type Hcs11MirrorV1Request } from "../../src/resolvers/hcs11MirrorV1.js";
import type { Hcs1V1ContentOptions } from "../../src/standards/hcs/hcs1V1.js";

const base = "https://testnet.mirrornode.hedera.com/api/v1";
const account = "0.0.10738880";
const registry = "0.0.10765269";
const profileTopic = "0.0.10765268";
const sequence = 1;
const did = "did:web:agents.example.org";
const uaid = `uaid:did:agents.example.org;uid=lab;registry=self;proto=hcs-26;nativeId=hedera:testnet:${account}`;
const profile = `{"aiAgent":{"capabilities":[0,7],"model":"lab-model","type":1},"display_name":"Lab Agent","type":1,"uaid":"${uaid}","version":"1.1"}`;
const checksum = createHash("sha256").update(profile, "utf8").digest("hex");
const b64 = (text: string) => Buffer.from(text).toString("base64");
const directMemo = `hcs-11:hcs://1/${profileTopic}`;
const registryMemo = `hcs-11:hcs://2/${registry}`;

const decodeOptions: Hcs1V1ContentOptions = {
  decompress_zstd: async (compressed) => new Uint8Array(await zstdDecompress(Buffer.from(compressed))),
};

function req(overrides: Partial<Hcs11MirrorV1Request> = {}): Hcs11MirrorV1Request {
  return { hedera_network: "testnet", account_id: account, ...overrides };
}

async function fixture(mode: "direct" | "registry" = "registry", overrides: Readonly<{
  account_memo?: string; account_id?: string; target?: string;
  canonical_profile?: string; registry_sequence?: number;
  registry_memo?: string; file_memo?: string;
}> = {}): Promise<{ fetch_impl: typeof fetch; urls: string[] }> {
  const urls: string[] = [];
  const rawProfile = overrides.canonical_profile ?? profile;
  const fileBytes = Buffer.from(rawProfile, "utf8");
  const compressed = (await zstdCompress(fileBytes, 10)).toString("base64");
  const fileChunk = Buffer.from(JSON.stringify({ o: 0, c: `data:application/json;base64,${compressed}` }));

  const fetch_impl = vi.fn(async (url: string | URL | Request) => {
    const path = String(url);
    urls.push(path);

    if (path === `${base}/accounts/${account}`) return Response.json({
      account: overrides.account_id ?? account,
      memo_base64: b64(overrides.account_memo ?? (mode === "registry" ? registryMemo : directMemo)),
      deleted: false,
    });

    if (path === `${base}/topics/${registry}`) {
      return Response.json({ topic_id: registry, memo: overrides.registry_memo ?? "hcs-2:0:86400" });
    }

    if (path === `${base}/topics/${registry}/messages/${sequence}`) {
      return Response.json({ topic_id: registry, sequence_number: overrides.registry_sequence ?? sequence,
        consensus_timestamp: "1792039124.000000003",
        message: b64(JSON.stringify({ p: "hcs-2", op: "register", t_id: overrides.target ?? profileTopic })) });
    }

    if (path === `${base}/topics/${profileTopic}`) {
      return Response.json({ topic_id: profileTopic,
        memo: overrides.file_memo ?? `${createHash("sha256").update(fileBytes).digest("hex")}:zstd:base64`,
        submit_key: { key: "present" }, admin_key: null });
    }

    if (path.startsWith(`${base}/topics/${profileTopic}/messages?`)) {
      return Response.json({ messages: [{ topic_id: profileTopic, sequence_number: 1,
        message: fileChunk.toString("base64") }], links: { next: null } });
    }

    throw new Error(`Unexpected Mirror request: ${path}`);
  }) as unknown as typeof fetch;

  return { fetch_impl, urls };
}

describe("independent HCS-11 account/profile resolution", () => {
  it("observes a current account memo, a caller-selected HCS-2 entry and integrity-checked HCS-1 profile", async () => {
    const transport = await fixture();
    const result = await resolveHcs11ProfileV1(transport, req({ hcs2_sequence_number: sequence,
      expected_profile_reference: `hcs://2/${registry}`, expected_hcs1_reference: `hcs://1/${profileTopic}`,
      expected_hcs1_sha256: checksum, expected_profile_sha256: checksum,
      expected_uaid: uaid, expected_base_did: did }), decodeOptions);

    expect(result).toMatchObject({ status: "resolved", reason_code: null,
      account_memo_temporal_scope: "current_observation", account_id: account,
      profile_reference: `hcs://1/${profileTopic}`, content_sha256: checksum,
      canonical_profile_sha256: checksum, did_binding: "match",
      account_memo: { protocol: "hcs-2", topic_id: registry },
      registry_entry: { topic_id: registry, sequence_number: sequence,
        consensus_timestamp: "1792039124.000000003" },
      profile: { uaid, display_name: "Lab Agent" } });

    expect(transport.urls).toEqual([
      `${base}/accounts/${account}`, `${base}/topics/${registry}`,
      `${base}/topics/${registry}/messages/${sequence}`,
      `${base}/topics/${profileTopic}`, `${base}/topics/${profileTopic}/messages?limit=100&order=asc`,
    ]);
    expect(Object.isFrozen(result)).toBe(true);
    expect(result).not.toHaveProperty("bytes");
  });

  it("also accepts the direct HCS-1 account-memo route without consulting an HCS-2 registry", async () => {
    const transport = await fixture("direct");
    const result = await resolveHcs11ProfileV1(transport, req({ expected_hcs1_sha256: checksum }), decodeOptions);

    expect(result).toMatchObject({ status: "resolved", registry_entry: null,
      account_memo: { protocol: "hcs-1" }, did_binding: "not_checked" });
    expect(transport.urls).toHaveLength(3);
  });

  it("refuses to infer a mutable/latest HCS-2 entry; does not fetch the registry", async () => {
    const transport = await fixture();
    const result = await resolveHcs11ProfileV1(transport, req(), decodeOptions);

    expect(result).toMatchObject({ status: "unavailable", reason_code: "HCS11_HCS2_SEQUENCE_REQUIRED" });
    expect(transport.urls).toEqual([`${base}/accounts/${account}`]);
  });

  it("does not silently ignore a registry sequence supplied for a direct reference", async () => {
    const transport = await fixture("direct");
    const result = await resolveHcs11ProfileV1(transport, req({ hcs2_sequence_number: sequence }), decodeOptions);

    expect(result).toMatchObject({ status: "invalid", reason_code: "HCS11_HCS2_SEQUENCE_NOT_APPLICABLE" });
    expect(transport.urls).toHaveLength(1);
  });

  it("rejects mismatch against caller's expected account reference before further reads", async () => {
    const transport = await fixture();
    const result = await resolveHcs11ProfileV1(transport,
      req({ hcs2_sequence_number: sequence, expected_profile_reference: `hcs://1/${profileTopic}` }), decodeOptions);

    expect(result).toMatchObject({ status: "conflict", reason_code: "HCS11_ACCOUNT_REFERENCE_MISMATCH" });
    expect(transport.urls).toHaveLength(1);
  });

  it("rejects account scope mismatch even when the requested account's data is otherwise plausible", async () => {
    const transport = await fixture("direct", { account_id: "0.0.999" });
    const result = await resolveHcs11ProfileV1(transport, req(), decodeOptions);

    expect(result).toMatchObject({ status: "invalid", reason_code: "HCS11_ACCOUNT_SCOPE_MISMATCH" });
    expect(transport.urls).toHaveLength(1);
  });

  it("rejects substitution of a different historical HCS-2 registered profile topic", async () => {
    const transport = await fixture("registry", { target: "0.0.999" });
    const result = await resolveHcs11ProfileV1(transport,
      req({ hcs2_sequence_number: sequence, expected_hcs1_reference: `hcs://1/${profileTopic}` }), decodeOptions);

    expect(result).toMatchObject({ status: "conflict", reason_code: "HCS2_TARGET_MISMATCH" });
    expect(transport.urls).toHaveLength(3);
  });

  it("does not promote an HCS-1 memo checksum disagreement to successful profile resolution", async () => {
    const transport = await fixture("direct", { file_memo: `${"a".repeat(64)}:zstd:base64` });
    const result = await resolveHcs11ProfileV1(transport, req(), decodeOptions);

    expect(result).toMatchObject({ status: "invalid", reason_code: "HCS1_CHECKSUM_MISMATCH", profile: null });
  });

  it("separates noncanonical HCS-11 JSON content from canonical pinned profile publication", async () => {
    const noncanonical = JSON.stringify({ version: "1.1", type: 1, display_name: "Lab Agent", uaid,
      aiAgent: { model: "lab-model", type: 1, capabilities: [0, 7] } });
    const transport = await fixture("direct", { canonical_profile: noncanonical });
    const result = await resolveHcs11ProfileV1(transport, req(), decodeOptions);

    expect(result).toMatchObject({ status: "unsupported", reason_code: "HCS11_PROFILE_CONTENT_NOT_CANONICAL" });
    expect(result.canonical_profile_sha256).toBe(checksum);
    expect(result.content_sha256).not.toBe(checksum);
  });

  it("rejects an independently expected UAID mismatch", async () => {
    const transport = await fixture("direct");
    const mismatchedUaid = uaid.replace("uid=lab", "uid=other");
    const result = await resolveHcs11ProfileV1(transport, req({ expected_uaid: mismatchedUaid }), decodeOptions);

    expect(result).toMatchObject({ status: "conflict", reason_code: "HCS11_UAID_MISMATCH" });
  });

  it("distinguishes missing accounts from invalid response and rate limiting", async () => {
    const unavailable = await resolveHcs11ProfileV1(
      { fetch_impl: async () => new Response(null, { status: 404 }) }, req(), decodeOptions);
    expect(unavailable).toMatchObject({ status: "unavailable", reason_code: "HCS11_ACCOUNT_NOT_FOUND" });

    const rate = await resolveHcs11ProfileV1(
      { fetch_impl: async () => new Response(null, { status: 429 }) }, req(), decodeOptions);
    expect(rate).toMatchObject({ status: "unavailable", reason_code: "HCS11_ACCOUNT_RATE_LIMITED" });

    const invalid = await resolveHcs11ProfileV1(
      { fetch_impl: async () => Response.json([]) }, req(), decodeOptions);
    expect(invalid).toMatchObject({ status: "invalid", reason_code: "HCS11_ACCOUNT_RESPONSE_INVALID" });
  });

  it("validates network, expected commitments and locator before any network calls", async () => {
    const transport = await fixture("direct");

    await expect(resolveHcs11ProfileV1(transport, req({ account_id: "https://example.org/private" }), decodeOptions))
      .rejects.toThrow();
    await expect(resolveHcs11ProfileV1(transport, req({ expected_hcs1_sha256: "bad" }), decodeOptions))
      .rejects.toThrow();
    await expect(resolveHcs11ProfileV1(transport,
      req({ expected_profile_reference: "https://evil.example" }), decodeOptions)).rejects.toThrow();
    await expect(resolveHcs11ProfileV1({ ...transport, base_urls: { testnet: "http://evil.example/api/v1" } },
      req(), decodeOptions)).rejects.toThrow();

    expect(transport.urls).toHaveLength(0);
  });

  it("preserves network scope in the HCS-14 native Hedera identity", async () => {
    const mainnet = "https://mainnet-public.mirrornode.hedera.com/api/v1";
    const test = await fixture("direct");

    const mirror = vi.fn(async (url: string | URL | Request) => {
      const u = String(url).replace(mainnet, base);
      return (test.fetch_impl as typeof fetch)(u);
    }) as unknown as typeof fetch;

    const out = await resolveHcs11ProfileV1({ fetch_impl: mirror }, {
      hedera_network: "mainnet", account_id: account,
    }, decodeOptions);

    expect(out).toMatchObject({ status: "conflict", reason_code: "HCS11_UAID_NETWORK_MISMATCH" });
  });
});
