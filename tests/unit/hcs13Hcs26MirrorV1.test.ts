
import { compress as zstdCompress, decompress as zstdDecompress } from "@mongodb-js/zstd";
import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { resolveHcs13SchemaV1 } from "../../src/resolvers/hcs13MirrorV1.js";
import { resolveHcs26SkillVersionV1 } from "../../src/resolvers/hcs26MirrorV1.js";
import { finalizeHcs13SchemaV1 } from "../../src/standards/hcs/hcs13V1.js";
import { finalizeHcs26SkillManifestV1 } from "../../src/standards/hcs/hcs26V1.js";

const base = "https://testnet.mirrornode.hedera.com/api/v1";
const net = "testnet" as const;
const hcs13Registry = "0.0.5001";
const schemaTopic = "0.0.5002";
const discoveryTopic = "0.0.6001";
const versionTopic = "0.0.6002";
const manifestTopic = "0.0.6003";
const publisher = "0.0.6999";
const schema = finalizeHcs13SchemaV1({
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object", properties: { count: { type: "integer", minimum: 0 } },
  required: ["count"],
});
const manifest = finalizeHcs26SkillManifestV1({
  name: "Independent agent capability", description: "Pinned HCS-26 skill",
  version: "1.2.3", license: "MIT", author: "Independent Author",
  files: [{ path: "SKILL.md", hrl: "hcs://1/0.0.6004",
    sha256: "a".repeat(64), mime: "text/markdown" }],
});

function b64(raw: string | Uint8Array): string { return Buffer.from(raw).toString("base64"); }

const decodeOptions = {
  decompress_zstd: async (compressed: Uint8Array): Promise<Uint8Array> =>
    new Uint8Array(await zstdDecompress(Buffer.from(compressed))),
};

async function contentRoutes(topic: string, bytes: Uint8Array): Promise<Record<string, unknown>> {
  const compressed = await zstdCompress(Buffer.from(bytes), 10);
  const chunk = Buffer.from(JSON.stringify({ o: 0,
    c: `data:application/json;base64,${b64(compressed)}` }));
  return {
    [`${base}/topics/${topic}`]: { topic_id: topic,
      memo: `${createHash("sha256").update(bytes).digest("hex")}:zstd:base64`,
      submit_key: { key: "present" }, admin_key: null },
    [`${base}/topics/${topic}/messages?limit=100&order=asc`]: {
      messages: [{ topic_id: topic, sequence_number: 1, message: b64(chunk) }],
      links: { next: null },
    },
  };
}

async function hcs13Fixture(overrides: Readonly<{
  target?: string; schemaBytes?: Uint8Array; memo?: string;
  missing?: string; invalidSequence?: number;
}> = {}): Promise<{ fetch_impl: typeof fetch; urls: string[] }> {
  const urls: string[] = [];
  const paths: Record<string, unknown> = {
    [`${base}/topics/${hcs13Registry}`]: { topic_id: hcs13Registry,
      memo: overrides.memo ?? "hcs-2:0:86400" },
    [`${base}/topics/${hcs13Registry}/messages/7`]: { topic_id: hcs13Registry,
      sequence_number: overrides.invalidSequence ?? 7,
      consensus_timestamp: "1792039124.000000123",
      message: b64(JSON.stringify({ p: "hcs-2", op: "register",
        t_id: overrides.target ?? schemaTopic })) },
    ...(await contentRoutes(schemaTopic, overrides.schemaBytes ?? Buffer.from(schema.canonical_payload))),
  };
  const fetch_impl = vi.fn(async (url: string | URL | Request) => {
    const path = String(url);
    urls.push(path);
    if (path === overrides.missing) return new Response(null, { status: 404 });
    if (!Object.hasOwn(paths, path)) throw new Error(`Unexpected HCS-13 Mirror URL ${path}`);
    return Response.json(paths[path]);
  }) as unknown as typeof fetch;
  return { fetch_impl, urls };
}

async function hcs26Fixture(overrides: Readonly<{
  account?: string; versionTopic?: string; skillUid?: number; status?: string;
  discoveryMemo?: string; versionMemo?: string; version?: string;
  checksum?: string; manifestBytes?: Uint8Array; missing?: string;
}> = {}): Promise<{ fetch_impl: typeof fetch; urls: string[] }> {
  const urls: string[] = [];
  const paths: Record<string, unknown> = {
    [`${base}/topics/${discoveryTopic}`]: { topic_id: discoveryTopic,
      memo: overrides.discoveryMemo ?? "hcs-26:0:86400:0" },
    [`${base}/topics/${discoveryTopic}/messages/42`]: {
      topic_id: discoveryTopic, sequence_number: 42,
      consensus_timestamp: "1792039124.000000001",
      message: b64(JSON.stringify({ p: "hcs-26", op: "register",
        t_id: overrides.versionTopic ?? versionTopic,
        account_id: overrides.account ?? publisher,
        metadata: "hcs://1/0.0.6900" })) },
    [`${base}/topics/${versionTopic}`]: { topic_id: versionTopic,
      memo: overrides.versionMemo ?? "hcs-26:0:86400:1" },
    [`${base}/topics/${versionTopic}/messages/3`]: {
      topic_id: versionTopic, sequence_number: 3,
      consensus_timestamp: "1792039130.000000010",
      message: b64(JSON.stringify({ p: "hcs-26", op: "register",
        skill_uid: overrides.skillUid ?? 42, version: overrides.version ?? "1.2.3",
        t_id: manifestTopic, checksum: `sha256:${overrides.checksum ?? manifest.sha256}`,
        status: overrides.status ?? "deprecated" })) },
    ...(await contentRoutes(manifestTopic, overrides.manifestBytes ?? Buffer.from(manifest.canonical_payload))),
  };
  const fetch_impl = vi.fn(async (url: string | URL | Request) => {
    const path = String(url);
    urls.push(path);
    if (path === overrides.missing) return new Response(null, { status: 404 });
    if (!Object.hasOwn(paths, path)) throw new Error(`Unexpected HCS-26 Mirror URL ${path}`);
    return Response.json(paths[path]);
  }) as unknown as typeof fetch;
  return { fetch_impl, urls };
}

const schemaRequest = { hedera_network: net, reference: `hcs://13/${hcs13Registry}#7` };
const skillRequest = { hedera_network: net, discovery_topic_id: discoveryTopic,
  discovery_sequence_number: 42, version_sequence_number: 3 };

describe("HCS-13 exact historical schema resolution", () => {
  it("resolves HCS-2 entry -> HCS-1 original content -> canonical HCS-13 schema", async () => {
    const transport = await hcs13Fixture();
    const result = await resolveHcs13SchemaV1(transport, { ...schemaRequest,
      expected_schema_sha256: schema.sha256, expected_hcs1_reference: `hcs://1/${schemaTopic}` }, decodeOptions);
    expect(result).toMatchObject({ status: "resolved", reason_code: null,
      schema_hcs1_reference: `hcs://1/${schemaTopic}`, content_sha256: schema.sha256,
      schema_sha256: schema.sha256, assurance: "mirror_corroborated",
      registry_memo_temporal_scope: "current_observation",
      registry_consensus_timestamp_exact: "1792039124.000000123",
      schema: { type: "object" } });
    expect(transport.urls).toHaveLength(4);
    expect(Object.isFrozen(result)).toBe(true);
  });
  it("rejects topic substitution before reading schema content", async () => {
    const transport = await hcs13Fixture({ target: "0.0.999" });
    const result = await resolveHcs13SchemaV1(transport, { ...schemaRequest,
      expected_hcs1_reference: `hcs://1/${schemaTopic}` }, decodeOptions);
    expect(result).toMatchObject({ status: "conflict", reason_code: "HCS2_TARGET_MISMATCH" });
    expect(transport.urls).toHaveLength(2);
  });
  it("rejects a caller-expected schema hash mismatch", async () => {
    const result = await resolveHcs13SchemaV1(await hcs13Fixture(), { ...schemaRequest,
      expected_schema_sha256: "f".repeat(64) }, decodeOptions);
    expect(result).toMatchObject({ status: "conflict", reason_code: "HCS1_EXPECTED_CHECKSUM_MISMATCH" });
  });
  it("does not claim pinned canonical schema validity for a noncanonical publication", async () => {
    const raw = Buffer.from(JSON.stringify({ required: ["count"], type: "object",
      $schema: "https://json-schema.org/draft/2020-12/schema",
      properties: { count: { minimum: 0, type: "integer" } } }));
    const result = await resolveHcs13SchemaV1(await hcs13Fixture({ schemaBytes: raw }), schemaRequest, decodeOptions);
    expect(result).toMatchObject({ status: "unsupported", reason_code: "HCS13_SCHEMA_CONTENT_NOT_CANONICAL" });
  });
  it("distinguishes missing exact registry entry", async () => {
    const result = await resolveHcs13SchemaV1(await hcs13Fixture({ missing:
      `${base}/topics/${hcs13Registry}/messages/7` }), schemaRequest, decodeOptions);
    expect(result).toMatchObject({ status: "unavailable", reason_code: "HCS2_REGISTER_NOT_FOUND" });
  });
  it("rejects malformed historical sequence without reading HCS-1", async () => {
    const result = await resolveHcs13SchemaV1(await hcs13Fixture({ invalidSequence: 8 }), schemaRequest, decodeOptions);
    expect(result).toMatchObject({ status: "invalid", reason_code: "HCS2_MESSAGE_SCOPE_INVALID" });
  });
});

describe("HCS-26 historical capability version resolution", () => {
  it("resolves discovery UID -> exact version register -> integrity checked SKILL.json", async () => {
    const transport = await hcs26Fixture();
    const result = await resolveHcs26SkillVersionV1(transport, { ...skillRequest,
      expected_account_id: publisher, expected_version_topic_id: versionTopic, expected_skill_uid: 42,
      expected_version: "1.2.3", expected_manifest_sha256: manifest.sha256,
      expected_manifest_reference: `hcs://1/${manifestTopic}` }, decodeOptions);
    expect(result).toMatchObject({ status: "resolved", reason_code: null,
      skill_uid: 42, version: "1.2.3", publisher_account_id: publisher,
      version_topic_id: versionTopic, historical_version_status: "deprecated",
      manifest_reference: `hcs://1/${manifestTopic}`, manifest_sha256: manifest.sha256,
      content_sha256: manifest.sha256, manifest_files_resolution: "not_checked",
      discovery_metadata_resolution: "not_checked", assurance: "mirror_corroborated",
      registry_memo_temporal_scope: "current_observation",
      discovery_consensus_timestamp_exact: "1792039124.000000001",
      version_consensus_timestamp_exact: "1792039130.000000010" });
    expect(transport.urls).toHaveLength(6);
  });
  it("rejects caller UID conflicting with discovery sequence before any Mirror reads", async () => {
    const transport = await hcs26Fixture();
    const out = await resolveHcs26SkillVersionV1(transport, { ...skillRequest, expected_skill_uid: 9 }, decodeOptions);
    expect(out).toMatchObject({ status: "conflict", reason_code: "HCS26_SKILL_UID_MISMATCH" });
    expect(transport.urls).toHaveLength(0);
  });
  it("rejects publisher account substitution before reading version registry", async () => {
    const transport = await hcs26Fixture({ account: "0.0.777" });
    const out = await resolveHcs26SkillVersionV1(transport, { ...skillRequest,
      expected_account_id: publisher }, decodeOptions);
    expect(out).toMatchObject({ status: "conflict", reason_code: "HCS26_PUBLISHER_ACCOUNT_MISMATCH" });
    expect(transport.urls).toHaveLength(2);
  });
  it("rejects a discovery-substituted version topic before following it", async () => {
    const transport = await hcs26Fixture({ versionTopic: "0.0.6666" });
    const result = await resolveHcs26SkillVersionV1(transport, { ...skillRequest,
      expected_version_topic_id: versionTopic }, decodeOptions);
    expect(result).toMatchObject({ status: "conflict", reason_code: "HCS26_VERSION_TOPIC_MISMATCH" });
    expect(transport.urls).toHaveLength(2);
  });
  it("rejects wrong registry type memo", async () => {
    const transport = await hcs26Fixture({ versionMemo: "hcs-26:0:86400:0" });
    const out = await resolveHcs26SkillVersionV1(transport, skillRequest, decodeOptions);
    expect(out).toMatchObject({ status: "invalid", reason_code: "HCS26_REGISTRY_TYPE_MISMATCH" });
    expect(transport.urls).toHaveLength(3);
  });
  it("rejects a different skill UID in the historical version register", async () => {
    const transport = await hcs26Fixture({ skillUid: 41 });
    const out = await resolveHcs26SkillVersionV1(transport, skillRequest, decodeOptions);
    expect(out).toMatchObject({ status: "conflict", reason_code: "HCS26_SKILL_UID_MISMATCH" });
    expect(transport.urls).toHaveLength(4);
  });
  it("rejects a different requested version before HCS-1 retrieval", async () => {
    const transport = await hcs26Fixture();
    const out = await resolveHcs26SkillVersionV1(transport, { ...skillRequest, expected_version: "9.9.9" }, decodeOptions);
    expect(out).toMatchObject({ status: "conflict", reason_code: "HCS26_VERSION_MISMATCH" });
    expect(transport.urls).toHaveLength(4);
  });
  it("rejects a version-register checksum inconsistent with the fetched manifest", async () => {
    const out = await resolveHcs26SkillVersionV1(await hcs26Fixture({ checksum: "f".repeat(64) }), skillRequest, decodeOptions);
    expect(out).toMatchObject({ status: "conflict", reason_code: "HCS26_CHECKSUM_MISMATCH" });
  });
  it("does not claim pinned manifest publication for noncanonical SKILL.json bytes", async () => {
    const raw = Buffer.from(JSON.stringify({
      files: [{ path: "SKILL.md", hrl: "hcs://1/0.0.6004", sha256: "a".repeat(64), mime: "text/markdown" }],
      author: "Independent Author", license: "MIT", version: "1.2.3",
      description: "Pinned HCS-26 skill", name: "Independent agent capability",
    }));
    const out = await resolveHcs26SkillVersionV1(await hcs26Fixture({ manifestBytes: raw }), skillRequest, decodeOptions);
    expect(out).toMatchObject({ status: "unsupported", reason_code: "HCS26_MANIFEST_CONTENT_NOT_CANONICAL" });
  });
  it("preserves missing historical entries as unavailable", async () => {
    const out = await resolveHcs26SkillVersionV1(await hcs26Fixture({ missing:
      `${base}/topics/${versionTopic}/messages/3` }), skillRequest, decodeOptions);
    expect(out).toMatchObject({ status: "unavailable", reason_code: "HCS26_REGISTRY_ENTRY_NOT_FOUND" });
  });
  it("rejects untrusted URL, invalid network and unbounded expected digests before I/O", async () => {
    const transport = await hcs26Fixture();
    await expect(resolveHcs26SkillVersionV1(transport, { ...skillRequest,
      discovery_topic_id: "https://example.invalid/private" }, decodeOptions)).rejects.toThrow();
    await expect(resolveHcs26SkillVersionV1(transport, { ...skillRequest,
      hedera_network: "wrong" as "testnet" }, decodeOptions)).rejects.toThrow();
    await expect(resolveHcs26SkillVersionV1(transport, { ...skillRequest,
      expected_manifest_sha256: "invalid" }, decodeOptions)).rejects.toThrow();
    await expect(resolveHcs26SkillVersionV1({ ...transport,
      base_urls: { testnet: "http://evil.invalid/api/v1" } }, skillRequest, decodeOptions)).rejects.toThrow();
    expect(transport.urls).toHaveLength(0);
  });
});
