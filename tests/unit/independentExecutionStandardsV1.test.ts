
import { createHash } from "node:crypto";
import { compress as zstdCompress, decompress as zstdDecompress } from "@mongodb-js/zstd";
import { describe, expect, it } from "vitest";
import { verifyExecutionWithIndependentStandardsV1 } from "../../src/profiles/execution/independentStandardsV1.js";
import { buildHcs14DidUaidV1 } from "../../src/standards/hcs/hcs14V1.js";
import { canonicalHcsJsonV1 } from "../../src/standards/hcs/jsonCanonicalV1.js";
import { finalizeHcs13SchemaV1 } from "../../src/standards/hcs/hcs13V1.js";
import { finalizeHcs26SkillManifestV1 } from "../../src/standards/hcs/hcs26V1.js";

import type { ExecutionV1Input } from "../../src/profiles/execution/verificationV1.js";

const BASE = "https://testnet.mirrornode.hedera.com/api/v1";
const JOB = "f365ad8e-bf03-5654-8b8c-9d54eddffac1";
const sha = (value: string | Uint8Array) => createHash("sha256").update(value).digest("hex");
const b64 = (value: string | Uint8Array) => Buffer.from(value).toString("base64");

async function decompressFixtureZstd(compressed: Uint8Array, maxOutputBytes: number): Promise<Uint8Array> {
  const decoded = await zstdDecompress(Buffer.from(compressed));
  if (decoded.byteLength > maxOutputBytes) throw new RangeError("HCS1_FILE_TOO_LARGE");
  return decoded;
}

type Routes = Record<string, unknown>;

async function hcs1(routes: Routes, topic: string, raw: Uint8Array): Promise<void> {
  const compressed = await zstdCompress(Buffer.from(raw), 10);
  const payload = Buffer.from(JSON.stringify({ o: 0,
    c: `data:application/json;base64,${b64(compressed)}` }));
  routes[`${BASE}/topics/${topic}`] = { topic_id: topic,
    memo: `${sha(raw)}:zstd:base64`, submit_key: { key: "present" }, admin_key: null };
  routes[`${BASE}/topics/${topic}/messages?limit=100&order=asc`] = {
    messages: [{ topic_id: topic, sequence_number: 1, message: b64(payload) }], links: { next: null },
  };
}

function registry(routes: Routes, topic: string, seq: number, memo: string, message: object): void {
  routes[`${BASE}/topics/${topic}`] = { topic_id: topic, memo };
  routes[`${BASE}/topics/${topic}/messages/${seq}`] = {
    topic_id: topic, sequence_number: seq,
    consensus_timestamp: `1792039124.${String(seq).padStart(9, "0")}`,
    message: b64(JSON.stringify(message)),
  };
}

async function fixture() {
  const routes: Routes = {};
  const requests: string[] = [];
  async function agent(i: 1 | 2) {
    const account = `0.0.${7100 + i}`;
    const registryTopic = `0.0.${7000 + i}`;
    const profileTopic = `0.0.${7200 + i}`;
    const did = `did:web:agent${i}.example.org`;
    const uaid = buildHcs14DidUaidV1({ base_did: did, uid: `agent${i}`,
      proto: "hcs-26", native_id: `hedera:testnet:${account}` }).uaid;
    const profile = canonicalHcsJsonV1({ version: "1.1", type: 1,
      display_name: `Agent ${i}`, uaid,
      aiAgent: { type: 1, capabilities: [0], model: "agent" } }, 128 * 1024);
    routes[`${BASE}/accounts/${account}`] = { account, memo: `hcs-11:hcs://2/${registryTopic}` };
    registry(routes, registryTopic, 1, "hcs-2:0:86400",
      { p: "hcs-2", op: "register", t_id: profileTopic });
    await hcs1(routes, profileTopic, Buffer.from(profile));
    return { logical_id: `agent${i}`, base_did: did, hcs14_uaid: uaid,
      hcs11: { account_id: account, profile_registry_topic_id: registryTopic,
        profile_registry_sequence: 1, profile_hcs1_ref: `hcs://1/${profileTopic}`,
        profile_checksum_sha256: sha(profile) } };
  }
  const requester = await agent(1);
  const executor = await agent(2);
  const schema = finalizeHcs13SchemaV1({ type: "object", properties: { value: { type: "integer" } } });
  registry(routes, "0.0.9001", 7, "hcs-2:0:86400",
    { p: "hcs-2", op: "register", t_id: "0.0.9002" });
  await hcs1(routes, "0.0.9002", Buffer.from(schema.canonical_payload));
  const commit = "a".repeat(40);
  const manifest = finalizeHcs26SkillManifestV1({ name: "Capability", description: "A capability",
    version: "1.0.0", license: "MIT", author: "Person", commit,
    files: [{ path: "SKILL.md", hrl: "hcs://1/0.0.8100",
      sha256: "b".repeat(64), mime: "text/markdown" }] });
  registry(routes, "0.0.8001", 42, "hcs-26:0:86400:0",
    { p: "hcs-26", op: "register", t_id: "0.0.8002",
      account_id: "0.0.7999", metadata: "hcs://1/0.0.7998" });
  registry(routes, "0.0.8002", 3, "hcs-26:0:86400:1",
    { p: "hcs-26", op: "register", skill_uid: 42, version: "1.0.0",
      t_id: "0.0.8003", checksum: `sha256:${manifest.sha256}`, status: "active" });
  await hcs1(routes, "0.0.8003", Buffer.from(manifest.canonical_payload));
  const evidence = { available: true, contract_version: "1.0.0",
    execution: { program: "sage", job_id: JOB, hedera_network: "testnet" },
    agents: { requester, executor },
    capability: { standard: "HCS-26", discovery_registry_topic_id: "0.0.8001",
      skill_uid: "42", skill_version: "1.0.0", version_registry_topic_id: "0.0.8002",
      version_sequence_number: 3, manifest_hcs1_ref: "hcs://1/0.0.8003",
      manifest_checksum_sha256: manifest.sha256, repository_commit: commit },
    standards: { schemas: [{ role: "parameters", ordinal: 0, registry_topic_id: "0.0.9001",
      registry_sequence_number: 7, hcs13_ref: "hcs://13/0.0.9001#7",
      schema_checksum_sha256: schema.sha256 }] },
  };
  const input: ExecutionV1Input = { profile: "sage-standards-v1", evidence,
    intent: { subject: { kind: "execution", id: JOB, hedera_network: "testnet" }, expected: [] } };
  const fetch_impl = (async (url: string | URL | Request) => {
    const key = String(url);
    requests.push(key);
    if (!Object.hasOwn(routes, key)) return new Response(null, { status: 404 });
    return Response.json(routes[key]);
  }) as typeof fetch;
  return { input, evidence, routes, requests, fetch_impl,
    verify: (value: ExecutionV1Input = input) =>
      verifyExecutionWithIndependentStandardsV1({ fetch_impl }, value, {
        decompress_zstd: decompressFixtureZstd,
      }) };
}

describe("independent SAGE standards integration", () => {

  it("verifies the exact 2-agent, 1-capability, 1-schema plan with bounded Mirror reads", async () => {
    const f = await fixture();
    const report = await f.verify();
    expect(report.independent_standards.status).toBe("verified");
    expect(report.independent_standards.items.map((x) => x.status)).toEqual([
      "resolved", "resolved", "resolved", "resolved",
    ]);
    expect(report.findings.find((x) => x.check_id === "standards.references_resolved")?.outcome).toBe("pass");
    expect(report.findings.filter((x) => /^standards\.reference\.\d+$/.test(x.check_id))).toHaveLength(4);
    expect(report.independent_standards.did_controller_authentication).toBe("not_checked");
    expect(report.independent_standards.hedera_consensus_authentication).toBe("not_checked");
    expect(report.independent_standards.historical_account_memo_binding).toBe("not_checked");
    expect(report.independent_standards.manifest_files_resolution).toBe("not_checked");
    expect(report.independent_standards.json_schema_instance_validation).toBe("not_checked");
    expect(report.observations.filter((x) => x.source === "hedera_mirror")).toHaveLength(4);
    expect(JSON.stringify(report)).not.toContain("A capability");
    expect(f.requests.length).toBeGreaterThan(10);
  });

  it("accepts an HCS-1-direct account memo only after separately checking its historical HCS-2 entry", async () => {
    const f = await fixture();
    f.routes[`${BASE}/accounts/0.0.7101`] = {
      account: "0.0.7101", memo: "hcs-11:hcs://1/0.0.7201",
    };
    const report = await f.verify();
    expect(report.independent_standards.status).toBe("verified");
    expect(report.independent_standards.items[0]?.historical_consensus_timestamps_exact).toEqual([
      "1792039124.000000001",
    ]);
    expect(f.requests.filter((x) => x === `${BASE}/accounts/0.0.7101`)).toHaveLength(2);
    expect(f.requests.some((x) => x === `${BASE}/topics/0.0.7001/messages/1`)).toBe(true);
  });

  it("rejects a direct-memo profile when the historical HCS-2 registration points elsewhere", async () => {
    const f = await fixture();
    f.routes[`${BASE}/accounts/0.0.7101`] = {
      account: "0.0.7101", memo: "hcs-11:hcs://1/0.0.7201",
    };
    f.routes[`${BASE}/topics/0.0.7001/messages/1`] = {
      topic_id: "0.0.7001", sequence_number: 1,
      consensus_timestamp: "1792039124.000000001",
      message: b64(JSON.stringify({ p: "hcs-2", op: "register", t_id: "0.0.9999" })),
    };
    const report = await f.verify();
    expect(report.independent_standards.items[0]?.status).toBe("conflict");
    expect(report.independent_standards.status).toBe("failed");
  });

  it("does not elevate supplied standards_resolution or hide a schema checksum conflict", async () => {
    const f = await fixture();
    const evidence = structuredClone(f.evidence);
    evidence.standards.schemas[0]!.schema_checksum_sha256 = "c".repeat(64);
    const report = await f.verify({ ...f.input, evidence,
      verification_material: { standards_resolution: { schema_version: "vera.standards-resolution.v1",
        hedera_network: "testnet", state: "verified", items: [] } } });
    expect(report.independent_standards.status).toBe("failed");
    expect(report.independent_standards.items.at(-1)?.status).toBe("conflict");
    expect(report.findings.find((x) => x.check_id === "standards.references_resolved")?.outcome).toBe("fail");
  });

  it("does no network I/O when the caller demands a different program", async () => {
    const f = await fixture();
    const report = await f.verify({ ...f.input, expected_program: "other" });
    expect(report.independent_standards.status).toBe("not_performed");
    expect(f.requests).toHaveLength(0);
  });

  it("does no network I/O for wrong-network or wrong-job execution claims", async () => {
    const f = await fixture();
    for (const mutation of [
      { ...f.evidence.execution, hedera_network: "mainnet" },
      { ...f.evidence.execution, job_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" },
    ]) {
      const report = await f.verify({ ...f.input,
        evidence: { ...f.evidence, execution: mutation } });
      expect(report.independent_standards.status).toBe("not_performed");
    }
    expect(f.requests).toHaveLength(0);
  });

  it("rejects an HCS-13 topic/sequence disagreement without following the bad reference", async () => {
    const f = await fixture();
    const evidence = structuredClone(f.evidence);
    evidence.standards.schemas[0]!.registry_sequence_number = 8;
    const report = await f.verify({ ...f.input, evidence });
    expect(report.independent_standards.items.at(-1)?.status).toBe("conflict");
    expect(report.independent_standards.items.at(-1)?.reason_code).toBe("HCS13_EXECUTION_REFERENCE_SCOPE_MISMATCH");
    expect(f.requests.some((x) => x.includes("/topics/0.0.9001"))).toBe(false);
  });

  it("fails closed on missing version locator and does not visit the version registry", async () => {
    const f = await fixture();
    const evidence = structuredClone(f.evidence);
    delete (evidence.capability as { version_sequence_number?: number }).version_sequence_number;
    const report = await f.verify({ ...f.input, evidence });
    expect(report.independent_standards.status).toBe("failed");
    expect(report.independent_standards.items[2]?.reason_code).toBe("HCS26_EXECUTION_REFERENCE_INVALID");
    expect(f.requests.some((x) => x.includes("/topics/0.0.8002"))).toBe(false);
  });

  it("rejects duplicate schema keys before any network read", async () => {
    const f = await fixture();
    const evidence = structuredClone(f.evidence);
    evidence.standards.schemas.push({ ...evidence.standards.schemas[0]! });
    const report = await f.verify({ ...f.input, evidence });
    expect(report.independent_standards.status).toBe("not_performed");
    expect(f.requests).toHaveLength(0);
  });

  it("reports missing current account as unavailable, never verified", async () => {
    const f = await fixture();
    delete f.routes[`${BASE}/accounts/0.0.7101`];
    const report = await f.verify();
    expect(report.independent_standards.items[0]?.status).toBe("unavailable");
    expect(report.independent_standards.status).toBe("unavailable");
  });

  it("rejects a conflicting SKILL.json release commit", async () => {
    const f = await fixture();
    const evidence = structuredClone(f.evidence);
    evidence.capability.repository_commit = "c".repeat(40);
    const report = await f.verify({ ...f.input, evidence });
    expect(report.independent_standards.items[2]?.reason_code).toBe("HCS26_EXECUTION_RELEASE_COMMIT_MISMATCH");
    expect(report.independent_standards.items[2]?.status).toBe("conflict");
    expect(report.independent_standards.status).toBe("failed");
  });

  it("does not accept generic execution profiles through standards resolution", async () => {
    const f = await fixture();
    await expect(f.verify({ ...f.input, profile: "execution-v1",
      expected_program: "other" })).rejects.toThrow("sage-standards-v1");
    expect(f.requests).toHaveLength(0);
  });
});
