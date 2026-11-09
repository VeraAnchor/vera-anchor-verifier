import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as zlib from "node:zlib";
import { compress as zstdCompress, decompress as zstdDecompress } from "@mongodb-js/zstd";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  VERIFICATION_POLICY_SCHEMA_VERSION,
  assessPortableVerificationPolicyV1,
  computeExecutionDomainSeparatedSha3_512,
  verifyExecutionStandardsWithPolicyV1,
  validatePortableVerificationReportV1,
  type VerificationPolicyV1,
} from "../../src/index.js";
import { runVerifierCliV1 } from "../../src/cli/commandV1.js";
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
  const skillFile = Buffer.from("# Capability\n");
  const manifest = finalizeHcs26SkillManifestV1({ name: "Capability", description: "A capability",
    version: "1.0.0", license: "MIT", author: "Person", commit,
    files: [{ path: "SKILL.md", hrl: "hcs://1/0.0.8100",
      sha256: sha(skillFile), mime: "text/markdown" }] });

  registry(routes, "0.0.8001", 42, "hcs-26:0:86400:0",
    { p: "hcs-26", op: "register", t_id: "0.0.8002",
      account_id: "0.0.7999", metadata: "hcs://1/0.0.7998" });
  registry(routes, "0.0.8002", 3, "hcs-26:0:86400:1",
    { p: "hcs-26", op: "register", skill_uid: 42, version: "1.0.0",
      t_id: "0.0.8003", checksum: `sha256:${manifest.sha256}`, status: "active" });
  await hcs1(routes, "0.0.8003", Buffer.from(manifest.canonical_payload));
  await hcs1(routes, "0.0.8100", skillFile);

  const evidence = { available: true, contract_version: "1.0.0",
    execution: { program: "sage", job_id: JOB, proof_date: "2026-10-15", hedera_network: "testnet" },
    agents: { requester, executor },
    capability: { standard: "HCS-26", discovery_registry_topic_id: "0.0.8001",
      skill_uid: "42", skill_version: "1.0.0", version_registry_topic_id: "0.0.8002",
      version_sequence_number: 3, manifest_hcs1_ref: "hcs://1/0.0.8003",
      manifest_checksum_sha256: manifest.sha256, repository_uri: "https://github.com/example/capability",
      repository_commit: commit },
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

  return { input, evidence, routes, requests, fetch_impl };
}

/** Keep real hashing and resolver code; only the Hedera Mirror REST transport is controlled. */
function scopedInput(base: ExecutionV1Input): ExecutionV1Input {
  const digest_payload = { result: { x: 1 }, id: JOB };
  return { ...base, expected_program: "sage", evidence: {
    ...(base.evidence as Record<string, unknown>),
    binding: {
      schema: "ExecutionBindingV1", canonicalization: "RFC8785-JCS",
      digest_algorithm: "SHA3-512", domain_separator: "vera-anchor:execution-binding:v1",
      finalized_at: "2026-10-15T00:00:00Z", digest_payload,
      digest: computeExecutionDomainSeparatedSha3_512("vera-anchor:execution-binding:v1", digest_payload),
    },
  } };
}

function requirements(): VerificationPolicyV1 {
  return {
    schema_version: VERIFICATION_POLICY_SCHEMA_VERSION,
    subject: { kind: "execution", id: JOB, hedera_network: "testnet" },
    report_kind: "independent_standards",
    required_checks: ["binding.digest_recomputed", "standards.references_resolved"],
    required_assurance: ["mirror_corroboration"],
    execution_scope: { profile: "sage-standards-v1", expected_program: "sage", requested_result_id: null },
    on_unresolved: "review",
  };
}

type Fixture = Awaited<ReturnType<typeof fixture>>;

function run(f: Fixture, input: ExecutionV1Input = scopedInput(f.input), policy = requirements()) {
  return verifyExecutionStandardsWithPolicyV1(
    { fetch_impl: f.fetch_impl }, input, { decompress_zstd: decompressFixtureZstd }, policy,
  );
}

function standardContext(result: Awaited<ReturnType<typeof run>>) {
  return result.report.context.independent_standards as {
    network: string; status: string; assurance: string;
    items: Array<{ key: string; status: string; reason_code: string | null; content_sha256: string | null;
      historical_consensus_timestamps_exact: string[] }>;
  };
}

function outcome(result: Awaited<ReturnType<typeof run>>, check: string) {
  return result.report.core.findings.find((item) => item.check_id === check)?.outcome;
}

function requirement(result: Awaited<ReturnType<typeof run>>, key: string) {
  return result.policy.requirements.find((item) => item.key === key)?.outcome;
}

async function save(dir: string, name: string, value: unknown) {
  const path = join(dir, name);
  await writeFile(path, JSON.stringify(value), "utf8");
  return path;
}

async function cli(args: string[]) {
  const lines: string[] = [];
  const code = await runVerifierCliV1(args, (line) => lines.push(line));
  expect(lines).toHaveLength(1);
  return { code, body: JSON.parse(lines[0]!) as {
    result: { report?: unknown; policy?: { decision: string; authority: string }; status?: string;
      authenticity?: string; decision?: string; authority?: string };
  } };
}

afterEach(() => vi.unstubAllGlobals());

describe("SAGE independent HCS standards integration: pinned Mirror, policy and reports", () => {
  it("INT-H01 resolves the 4-reference plan through real SDK logic and grants only established policy", async () => {
    const f = await fixture();
    const result = await run(f);
    expect(result.report.kind).toBe("independent_standards");
    expect(result.report.core.findings.filter((finding) => finding.outcome === "fail")
      .map((finding) => [finding.check_id, finding.reason_code])).toEqual([]);
    expect(result.policy).toMatchObject({ decision: "allow", authority: "sdk_verification" });
    expect(outcome(result, "binding.digest_recomputed")).toBe("pass");
    expect(outcome(result, "standards.references_resolved")).toBe("pass");
    expect(requirement(result, "assurance.mirror_corroboration")).toBe("pass");
    expect(standardContext(result)).toMatchObject({
      network: "testnet", status: "verified", assurance: "mirror_corroborated",
    });
    expect(standardContext(result).items.map((item) => [item.key, item.status])).toEqual([
      ["agent:requester", "resolved"], ["agent:executor", "resolved"],
      ["capability:hcs26", "resolved"], ["schema:parameters:0", "resolved"],
    ]);
    expect(result.report.core.observations.filter((o) => o.source === "hedera_mirror")).toHaveLength(4);
    expect(validatePortableVerificationReportV1(result.report).status).toBe("valid");
    expect(f.requests.length).toBeGreaterThan(10);
    expect(f.requests.every((url) => url.startsWith(`${BASE}/`))).toBe(true);
    expect(JSON.stringify(result.report)).not.toContain("A capability");
  });

  it("INT-H02 binds HCS-11 profiles and HCS-14 UAIDs, without claiming unsupported authentication", async () => {
    const f = await fixture();
    f.routes[`${BASE}/accounts/0.0.7101`] = { account: "0.0.7101", memo: "hcs-11:hcs://1/0.0.7201" };
    const result = await run(f);
    expect(standardContext(result).items.slice(0, 2).map((item) => item.status)).toEqual(["resolved", "resolved"]);
    expect(standardContext(result).items[0]?.historical_consensus_timestamps_exact).toEqual(["1792039124.000000001"]);
    expect(f.requests).toContain(`${BASE}/topics/0.0.7001/messages/1`);
    expect(f.requests.filter((url) => url === `${BASE}/accounts/0.0.7101`)).toHaveLength(2);
    expect(result.policy.decision).toBe("allow");
    expect(JSON.stringify(result.report)).not.toContain("did_controller_authentication");
    expect(JSON.stringify(result.report)).not.toContain("hedera_consensus_authentication");
    expect(JSON.stringify(result.report)).not.toContain("historical_account_memo_binding");
  });

  it("INT-H03 enforces exact historical HCS-2 registrations; no later or latest substitution", async () => {
    const f = await fixture();
    registry(f.routes, "0.0.9001", 8, "hcs-2:0:86400",
      { p: "hcs-2", op: "register", t_id: "0.0.9999" });
    const resolved = await run(f);
    expect(standardContext(resolved).status).toBe("verified");
    expect(outcome(resolved, "standards.references_resolved")).toBe("pass");
    expect(resolved.report.core.findings.filter((finding) => finding.outcome === "fail")
      .map((finding) => [finding.check_id, finding.reason_code])).toEqual([]);
    expect(resolved.policy.decision).toBe("allow");
    expect(f.requests).toContain(`${BASE}/topics/0.0.9001/messages/7`);
    expect(f.requests).not.toContain(`${BASE}/topics/0.0.9001/messages/8`);
    expect(f.requests.every((url) => !url.includes("latest"))).toBe(true);

    const bad = await fixture();
    bad.routes[`${BASE}/accounts/0.0.7101`] = { account: "0.0.7101", memo: "hcs-11:hcs://1/0.0.7201" };
    registry(bad.routes, "0.0.7001", 1, "hcs-2:0:86400",
      { p: "hcs-2", op: "register", t_id: "0.0.9999" });
    const rejected = await run(bad);
    expect(standardContext(rejected).items[0]?.status).toBe("conflict");
    expect(outcome(rejected, "standards.references_resolved")).toBe("fail");
    expect(rejected.policy.decision).toBe("deny");
  });

  it("INT-H04 checks pinned HCS-13 schemas, HCS-26 skill versions and declared manifest files", async () => {
    const f = await fixture();
    const result = await run(f);
    const items = standardContext(result).items;
    expect(items[2]).toMatchObject({ key: "capability:hcs26", status: "resolved" });
    expect(items[3]).toMatchObject({ key: "schema:parameters:0", status: "resolved" });
    expect(items[2]?.historical_consensus_timestamps_exact).toEqual([
      "1792039124.000000042", "1792039124.000000003",
    ]);
    expect(items[3]?.historical_consensus_timestamps_exact).toEqual(["1792039124.000000007"]);
    expect(items[2]?.content_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(items[3]?.content_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(f.requests).toContain(`${BASE}/topics/0.0.8002/messages/3`);
    expect(f.requests).toContain(`${BASE}/topics/0.0.8100`);
    expect(f.requests).toContain(`${BASE}/topics/0.0.8100/messages?limit=100&order=asc`);

    const bad = await fixture();
    await hcs1(bad.routes, "0.0.8100", Buffer.from("# Substituted capability\n"));
    const rejected = await run(bad);
    expect(standardContext(rejected).status).toBe("failed");
    expect(standardContext(rejected).items[2]).toMatchObject({
      key: "capability:hcs26", status: "conflict",
      reason_code: "HCS26_MANIFEST_FILE_CHECKSUM_MISMATCH",
    });
    expect(outcome(rejected, "standards.references_resolved")).toBe("fail");
    expect(rejected.policy.decision).toBe("deny");
  });

  it("INT-H05 rejects HCS-1 checksum contradictions after actual compressed-content verification", async () => {
    const f = await fixture();
    f.routes[`${BASE}/topics/0.0.9002`] = { ...(f.routes[`${BASE}/topics/0.0.9002`] as object),
      memo: `${"0".repeat(64)}:zstd:base64` };
    const result = await run(f);
    expect(standardContext(result).status).toBe("failed");
    expect(standardContext(result).items[3]?.status).not.toBe("resolved");
    expect(outcome(result, "standards.references_resolved")).toBe("fail");
    expect(requirement(result, "check.standards.references_resolved")).toBe("fail");
    expect(result.policy.decision).toBe("deny");
    expect(validatePortableVerificationReportV1(result.report).status).toBe("valid");
  });

  it("INT-H06 rejects independent schema and skill substitutions despite producer success claims", async () => {
    for (const kind of ["schema", "skill"] as const) {
      const f = await fixture();
      const evidence = structuredClone(f.evidence);
      if (kind === "schema") evidence.standards.schemas[0]!.schema_checksum_sha256 = "c".repeat(64);
      else evidence.capability.repository_commit = "c".repeat(40);
      const input: ExecutionV1Input = { ...scopedInput(f.input), evidence: {
        ...evidence, binding: (scopedInput(f.input).evidence as { binding: unknown }).binding,
      }, verification_material: { standards_resolution: {
        schema_version: "vera.standards-resolution.v1", hedera_network: "testnet", state: "verified", items: [],
      } } };
      const result = await run(f, input);
      expect(standardContext(result).status, kind).toBe("failed");
      expect(standardContext(result).items[kind === "schema" ? 3 : 2]?.status, kind).toBe("conflict");
      expect(outcome(result, "standards.references_resolved"), kind).toBe("fail");
      expect(result.policy.decision, kind).toBe("deny");
    }
  });

  it("INT-H07 retains missing evidence as unresolved and rejects invalid preflight scope without I/O", async () => {
    const f = await fixture();
    delete f.routes[`${BASE}/accounts/0.0.7101`];
    const missing = await run(f);
    expect(standardContext(missing).status).toBe("unavailable");
    expect(standardContext(missing).items[0]?.status).toBe("unavailable");
    expect(outcome(missing, "standards.references_resolved")).toBe("indeterminate");
    expect(requirement(missing, "check.standards.references_resolved")).toBe("unresolved");
    expect(requirement(missing, "assurance.mirror_corroboration")).toBe("unresolved");
    expect(missing.policy.decision).not.toBe("allow");

    const preflight = await fixture();
    const evidence = structuredClone(preflight.evidence);
    evidence.execution.hedera_network = "mainnet";
    const denied = await run(preflight, { ...scopedInput(preflight.input), evidence });
    expect(standardContext(denied).status).toBe("not_performed");
    expect(preflight.requests).toHaveLength(0);
    expect(denied.policy.decision).not.toBe("allow");
  });

  it("INT-H08 exports a CLI report, validates integrity and never authenticates a reloaded report", async () => {
    const f = await fixture();
    const dir = await mkdtemp(join(tmpdir(), "va-hcs-standards-int-"));
    try {
      vi.stubGlobal("fetch", f.fetch_impl);
      const input = scopedInput(f.input);
      const evidencePath = await save(dir, "evidence.json", input.evidence);
      const intentPath = await save(dir, "intent.json", input.intent);
      const policyPath = await save(dir, "policy.json", requirements());
      const reportPath = join(dir, "standards-report.json");
      const verified = await cli(["verify", "standards", "--evidence", evidencePath,
        "--intent", intentPath, "--policy", policyPath, "--mirror-url", BASE,
        "--report-out", reportPath]);

      const nativeZstd = typeof (zlib as unknown as {
        zstdDecompressSync?: unknown;
      }).zstdDecompressSync === "function";
      expect(verified.body.result.report).toMatchObject({ kind: "independent_standards" });

      if (nativeZstd) {
        expect(verified.code).toBe(0);
        expect(verified.body.result.policy).toMatchObject({
          decision: "allow", authority: "sdk_verification",
        });
      } else {
        expect(verified.body.result.policy?.decision).not.toBe("allow");
        expect([1, 2]).toContain(verified.code);
      }

      const saved = JSON.parse(await readFile(reportPath, "utf8"));
      expect(saved).toEqual(verified.body.result.report);
      expect(validatePortableVerificationReportV1(saved).status).toBe("valid");
      const checked = await cli(["report", "validate", "--report", reportPath]);
      expect(checked.code).toBe(0);
      expect(checked.body.result).toMatchObject({ status: "valid", authenticity: "not_checked" });
      const assessed = await cli(["policy", "assess", "--report", reportPath, "--policy", policyPath]);
      expect(assessed.body.result).toMatchObject({ authority: "unauthenticated_report" });
      expect(assessed.body.result.decision).not.toBe("allow");
      expect(assessed.code).not.toBe(0);
      expect(assessPortableVerificationPolicyV1(saved, requirements()).decision).not.toBe("allow");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});