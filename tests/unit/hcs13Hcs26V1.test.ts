import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { buildHcs13ReferenceV1, parseHcs13ReferenceV1, finalizeHcs13SchemaV1,
  parseHcs13SchemaV1, verifyHcs13SchemaV1 } from "../../src/standards/hcs/hcs13V1.js";
import { parseHcs26MemoV1, parseHcs26DiscoveryRegisterV1, parseHcs26DiscoveryUpdateV1,
  parseHcs26VersionRegisterV1, finalizeHcs26SkillManifestV1, parseHcs26SkillManifestV1,
  verifyHcs26SkillVersionV1 } from "../../src/standards/hcs/hcs26V1.js";

const A = "a".repeat(64);
const B = "b".repeat(64);
const COMMIT = "c".repeat(40);
const schema = () => ({
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://veraanchor.ai/schemas/sage-parameters-v1.json",
  title: "SAGE Parameters V1", type: "object", additionalProperties: false,
  properties: { iterations: { type: "integer", minimum: 1 }, seed: { type: "integer", minimum: 0 },
    temperature: { type: "number", minimum: 0 } }, required: ["iterations", "seed"],
});
const schemaSha = "47609d2a1c1777932ece21aaf0deea00625a2d4072e559b4e3a728e30d5284f2";
const manifest = () => ({
  name: "SAGE Verifiable Compute",
  description: "Execute deterministic SAGE scientific workloads with Vera Anchor provenance.",
  version: "1.0.0", license: "Apache-2.0",
  author: { name: "Vera Anchor", contact: "engineering@veraanchor.ai", url: "https://veraanchor.ai" },
  tags: [1403, 50401, 1403], languages: ["javascript", "python"],
  homepage: "https://veraanchor.ai/sage", repo: "https://github.com/veraanchor/sage", commit: COMMIT,
  entrypoints: [{ path: "scripts/run.js", language: "javascript", args: ["--deterministic"] }],
  files: [{ path: "scripts/run.js", hrl: "hcs://1/0.0.55555", sha256: B, mime: "application/javascript" },
    { path: "SKILL.md", hrl: "hcs://1/0.0.44444", sha256: A.toUpperCase(), mime: "text/markdown" }],
});
const manifestSha = "cbf649819f4269e9a60f2222aebde24ac3babb28e36ee51f83a7ed808a9953a6";
const versionRegister = (fields: Record<string, unknown> = {}) => JSON.stringify({
  p: "hcs-26", op: "register", skill_uid: 42, version: "1.0.0", t_id: "0.0.33333",
  checksum: `sha256:${manifestSha}`, status: "active", ...fields,
});

describe("HCS-13 pinned schema verification (offline)", () => {
  it("parses exact historical refs and rejects noncanonical sequences", () => {
    expect(buildHcs13ReferenceV1(" 0.0.5001 ", "007")).toBe("hcs://13/0.0.5001#7");
    expect(parseHcs13ReferenceV1("hcs://13/0.0.5001#7")).toEqual({
      ref: "hcs://13/0.0.5001#7", registry_topic_id: "0.0.5001", sequence_number: 7,
    });
    for (const ref of ["hcs://13/0.0.5001", "hcs://13/0.0.5001#latest", "hcs://13/0.0.5001#01", "hcs://13/1.0.5001#1"]) {
      expect(() => parseHcs13ReferenceV1(ref)).toThrow();
    }
  });
  it("matches the frozen HCS-13 canonical byte length and SHA-256", () => {
    const computed = finalizeHcs13SchemaV1(schema());
    expect(computed.byte_length).toBe(368);
    expect(computed.sha256).toBe(schemaSha);
    expect(createHash("sha256").update(computed.canonical_payload).digest("hex")).toBe(schemaSha);
    expect(parseHcs13SchemaV1(JSON.stringify(schema())).sha256).toBe(schemaSha);
  });
  it("compares independently supplied reference and checksum expectations", () => {
    const evidence = { reference: "hcs://13/0.0.5001#7", schema: JSON.stringify(schema()),
      expected_registry_topic_id: "0.0.5001", expected_sequence_number: 7, expected_sha256: schemaSha };
    expect(verifyHcs13SchemaV1(evidence)).toMatchObject({ status: "pass", checksum_match: "match" });
    expect(verifyHcs13SchemaV1({ ...evidence, expected_sha256: A })).toMatchObject({ status: "fail", checksum_match: "mismatch", reason_code: "HCS13_CHECKSUM_MISMATCH" });
    expect(verifyHcs13SchemaV1({ ...evidence, expected_sequence_number: 8 })).toMatchObject({ status: "fail", reason_code: "HCS13_SEQUENCE_MISMATCH" });
    expect(verifyHcs13SchemaV1({ reference: evidence.reference, schema: evidence.schema })).toMatchObject({ status: "pass", checksum_match: "not_checked" });
  });
  it("rejects duplicate and escaped duplicate JSON keys before hashing", () => {
    for (const raw of ['{"type":"object","type":"array"}', '{"type":"object","t\\u0079pe":"array"}']) {
      expect(() => parseHcs13SchemaV1(raw)).toThrow();
    }
  });
  it("does not evaluate JSON Schema validity or claim remote registry authority", () => {
    expect(finalizeHcs13SchemaV1({ $schema: "urn:unknown", foo: 1 }).sha256).toHaveLength(64);
    expect(verifyHcs13SchemaV1({ reference: "hcs://13/0.0.5001#7", schema: "{}" })).toMatchObject({ status: "pass", checksum_match: "not_checked" });
  });
  it("preserves schema array order and rejects malformed I-JSON content", () => {
    const first = finalizeHcs13SchemaV1(schema());
    const reordered = schema();
    reordered.required.reverse();
    expect(finalizeHcs13SchemaV1(reordered).sha256).not.toBe(first.sha256);
    expect(() => finalizeHcs13SchemaV1({ bad: undefined })).toThrow();
    expect(() => finalizeHcs13SchemaV1({ bad: "\ud800" })).toThrow();
    expect(() => parseHcs13SchemaV1('{"type":')).toThrow();
  });
  it("preserves exactly the pinned 512KiB canonical byte ceiling", () => {
    expect(finalizeHcs13SchemaV1({ payload: "x".repeat(524_274) }).byte_length).toBe(524_288);
    expect(() => finalizeHcs13SchemaV1({ payload: "x".repeat(524_275) })).toThrow();
  });
});

describe("HCS-26 pinned skill and registry verification (offline)", () => {
  it("parses pinned discovery/version topic memo variants", () => {
    expect(parseHcs26MemoV1("hcs-26:0:86400:0")).toMatchObject({ indexed: true, ttl: 86400, type: "discovery" });
    expect(parseHcs26MemoV1("hcs-26:1:0:1")).toMatchObject({ indexed: false, ttl: 0, type: "version" });
    expect(() => parseHcs26MemoV1("hcs-26:0:86400:2")).toThrow();
  });
  it("parses discovery registration, account/metadata update, and version registration", () => {
    expect(parseHcs26DiscoveryRegisterV1(JSON.stringify({ p: "hcs-26", op: "register", t_id: "0.0.234567", account_id: "0.0.78910", metadata: "hcs://1/0.0.22222" })))
      .toMatchObject({ t_id: "0.0.234567", account_id: "0.0.78910", metadata: "hcs://1/0.0.22222" });
    expect(parseHcs26DiscoveryUpdateV1(JSON.stringify({ p: "hcs-26", op: "update", uid: "42", metadata: { name: "Updated" } })))
      .toMatchObject({ uid: "42", metadata: { name: "Updated" } });
    expect(parseHcs26VersionRegisterV1(versionRegister({ checksum: manifestSha })))
      .toMatchObject({ checksum: `sha256:${manifestSha}`, status: "active", skill_uid: 42 });
  });
  it("rejects unsupported discovery operations and invalid wire shape", () => {
    expect(() => parseHcs26DiscoveryRegisterV1('{"p":"hcs-26","op":"delete"}')).toThrow();
    expect(() => parseHcs26DiscoveryUpdateV1('{"p":"hcs-26","op":"update","uid":"42"}')).toThrow();
    expect(() => parseHcs26VersionRegisterV1(versionRegister({ extra: true }))).toThrow();
    expect(() => parseHcs26VersionRegisterV1(versionRegister({ checksum: "A".repeat(64) }))).toThrow();
  });
  it("reports oversize wire messages as bounded-input failures", () => {
    expect(() => parseHcs26VersionRegisterV1(JSON.stringify({ p: "hcs-26", op: "register",
      skill_uid: 42, version: "1.0.0", t_id: "0.0.33333", checksum: A, m: "x".repeat(950) }))).toThrow("HCS26_MESSAGE_TOO_LARGE");
  });
  it("recomputes the frozen 868-byte SKILL.json and SHA-256 vector", () => {
    const value = finalizeHcs26SkillManifestV1(manifest());
    expect(value.byte_length).toBe(868);
    expect(value.sha256).toBe(manifestSha);
    expect(createHash("sha256").update(value.canonical_payload).digest("hex")).toBe(manifestSha);
    expect(parseHcs26SkillManifestV1(JSON.stringify(manifest())).sha256).toBe(manifestSha);
  });
  it("verifies version register checksum, version and explicit caller expectations", () => {
    const evidence = { version_register: versionRegister(), manifest: JSON.stringify(manifest()),
      expected_skill_uid: 42, expected_manifest_topic_id: "0.0.33333", expected_version: "1.0.0", expected_sha256: manifestSha };
    expect(verifyHcs26SkillVersionV1(evidence)).toMatchObject({ status: "pass", checksum_match: "match", version_status: "active" });
    expect(verifyHcs26SkillVersionV1({ ...evidence, expected_skill_uid: 41 })).toMatchObject({ status: "fail", reason_code: "HCS26_SKILL_UID_MISMATCH" });
    expect(verifyHcs26SkillVersionV1({ ...evidence, version_register: versionRegister({ checksum: A }) }))
      .toMatchObject({ status: "fail", reason_code: "HCS26_CHECKSUM_MISMATCH", checksum_match: "mismatch" });
    expect(verifyHcs26SkillVersionV1({ ...evidence, version_register: versionRegister({ version: "2.0.0" }) }))
      .toMatchObject({ status: "fail", reason_code: "HCS26_VERSION_MISMATCH" });
  });
  it("preserves historical status without interpreting deprecated/yanked as current approval", () => {
    expect(verifyHcs26SkillVersionV1({ version_register: versionRegister({ status: "yanked" }),
      manifest: JSON.stringify(manifest()) })).toMatchObject({ status: "pass", version_status: "yanked" });
  });
  it("rejects traversal, duplicate paths, missing SKILL.md, unsupported fields and malformed HCS-1 refs", () => {
    const base = manifest();
    expect(() => finalizeHcs26SkillManifestV1({ ...base, files: base.files.map((f) => ({ ...f, path: "../SKILL.md" })) })).toThrow();
    expect(() => finalizeHcs26SkillManifestV1({ ...base, files: [base.files[1], base.files[1]] })).toThrow();
    expect(() => finalizeHcs26SkillManifestV1({ ...base, files: [base.files[0]] })).toThrow();
    expect(() => finalizeHcs26SkillManifestV1({ ...base, files: [{ ...base.files[1], hrl: "https://example.com" }] })).toThrow();
    expect(() => finalizeHcs26SkillManifestV1({ ...base, extra: 42 })).toThrow();
  });
  it("rejects ambiguous duplicate keys, malformed and oversized manifests", () => {
    expect(() => parseHcs26SkillManifestV1('{"name":"a","name":"b"}')).toThrow();
    expect(() => parseHcs26VersionRegisterV1('{"p":"hcs-26","op":"register","op":"update"}')).toThrow();
    expect(() => parseHcs26SkillManifestV1("not-json")).toThrow();
    expect(() => finalizeHcs26SkillManifestV1({ ...manifest(), entrypoints: ["x".repeat(300 * 1024)] })).toThrow();
  });
});
