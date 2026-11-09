import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
  VERIFICATION_POLICY_SCHEMA_VERSION,
  assessPortableVerificationPolicyV1,
  sha3_512Hex,
  triangulateIngestWithPolicyV1,
  validatePortableVerificationReportV1,
  verifyIngestV1Pair,
  verifyIngestWithPolicyV1,
  type VerificationPolicyV1,
} from "../../src/index.js";
import { runVerifierCliV1 } from "../../src/cli/commandV1.js";

type FileMaterial = Readonly<{ path_rel: string; content_base64: string }>;
type IngestMaterial =
  | Readonly<{ kind: "json"; value: unknown }>
  | Readonly<{ kind: "text"; text: string; media_type?: string }>
  | Readonly<{ kind: "file"; file: FileMaterial }>
  | Readonly<{ kind: "file_set"; files: readonly FileMaterial[] }>;
type IngestCase = Readonly<{
  case_id: string;
  bundle: unknown;
  hash_only_receipt: unknown;
  bundle_expectations: Readonly<{
    fingerprint: string;
    bundle_digest: string;
    merkle_root: string;
  }>;
}>;
type Fixtures = Readonly<{
  cases: readonly IngestCase[];
  materials: Readonly<Record<string, IngestMaterial>>;
}>;
type IngestInput = Parameters<typeof verifyIngestWithPolicyV1>[0];
type TransportState = "consistent" | "unavailable" | "conflict" | "wrong_anchor" | "wrong_network";

const EXPLORER = "https://explorer.example.test";
const MIRROR = "https://mirror.example.test/api/v1";
const ANCHOR = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const TOPIC = "0.0.12345";
const TX = "0.0.77@1234567890.123456789";
const MESSAGE = Buffer.from("encrypted-publication-envelope", "utf8");
const MESSAGE_DIGEST = sha3_512Hex(MESSAGE);

async function fixtures(): Promise<Fixtures> {
  const [vectors, sources] = await Promise.all([
    readFile(new URL("../unit/fixtures/ingestV1SelectedVectors.json", import.meta.url), "utf8"),
    readFile(new URL("../unit/fixtures/sourceV1Materials.json", import.meta.url), "utf8"),
  ]);
  return {
    cases: (JSON.parse(vectors) as { cases: IngestCase[] }).cases,
    materials: (JSON.parse(sources) as { ingest: Record<string, IngestMaterial> }).ingest,
  };
}

function selected(all: Fixtures, id: string): IngestCase {
  const entry = all.cases.find((item) => item.case_id === id);
  if (!entry || !all.materials[id]) throw new Error(`Missing Ingest fixture: ${id}`);
  return entry;
}

function sourceMaterial(value: IngestMaterial, tamper = false): IngestInput["material"] {
  if (value.kind === "json") return {
    kind: "json", value: tamper ? { changed: true } : structuredClone(value.value),
  };
  if (value.kind === "text") return {
    kind: "text", text: tamper ? `${value.text}tampered` : value.text,
    ...(value.media_type === undefined ? {} : { media_type: value.media_type }),
  };
  if (value.kind === "file") return {
    kind: "file", file: {
      path_rel: value.file.path_rel,
      source: [tamper ? Buffer.from("modified-ingest-file") : Buffer.from(value.file.content_base64, "base64")],
    },
  };
  return {
    kind: "file_set",
    files: value.files.map((file, index) => ({
      path_rel: file.path_rel,
      source: [tamper && index === 0 ? Buffer.from("modified-ingest-file-set") :
        Buffer.from(file.content_base64, "base64")],
    })),
  };
}

function ingestInput(all: Fixtures, id: string, tamper = false): IngestInput {
  const entry = selected(all, id);
  const material = all.materials[id];
  if (!material) throw new Error(`Missing Ingest source material: ${id}`);
  return {
    bundle: structuredClone(entry.bundle),
    receipt: structuredClone(entry.hash_only_receipt),
    material: sourceMaterial(material, tamper),
    intent: {
      subject: { kind: "ingest", id: (entry.bundle as { identity: { object_key: string } }).identity.object_key,
        hedera_network: "testnet" },
      expected: [],
    },
  };
}

function requirements(
  key: string,
  mode: "offline" | "public",
  network: "testnet" | "mainnet" = "testnet",
): VerificationPolicyV1 {
  return {
    schema_version: VERIFICATION_POLICY_SCHEMA_VERSION,
    subject: { kind: "ingest", id: key, hedera_network: network },
    report_kind: mode === "public" ? "public_triangulation" : "verification",
    required_checks: [
      "ingest.source_binding", "ingest.bundle_consistency",
      ...(mode === "public" ? ["triangulation.public_record_hedera.message_sha3_512"] : []),
    ],
    ...(mode === "public" ? { required_assurance: ["mirror_corroboration" as const] } : {}),
    on_unresolved: "review",
  };
}

/** Only Explorer and Mirror HTTP are simulated; all SDK verification is real. */
function publicationTransport(
  key: string, fingerprint: string, bundleDigest: string, state: TransportState = "consistent",
) {
  const requests: Array<{ url: URL; init: RequestInit }> = [];
  const fetch_impl = vi.fn(async (raw: string | URL | Request, init: RequestInit = {}): Promise<Response> => {
    const url = new URL(String(raw));
    requests.push({ url, init });
    if (url.pathname === `/v1/merkle/anchors/${ANCHOR}`) return Response.json({
      hedera_network: state === "wrong_network" ? "mainnet" : "testnet",
      anchor_request_id: state === "wrong_anchor" ? "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" : ANCHOR,
      ingest_object_key: key,
      ingest_fingerprint: fingerprint,
      ingest_bundle_digest: bundleDigest,
      publication_anchor_transaction_id: TX,
      publication_anchor_message_id: `5@${TOPIC}`,
      publication_anchor_topic_id: TOPIC,
      publication_anchor_sequence_number: 5,
    });
    if (url.pathname === "/v1/hcs/verify-decrypt") return Response.json({
      hedera_network: "testnet", verified: true, hash: { match: true },
      tx: { transaction_id: TX, message_id: `5@${TOPIC}` }, topic: { topic_id: TOPIC },
      message_binding: { schema_version: "vera.hcs-message-binding.v1", algorithm: "sha3-512",
        message_sha3_512: MESSAGE_DIGEST, message_bytes: MESSAGE.length },
      payload: {
        schema: "va:explorer_publication_receipt:v1", event_type: "published", event_version: 1,
        entity_kind: "merkle_anchor", entity_id: ANCHOR, visibility: "public",
        proof: { ingest_object_key: key, ingest_fingerprint: fingerprint, ingest_bundle_digest: bundleDigest },
      },
    });
    if (url.pathname === `/api/v1/topics/${TOPIC}/messages/5`) {
      if (state === "unavailable") return Response.json({}, { status: 404 });
      const content = state === "conflict" ? Buffer.from("mismatched-publication") : MESSAGE;
      return Response.json({ topic_id: TOPIC, sequence_number: 5,
        consensus_timestamp: "1234567890.123456789", message: content.toString("base64") });
    }
    if (url.pathname === "/api/v1/transactions/0.0.77-1234567890-123456789") return Response.json({
      transactions: [{ transaction_id: "0.0.77-1234567890-123456789",
        result: "SUCCESS", consensus_timestamp: "1234567890.123456790" }],
    });
    throw new Error(`Unexpected Ingest resolver endpoint: ${url.pathname}`);
  });
  return {
    requests,
    config: {
      explorer: { base_url: EXPLORER, fetch_impl: fetch_impl as typeof fetch },
      mirror: { base_urls: { testnet: MIRROR }, fetch_impl: fetch_impl as typeof fetch },
    },
  };
}

function publicInput(all: Fixtures, id: string) {
  return { ...ingestInput(all, id), anchor_request_id: ANCHOR };
}

async function cli(args: string[]) {
  const lines: string[] = [];
  const code = await runVerifierCliV1(args, (line) => lines.push(line));
  expect(lines).toHaveLength(1);
  return { code, body: JSON.parse(lines[0]!) as {
    result: {
      report?: unknown;
      policy?: { decision: string; authority: string };
      status?: string;
      authenticity?: string;
      decision?: string;
      authority?: string;
    };
  } };
}

async function save(dir: string, name: string, data: unknown): Promise<string> {
  const path = join(dir, name);
  await writeFile(path, JSON.stringify(data), "utf8");
  return path;
}

describe("Ingest integration: material, Core anchor, public publication, policy and report", () => {
  it("INT-I01 recomputes JSON, text, file and normalized/redacted file-set source commitments", async () => {
    const all = await fixtures();
    for (const id of ["json-v1", "text-v1", "file-v1", "file-set-v1"]) {
      const sample = selected(all, id);
      const key = (sample.bundle as { identity: { object_key: string } }).identity.object_key;
      const result = await verifyIngestWithPolicyV1(ingestInput(all, id), requirements(key, "offline"));
      expect(result.policy.decision, id).toBe("allow");
      expect(result.policy.authority).toBe("sdk_verification");
      expect(result.report.kind).toBe("verification");
      expect(validatePortableVerificationReportV1(result.report).status).toBe("valid");
      for (const check of ["ingest.source_binding", "ingest.bundle_consistency", "ingest.receipt_binding"]) {
        expect(result.report.core.findings.find((f) => f.check_id === check)?.outcome, `${id}: ${check}`).toBe("pass");
      }
    }
  });

  it("INT-I02 independently corroborates an Ingest object and its distinct Core publication anchor", async () => {
    const all = await fixtures();
    const sample = selected(all, "json-v1");
    const key = (sample.bundle as { identity: { object_key: string } }).identity.object_key;
    const transport = publicationTransport(key, sample.bundle_expectations.fingerprint,
      sample.bundle_expectations.bundle_digest);
    const result = await triangulateIngestWithPolicyV1(
      transport.config, publicInput(all, "json-v1"), requirements(key, "public"),
    );
    expect(result.policy).toMatchObject({ decision: "allow", authority: "sdk_verification" });
    expect(result.report.kind).toBe("public_triangulation");
    expect(result.report.core.intent.subject).toMatchObject({ kind: "ingest", id: key, hedera_network: "testnet" });
    expect(result.report.context).toMatchObject({
      resolution: { public_record: "resolved", publication_disclosure: "resolved", hedera_mirror: "resolved" },
    });
    expect(result.report.context).not.toHaveProperty("publication_payload_binding");
    expect(result.report.core.findings.find((f) =>
      f.check_id === "triangulation.public_record_hedera.message_sha3_512")?.outcome).toBe("pass");
    expect(validatePortableVerificationReportV1(result.report).status).toBe("valid");
    expect(transport.requests).toHaveLength(4);
    expect(transport.requests.some((call) => call.url.pathname === `/v1/merkle/anchors/${ANCHOR}`)).toBe(true);
    expect(transport.requests.every((call) =>
      call.init.credentials === "omit" && call.init.redirect === "error")).toBe(true);
    expect(transport.requests.every((call) =>
      call.url.host === "explorer.example.test" || call.url.host === "mirror.example.test")).toBe(true);
    expect(transport.requests.filter((call) => call.url.host === "mirror.example.test")).toHaveLength(2);
  });

  it("INT-I03 denies tampered material even when its original bundle and receipt still match", async () => {
    const all = await fixtures();
    for (const id of ["json-v1", "text-v1", "file-v1", "file-set-v1"]) {
      const sample = selected(all, id);
      const key = (sample.bundle as { identity: { object_key: string } }).identity.object_key;
      // The original bundle and receipt agree with each other independently of source bytes.
      expect(verifyIngestV1Pair({ bundle: sample.bundle, receipt: sample.hash_only_receipt }).ok, id).toBe(true);
      const result = await verifyIngestWithPolicyV1(ingestInput(all, id, true), requirements(key, "offline"));
      expect(result.policy.decision, id).toBe("deny");
      expect(result.report.core.findings.find((f) => f.check_id === "ingest.source_binding")?.outcome, id).toBe("fail");
      expect(result.report.core.findings.find((f) => f.check_id === "ingest.bundle_consistency")?.outcome, id).toBe("pass");
      // The tampered material's Merkle root no longer agrees with the original receipt.
      expect(result.report.core.findings.find((f) => f.check_id === "ingest.receipt_binding"), id).toMatchObject({
        outcome: "fail", reason_code: "RECEIPT_OR_BINDING_MISMATCH",
      });
      expect(validatePortableVerificationReportV1(result.report).status).toBe("valid");
    }
  });

  it("INT-I04 rejects a substituted Core anchor and wrong-network scope without identity conflation", async () => {
    const all = await fixtures();
    const sample = selected(all, "json-v1");
    const key = (sample.bundle as { identity: { object_key: string } }).identity.object_key;
    const mismatchedPolicy = publicationTransport(key, sample.bundle_expectations.fingerprint,
      sample.bundle_expectations.bundle_digest);
    await expect(triangulateIngestWithPolicyV1(
      mismatchedPolicy.config, publicInput(all, "json-v1"), requirements(key, "public", "mainnet"),
    )).rejects.toThrow(/policy intent/);
    expect(mismatchedPolicy.requests).toHaveLength(0);

    for (const state of ["wrong_anchor", "wrong_network"] as const) {
      const transport = publicationTransport(key, sample.bundle_expectations.fingerprint,
        sample.bundle_expectations.bundle_digest, state);
      const result = await triangulateIngestWithPolicyV1(
        transport.config, publicInput(all, "json-v1"), requirements(key, "public"),
      );
      expect(result.policy.decision, state).toBe("deny");
      expect(result.report.context).not.toMatchObject({ resolution: { public_record: "resolved" } });
    }
  });

  it("INT-I05 reviews missing Mirror evidence and denies conflicting publication bytes", async () => {
    const all = await fixtures();
    const sample = selected(all, "json-v1");
    const key = (sample.bundle as { identity: { object_key: string } }).identity.object_key;
    for (const [state, expected] of [["unavailable", "review"], ["conflict", "deny"]] as const) {
      const transport = publicationTransport(key, sample.bundle_expectations.fingerprint,
        sample.bundle_expectations.bundle_digest, state);
      const result = await triangulateIngestWithPolicyV1(
        transport.config, publicInput(all, "json-v1"), requirements(key, "public"),
      );
      expect(result.policy.decision, state).toBe(expected);
      expect(result.report.core.findings.find((f) =>
        f.check_id === "triangulation.public_record_hedera.message_sha3_512")?.outcome, state).not.toBe("pass");
      expect(validatePortableVerificationReportV1(result.report).status).toBe("valid");
      expect(transport.requests.some((call) => call.url.host === "mirror.example.test")).toBe(true);
    }
  });

  it("INT-I06 completes a file-set CLI verification, report export and independent reassessment", async () => {
    const all = await fixtures();
    const sample = selected(all, "file-set-v1");
    const selectedMaterial = all.materials["file-set-v1"];
    if (!selectedMaterial || selectedMaterial.kind !== "file_set") throw new Error("Missing file-set material");
    const key = (sample.bundle as { identity: { object_key: string } }).identity.object_key;
    const dir = await mkdtemp(join(tmpdir(), "va-ingest-int-"));
    try {
      const root = join(dir, "source-files");
      await mkdir(root);
      for (const file of selectedMaterial.files) {
        const segments = file.path_rel.split("/");
        await mkdir(join(root, ...segments.slice(0, -1)), { recursive: true });
        await writeFile(join(root, ...segments), Buffer.from(file.content_base64, "base64"));
      }
      const policy = requirements(key, "offline");
      const bundle = await save(dir, "bundle.json", sample.bundle);
      const receipt = await save(dir, "receipt.json", sample.hash_only_receipt);
      const material = await save(dir, "material.json", {
        kind: "file_set", paths: selectedMaterial.files.map((file) => file.path_rel),
      });
      const intent = await save(dir, "intent.json", {
        subject: { kind: "ingest", id: key, hedera_network: "testnet" }, expected: [],
      });
      const policyFile = await save(dir, "policy.json", policy);
      const reportPath = join(dir, "portable-report.json");
      const verified = await cli(["verify", "ingest", "--bundle", bundle,
        "--material", material, "--source-root", root, "--receipt", receipt,
        "--intent", intent, "--policy", policyFile, "--report-out", reportPath]);
      expect(verified.code).toBe(0);
      expect(verified.body.result.policy).toMatchObject({ decision: "allow", authority: "sdk_verification" });
      const saved = JSON.parse(await readFile(reportPath, "utf8"));
      expect(saved).toEqual(verified.body.result.report);
      expect(validatePortableVerificationReportV1(saved).status).toBe("valid");
      const checked = await cli(["report", "validate", "--report", reportPath]);
      expect(checked.code).toBe(0);
      expect(checked.body.result).toMatchObject({ status: "valid", authenticity: "not_checked" });
      const assessed = await cli(["policy", "assess", "--report", reportPath, "--policy", policyFile]);
      expect(assessed.code).toBe(2);
      expect(assessed.body.result).toMatchObject({ decision: "review", authority: "unauthenticated_report" });
      expect(assessPortableVerificationPolicyV1(saved, policy).decision).not.toBe("allow");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});