import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
  VERIFICATION_POLICY_SCHEMA_VERSION,
  assessPortableVerificationPolicyV1,
  sha3_512Hex,
  triangulateDatasetWithPolicyV1,
  validatePortableVerificationReportV1,
  verifyDatasetWithPolicyV1,
  type VerificationPolicyV1,
} from "../../src/index.js";
import { runVerifierCliV1 } from "../../src/cli/commandV1.js";

type Material = Readonly<{ path_rel: string; content_base64: string }>;
type DatasetCase = Readonly<{
  case_id: string;
  bundle: unknown;
  hash_only_receipt: unknown;
  bundle_expectations: Readonly<{
    dataset_key: string;
    dataset_fingerprint: string;
    bundle_digest: string;
    merkle_root: string;
  }>;
}>;

type DatasetInput = Parameters<typeof verifyDatasetWithPolicyV1>[0];
type TransportMode = "consistent" | "missing" | "conflict" | "wrong_network";

const EXPLORER = "https://explorer.example.test";
const MIRROR = "https://testnet.mirrornode.hedera.com/api/v1";
const TOPIC = "0.0.12345";
const TX = "0.0.77@1234567890.123456789";
const VERSION = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const MESSAGE = Buffer.from("encrypted-publication-envelope", "utf8");
const MESSAGE_DIGEST = sha3_512Hex(MESSAGE);

async function fixtures(): Promise<{ cases: DatasetCase[]; materials: Record<string, Material[]> }> {
  const [vectors, sourceMaterials] = await Promise.all([
    readFile(new URL("../unit/fixtures/datasetV1SelectedVectors.json", import.meta.url), "utf8"),
    readFile(new URL("../unit/fixtures/sourceV1Materials.json", import.meta.url), "utf8"),
  ]);
  return {
    cases: (JSON.parse(vectors) as { cases: DatasetCase[] }).cases,
    materials: (JSON.parse(sourceMaterials) as { dataset: Record<string, Material[]> }).dataset,
  };
}

function selected(all: Awaited<ReturnType<typeof fixtures>>, id: string): DatasetCase {
  const value = all.cases.find((entry) => entry.case_id === id);
  if (!value || !all.materials[id]) throw new Error(`Missing Dataset fixture: ${id}`);
  return value;
}

function datasetInput(
  all: Awaited<ReturnType<typeof fixtures>>,
  id: string,
  change?: (bytes: Buffer, index: number) => Buffer,
): DatasetInput {
  const entry = selected(all, id);
  return {
    bundle: structuredClone(entry.bundle),
    receipt: structuredClone(entry.hash_only_receipt),
    files: all.materials[id]!.map((file, index) => ({
      path_rel: file.path_rel,
      source: (async function* () {
        const original = Buffer.from(file.content_base64, "base64");
        yield change ? change(original, index) : original;
      })(),
    })),
    intent: {
      subject: { kind: "dataset", id: entry.bundle_expectations.dataset_key, hedera_network: "testnet" },
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
    subject: { kind: "dataset", id: key, hedera_network: network },
    report_kind: mode === "public" ? "public_triangulation" : "verification",
    required_checks: [
      "dataset.source_binding",
      "dataset.bundle_consistency",
      ...(mode === "public" ? ["triangulation.public_record_hedera.message_sha3_512"] : []),
    ],
    ...(mode === "public" ? { required_assurance: ["mirror_corroboration" as const] } : {}),
    on_unresolved: "review",
  };
}

/** Only the external HTTP transport is simulated. All verifier computations remain real. */
function publicationTransport(key: string, fingerprint: string, mode: TransportMode = "consistent") {
  const requests: Array<{ url: URL; init: RequestInit }> = [];
  const fetch_impl = vi.fn(async (raw: string | URL | Request, init: RequestInit = {}): Promise<Response> => {
    const url = new URL(String(raw));
    requests.push({ url, init });
    if (url.pathname === `/v1/datasets/${key}`) return Response.json({
      hedera_network: mode === "wrong_network" ? "mainnet" : "testnet",
      dataset_key: key,
      dataset_version_id: VERSION,
      dataset_fingerprint: fingerprint,
      publication_version_transaction_id: TX,
      publication_version_message_id: `5@${TOPIC}`,
      publication_version_topic_id: TOPIC,
      publication_version_sequence_number: 5,
    });
    if (url.pathname === "/v1/hcs/verify-decrypt") return Response.json({
      hedera_network: "testnet", verified: true, hash: { match: true },
      tx: { transaction_id: TX, message_id: `5@${TOPIC}` },
      topic: { topic_id: TOPIC },
      message_binding: {
        schema_version: "vera.hcs-message-binding.v1",
        algorithm: "sha3-512", message_sha3_512: MESSAGE_DIGEST, message_bytes: MESSAGE.length,
      },
      payload: {
        schema: "va:explorer_publication_receipt:v1", event_type: "published",
        event_version: 1, entity_kind: "dataset_version", entity_id: VERSION,
        visibility: "public", proof: { dataset_key: key, fingerprint },
      },
    });
    if (url.pathname === `/api/v1/topics/${TOPIC}/messages/5`) {
      if (mode === "missing") return Response.json({}, { status: 404 });
      const bytes = mode === "conflict" ? Buffer.from("mismatched-publication") : MESSAGE;
      return Response.json({
        topic_id: TOPIC, sequence_number: 5,
        consensus_timestamp: "1234567890.123456789", message: bytes.toString("base64"),
      });
    }
    if (url.pathname === "/api/v1/transactions/0.0.77-1234567890-123456789") return Response.json({
      transactions: [{ transaction_id: "0.0.77-1234567890-123456789",
        result: "SUCCESS", consensus_timestamp: "1234567890.123456790" }],
    });
    throw new Error(`Unexpected Dataset resolver endpoint: ${url.pathname}`);
  });
  const config = {
    explorer: { base_url: EXPLORER, fetch_impl: fetch_impl as typeof fetch },
    mirror: { base_urls: { testnet: MIRROR }, fetch_impl: fetch_impl as typeof fetch },
  };
  return { requests, fetch_impl, config };
}

async function cli(args: string[]) {
  const output: string[] = [];
  const code = await runVerifierCliV1(args, (line) => output.push(line));
  expect(output).toHaveLength(1);
  return { code, body: JSON.parse(output[0]!) as Readonly<{
    schema_version?: string;
    result: Readonly<{
      report?: unknown;
      policy?: Readonly<{ decision: string; authority: string }>;
      decision?: string;
      authority?: string;
      status?: string;
      authenticity?: string;
    }>;
  }> };
}

async function save(dir: string, name: string, value: unknown): Promise<string> {
  const path = join(dir, name);
  await writeFile(path, JSON.stringify(value), "utf8");
  return path;
}

describe("Dataset integration: source, public publication, policy and report", () => {
  it("INT-D01 recomputes real producer-derived single, multi, redacted and zero-byte Dataset materials", async () => {
    const all = await fixtures();
    for (const id of ["basic-v1", "realistic-multifile-v1", "redacted-paths-v1", "zero-byte-v1"]) {
      const sample = selected(all, id);
      const result = await verifyDatasetWithPolicyV1(
        datasetInput(all, id), requirements(sample.bundle_expectations.dataset_key, "offline"),
      );
      expect(result.policy.decision, id).toBe("allow");
      expect(result.policy.authority).toBe("sdk_verification");
      expect(result.report.kind).toBe("verification");
      expect(validatePortableVerificationReportV1(result.report).status).toBe("valid");
      for (const check of ["dataset.source_binding", "dataset.bundle_consistency"]) {
        expect(result.report.core.findings.find((f) => f.check_id === check)?.outcome, `${id}: ${check}`).toBe("pass");
      }
    }
  });

  it("INT-D02 independently corroborates the public Dataset publication and Mirror message", async () => {
    const all = await fixtures();
    const sample = selected(all, "basic-v1");
    const { dataset_key: key, dataset_fingerprint: fingerprint } = sample.bundle_expectations;
    const transport = publicationTransport(key, fingerprint);
    const result = await triangulateDatasetWithPolicyV1(
      transport.config, datasetInput(all, "basic-v1"), requirements(key, "public"),
    );
    expect(result.policy).toMatchObject({ decision: "allow", authority: "sdk_verification" });
    expect(result.report.kind).toBe("public_triangulation");
    expect(result.report.context).toMatchObject({
      resolution: { public_record: "resolved", publication_disclosure: "resolved", hedera_mirror: "resolved" },
    });
    expect(result.report.context).not.toHaveProperty("publication_payload_binding");
    expect(result.report.core.findings.find((f) =>
      f.check_id === "triangulation.public_record_hedera.message_sha3_512")?.outcome).toBe("pass");
    expect(validatePortableVerificationReportV1(result.report).status).toBe("valid");
    expect(transport.requests).toHaveLength(4);
    expect(transport.requests.every((call) =>
      call.init.credentials === "omit" && call.init.redirect === "error")).toBe(true);
    expect(transport.requests.every((call) =>
      call.url.host === "explorer.example.test" || call.url.host === "testnet.mirrornode.hedera.com")).toBe(true);
  });

  it("INT-D03 rejects tampered source bytes even when the original Dataset bundle and receipt are supplied", async () => {
    const all = await fixtures();
    const sample = selected(all, "basic-v1");
    const result = await verifyDatasetWithPolicyV1(
      datasetInput(all, "basic-v1", (_bytes, index) => index === 0 ? Buffer.from("tampered\n") : _bytes),
      requirements(sample.bundle_expectations.dataset_key, "offline"),
    );
    expect(result.policy.decision).toBe("deny");
    expect(result.report.core.findings.find((f) => f.check_id === "dataset.source_binding")?.outcome).toBe("fail");
    expect(validatePortableVerificationReportV1(result.report).status).toBe("valid");
  });

  it("INT-D04 rejects wrong-network policy scope before fetching and cannot accept a wrong-network record", async () => {
    const all = await fixtures();
    const sample = selected(all, "basic-v1");
    const { dataset_key: key, dataset_fingerprint: fingerprint } = sample.bundle_expectations;
    const transport = publicationTransport(key, fingerprint);
    await expect(triangulateDatasetWithPolicyV1(
      transport.config, datasetInput(all, "basic-v1"), requirements(key, "public", "mainnet"),
    )).rejects.toThrow(/policy intent/);
    expect(transport.requests).toHaveLength(0);

    const substituted = publicationTransport(key, fingerprint, "wrong_network");
    const result = await triangulateDatasetWithPolicyV1(
      substituted.config, datasetInput(all, "basic-v1"), requirements(key, "public"),
    );
    expect(result.policy.decision).not.toBe("allow");
    expect(result.report.context).not.toMatchObject({ resolution: { public_record: "resolved" } });
  });

  it("INT-D05 reviews missing Mirror evidence and denies a conflicting publication message", async () => {
    const all = await fixtures();
    const sample = selected(all, "basic-v1");
    const { dataset_key: key, dataset_fingerprint: fingerprint } = sample.bundle_expectations;
    for (const [mode, decision] of [["missing", "review"], ["conflict", "deny"]] as const) {
      const transport = publicationTransport(key, fingerprint, mode);
      const result = await triangulateDatasetWithPolicyV1(
        transport.config, datasetInput(all, "basic-v1"), requirements(key, "public"),
      );
      expect(result.policy.decision, mode).toBe(decision);
      expect(result.report.core.findings.find((f) =>
        f.check_id === "triangulation.public_record_hedera.message_sha3_512")?.outcome).not.toBe("pass");
      expect(validatePortableVerificationReportV1(result.report).status).toBe("valid");
      expect(transport.requests.some((call) => call.url.host === "testnet.mirrornode.hedera.com")).toBe(true);
    }
  });

  it("INT-D06 completes the CLI file-to-report lifecycle without authenticating an imported report", async () => {
    const all = await fixtures();
    const sample = selected(all, "realistic-multifile-v1");
    const files = all.materials["realistic-multifile-v1"]!;
    const key = sample.bundle_expectations.dataset_key;
    const dir = await mkdtemp(join(tmpdir(), "va-dataset-int-"));
    try {
      const root = join(dir, "sources");
      await mkdir(root);
      for (const file of files) {
        const segments = file.path_rel.split("/");
        const path = join(root, ...segments);
        await mkdir(join(root, ...segments.slice(0, -1)), { recursive: true });
        await writeFile(path, Buffer.from(file.content_base64, "base64"));
      }
      const policy = requirements(key, "offline");
      const bundle = await save(dir, "bundle.json", sample.bundle);
      const receipt = await save(dir, "receipt.json", sample.hash_only_receipt);
      const manifest = await save(dir, "sources.json", { paths: files.map((file) => file.path_rel) });
      const intent = await save(dir, "intent.json", {
        subject: { kind: "dataset", id: key, hedera_network: "testnet" }, expected: [],
      });
      const policyPath = await save(dir, "policy.json", policy);
      const output = join(dir, "portable-report.json");
      const verified = await cli(["verify", "dataset", "--bundle", bundle,
        "--sources", manifest, "--source-root", root, "--receipt", receipt,
        "--intent", intent, "--policy", policyPath, "--report-out", output]);
      expect(verified.code).toBe(0);
      expect(verified.body.result.policy).toMatchObject({ decision: "allow", authority: "sdk_verification" });
      const saved = JSON.parse(await readFile(output, "utf8"));
      expect(saved).toEqual(verified.body.result.report);
      expect(validatePortableVerificationReportV1(saved).status).toBe("valid");
      const validated = await cli(["report", "validate", "--report", output]);
      expect(validated.code).toBe(0);
      expect(validated.body.result).toMatchObject({ status: "valid", authenticity: "not_checked" });
      const assessed = await cli(["policy", "assess", "--report", output, "--policy", policyPath]);
      expect(assessed.code).toBe(2);
      expect(assessed.body.result).toMatchObject({ decision: "review", authority: "unauthenticated_report" });
      expect(assessPortableVerificationPolicyV1(saved, policy).decision).not.toBe("allow");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});