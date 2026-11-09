import { link, lstat, mkdtemp, readFile, rm, symlink, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { runVerifierCliV1 } from "../../src/cli/commandV1.js";
import { createPortableVerificationReportV1 } from "../../src/reports/portableV1.js";
import { VERIFICATION_POLICY_SCHEMA_VERSION } from "../../src/policy/contractV1.js";
import { computeExecutionDomainSeparatedSha3_512 } from "../../src/profiles/execution/recomputationV1.js";
import { sha3_512Hex } from "../../src/crypto/sha3.js";

async function sandbox<T>(run: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), "va-verifier-cli-"));
  try { return await run(dir); } finally { await rm(dir, { recursive: true, force: true }); }
}

async function save(dir: string, name: string, data: unknown): Promise<string> {
  const file = join(dir, name);
  await writeFile(file, JSON.stringify(data), "utf8");
  return file;
}

async function command(args: string[]): Promise<{ code: number; output: any }> {
  const lines: string[] = [];
  const code = await runVerifierCliV1(args, (line) => lines.push(line));
  expect(lines).toHaveLength(1);
  return { code, output: JSON.parse(lines[0]!) };
}

const job = "11111111-1111-4111-8111-111111111111";
const subject = { kind: "execution" as const, id: job, hedera_network: "testnet" as const };
const intent = { subject, expected: [] };
const policy = { schema_version: VERIFICATION_POLICY_SCHEMA_VERSION, subject,
  report_kind: "execution" as const, required_checks: ["binding.digest_recomputed"],
  execution_scope: { profile: "sage-standards-v1" as const, expected_program: "sage", requested_result_id: null } };

function evidence() {
  const digest_payload = { result: { x: 1 }, id: job };
  const digest = computeExecutionDomainSeparatedSha3_512("vera-anchor:execution-binding:v1", digest_payload);
  return { available: true, contract_version: "1.0.0",
    execution: { job_id: job, program: "sage", hedera_network: "testnet", proof_date: "2026-10-15" },
    binding: { schema: "ExecutionBindingV1", canonicalization: "RFC8785-JCS", digest_algorithm: "SHA3-512",
      domain_separator: "vera-anchor:execution-binding:v1", finalized_at: "2026-10-15T00:00:00Z", digest_payload, digest } };
}

describe("offline verifier CLI", () => {
  it("invokes real SAGE verification and applies independent policy scope", async () => sandbox(async (dir) => {
    const e = await save(dir, "e.json", evidence());
    const i = await save(dir, "i.json", intent);
    const p = await save(dir, "p.json", policy);
    const out = await command(["verify", "execution", "--evidence", e, "--intent", i, "--policy", p]);
    expect(out.output.schema_version).toBe("va.verifier-cli-result.v1");
    expect(out.output.result.report.kind).toBe("execution");
    expect(out.output.result.policy.authority).toBe("sdk_verification");
    expect(out.output.result.report.core.findings.find((f: any) => f.check_id === "binding.digest_recomputed")?.outcome).toBe("pass");
    expect(out.code).toBe(out.output.result.policy.decision === "allow" ? 0 : out.output.result.policy.decision === "review" ? 2 : 1);
  }));

  it("validates a saved report but does not authorize it", async () => sandbox(async (dir) => {
    const report = createPortableVerificationReportV1({ kind: "verification", result: {
      intent: { subject: { kind: "dataset", id: "study", hedera_network: "testnet" }, expected: [] },
      findings: [{ check_id: "intent.subject", outcome: "pass", reason_code: null, observation_ids: ["dataset.source"] }],
      observations: [{ id: "dataset.source", subject: { kind: "dataset", id: "study", hedera_network: "testnet" }, source: "local_computation", facts: [] }],
    } });
    const document = await save(dir, "report.json", report);
    const p = await save(dir, "policy.json", { schema_version: VERIFICATION_POLICY_SCHEMA_VERSION,
      subject: report.core.intent.subject, report_kind: "verification", required_checks: ["intent.subject"] });
    const valid = await command(["report", "validate", "--report", document]);
    expect(valid).toMatchObject({ code: 0, output: { result: { status: "valid", authenticity: "not_checked" } } });
    const assessed = await command(["policy", "assess", "--report", document, "--policy", p]);
    expect(assessed.code).toBe(2);
    expect(assessed.output.result).toMatchObject({ authority: "unauthenticated_report", decision: "review" });
  }));

  it("recomputes an actual Dataset fixture from local source bytes", async () => sandbox(async (dir) => {
    const vectors = JSON.parse(await readFile(new URL("./fixtures/datasetV1SelectedVectors.json", import.meta.url), "utf8"));
    const materials = JSON.parse(await readFile(new URL("./fixtures/sourceV1Materials.json", import.meta.url), "utf8"));
    const sample = vectors.cases.find((entry: any) => entry.case_id === "basic-v1");
    const sourceFiles = materials.dataset["basic-v1"] as { path_rel: string; content_base64: string }[];
    const sourceRoot = join(dir, "sources");
    await mkdir(sourceRoot);
    for (const entry of sourceFiles) {
      const segments = entry.path_rel.split("/");
      if (segments.length > 1) await mkdir(join(sourceRoot, ...segments.slice(0, -1)), { recursive: true });
      await writeFile(join(sourceRoot, ...segments), Buffer.from(entry.content_base64, "base64"));
    }
    const key = sample.bundle.dataset_identity.dataset_key;
    const expected = { subject: { kind: "dataset", id: key }, expected: [] };
    const p = { schema_version: VERIFICATION_POLICY_SCHEMA_VERSION, subject: expected.subject, report_kind: "verification",
      required_checks: ["dataset.source_binding", "dataset.bundle_consistency"] };
    const bundle = await save(dir, "bundle.json", sample.bundle);
    const sources = await save(dir, "sources.json", { paths: sourceFiles.map((entry) => entry.path_rel) });
    const i = await save(dir, "intent.json", expected);
    const policy = await save(dir, "policy.json", p);
    const out = await command(["verify", "dataset", "--bundle", bundle, "--sources", sources,
      "--source-root", sourceRoot, "--intent", i, "--policy", policy]);
    expect(out.code).toBe(0);
    expect(out.output.result.policy.decision).toBe("allow");
    expect(out.output.result.report.core.findings.find((f: any) => f.check_id === "dataset.source_binding")?.outcome).toBe("pass");
  }));

  it("rejects path traversal, duplicates and malformed CLI options before reading a source", async () => sandbox(async (dir) => {
    const required = { schema_version: VERIFICATION_POLICY_SCHEMA_VERSION, subject: { kind: "dataset", id: "x" },
      report_kind: "verification", required_checks: ["dataset.source_binding"] };
    const args = ["verify", "dataset", "--bundle", await save(dir, "bundle.json", {}),
      "--source-root", dir, "--intent", await save(dir, "intent.json", { subject: required.subject, expected: [] }),
      "--policy", await save(dir, "policy.json", required), "--sources"];
    // The first occurrence must exist so the duplicate-path check is reached,
    // rather than failing earlier with an ENOENT operational error.
    await writeFile(join(dir, "x.txt"), "test source", "utf8");
    for (const paths of [["../secrets"], ["x.txt", "x.txt"], ["C:/secret.txt"]]) {
      const file = await save(dir, "manifest.json", { paths });
      const out = await command([...args, file]);
      expect(out.code, `Invalid paths: ${JSON.stringify(paths)}`).toBe(64);
      expect(out.output.error.code).toBe("CLI_INPUT_INVALID");
    }
    expect((await command(["report", "validate", "--report"])).code).toBe(64);
    expect((await command(["policy", "assess", "--report", "x", "--report", "x", "--policy", "x"])).code).toBe(64);
  }));

  it("rejects file symlinks and Windows junctions inside the source root", async () => sandbox(async (dir) => {
    // Use valid Dataset inputs so an invalid bundle cannot mask the link-path check.
    const { args } = await publicDatasetCase(dir);
    const root = args[args.indexOf("--source-root") + 1]!;
    const manifest = args[args.indexOf("--sources") + 1]!;
    let linkedPath: string;
    let sourcePath: string;
    if (process.platform === "win32") {
      const external = join(dir, "outside");
      await mkdir(external);
      await writeFile(join(external, "secret.txt"), "secret", "utf8");
      linkedPath = join(root, "linked");
      // A junction is a filesystem link Windows can create without file-symlink privileges.
      await symlink(external, linkedPath, "junction");
      sourcePath = "linked/secret.txt";
    } else {
      const external = join(dir, "secret.txt");
      await writeFile(external, "secret", "utf8");
      linkedPath = join(root, "linked.txt");
      await symlink(external, linkedPath, "file");
      sourcePath = "linked.txt";
    }
    expect((await lstat(linkedPath)).isSymbolicLink()).toBe(true);
    const { sourceV1Path } = await import("../../src/profiles/sourceV1Helpers.js");
    expect(() => sourceV1Path("../secret.txt", 1024)).toThrow();
    await writeFile(manifest, JSON.stringify({ paths: [sourcePath] }), "utf8");
    const out = await command(args);
    expect(out.code).toBe(64);
    expect(out.output.error.code).toBe("CLI_INPUT_INVALID");
  }));
});

const PUBLIC_TOPIC = "0.0.12345";
const PUBLIC_TX = "0.0.77@1234567890.123456789";
const PUBLIC_VERSION = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const PUBLIC_BYTES = Buffer.from("encrypted-publication-envelope", "utf8");
const PUBLIC_DIGEST = sha3_512Hex(PUBLIC_BYTES);

async function publicDatasetCase(dir: string) {
  const vectors = JSON.parse(await readFile(new URL("./fixtures/datasetV1SelectedVectors.json", import.meta.url), "utf8"));
  const materials = JSON.parse(await readFile(new URL("./fixtures/sourceV1Materials.json", import.meta.url), "utf8"));
  const entry = vectors.cases.find((row: any) => row.case_id === "basic-v1");
  const files = materials.dataset["basic-v1"] as { path_rel: string; content_base64: string }[];
  const key: string = entry.bundle.dataset_identity.dataset_key;
  const fingerprint: string = entry.hash_only_receipt.evidence.dataset_fingerprint;
  const root = join(dir, "sources");
  await mkdir(root);
  for (const file of files) {
    const parts = file.path_rel.split("/");
    if (parts.length > 1) await mkdir(join(root, ...parts.slice(0, -1)), { recursive: true });
    await writeFile(join(root, ...parts), Buffer.from(file.content_base64, "base64"));
  }
  const expected = { subject: { kind: "dataset" as const, id: key, hedera_network: "testnet" as const }, expected: [] };
  const required = { schema_version: VERIFICATION_POLICY_SCHEMA_VERSION, subject: expected.subject,
    report_kind: "public_triangulation" as const,
    required_checks: ["dataset.source_binding", "dataset.bundle_consistency",
      "triangulation.public_record_hedera.message_sha3_512"],
    required_assurance: ["mirror_corroboration"] as const };
  const args = ["verify", "dataset", "--mode", "public", "--explorer-url", "https://explorer.example.test",
    "--bundle", await save(dir, "bundle.json", entry.bundle),
    "--sources", await save(dir, "sources.json", { paths: files.map((file) => file.path_rel) }),
    "--source-root", root, "--intent", await save(dir, "intent.json", expected),
    "--policy", await save(dir, "policy.json", required),
    "--receipt", await save(dir, "receipt.json", entry.hash_only_receipt)];
  return { args, key, fingerprint };
}

function publicResponses(key: string, fingerprint: string, mode: "consistent" | "missing" | "conflict" = "consistent") {
  const calls: Array<{ url: URL; init: RequestInit }> = [];
  const fetch_impl = vi.fn(async (raw: string | URL | Request, init: RequestInit = {}): Promise<Response> => {
    const url = new URL(String(raw));
    calls.push({ url, init });
    if (url.pathname === `/v1/datasets/${key}`) return Response.json({
      hedera_network: "testnet", dataset_key: key, dataset_version_id: PUBLIC_VERSION,
      dataset_fingerprint: fingerprint, publication_version_transaction_id: PUBLIC_TX,
      publication_version_message_id: `5@${PUBLIC_TOPIC}`, publication_version_topic_id: PUBLIC_TOPIC,
      publication_version_sequence_number: 5,
    });
    if (url.pathname === "/v1/hcs/verify-decrypt") return Response.json({
      hedera_network: "testnet", verified: true, hash: { match: true },
      tx: { transaction_id: PUBLIC_TX, message_id: `5@${PUBLIC_TOPIC}` }, topic: { topic_id: PUBLIC_TOPIC },
      message_binding: { schema_version: "vera.hcs-message-binding.v1", algorithm: "sha3-512",
        message_sha3_512: PUBLIC_DIGEST, message_bytes: PUBLIC_BYTES.length },
      payload: { schema: "va:explorer_publication_receipt:v1", event_type: "published", event_version: 1,
        entity_kind: "dataset_version", entity_id: PUBLIC_VERSION, visibility: "public",
        proof: { dataset_key: key, fingerprint } },
    });
    if (url.pathname === `/api/v1/topics/${PUBLIC_TOPIC}/messages/5`) {
      if (mode === "missing") return Response.json({}, { status: 404 });
      const bytes = mode === "conflict" ? Buffer.from("mismatched-publication") : PUBLIC_BYTES;
      return Response.json({ topic_id: PUBLIC_TOPIC, sequence_number: 5,
        consensus_timestamp: "1234567890.123456789", message: bytes.toString("base64") });
    }
    if (url.pathname === "/api/v1/transactions/0.0.77-1234567890-123456789") return Response.json({
      transactions: [{ transaction_id: "0.0.77-1234567890-123456789", result: "SUCCESS",
        consensus_timestamp: "1234567890.123456790" }],
    });
    throw new Error(`Unexpected public endpoint: ${url.pathname}`);
  });
  return { calls, fetch_impl };
}

afterEach(() => { vi.unstubAllGlobals(); });

describe("public Dataset verifier CLI", () => {
  it("recomputes source bytes and corroborates the separately resolved public publication", async () => sandbox(async (dir) => {
    const { args, key, fingerprint } = await publicDatasetCase(dir);
    const network = publicResponses(key, fingerprint);
    vi.stubGlobal("fetch", network.fetch_impl);
    const out = await command(args);
    expect(out.code).toBe(0);
    expect(out.output.result.policy).toMatchObject({ decision: "allow", authority: "sdk_verification" });
    expect(out.output.result.report).toMatchObject({ kind: "public_triangulation",
      context: { resolution: { hedera_mirror: "resolved" } } });
    expect(out.output.result.report.context).not.toHaveProperty("publication_payload_binding");
    expect(out.output.result.report.core.findings.find((f: any) =>
      f.check_id === "triangulation.public_record_hedera.message_sha3_512")?.outcome).toBe("pass");
    expect(network.calls).toHaveLength(4);
    expect(network.calls.every((c) => c.init.credentials === "omit" && c.init.redirect === "error")).toBe(true);
    expect(network.calls.some((c) => c.url.pathname === "/v1/hcs/verify-decrypt")).toBe(true);
    expect(network.calls.filter((c) => c.url.host.includes("mirrornode.hedera.com"))).toHaveLength(2);
  }));

  it("uses an explicitly selected Mirror API origin without changing the selected network", async () => sandbox(async (dir) => {
    const { args, key, fingerprint } = await publicDatasetCase(dir);
    const network = publicResponses(key, fingerprint);
    vi.stubGlobal("fetch", network.fetch_impl);
    const out = await command([...args, "--mirror-url", "https://custom-mirror.example/api/v1"]);
    expect(out.code).toBe(0);
    expect(network.calls.filter((c) => c.url.host === "custom-mirror.example")).toHaveLength(2);
    expect(network.calls.every((c) => c.url.host === "explorer.example.test" ||
      c.url.host === "custom-mirror.example")).toBe(true);
  }));

  it("returns review for missing Mirror evidence rather than approving offline checks", async () => sandbox(async (dir) => {
    const { args, key, fingerprint } = await publicDatasetCase(dir);
    vi.stubGlobal("fetch", publicResponses(key, fingerprint, "missing").fetch_impl);
    const out = await command(args);
    expect(out.code).toBe(2);
    expect(out.output.result.policy.decision).toBe("review");
    expect(out.output.result.policy.reason_codes).toContain("POLICY_PUBLIC_EVIDENCE_INCOMPLETE");
  }));

  it("denies a conflicting Hedera ciphertext digest", async () => sandbox(async (dir) => {
    const { args, key, fingerprint } = await publicDatasetCase(dir);
    vi.stubGlobal("fetch", publicResponses(key, fingerprint, "conflict").fetch_impl);
    const out = await command(args);
    expect(out.code).toBe(1);
    expect(out.output.result.policy.decision).toBe("deny");
  }));

  it("rejects missing network, unsafe endpoint and offline resolver flags without any fetch", async () => sandbox(async (dir) => {
    const { args } = await publicDatasetCase(dir);
    const fetch_impl = vi.fn(async (): Promise<Response> => { throw new Error("Network should not be contacted"); });
    vi.stubGlobal("fetch", fetch_impl);
    const replace = (flag: string, value: string) => args.map((part, index) =>
      index > 0 && args[index - 1] === flag ? value : part);
    for (const url of ["http://outside.example", "https://user:pass@host.example", "https://host.example/private"]) {
      expect((await command(replace("--explorer-url", url))).code).toBe(64);
    }
    expect((await command(args.filter((part, index) => part !== "--explorer-url" && args[index - 1] !== "--explorer-url"))).code).toBe(64);
    expect((await command(replace("--mode", "offline"))).code).toBe(64);
    expect((await command([...args, "--mirror-url", "https://mirror.example/api/v1/"])).code).toBe(64);
    const originalIntent = JSON.parse(await readFile(args[args.indexOf("--intent") + 1]!, "utf8"));
    delete originalIntent.subject.hedera_network;
    const noNetworkIntent = await save(dir, "no-network-intent.json", originalIntent);
    expect((await command(replace("--intent", noNetworkIntent))).code).toBe(64);
    expect(fetch_impl).not.toHaveBeenCalled();
  }));
});

const SAGE_RESULT = "33333333-3333-4333-8333-333333333333";
const SAGE_TX = "0.0.11@1792033594.000000001";
const SAGE_ACCEPTANCE = "a".repeat(128);
const SAGE_MESSAGE_HASH = "b".repeat(128);

function publicExecutionEvidence(result_id?: string) {
  return { ...evidence(),
    execution: { ...evidence().execution, ...(result_id ? { result_id } : {}) },
    acceptance: { digest: SAGE_ACCEPTANCE,
      hcs: { transaction_id: "0.0.11@1792033594.1", topic_id: "0.0.22",
        sequence_number: 3, message_id: "3@0.0.22", data_hash_sha3_512: SAGE_MESSAGE_HASH } },
    ...(result_id ? { result_evidence: { result_id, digest: SAGE_ACCEPTANCE,
      hcs: { transaction_id: "0.0.15@1792033599.2" } } } : {}),
  };
}

async function publicExecutionCase(dir: string, result_id: string | null = null) {
  const e = publicExecutionEvidence(result_id ?? undefined);
  const requirements = { ...policy, report_kind: "execution_triangulation" as const,
    required_assurance: ["mirror_corroboration"] as const,
    execution_scope: { ...policy.execution_scope, requested_result_id: result_id } };
  const args = ["verify", "execution", "--mode", "public", "--explorer-url", "https://explorer.example.test",
    "--evidence", await save(dir, "execution.json", e),
    "--intent", await save(dir, "intent.json", intent),
    "--policy", await save(dir, "policy.json", requirements)];
  return { args, e };
}

function executionResponses(options: { missingMirror?: boolean; conflictingMirror?: boolean;
  substitutedResult?: boolean; unavailableExplorer?: boolean } = {}) {
  const requests: Array<{ url: URL; init: RequestInit }> = [];
  const fetch_impl = vi.fn(async (raw: string | URL | Request, init: RequestInit = {}): Promise<Response> => {
    const url = new URL(String(raw));
    requests.push({ url, init });
    if (url.pathname.endsWith(`/sage/results/${SAGE_RESULT}`)) return Response.json({
      id: SAGE_RESULT, job_id: options.substitutedResult ? "22222222-2222-4222-8222-222222222222" : job,
      hedera_network: "testnet",
    });
    if (url.pathname.endsWith(`/sage/jobs/${job}/standards`)) {
      return options.unavailableExplorer ? Response.json({}, { status: 503 }) :
        Response.json(publicExecutionEvidence(url.searchParams.get("resultId") ?? undefined));
    }
    if (url.pathname.includes("/topics/")) return options.missingMirror ? Response.json({}, { status: 404 }) :
      Response.json({ topic_id: options.conflictingMirror ? "0.0.999" : "0.0.22", sequence_number: 3,
        consensus_timestamp: "1792033600.123456789", message: "YWJj" });
    if (url.pathname.includes("/transactions/")) return Response.json({ transactions: [
      { transaction_id: url.pathname.includes("/transactions/0.0.15-")
        ? "0.0.15@1792033599.000000002" : SAGE_TX,
        result: "SUCCESS", consensus_timestamp: "1792033600.123456789" },
    ] });
    throw new Error("Unexpected resolver route");
  });
  return { requests, fetch_impl };
}

describe("public SAGE execution verifier CLI", () => {
  it("corroborates independently scoped execution without claiming plaintext or DID authentication", async () => sandbox(async (dir) => {
    const { args } = await publicExecutionCase(dir);
    const transport = executionResponses();
    vi.stubGlobal("fetch", transport.fetch_impl);
    const out = await command(args);
    expect(out.output.result.report.kind).toBe("execution_triangulation");
    expect(out.output.result.policy.authority).toBe("sdk_verification");
    expect(out.output.result.report.core.findings.find((f: any) =>
      f.check_id === "binding.digest_recomputed")?.outcome).toBe("pass");
    expect(out.output.result.report.context.public_execution).toMatchObject({
      hedera_resolution: "resolved" });
    expect(out.output.result.report.context.public_execution).not.toHaveProperty("publication_payload_binding");
    expect(out.code).toBe(out.output.result.policy.decision === "allow" ? 0 :
      out.output.result.policy.decision === "review" ? 2 : 1);
    expect(transport.requests).toHaveLength(5);
    expect(transport.requests.every((r) => r.init.credentials === "omit" && r.init.redirect === "error")).toBe(true);
    expect(transport.requests.every((r) => r.url.host === "explorer.example.test" ||
      r.url.host.includes("mirrornode.hedera.com"))).toBe(true);
  }));

  it("fetches a pinned SAGE result before standards and never selects a latest result", async () => sandbox(async (dir) => {
    const { args } = await publicExecutionCase(dir, SAGE_RESULT);
    const transport = executionResponses();
    vi.stubGlobal("fetch", transport.fetch_impl);
    const out = await command(args);
    expect(out.output.result.report.kind).toBe("execution_triangulation");
    expect(out.output.result.report.context.verification_scope.requested_result_id).toBe(SAGE_RESULT);
    expect(transport.requests[0]?.url.pathname).toContain(`/sage/results/${SAGE_RESULT}`);
    expect(transport.requests[1]?.url.searchParams.get("resultId")).toBe(SAGE_RESULT);
    expect(transport.requests.every((r) => !r.url.pathname.includes("/latest"))).toBe(true);
  }));

  it("preserves the selected result UUID and rejects substitution before Mirror acquisition", async () => sandbox(async (dir) => {
    const { args } = await publicExecutionCase(dir, SAGE_RESULT);
    const transport = executionResponses({ substitutedResult: true });
    vi.stubGlobal("fetch", transport.fetch_impl);
    const out = await command(args);
    expect(out.code).toBe(1);
    expect(out.output.result.policy.decision).toBe("deny");
    expect(transport.requests).toHaveLength(1);
    expect(transport.requests[0]?.url.pathname).toContain(`/sage/results/${SAGE_RESULT}`);
  }));

  it("never accepts unavailable Explorer or Hedera evidence and preserves independent failures", async () => sandbox(async (dir) => {
    const { args } = await publicExecutionCase(dir);
    for (const conditions of [{ unavailableExplorer: true }, { missingMirror: true }]) {
      const transport = executionResponses(conditions);
      vi.stubGlobal("fetch", transport.fetch_impl);
      const out = await command(args);
      const decision = out.output.result.policy.decision;
      const requirements = out.output.result.policy.requirements as Array<{ outcome: string }>;

      expect(out.output.result.report.kind).toBe("execution_triangulation");
      expect(out.output.result.policy.authority).toBe("sdk_verification");

      const publicRequirement = out.output.result.policy.requirements.find(
        (entry: { key: string; outcome: string; reason_code: string | null }) =>
          entry.key === "verification.public_evidence",
      );
      expect(publicRequirement).toBeDefined();
      expect(["unresolved", "fail"]).toContain(publicRequirement.outcome);
      expect(publicRequirement.reason_code).toBe(publicRequirement.outcome === "fail" ?
        "POLICY_PUBLIC_EVIDENCE_CONFLICT" : "POLICY_PUBLIC_EVIDENCE_INCOMPLETE");
      expect(out.output.result.policy.reason_codes).toContain(publicRequirement.reason_code);

      expect(decision).not.toBe("allow");
      if (decision === "deny") {
        // Denial is required when another finding fails; unavailability cannot mask it.
        expect(requirements.some((entry) => entry.outcome === "fail")).toBe(true);
      } else {
        expect(decision).toBe("review");
        expect(requirements.some((entry) => entry.outcome === "fail")).toBe(false);
      }
      expect(out.code).toBe(decision === "deny" ? 1 : 2);
    }
  }));

  it("denies independently contradictory Hedera topic evidence", async () => sandbox(async (dir) => {
    const { args } = await publicExecutionCase(dir);
    const transport = executionResponses({ conflictingMirror: true });
    vi.stubGlobal("fetch", transport.fetch_impl);
    const out = await command(args);
    expect(out.code).toBe(1);
    expect(out.output.result.policy.decision).toBe("deny");
  }));

  it("rejects unsafe public configuration, missing scope and offline resolver flags without fetches", async () => sandbox(async (dir) => {
    const { args } = await publicExecutionCase(dir);
    const fetch_impl = vi.fn(async (): Promise<Response> => { throw new Error("Unexpected network request"); });
    vi.stubGlobal("fetch", fetch_impl);
    const replace = (flag: string, value: string) => args.map((part, index) =>
      index > 0 && args[index - 1] === flag ? value : part);
    expect((await command(replace("--mode", "offline"))).code).toBe(64);
    expect((await command(replace("--explorer-url", "http://remote.example"))).code).toBe(64);
    expect((await command([...args, "--mirror-url", "https://mirror.example/private"])).code).toBe(64);
    expect((await command(args.filter((part, index) => part !== "--explorer-url" && args[index - 1] !== "--explorer-url"))).code).toBe(64);
    const wrong = await save(dir, "wrong.json", { ...intent, subject: { ...subject, hedera_network: "mainnet" } });
    expect((await command(replace("--intent", wrong))).code).toBe(64);
    const policyFile = await save(dir, "no-scope.json", { ...policy, report_kind: "execution_triangulation",
      execution_scope: undefined });
    expect((await command(replace("--policy", policyFile))).code).toBe(64);
    expect(fetch_impl).not.toHaveBeenCalled();
  }));
});

const INGEST_ANCHOR = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

/** Reuse the repository's producer-derived fixtures, never synthetic passing hashes. */
async function ingestCase(dir: string, caseId: string, publicMode = false) {
  const vectors = JSON.parse(await readFile(new URL("./fixtures/ingestV1SelectedVectors.json", import.meta.url), "utf8"));
  const materials = JSON.parse(await readFile(new URL("./fixtures/sourceV1Materials.json", import.meta.url), "utf8"));
  const entry = vectors.cases.find((item: any) => item.case_id === caseId);
  if (!entry) throw new Error(`Missing Ingest fixture ${caseId}`);
  const input = materials.ingest[caseId];
  const key: string = entry.bundle.identity.object_key;
  const root = join(dir, "ingest-sources");
  let descriptor: unknown;
  let sourceRoot: string[] = [];
  if (input.kind === "file" || input.kind === "file_set") {
    await mkdir(root);
    const files = input.kind === "file" ? [input.file] : input.files;
    for (const file of files) {
      const parts = file.path_rel.split("/");
      if (parts.length > 1) await mkdir(join(root, ...parts.slice(0, -1)), { recursive: true });
      await writeFile(join(root, ...parts), Buffer.from(file.content_base64, "base64"));
    }
    descriptor = input.kind === "file" ? { kind: "file", path_rel: input.file.path_rel } :
      { kind: "file_set", paths: files.map((file: { path_rel: string }) => file.path_rel) };
    sourceRoot = ["--source-root", root];
  } else {
    descriptor = input;
  }
  const expected = { subject: { kind: "ingest" as const, id: key,
    ...(publicMode ? { hedera_network: "testnet" as const } : {}) }, expected: [] };
  const requirements = { schema_version: VERIFICATION_POLICY_SCHEMA_VERSION, subject: expected.subject,
    report_kind: publicMode ? "public_triangulation" as const : "verification" as const,
    required_checks: ["ingest.source_binding", "ingest.bundle_consistency",
      ...(publicMode ? ["triangulation.public_record_hedera.message_sha3_512"] : [])],
    ...(publicMode ? { required_assurance: ["mirror_corroboration"] } : {}),
    on_unresolved: "review" as const };
  const args = ["verify", "ingest", "--bundle", await save(dir, "ingest-bundle.json", entry.bundle),
    "--material", await save(dir, "ingest-material.json", descriptor), ...sourceRoot,
    "--intent", await save(dir, "ingest-intent.json", expected),
    "--policy", await save(dir, "ingest-policy.json", requirements),
    "--receipt", await save(dir, "ingest-receipt.json", entry.hash_only_receipt),
    ...(publicMode ? ["--mode", "public", "--anchor-request-id", INGEST_ANCHOR,
      "--explorer-url", "https://explorer.example.test", "--mirror-url", "https://mirror.example.test/api/v1"] : [])];
  return { args, entry, key };
}

function ingestPublicResponses(key: string, fingerprint: string, bundleDigest: string,
  state: "consistent" | "unavailable" | "conflict" | "wrong_anchor" = "consistent") {
  const requests: Array<{ url: URL; init: RequestInit }> = [];
  const fetch_impl = vi.fn(async (raw: string | URL | Request, init: RequestInit = {}): Promise<Response> => {
    const url = new URL(String(raw));
    requests.push({ url, init });
    if (url.pathname.includes("/v1/merkle/anchors/")) return Response.json({
      hedera_network: "testnet", anchor_request_id: state === "wrong_anchor" ?
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" : INGEST_ANCHOR,
      ingest_object_key: key, ingest_fingerprint: fingerprint, ingest_bundle_digest: bundleDigest,
      publication_anchor_transaction_id: PUBLIC_TX, publication_anchor_message_id: `5@${PUBLIC_TOPIC}`,
      publication_anchor_topic_id: PUBLIC_TOPIC, publication_anchor_sequence_number: 5,
    });
    if (url.pathname === "/v1/hcs/verify-decrypt") return Response.json({
      hedera_network: "testnet", verified: true, hash: { match: true },
      tx: { transaction_id: PUBLIC_TX, message_id: `5@${PUBLIC_TOPIC}` }, topic: { topic_id: PUBLIC_TOPIC },
      message_binding: { schema_version: "vera.hcs-message-binding.v1", algorithm: "sha3-512",
        message_sha3_512: PUBLIC_DIGEST, message_bytes: PUBLIC_BYTES.length },
      payload: { schema: "va:explorer_publication_receipt:v1", event_type: "published", event_version: 1,
        entity_kind: "merkle_anchor", entity_id: INGEST_ANCHOR, visibility: "public",
        proof: { ingest_object_key: key, ingest_fingerprint: fingerprint, ingest_bundle_digest: bundleDigest } },
    });
    if (url.pathname === `/api/v1/topics/${PUBLIC_TOPIC}/messages/5`) {
      if (state === "unavailable") return Response.json({}, { status: 404 });
      return Response.json({ topic_id: PUBLIC_TOPIC, sequence_number: 5,
        consensus_timestamp: "1234567890.123456789",
        message: (state === "conflict" ? Buffer.from("wrong-publication") : PUBLIC_BYTES).toString("base64") });
    }
    if (url.pathname === "/api/v1/transactions/0.0.77-1234567890-123456789") return Response.json({
      transactions: [{ transaction_id: "0.0.77-1234567890-123456789", result: "SUCCESS",
        consensus_timestamp: "1234567890.123456790" }],
    });
    throw new Error("Unexpected Ingest resolver path");
  });
  return { requests, fetch_impl };
}

describe("Ingest verifier CLI", () => {
  it("verifies JSON, text, single-file and file-set source material without network reads", async () => {
    const fixtures = JSON.parse(await readFile(new URL("./fixtures/ingestV1SelectedVectors.json", import.meta.url), "utf8"));
    const materials = JSON.parse(await readFile(new URL("./fixtures/sourceV1Materials.json", import.meta.url), "utf8"));
    const kinds = new Set<string>();
    const fetch_impl = vi.fn(async (): Promise<Response> => { throw new Error("Offline verification fetched network data"); });
    vi.stubGlobal("fetch", fetch_impl);
    for (const entry of fixtures.cases) {
      await sandbox(async (dir) => {
        const { args } = await ingestCase(dir, entry.case_id);
        const materialKind: string = materials.ingest[entry.case_id].kind;
        kinds.add(materialKind);
        const out = await command(args);
        expect(out.code, `Ingest fixture ${entry.case_id}`).toBe(0);
        expect(out.output.result.report.kind).toBe("verification");
        expect(out.output.result.policy).toMatchObject({ decision: "allow", authority: "sdk_verification" });
        expect(out.output.result.report.core.findings.find((f: any) => f.check_id === "ingest.source_binding")?.outcome).toBe("pass");
      });
    }
    expect(kinds).toEqual(new Set(["json", "text", "file", "file_set"]));
    expect(fetch_impl).not.toHaveBeenCalled();
  });

  it("corroborates public Ingest fingerprint and Core anchor without conflating identities", async () => sandbox(async (dir) => {
    const { args, key, entry } = await ingestCase(dir, "json-v1", true);
    const evidence = entry.hash_only_receipt.evidence;
    const transport = ingestPublicResponses(key, evidence.fingerprint, evidence.bundle_digest);
    vi.stubGlobal("fetch", transport.fetch_impl);
    const out = await command(args);
    expect(out.code).toBe(0);
    expect(out.output.result.policy).toMatchObject({ decision: "allow", authority: "sdk_verification" });
    expect(out.output.result.report.kind).toBe("public_triangulation");
    expect(out.output.result.report.core.intent.subject.id).toBe(key);
    expect(transport.requests.some((r) => r.url.pathname.includes(`/merkle/anchors/${INGEST_ANCHOR}`))).toBe(true);
    expect(transport.requests.every((r) => r.init.credentials === "omit" && r.init.redirect === "error")).toBe(true);
    expect(transport.requests.filter((r) => r.url.host === "mirror.example.test")).toHaveLength(2);
  }));

  it("reviews missing Mirror evidence; denies conflicting bytes and a substituted Core anchor", async () => sandbox(async (dir) => {
    const { args, key, entry } = await ingestCase(dir, "json-v1", true);
    const evidence = entry.hash_only_receipt.evidence;
    for (const state of ["unavailable", "conflict", "wrong_anchor"] as const) {
      const transport = ingestPublicResponses(key, evidence.fingerprint, evidence.bundle_digest, state);
      vi.stubGlobal("fetch", transport.fetch_impl);
      const out = await command(args);
      expect(out.output.result.policy.decision).toBe(state === "unavailable" ? "review" : "deny");
      expect(out.code).toBe(state === "unavailable" ? 2 : 1);
    }
  }));

  it("rejects missing public anchor, wrong network, unsafe paths and offline resolver options before fetching", async () => sandbox(async (dir) => {
    const { args } = await ingestCase(dir, "json-v1", true);
    const fetch_impl = vi.fn(async (): Promise<Response> => { throw new Error("Unexpected request"); });
    vi.stubGlobal("fetch", fetch_impl);
    const remove = (flag: string) => args.filter((part, i) => part !== flag && args[i - 1] !== flag);
    expect((await command(remove("--anchor-request-id"))).code).toBe(64);
    expect((await command([...remove("--anchor-request-id"), "--anchor-request-id", "not-a-uuid"])).code).toBe(64);
    expect((await command([...args, "--mode", "offline"])).code).toBe(64);
    const updated = args.map((v, i) => args[i - 1] === "--mode" ? "offline" : v);
    expect((await command(updated)).code).toBe(64);
    const badIntent = await save(dir, "wrong-intent.json", { subject: { kind: "ingest", id: "other", hedera_network: "testnet" }, expected: [] });
    const wrong = args.map((v, i) => args[i - 1] === "--intent" ? badIntent : v);
    expect((await command(wrong)).code).toBe(64);
    const file = await save(dir, "invalid-material.json", { kind: "file_set", paths: ["../private.txt"] });
    const invalidMaterial = args.map((v, i) => args[i - 1] === "--material" ? file : v);
    expect((await command([...invalidMaterial, "--source-root", dir])).code).toBe(64);
    expect(fetch_impl).not.toHaveBeenCalled();
  }));
});

describe("portable report export from verifier CLI", () => {
  it("saves a standalone, validated offline SAGE report without changing stdout or the policy decision", async () => sandbox(async (dir) => {
    const e = await save(dir, "evidence.json", evidence());
    const i = await save(dir, "intent.json", intent);
    const p = await save(dir, "policy.json", policy);
    const destination = join(dir, "execution-report.json");
    const out = await command(["verify", "execution", "--evidence", e, "--intent", i,
      "--policy", p, "--report-out", destination]);
    expect(out.code).toBe(out.output.result.policy.decision === "allow" ? 0 :
      out.output.result.policy.decision === "review" ? 2 : 1);
    expect(out.output.command).toBe("verify execution");
    const saved = JSON.parse(await readFile(destination, "utf8"));
    expect(saved).toEqual(out.output.result.report);
    expect(saved.schema_version).toBe("va.portable-verification-report.v1");
    expect((await command(["report", "validate", "--report", destination]))).toMatchObject({
      code: 0, output: { result: { status: "valid", authenticity: "not_checked" } },
    });
    const assessed = await command(["policy", "assess", "--report", destination, "--policy", p]);
    expect(assessed.code).toBe(2);
    expect(assessed.output.result.authority).toBe("unauthenticated_report");
  }));

  it("exports a public Dataset report from independently corroborated source bytes", async () => sandbox(async (dir) => {
    const { args, key, fingerprint } = await publicDatasetCase(dir);
    vi.stubGlobal("fetch", publicResponses(key, fingerprint).fetch_impl);
    const destination = join(dir, "dataset-report.json");
    const out = await command([...args, "--report-out", destination]);
    expect(out.code).toBe(0);
    expect(out.output.result.report.kind).toBe("public_triangulation");
    expect(JSON.parse(await readFile(destination, "utf8"))).toEqual(out.output.result.report);
    expect((await command(["report", "validate", "--report", destination])).code).toBe(0);
  }));

  it("exports public Ingest review and denial reports rather than silently dropping non-allow findings", async () => sandbox(async (dir) => {
    const { args, key, entry } = await ingestCase(dir, "json-v1", true);
    const receipt = entry.hash_only_receipt.evidence;
    for (const [state, expectedCode] of [["unavailable", 2], ["conflict", 1]] as const) {
      vi.stubGlobal("fetch", ingestPublicResponses(key, receipt.fingerprint, receipt.bundle_digest, state).fetch_impl);
      const destination = join(dir, `${state}.json`);
      const out = await command([...args, "--report-out", destination]);
      expect(out.code).toBe(expectedCode);
      const saved = JSON.parse(await readFile(destination, "utf8"));
      expect(saved).toEqual(out.output.result.report);
      expect(saved.kind).toBe("public_triangulation");
      expect((await command(["report", "validate", "--report", destination])).code).toBe(0);
    }
  }));

  it("never overwrites an existing report or one of its inputs", async () => sandbox(async (dir) => {
    const e = await save(dir, "evidence.json", evidence());
    const i = await save(dir, "intent.json", intent);
    const p = await save(dir, "policy.json", policy);
    const args = ["verify", "execution", "--evidence", e, "--intent", i, "--policy", p];
    const destination = join(dir, "existing-report.json");
    await writeFile(destination, "original content", "utf8");
    const existing = await command([...args, "--report-out", destination]);
    expect(existing.code).toBe(64);
    expect(existing.output.error.code).toBe("CLI_INPUT_INVALID");
    expect(await readFile(destination, "utf8")).toBe("original content");
    const originalEvidence = await readFile(e, "utf8");
    expect((await command([...args, "--report-out", e])).code).toBe(64);
    expect(await readFile(e, "utf8")).toBe(originalEvidence);
  }));

  it("never follows a report-output symlink or overwrites an existing file alias", async () => sandbox(async (dir) => {
    const e = await save(dir, "evidence.json", evidence());
    const i = await save(dir, "intent.json", intent);
    const p = await save(dir, "policy.json", policy);
    const protectedFile = join(dir, "protected.json");
    await writeFile(protectedFile, "protected", "utf8");
    const destination = join(dir, "report-link.json");
    let hardLinkFallback = false;
    try {
      await symlink(protectedFile, destination, "file");
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (process.platform !== "win32" || (code !== "EPERM" && code !== "EACCES")) throw error;
      // On Windows without symlink privileges, a hard link still tests that
      // exclusive report creation cannot overwrite another file through an alias.
      await link(protectedFile, destination);
      hardLinkFallback = true;
    }
    expect((await lstat(destination)).isSymbolicLink()).toBe(!hardLinkFallback);
    const out = await command(["verify", "execution", "--evidence", e, "--intent", i,
      "--policy", p, "--report-out", destination]);
    expect(out.code).toBe(64);
    expect(out.output.error.code).toBe("CLI_INPUT_INVALID");
    expect(await readFile(protectedFile, "utf8")).toBe("protected");
    expect(await readFile(destination, "utf8")).toBe("protected");
  }));

  it("returns an operational failure rather than an acceptance result when a report cannot be saved", async () => sandbox(async (dir) => {
    const e = await save(dir, "evidence.json", evidence());
    const i = await save(dir, "intent.json", intent);
    const p = await save(dir, "policy.json", policy);
    const out = await command(["verify", "execution", "--evidence", e, "--intent", i,
      "--policy", p, "--report-out", join(dir, "missing-directory", "report.json")]);
    expect(out).toMatchObject({ code: 70, output: { error: { code: "CLI_OPERATION_FAILED" } } });
    expect(out.output.result).toBeUndefined();
    expect((await command(["report", "validate", "--report", e, "--report-out", join(dir, "ignored.json")])).code).toBe(64);
  }));
});

describe("independent standards CLI input boundaries", () => {
  it("does not treat missing HCS plan material as independently verified or fetch any network source", async () => sandbox(async (dir) => {
    const subject = { kind: "execution" as const, id: job, hedera_network: "testnet" as const };
    const requested = { subject, expected: [] };
    const requirements = { schema_version: VERIFICATION_POLICY_SCHEMA_VERSION,
      subject, report_kind: "independent_standards", required_checks: ["standards.references_resolved"],
      required_assurance: ["mirror_corroboration"], on_unresolved: "review",
      execution_scope: { profile: "sage-standards-v1", expected_program: "sage", requested_result_id: null } };
    const fetch_impl = vi.fn(async () => { throw new Error("No request expected without a valid standards plan"); });
    vi.stubGlobal("fetch", fetch_impl);
    const args = ["verify", "standards", "--evidence", await save(dir, "e.json", evidence()),
      "--intent", await save(dir, "intent.json", requested),
      "--policy", await save(dir, "policy.json", requirements)];
    const out = await command(args);
    expect(out.code).toBe(2);
    expect(out.output.result.policy).toMatchObject({ decision: "review", authority: "sdk_verification" });
    expect(out.output.result.report.kind).toBe("independent_standards");
    expect(out.output.result.report.core.findings.find((f: any) =>
      f.check_id === "standards.references_resolved")?.outcome).toBe("indeterminate");
    expect(fetch_impl).not.toHaveBeenCalled();
  }));

  it("rejects missing network, incorrect policy scope, unsafe Mirror and accidental modes before any I/O", async () => sandbox(async (dir) => {
    const subject = { kind: "execution" as const, id: job, hedera_network: "testnet" as const };
    const req = { schema_version: VERIFICATION_POLICY_SCHEMA_VERSION,
      subject, report_kind: "independent_standards", required_checks: ["standards.references_resolved"],
      execution_scope: { profile: "sage-standards-v1", expected_program: "sage", requested_result_id: null } };
    const e = await save(dir, "e.json", evidence());
    const i = await save(dir, "i.json", { subject, expected: [] });
    const p = await save(dir, "p.json", req);
    const args = ["verify", "standards", "--evidence", e, "--intent", i, "--policy", p];
    const fetch_impl = vi.fn(async () => { throw new Error("Invalid request caused network I/O"); });
    vi.stubGlobal("fetch", fetch_impl);
    const noNetwork = await save(dir, "no-network.json", { subject: { kind: "execution", id: job }, expected: [] });
    const wrongKind = await save(dir, "wrong-kind.json", { ...req, report_kind: "execution" });
    const wrongProgram = await save(dir, "wrong-program.json", {
      ...req, execution_scope: { ...req.execution_scope, expected_program: "other" },
    });
    for (const suffix of [
      ["--mirror-url", "http://169.254.169.254/api/v1"],
      ["--mirror-url", "https://mirror.example/api/v1?token=secret"],
      ["--mode", "offline"],
      ["--explorer-url", "https://explorer.example"],
    ]) {
      const out = await command([...args, ...suffix]);
      expect(out.code).toBe(64);
      expect(out.output.error.code).toBe("CLI_INPUT_INVALID");
    }
    const substitutions: readonly (readonly [string, string])[] = [
      ["--intent", noNetwork], ["--policy", wrongKind], ["--policy", wrongProgram],
    ];
    for (const [flag, file] of substitutions) {
      const modified = args.map((v, idx) => args[idx - 1] === flag ? file : v);
      expect((await command(modified)).code).toBe(64);
    }
    expect(fetch_impl).not.toHaveBeenCalled();
  }));
});