import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  VERIFICATION_POLICY_SCHEMA_VERSION,
  assessPortableVerificationPolicyV1,
  computeExecutionDomainSeparatedSha3_512,
  triangulateExecutionWithPolicyV1,
  validatePortableVerificationReportV1,
  verifyExecutionWithPolicyV1,
  type VerificationPolicyV1,
} from "../../src/index.js";
import { runVerifierCliV1 } from "../../src/cli/commandV1.js";

type ExecutionInput = Parameters<typeof verifyExecutionWithPolicyV1>[0];
type Scenario = "consistent" | "explorer_unavailable" | "missing_mirror" | "conflicting_topic" |
  "substituted_result" | "missing_result" | "wrong_job" | "wrong_network";

const JOB = "11111111-1111-4111-8111-111111111111";
const OTHER = "22222222-2222-4222-8222-222222222222";
const RESULT = "33333333-3333-4333-8333-333333333333";
const HASH_A = "a".repeat(128);
const HASH_B = "b".repeat(128);
const ACCEPTANCE_TX = "0.0.11@1792033594.000000001";
const RESULT_TX = "0.0.15@1792033599.000000002";
const EXPLORER = "https://explorer.example.test";
const MIRROR = "https://mirror.example.test/api/v1";

/** A real recomputable execution binding, with deliberately limited standards material. */
function evidence(resultId: string | null = null) {
  const digest_payload = { result: { x: 1 }, id: JOB };
  const digest = computeExecutionDomainSeparatedSha3_512("vera-anchor:execution-binding:v1", digest_payload);
  const accepted_at = "2026-10-15T00:00:00.000Z";
  const admission_policy_id = "standard";
  const acceptanceDigest = computeExecutionDomainSeparatedSha3_512("vera-anchor:execution-acceptance:v1", {
    record_type: "vera_anchor.execution_acceptance",
    acceptance_schema: "ExecutionAcceptanceV1",
    binding_digest_sha3_512: digest,
    job_id: JOB,
    proof_date: "2026-10-15",
    hedera_network: "testnet",
    admission_policy: { policy_id: admission_policy_id, require_hcs_confirmation_before_execution: true },
    accepted_at,
  });
  return {
    available: true, contract_version: "1.0.0",
    execution: { job_id: JOB, program: "sage", proof_date: "2026-10-15",
      hedera_network: "testnet", pipeline_hash: HASH_A,
      ...(resultId ? { result_id: resultId } : {}) },
    binding: { schema: "ExecutionBindingV1", canonicalization: "RFC8785-JCS",
      digest_algorithm: "SHA3-512", domain_separator: "vera-anchor:execution-binding:v1",
      finalized_at: "2026-10-15T00:00:00Z", digest_payload, digest },
    acceptance: { schema: "ExecutionAcceptanceV1", canonicalization: "RFC8785-JCS",
      digest_algorithm: "SHA3-512", domain_separator: "vera-anchor:execution-acceptance:v1",
      digest: acceptanceDigest, binding_digest: digest, accepted_at, admission_policy_id,
      requires_hcs_confirmation: true, state: "confirmed",
      hcs: { transaction_id: "0.0.11@1792033594.1", topic_id: "0.0.22",
        sequence_number: 3, message_id: "3@0.0.22", data_hash_sha3_512: HASH_B,
        consensus_timestamp_exact: "1792033600.123456789" } },
    ...(resultId ? { result_evidence: { schema: "ResultEvidenceV1", canonicalization: "RFC8785-JCS",
      digest_algorithm: "SHA3-512", domain_separator: "vera-anchor:result-evidence:v1",
      result_id: resultId, digest: HASH_A, binding_digest: digest, acceptance_digest: acceptanceDigest,
      pipeline_hash: HASH_A, sealed_at: "2026-10-15T01:00:00Z",
      hcs: { transaction_id: "0.0.15@1792033599.2", topic_id: "0.0.23" } } } : {}),
  };
}

function input(resultId: string | null = null): ExecutionInput {
  return {
    profile: "sage-standards-v1", expected_program: "sage", evidence: evidence(resultId),
    intent: { subject: { kind: "execution", id: JOB, hedera_network: "testnet" }, expected: [] },
    ...(resultId ? { result_id: resultId } : {}),
  };
}

function policy(kind: "execution" | "execution_triangulation", resultId: string | null = null): VerificationPolicyV1 {
  return {
    schema_version: VERIFICATION_POLICY_SCHEMA_VERSION,
    subject: { kind: "execution", id: JOB, hedera_network: "testnet" },
    report_kind: kind,
    required_checks: ["binding.digest_recomputed", "standards.references_resolved"],
    ...(kind === "execution_triangulation" ? { required_assurance: ["mirror_corroboration" as const] } : {}),
    execution_scope: { profile: "sage-standards-v1", expected_program: "sage", requested_result_id: resultId },
    on_unresolved: "review",
  };
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

/** Only Explorer and Hedera Mirror HTTP are simulated. The SDK verification path is real. */
function transport(scenario: Scenario = "consistent") {
  const requests: Array<{ url: URL; init: RequestInit }> = [];
  const fetch_impl = vi.fn(async (raw: URL | RequestInfo, init: RequestInit = {}): Promise<Response> => {
    const url = new URL(String(raw));
    requests.push({ url, init });
    if (url.pathname === `/v1/sage/results/${RESULT}`) return json({
      id: RESULT, job_id: scenario === "substituted_result" ? OTHER : JOB, hedera_network: "testnet",
    });
    if (url.pathname === `/v1/sage/jobs/${JOB}/standards`) {
      if (scenario === "explorer_unavailable") return json({ error: "unavailable" }, 503);
      const scoped = url.searchParams.get("resultId");
      const value = evidence(scoped === RESULT ? RESULT : null);
      return json({ ...value,
        execution: { ...value.execution,
          job_id: scenario === "wrong_job" ? OTHER : JOB,
          hedera_network: scenario === "wrong_network" ? "mainnet" : "testnet" },
        ...(scenario === "missing_result" ? { result_evidence: null } : {}),
      });
    }
    if (url.pathname.includes("/topics/")) {
      if (scenario === "missing_mirror") return json({}, 404);
      return json({ topic_id: scenario === "conflicting_topic" ? "0.0.999" : "0.0.22",
        sequence_number: 3, consensus_timestamp: "1792033600.123456789", message: "YWJj" });
    }
    if (url.pathname.includes("/transactions/")) return json({ transactions: [{
      transaction_id: url.pathname.includes("/transactions/0.0.15-") ? RESULT_TX : ACCEPTANCE_TX,
      result: "SUCCESS", consensus_timestamp: "1792033600.123456789",
    }] });
    throw new Error(`Unexpected SAGE resolver request: ${url}`);
  });
  return {
    requests, fetch_impl,
    config: {
      explorer: { base_url: EXPLORER, fetch_impl: fetch_impl as typeof fetch },
      mirror: { base_urls: { testnet: MIRROR }, fetch_impl: fetch_impl as typeof fetch },
    },
  };
}

function finding(report: { core: { findings: readonly { check_id: string; outcome: string }[] } }, key: string) {
  return report.core.findings.find((item) => item.check_id === key)?.outcome;
}

function publicRequirement(result: Awaited<ReturnType<typeof triangulateExecutionWithPolicyV1>>) {
  const requirement = result.policy.requirements.find((item) => item.key === "verification.public_evidence");
  expect(requirement).toBeDefined();
  return requirement!;
}

async function save(dir: string, filename: string, value: unknown): Promise<string> {
  const target = join(dir, filename);
  await writeFile(target, JSON.stringify(value), "utf8");
  return target;
}

async function cli(args: string[]): Promise<{ code: number; output: any }> {
  const lines: string[] = [];
  const code = await runVerifierCliV1(args, (line) => lines.push(line));
  expect(lines).toHaveLength(1);
  return { code, output: JSON.parse(lines[0]!) };
}

afterEach(() => vi.unstubAllGlobals());

describe("SAGE execution integration: recomputation, public scope, policy and reports", () => {
  it("INT-E01 independently recomputes the execution binding and applies a scoped offline policy", () => {
    const result = verifyExecutionWithPolicyV1(input(), policy("execution"));
    expect(result.report.kind).toBe("execution");
    expect(result.policy.authority).toBe("sdk_verification");
    expect(finding(result.report, "binding.digest_recomputed")).toBe("pass");
    expect(finding(result.report, "intent.subject")).toBe("pass");
    expect(result.policy.requirements.find((r) => r.key === "check.binding.digest_recomputed")?.outcome).toBe("pass");
    expect(result.report.context.verification_scope).toMatchObject({
      profile: "sage-standards-v1", expected_program: "sage", requested_result_id: null,
    });
    expect(validatePortableVerificationReportV1(result.report).status).toBe("valid");
    expect(result.report.core.findings.filter((f) => f.outcome === "fail")).toEqual([]);
    expect(result.policy.requirements.find((r) => r.key === "check.standards.references_resolved")?.outcome).toBe("unresolved");
    expect(result.policy.decision).toBe("review");
  });

  it("INT-E02 combines local execution recomputation, Explorer acquisition and direct Hedera corroboration", async () => {
    const remote = transport();
    const result = await triangulateExecutionWithPolicyV1(remote.config, input(), policy("execution_triangulation"));
    expect(result.report.kind).toBe("execution_triangulation");
    expect(result.policy.authority).toBe("sdk_verification");
    expect(finding(result.report, "binding.digest_recomputed")).toBe("pass");
    expect(result.report.context.public_execution).toMatchObject({
      status: "resolved", public_record_acquisition: "resolved", mirror_status: "resolved",
      hedera_resolution: "resolved",
    });
    expect(result.report.context.public_execution).not.toHaveProperty("publication_payload_binding");
    expect(result.policy.requirements.find((r) => r.key === "assurance.mirror_corroboration")?.outcome).toBe("pass");
    const triangulation = result.report.context.triangulation as {
      consistency: string;
      relationships: Array<{ id: string; status: string }>;
    };
    expect(triangulation.relationships.find((r) => r.id === "public_record_hedera")?.status).toBe("consistent");
    expect(triangulation.relationships.find((r) => r.id === "provided_hedera")?.status).toBe("consistent");
    // Completion also depends on the triangulation's source-verification prerequisite.
    // An incomplete source prerequisite is not silently promoted by a resolved Mirror response.
    expect(publicRequirement(result).outcome).toBe(triangulation.consistency === "consistent" ? "pass" : "unresolved");
    expect(result.policy.decision).toBe("review");
    expect(result.report.core.findings.filter((f) => f.outcome === "fail")).toEqual([]);
    expect(validatePortableVerificationReportV1(result.report).status).toBe("valid");
    expect(remote.requests).toHaveLength(5);
    expect(remote.requests.every((r) => r.init.credentials === "omit" && r.init.redirect === "error")).toBe(true);
    expect(remote.requests.every((r) => r.url.host === "explorer.example.test" || r.url.host === "mirror.example.test")).toBe(true);
  });

  it("INT-E03 binds a requested result before reading standards and rejects substitution or job-level fallback", async () => {
    const valid = transport();
    const result = await triangulateExecutionWithPolicyV1(
      valid.config, input(RESULT), policy("execution_triangulation", RESULT));
    expect(result.report.context).toMatchObject({
      verification_scope: { requested_result_id: RESULT },
    });
    expect(result.report.context.public_execution).toMatchObject({
      status: "resolved", hedera_resolution: "resolved",
    });
    expect(result.report.context.public_execution).not.toHaveProperty("publication_payload_binding");
    expect(valid.requests[0]?.url.pathname).toBe(`/v1/sage/results/${RESULT}`);
    expect(valid.requests[1]?.url.searchParams.get("resultId")).toBe(RESULT);
    expect(valid.requests.every((r) => !r.url.pathname.includes("/latest"))).toBe(true);
    expect(valid.requests.filter((r) => r.url.host === "mirror.example.test")).toHaveLength(6);

    for (const scenario of ["substituted_result", "missing_result"] as const) {
      const remote = transport(scenario);
      const rejected = await triangulateExecutionWithPolicyV1(
        remote.config, input(RESULT), policy("execution_triangulation", RESULT));
      expect(rejected.policy.decision, scenario).not.toBe("allow");
      expect(rejected.report.context.public_execution).toMatchObject({ hedera_resolution: "not_checked" });
      expect(remote.requests.some((r) => r.url.host === "mirror.example.test")).toBe(false);
      expect(remote.requests.every((r) => !r.url.pathname.includes("/latest"))).toBe(true);
    }
  });

  it("INT-E04 rejects an altered execution-binding digest despite unchanged caller scope", () => {
    const original = input();
    const altered = { ...original, evidence: {
      ...evidence(), binding: { ...evidence().binding, digest: "0".repeat(128) },
    } };
    const result = verifyExecutionWithPolicyV1(altered, policy("execution"));
    expect(finding(result.report, "binding.digest_recomputed")).toBe("fail");
    expect(result.policy.requirements.find((r) => r.key === "check.binding.digest_recomputed")?.outcome).toBe("fail");
    expect(result.policy.decision).toBe("deny");
    expect(validatePortableVerificationReportV1(result.report).status).toBe("valid");
  });

  it("INT-E05 rejects wrong relying-party network before I/O and never substitutes a different public job or network", async () => {
    const preflight = transport();
    await expect(triangulateExecutionWithPolicyV1(preflight.config, input(), {
      ...policy("execution_triangulation"),
      subject: { kind: "execution", id: JOB, hedera_network: "mainnet" },
    })).rejects.toThrow(/policy intent/);
    expect(preflight.requests).toHaveLength(0);

    for (const scenario of ["wrong_job", "wrong_network"] as const) {
      const remote = transport(scenario);
      const result = await triangulateExecutionWithPolicyV1(
        remote.config, input(), policy("execution_triangulation"));
      expect(result.policy.decision, scenario).toBe("deny");
      expect(result.report.context.public_execution).toMatchObject({ hedera_resolution: "not_checked" });
      expect(remote.requests).toHaveLength(1);
    }
  });

  it("INT-E06 preserves missing-evidence uncertainty and denies conflicting Mirror facts", async () => {
    for (const scenario of ["explorer_unavailable", "missing_mirror", "conflicting_topic"] as const) {
      const remote = transport(scenario);
      const result = await triangulateExecutionWithPolicyV1(
        remote.config, input(), policy("execution_triangulation"));
      const requirement = publicRequirement(result);
      const conflict = scenario === "conflicting_topic";
      expect(requirement.outcome).toBe(conflict ? "fail" : "unresolved");
      expect(requirement.reason_code).toBe(conflict ?
        "POLICY_PUBLIC_EVIDENCE_CONFLICT" : "POLICY_PUBLIC_EVIDENCE_INCOMPLETE");
      expect(result.policy.reason_codes).toContain(requirement.reason_code);
      expect(result.policy.decision).not.toBe("allow");
      if (conflict) expect(result.policy.decision).toBe("deny");
      expect(validatePortableVerificationReportV1(result.report).status).toBe("valid");
      if (scenario === "explorer_unavailable") expect(remote.requests).toHaveLength(1);
    }
  });

  it("INT-E07 runs the CLI through public verification, report export, integrity check and unauthenticated assessment", async () => {
    const dir = await mkdtemp(join(tmpdir(), "va-execution-int-"));
    try {
      const remote = transport();
      vi.stubGlobal("fetch", remote.fetch_impl);
      const document = await save(dir, "evidence.json", evidence());
      const intent = await save(dir, "intent.json", input().intent);
      const constraints = policy("execution_triangulation");
      const policyPath = await save(dir, "policy.json", constraints);
      const outputPath = join(dir, "execution-report.json");
      const verified = await cli(["verify", "execution", "--mode", "public",
        "--explorer-url", EXPLORER, "--mirror-url", MIRROR,
        "--evidence", document, "--intent", intent, "--policy", policyPath,
        "--report-out", outputPath]);
      expect(verified.output.result.report.kind).toBe("execution_triangulation");
      expect(verified.output.result.policy.authority).toBe("sdk_verification");
      expect(verified.output.result.report.context.public_execution).not.toHaveProperty(
        "publication_payload_binding");
      expect(verified.code).toBe(verified.output.result.policy.decision === "allow" ? 0 :
        verified.output.result.policy.decision === "review" ? 2 : 1);
      const saved = JSON.parse(await readFile(outputPath, "utf8"));
      expect(saved).toEqual(verified.output.result.report);
      expect(validatePortableVerificationReportV1(saved).status).toBe("valid");
      const validated = await cli(["report", "validate", "--report", outputPath]);
      expect(validated.code).toBe(0);
      expect(validated.output.result).toMatchObject({ status: "valid", authenticity: "not_checked" });
      const assessed = await cli(["policy", "assess", "--report", outputPath, "--policy", policyPath]);
      expect(assessed.output.result.authority).toBe("unauthenticated_report");
      expect(assessed.output.result.decision).not.toBe("allow");
      expect(assessed.code).not.toBe(0);
      expect(assessPortableVerificationPolicyV1(saved, constraints).decision).not.toBe("allow");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});