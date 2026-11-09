import { describe, expect, it, vi } from "vitest";
import type { VerificationReport } from "../../src/contracts/verification.js";
import type { ExecutionV1Report } from "../../src/profiles/execution/verificationV1.js";
import { createPortableVerificationReportV1 } from "../../src/reports/portableV1.js";
import { VERIFICATION_POLICY_SCHEMA_VERSION, type VerificationPolicyV1 } from "../../src/policy/contractV1.js";
import { assessPortableVerificationPolicyV1, verifyDatasetWithPolicyV1,
  verifyExecutionWithPolicyV1, triangulateDatasetWithPolicyV1,
  triangulateIngestWithPolicyV1, triangulateExecutionWithPolicyV1,
  verifyExecutionStandardsWithPolicyV1 } from "../../src/policy/evaluateV1.js";
import { verifyDatasetV1WithIntent } from "../../src/verification/sourceIntentV1.js";
import { verifyExecutionV1WithIntent } from "../../src/profiles/execution/verificationV1.js";
import { verifyExecutionWithIndependentStandardsV1 } from "../../src/profiles/execution/independentStandardsV1.js";
import { triangulateDatasetV1, triangulateIngestV1,
  type PublicTriangulationV1Result } from "../../src/triangulation/publicV1.js";
import { triangulatePublicExecutionV1,
  type PublicExecutionTriangulationV1Result } from "../../src/triangulation/executionPublicV1.js";

vi.mock("../../src/verification/sourceIntentV1.js", () => ({
  verifyDatasetV1WithIntent: vi.fn(), verifyIngestV1WithIntent: vi.fn(),
}));
vi.mock("../../src/profiles/execution/verificationV1.js", () => ({
  verifyExecutionV1WithIntent: vi.fn(),
}));
vi.mock("../../src/profiles/execution/independentStandardsV1.js", () => ({
  verifyExecutionWithIndependentStandardsV1: vi.fn(),
}));
vi.mock("../../src/triangulation/publicV1.js", () => ({
  triangulateDatasetV1: vi.fn(), triangulateIngestV1: vi.fn(),
}));
vi.mock("../../src/triangulation/executionPublicV1.js", () => ({
  triangulatePublicExecutionV1: vi.fn(),
}));

const job = "11111111-1111-4111-8111-111111111111";
const subject = { kind: "dataset" as const, id: "dataset-1", hedera_network: "testnet" as const };
function source(): VerificationReport {
  return { intent: { subject, expected: [] },
    observations: [
      { id: "dataset.source", subject, source: "local_computation", facts: [
        { key: "source_merkle_root", state: "available", value: "a".repeat(128) },
      ] },
    ],
    findings: [
      { check_id: "intent.subject", outcome: "pass", reason_code: null, observation_ids: ["dataset.source"] },
      { check_id: "dataset.source_binding", outcome: "pass", reason_code: null,
        observation_ids: ["dataset.source"] },
      { check_id: "dataset.bundle_consistency", outcome: "pass", reason_code: null,
        observation_ids: ["dataset.source"] },
    ] };
}
function policy(): VerificationPolicyV1 {
  return { schema_version: VERIFICATION_POLICY_SCHEMA_VERSION, subject,
    report_kind: "verification", required_checks: ["dataset.source_binding", "dataset.bundle_consistency"] };
}
function execution(): ExecutionV1Report {
  const who = { kind: "execution" as const, id: job, hedera_network: "testnet" as const };
  return { intent: { subject: who, expected: [] },
    verification_scope: { profile: "sage-standards-v1", expected_program: "sage", requested_result_id: null },
    observations: [{ id: "execution.provided", subject: who, source: "provided_evidence", facts: [] },
      { id: "execution.recomputed", subject: who, source: "local_computation", facts: [
        { key: "check.acceptance.digest_recomputed", state: "available", value: true },
      ] }],
    findings: [
      { check_id: "intent.subject", outcome: "pass", reason_code: null, observation_ids: ["execution.provided"] },
      { check_id: "profile.program_scope", outcome: "pass", reason_code: null, observation_ids: ["execution.provided"] },
      { check_id: "acceptance.digest_recomputed", outcome: "pass", reason_code: null,
        observation_ids: ["execution.provided", "execution.recomputed"] },
    ] };
}

describe("verification policy and report authority", () => {
  it("does not allow based on an internally valid but unsigned imported report", () => {
    const doc = createPortableVerificationReportV1({ kind: "verification", result: source() });
    expect(assessPortableVerificationPolicyV1(doc, policy())).toMatchObject({ decision: "review",
      authority: "unauthenticated_report", reason_codes: ["POLICY_REPORT_NOT_AUTHENTICATED"] });
  });

  it("denies a verified-finding contradiction even in an unrequired check", () => {
    const x = source();
    const bad = { ...x, findings: [...x.findings, { check_id: "dataset.receipt_binding", outcome: "fail" as const,
      reason_code: "MISMATCH", observation_ids: ["dataset.source"] }] };
    const doc = createPortableVerificationReportV1({ kind: "verification", result: bad });
    expect(assessPortableVerificationPolicyV1(doc, policy()).decision).toBe("deny");
  });

  it("fails closed on subject, network and report-kind substitution", () => {
    const doc = createPortableVerificationReportV1({ kind: "verification", result: source() });
    expect(assessPortableVerificationPolicyV1(doc, { ...policy(), subject: { ...subject, id: "other" } }).decision).toBe("deny");
    expect(assessPortableVerificationPolicyV1(doc, { ...policy(), subject: { ...subject, hedera_network: "mainnet" } }).decision).toBe("deny");
    expect(assessPortableVerificationPolicyV1(doc, { ...policy(), report_kind: "public_triangulation" }).decision).toBe("deny");
  });

  it("does not treat missing, indeterminate, skipped or unsupported checks as passes", () => {
    for (const status of [undefined, "indeterminate", "skipped", "unsupported"] as const) {
      const x = source();
      const other: VerificationReport = { ...x,
        findings: [...x.findings.filter((f) => f.check_id !== "dataset.source_binding"),
          ...(status ? [{ check_id: "dataset.source_binding", outcome: status, reason_code: "NOT_VERIFIED",
            observation_ids: ["dataset.source"] }] : [])] };
      const doc = createPortableVerificationReportV1({ kind: "verification", result: other });
      expect(assessPortableVerificationPolicyV1(doc, policy()).decision).toBe("review");
      expect(assessPortableVerificationPolicyV1(doc, { ...policy(), on_unresolved: "deny" }).decision).toBe("deny");
    }
  });

  it("does not count a mirror-labelled observation as established Mirror corroboration", () => {
    const x = source();
    const doc = createPortableVerificationReportV1({ kind: "verification", result: {
      ...x, observations: [...x.observations, { ...x.observations[0]!, id: "dataset.mirror", source: "hedera_mirror" as const }],
    } });
    const p: VerificationPolicyV1 = { ...policy(), required_assurance: ["mirror_corroboration"] };
    const result = assessPortableVerificationPolicyV1(doc, p);
    expect(result.decision).toBe("review");
    expect(result.requirements.filter((r) => r.key.startsWith("assurance.")).map((r) => r.outcome)).toEqual(["unresolved"]);
  });

  it("requires exact expected execution scope rather than accepting evidence's declared program", () => {
    const doc = createPortableVerificationReportV1({ kind: "execution", result: execution() });
    const intended: VerificationPolicyV1 = { schema_version: VERIFICATION_POLICY_SCHEMA_VERSION,
      subject: execution().intent.subject, report_kind: "execution", required_checks: ["profile.program_scope"],
      execution_scope: { profile: "sage-standards-v1", expected_program: "other", requested_result_id: null } };
    expect(assessPortableVerificationPolicyV1(doc, intended).decision).toBe("deny");
  });

  it("rejects malformed policies, duplicate checks and unrecognized claims", () => {
    const doc = createPortableVerificationReportV1({ kind: "verification", result: source() });
    expect(() => assessPortableVerificationPolicyV1(doc, { ...policy(), required_checks: [] })).toThrow();
    expect(() => assessPortableVerificationPolicyV1(doc, { ...policy(), required_checks: ["intent.subject", "intent.subject"] })).toThrow();
    expect(() => assessPortableVerificationPolicyV1(doc, { ...policy(), required_assurance: ["authenticated" as never] })).toThrow();
    expect(() => assessPortableVerificationPolicyV1(doc, { ...policy(), executable: "return true" } as never)).toThrow();
    const accessor = { ...policy() };
    Object.defineProperty(accessor, "required_checks", { enumerable: true, get: () => ["dataset.source_binding"] });
    expect(() => assessPortableVerificationPolicyV1(doc, accessor)).toThrow(/field/);
  });

  it("produces stable policy assessment independent of required-check ordering", () => {
    const doc = createPortableVerificationReportV1({ kind: "verification", result: source() });
    const a = assessPortableVerificationPolicyV1(doc, policy());
    const b = assessPortableVerificationPolicyV1(doc, { ...policy(), required_checks: [...policy().required_checks].reverse() });
    expect(a).toEqual(b);
  });

  it("rejects digest-tampered saved reports instead of evaluating their claims", () => {
    const doc = createPortableVerificationReportV1({ kind: "verification", result: source() });
    const changed = { ...doc, report_sha3_512: "f".repeat(128) };
    expect(assessPortableVerificationPolicyV1(changed, policy())).toMatchObject({
      decision: "deny", reason_codes: ["POLICY_REPORT_INVALID"] });
  });

  it("allows only through a fresh SDK dataset verification invocation", async () => {
    vi.mocked(verifyDatasetV1WithIntent).mockResolvedValueOnce(source());
    const input = { intent: source().intent } as Parameters<typeof verifyDatasetV1WithIntent>[0];
    const x = await verifyDatasetWithPolicyV1(input, policy());
    expect(verifyDatasetV1WithIntent).toHaveBeenCalledWith(input);
    expect(x.policy).toMatchObject({ decision: "allow", authority: "sdk_verification" });
    expect(assessPortableVerificationPolicyV1(x.report, policy()).decision).toBe("review");
  });

  it("requires exact execution intent on fresh SDK verification", () => {
    vi.mocked(verifyExecutionV1WithIntent).mockReturnValueOnce(execution());
    const x = verifyExecutionWithPolicyV1({ intent: execution().intent, evidence: {} } as Parameters<typeof verifyExecutionV1WithIntent>[0],
      { schema_version: VERIFICATION_POLICY_SCHEMA_VERSION,
        subject: execution().intent.subject, report_kind: "execution", required_checks: ["profile.program_scope"],
        execution_scope: { profile: "sage-standards-v1", expected_program: "sage", requested_result_id: null } });
    expect(x.policy.decision).toBe("review");
  });

  it("allows a required locally recomputed execution check after SDK verification", () => {
    vi.mocked(verifyExecutionV1WithIntent).mockReturnValueOnce(execution());
    const p: VerificationPolicyV1 = { schema_version: VERIFICATION_POLICY_SCHEMA_VERSION,
      subject: execution().intent.subject, report_kind: "execution", required_checks: ["acceptance.digest_recomputed"],
      execution_scope: { profile: "sage-standards-v1", expected_program: "sage", requested_result_id: null } };
    const result = verifyExecutionWithPolicyV1({ intent: execution().intent, evidence: {} } as
      Parameters<typeof verifyExecutionV1WithIntent>[0], p);
    expect(result.policy.decision).toBe("allow");
    expect(assessPortableVerificationPolicyV1(result.report, p).decision).toBe("review");
  });
});

function publicSource(kind: "dataset" | "ingest"): VerificationReport {
  const selected = { kind, id: `${kind}-1`, hedera_network: "testnet" as const };
  return { intent: { subject: selected, expected: [] },
    observations: [{ id: `${kind}.source`, subject: selected, source: "local_computation", facts: [
      { key: "source_merkle_root", state: "available", value: "a".repeat(128) },
    ] }],
    findings: [
      { check_id: "intent.subject", outcome: "pass", reason_code: null, observation_ids: [`${kind}.source`] },
      { check_id: `${kind}.source_binding`, outcome: "pass", reason_code: null, observation_ids: [`${kind}.source`] },
    ],
  };
}

function publicResult(kind: "dataset" | "ingest"): PublicTriangulationV1Result {
  const base = publicSource(kind);
  const comparisons = [
    { id: "provided_public_record" as const, key: "fingerprint" },
    { id: "public_record_hedera" as const, key: "publication_topic" },
  ];
  return { consistency: "consistent",
    relationships: comparisons.map((part) => ({ id: part.id, status: "consistent" as const,
      fact_comparisons: [{ key: part.key, outcome: "pass" as const, reason_code: null }] })),
    report: { ...base, findings: [...base.findings, ...comparisons.map((part) => ({
      check_id: `triangulation.${part.id}.${part.key}`, outcome: "pass" as const, reason_code: null,
      observation_ids: [`${kind}.source`],
    }))] },
    resolution: { public_record: "resolved", publication_disclosure: "resolved", hedera_mirror: "resolved" },
  };
}

function publicExecutionResult(): PublicExecutionTriangulationV1Result {
  const initial = execution();
  const compared = { ...initial, findings: [...initial.findings, {
    check_id: "triangulation.provided_hedera.transaction_id", outcome: "pass" as const,
    reason_code: null, observation_ids: ["execution.provided"],
  }] };
  return {
    status: "resolved", reason_code: null, public_record_acquisition: "resolved",
    hedera_resolution: "resolved",
    plan: { stage: "unresolved_authority_plan", public_record_acquisition: "not_checked",
      hedera_resolution: "not_checked",
      source_report: initial, hedera_targets: [{ source: "provided_evidence", role: "acceptance_anchor",
        network: "testnet", transaction_id: "0.0.123@1792000000.000000001", topic_id: null,
        sequence_number: null, observation_fact_prefix: "ledger.provided_evidence.acceptance_anchor" }],
      triangulation: { source_report: initial, observations: [], relationships: [] } },
    mirror: { status: "resolved", reason_code: null },
    comparison: { consistency: "consistent", relationships: [{ id: "provided_hedera", status: "consistent",
      fact_comparisons: [{ key: "transaction_id", outcome: "pass", reason_code: null }] }], report: compared },
  } as unknown as PublicExecutionTriangulationV1Result;
}

function onlinePolicy(kind: "dataset" | "ingest"): VerificationPolicyV1 {
  const base = publicSource(kind);
  return { schema_version: VERIFICATION_POLICY_SCHEMA_VERSION, subject: base.intent.subject,
    report_kind: "public_triangulation", required_checks: [`${kind}.source_binding`],
    required_assurance: ["mirror_corroboration"] };
}

describe("SDK-owned public triangulation policy workflows", () => {
  const config = {} as Parameters<typeof triangulateDatasetV1>[0];

  it("allows a fully resolved dataset pathway with local source verification and Mirror corroboration", async () => {
    vi.mocked(triangulateDatasetV1).mockResolvedValueOnce(publicResult("dataset"));
    const input = { intent: publicSource("dataset").intent } as Parameters<typeof triangulateDatasetV1>[1];
    const response = await triangulateDatasetWithPolicyV1(config, input, onlinePolicy("dataset"));
    expect(response.report.kind).toBe("public_triangulation");
    expect(response.policy).toMatchObject({ decision: "allow", authority: "sdk_verification" });
    expect(assessPortableVerificationPolicyV1(response.report, onlinePolicy("dataset")).decision).toBe("review");
  });

  it("retains the distinct Core anchor identity in the ingest public verification request", async () => {
    vi.mocked(triangulateIngestV1).mockResolvedValueOnce(publicResult("ingest"));
    const input = { intent: publicSource("ingest").intent,
      anchor_request_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" } as Parameters<typeof triangulateIngestV1>[1];
    const response = await triangulateIngestWithPolicyV1(config, input, onlinePolicy("ingest"));
    expect(triangulateIngestV1).toHaveBeenCalledWith(config, input);
    expect(response.policy.decision).toBe("allow");
  });

  it("does not allow offline-only findings if the public evidence or Mirror is unavailable", async () => {
    const good = publicResult("dataset");
    const missing: PublicTriangulationV1Result = { ...good, consistency: "incomplete",
      relationships: good.relationships.filter((rel) => rel.id !== "public_record_hedera"),
      report: { ...good.report, findings: good.report.findings.filter((f) =>
        !f.check_id.startsWith("triangulation.public_record_hedera.")) },
      resolution: { ...good.resolution, hedera_mirror: "unavailable" } };
    vi.mocked(triangulateDatasetV1).mockResolvedValueOnce(missing);
    const input = { intent: publicSource("dataset").intent } as Parameters<typeof triangulateDatasetV1>[1];
    const response = await triangulateDatasetWithPolicyV1(config, input,
      { schema_version: VERIFICATION_POLICY_SCHEMA_VERSION, subject: input.intent.subject,
        report_kind: "public_triangulation", required_checks: ["dataset.source_binding"] });
    expect(response.policy).toMatchObject({ decision: "review",
      reason_codes: ["POLICY_PUBLIC_EVIDENCE_INCOMPLETE"] });
  });

  it("denies a resolved public evidence conflict even if only offline checks are requested", async () => {
    const good = publicResult("dataset");
    const contradictory: PublicTriangulationV1Result = { ...good, consistency: "conflict",
      resolution: { ...good.resolution, public_record: "conflict" } };
    vi.mocked(triangulateDatasetV1).mockResolvedValueOnce(contradictory);
    const input = { intent: publicSource("dataset").intent } as Parameters<typeof triangulateDatasetV1>[1];
    const response = await triangulateDatasetWithPolicyV1(config, input,
      { schema_version: VERIFICATION_POLICY_SCHEMA_VERSION, subject: input.intent.subject,
        report_kind: "public_triangulation", required_checks: ["dataset.source_binding"] });
    expect(response.policy.decision).toBe("deny");
  });

  it("refuses mismatched public intent or report kind before any acquisition", async () => {
    const input = { intent: publicSource("dataset").intent } as Parameters<typeof triangulateDatasetV1>[1];
    await expect(triangulateDatasetWithPolicyV1(config, input,
      { ...onlinePolicy("dataset"), subject: { ...input.intent.subject, id: "other" } }))
      .rejects.toThrow(/policy intent/);
    await expect(triangulateDatasetWithPolicyV1(config, input,
      { ...onlinePolicy("dataset"), report_kind: "verification" }))
      .rejects.toThrow(/policy intent/);
  });

  it("integrates public SAGE execution with resolved Mirror corroboration", async () => {
    vi.mocked(triangulatePublicExecutionV1).mockResolvedValueOnce(publicExecutionResult());
    const input = { intent: execution().intent, evidence: {} } as Parameters<typeof triangulatePublicExecutionV1>[1];
    const required: VerificationPolicyV1 = { schema_version: VERIFICATION_POLICY_SCHEMA_VERSION,
      subject: execution().intent.subject, report_kind: "execution_triangulation",
      required_checks: ["acceptance.digest_recomputed"], required_assurance: ["mirror_corroboration"],
      execution_scope: execution().verification_scope };
    const response = await triangulateExecutionWithPolicyV1(config, input, required);
    expect(response.policy.decision).toBe("allow");
    expect(response.report.context.public_execution).toMatchObject({
      public_record_acquisition: "resolved", hedera_resolution: "resolved", mirror_status: "resolved",
    });
    expect(assessPortableVerificationPolicyV1(response.report, required).decision).toBe("review");
  });

  it("keeps unresolved SAGE public acquisition non-authorizing after offline recomputation", async () => {
    vi.mocked(triangulatePublicExecutionV1).mockResolvedValueOnce({ status: "not_found", reason_code: "EXECUTION_NOT_FOUND",
      public_record_acquisition: "not_found", hedera_resolution: "not_checked",
      plan: null, mirror: null, comparison: null });
    vi.mocked(verifyExecutionV1WithIntent).mockReturnValueOnce(execution());
    const input = { intent: execution().intent, evidence: {} } as Parameters<typeof triangulatePublicExecutionV1>[1];
    const required: VerificationPolicyV1 = { schema_version: VERIFICATION_POLICY_SCHEMA_VERSION,
      subject: execution().intent.subject, report_kind: "execution_triangulation",
      required_checks: ["acceptance.digest_recomputed"], execution_scope: execution().verification_scope };
    const response = await triangulateExecutionWithPolicyV1(config, input, required);
    expect(response.policy.decision).toBe("review");
    expect(response.report.context.public_execution).toMatchObject({ status: "not_found" });
  });

  it("rejects the removed publication payload assurance", async () => {
    vi.mocked(triangulatePublicExecutionV1).mockResolvedValueOnce(publicExecutionResult());
    const input = { intent: execution().intent, evidence: {} } as Parameters<typeof triangulatePublicExecutionV1>[1];
    const required: VerificationPolicyV1 = { schema_version: VERIFICATION_POLICY_SCHEMA_VERSION,
      subject: execution().intent.subject, report_kind: "execution_triangulation",
      required_checks: ["acceptance.digest_recomputed"], required_assurance: ["publication_payload_binding" as never],
      execution_scope: execution().verification_scope };
    await expect(triangulateExecutionWithPolicyV1(config, input, required))
      .rejects.toThrow(/Unsupported assurance dimension/);
  });
});

describe("independent HCS standards policy boundary", () => {
  const subject = { kind: "execution" as const, id: job, hedera_network: "testnet" as const };
  const sample = { profile: "sage-standards-v1" as const, intent: { subject, expected: [] }, evidence: {} } as
    Parameters<typeof verifyExecutionWithIndependentStandardsV1>[1];
  const policy: VerificationPolicyV1 = {
    schema_version: VERIFICATION_POLICY_SCHEMA_VERSION, subject,
    report_kind: "independent_standards", required_checks: ["acceptance.digest_recomputed"],
    required_assurance: ["mirror_corroboration"],
    execution_scope: { profile: "sage-standards-v1", expected_program: "sage", requested_result_id: null },
  };
  const config = {} as Parameters<typeof verifyExecutionWithIndependentStandardsV1>[0];
  const options = {} as Parameters<typeof verifyExecutionWithIndependentStandardsV1>[2];

  it("rejects an unrelated policy before any standards resolver is called", async () => {
    await expect(verifyExecutionStandardsWithPolicyV1(config, sample, options,
      { ...policy, subject: { ...subject, hedera_network: "mainnet" } })).rejects.toThrow(/policy intent/);
    expect(verifyExecutionWithIndependentStandardsV1).not.toHaveBeenCalled();
  });

  it("retains Mirror-only assurance without exposing DID or consensus authentication claims", async () => {
    const base = execution();
    vi.mocked(verifyExecutionWithIndependentStandardsV1).mockResolvedValueOnce({
      ...base, findings: [...base.findings,
        { check_id: "standards.reference.0", outcome: "pass", reason_code: null,
          observation_ids: ["standards.mirror.0"] },
        { check_id: "standards.references_resolved", outcome: "pass", reason_code: null,
          observation_ids: ["standards.mirror.0"] }],
      observations: [...base.observations, { id: "standards.mirror.0", subject,
        source: "hedera_mirror", facts: [] }],
      independent_standards: {
        network: "testnet", status: "verified", assurance: "mirror_corroborated",
        items: [{ key: "agent.0", standard: "HCS-11", reference: "hcs://1/0.0.100",
          status: "resolved", reason_code: null, resolver_id: "hedera.mirror-rest.hcs11.v1",
          historical_consensus_timestamps_exact: ["1792000000.000000001"],
          current_topic_or_account_memo_observed: true, content_sha256: "a".repeat(64),
          assurance: "mirror_corroborated" }],
      },
    });
    const output = await verifyExecutionStandardsWithPolicyV1(config, sample, options, policy);
    expect(verifyExecutionWithIndependentStandardsV1).toHaveBeenCalledWith(config, sample, options);
    expect(output.report.kind).toBe("independent_standards");
    expect(output.policy.requirements.find((r) => r.key === "assurance.mirror_corroboration")?.outcome).toBe("pass");
    expect(output.policy.decision).toBe("allow");
    expect(JSON.stringify(output.report)).not.toContain("did_controller_authentication");
    expect(JSON.stringify(output.report)).not.toContain("hedera_consensus_authentication");
    expect(assessPortableVerificationPolicyV1(output.report, policy).decision).toBe("review");
  });
});