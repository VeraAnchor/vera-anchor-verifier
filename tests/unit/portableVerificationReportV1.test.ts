import { describe, expect, it } from "vitest";
import type { VerificationReport } from "../../src/contracts/verification.js";
import type { ExecutionV1Report } from "../../src/profiles/execution/verificationV1.js";
import type { IndependentStandardsV1Report } from "../../src/profiles/execution/independentStandardsV1.js";
import type { PublicTriangulationV1Result } from "../../src/triangulation/publicV1.js";
import type { PublicExecutionTriangulationV1Result } from "../../src/triangulation/executionPublicV1.js";
import { createPortableVerificationReportV1, canonicalizePortableVerificationReportV1,
  computePortableVerificationReportDigestV1, PORTABLE_VERIFICATION_REPORT_SCHEMA_VERSION,
} from "../../src/reports/portableV1.js";
import { validatePortableVerificationReportV1, comparePortableVerificationReportsV1 } from "../../src/reports/validationV1.js";

const job = "11111111-1111-4111-8111-111111111111";
const resultId = "22222222-2222-4222-8222-222222222222";

function dataset(): VerificationReport {
  const subject = { kind: "dataset" as const, id: "dataset-1", hedera_network: "testnet" as const };
  return {
    intent: { subject, expected: [] },
    findings: [{ check_id: "dataset.source_binding", outcome: "pass", reason_code: null,
      observation_ids: ["dataset.source"] }],
    observations: [{ id: "dataset.source", subject, source: "local_computation", facts: [
      { key: "bundle_digest", state: "available", value: "a".repeat(128) },
    ] }],
  };
}

function execution(): ExecutionV1Report {
  const subject = { kind: "execution" as const, id: job, hedera_network: "testnet" as const };
  return {
    intent: { subject, expected: [] },
    verification_scope: { profile: "sage-standards-v1", expected_program: "sage", requested_result_id: resultId },
    findings: [
      { check_id: "intent.subject", outcome: "pass", reason_code: null, observation_ids: ["execution.provided"] },
      { check_id: "intent.result", outcome: "pass", reason_code: null, observation_ids: ["execution.provided"] },
    ],
    observations: [{ id: "execution.provided", subject, source: "provided_evidence", facts: [
      { key: "execution.job_id", state: "available", value: job },
    ] }],
  };
}

function independent(): IndependentStandardsV1Report {
  const source = execution();
  return {
    ...source,
    findings: [...source.findings,
      { check_id: "standards.reference.0", outcome: "pass", reason_code: null, observation_ids: ["standards.mirror.0"] },
      { check_id: "standards.references_resolved", outcome: "pass", reason_code: null,
        observation_ids: ["standards.mirror.0"] }],
    observations: [...source.observations,
      { id: "standards.mirror.0", subject: source.intent.subject, source: "hedera_mirror", facts: [
        { key: "standards.resolution_status", state: "available", value: "resolved" },
      ] }],
    independent_standards: {
      network: "testnet", status: "verified", assurance: "mirror_corroborated",
      items: [{ key: "agent.0", standard: "HCS-11", reference: "hcs://1/0.0.100",
        status: "resolved", reason_code: null, resolver_id: "hedera.mirror-rest.hcs11.v1",
        historical_consensus_timestamps_exact: ["1792000000.000000001"],
        current_topic_or_account_memo_observed: true,
        content_sha256: "a".repeat(64), assurance: "mirror_corroborated" }],
    },
  };
}

function publicDataset(): PublicTriangulationV1Result {
  const source = dataset();
  const relationship = { id: "provided_public_record" as const, status: "consistent" as const,
    fact_comparisons: [{ key: "bundle_digest", outcome: "pass" as const, reason_code: null }] };
  return {
    consistency: "consistent", relationships: [relationship],
    report: { ...source, findings: [...source.findings,
      { check_id: "triangulation.provided_public_record.bundle_digest", outcome: "pass", reason_code: null,
        observation_ids: ["dataset.source"] }] },
    resolution: { public_record: "resolved", publication_disclosure: "resolved", hedera_mirror: "resolved" },
  } as PublicTriangulationV1Result;
}

function publicExecution(): PublicExecutionTriangulationV1Result {
  const source = execution();
  const comparisonReport = { ...source, findings: [...source.findings,
    { check_id: "triangulation.provided_hedera.transaction_id", outcome: "pass" as const,
      reason_code: null, observation_ids: ["execution.provided"] }] };
  return {
    status: "resolved", reason_code: null, public_record_acquisition: "resolved",
    hedera_resolution: "resolved",
    plan: { stage: "unresolved_authority_plan", public_record_acquisition: "not_checked",
      hedera_resolution: "not_checked",
      source_report: source,
      hedera_targets: [{ source: "provided_evidence", role: "acceptance_anchor", network: "testnet",
        transaction_id: "0.0.123@1792000000.000000001", topic_id: null, sequence_number: null,
        observation_fact_prefix: "ledger.provided_evidence.acceptance_anchor" }],
      triangulation: { source_report: source, observations: [], relationships: [] },
    },
    mirror: { status: "resolved", reason_code: null },
    comparison: { consistency: "consistent", relationships: [{ id: "provided_hedera", status: "consistent",
      fact_comparisons: [{ key: "transaction_id", outcome: "pass", reason_code: null }] }],
      report: comparisonReport },
  } as unknown as PublicExecutionTriangulationV1Result;
}

describe("portable verification report", () => {
  it("builds a versioned dataset report with distinct core and envelope digests", () => {
    const output = createPortableVerificationReportV1({ kind: "verification", result: dataset() });
    expect(output.schema_version).toBe(PORTABLE_VERIFICATION_REPORT_SCHEMA_VERSION);
    expect(output.kind).toBe("verification");
    expect(output.core_sha3_512).toMatch(/^[a-f0-9]{128}$/);
    expect(output.report_sha3_512).toMatch(/^[a-f0-9]{128}$/);
    expect(output.report_sha3_512).not.toBe(output.core_sha3_512);
  });

  it("is deterministic under reordered set-like core findings and facts", () => {
    const first = dataset();
    const second: VerificationReport = { ...first,
      observations: first.observations.map((o) => ({ ...o, facts: [...o.facts].reverse() })),
      findings: [...first.findings].reverse() };
    expect(canonicalizePortableVerificationReportV1({ kind: "verification", result: first }))
      .toBe(canonicalizePortableVerificationReportV1({ kind: "verification", result: second }));
    expect(computePortableVerificationReportDigestV1({ kind: "verification", result: first }))
      .toBe(computePortableVerificationReportDigestV1({ kind: "verification", result: second }));
  });

  it("changes the envelope digest when a core finding changes", () => {
    const first = dataset();
    const second = { ...first, findings: [{ ...first.findings[0]!, outcome: "fail" as const,
      reason_code: "SOURCE_MISMATCH" }] };
    expect(computePortableVerificationReportDigestV1({ kind: "verification", result: first }))
      .not.toBe(computePortableVerificationReportDigestV1({ kind: "verification", result: second }));
  });

  it("preserves execution scope and binds program and result selection", () => {
    const first = execution();
    const altered: ExecutionV1Report = { ...first, verification_scope: { ...first.verification_scope,
      expected_program: "alternate" } };
    const before = createPortableVerificationReportV1({ kind: "execution", result: first });
    const after = createPortableVerificationReportV1({ kind: "execution", result: altered });
    expect(before.context.verification_scope).toMatchObject({ profile: "sage-standards-v1",
      requested_result_id: resultId });
    expect(before.core_sha3_512).toBe(after.core_sha3_512);
    expect(before.report_sha3_512).not.toBe(after.report_sha3_512);
  });

  it("rejects execution reports that claim a result scope without its finding", () => {
    const first = execution();
    expect(() => createPortableVerificationReportV1({ kind: "execution", result: {
      ...first, findings: first.findings.filter((f) => f.check_id !== "intent.result"),
    } })).toThrow(/result-scope finding/);
  });

  it("preserves historical HCS references and Mirror corroboration", () => {
    const output = createPortableVerificationReportV1({ kind: "independent_standards", result: independent() });
    expect(output.context.independent_standards).toMatchObject({ status: "verified",
      assurance: "mirror_corroborated" });
    expect(output.context.independent_standards).not.toHaveProperty("hedera_consensus_authentication");
    expect(JSON.stringify(output.context)).toContain("1792000000.000000001");
  });

  it("binds standards assurance changes to the report digest", () => {
    const first = independent();
    const changed: IndependentStandardsV1Report = { ...first, independent_standards: {
      ...first.independent_standards, items: first.independent_standards.items.map((item) => ({
        ...item, current_topic_or_account_memo_observed: false,
      })) } };
    const a = createPortableVerificationReportV1({ kind: "independent_standards", result: first });
    const b = createPortableVerificationReportV1({ kind: "independent_standards", result: changed });
    expect(a.core_sha3_512).toBe(b.core_sha3_512);
    expect(a.report_sha3_512).not.toBe(b.report_sha3_512);
  });

  it("rejects contradictory resolution findings", () => {
    const first = independent();
    const contradictory: IndependentStandardsV1Report = { ...first,
      findings: first.findings.map((f) => f.check_id !== "standards.reference.0" ? f :
        { ...f, outcome: "fail" as const, reason_code: "MISMATCH" }) };
    expect(() => createPortableVerificationReportV1({ kind: "independent_standards", result: contradictory }))
      .toThrow(/Inconsistent report finding/);
  });

  it("preserves dataset triangulation resolution without retired publication binding", () => {
    const first = publicDataset();
    const report = createPortableVerificationReportV1({ kind: "public_triangulation", result: first });
    expect(report.context).toMatchObject({ consistency: "consistent",
      resolution: { hedera_mirror: "resolved" } });
    expect(report.context).not.toHaveProperty("publication_payload_binding");
    const changed: PublicTriangulationV1Result = { ...first, resolution: {
      ...first.resolution, hedera_mirror: "unavailable" } } as PublicTriangulationV1Result;
    expect(createPortableVerificationReportV1({ kind: "public_triangulation", result: changed }).report_sha3_512)
      .not.toBe(report.report_sha3_512);
  });

  it("rejects relationship findings that contradict comparison outcomes", () => {
    const first = publicDataset();
    const wrong: PublicTriangulationV1Result = { ...first, report: { ...first.report,
      findings: first.report.findings.map((f) => f.check_id === "triangulation.provided_public_record.bundle_digest"
        ? { ...f, outcome: "fail" as const, reason_code: "FACT_MISMATCH" } : f) } };
    expect(() => createPortableVerificationReportV1({ kind: "public_triangulation", result: wrong }))
      .toThrow(/Inconsistent report finding/);
  });

  it("binds execution Mirror resolution and exact ledger targets without retired publication binding", () => {
    const first = publicExecution();
    const report = createPortableVerificationReportV1({ kind: "execution_triangulation", result: first });
    expect(report.context.public_execution).toMatchObject({ hedera_resolution: "resolved" });
    expect(report.context.public_execution).not.toHaveProperty("publication_payload_binding");
    const changed = { ...first, plan: { ...first.plan!, hedera_targets: first.plan!.hedera_targets.map((t) =>
      ({ ...t, transaction_id: "0.0.456@1792000000.000000001" })) } } as PublicExecutionTriangulationV1Result;
    expect(createPortableVerificationReportV1({ kind: "execution_triangulation", result: changed }).report_sha3_512)
      .not.toBe(report.report_sha3_512);
  });

  it("records unresolved execution acquisition only with a supplied offline report", () => {
    const unresolved = { status: "not_found", reason_code: "EXECUTION_NOT_FOUND",
      public_record_acquisition: "not_found", hedera_resolution: "not_checked",
      plan: null, mirror: null, comparison: null,
    } as const;
    expect(() => createPortableVerificationReportV1({ kind: "execution_triangulation", result: unresolved }))
      .toThrow(/offline report/);
    const output = createPortableVerificationReportV1({ kind: "execution_triangulation",
      result: unresolved, source_report: execution() });
    expect(output.context.public_execution).toMatchObject({ status: "not_found", hedera_resolution: "not_checked" });
  });
});

describe("saved portable report integrity and comparison", () => {
  const copy = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

  it("validates constructed shared, execution, standards and triangulation reports", () => {
    const candidates = [
      createPortableVerificationReportV1({ kind: "verification", result: dataset() }),
      createPortableVerificationReportV1({ kind: "execution", result: execution() }),
      createPortableVerificationReportV1({ kind: "independent_standards", result: independent() }),
      createPortableVerificationReportV1({ kind: "public_triangulation", result: publicDataset() }),
      createPortableVerificationReportV1({ kind: "execution_triangulation", result: publicExecution() }),
    ];
    for (const candidate of candidates) {
      expect(validatePortableVerificationReportV1(copy(candidate))).toEqual({
        status: "valid", reason_code: null,
        authenticity: "not_checked", evidence_recomputation: "not_performed",
      });
    }
  });

  it("validates unresolved execution acquisition without creating a resolved claim", () => {
    const report = createPortableVerificationReportV1({ kind: "execution_triangulation",
      result: { status: "not_found", reason_code: "EXECUTION_NOT_FOUND", public_record_acquisition: "not_found",
        hedera_resolution: "not_checked", plan: null,
        mirror: null, comparison: null }, source_report: execution() });
    expect(validatePortableVerificationReportV1(report).status).toBe("valid");
  });

  it("detects changes to core findings or claimed core digest", () => {
    const report = JSON.parse(JSON.stringify(createPortableVerificationReportV1({ kind: "verification", result: dataset() })));
    report.core.findings[0]!.outcome = "fail";
    expect(validatePortableVerificationReportV1(report).status).toBe("invalid");
    const clean = JSON.parse(JSON.stringify(createPortableVerificationReportV1({ kind: "verification", result: dataset() })));
    clean.core_sha3_512 = "0".repeat(128);
    expect(validatePortableVerificationReportV1(clean).reason_code).toBe("PORTABLE_CORE_DIGEST_MISMATCH");
  });

  it("detects altered assurance and publication disclosures in the envelope", () => {
    const report = JSON.parse(JSON.stringify(createPortableVerificationReportV1({ kind: "independent_standards", result: independent() })));
    report.context.independent_standards.items[0]!.current_topic_or_account_memo_observed = false;
    expect(validatePortableVerificationReportV1(report).reason_code).toBe("PORTABLE_REPORT_DIGEST_MISMATCH");
    const publicReport = JSON.parse(JSON.stringify(createPortableVerificationReportV1({ kind: "public_triangulation", result: publicDataset() })));
    publicReport.context.resolution.hedera_mirror = "unavailable";
    expect(validatePortableVerificationReportV1(publicReport).reason_code).toBe("PORTABLE_REPORT_DIGEST_MISMATCH");
  });

  it("rejects unsupported version, unknown fields and unknown contexts", () => {
    const report = createPortableVerificationReportV1({ kind: "verification", result: dataset() });
    expect(validatePortableVerificationReportV1({ ...report, schema_version: "va.portable-verification-report.v2" }).status).toBe("invalid");
    expect(validatePortableVerificationReportV1({ ...report, authorization: "trusted" }).status).toBe("invalid");
    expect(validatePortableVerificationReportV1({ ...report, context: { authorized: true } }).status).toBe("invalid");
    expect(validatePortableVerificationReportV1({ ...report, core: { ...report.core, verification_scope: {} } }).status).toBe("invalid");
  });

  it("rejects contradictory standards and triangulation context", () => {
    const standard = JSON.parse(JSON.stringify(createPortableVerificationReportV1({ kind: "independent_standards", result: independent() })));
    standard.context.independent_standards.hedera_consensus_authentication = "verified";
    expect(validatePortableVerificationReportV1(standard).status).toBe("invalid");
    const wrongNetwork = JSON.parse(JSON.stringify(createPortableVerificationReportV1({ kind: "independent_standards", result: independent() })));
    wrongNetwork.context.independent_standards.network = "mainnet";
    expect(validatePortableVerificationReportV1(wrongNetwork).status).toBe("invalid");
    const tri = JSON.parse(JSON.stringify(createPortableVerificationReportV1({ kind: "public_triangulation", result: publicDataset() })));
    tri.context.relationships[0]!.fact_comparisons[0]!.outcome = "fail";
    expect(validatePortableVerificationReportV1(tri).status).toBe("invalid");
  });

  it("rejects malformed, cyclic, sparse, oversized and accessor-backed reports", () => {
    const report = createPortableVerificationReportV1({ kind: "verification", result: dataset() });
    const cyclic: Record<string, unknown> = { ...report };
    cyclic.loop = cyclic;
    expect(validatePortableVerificationReportV1(cyclic).status).toBe("invalid");
    expect(validatePortableVerificationReportV1({ ...report, padding: "x".repeat(1024 * 1024 + 1) }).status).toBe("invalid");
    expect(validatePortableVerificationReportV1({ ...report, context: [,] }).status).toBe("invalid");
    const accessor = { ...report };
    Object.defineProperty(accessor, "kind", { enumerable: true, get: () => "verification" });
    expect(validatePortableVerificationReportV1(accessor).status).toBe("invalid");
  });

  it("marks even internally valid, fabricated findings as unauthenticated", () => {
    const fabricated = createPortableVerificationReportV1({ kind: "verification", result: dataset() });
    expect(validatePortableVerificationReportV1(fabricated)).toMatchObject({
      status: "valid", authenticity: "not_checked", evidence_recomputation: "not_performed",
    });
  });

  it("compares equivalent saved reports regardless of object property order", () => {
    const report = createPortableVerificationReportV1({ kind: "verification", result: dataset() });
    const reversed = Object.fromEntries(Object.entries(copy(report)).reverse());
    expect(comparePortableVerificationReportsV1(report, reversed)).toEqual({
      status: "equivalent", differences: [], authenticity: "not_checked", evidence_recomputation: "not_performed",
    });
  });

  it("identifies differences in verification scope and assurance context", () => {
    const first = execution();
    const second: ExecutionV1Report = { ...first, verification_scope: { ...first.verification_scope,
      expected_program: "different-program" } };
    const a = createPortableVerificationReportV1({ kind: "execution", result: first });
    const b = createPortableVerificationReportV1({ kind: "execution", result: second });
    expect(comparePortableVerificationReportsV1(a, b)).toMatchObject({ status: "different", differences: ["context"] });
    const c = createPortableVerificationReportV1({ kind: "independent_standards", result: independent() });
    expect(comparePortableVerificationReportsV1(a, c)).toMatchObject({ status: "different", differences: ["kind", "findings", "observations", "context"] });
  });

  it("identifies subject, intent and finding differences deterministically", () => {
    const first = dataset();
    const second = { ...first, intent: { ...first.intent, subject: { ...first.intent.subject, id: "dataset-2" } } };
    const a = createPortableVerificationReportV1({ kind: "verification", result: first });
    const b = createPortableVerificationReportV1({ kind: "verification", result: second });
    expect(comparePortableVerificationReportsV1(a, b).differences).toEqual(["subject", "intent"]);
    const altered = { ...first, findings: first.findings.map((f) => ({ ...f, outcome: "fail" as const, reason_code: "SOURCE_MISMATCH" })) };
    const c = createPortableVerificationReportV1({ kind: "verification", result: altered });
    expect(comparePortableVerificationReportsV1(a, c).differences).toEqual(["findings"]);
  });

  it("never compares malformed or digest-mismatched reports as authentic observations", () => {
    const report = createPortableVerificationReportV1({ kind: "verification", result: dataset() });
    const changed = { ...report, report_sha3_512: "0".repeat(128) };
    expect(() => comparePortableVerificationReportsV1(report, changed)).toThrow();
  });
});