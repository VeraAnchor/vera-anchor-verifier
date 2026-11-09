import { describe, expect, it } from "vitest";
import { verifyExecutionV1WithIntent } from "../../src/profiles/execution/verificationV1.js";
import { computeExecutionDomainSeparatedSha3_512 } from "../../src/profiles/execution/recomputationV1.js";

const JOB = "11111111-1111-4111-8111-111111111111";
const OTHER_JOB = "22222222-2222-4222-8222-222222222222";
const RESULT = "33333333-3333-4333-8333-333333333333";
const HASH = "a".repeat(128);
const base = () => ({
  available: true,
  contract_version: "1.0.0",
  execution: { job_id: JOB, program: "sage", proof_date: "2026-10-15", hedera_network: "testnet", pipeline_hash: HASH },
});
const intent = (id = JOB, hedera_network: "testnet" | "mainnet" = "testnet") =>
  ({ subject: { kind: "execution" as const, id, hedera_network }, expected: [] });
const check = (report: ReturnType<typeof verifyExecutionV1WithIntent>, id: string) => {
  const found = report.findings.find((item) => item.check_id === id);
  expect(found, `Missing ${id}`).toBeDefined();
  return found!;
};

describe("offline SAGE execution verification v1", () => {
  it("validates a supported SAGE execution identity with caller-supplied intent", () => {
    const report = verifyExecutionV1WithIntent({ evidence: base(), intent: intent(), expected_program: "sage" });
    expect(check(report, "execution.identity").outcome).toBe("pass");
    expect(check(report, "intent.subject").outcome).toBe("pass");
    expect(check(report, "intent.program").outcome).toBe("pass");
    expect(check(report, "standards.references_resolved").outcome).toBe("indeterminate");
  });

  it("distinguishes general execution from SAGE and preserves caller scope", () => {
    const generic = verifyExecutionV1WithIntent({
      profile: "execution-v1",
      evidence: { ...base(), execution: { ...base().execution, program: "other-compute" } },
      intent: intent(),
      expected_program: "other-compute",
      result_id: RESULT,
    });
    expect(check(generic, "profile.program_scope").outcome).toBe("pass");
    expect(check(generic, "profile.standards_scope").outcome).toBe("skipped");
    expect(generic.findings.some((item) => item.check_id === "standards.baseline_reference")).toBe(false);
    expect(check(generic, "execution.identity").outcome).toBe("pass");
    expect(generic.verification_scope).toEqual({
      profile: "execution-v1", expected_program: "other-compute", requested_result_id: RESULT,
    });
    expect(check(generic, "intent.program").outcome).toBe("pass");
    const sage = verifyExecutionV1WithIntent({ profile: "sage-standards-v1", evidence: base(), intent: intent() });
    expect(check(sage, "profile.program_scope").outcome).toBe("pass");
    expect(sage.findings.some((item) => item.check_id === "standards.baseline_reference")).toBe(true);
    expect(sage.verification_scope.profile).toBe("sage-standards-v1");
  });

  it("rejects profile downgrades and mismatched program evidence", () => {
    const downgraded = verifyExecutionV1WithIntent({ profile: "execution-v1", evidence: base(), intent: intent(), expected_program: "other-compute" });
    expect(check(downgraded, "profile.program_scope")).toMatchObject({
      outcome: "fail", reason_code: "EXECUTION_PROFILE_PROGRAM_MISMATCH",
    });
    const wrongProfile = verifyExecutionV1WithIntent({
      profile: "sage-standards-v1",
      evidence: { ...base(), execution: { ...base().execution, program: "other-compute" } },
      intent: intent(),
    });
    expect(check(wrongProfile, "profile.program_scope").outcome).toBe("fail");
    expect(() => verifyExecutionV1WithIntent({ profile: "execution-v1", evidence: base(), intent: intent() }))
      .toThrow(/independently supplied expected_program/);
    expect(() => verifyExecutionV1WithIntent({ profile: "execution-v1", evidence: base(), intent: intent(), expected_program: "sage" }))
      .toThrow(/SAGE requires sage-standards-v1/);
    expect(() => verifyExecutionV1WithIntent({ profile: "bogus" as any, evidence: base(), intent: intent() }))
      .toThrow(/Unsupported execution verification profile/);
  });

  it("normalizes omitted verification material to null with exact optional types", () => {
    const out = verifyExecutionV1WithIntent({ evidence: base(), intent: intent() });
    expect(check(out, "input.bounds").outcome).toBe("pass");
    expect(out.verification_scope).toEqual({
      profile: "sage-standards-v1", expected_program: null, requested_result_id: null,
    });
  });

  it("fails independent subject, network, and program mismatches", () => {
    const report = verifyExecutionV1WithIntent({ evidence: base(), intent: intent(OTHER_JOB, "mainnet"), expected_program: "cipher" });
    expect(check(report, "intent.subject").outcome).toBe("fail");
    expect(check(report, "execution.network_scope").outcome).toBe("fail");
    expect(check(report, "intent.program").outcome).toBe("fail");
  });

  it("preserves exact nanosecond temporal ordering and detects acceptance after start", () => {
    const evidence = { ...base(), acceptance: {
      requires_hcs_confirmation: true,
      hcs: { consensus_timestamp_exact: "1792033594.745290901" },
    } };
    const verification_material = { execution_start: {
      hcs_transaction_id: "0.0.10@1792033594.745290900",
      hcs_topic_id: "0.0.8751296",
      consensus_timestamp_exact: "1792033594.745290900",
    } };
    const later = verifyExecutionV1WithIntent({ evidence, intent: intent(), verification_material });
    expect(check(later, "acceptance.precedes_execution")).toMatchObject({
      outcome: "fail", reason_code: "ACCEPTANCE_AFTER_EXECUTION_START",
    });
    const before = verifyExecutionV1WithIntent({
      evidence: { ...evidence, acceptance: { ...evidence.acceptance,
        hcs: { consensus_timestamp_exact: "1792033594.745290899" } } },
      intent: intent(), verification_material,
    });
    expect(check(before, "acceptance.precedes_execution").outcome).toBe("pass");
  });

  it("recomputes digest binding from canonical payload and detects tampering", () => {
    const digest_payload = { result: { x: 1 }, id: JOB };
    const digest = computeExecutionDomainSeparatedSha3_512("vera-anchor:execution-binding:v1", digest_payload);
    const binding = { schema: "ExecutionBindingV1", canonicalization: "RFC8785-JCS", digest_algorithm: "SHA3-512",
      domain_separator: "vera-anchor:execution-binding:v1", finalized_at: "2026-10-15T00:00:00Z", digest_payload, digest };
    expect(check(verifyExecutionV1WithIntent({ evidence: { ...base(), binding }, intent: intent() }),
      "binding.digest_recomputed").outcome).toBe("pass");
    const mutated = { ...binding, digest_payload: { result: { x: 2 }, id: JOB } };
    expect(check(verifyExecutionV1WithIntent({ evidence: { ...base(), binding: mutated }, intent: intent() }),
      "binding.digest_recomputed")).toMatchObject({ outcome: "fail", reason_code: "BINDING_DIGEST_MISMATCH" });
  });

  it("never adopts an arbitrary latest result without caller-scoped result_id", () => {
    const evidence = { ...base(), result_evidence: { result_id: RESULT } };
    const report = verifyExecutionV1WithIntent({ evidence, intent: intent() });
    expect(check(report, "result_evidence.scope").outcome).toBe("skipped");
    expect(report.findings.some((f) => f.check_id === "intent.result")).toBe(false);
  });

  it("refuses unsupported contract versions and unsupported expectation types", () => {
    const report = verifyExecutionV1WithIntent({ evidence: { ...base(), contract_version: "1.2.0" }, intent: intent() });
    expect(check(report, "public_evidence.contract_version")).toMatchObject({
      outcome: "fail", reason_code: "PUBLIC_CONTRACT_UNSUPPORTED",
    });
    expect(() => verifyExecutionV1WithIntent({ evidence: base(), intent: {
      subject: intent().subject,
      expected: [{ kind: "digest", key: "pipeline", contract: "raw-sha3-512", digest: HASH }],
    } })).toThrow(/does not support/);
  });

  it("does not equate caller-provided standards 'verified' assertions with independent resolution", () => {
    const material = {
      standards_resolution: {
        schema_version: "vera.standards-resolution.v1" as const,
        hedera_network: "testnet" as const,
        state: "verified" as const,
        items: [
          { key: "agent:requester", standard: "HCS-11/HCS-14", reference: "", state: "verified" as const },
          { key: "agent:executor", standard: "HCS-11/HCS-14", reference: "", state: "verified" as const },
          { key: "capability:hcs26", standard: "HCS-26", reference: "", state: "verified" as const },
        ],
      },
    };
    const report = verifyExecutionV1WithIntent({ evidence: base(), intent: intent(), verification_material: material });
    expect(check(report, "standards.references_resolved")).toMatchObject({
      outcome: "indeterminate", reason_code: "STANDARDS_RESOLUTION_NOT_INDEPENDENTLY_VERIFIED",
    });
    const claimedFailure = verifyExecutionV1WithIntent({
      evidence: base(), intent: intent(),
      verification_material: { standards_resolution: {
        ...material.standards_resolution,
        state: "failed", items: material.standards_resolution.items.map((item) => ({ ...item, state: "failed" as const })),
      } },
    });
    expect(check(claimedFailure, "standards.references_resolved").outcome).toBe("indeterminate");
  });

  it("fails structural bounds safely and produces deterministic, immutable findings", () => {
    const evidence = base();
    const first = verifyExecutionV1WithIntent({ evidence, intent: intent() });
    expect(verifyExecutionV1WithIntent({ evidence, intent: intent() })).toEqual(first);
    expect(Object.isFrozen(first.findings)).toBe(true);
    expect(Object.isFrozen(first.observations)).toBe(true);
    expect(check(verifyExecutionV1WithIntent({ evidence: { malicious: () => 0 }, intent: intent() }),
      "input.bounds").outcome).toBe("fail");
  });
});
