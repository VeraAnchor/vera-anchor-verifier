import { describe, expect, it } from "vitest";
import { prepareExecutionTriangulationV1, EXECUTION_HEDERA_OBSERVATION_V1_ID } from "../../src/triangulation/executionPlanV1.js";
import { compareEvidenceTriangulationV1 } from "../../src/triangulation/compareV1.js";

const JOB = "11111111-1111-4111-8111-111111111111";
const OTHER = "22222222-2222-4222-8222-222222222222";
const RESULT = "33333333-3333-4333-8333-333333333333";
const H1 = "a".repeat(128);
const H2 = "b".repeat(128);
const evidence = () => ({
  available: true, contract_version: "1.0.0",
  execution: { job_id: JOB, program: "sage", proof_date: "2026-10-15", hedera_network: "testnet", pipeline_hash: H1 },
  acceptance: { digest: H1, hcs: { transaction_id: "0.0.11@1792033594.1", topic_id: "0.0.22",
    sequence_number: 3, message_id: "3@0.0.22", data_hash_sha3_512: H2 } },
});
const setup = (provided: unknown = evidence(), public_evidence: unknown = evidence(), result_id?: string) =>
  prepareExecutionTriangulationV1({
    execution: {
      evidence: provided,
      intent: { subject: { kind: "execution", id: JOB, hedera_network: "testnet" }, expected: [] },
      ...(result_id ? { result_id } : {}),
    },
    public_evidence: public_evidence as ReturnType<typeof evidence>,
  });
function ppOutcome(plan: ReturnType<typeof setup>, key: string) {
  const outcome = compareEvidenceTriangulationV1(plan.triangulation);
  return outcome.relationships[0]?.fact_comparisons.find((f) => f.key === key);
}

describe("Execution triangulation authority plan", () => {
  it("creates a job-scoped three-way plan without claiming ledger retrieval", () => {
    const plan = setup();
    expect(plan.stage).toBe("unresolved_authority_plan");
    expect(plan.hedera_resolution).toBe("not_checked");
    expect(plan.publication_payload_binding).toBe("not_checked");
    expect(plan.triangulation.relationships.map((p) => p.id)).toEqual([
      "provided_public_record", "public_record_hedera", "provided_hedera",
    ]);
    expect(plan.triangulation.relationships[1]?.right_observation_id).toBe(EXECUTION_HEDERA_OBSERVATION_V1_ID);
    expect(plan.triangulation.observations.some((o) => o.source === "hedera_mirror")).toBe(false);
    expect(plan.hedera_targets).toHaveLength(2);
    expect(plan.hedera_targets[0]).toMatchObject({ source: "public_record", role: "acceptance_anchor",
      transaction_id: "0.0.11@1792033594.000000001", topic_id: "0.0.22", sequence_number: 3 });
    expect(plan.triangulation.relationships[1]?.comparisons.map((c) => c.key)).toEqual([
      "acceptance_anchor.transaction_id", "acceptance_anchor.topic_id", "acceptance_anchor.sequence_number",
    ]);
    expect(ppOutcome(plan, "acceptance_anchor.transaction_id")?.outcome).toBe("pass");
  });

  it("detects submitted versus public commitment disagreement", () => {
    const pub = evidence();
    pub.execution.pipeline_hash = H2;
    expect(ppOutcome(setup(evidence(), pub), "execution.pipeline_hash")).toMatchObject({
      outcome: "fail", reason_code: "FACT_MISMATCH",
    });
  });

  it("detects a substituted acceptance transaction despite valid HCS metadata", () => {
    const pub = evidence();
    pub.acceptance.hcs.transaction_id = "0.0.12@1792033594.1";
    expect(ppOutcome(setup(evidence(), pub), "acceptance_anchor.transaction_id")?.outcome).toBe("fail");
  });

  it("reports absent public acceptance locator as unresolved, never pass", () => {
    const pub = { ...evidence(), acceptance: { digest: H1, hcs: null } };
    expect(ppOutcome(setup(evidence(), pub), "acceptance_anchor.transaction_id")?.outcome).toBe("indeterminate");
  });

  it("rejects a public job substitution or cross-network projection", () => {
    expect(() => setup(evidence(), { ...evidence(), execution: { ...evidence().execution, job_id: OTHER } }))
      .toThrow(/scope mismatch/);
    expect(() => setup(evidence(), { ...evidence(), execution: { ...evidence().execution, hedera_network: "mainnet" } }))
      .toThrow(/scope mismatch/);
  });

  it("requires explicitly requested result scope and rejects result substitution", () => {
    const pub = { ...evidence(), result_evidence: { result_id: OTHER, digest: H1 } };
    expect(() => setup(evidence(), pub, RESULT)).toThrow(/result scope mismatch/);
    const good = { ...evidence(), result_evidence: { result_id: RESULT, digest: H1,
      hcs: { transaction_id: "0.0.15@1792033599.2" } } };
    const plan = setup(good, good, RESULT);
    expect(plan.hedera_targets.filter((p) => p.role === "result_evidence_anchor")).toHaveLength(2);
    expect(plan.triangulation.relationships[1]?.comparisons.some((c) => c.key === "result_evidence_anchor.transaction_id")).toBe(true);
    expect(setup(good, good).hedera_targets).toHaveLength(2);
    expect(setup(good, good).triangulation.relationships[1]?.comparisons.some((c) => c.key.includes("result_evidence"))).toBe(false);
  });

  it("rejects inconsistent message_id topic and explicit sequence", () => {
    const bad = evidence();
    bad.acceptance.hcs.message_id = "4@0.0.22";
    expect(() => setup(bad)).toThrow(/locator conflict/);
  });

  it("does not fabricate a sequence when only a transaction and topic are known", () => {
    const given = { ...evidence(), acceptance: { digest: H1, hcs: { topic_id: "0.0.22",
      transaction_id: "0.0.11@1792033594.1" } } };
    const target = setup(given, given).hedera_targets[0];
    expect(target?.topic_id).toBe(null);
    expect(target?.sequence_number).toBe(null);
    expect(target?.transaction_id).toBe("0.0.11@1792033594.000000001");
  });

  it("never elevates producer application data_hash to Mirror-proof comparison", () => {
    const plan = setup();
    const all = plan.triangulation.relationships.flatMap((r) => r.comparisons);
    expect(all.some((f) => f.key.includes("data_hash") || f.right_key.includes("data_hash"))).toBe(false);
    expect(all.some((f) => f.key.includes("mirror_message_sha3_512"))).toBe(false);
  });

  it("rejects unsupported or structurally unsafe provided evidence", () => {
    expect(() => setup({ malicious: () => 0 })).toThrow(/structural bounds/);
    expect(() => setup(evidence(), { available: false })).toThrow(/unavailable/);
  });
});
