import { describe, expect, it } from "vitest";
import { resolveExplorerExecutionV1 } from "../../src/resolvers/explorerExecutionV1.js";
import { resolveExecutionHederaV1 } from "../../src/resolvers/executionMirrorV1.js";
import { triangulatePublicExecutionV1 } from "../../src/triangulation/executionPublicV1.js";
import { triangulateExecutionWithPolicyV1, assessPortableVerificationPolicyV1 } from "../../src/policy/evaluateV1.js";
import { verifyExecutionV1WithIntent } from "../../src/profiles/execution/verificationV1.js";
import { VERIFICATION_POLICY_SCHEMA_VERSION, type VerificationPolicyV1 } from "../../src/policy/contractV1.js";
import { validatePortableVerificationReportV1 } from "../../src/reports/validationV1.js";

const JOB = "11111111-1111-4111-8111-111111111111";
const OTHER = "22222222-2222-4222-8222-222222222222";
const RESULT = "33333333-3333-4333-8333-333333333333";
const HASH_A = "a".repeat(128);
const HASH_B = "b".repeat(128);
const TX = "0.0.11@1792033594.000000001";
const assertion = (evidence: any, result_id?: string) => ({
  evidence,
  intent: { subject: { kind: "execution" as const, id: JOB, hedera_network: "testnet" as const }, expected: [] },
  ...(result_id ? { result_id } : {}),
});
const evidence = () => ({
  available: true, contract_version: "1.0.0",
  execution: { job_id: JOB, program: "sage", proof_date: "2026-10-15", hedera_network: "testnet", pipeline_hash: HASH_A },
  acceptance: { digest: HASH_A, hcs: { transaction_id: "0.0.11@1792033594.1",
    topic_id: "0.0.22", sequence_number: 3, message_id: "3@0.0.22", data_hash_sha3_512: HASH_B } },
});
const resultEvidence = () => ({ ...evidence(), execution: { ...evidence().execution, result_id: RESULT },
  result_evidence: { result_id: RESULT, digest: HASH_A, hcs: { transaction_id: "0.0.15@1792033599.2" } },
});

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function mock(options: {
  publicEvidence?: any;
  publicResult?: any;
  mirrorMessage?: any;
  mirrorTx?: any;
  missingMessage?: boolean;
  missingTx?: boolean;
  resultStatus?: number;
  standardsStatus?: number;
} = {}) {
  const calls: Array<{ url: URL; init: RequestInit }> = [];
  const fetchImpl = async (raw: URL | RequestInfo, init: RequestInit = {}): Promise<Response> => {
    const url = new URL(String(raw));
    calls.push({ url, init });
    if (url.pathname.endsWith(`/sage/results/${RESULT}`)) return options.resultStatus
      ? json({ error: "not_found" }, options.resultStatus)
      : json(options.publicResult ?? { id: RESULT, job_id: JOB, hedera_network: "testnet" });
    if (url.pathname.endsWith(`/sage/jobs/${JOB}/standards`)) return options.standardsStatus
      ? json({ error: "service_unavailable" }, options.standardsStatus)
      : json(options.publicEvidence ?? evidence());
    if (url.pathname.includes("/topics/")) return options.missingMessage ? json({}, 404) : json(options.mirrorMessage ?? {
      topic_id: "0.0.22", sequence_number: 3, consensus_timestamp: "1792033600.123456789", message: "YWJj",
    });
    if (url.pathname.includes("/transactions/")) return options.missingTx ? json({}, 404) : json(options.mirrorTx ?? {
      transactions: [{ transaction_id: url.pathname.includes("/transactions/0.0.15-")
        ? "0.0.15@1792033599.000000002" : TX, result: "SUCCESS", consensus_timestamp: "1792033600.123456789" }],
    });
    throw new Error(`Unexpected URL: ${url}`);
  };
  const config = { explorer: { base_url: "https://explorer.example", fetch_impl: fetchImpl as typeof fetch },
    mirror: { base_urls: { testnet: "https://mirror.example/api/v1" }, fetch_impl: fetchImpl as typeof fetch } };
  return { config, calls };
}

describe("Independent public execution triangulation", () => {
  it("resolves job-scoped public and Hedera locators without exposing a retired publication binding field", async () => {
    const m = mock();
    const out = await triangulatePublicExecutionV1(m.config, assertion(evidence()));
    expect(out.status).toBe("resolved");
    expect(out.public_record_acquisition).toBe("resolved");
    expect(out.hedera_resolution).toBe("resolved");
    expect(out).not.toHaveProperty("publication_payload_binding");
    expect(out.comparison?.relationships.find((x) => x.id === "public_record_hedera")?.fact_comparisons
      .map((x) => x.outcome)).toEqual(["pass", "pass", "pass"]);
    expect(m.calls).toHaveLength(5);
    expect(m.calls.every((c) => c.init.credentials === "omit" && c.init.redirect === "error")).toBe(true);
    expect(m.calls.every((c) => c.url.searchParams.get("network") === "testnet" || c.url.host === "mirror.example")).toBe(true);
  });

  it("retrieves exact result scope before fetching standards and forwards resultId", async () => {
    const m = mock({ publicEvidence: resultEvidence() });
    const out = await triangulatePublicExecutionV1(m.config, assertion(resultEvidence(), RESULT));
    expect(out.public_record_acquisition).toBe("resolved");
    expect(out.hedera_resolution).toBe("resolved");
    expect(out.comparison?.relationships[1]?.status).toBe("consistent");
    expect(m.calls[0]?.url.pathname).toContain(`/sage/results/${RESULT}`);
    expect(m.calls[1]?.url.searchParams.get("resultId")).toBe(RESULT);
    expect(m.calls.filter((c) => c.url.host === "mirror.example")).toHaveLength(6);
  });

  it("does not accept a substituted result even if the standards projection is otherwise valid", async () => {
    const m = mock({ publicEvidence: resultEvidence(), publicResult: { id: RESULT, job_id: OTHER, hedera_network: "testnet" } });
    const out = await triangulatePublicExecutionV1(m.config, assertion(resultEvidence(), RESULT));
    expect(out.status).toBe("conflict");
    expect(out.hedera_resolution).toBe("not_checked");
    expect(m.calls).toHaveLength(1);
  });

  it("rejects unselected job-level fallback when a result was requested", async () => {
    const m = mock({ publicEvidence: evidence() });
    const out = await triangulatePublicExecutionV1(m.config, assertion(resultEvidence(), RESULT));
    expect(out.status).toBe("verification_material_unavailable");
    expect(out.comparison).toBe(null);
    expect(m.calls).toHaveLength(2);
  });

  it("rejects another result in the public execution projection", async () => {
    const m = mock({ publicEvidence: { ...resultEvidence(), result_evidence: { ...resultEvidence().result_evidence, result_id: OTHER } } });
    const out = await triangulatePublicExecutionV1(m.config, assertion(resultEvidence(), RESULT));
    expect(out.status).toBe("conflict");
    expect(out.hedera_resolution).toBe("not_checked");
  });

  it("distinguishes result not-found from a valid scoped result", async () => {
    const m = mock({ resultStatus: 404 });
    const out = await triangulatePublicExecutionV1(m.config, assertion(resultEvidence(), RESULT));
    expect(out.status).toBe("not_found");
    expect(out.hedera_resolution).toBe("not_checked");
  });

  it("rejects a substituted public network before Hedera requests", async () => {
    const m = mock({ publicEvidence: { ...evidence(), execution: { ...evidence().execution, hedera_network: "mainnet" } } });
    const out = await triangulatePublicExecutionV1(m.config, assertion(evidence()));
    expect(out.status).toBe("conflict");
    expect(out.mirror).toBe(null);
  });

  it("reports unregistered historical jobs without pretending evidence exists", async () => {
    const m = mock({ publicEvidence: { available: false, contract_version: "1.0.0",
      execution: { job_id: JOB, hedera_network: "testnet" } } });
    const out = await triangulatePublicExecutionV1(m.config, assertion(evidence()));
    expect(out.status).toBe("verification_material_unavailable");
    expect(out.mirror).toBe(null);
  });

  it("does not mark missing Hedera messages as matches", async () => {
    const m = mock({ missingMessage: true });
    const out = await triangulatePublicExecutionV1(m.config, assertion(evidence()));
    expect(out.hedera_resolution).toBe("unavailable");
    expect(out.comparison?.relationships[1]?.status).toBe("incomplete");
    expect(out.comparison?.relationships[1]?.fact_comparisons.filter((x) => x.outcome === "indeterminate")).toHaveLength(2);
  });

  it("rejects a ledger message for the wrong topic or sequence", async () => {
    const m = mock({ mirrorMessage: { topic_id: "0.0.999", sequence_number: 3,
      consensus_timestamp: "1792033600.123456789", message: "YWJj" } });
    const out = await triangulatePublicExecutionV1(m.config, assertion(evidence()));
    expect(out.status).toBe("conflict");
    expect(out.comparison?.relationships[1]?.status).toBe("conflict");
  });

  it("rejects a failed Hedera transaction rather than accepting its ID", async () => {
    const m = mock({ mirrorTx: { transactions: [{ transaction_id: TX, result: "INVALID_SIGNATURE" }] } });
    const out = await triangulatePublicExecutionV1(m.config, assertion(evidence()));
    expect(out.status).toBe("conflict");
    expect(out.comparison?.relationships[1]?.fact_comparisons[0]?.outcome).not.toBe("pass");
  });

  it("detects a public pipeline commitment mismatch even when Mirror identifiers match", async () => {
    const m = mock({ publicEvidence: { ...evidence(), execution: { ...evidence().execution, pipeline_hash: HASH_B } } });
    const out = await triangulatePublicExecutionV1(m.config, assertion(evidence()));
    expect(out.status).toBe("conflict");
    expect(out.comparison?.relationships[0]?.status).toBe("conflict");
  });

  it("does not fetch Hedera when Explorer is unavailable", async () => {
    const m = mock({ standardsStatus: 503 });
    const out = await triangulatePublicExecutionV1(m.config, assertion(evidence()));
    expect(out.status).toBe("unavailable");
    expect(m.calls).toHaveLength(1);
  });

  it("rejects invalid caller intent before making requests", async () => {
    const m = mock();
    await expect(triangulatePublicExecutionV1(m.config, {
      ...assertion(evidence()), intent: { subject: { kind: "execution", id: OTHER, hedera_network: "mainnet" }, expected: [{
        key: "untrusted", kind: "digest", contract: "raw-sha3-512", digest: HASH_A,
      }] },
    })).rejects.toThrow();
    expect(m.calls).toHaveLength(0);
  });

  it("marks a missing original Hedera transaction unresolved", async () => {
    const m = mock({ missingTx: true });
    const out = await triangulatePublicExecutionV1(m.config, assertion(evidence()));
    expect(out.hedera_resolution).toBe("unavailable");
    expect(out.comparison?.relationships[1]?.fact_comparisons[0]?.outcome).toBe("indeterminate");
  });

  it("does not classify an invalid Mirror message as an unavailable transport", async () => {
    const m = mock({ mirrorMessage: { topic_id: "0.0.22", sequence_number: 3, consensus_timestamp: "1792033600.123", message: "###" } });
    const out = await triangulatePublicExecutionV1(m.config, assertion(evidence()));
    expect(out.hedera_resolution).toBe("invalid");
    expect(out.comparison?.relationships[1]?.status).toBe("incomplete");
  });

  it("never treats absent original ledger locators as successful resolution", async () => {
    const without = { ...evidence(), acceptance: { digest: HASH_A, hcs: null } };
    const m = mock({ publicEvidence: without });
    const out = await triangulatePublicExecutionV1(m.config, assertion(without));
    expect(out.hedera_resolution).toBe("unavailable");
    expect(out.mirror?.reason_code).toBe("MIRROR_LEDGER_TARGETS_MISSING");
    expect(m.calls).toHaveLength(1);
  });

});

describe("execution public-policy conformance", () => {
  const input = () => ({ ...assertion(evidence()), profile: "sage-standards-v1" as const,
    expected_program: "sage" });
  function policy(): VerificationPolicyV1 {
    const verified = verifyExecutionV1WithIntent(input());
    return { schema_version: VERIFICATION_POLICY_SCHEMA_VERSION,
      subject: verified.intent.subject, report_kind: "execution_triangulation",
      required_checks: ["intent.subject"],
      execution_scope: verified.verification_scope };
  }

  it("emits a valid portable report without exposing retired publication binding claims", async () => {
    const m = mock();
    const result = await triangulateExecutionWithPolicyV1(m.config, input(), policy());
    expect(result.report.kind).toBe("execution_triangulation");
    expect(validatePortableVerificationReportV1(result.report).status).toBe("valid");
    expect(result.report.context.public_execution).toMatchObject({ hedera_resolution: "resolved" });
    expect(result.report.context.public_execution).not.toHaveProperty("publication_payload_binding");
    expect(result.policy.requirements.find((r) => r.key === "assurance.hedera_consensus_authentication")).toBeUndefined();
    expect(assessPortableVerificationPolicyV1(result.report, policy()).decision).not.toBe("allow");
  });

  it("never grants public acceptance when Mirror evidence is missing", async () => {
    const m = mock({ missingMessage: true });
    const result = await triangulateExecutionWithPolicyV1(m.config, input(), policy());
    expect(result.policy.decision).not.toBe("allow");
    expect(result.policy.reason_codes).toContain("POLICY_PUBLIC_EVIDENCE_INCOMPLETE");
  });

  it("rejects wrong-network relying-party policies without public fetches", async () => {
    const m = mock();
    await expect(triangulateExecutionWithPolicyV1(m.config, input(), {
      ...policy(), subject: { kind: "execution", id: JOB, hedera_network: "mainnet" },
    })).rejects.toThrow(/policy intent/);
    expect(m.calls).toHaveLength(0);
  });
});