import { describe, expect, it } from "vitest";
import type { VerificationReport } from "../../src/contracts/verification.js";
import { canonicalizeVerificationCoreV1, computeVerificationCoreDigestV1,
  VERIFICATION_CORE_SCHEMA_VERSION } from "../../src/reports/coreV1.js";

function sample(): VerificationReport {
  const subject = { kind: "dataset" as const, id: "study-1", hedera_network: "testnet" as const };
  return {
    intent: { subject, expected: [] },
    observations: [
      { id: "dataset.bundle", subject, source: "local_computation", facts: [
        { key: "item_count", state: "available", value: 2 },
        { key: "bundle_digest", state: "available", value: "a".repeat(128) },
      ] },
      { id: "dataset.receipt", subject, source: "provided_evidence", facts: [
        { key: "receipt_status", state: "unavailable", reason_code: "RECEIPT_NOT_SUPPLIED" },
      ] },
    ],
    findings: [
      { check_id: "dataset.source_binding", outcome: "pass", reason_code: null,
        observation_ids: ["dataset.bundle"] },
      { check_id: "dataset.receipt_binding", outcome: "indeterminate", reason_code: "RECEIPT_NOT_SUPPLIED",
        observation_ids: ["dataset.receipt", "dataset.bundle"] },
    ],
  };
}

describe("deterministic shared verification core", () => {
  it("produces a versioned canonical JSON projection and a 128-character digest", () => {
    const input = sample();
    const projection = JSON.parse(canonicalizeVerificationCoreV1(input));
    expect(projection.schema_version).toBe(VERIFICATION_CORE_SCHEMA_VERSION);
    expect(projection.findings).toHaveLength(2);
    expect(computeVerificationCoreDigestV1(input)).toBe(
      "d32f4b858f4c765666889e7312985223d9db17b3ce3d4ad517aa428069d93e6acc7c595ae22dc89d60e6b525eeb678557bd674944a98bf56abb3b044d87dc6fb");
  });

  it("normalizes set-like orders without mutating the caller", () => {
    const first = sample();
    const reversed: VerificationReport = {
      ...first,
      observations: [...first.observations].reverse().map((obs) => ({
        ...obs, facts: [...obs.facts].reverse(),
      })),
      findings: [...first.findings].reverse().map((f) => ({
        ...f, observation_ids: [...f.observation_ids].reverse(),
      })),
    };
    expect(canonicalizeVerificationCoreV1(reversed)).toBe(canonicalizeVerificationCoreV1(first));
    expect(computeVerificationCoreDigestV1(reversed)).toBe(computeVerificationCoreDigestV1(first));
    expect(first.findings[0]?.check_id).toBe("dataset.source_binding");
  });

  it("changes the digest when a finding or observed fact changes", () => {
    const first = sample();
    const changedFinding = { ...first, findings: [
      { ...first.findings[0]!, outcome: "fail" as const, reason_code: "SOURCE_MISMATCH" },
      first.findings[1]!,
    ] };
    const changedFact = { ...first, observations: [
      { ...first.observations[0]!, facts: [
        { key: "item_count", state: "available" as const, value: 3 },
        first.observations[0]!.facts[1]!,
      ] },
      first.observations[1]!,
    ] };
    expect(computeVerificationCoreDigestV1(changedFinding)).not.toBe(computeVerificationCoreDigestV1(first));
    expect(computeVerificationCoreDigestV1(changedFact)).not.toBe(computeVerificationCoreDigestV1(first));
  });

  it("preserves the distinction between digest and HF-framed commitments", () => {
    const first = sample();
    const raw: VerificationReport = { ...first, intent: { ...first.intent, expected: [
      { key: "bundle_digest", kind: "digest", contract: "raw-sha3-512", digest: "A".repeat(128) },
    ] } };
    const hf: VerificationReport = { ...first, intent: { ...first.intent, expected: [
      { key: "bundle_digest", kind: "digest", contract: "hf-contract-v1", material: "json",
        domain: "va:dataset:bundle:v1", digest: "a".repeat(128) },
    ] } };
    expect(computeVerificationCoreDigestV1(raw)).not.toBe(computeVerificationCoreDigestV1(hf));
    expect(JSON.parse(canonicalizeVerificationCoreV1(raw)).intent.expected[0].digest).toBe("a".repeat(128));
  });

  it("rejects duplicate IDs and dangling references", () => {
    const first = sample();
    expect(() => canonicalizeVerificationCoreV1({ ...first, findings: [...first.findings, first.findings[0]!] }))
      .toThrow(/Duplicate check id/);
    expect(() => canonicalizeVerificationCoreV1({ ...first,
      findings: [{ ...first.findings[0]!, observation_ids: ["unknown.observation"] }] }))
      .toThrow(/missing observation/);
    expect(() => canonicalizeVerificationCoreV1({ ...first,
      observations: [first.observations[0]!, first.observations[0]!] })).toThrow(/Duplicate observation id/);
  });

  it("rejects unsupported and malformed runtime input", () => {
    const first = sample();
    expect(() => canonicalizeVerificationCoreV1({ ...first,
      findings: [{ ...first.findings[0]!, outcome: "verified" as never }] })).toThrow();
    expect(() => canonicalizeVerificationCoreV1({ ...first,
      observations: [{ ...first.observations[0]!, facts: [
        { key: "count", state: "available" as const, value: Number.NaN },
      ] }] })).toThrow();
    expect(() => canonicalizeVerificationCoreV1({ ...first,
      observations: [{ ...first.observations[0]!, facts: [
        { key: "count", state: "available" as const, value: -0 },
      ] }] })).toThrow();
  });

  it("does not bind execution-specific extensions or authenticate reports", () => {
    const first = sample();
    const extended = { ...first, verification_scope: { profile: "sage-standards-v1" } };
    expect(computeVerificationCoreDigestV1(extended)).toBe(computeVerificationCoreDigestV1(first));
  });
});
