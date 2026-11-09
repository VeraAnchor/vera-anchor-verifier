import { describe, expect, it, vi } from "vitest";
import type { VerificationObservation, VerificationReport } from "../../src/contracts/verification.js";
import { VERIFICATION_POLICY_SCHEMA_VERSION, type VerificationPolicyV1 } from "../../src/policy/contractV1.js";
import { assessPortableVerificationPolicyV1, triangulateAuthorizedDatasetWithPolicyV1 } from "../../src/policy/evaluateV1.js";
import { createPortableVerificationReportV1 } from "../../src/reports/portableV1.js";
import { validatePortableVerificationReportV1 } from "../../src/reports/validationV1.js";
import { triangulateAuthorizedDatasetV1,
  type AuthorizedDatasetTriangulationV1Input, type AuthorizedDatasetTriangulationV1Result } from "../../src/triangulation/authorizedDatasetV1.js";

vi.mock("../../src/triangulation/authorizedDatasetV1.js", async () => {
  const actual = await vi.importActual<typeof import("../../src/triangulation/authorizedDatasetV1.js")>(
    "../../src/triangulation/authorizedDatasetV1.js",
  );
  return { ...actual, triangulateAuthorizedDatasetV1: vi.fn() };
});

const SUBJECT = Object.freeze({ kind: "dataset" as const, id: "research.dataset", hedera_network: "testnet" as const });
const FINGERPRINT = "a".repeat(128);
const MESSAGE = "b".repeat(128);

function observation(
  id: string,
  source: VerificationObservation["source"],
  facts: VerificationObservation["facts"],
): VerificationObservation {
  return Object.freeze({ id, subject: SUBJECT, source, facts: Object.freeze([...facts]) });
}

function result(options: Readonly<{
  mirror?: "resolved" | "unavailable" | "invalid" | "conflict";
  core?: "resolved" | "invalid" | "forbidden";
}> = {}): AuthorizedDatasetTriangulationV1Result {
  const mirror = options.mirror ?? "resolved";
  const core = options.core ?? "resolved";
  const mirrorOutcome = mirror === "resolved" ? "pass" as const : mirror === "conflict" ? "fail" as const : "indeterminate" as const;
  const mirrorRelationship = mirror === "resolved" ? "consistent" as const : mirror === "conflict" ? "conflict" as const : "incomplete" as const;
  const consistency = mirror === "conflict" ? "conflict" as const :
    mirror === "resolved" && core === "resolved" ? "consistent" as const : "incomplete" as const;
  const authorized = observation("dataset.authorized_core", "authorized_service", [
    { key: "publication.message_sha3_512", state: "available", value: MESSAGE },
  ]);
  const hedera = observation("dataset.hedera_mirror", "hedera_mirror", [
    ...(mirror === "resolved" ? [{ key: "publication.message_sha3_512", state: "available" as const, value: MESSAGE }] : []),
  ]);
  const registry = observation("dataset.authorized_registry", "authorized_service", [
    { key: "dataset.registry.dataset_fingerprint", state: "available", value: FINGERPRINT },
  ]);
  const report: VerificationReport = {
    intent: { subject: SUBJECT, expected: [] },
    observations: [
      observation("dataset.source", "local_computation", []),
      observation("dataset.bundle", "local_computation", [
        { key: "dataset_fingerprint", state: "available", value: FINGERPRINT },
      ]),
      authorized,
      hedera,
      registry,
    ],
    findings: [
      { check_id: "intent.subject", outcome: "pass", reason_code: null,
        observation_ids: ["dataset.source", "dataset.bundle"] },
      { check_id: "dataset.source_binding", outcome: "pass", reason_code: null,
        observation_ids: ["dataset.source", "dataset.bundle"] },
      { check_id: "dataset.bundle_consistency", outcome: "pass", reason_code: null,
        observation_ids: ["dataset.bundle"] },
      { check_id: "triangulation.provided_authorized.dataset_fingerprint", outcome: "pass", reason_code: null,
        observation_ids: ["dataset.bundle", "dataset.authorized_registry"] },
      { check_id: "triangulation.authorized_hedera.message_sha3_512", outcome: mirrorOutcome,
        reason_code: mirror === "resolved" ? null : "FACT_UNAVAILABLE",
        observation_ids: ["dataset.authorized_core", "dataset.hedera_mirror"] },
      { check_id: "triangulation.authorized_dataset.registry_event_profile", outcome: "pass", reason_code: null,
        observation_ids: ["dataset.authorized_registry"] },
    ],
  };
  return {
    consistency,
    relationships: [
      { id: "authorized_hedera", status: mirrorRelationship,
        fact_comparisons: [{ key: "message_sha3_512", outcome: mirrorOutcome,
          reason_code: mirror === "resolved" ? null : "FACT_UNAVAILABLE" }] },
      { id: "provided_authorized", status: "consistent",
        fact_comparisons: [{ key: "dataset_fingerprint", outcome: "pass", reason_code: null }] },
    ],
    report,
    resolution: {
      authorized_core: core,
      hedera_mirror: mirror,
      dataset_registry_event: "resolved",
    },
  };
}

function policy(): VerificationPolicyV1 {
  return {
    schema_version: VERIFICATION_POLICY_SCHEMA_VERSION,
    subject: SUBJECT,
    report_kind: "authorized_dataset_triangulation",
    required_checks: ["dataset.source_binding", "triangulation.provided_authorized.dataset_fingerprint"],
    required_assurance: ["mirror_corroboration"],
  };
}

const input = {
  bundle: {}, files: [], intent: { subject: SUBJECT, expected: [] },
  hcs_reference: { message_id: "7@0.0.12345" },
} as unknown as AuthorizedDatasetTriangulationV1Input;
const config = {} as Parameters<typeof triangulateAuthorizedDatasetV1>[0];

describe("authorized Dataset portable report and policy", () => {
  it("constructs and validates a digest-bound authenticated Dataset report", () => {
    const portable = createPortableVerificationReportV1({ kind: "authorized_dataset_triangulation", result: result() });
    expect(portable.kind).toBe("authorized_dataset_triangulation");
    expect(portable.context).toMatchObject({
      consistency: "consistent",
      resolution: { authorized_core: "resolved", hedera_mirror: "resolved", dataset_registry_event: "resolved" },
    });
    expect(validatePortableVerificationReportV1(portable).status).toBe("valid");
  });

  it("allows only after a fresh SDK invocation establishes local, authorized and Mirror requirements", async () => {
    vi.mocked(triangulateAuthorizedDatasetV1).mockResolvedValueOnce(result());
    const workflow = await triangulateAuthorizedDatasetWithPolicyV1(config, input, policy());
    expect(workflow.policy).toMatchObject({ decision: "allow", authority: "sdk_verification" });
    expect(workflow.policy.requirements).toEqual(expect.arrayContaining([
      expect.objectContaining({ key: "verification.authorized_evidence", outcome: "pass" }),
      expect.objectContaining({ key: "assurance.mirror_corroboration", outcome: "pass" }),
    ]));
    expect(assessPortableVerificationPolicyV1(workflow.report, policy()).decision).toBe("review");
  });

  it("reviews unavailable Mirror evidence and denies invalid authorized Core evidence", async () => {
    vi.mocked(triangulateAuthorizedDatasetV1).mockResolvedValueOnce(result({ mirror: "unavailable" }));
    const incomplete = await triangulateAuthorizedDatasetWithPolicyV1(config, input, policy());
    expect(incomplete.policy.decision).toBe("review");
    expect(incomplete.policy.reason_codes).toContain("POLICY_AUTHORIZED_EVIDENCE_INCOMPLETE");

    vi.mocked(triangulateAuthorizedDatasetV1).mockResolvedValueOnce(result({ core: "invalid" }));
    const invalid = await triangulateAuthorizedDatasetWithPolicyV1(config, input, policy());
    expect(invalid.policy.decision).toBe("deny");
    expect(invalid.policy.reason_codes).toContain("POLICY_AUTHORIZED_EVIDENCE_CONFLICT");
  });

  it("rejects missing authenticated relationships and report-kind substitution", () => {
    const current = result();
    expect(() => createPortableVerificationReportV1({ kind: "authorized_dataset_triangulation",
      result: { ...current, relationships: current.relationships.filter((entry) => entry.id !== "authorized_hedera") } }))
      .toThrow(/required relationship/);
    expect(() => createPortableVerificationReportV1({ kind: "public_triangulation",
      result: current as never })).toThrow(/relationship/);
  });
});
