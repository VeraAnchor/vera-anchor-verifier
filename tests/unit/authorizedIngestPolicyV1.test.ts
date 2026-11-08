import { describe, expect, it, vi } from "vitest";
import type { VerificationObservation, VerificationReport } from "../../src/contracts/verification.js";
import { VERIFICATION_POLICY_SCHEMA_VERSION, type VerificationPolicyV1 } from "../../src/policy/contractV1.js";
import {
  assessPortableVerificationPolicyV1,
  triangulateAuthorizedIngestWithPolicyV1,
} from "../../src/policy/evaluateV1.js";
import { createPortableVerificationReportV1 } from "../../src/reports/portableV1.js";
import { validatePortableVerificationReportV1 } from "../../src/reports/validationV1.js";
import {
  triangulateAuthorizedIngestV1,
  type AuthorizedIngestTriangulationV1Input,
  type AuthorizedIngestTriangulationV1Result,
} from "../../src/triangulation/authorizedIngestV1.js";

vi.mock("../../src/triangulation/authorizedIngestV1.js", async () => {
  const actual = await vi.importActual<typeof import("../../src/triangulation/authorizedIngestV1.js")>(
    "../../src/triangulation/authorizedIngestV1.js",
  );
  return { ...actual, triangulateAuthorizedIngestV1: vi.fn() };
});

const SUBJECT = Object.freeze({
  kind: "ingest" as const,
  id: "research.ingest",
  hedera_network: "testnet" as const,
});
const FINGERPRINT = "a".repeat(128);
const ROOT = "b".repeat(128);
const MESSAGE = "c".repeat(128);

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
  receipt?: "resolved" | "unavailable" | "unsupported" | "invalid" | "conflict";
}> = {}): AuthorizedIngestTriangulationV1Result {
  const mirror = options.mirror ?? "resolved";
  const core = options.core ?? "resolved";
  const receipt = core === "resolved" ? options.receipt ?? "resolved" : "unavailable";

  const mirrorOutcome = mirror === "resolved"
    ? "pass" as const
    : mirror === "conflict" || mirror === "invalid"
      ? "fail" as const
      : "indeterminate" as const;
  const mirrorRelationship = mirror === "resolved"
    ? "consistent" as const
    : mirror === "conflict" || mirror === "invalid"
      ? "conflict" as const
      : "incomplete" as const;
  const receiptOutcome = receipt === "resolved"
    ? "pass" as const
    : receipt === "invalid" || receipt === "conflict"
      ? "fail" as const
      : receipt === "unsupported"
        ? "unsupported" as const
        : "indeterminate" as const;
  const providedRelationship = receipt === "resolved" ? "consistent" as const : "incomplete" as const;
  const consistency = mirror === "conflict" || mirror === "invalid" ||
      receipt === "invalid" || receipt === "conflict"
    ? "conflict" as const
    : mirror === "resolved" && core === "resolved" && receipt === "resolved"
      ? "consistent" as const
      : "incomplete" as const;

  const report: VerificationReport = {
    intent: { subject: SUBJECT, expected: [] },
    observations: [
      observation("ingest.source", "local_computation", [
        { key: "source_merkle_root", state: "available", value: ROOT },
      ]),
      observation("ingest.bundle", "local_computation", [
        { key: "fingerprint", state: "available", value: FINGERPRINT },
      ]),
      observation("ingest.local_commitments", "local_computation", [
        { key: "ingest.local.fingerprint", state: "available", value: FINGERPRINT },
        { key: "ingest.local.merkle_root", state: "available", value: ROOT },
      ]),
      observation("ingest.authorized_core", "authorized_service", [
        { key: "publication.message_sha3_512", state: "available", value: MESSAGE },
      ]),
      ...(mirror === "resolved" || mirror === "conflict" || mirror === "invalid"
        ? [observation("ingest.hedera_mirror", "hedera_mirror", [
            { key: "publication.message_sha3_512", state: "available",
              value: mirror === "resolved" ? MESSAGE : "d".repeat(128) },
          ])]
        : []),
      ...(receipt === "resolved"
        ? [observation("ingest.receipt", "authorized_service", [
            { key: "ingest.receipt.fingerprint", state: "available", value: FINGERPRINT },
            { key: "ingest.receipt.merkle_root", state: "available", value: ROOT },
          ])]
        : []),
    ],
    findings: [
      { check_id: "intent.subject", outcome: "pass", reason_code: null,
        observation_ids: ["ingest.source", "ingest.bundle"] },
      { check_id: "ingest.source_binding", outcome: "pass", reason_code: null,
        observation_ids: ["ingest.source", "ingest.bundle"] },
      { check_id: "ingest.bundle_consistency", outcome: "pass", reason_code: null,
        observation_ids: ["ingest.bundle"] },
      { check_id: "triangulation.provided_authorized.fingerprint",
        outcome: receipt === "resolved" ? "pass" : "indeterminate",
        reason_code: receipt === "resolved" ? null : "FACT_UNAVAILABLE",
        observation_ids: receipt === "resolved"
          ? ["ingest.local_commitments", "ingest.receipt"]
          : ["ingest.local_commitments"] },
      { check_id: "triangulation.provided_authorized.merkle_root",
        outcome: receipt === "resolved" ? "pass" : "indeterminate",
        reason_code: receipt === "resolved" ? null : "FACT_UNAVAILABLE",
        observation_ids: receipt === "resolved"
          ? ["ingest.local_commitments", "ingest.receipt"]
          : ["ingest.local_commitments"] },
      { check_id: "triangulation.authorized_hedera.message_sha3_512",
        outcome: mirrorOutcome,
        reason_code: mirror === "resolved" ? null : "FACT_UNAVAILABLE",
        observation_ids: mirror === "resolved" || mirror === "conflict" || mirror === "invalid"
          ? ["ingest.authorized_core", "ingest.hedera_mirror"]
          : ["ingest.authorized_core"] },
      { check_id: "triangulation.authorized_ingest.receipt_profile",
        outcome: receiptOutcome,
        reason_code: receipt === "resolved" ? null : `AUTHORIZED_INGEST_RECEIPT_${receipt.toUpperCase()}`,
        observation_ids: receipt === "resolved" ? ["ingest.receipt"] : [] },
    ],
  };

  return {
    consistency,
    relationships: [
      {
        id: "authorized_hedera",
        status: mirrorRelationship,
        fact_comparisons: [{
          key: "message_sha3_512",
          outcome: mirrorOutcome,
          reason_code: mirror === "resolved" ? null : "FACT_UNAVAILABLE",
        }],
      },
      {
        id: "provided_authorized",
        status: providedRelationship,
        fact_comparisons: [
          {
            key: "fingerprint",
            outcome: receipt === "resolved" ? "pass" : "indeterminate",
            reason_code: receipt === "resolved" ? null : "FACT_UNAVAILABLE",
          },
          {
            key: "merkle_root",
            outcome: receipt === "resolved" ? "pass" : "indeterminate",
            reason_code: receipt === "resolved" ? null : "FACT_UNAVAILABLE",
          },
        ],
      },
    ],
    report,
    resolution: {
      authorized_core: core,
      hedera_mirror: mirror,
      ingest_receipt: receipt,
    },
  };
}

function policy(): VerificationPolicyV1 {
  return {
    schema_version: VERIFICATION_POLICY_SCHEMA_VERSION,
    subject: SUBJECT,
    report_kind: "authorized_ingest_triangulation",
    required_checks: [
      "ingest.source_binding",
      "triangulation.provided_authorized.merkle_root",
    ],
    required_assurance: ["mirror_corroboration"],
  };
}

const input = {
  bundle: {},
  material: { kind: "json", value: {} },
  intent: { subject: SUBJECT, expected: [] },
  hcs_reference: { message_id: "7@0.0.12345" },
} as unknown as AuthorizedIngestTriangulationV1Input;
const config = {} as Parameters<typeof triangulateAuthorizedIngestV1>[0];

describe("authorized Ingest portable report and policy", () => {
  it("constructs and validates a digest-bound authenticated Ingest report", () => {
    const portable = createPortableVerificationReportV1({
      kind: "authorized_ingest_triangulation",
      result: result(),
    });
    expect(portable.kind).toBe("authorized_ingest_triangulation");
    expect(portable.context).toMatchObject({
      consistency: "consistent",
      resolution: {
        authorized_core: "resolved",
        hedera_mirror: "resolved",
        ingest_receipt: "resolved",
      },
    });
    expect(validatePortableVerificationReportV1(portable).status).toBe("valid");
  });

  it("allows only after a fresh SDK invocation establishes local, authorized and Mirror requirements", async () => {
    vi.mocked(triangulateAuthorizedIngestV1).mockResolvedValueOnce(result());
    const workflow = await triangulateAuthorizedIngestWithPolicyV1(config, input, policy());
    expect(workflow.policy).toMatchObject({ decision: "allow", authority: "sdk_verification" });
    expect(workflow.policy.requirements).toEqual(expect.arrayContaining([
      expect.objectContaining({ key: "verification.authorized_evidence", outcome: "pass" }),
      expect.objectContaining({ key: "assurance.mirror_corroboration", outcome: "pass" }),
    ]));
    expect(assessPortableVerificationPolicyV1(workflow.report, policy()).decision).toBe("review");
  });

  it("reviews unavailable Mirror evidence and denies invalid authorized evidence", async () => {
    vi.mocked(triangulateAuthorizedIngestV1).mockResolvedValueOnce(result({ mirror: "unavailable" }));
    const incomplete = await triangulateAuthorizedIngestWithPolicyV1(config, input, policy());
    expect(incomplete.policy.decision).toBe("review");
    expect(incomplete.policy.reason_codes).toContain("POLICY_AUTHORIZED_EVIDENCE_INCOMPLETE");

    vi.mocked(triangulateAuthorizedIngestV1).mockResolvedValueOnce(result({ core: "invalid" }));
    const invalidCore = await triangulateAuthorizedIngestWithPolicyV1(config, input, policy());
    expect(invalidCore.policy.decision).toBe("deny");
    expect(invalidCore.policy.reason_codes).toContain("POLICY_AUTHORIZED_EVIDENCE_CONFLICT");

    vi.mocked(triangulateAuthorizedIngestV1).mockResolvedValueOnce(result({ receipt: "conflict" }));
    const invalidReceipt = await triangulateAuthorizedIngestWithPolicyV1(config, input, policy());
    expect(invalidReceipt.policy.decision).toBe("deny");
    expect(invalidReceipt.policy.reason_codes).toContain("POLICY_AUTHORIZED_EVIDENCE_CONFLICT");
  });

  it("rejects missing authenticated relationships and report-kind substitution", () => {
    const current = result();
    expect(() => createPortableVerificationReportV1({
      kind: "authorized_ingest_triangulation",
      result: {
        ...current,
        relationships: current.relationships.filter((entry) => entry.id !== "authorized_hedera"),
      },
    })).toThrow(/required relationship/);

    expect(() => createPortableVerificationReportV1({
      kind: "public_triangulation",
      result: current as never,
    })).toThrow(/relationship/);
  });
});
