import { describe, expect, it } from "vitest";
import type { VerificationObservation, VerificationReport } from "../../src/contracts/verification.js";
import type { AuthorizedHcsObservationsV1Result } from "../../src/resolvers/authorizedObservationV1.js";
import { triangulateAuthorizedHcsV1 } from "../../src/triangulation/authorizedHcsV1.js";
import { compareEvidenceTriangulationV1 } from "../../src/triangulation/compareV1.js";

const NETWORK = "testnet" as const;
const SUBJECT = Object.freeze({ kind: "dataset" as const, id: "research.dataset", hedera_network: NETWORK });
const DIGEST = "a".repeat(128);

function sourceReport(): VerificationReport {
  return Object.freeze({
    intent: Object.freeze({ subject: SUBJECT, expected: Object.freeze([]) }),
    findings: Object.freeze([
      Object.freeze({ check_id: "dataset.source_binding", outcome: "pass" as const, reason_code: null, observation_ids: Object.freeze([]) }),
      Object.freeze({ check_id: "dataset.bundle_consistency", outcome: "pass" as const, reason_code: null, observation_ids: Object.freeze([]) }),
      Object.freeze({ check_id: "intent.subject", outcome: "pass" as const, reason_code: null, observation_ids: Object.freeze([]) }),
    ]),
    observations: Object.freeze([]),
  });
}

function observation(
  source: "authorized_service" | "hedera_mirror",
  digest = DIGEST,
): VerificationObservation {
  const authorized = source === "authorized_service";
  return Object.freeze({
    id: authorized ? "dataset.authorized_core" : "dataset.hedera_mirror",
    subject: SUBJECT,
    source,
    facts: Object.freeze([
      Object.freeze({ key: authorized ? "publication.topic_id" : "hedera.topic_id", state: "available" as const, value: "0.0.12345" }),
      Object.freeze({ key: authorized ? "publication.sequence_number" : "hedera.sequence_number", state: "available" as const, value: 5 }),
      Object.freeze({ key: "publication.message_sha3_512", state: "available" as const, value: digest }),
      Object.freeze({ key: "publication.message_bytes", state: "available" as const, value: 42 }),
    ]),
  });
}

function resolution(
  authorized: VerificationObservation | null = observation("authorized_service"),
  mirrorObservation: VerificationObservation | null = observation("hedera_mirror"),
  mirrorStatus: "resolved" | "unavailable" | "invalid" | "conflict" = "resolved",
): AuthorizedHcsObservationsV1Result {
  return {
    core: { status: authorized ? "resolved" : "unavailable", reason_code: authorized ? null : "CORE_UNAVAILABLE", evidence: null },
    authorized_observation: authorized,
    mirror: mirrorStatus === "resolved" || mirrorStatus === "conflict"
      ? { status: mirrorStatus, reason_code: mirrorStatus === "conflict" ? "MIRROR_TRANSACTION_FAILED" : null, observation: mirrorObservation }
      : { status: mirrorStatus, reason_code: "MIRROR_UNAVAILABLE", observation: null },
    mirror_resolution: mirrorStatus,
  };
}

describe("authenticated HCS triangulation", () => {
  it("establishes exact authorized Core to Hedera message consistency", () => {
    const out = triangulateAuthorizedHcsV1({ source_report: sourceReport(), resolution: resolution() });
    expect(out.consistency).toBe("consistent");
    expect(out.relationships).toHaveLength(1);
    expect(out.relationships[0]?.id).toBe("authorized_hedera");
    expect(out.relationships[0]?.fact_comparisons.every((entry) => entry.outcome === "pass")).toBe(true);
    expect(out.report.findings.find((entry) => entry.check_id === "triangulation.authorized_hedera.message_sha3_512")?.outcome)
      .toBe("pass");
    expect(out.resolution).toEqual({ authorized_core: "resolved", hedera_mirror: "resolved" });
  });

  it("reports a ciphertext digest mismatch as a conflict", () => {
    const out = triangulateAuthorizedHcsV1({
      source_report: sourceReport(),
      resolution: resolution(observation("authorized_service"), observation("hedera_mirror", "b".repeat(128))),
    });
    expect(out.consistency).toBe("conflict");
    expect(out.report.findings.find((entry) => entry.check_id === "triangulation.authorized_hedera.message_sha3_512"))
      .toMatchObject({ outcome: "fail", reason_code: "FACT_MISMATCH" });
  });

  it("preserves a Mirror transaction conflict instead of degrading it to missing evidence", () => {
    const out = triangulateAuthorizedHcsV1({
      source_report: sourceReport(),
      resolution: resolution(observation("authorized_service"), null, "conflict"),
    });
    expect(out.consistency).toBe("conflict");
    expect(out.report.findings.find((entry) => entry.check_id === "triangulation.authorized_hedera.mirror_resolution"))
      .toMatchObject({ outcome: "fail", reason_code: "MIRROR_TRANSACTION_FAILED" });
  });

  it("remains incomplete when authorized or Mirror evidence is unavailable", () => {
    const out = triangulateAuthorizedHcsV1({
      source_report: sourceReport(),
      resolution: resolution(null, null, "unavailable"),
    });
    expect(out.consistency).toBe("incomplete");
    expect(out.relationships[0]?.status).toBe("incomplete");
  });

  it("rejects source-role substitution for the authenticated relationship", () => {
    expect(() => compareEvidenceTriangulationV1({
      source_report: sourceReport(),
      observations: [
        { ...observation("authorized_service"), source: "public_record" },
        observation("hedera_mirror"),
      ],
      relationships: [{
        id: "authorized_hedera",
        left_observation_id: "dataset.authorized_core",
        right_observation_id: "dataset.hedera_mirror",
        comparisons: [{ key: "message_sha3_512", left_key: "publication.message_sha3_512", right_key: "publication.message_sha3_512" }],
      }],
    })).toThrow(/sources do not match/);
  });
});
