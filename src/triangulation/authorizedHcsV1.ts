import type { VerificationFinding, VerificationObservation, VerificationReport } from "../contracts/verification.js";
import type { AuthorizedHcsObservationsV1Result } from "../resolvers/authorizedObservationV1.js";
import {
  compareEvidenceTriangulationV1,
  type TriangulationRelationshipPlanV1,
  type TriangulationV1Result,
} from "./compareV1.js";

export type AuthorizedHcsTriangulationV1Input = Readonly<{
  /** Must be produced by the SDK's profile/source verifier, not accepted as an authenticated attestation. */
  source_report: VerificationReport;
  /** Result returned by resolveAuthorizedHcsObservationsV1(). */
  resolution: AuthorizedHcsObservationsV1Result;
}>;

export type AuthorizedHcsTriangulationV1Result = Readonly<{
  consistency: TriangulationV1Result["consistency"];
  relationships: TriangulationV1Result["relationships"];
  report: VerificationReport;
  resolution: Readonly<{
    authorized_core: AuthorizedHcsObservationsV1Result["core"]["status"];
    hedera_mirror: AuthorizedHcsObservationsV1Result["mirror_resolution"];
  }>;
}>;

const MESSAGE_RELATIONSHIP = Object.freeze({
  id: "authorized_hedera" as const,
  comparisons: Object.freeze([
    Object.freeze({ key: "publication_topic", left_key: "publication.topic_id", right_key: "hedera.topic_id" }),
    Object.freeze({ key: "publication_sequence", left_key: "publication.sequence_number", right_key: "hedera.sequence_number" }),
    Object.freeze({ key: "message_sha3_512", left_key: "publication.message_sha3_512", right_key: "publication.message_sha3_512" }),
    Object.freeze({ key: "message_bytes", left_key: "publication.message_bytes", right_key: "publication.message_bytes" }),
  ]),
});

function expectedObservationId(kind: string, suffix: "authorized_core" | "hedera_mirror"): string {
  const id = `${kind}.${suffix}`;
  if (!/^[a-z][a-z0-9._:-]{0,127}$/.test(id)) {
    throw new TypeError("Authenticated HCS triangulation subject kind cannot form a valid observation id");
  }
  return id;
}

function checkedObservation(
  observation: VerificationObservation | null,
  expectedId: string,
  expectedSource: "authorized_service" | "hedera_mirror",
): VerificationObservation | null {
  if (!observation) return null;
  if (observation.id !== expectedId || observation.source !== expectedSource) {
    throw new TypeError("Authenticated HCS triangulation received an unexpected observation role");
  }
  return observation;
}

function finding(
  checkId: string,
  outcome: "fail",
  reasonCode: string | null,
): VerificationFinding {
  return Object.freeze({
    check_id: checkId,
    outcome,
    reason_code: reasonCode,
    observation_ids: Object.freeze([]),
  });
}

/**
 * Compare the exact HCS message binding returned by authorized Core resolution
 * with independently retrieved Mirror bytes. This establishes consistency of
 * the encrypted message identity only; it does not validate decrypted payload
 * semantics, authenticate Core itself, or make a policy decision.
 */
export function triangulateAuthorizedHcsV1(
  input: AuthorizedHcsTriangulationV1Input,
): AuthorizedHcsTriangulationV1Result {
  if (!input?.source_report?.intent?.subject || !input.resolution) {
    throw new TypeError("Authenticated HCS triangulation requires a source report and resolution");
  }
  const subject = input.source_report.intent.subject;
  const authorizedId = expectedObservationId(subject.kind, "authorized_core");
  const mirrorId = expectedObservationId(subject.kind, "hedera_mirror");

  const authorized = checkedObservation(
    input.resolution.authorized_observation,
    authorizedId,
    "authorized_service",
  );
  const mirror = checkedObservation(
    input.resolution.mirror?.observation ?? null,
    mirrorId,
    "hedera_mirror",
  );

  const relationship: TriangulationRelationshipPlanV1 = Object.freeze({
    ...MESSAGE_RELATIONSHIP,
    left_observation_id: authorizedId,
    right_observation_id: mirrorId,
  });
  const observations = [authorized, mirror].filter(
    (entry): entry is VerificationObservation => entry !== null,
  );
  const compared = compareEvidenceTriangulationV1({
    source_report: input.source_report,
    observations: Object.freeze(observations),
    relationships: Object.freeze([relationship]),
  });

  const conflicts: VerificationFinding[] = [];
  if (input.resolution.mirror?.status === "conflict") {
    conflicts.push(finding(
      "triangulation.authorized_hedera.mirror_resolution",
      "fail",
      input.resolution.mirror.reason_code,
    ));
  }

  return Object.freeze({
    consistency: conflicts.length ? "conflict" : compared.consistency,
    relationships: compared.relationships,
    report: conflicts.length
      ? Object.freeze({
          ...compared.report,
          findings: Object.freeze([...compared.report.findings, ...conflicts]),
        })
      : compared.report,
    resolution: Object.freeze({
      authorized_core: input.resolution.core.status,
      hedera_mirror: input.resolution.mirror_resolution,
    }),
  });
}
