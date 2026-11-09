import type {
  VerificationFact,
  VerificationObservation,
  VerificationSubject,
} from "../contracts/verification.js";
import {
  resolveAuthorizedHcsEvidenceV1,
  type AuthorizedHcsEvidenceV1,
  type AuthorizedHcsEvidenceV1Request,
  type AuthorizedHcsEvidenceV1Result,
  type CoreAuthorizedV1Config,
} from "./coreAuthorizedV1.js";
import {
  resolveHederaMessageV1,
  type HederaMessageLocatorV1,
  type HederaMessageObservationV1,
  type HederaMirrorV1Config,
} from "./hederaMirrorV1.js";
import { observeAuthorizedCoreMessageBindingV1 } from "../triangulation/messageObservationV1.js";

type PreparedAuthorizedHcsObservationV1 = Readonly<{
  observation: VerificationObservation;
  mirror_locator: HederaMessageLocatorV1 | null;
}>;

export type AuthorizedHcsObservationsV1Config = Readonly<{
  core: CoreAuthorizedV1Config;
  /** false disables independent Mirror resolution; omitted uses the SDK defaults. */
  mirror?: HederaMirrorV1Config | false;
}>;

export type AuthorizedHcsObservationsV1Input = Readonly<{
  subject: VerificationSubject;
  request: AuthorizedHcsEvidenceV1Request;
}>;

export type AuthorizedHcsObservationsV1Result = Readonly<{
  core: AuthorizedHcsEvidenceV1Result;
  authorized_observation: VerificationObservation | null;
  mirror: HederaMessageObservationV1 | null;
  mirror_resolution:
    | HederaMessageObservationV1["status"]
    | "not_requested"
    | "not_resolved"
    | "locator_unavailable";
}>;

function available(key: string, value: string | number): VerificationFact {
  return Object.freeze({ key, state: "available" as const, value });
}

function unavailable(key: string, reason: string): VerificationFact {
  return Object.freeze({ key, state: "unavailable" as const, reason_code: reason });
}

function optionalFact(
  key: string,
  value: string | number | null,
  reason: string,
): VerificationFact {
  return value === null ? unavailable(key, reason) : available(key, value);
}

function checkedSubject(subject: VerificationSubject, network: "mainnet" | "testnet"): VerificationSubject {
  if (!subject || typeof subject.id !== "string" || subject.id.length === 0 ||
    subject.id.length > 512 || subject.id.trim() !== subject.id ||
    subject.hedera_network !== network) {
    throw new TypeError("Authorized HCS observation requires an exact network-bound subject");
  }
  return subject;
}

/**
 * Converts authorized Core evidence into provenance-bearing scalar observations.
 * Plaintext is intentionally excluded: it must enter a profile verifier through
 * a separate adapter rather than becoming a report fact by implication.
 */
function prepareAuthorizedHcsObservationV1(
  evidence: AuthorizedHcsEvidenceV1,
  subject: VerificationSubject,
): PreparedAuthorizedHcsObservationV1 {
  if (!evidence || (evidence.hedera_network !== "mainnet" && evidence.hedera_network !== "testnet")) {
    throw new TypeError("Invalid authorized HCS evidence");
  }
  const scopedSubject = checkedSubject(subject, evidence.hedera_network);
  const binding = observeAuthorizedCoreMessageBindingV1({
    id: `${scopedSubject.kind}.authorized_core`,
    subject: scopedSubject,
    binding: evidence.message_binding,
  });

  const facts: VerificationFact[] = [
    ...binding.facts,
    optionalFact("publication.topic_id", evidence.topic.topic_id, "CORE_AUTHORIZED_TOPIC_UNAVAILABLE"),
    optionalFact("publication.sequence_number", evidence.tx.sequence_number, "CORE_AUTHORIZED_SEQUENCE_UNAVAILABLE"),
    optionalFact("core.hash.expected", evidence.core_hash_observation.expected, "CORE_HASH_EXPECTED_UNAVAILABLE"),
    optionalFact("core.hash.computed", evidence.core_hash_observation.computed, "CORE_HASH_COMPUTED_UNAVAILABLE"),
    available("acquisition.access_context", evidence.acquisition.access_context),
    available("acquisition.decryption_method", evidence.acquisition.decryption_method),
    available("acquisition.recoverability", evidence.acquisition.recoverability),
  ];

  const observation: VerificationObservation = Object.freeze({
    ...binding,
    facts: Object.freeze(facts),
  });

  const mirrorLocator = evidence.topic.topic_id !== null && evidence.tx.sequence_number !== null
    ? Object.freeze({
        hedera_network: evidence.hedera_network,
        topic_id: evidence.topic.topic_id,
        sequence_number: evidence.tx.sequence_number,
        transaction_id: evidence.tx.transaction_id,
      })
    : null;

  return Object.freeze({ observation, mirror_locator: mirrorLocator });
}

/**
 * Resolve authorized Core evidence and, when requested and locatable, obtain a
 * separate Hedera Mirror observation. This function acquires observations only;
 * it does not declare the two sources consistent or policy-acceptable.
 */
export async function resolveAuthorizedHcsObservationsV1(
  config: AuthorizedHcsObservationsV1Config,
  input: AuthorizedHcsObservationsV1Input,
): Promise<AuthorizedHcsObservationsV1Result> {
  if (!config?.core || !input?.request) {
    throw new TypeError("Authorized HCS observations require Core config and request");
  }
  checkedSubject(input.subject, input.request.network);

  const core = await resolveAuthorizedHcsEvidenceV1(config.core, input.request);
  if (core.status !== "resolved" || !core.evidence) {
    return Object.freeze({
      core,
      authorized_observation: null,
      mirror: null,
      mirror_resolution: config.mirror === false ? "not_requested" : "not_resolved",
    });
  }

  const prepared = prepareAuthorizedHcsObservationV1(core.evidence, input.subject);
  if (config.mirror === false) {
    return Object.freeze({
      core,
      authorized_observation: prepared.observation,
      mirror: null,
      mirror_resolution: "not_requested",
    });
  }
  if (!prepared.mirror_locator) {
    return Object.freeze({
      core,
      authorized_observation: prepared.observation,
      mirror: null,
      mirror_resolution: "locator_unavailable",
    });
  }

  const mirror = await resolveHederaMessageV1(config.mirror ?? {}, prepared.mirror_locator, input.subject);
  return Object.freeze({
    core,
    authorized_observation: prepared.observation,
    mirror,
    mirror_resolution: mirror.status,
  });
}
