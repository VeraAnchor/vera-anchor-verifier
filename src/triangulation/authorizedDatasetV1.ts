import type {
  EvidenceConsistency,
  VerificationFact,
  VerificationFinding,
  VerificationObservation,
  VerificationReport,
} from "../contracts/verification.js";
import {
  parseDatasetRegistryVersionCreatedV1,
  type DatasetRegistryVersionCreatedV1Result,
} from "../profiles/dataset/registryEventV1.js";
import {
  resolveAuthorizedHcsObservationsV1,
  type AuthorizedHcsObservationsV1Config,
  type AuthorizedHcsObservationsV1Result,
} from "../resolvers/authorizedObservationV1.js";
import {
  verifyDatasetV1WithIntent,
  type DatasetV1IntentInput,
} from "../verification/sourceIntentV1.js";
import {
  compareEvidenceTriangulationV1,
  type TriangulationRelationshipPlanV1,
  type TriangulationRelationshipResultV1,
} from "./compareV1.js";
import { triangulateAuthorizedHcsV1 } from "./authorizedHcsV1.js";

export type AuthorizedDatasetHcsReferenceV1 =
  | Readonly<{ message_id: string; transaction_id?: never }>
  | Readonly<{ transaction_id: string; message_id?: never }>;

export type AuthorizedDatasetTriangulationV1Config = AuthorizedHcsObservationsV1Config;

export type AuthorizedDatasetTriangulationV1Input = DatasetV1IntentInput & Readonly<{
  /** Caller-selected private Dataset Registry HCS message. Network comes only from verification intent. */
  hcs_reference: AuthorizedDatasetHcsReferenceV1;
}>;

export type AuthorizedDatasetTriangulationV1Result = Readonly<{
  consistency: EvidenceConsistency;
  relationships: readonly TriangulationRelationshipResultV1[];
  report: VerificationReport;
  resolution: Readonly<{
    authorized_core: AuthorizedHcsObservationsV1Result["core"]["status"];
    hedera_mirror: AuthorizedHcsObservationsV1Result["mirror_resolution"];
    dataset_registry_event: DatasetRegistryVersionCreatedV1Result["status"];
  }>;
}>;

const REGISTRY_OBSERVATION_ID = "dataset.authorized_registry";
const BUNDLE_OBSERVATION_ID = "dataset.bundle";

function available(key: string, value: string | number): VerificationFact {
  return Object.freeze({ key, state: "available" as const, value });
}

function unavailable(key: string, reason: string): VerificationFact {
  return Object.freeze({ key, state: "unavailable" as const, reason_code: reason });
}

function registryObservation(
  parsed: DatasetRegistryVersionCreatedV1Result,
  sourceReport: VerificationReport,
): VerificationObservation | null {
  if (parsed.status !== "resolved" || !parsed.event) return null;
  const event = parsed.event;
  return Object.freeze({
    id: REGISTRY_OBSERVATION_ID,
    subject: Object.freeze({ ...sourceReport.intent.subject }),
    source: "authorized_service" as const,
    resolver_id: "core.authorized-hcs.v1",
    facts: Object.freeze([
      available("dataset.registry.schema", event.schema_version),
      available("dataset.registry.event", event.event),
      available("dataset.registry.entity_id", event.entity_id),
      available("dataset.registry.dataset_version_id", event.dataset_version_id),
      available("dataset.registry.dataset_key", event.dataset_key),
      available("dataset.registry.version", event.version),
      available("dataset.registry.dataset_fingerprint", event.dataset_fingerprint),
      event.manifest_hash === null
        ? unavailable("dataset.registry.manifest_hash", "AUTHORIZED_DATASET_MANIFEST_HASH_UNAVAILABLE")
        : available("dataset.registry.manifest_hash", event.manifest_hash),
      event.schema_hash === null
        ? unavailable("dataset.registry.schema_hash", "AUTHORIZED_DATASET_SCHEMA_HASH_UNAVAILABLE")
        : available("dataset.registry.schema_hash", event.schema_hash),
    ]),
  });
}

function sourceReportWithSubjectFact(report: VerificationReport): VerificationReport {
  let found = false;
  const observations = report.observations.map((entry) => {
    if (entry.id !== BUNDLE_OBSERVATION_ID) return entry;
    if (entry.source !== "local_computation") {
      throw new TypeError("Dataset bundle observation must be local computation");
    }
    found = true;
    if (entry.facts.some((fact) => fact.key === "source_subject_id")) {
      throw new TypeError("Dataset bundle observation already contains source_subject_id");
    }
    return Object.freeze({
      ...entry,
      facts: Object.freeze([...entry.facts, available("source_subject_id", report.intent.subject.id)]),
    });
  });
  if (!found) throw new TypeError("Dataset source report is missing dataset.bundle observation");
  return Object.freeze({ ...report, observations: Object.freeze(observations) });
}

function profileFinding(
  parsed: DatasetRegistryVersionCreatedV1Result,
): VerificationFinding {
  const observationIds = parsed.status === "resolved" ? [REGISTRY_OBSERVATION_ID] : [];
  const outcome = parsed.status === "resolved"
    ? "pass" as const
    : parsed.status === "unavailable"
      ? "indeterminate" as const
      : parsed.status === "unsupported"
        ? "unsupported" as const
        : "fail" as const;
  return Object.freeze({
    check_id: "triangulation.authorized_dataset.registry_event_profile",
    outcome,
    reason_code: parsed.reason_code,
    observation_ids: Object.freeze(observationIds),
  });
}

function aggregate(
  hcs: EvidenceConsistency,
  dataset: EvidenceConsistency,
  parsed: DatasetRegistryVersionCreatedV1Result,
): EvidenceConsistency {
  if (hcs === "conflict" || dataset === "conflict" || parsed.status === "invalid" || parsed.status === "conflict") {
    return "conflict";
  }
  if (hcs !== "consistent" || dataset !== "consistent" || parsed.status !== "resolved") {
    return "incomplete";
  }
  return "consistent";
}

function checkedReference(reference: AuthorizedDatasetHcsReferenceV1): AuthorizedDatasetHcsReferenceV1 {
  const message = "message_id" in reference ? reference.message_id : undefined;
  const transaction = "transaction_id" in reference ? reference.transaction_id : undefined;
  if ((typeof message === "string") === (typeof transaction === "string") ||
    (message !== undefined && (message.length === 0 || message.length > 256 || message.trim() !== message)) ||
    (transaction !== undefined && (transaction.length === 0 || transaction.length > 256 || transaction.trim() !== transaction))) {
    throw new TypeError("Authorized Dataset triangulation requires exactly one bounded HCS reference");
  }
  return reference;
}

/**
 * Recompute Dataset v1 source evidence, retrieve the caller-authorized private
 * Dataset Registry event, independently corroborate its exact HCS ciphertext,
 * and compare only commitments the local Dataset verifier also establishes.
 * Raw decrypted payload is intentionally excluded from the returned report.
 */
export async function triangulateAuthorizedDatasetV1(
  config: AuthorizedDatasetTriangulationV1Config,
  input: AuthorizedDatasetTriangulationV1Input,
): Promise<AuthorizedDatasetTriangulationV1Result> {
  if (!config?.core || !input?.intent?.subject || input.intent.subject.kind !== "dataset") {
    throw new TypeError("Authorized Dataset triangulation requires Dataset intent and Core config");
  }
  const network = input.intent.subject.hedera_network;
  if (network !== "mainnet" && network !== "testnet") {
    throw new TypeError("Authorized Dataset triangulation requires an explicit Hedera network");
  }
  const reference = checkedReference(input.hcs_reference);

  const source = sourceReportWithSubjectFact(await verifyDatasetV1WithIntent(input));
  const resolution = await resolveAuthorizedHcsObservationsV1(config, {
    subject: input.intent.subject,
    request: Object.freeze({
      network,
      include_decrypted: true,
      ...(reference.message_id !== undefined ? { message_id: reference.message_id } : {}),
      ...(reference.transaction_id !== undefined ? { transaction_id: reference.transaction_id } : {}),
    }),
  });
  const hcs = triangulateAuthorizedHcsV1({ source_report: source, resolution });

  const parsed = parseDatasetRegistryVersionCreatedV1(
    resolution.core.evidence?.payload_included === true ? resolution.core.evidence.payload : null,
    network,
  );
  const registry = registryObservation(parsed, hcs.report);
  const relationship: TriangulationRelationshipPlanV1 = Object.freeze({
    id: "provided_authorized",
    left_observation_id: BUNDLE_OBSERVATION_ID,
    right_observation_id: REGISTRY_OBSERVATION_ID,
    comparisons: Object.freeze([
      Object.freeze({ key: "dataset_key", left_key: "source_subject_id", right_key: "dataset.registry.dataset_key" }),
      Object.freeze({ key: "dataset_fingerprint", left_key: "dataset_fingerprint", right_key: "dataset.registry.dataset_fingerprint" }),
    ]),
  });
  const compared = compareEvidenceTriangulationV1({
    source_report: hcs.report,
    observations: Object.freeze(registry ? [registry] : []),
    relationships: Object.freeze([relationship]),
  });

  const finding = profileFinding(parsed);
  return Object.freeze({
    consistency: aggregate(hcs.consistency, compared.consistency, parsed),
    relationships: Object.freeze([...hcs.relationships, ...compared.relationships]),
    report: Object.freeze({
      ...compared.report,
      findings: Object.freeze([...compared.report.findings, finding]),
    }),
    resolution: Object.freeze({
      authorized_core: resolution.core.status,
      hedera_mirror: resolution.mirror_resolution,
      dataset_registry_event: parsed.status,
    }),
  });
}
