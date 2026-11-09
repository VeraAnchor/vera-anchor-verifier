import type { VerificationFact, VerificationFinding, VerificationObservation, VerificationReport, VerificationSubject } from "../contracts/verification.js";
import { resolveExplorerDatasetPublicationV1, resolveExplorerIngestPublicationV1,
  type ExplorerPublishedEvidenceV1 } from "../resolvers/explorerPublicationV1.js";
import type { ExplorerPublicTransportV1 } from "../resolvers/explorerTransportV1.js";
import type { ExplorerPublicationV1 } from "../resolvers/explorerPublicV1.js";
import { resolveHederaPublicationV1, type HederaMirrorV1Config,
  type HederaPublicationObservationV1 } from "../resolvers/hederaMirrorV1.js";
import { compareEvidenceTriangulationV1, type TriangulationV1Result,
  type TriangulationRelationshipPlanV1 } from "./compareV1.js";
import { verifyDatasetV1WithIntent, verifyIngestV1WithIntent,
  type DatasetV1IntentInput, type IngestV1IntentInput } from "../verification/sourceIntentV1.js";

export type PublicTriangulationV1Config = Readonly<{
  explorer: ExplorerPublicTransportV1;
  mirror?: HederaMirrorV1Config;
}>;
export type PublicIngestTriangulationV1Input = IngestV1IntentInput & Readonly<{
  /** Source identity and Core Merkle anchor identity are distinct. */
  anchor_request_id: string;
}>;
export type PublicTriangulationV1Result = Readonly<{
  consistency: TriangulationV1Result["consistency"];
  relationships: TriangulationV1Result["relationships"];
  report: VerificationReport;
  resolution: Readonly<{
    public_record: ExplorerPublishedEvidenceV1["public_record"]["status"];
    publication_disclosure: ExplorerPublishedEvidenceV1["disclosure"]["status"];
    hedera_mirror: HederaPublicationObservationV1["status"] | "not_requested";
  }>;
}>;

const PROOF_DATASET = "publication.proof.fingerprint";
const PROOF_INGEST_FINGERPRINT = "publication.proof.ingest_fingerprint";
const PROOF_INGEST_BUNDLE = "publication.proof.ingest_bundle_digest";

function requiredNetwork(subject: VerificationSubject): "mainnet" | "testnet" {
  if (subject.hedera_network !== "testnet" && subject.hedera_network !== "mainnet") {
    throw new TypeError("Public triangulation requires an explicit Hedera network in verification intent");
  }
  return subject.hedera_network;
}
function notAvailable(key: string, reason: string): VerificationFact {
  return Object.freeze({ key, state: "unavailable" as const, reason_code: reason });
}
function available(key: string, value: string | number): VerificationFact {
  return Object.freeze({ key, state: "available" as const, value });
}
function mergePublicFacts(profile: "dataset" | "ingest", disclosure: ExplorerPublishedEvidenceV1): VerificationObservation | null {
  const publicObs = disclosure.public_record.observation;
  if (!publicObs) return null;
  const claims = disclosure.disclosure.receipt_observation;
  const keys = profile === "dataset"
    ? ["publication.proof.dataset_key", PROOF_DATASET]
    : ["publication.proof.ingest_object_key", PROOF_INGEST_FINGERPRINT, PROOF_INGEST_BUNDLE];
  const extra = claims?.facts ?? keys.map((key) => notAvailable(key, disclosure.disclosure.reason_code ?? "PUBLICATION_DISCLOSURE_UNAVAILABLE"));
  return Object.freeze({ ...publicObs,
    // Both original and disclosed receipt are Explorer-sourced; never count as two independent authorities.
    facts: Object.freeze([...publicObs.facts, ...extra]),
  });
}
function mergeBindingFacts(
  subject: VerificationSubject,
  pub: ExplorerPublicationV1 | null,
  disclosure: ExplorerPublishedEvidenceV1,
): VerificationObservation {
  const claim = disclosure.disclosure.message_binding_observation;
  const reason = disclosure.disclosure.reason_code ?? "PUBLICATION_MESSAGE_BINDING_UNAVAILABLE";
  const binding = claim?.facts ?? [
    notAvailable("publication.message_sha3_512", reason),
    notAvailable("publication.message_bytes", reason),
  ];
  return Object.freeze({
    id: `${subject.kind}.core_binding`,
    subject: Object.freeze({ ...subject }),
    source: "public_record" as const,
    resolver_id: "explorer.publication-claims.v1",
    facts: Object.freeze([
      ...binding,
      pub?.topic_id ? available("publication.topic_id", pub.topic_id) : notAvailable("publication.topic_id", "PUBLICATION_LOCATOR_UNAVAILABLE"),
      pub?.sequence_number != null ? available("publication.sequence_number", pub.sequence_number) :
        notAvailable("publication.sequence_number", "PUBLICATION_LOCATOR_UNAVAILABLE"),
    ]),
  });
}
function plans(profile: "dataset" | "ingest"): readonly TriangulationRelationshipPlanV1[] {
  const publicComparisons = profile === "dataset"
    ? [
        { key: "dataset_fingerprint", left_key: "dataset_fingerprint", right_key: "dataset_fingerprint" },
        { key: "publication_subject", left_key: "source_subject_id", right_key: "publication.proof.dataset_key" },
        { key: "publication_fingerprint", left_key: "dataset_fingerprint", right_key: PROOF_DATASET },
      ]
    : [
        { key: "ingest_fingerprint", left_key: "fingerprint", right_key: "fingerprint" },
        { key: "ingest_bundle_digest", left_key: "bundle_digest", right_key: "bundle_digest" },
        { key: "publication_subject", left_key: "source_subject_id", right_key: "publication.proof.ingest_object_key" },
        { key: "publication_fingerprint", left_key: "fingerprint", right_key: PROOF_INGEST_FINGERPRINT },
        { key: "publication_bundle_digest", left_key: "bundle_digest", right_key: PROOF_INGEST_BUNDLE },
      ];
  return Object.freeze([
    Object.freeze({
      id: "provided_public_record" as const,
      left_observation_id: `${profile}.bundle`,
      right_observation_id: `${profile}.public_record`,
      comparisons: Object.freeze(publicComparisons),
    }),
    Object.freeze({
      id: "public_record_hedera" as const,
      left_observation_id: `${profile}.core_binding`,
      right_observation_id: `${profile}.hedera_mirror`,
      comparisons: Object.freeze([
        { key: "publication_topic", left_key: "publication.topic_id", right_key: "hedera.topic_id" },
        { key: "publication_sequence", left_key: "publication.sequence_number", right_key: "hedera.sequence_number" },
        { key: "message_sha3_512", left_key: "publication.message_sha3_512", right_key: "publication.message_sha3_512" },
        { key: "message_bytes", left_key: "publication.message_bytes", right_key: "publication.message_bytes" },
      ]),
    }),
  ]);
}
async function execute(
  config: PublicTriangulationV1Config,
  profile: "dataset" | "ingest",
  sourceReport: VerificationReport,
  publicEvidence: ExplorerPublishedEvidenceV1,
): Promise<PublicTriangulationV1Result> {
  const subject = sourceReport.intent.subject;
  const publicRecord = mergePublicFacts(profile, publicEvidence);
  const pub = publicEvidence.public_record.publication;
  const mirror = pub ? await resolveHederaPublicationV1(config.mirror ?? {}, pub, subject) : null;
  const binding = mergeBindingFacts(subject, pub, publicEvidence);
  const disclosureReceipt = publicEvidence.disclosure.receipt_observation;
  const observations = [
    ...(publicRecord ? [publicRecord] : []),
    binding,
    ...(disclosureReceipt ? [disclosureReceipt] : []),
    ...(mirror?.observation ? [mirror.observation] : []),
  ];
  // Actual offline hash verification was invoked above; no caller-supplied report is accepted.
  const scopedReport: VerificationReport = Object.freeze({ ...sourceReport,
    observations: Object.freeze(sourceReport.observations.map((entry) => entry.id !== `${profile}.bundle`
      ? entry : Object.freeze({ ...entry, facts: Object.freeze([...entry.facts,
        available("source_subject_id", subject.id),
      ]) }))),
  });
  const compared = compareEvidenceTriangulationV1({
    source_report: scopedReport,
    observations,
    relationships: plans(profile),
  });
  const check: VerificationFinding = Object.freeze({
    check_id: "triangulation.plaintext_ciphertext_binding",
    outcome: "indeterminate" as const,
    reason_code: disclosureReceipt ? "EXPLORER_ASSISTED_DECRYPTION" : "PUBLICATION_DISCLOSURE_UNAVAILABLE",
    observation_ids: Object.freeze(disclosureReceipt ? [disclosureReceipt.id] : []),
  });
  const conflicts: VerificationFinding[] = [];
  if (publicEvidence.public_record.status === "conflict") conflicts.push(Object.freeze({
    check_id: "triangulation.public_record_scope", outcome: "fail" as const,
    reason_code: publicEvidence.public_record.reason_code, observation_ids: Object.freeze([]),
  }));
  if (publicEvidence.disclosure.status === "conflict") conflicts.push(Object.freeze({
    check_id: "triangulation.publication_disclosure", outcome: "fail" as const,
    reason_code: publicEvidence.disclosure.reason_code, observation_ids: Object.freeze([]),
  }));
  if (mirror?.status === "conflict") conflicts.push(Object.freeze({
    check_id: "triangulation.mirror_transaction", outcome: "fail" as const,
    reason_code: mirror.reason_code, observation_ids: Object.freeze([]),
  }));
  return Object.freeze({
    consistency: conflicts.length ? "conflict" as const : compared.consistency,
    relationships: compared.relationships,
    report: Object.freeze({ ...compared.report, findings: Object.freeze([...compared.report.findings, check, ...conflicts]) }),
    resolution: Object.freeze({
      public_record: publicEvidence.public_record.status,
      publication_disclosure: publicEvidence.disclosure.status,
      hedera_mirror: mirror?.status ?? "not_requested",
    }),
  });
}

/** Full Dataset source recomputation -> public record -> Explorer disclosure -> direct Mirror observation. */
export async function triangulateDatasetV1(
  config: PublicTriangulationV1Config,
  input: DatasetV1IntentInput,
): Promise<PublicTriangulationV1Result> {
  const network = requiredNetwork(input.intent.subject);
  if (input.intent.subject.kind !== "dataset") throw new TypeError("Dataset triangulation requires dataset intent");
  const source = await verifyDatasetV1WithIntent(input);
  const published = await resolveExplorerDatasetPublicationV1(config.explorer, {
    dataset_key: input.intent.subject.id, network,
  });
  return execute(config, "dataset", source, published);
}

/** Full Ingest source recomputation; public anchor identity must be provided independently by caller. */
export async function triangulateIngestV1(
  config: PublicTriangulationV1Config,
  input: PublicIngestTriangulationV1Input,
): Promise<PublicTriangulationV1Result> {
  const network = requiredNetwork(input.intent.subject);
  if (input.intent.subject.kind !== "ingest") throw new TypeError("Ingest triangulation requires ingest intent");
  const source = await verifyIngestV1WithIntent(input);
  const published = await resolveExplorerIngestPublicationV1(config.explorer, {
    ingest_object_key: input.intent.subject.id,
    anchor_request_id: input.anchor_request_id,
    network,
  });
  return execute(config, "ingest", source, published);
}
