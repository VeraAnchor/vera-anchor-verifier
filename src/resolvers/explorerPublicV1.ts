import type { HederaNetwork, VerificationFact, VerificationObservation, VerificationSubject } from "../contracts/verification.js";
import { readExplorerPublicV1, type ExplorerPublicTransportV1 } from "./explorerTransportV1.js";

const HASH = /^[0-9a-f]{128}$/i;
const KEY = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/;
const UUID = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i;
const TOPIC = /^0\.0\.[1-9][0-9]*$/;
const MAX_VALUE = 4096;

type Json = Readonly<Record<string, unknown>>;
export type ExplorerPublicationV1 = Readonly<{
  hedera_network: HederaNetwork;
  entity_kind: "dataset" | "dataset_version" | "merkle_anchor" | "merkle_root";
  entity_id: string;
  transaction_id: string | null;
  message_id: string | null;
  topic_id: string | null;
  sequence_number: number | null;
}>;

export type ExplorerPublicRecordV1 = Readonly<{
  status: "resolved" | "not_found" | "unavailable" | "invalid" | "conflict";
  reason_code: string | null;
  observation: VerificationObservation | null;
  publication: ExplorerPublicationV1 | null;
}>;

export type ExplorerDatasetV1Request = Readonly<{
  dataset_key: string;
  network: HederaNetwork;
}>;
export type ExplorerIngestV1Request = Readonly<{
  anchor_request_id: string;
  ingest_object_key: string;
  network: HederaNetwork;
}>;
export type ExplorerMerkleRootV1Request = Readonly<{
  root_id: string;
  network: HederaNetwork;
}>;

function record(value: unknown): Json {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError("Invalid Explorer public record");
  return value as Json;
}

function string(value: unknown, max = MAX_VALUE): string | null {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value !== "string" || value.length > max || !value.trim()) {
    throw new TypeError("Invalid Explorer public string");
  }
  return value.trim();
}

function hash(value: unknown): string | null {
  const s = string(value, 128);
  if (!s) return null;
  if (!HASH.test(s)) throw new TypeError("Invalid Explorer SHA3-512 commitment");
  return s.toLowerCase();
}

function positiveInt(value: unknown): number | null {
  if (value === null || value === undefined || value === "") return null;
  const n = typeof value === "number" ? value : typeof value === "string" ? Number(value) : NaN;
  if (!Number.isSafeInteger(n) || n < 1) throw new TypeError("Invalid Explorer sequence number");
  return n;
}

function count(value: unknown): number | null {
  if (value === null || value === undefined || value === "") return null;
  const n = typeof value === "number" ? value : typeof value === "string" ? Number(value) : NaN;
  if (!Number.isSafeInteger(n) || n < 0) throw new TypeError("Invalid Explorer count");
  return n;
}

function available(key: string, value: string | number | null, reason = "PUBLIC_FIELD_UNAVAILABLE"): VerificationFact {
  return value === null
    ? { key, state: "unavailable", reason_code: reason }
    : { key, state: "available", value };
}

function observation(subject: VerificationSubject, id: string, facts: readonly VerificationFact[]): VerificationObservation {
  return Object.freeze({
    id,
    subject: Object.freeze({ ...subject }),
    source: "public_record" as const,
    resolver_id: "explorer.public-http.v1",
    facts: Object.freeze(facts.map((fact) => Object.freeze(fact))),
  });
}

function outcome(status: ExplorerPublicRecordV1["status"], reason: string | null): ExplorerPublicRecordV1 {
  return { status, reason_code: reason, observation: null, publication: null };
}

function publication(
  row: Json,
  prefix: string,
  kind: ExplorerPublicationV1["entity_kind"],
  entityId: string | null,
  network: HederaNetwork,
): ExplorerPublicationV1 | null {
  const transaction = string(row[`${prefix}transaction_id`], 256);
  const message = string(row[`${prefix}message_id`], 256);
  const topic = string(row[`${prefix}topic_id`], 64);
  const sequence = positiveInt(row[`${prefix}sequence_number`]);
  if (!transaction && !message && !topic && sequence === null) return null;
  if (!entityId || (!transaction && !message && !(topic && sequence !== null)) ||
    (topic !== null && !TOPIC.test(topic)) || (topic === null) !== (sequence === null)) {
    throw new TypeError("Invalid Explorer publication locator");
  }
  if (message) {
    const match = /^(?:(\d+)@(0\.0\.\d+)|(0\.0\.\d+)@(\d+))$/.exec(message);
    if (!match) throw new TypeError("Invalid Explorer publication message id");
    const messageTopic = match[2] ?? match[3];
    const messageSequence = Number(match[1] ?? match[4]);
    if (!messageTopic || !TOPIC.test(messageTopic) || !Number.isSafeInteger(messageSequence) || messageSequence < 1 ||
      (topic && messageTopic !== topic) || (sequence !== null && sequence !== messageSequence)) {
      throw new TypeError("Inconsistent Explorer publication message identity");
    }
    return Object.freeze({
      hedera_network: network,
      entity_kind: kind,
      entity_id: entityId,
      transaction_id: transaction,
      message_id: `${messageSequence}@${messageTopic}`,
      topic_id: topic ?? messageTopic,
      sequence_number: sequence ?? messageSequence,
    });
  }
  return Object.freeze({
    hedera_network: network,
    entity_kind: kind,
    entity_id: entityId,
    transaction_id: transaction,
    message_id: topic && sequence !== null ? `${sequence}@${topic}` : null,
    topic_id: topic,
    sequence_number: sequence,
  });
}

function requiredNetwork(row: Json, network: HederaNetwork): void {
  if (row.hedera_network !== network) throw new TypeError("Explorer public record network mismatch");
}

function materialize(
  subject: VerificationSubject,
  id: string,
  facts: VerificationFact[],
  pub: ExplorerPublicationV1 | null,
): ExplorerPublicRecordV1 {
  facts.push(
    available("publication.entity_kind", pub?.entity_kind ?? null, "PUBLICATION_ANCHOR_UNAVAILABLE"),
    available("publication.entity_id", pub?.entity_id ?? null, "PUBLICATION_ANCHOR_UNAVAILABLE"),
    available("publication.topic_id", pub?.topic_id ?? null, "PUBLICATION_ANCHOR_UNAVAILABLE"),
    available("publication.sequence_number", pub?.sequence_number ?? null, "PUBLICATION_ANCHOR_UNAVAILABLE"),
  );
  return Object.freeze({
    status: "resolved",
    reason_code: null,
    observation: observation(subject, id, facts),
    publication: pub,
  });
}

function validatedInput(id: string, network: HederaNetwork, pattern: RegExp): void {
  if (typeof id !== "string" || !pattern.test(id) || (network !== "testnet" && network !== "mainnet")) {
    throw new TypeError("Invalid Explorer public lookup input");
  }
}

/** Resolve the active Dataset manifest; never infer bundle_digest from manifest_hash. */
export async function resolveExplorerDatasetV1(
  config: ExplorerPublicTransportV1,
  request: ExplorerDatasetV1Request,
): Promise<ExplorerPublicRecordV1> {
  validatedInput(request.dataset_key, request.network, KEY);
  const read = await readExplorerPublicV1(config, `/v1/datasets/${encodeURIComponent(request.dataset_key)}`, request.network);
  if (read.status !== "ok") return outcome(read.status, read.reason_code);
  try {
    const row = record(read.body);
    requiredNetwork(row, request.network);
    if (row.dataset_key == null) return outcome("unavailable", "PUBLIC_DATASET_KEY_UNAVAILABLE");
    if (row.dataset_key !== request.dataset_key) return outcome("conflict", "PUBLIC_DATASET_KEY_MISMATCH");
    const versionId = string(row.dataset_version_id, 128);
    const datasetId = string(row.dataset_id, 128);
    const version = publication(row, "publication_version_", "dataset_version", versionId, request.network);
    const dataset = publication(row, "publication_dataset_", "dataset", datasetId, request.network);
    const selected = version ?? dataset;
    return materialize({ kind: "dataset", id: request.dataset_key, hedera_network: request.network }, "dataset.public_record", [
      available("dataset_key", request.dataset_key),
      available("dataset_fingerprint", hash(row.dataset_fingerprint)),
      available("dataset.manifest_hash", hash(row.manifest_hash)),
      available("dataset.version_id", versionId),
      available("dataset.dataset_id", datasetId),
    ], selected);
  } catch {
    return outcome("invalid", "PUBLIC_DATASET_RESPONSE_INVALID");
  }
}

/** Resolve a public Merkle anchor by its explicit ID; bind it to caller's Ingest object key. */
export async function resolveExplorerIngestV1(
  config: ExplorerPublicTransportV1,
  request: ExplorerIngestV1Request,
): Promise<ExplorerPublicRecordV1> {
  validatedInput(request.anchor_request_id, request.network, UUID);
  validatedInput(request.ingest_object_key, request.network, KEY);
  const read = await readExplorerPublicV1(config, `/v1/merkle/anchors/${request.anchor_request_id}`, request.network);
  if (read.status !== "ok") return outcome(read.status, read.reason_code);
  try {
    const row = record(read.body);
    requiredNetwork(row, request.network);
    if (row.anchor_request_id == null) return outcome("unavailable", "PUBLIC_ANCHOR_ID_UNAVAILABLE");
    if (row.anchor_request_id !== request.anchor_request_id) return outcome("conflict", "PUBLIC_ANCHOR_ID_MISMATCH");
    if (row.ingest_object_key == null) return outcome("unavailable", "PUBLIC_INGEST_OBJECT_UNAVAILABLE");
    if (row.ingest_object_key !== request.ingest_object_key) return outcome("conflict", "PUBLIC_INGEST_OBJECT_MISMATCH");
    const pub = publication(row, "publication_anchor_", "merkle_anchor", request.anchor_request_id, request.network);
    return materialize({ kind: "ingest", id: request.ingest_object_key, hedera_network: request.network }, "ingest.public_record", [
      available("ingest.object_key", request.ingest_object_key),
      available("fingerprint", hash(row.ingest_fingerprint)),
      available("bundle_digest", hash(row.ingest_bundle_digest)),
      available("ingest.merkle_root", hash(row.ingest_merkle_root)),
      available("ingest.total_bytes", count(row.ingest_total_bytes)),
      available("merkle.anchor_request_id", request.anchor_request_id),
      available("merkle.root_id", string(row.root_id, 128)),
      available("merkle.root_hash", hash(row.root_hash)),
    ], pub);
  } catch {
    return outcome("invalid", "PUBLIC_INGEST_RESPONSE_INVALID");
  }
}

/** Core-generated root evidence; independent of any HF tenant anchor request. */
export async function resolveExplorerMerkleRootV1(
  config: ExplorerPublicTransportV1,
  request: ExplorerMerkleRootV1Request,
): Promise<ExplorerPublicRecordV1> {
  validatedInput(request.root_id, request.network, UUID);
  const read = await readExplorerPublicV1(config, `/v1/merkle/roots/${request.root_id}`, request.network);
  if (read.status !== "ok") return outcome(read.status, read.reason_code);
  try {
    const row = record(read.body);
    requiredNetwork(row, request.network);
    if (row.id == null) return outcome("unavailable", "PUBLIC_ROOT_ID_UNAVAILABLE");
    if (row.id !== request.root_id) return outcome("conflict", "PUBLIC_ROOT_ID_MISMATCH");
    const pub = publication(row, "publication_root_", "merkle_root", request.root_id, request.network);
    return materialize({ kind: "merkle_root", id: request.root_id, hedera_network: request.network }, "merkle_root.public_record", [
      available("merkle.root_id", request.root_id),
      available("merkle.root_hash", hash(row.root_hash)),
      available("merkle.leaf_count", count(row.leaf_count)),
      available("merkle.hash_alg", string(row.hash_alg, 64)),
      available("merkle.tree_alg", string(row.tree_alg, 64)),
    ], pub);
  } catch {
    return outcome("invalid", "PUBLIC_MERKLE_RESPONSE_INVALID");
  }
}
