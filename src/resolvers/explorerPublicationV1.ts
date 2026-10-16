import type { VerificationFact, VerificationObservation } from "../contracts/verification.js";
import { observeCoreMessageBindingV1 } from "../triangulation/messageObservationV1.js";
import {
  resolveExplorerDatasetV1,
  resolveExplorerIngestV1,
  resolveExplorerMerkleRootV1,
  type ExplorerDatasetV1Request,
  type ExplorerIngestV1Request,
  type ExplorerMerkleRootV1Request,
  type ExplorerPublicRecordV1,
  type ExplorerPublicationV1,
} from "./explorerPublicV1.js";
import { readExplorerPublicV1, type ExplorerPublicTransportV1 } from "./explorerTransportV1.js";

const HASH = /^[0-9a-f]{128}$/i;
const MAX_RECEIPT_BYTES = 128 * 1024;
const SCHEMA = "va:explorer_publication_receipt:v1";

type Json = Readonly<Record<string, unknown>>;
export type ExplorerPublicationDisclosureV1 = Readonly<{
  status: "resolved" | "unavailable" | "invalid" | "conflict" | "unsupported";
  reason_code: string | null;
  /** Core/Explorer-supplied disclosure claims; NOT independently decrypted evidence. */
  receipt_observation: VerificationObservation | null;
  /** Core's claimed HCS message digest, for independent comparison in Phase 3C. */
  message_binding_observation: VerificationObservation | null;
}>;

function result(status: ExplorerPublicationDisclosureV1["status"], reason: string | null): ExplorerPublicationDisclosureV1 {
  return { status, reason_code: reason, receipt_observation: null, message_binding_observation: null };
}
function record(value: unknown): Json | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Json : null;
}
function text(value: unknown, max = 512): string | null {
  if (value === undefined || value === null || value === "") return null;
  return typeof value === "string" && value.trim().length > 0 && value.length <= max ? value.trim() : null;
}
function digest(value: unknown): string | null {
  const normalized = text(value, 128);
  return normalized && HASH.test(normalized) ? normalized.toLowerCase() : null;
}
function optionalDigest(value: unknown): string | null {
  if (value === undefined || value === null || value === "") return null;
  const parsed = digest(value);
  if (!parsed) throw new TypeError("Invalid publication proof digest");
  return parsed;
}
function fact(key: string, value: string | number | null): VerificationFact {
  return value === null ? { key, state: "unavailable", reason_code: "PUBLICATION_RECEIPT_FIELD_UNAVAILABLE" } :
    { key, state: "available", value };
}
function optionalNumber(value: unknown): number | null {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new TypeError("Invalid publication receipt numeric commitment");
  }
  return value;
}

function publicReceipt(payload: unknown, claim: ExplorerPublicationV1): Json | null {
  let raw = payload;
  if (typeof payload === "string") {
    if (new TextEncoder().encode(payload).byteLength > MAX_RECEIPT_BYTES) return null;
    try { raw = JSON.parse(payload) as unknown; } catch { return null; }
  }
  const receipt = record(raw);
  if (!receipt) return null;
  try {
    if (new TextEncoder().encode(JSON.stringify(receipt)).byteLength > MAX_RECEIPT_BYTES) return null;
  } catch { return null; }
  if (receipt.schema !== SCHEMA || receipt.event_type !== "published" ||
    receipt.entity_kind !== claim.entity_kind || receipt.entity_id !== claim.entity_id ||
    receipt.visibility !== "public" || receipt.event_version !== 1) {
    return null;
  }
  if (receipt.proof !== undefined && !record(receipt.proof)) return null;
  return receipt;
}

/**
 * Scoped Explorer-assisted disclosure, using only the locator selected from a
 * successfully resolved public record. The public entry points below always
 * obtain the locator themselves. Never accepts a user-specified HCS URL,
 * tenant key, or a free-form decrypt locator. No payload is returned in reports.
 * This call does NOT independently authenticate ciphertext-to-plaintext binding.
 */
async function resolveExplorerPublicationV1(
  config: ExplorerPublicTransportV1,
  publicRecord: ExplorerPublicRecordV1,
): Promise<ExplorerPublicationDisclosureV1> {
  if (publicRecord.status !== "resolved" || !publicRecord.observation ||
    publicRecord.observation.source !== "public_record" || !publicRecord.publication) {
    return result("unavailable", "PUBLICATION_ANCHOR_UNAVAILABLE");
  }
  const locator = publicRecord.publication;
  if (locator.hedera_network !== publicRecord.observation.subject.hedera_network ||
    !locator.entity_id || !locator.entity_kind ||
    (!locator.transaction_id && !locator.message_id)) {
    return result("invalid", "PUBLICATION_REFERENCE_INVALID");
  }
  const body = {
    hedera_network: locator.hedera_network,
    mode: "decrypt_and_verify",
    include_decrypted: true,
    ...(locator.transaction_id ? { transaction_id: locator.transaction_id } : { message_id: locator.message_id }),
  };
  const read = await readExplorerPublicV1(config, "/v1/hcs/verify-decrypt", locator.hedera_network, body);
  if (read.status !== "ok") {
    return result("unavailable", read.reason_code ?? "PUBLICATION_DECRYPT_UNAVAILABLE");
  }
  const response = record(read.body);
  if (!response) return result("invalid", "PUBLICATION_DECRYPT_RESPONSE_INVALID");
  if (response.hedera_network !== locator.hedera_network) {
    return result("conflict", "PUBLICATION_NETWORK_MISMATCH");
  }
  const tx = record(response.tx);
  const topic = record(response.topic);
  if (locator.transaction_id && text(tx?.transaction_id, 256) !== locator.transaction_id) {
    return result(!tx?.transaction_id ? "invalid" : "conflict", "PUBLICATION_TRANSACTION_MISMATCH");
  }
  if (locator.message_id && !tx?.message_id && !locator.transaction_id) {
    return result("unavailable", "PUBLICATION_MESSAGE_REFERENCE_UNAVAILABLE");
  }
  if (locator.message_id) {
    const returnedId = text(tx?.message_id, 256);
    if (returnedId && returnedId !== locator.message_id &&
      returnedId !== `${locator.topic_id}@${locator.sequence_number}`) {
      return result("conflict", "PUBLICATION_MESSAGE_MISMATCH");
    }
    if (!returnedId && !locator.transaction_id) {
      return result("invalid", "PUBLICATION_MESSAGE_UNAVAILABLE");
    }
  }
  if (locator.topic_id && text(topic?.topic_id, 64) !== locator.topic_id) {
    return result(!topic?.topic_id ? "invalid" : "conflict", "PUBLICATION_TOPIC_MISMATCH");
  }
  const hash = record(response.hash);
  if (hash?.match === false || response.verified === false) {
    // A provider-declared hash failure is not, by itself, independently
    // established cryptographic contradiction. Record a non-passing result.
    return result("unavailable", "PUBLICATION_PROVIDER_VERIFICATION_FAILED");
  }
  if (hash?.match !== true || response.verified !== true) {
    return result("unavailable", "PUBLICATION_PROVIDER_VERIFICATION_UNAVAILABLE");
  }
  if (record(response.payload)?.schema !== undefined && record(response.payload)?.schema !== SCHEMA) {
    return result("unsupported", "PUBLICATION_RECEIPT_UNSUPPORTED_SCHEMA");
  }
  const receipt = publicReceipt(response.payload, locator);
  if (!receipt) return result("invalid", "PUBLICATION_RECEIPT_INVALID");
  try {
    const proof = record(receipt.proof) ?? {};
    const facts: VerificationFact[] = [
      fact("publication.receipt.schema", SCHEMA),
      fact("publication.receipt.entity_kind", locator.entity_kind),
      fact("publication.receipt.entity_id", locator.entity_id),
      fact("publication.receipt.event_type", "published"),
      fact("publication.proof.dataset_key", text(proof.dataset_key, 256)),
      fact("publication.proof.fingerprint", optionalDigest(proof.fingerprint)),
      fact("publication.proof.manifest_hash", optionalDigest(proof.manifest_hash)),
      fact("publication.proof.merkle_root", optionalDigest(proof.merkle_root)),
      fact("publication.proof.ingest_object_key", text(proof.ingest_object_key, 256)),
      fact("publication.proof.ingest_fingerprint", optionalDigest(proof.ingest_fingerprint)),
      fact("publication.proof.ingest_bundle_digest", optionalDigest(proof.ingest_bundle_digest)),
      fact("publication.proof.ingest_merkle_root", optionalDigest(proof.ingest_merkle_root)),
      fact("publication.proof.ingest_item_count", optionalNumber(proof.ingest_item_count)),
      fact("publication.proof.ingest_total_bytes", optionalNumber(proof.ingest_total_bytes)),
    ];
    const subject = publicRecord.observation.subject;
    const disclosure: VerificationObservation = Object.freeze({
      id: `${subject.kind}.publication_receipt`,
      subject,
      source: "public_record" as const,
      resolver_id: "explorer.public-disclosure.v1",
      facts: Object.freeze(facts.map((entry) => Object.freeze(entry))),
    });
    const binding = observeCoreMessageBindingV1({
      id: `${subject.kind}.core_binding`,
      subject,
      binding: response.message_binding,
    });
    return { status: "resolved", reason_code: null, receipt_observation: disclosure, message_binding_observation: binding };
  } catch {
    return result("invalid", "PUBLICATION_RECEIPT_INVALID");
  }
}

/** Public workflows cannot accept a caller-constructed publication locator. */
export type ExplorerPublishedEvidenceV1 = Readonly<{
  public_record: ExplorerPublicRecordV1;
  disclosure: ExplorerPublicationDisclosureV1;
}>;

async function withDisclosure(
  config: ExplorerPublicTransportV1,
  publicRecord: ExplorerPublicRecordV1,
): Promise<ExplorerPublishedEvidenceV1> {
  return Object.freeze({
    public_record: publicRecord,
    disclosure: await resolveExplorerPublicationV1(config, publicRecord),
  });
}

export async function resolveExplorerDatasetPublicationV1(
  config: ExplorerPublicTransportV1,
  request: ExplorerDatasetV1Request,
): Promise<ExplorerPublishedEvidenceV1> {
  return withDisclosure(config, await resolveExplorerDatasetV1(config, request));
}

export async function resolveExplorerIngestPublicationV1(
  config: ExplorerPublicTransportV1,
  request: ExplorerIngestV1Request,
): Promise<ExplorerPublishedEvidenceV1> {
  return withDisclosure(config, await resolveExplorerIngestV1(config, request));
}

export async function resolveExplorerMerkleRootPublicationV1(
  config: ExplorerPublicTransportV1,
  request: ExplorerMerkleRootV1Request,
): Promise<ExplorerPublishedEvidenceV1> {
  return withDisclosure(config, await resolveExplorerMerkleRootV1(config, request));
}
