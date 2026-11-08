import type { VerificationObservation, VerificationSubject } from "../contracts/verification.js";
import { sha3_512Hex } from "../crypto/sha3.js";

const TOPIC_ID_RE = /^0\.0\.[1-9][0-9]*$/;
const OBSERVATION_ID_RE = /^[a-z][a-z0-9._:-]{0,127}$/;
const MAX_MESSAGE_BYTES = 1024 * 1024;

export type MirrorMessageV1Input = Readonly<{
  id: string;
  subject: VerificationSubject;
  topic_id: string;
  sequence_number: number;
  message_bytes: Uint8Array;
}>;

/**
 * Recompute SHA3-512 over exact supplied HCS ciphertext/message bytes.
 * This is a local byte check, not proof the bytes came from Hedera; a Mirror
 * resolver must separately establish and attribute the network observation.
 */
export function observeMirrorMessageV1(input: MirrorMessageV1Input): VerificationObservation {
  if (!OBSERVATION_ID_RE.test(input.id) ||
    !input.subject ||
    (input.subject.hedera_network !== "mainnet" && input.subject.hedera_network !== "testnet") ||
    typeof input.subject.id !== "string" || !input.subject.id ||
    !TOPIC_ID_RE.test(input.topic_id) ||
    !Number.isSafeInteger(input.sequence_number) || input.sequence_number < 1 ||
    !(input.message_bytes instanceof Uint8Array) ||
    input.message_bytes.byteLength > MAX_MESSAGE_BYTES) {
    throw new TypeError("Invalid or oversized Mirror message observation");
  }
  return Object.freeze({
    id: input.id,
    source: "hedera_mirror" as const,
    subject: Object.freeze({ ...input.subject }),
    facts: Object.freeze([
      Object.freeze({ key: "hedera.topic_id", state: "available" as const, value: input.topic_id }),
      Object.freeze({ key: "hedera.sequence_number", state: "available" as const, value: input.sequence_number }),
      Object.freeze({ key: "publication.message_sha3_512", state: "available" as const, value: sha3_512Hex(input.message_bytes) }),
      Object.freeze({ key: "publication.message_bytes", state: "available" as const, value: input.message_bytes.byteLength }),
    ]),
  });
}

const DIGEST_RE = /^[0-9a-f]{128}$/i;
const CORE_BINDING_SCHEMA = "vera.hcs-message-binding.v1";

export type CoreMessageBindingV1Input = Readonly<{
  id: string;
  subject: VerificationSubject;
  /** The scoped public Core decrypt service's claimed exact-message binding. */
  binding: unknown;
}>;

/**
 * Normalize Core's claimed ciphertext binding, not its decrypted plaintext.
 * Only comparison with separately recomputed Mirror bytes can corroborate it.
 */
function coreMessageBindingObservation(
  input: CoreMessageBindingV1Input,
  source: "public_record" | "authorized_service",
  resolverId?: string,
): VerificationObservation {
  if (!OBSERVATION_ID_RE.test(input.id) || !input.subject ||
    typeof input.subject.id !== "string" || !input.subject.id) {
    throw new TypeError("Invalid Core message-binding observation");
  }
  const raw = input.binding;
  const binding = raw && typeof raw === "object" && !Array.isArray(raw)
    ? (raw as Record<string, unknown>) : null;
  const missing = !binding;
  const schema = binding?.schema_version;
  const algorithm = binding?.algorithm;
  const digest = binding?.message_sha3_512;
  const length = binding?.message_bytes;
  const valid = schema === CORE_BINDING_SCHEMA && algorithm === "sha3-512" &&
    typeof digest === "string" && DIGEST_RE.test(digest) &&
    typeof length === "number" && Number.isSafeInteger(length) && length >= 0;
  const reason = missing ? "CORE_MESSAGE_BINDING_UNAVAILABLE" : "CORE_MESSAGE_BINDING_INVALID";
  return Object.freeze({
    id: input.id,
    source,
    subject: Object.freeze({ ...input.subject }),
    ...(resolverId ? { resolver_id: resolverId } : {}),
    facts: Object.freeze(valid ? [
      Object.freeze({ key: "publication.message_sha3_512", state: "available" as const, value: digest.toLowerCase() }),
      Object.freeze({ key: "publication.message_bytes", state: "available" as const, value: length }),
    ] : [
      Object.freeze({ key: "publication.message_sha3_512", state: "unavailable" as const, reason_code: reason }),
      Object.freeze({ key: "publication.message_bytes", state: "unavailable" as const, reason_code: reason }),
    ]),
  });
}

export function observeCoreMessageBindingV1(input: CoreMessageBindingV1Input): VerificationObservation {
  return coreMessageBindingObservation(input, "public_record");
}

/** Normalize the same Core binding under an explicit authenticated-service provenance. */
export function observeAuthorizedCoreMessageBindingV1(input: CoreMessageBindingV1Input): VerificationObservation {
  return coreMessageBindingObservation(input, "authorized_service", "core.authorized-hcs.v1");
}
