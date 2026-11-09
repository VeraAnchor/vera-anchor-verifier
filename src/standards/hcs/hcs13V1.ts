/** Pinned HCS-13 Draft: exact historical schema refs and offline canonical digest.
 * Registry and HCS-1 content must be resolved independently by a separate adapter.
 * JSON Schema semantic evaluation is NOT performed here.
 */
import { createHash } from "node:crypto";
import { canonicalHcsJsonV1, cloneHcsJsonV1, HcsJsonV1Error, parseStrictHcsJsonV1 } from "./jsonCanonicalV1.js";

export const MAX_HCS13_V1_SCHEMA_BYTES = 512 * 1024;
const RAW_SCHEMA_BYTES = MAX_HCS13_V1_SCHEMA_BYTES + 64 * 1024;
const TOPIC = /^0\.0\.[0-9]+$/;
const REFERENCE = /^hcs:\/\/13\/(0\.0\.[0-9]+)#([1-9][0-9]*)$/;
const SHA256 = /^[0-9a-f]{64}$/;

export class Hcs13V1Error extends Error {
  constructor(readonly code: string) { super(code); this.name = "Hcs13V1Error"; }
}
function fail(code: string): never { throw new Hcs13V1Error(code); }
function topicId(value: unknown): string {
  if (typeof value !== "string" || !TOPIC.test(value.trim())) return fail("HCS13_TOPIC_INVALID");
  return value.trim();
}
function sequence(value: unknown): number {
  const number = Number(value);
  if (value == null || value === "" || !Number.isSafeInteger(number) || number < 1) return fail("HCS13_SEQUENCE_INVALID");
  return number;
}

export type Hcs13ReferenceV1 = Readonly<{ ref: string; registry_topic_id: string; sequence_number: number }>;
export type Hcs13SchemaV1 = Readonly<{ schema: Readonly<Record<string, unknown>>; canonical_payload: string; sha256: string; byte_length: number }>;
export type Hcs13SchemaVerificationV1 = Readonly<{
  status: "pass" | "fail";
  reason_code: string | null;
  reference: Hcs13ReferenceV1 | null;
  sha256: string | null;
  /** Compares only against an independently supplied SHA-256 expectation. */
  checksum_match: "match" | "mismatch" | "not_checked";
}>;

export function buildHcs13ReferenceV1(registry_topic_id: unknown, sequence_number: unknown): string {
  return `hcs://13/${topicId(registry_topic_id)}#${sequence(sequence_number)}`;
}
export function parseHcs13ReferenceV1(value: unknown): Hcs13ReferenceV1 {
  const match = typeof value === "string" ? REFERENCE.exec(value.trim()) : null;
  if (!match) return fail("HCS13_REF_INVALID");
  const number = sequence(match[2]);
  return Object.freeze({ ref: `hcs://13/${match[1]}#${number}`, registry_topic_id: match[1]!, sequence_number: number });
}

function finalize(value: unknown): Hcs13SchemaV1 {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      ![null, Object.prototype].includes(Object.getPrototypeOf(value))) {
    return fail("HCS13_SCHEMA_INVALID");
  }
  const schema = value as Record<string, unknown>;
  if (schema.$schema != null && typeof schema.$schema !== "string") return fail("HCS13_SCHEMA_INVALID");
  let canonical: string;
  try { canonical = canonicalHcsJsonV1(schema, MAX_HCS13_V1_SCHEMA_BYTES); }
  catch (error) {
    if (error instanceof HcsJsonV1Error) {
      return fail(error.code === "JSON_TOO_LARGE" ? "HCS13_SCHEMA_TOO_LARGE" : "HCS13_CANONICALIZATION_FAILED");
    }
    throw error;
  }
  const bytes = Buffer.from(canonical, "utf8");
  return Object.freeze({ schema: cloneHcsJsonV1(schema), canonical_payload: canonical,
    sha256: createHash("sha256").update(bytes).digest("hex"), byte_length: bytes.byteLength });
}

export function finalizeHcs13SchemaV1(value: unknown): Hcs13SchemaV1 { return finalize(value); }
export function parseHcs13SchemaV1(value: Uint8Array | string): Hcs13SchemaV1 {
  let document: unknown;
  try { document = parseStrictHcsJsonV1(value, RAW_SCHEMA_BYTES); }
  catch (error) {
    if (error instanceof HcsJsonV1Error) {
      return fail(error.code === "JSON_TOO_LARGE" ? "HCS13_SCHEMA_TOO_LARGE" : "HCS13_SCHEMA_JSON_INVALID");
    }
    throw error;
  }
  return finalize(document);
}

/** Offline structure/digest check. A 'pass' without an expected checksum is not
 * an independent schema-publication or registry-validation claim.
 */
export function verifyHcs13SchemaV1(input: Readonly<{
  reference: unknown;
  schema: Uint8Array | string;
  expected_sha256?: string | null;
  expected_registry_topic_id?: string | null;
  expected_sequence_number?: number | null;
}>): Hcs13SchemaVerificationV1 {
  let reference: Hcs13ReferenceV1 | null = null;
  let sha256: string | null = null;
  let checksumMatch: Hcs13SchemaVerificationV1["checksum_match"] = "not_checked";
  const result = (status: Hcs13SchemaVerificationV1["status"], reason: string | null): Hcs13SchemaVerificationV1 =>
    Object.freeze({ status, reason_code: reason, reference, sha256, checksum_match: checksumMatch });
  try {
    if (!input || typeof input !== "object") return fail("HCS13_INPUT_INVALID");
    reference = parseHcs13ReferenceV1(input.reference);
    if (input.expected_registry_topic_id != null && topicId(input.expected_registry_topic_id) !== reference.registry_topic_id) {
      return fail("HCS13_REGISTRY_MISMATCH");
    }
    if (input.expected_sequence_number != null && sequence(input.expected_sequence_number) !== reference.sequence_number) {
      return fail("HCS13_SEQUENCE_MISMATCH");
    }
    const document = parseHcs13SchemaV1(input.schema);
    sha256 = document.sha256;
    if (input.expected_sha256 != null) {
      if (typeof input.expected_sha256 !== "string" || !SHA256.test(input.expected_sha256)) {
        return fail("HCS13_EXPECTED_CHECKSUM_INVALID");
      }
      checksumMatch = input.expected_sha256 === sha256 ? "match" : "mismatch";
      if (checksumMatch === "mismatch") return fail("HCS13_CHECKSUM_MISMATCH");
    }
    return result("pass", null);
  } catch (error) {
    if (error instanceof Hcs13V1Error) return result("fail", error.code);
    throw error;
  }
}
