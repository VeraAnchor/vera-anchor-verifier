import type { ExpectedCommitment, VerificationOutcome } from "../contracts/verification.js";
import { normalizeSha3_512Digest, sha3_512Hex } from "../crypto/sha3.js";

/** HF v1 hashing is distinct from Core's unframed canonical-object hashes. */
export const HF_V1_CONTRACT_ID = "hf-contract-v1" as const;
export const HF_V1_FRAME_ID = "hf:frame:v1" as const;
export const HF_V1_CANONICAL_JSON_ID = "hf:canonical-json:v1" as const;

// SDK-specific resource ceilings; these are not claims about a producer's limits.
export const MAX_HF_V1_PAYLOAD_BYTES = 16 * 1024 * 1024;
const MAX_JSON_DEPTH = 64;
const MAX_JSON_KEYS = 200_000;
const MAX_JSON_ARRAY_LENGTH = 200_000;
const DOMAIN_RE = /^[a-z0-9][a-z0-9._:/-]{0,63}$/;
const FRAME_MAGIC = Buffer.from(HF_V1_FRAME_ID, "utf8");

type JsonMaterial = Readonly<{ material: "json"; value: unknown }>;
type RawMaterial = Readonly<{ material: "raw"; bytes: Uint8Array }>;
type Utf8Material = Readonly<{ material: "utf8"; text: string }>;
export type HfV1Material = JsonMaterial | RawMaterial | Utf8Material;
export type HfV1HashInput = HfV1Material & Readonly<{ domain: string }>;
export type HfV1ExpectedCommitment = Extract<
  ExpectedCommitment,
  { contract: "hf-contract-v1" }
>;
export type HfV1DigestVerificationResult = Readonly<{
  outcome: Extract<VerificationOutcome, "pass" | "fail">;
  reason_code: string | null;
  contract: typeof HF_V1_CONTRACT_ID;
  material: HfV1Material["material"];
  domain: string;
  expected_digest: string;
  computed_digest: string | null;
}>;

function chargeBudget(budget: { used: number }, bytes: number): void {
  budget.used += bytes;
  if (budget.used > MAX_HF_V1_PAYLOAD_BYTES) {
    throw new RangeError("HF v1 canonical JSON exceeds SDK byte limit");
  }
}

function quoted(value: string): string {
  return JSON.stringify(value);
}

function plainObject(value: object): boolean {
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/** Strict HF canonical-json:v1 bytes; UTF-16 key ordering, no lossy sentinels. */
export function canonicalizeHfV1Json(value: unknown): Uint8Array {
  const seen = new WeakSet<object>();
  const budget = { used: 0 };
  let keys = 0;

  function walk(node: unknown, depth: number): string {
    if (depth > MAX_JSON_DEPTH) throw new TypeError("HF v1 JSON nesting limit exceeded");

    if (node === null) {
      chargeBudget(budget, 4);
      return "null";
    }
    if (typeof node === "string") {
      const result = quoted(node);
      chargeBudget(budget, Buffer.byteLength(result, "utf8"));
      return result;
    }
    if (typeof node === "boolean") {
      chargeBudget(budget, node ? 4 : 5);
      return node ? "true" : "false";
    }
    if (typeof node === "number") {
      if (!Number.isFinite(node)) throw new TypeError("HF v1 JSON numbers must be finite");
      const result = JSON.stringify(node);
      chargeBudget(budget, result.length);
      return result;
    }
    if (typeof node === "bigint") {
      const result = quoted(node.toString(10));
      chargeBudget(budget, Buffer.byteLength(result, "utf8"));
      return result;
    }
    if (typeof node !== "object") {
      throw new TypeError(`HF v1 JSON unsupported type: ${typeof node}`);
    }
    if (node instanceof Uint8Array || !Array.isArray(node) && !plainObject(node)) {
      throw new TypeError("HF v1 JSON accepts only plain objects, arrays and scalar values");
    }
    if (seen.has(node)) throw new TypeError("HF v1 JSON repeated or circular object reference");
    seen.add(node);

    if (Array.isArray(node)) {
      if (node.length > MAX_JSON_ARRAY_LENGTH) {
        throw new RangeError("HF v1 JSON array exceeds SDK limit");
      }
      chargeBudget(budget, node.length ? node.length + 1 : 2);
      const parts: string[] = [];
      for (let i = 0; i < node.length; i++) parts.push(walk(node[i], depth + 1));
      return `[${parts.join(",")}]`;
    }

    const object = node as Record<string, unknown>;
    const sorted = Object.keys(object).sort();
    keys += sorted.length;
    if (keys > MAX_JSON_KEYS) throw new RangeError("HF v1 JSON key count exceeds SDK limit");
    chargeBudget(budget, sorted.length ? sorted.length + 1 : 2);
    const entries: string[] = [];
    for (const key of sorted) {
      const field = quoted(key);
      chargeBudget(budget, Buffer.byteLength(field, "utf8") + 1);
      entries.push(`${field}:${walk(object[key], depth + 1)}`);
    }
    return `{${entries.join(",")}}`;
  }

  return Buffer.from(walk(value, 0), "utf8");
}

export function normalizeHfV1Domain(domain: string): string {
  if (typeof domain !== "string") throw new TypeError("HF v1 domain must be a string");
  const normalized = domain.trim();
  if (!DOMAIN_RE.test(normalized)) throw new TypeError("Invalid HF v1 domain");
  return normalized;
}

/** frame = 'hf:frame:v1' || 0x00 || u16be(domain length) || domain || u32be(payload length) || payload. */
export function frameHfV1(domain: string, payload: Uint8Array): Uint8Array {
  const normalized = normalizeHfV1Domain(domain);
  if (!(payload instanceof Uint8Array)) throw new TypeError("HF v1 payload must be bytes");
  if (payload.byteLength > MAX_HF_V1_PAYLOAD_BYTES) {
    throw new RangeError("HF v1 payload exceeds SDK byte limit");
  }
  const domainBytes = Buffer.from(normalized, "utf8");
  const header = Buffer.alloc(FRAME_MAGIC.length + 1 + 2 + domainBytes.length + 4);
  let offset = 0;
  FRAME_MAGIC.copy(header, offset);
  offset += FRAME_MAGIC.length;
  header[offset++] = 0;
  header.writeUInt16BE(domainBytes.length, offset);
  offset += 2;
  domainBytes.copy(header, offset);
  offset += domainBytes.length;
  header.writeUInt32BE(payload.byteLength, offset);
  return Buffer.concat([header, Buffer.from(payload)]);
}

function payloadBytes(material: HfV1Material): Uint8Array {
  switch (material.material) {
    case "json":
      return canonicalizeHfV1Json(material.value);
    case "utf8": {
      if (typeof material.text !== "string") {
        throw new TypeError("HF v1 UTF-8 material must be a string");
      }
      const bytes = Buffer.from(material.text, "utf8");
      if (bytes.byteLength > MAX_HF_V1_PAYLOAD_BYTES) {
        throw new RangeError("HF v1 text exceeds SDK byte limit");
      }
      return bytes;
    }
    case "raw":
      if (!(material.bytes instanceof Uint8Array)) {
        throw new TypeError("HF v1 raw material must be bytes");
      }
      return material.bytes;
    default:
      throw new TypeError("Unsupported HF v1 material kind");
  }
}

/** SHA3-512 over exact HF v1 framed bytes; returns lowercase hex. */
export function hashHfV1(input: HfV1HashInput): string {
  const framed = frameHfV1(input.domain, payloadBytes(input));
  return sha3_512Hex(framed);
}

/** Caller expectation selects both framing domain and material encoding. */
export function verifyHfV1Digest(input: Readonly<{
  expected: HfV1ExpectedCommitment;
  evidence: HfV1Material;
}>): HfV1DigestVerificationResult {
  if (!input?.expected || input.expected.kind !== "digest" || input.expected.contract !== HF_V1_CONTRACT_ID) {
    throw new TypeError("Expected an hf-contract-v1 digest commitment");
  }
  const expected = normalizeSha3_512Digest(input.expected.digest);
  const domain = normalizeHfV1Domain(input.expected.domain);
  const material = input.expected.material;
  if (material !== "json" && material !== "raw" && material !== "utf8") {
    throw new TypeError("Unsupported HF v1 material kind");
  }
  if (!input.evidence || input.evidence.material !== material) {
    return Object.freeze({
      outcome: "fail",
      reason_code: "HF_MATERIAL_MISMATCH",
      contract: HF_V1_CONTRACT_ID,
      material,
      domain,
      expected_digest: expected,
      computed_digest: null,
    });
  }
  const computed = hashHfV1({ ...input.evidence, domain });
  const match = expected === computed;
  return Object.freeze({
    outcome: match ? "pass" : "fail",
    reason_code: match ? null : "DIGEST_MISMATCH",
    contract: HF_V1_CONTRACT_ID,
    material,
    domain,
    expected_digest: expected,
    computed_digest: computed,
  });
}
