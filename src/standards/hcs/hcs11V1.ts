/** Pinned HCS-11 Draft 1.1 AI-agent profile (type 1), offline only.
 *  Does not authenticate Hedera account memo, DID control, or publication.
 */
import { createHash } from "node:crypto";
import { parseHcs14DidUaidV1, verifyHcs14DidBindingV1, Hcs14V1Error } from "./hcs14V1.js";

export const MAX_HCS11_V1_PROFILE_BYTES = 128 * 1024;
const REF = /^hcs:\/\/(1|2)\/(0\.0\.[0-9]+)$/;
const TOP_KEYS = new Set(["version", "type", "display_name", "uaid", "alias", "bio", "profileImage", "properties", "aiAgent"]);
const AGENT_KEYS = new Set(["type", "capabilities", "model", "creator"]);

export type Hcs11V1Memo = Readonly<{
  memo: string;
  profile_reference: string;
  protocol: "hcs-1" | "hcs-2";
  topic_id: string;
}>;
export type Hcs11V1Profile = Readonly<{
  version: string;
  type: 1;
  display_name: string;
  uaid: string;
  alias?: string;
  bio?: string;
  profileImage?: string;
  properties?: Readonly<Record<string, unknown>>;
  aiAgent: Readonly<{ type: 0 | 1; capabilities: readonly number[]; model: string; creator?: string }>;
}>;
export type Hcs11V1Input = Readonly<{
  /** Original HCS-11 JSON bytes/string; offline content is caller-supplied. */
  profile: Uint8Array | string;
  /** Independently supplied expectations, not copied from the profile. */
  expected_sha256?: string | null;
  expected_uaid?: string | null;
  expected_base_did?: string | null;
  account_memo?: string | null;
  expected_profile_reference?: string | null;
}>;
export type Hcs11V1Result = Readonly<{
  status: "pass" | "fail" | "unsupported";
  reason_code: string | null;
  profile: Hcs11V1Profile | null;
  sha256: string | null;
  account_memo: Hcs11V1Memo | null;
  /** No account-to-memo authenticity is implied. */
  memo_reference_match: "match" | "mismatch" | "not_checked";
}>;
export class Hcs11V1Error extends Error {
  constructor(readonly code: string) { super(code); this.name = "Hcs11V1Error"; }
}
function fail(code: string): never { throw new Hcs11V1Error(code); }
function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return fail("HCS11_FIELD_INVALID");
  const proto = Object.getPrototypeOf(value);
  if (proto !== null && proto !== Object.prototype) return fail("HCS11_FIELD_INVALID");
  return value as Record<string, unknown>;
}
function keysOnly(value: Record<string, unknown>, allowed: Set<string>): void {
  for (const key of Object.keys(value)) if (!allowed.has(key)) fail("HCS11_FIELD_UNSUPPORTED");
}
function requiredText(value: unknown, max: number): string {
  if (typeof value !== "string") return fail("HCS11_FIELD_INVALID");
  const out = value.trim();
  if (!out || out.length > max || /[\u0000-\u001f\u007f]/.test(out)) return fail("HCS11_FIELD_INVALID");
  return out;
}
function optionalText(value: unknown, max: number): string | null {
  if (value == null || value === "") return null;
  if (typeof value === "string" && !value.trim()) return null;
  return requiredText(value, max);
}

export function parseHcs11AccountMemoV1(value: unknown): Hcs11V1Memo {
  if (typeof value !== "string") return fail("HCS11_MEMO_INVALID");
  if (value.length > 4096) return fail("HCS11_MEMO_TOO_LARGE");
  const memo = value.trim();
  if (!memo.startsWith("hcs-11:")) return fail("HCS11_MEMO_INVALID");
  if (Buffer.byteLength(memo, "utf8") > 100) return fail("HCS11_MEMO_TOO_LARGE");
  const reference = memo.slice(7);
  const match = REF.exec(reference);
  if (!match) return fail("HCS11_PROFILE_REF_INVALID");
  return Object.freeze({ memo, profile_reference: reference,
    protocol: `hcs-${match[1]}` as "hcs-1" | "hcs-2", topic_id: match[2]! });
}

/** Reject ambiguous JSON duplicate keys, including nested and escaped key aliases. */
function assertUniqueJsonKeys(source: string): void {
  let i = 0;
  const space = () => { while (i < source.length && /\s/.test(source[i]!)) i++; };
  const jsonString = (): string => {
    const start = i++;
    while (i < source.length) {
      if (source[i] === "\\") { i += 2; continue; }
      if (source[i++] === '"') return JSON.parse(source.slice(start, i)) as string;
    }
    return fail("HCS11_PROFILE_JSON_INVALID");
  };
  const visit = (depth: number): void => {
    if (depth > 32) return fail("HCS11_PROFILE_TOO_LARGE");
    space();
    if (source[i] === '{') {
      i++;
      space();
      const keys = new Set<string>();
      while (source[i] !== '}') {
        const key = jsonString();
        if (keys.has(key)) return fail("HCS11_PROFILE_JSON_INVALID");
        keys.add(key);
        space(); i++; space(); // validated colon (JSON.parse called first)
        visit(depth + 1);
        space();
        if (source[i] !== ',') break;
        i++; space();
      }
      i++;
    } else if (source[i] === '[') {
      i++; space();
      while (source[i] !== ']') {
        visit(depth + 1);
        space();
        if (source[i] !== ',') break;
        i++; space();
      }
      i++;
    } else if (source[i] === '"') {
      jsonString();
    } else {
      while (i < source.length && !/[\s,\]}]/.test(source[i]!)) i++;
    }
  };
  visit(0);
}

function freezeJson<T>(value: T, depth = 0): T {
  if (depth > 32) return fail("HCS11_PROFILE_TOO_LARGE");
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freezeJson(child, depth + 1);
    Object.freeze(value);
  }
  return value;
}

export function parseHcs11AiAgentProfileV1(value: Uint8Array | string): Hcs11V1Profile {
  let bytes: Uint8Array;
  if (typeof value === "string") {
    if (value.length > MAX_HCS11_V1_PROFILE_BYTES) return fail("HCS11_PROFILE_TOO_LARGE");
    bytes = Buffer.from(value, "utf8");
  }
  else if (value instanceof Uint8Array) bytes = value;
  else return fail("HCS11_PROFILE_JSON_INVALID");
  if (!bytes.byteLength || bytes.byteLength > MAX_HCS11_V1_PROFILE_BYTES) {
    return fail(bytes.byteLength ? "HCS11_PROFILE_TOO_LARGE" : "HCS11_PROFILE_JSON_INVALID");
  }
  let obj: Record<string, unknown>;
  try {
    const source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    obj = record(JSON.parse(source));
    assertUniqueJsonKeys(source);
  }
  catch (e) { if (e instanceof Hcs11V1Error) throw e; return fail("HCS11_PROFILE_JSON_INVALID"); }
  keysOnly(obj, TOP_KEYS);
  if (obj.type !== 1) return fail("HCS11_PROFILE_TYPE_UNSUPPORTED");
  const uaid = requiredText(obj.uaid, 4096);
  parseHcs14DidUaidV1(uaid);
  const agent = record(obj.aiAgent);
  keysOnly(agent, AGENT_KEYS);
  if (agent.type !== 0 && agent.type !== 1) return fail("HCS11_AGENT_TYPE_INVALID");
  if (!Array.isArray(agent.capabilities)) return fail("HCS11_CAPABILITIES_INVALID");
  const numeric = agent.capabilities.map((n: unknown) => Number(n));
  if (numeric.some((n) => !Number.isSafeInteger(n) || n < 0) || new Set(numeric).size !== numeric.length) {
    return fail("HCS11_CAPABILITIES_INVALID");
  }
  const alias = optionalText(obj.alias, 256);
  const bio = optionalText(obj.bio, 4096);
  const profileImage = optionalText(obj.profileImage, 4096);
  const creator = optionalText(agent.creator, 256);
  let properties: Readonly<Record<string, unknown>> | undefined;
  if (obj.properties != null) properties = record(obj.properties);
  // Material is reconstructed from validated typed fields, not mutated in place.
  const normalized: Hcs11V1Profile = {
    version: requiredText(obj.version ?? "1.1", 32), type: 1,
    display_name: requiredText(obj.display_name, 128), uaid,
    ...(alias == null ? {} : { alias }),
    ...(bio == null ? {} : { bio }),
    ...(profileImage == null ? {} : { profileImage }),
    ...(properties === undefined ? {} : { properties }),
    aiAgent: {
      type: agent.type,
      capabilities: Object.freeze(numeric.sort((a, b) => a - b)),
      model: requiredText(agent.model, 256),
      ...(creator == null ? {} : { creator }),
    },
  };
  return freezeJson(normalized);
}

/** A strict canonical JSON subset for the pinned profile contract; rejects non-I-JSON material. */
function canonical(value: unknown, depth = 0, seen = new Set<object>()): string {
  if (depth > 32) return fail("HCS11_CANONICALIZATION_FAILED");
  if (value === null) return "null";
  if (typeof value === "string") {
    if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)) {
      return fail("HCS11_CANONICALIZATION_FAILED");
    }
    return JSON.stringify(value);
  }
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (!value || typeof value !== "object") return fail("HCS11_CANONICALIZATION_FAILED");
  if (seen.has(value)) return fail("HCS11_CANONICALIZATION_FAILED");
  seen.add(value);
  if (Array.isArray(value)) {
    const out = `[${value.map((v) => canonical(v, depth + 1, seen)).join(",")}]`;
    seen.delete(value); return out;
  }
  const object = record(value);
  const fields = Object.keys(object).sort().map((key) => {
    const val = object[key];
    if (val === undefined) return fail("HCS11_CANONICALIZATION_FAILED");
    return `${canonical(key, depth + 1, seen)}:${canonical(val, depth + 1, seen)}`;
  });
  seen.delete(value);
  return `{${fields.join(",")}}`;
}

/** Offline parsing + digest recomputation over normalized pinned profile material. */
export function verifyHcs11AiAgentProfileV1(input: Hcs11V1Input): Hcs11V1Result {
  let profile: Hcs11V1Profile | null = null;
  let memo: Hcs11V1Memo | null = null;
  let sha256: string | null = null;
  let memoReferenceMatch: Hcs11V1Result["memo_reference_match"] = "not_checked";
  const output = (status: Hcs11V1Result["status"], reason: string | null): Hcs11V1Result =>
    Object.freeze({ status, reason_code: reason, profile, sha256, account_memo: memo,
      memo_reference_match: memoReferenceMatch });
  try {
    if (!input || typeof input !== "object" || Array.isArray(input)) return fail("HCS11_INPUT_INVALID");
    profile = parseHcs11AiAgentProfileV1(input.profile);
    if (profile.version !== "1.1") return output("unsupported", "HCS11_VERSION_UNSUPPORTED");
    const canonicalBytes = Buffer.from(canonical(profile), "utf8");
    if (canonicalBytes.byteLength > MAX_HCS11_V1_PROFILE_BYTES) return fail("HCS11_PROFILE_TOO_LARGE");
    sha256 = createHash("sha256").update(canonicalBytes).digest("hex");
    if (input.expected_sha256 != null) {
      if (typeof input.expected_sha256 !== "string" || !/^[0-9a-f]{64}$/.test(input.expected_sha256)) {
        return fail("HCS11_EXPECTED_CHECKSUM_INVALID");
      }
      if (sha256 !== input.expected_sha256) return fail("HCS11_CHECKSUM_MISMATCH");
    }
    if (input.expected_uaid != null && profile.uaid !== input.expected_uaid) return fail("HCS11_UAID_MISMATCH");
    if (input.expected_base_did != null) {
      const binding = verifyHcs14DidBindingV1({ uaid: profile.uaid, base_did: input.expected_base_did });
      if (binding.status !== "pass") return fail(binding.reason_code ?? "HCS14_DID_BINDING_MISMATCH");
    }
    if (input.account_memo != null) {
      memo = parseHcs11AccountMemoV1(input.account_memo);
      if (input.expected_profile_reference != null) {
        memoReferenceMatch = memo.profile_reference === input.expected_profile_reference ? "match" : "mismatch";
        if (memoReferenceMatch === "mismatch") return fail("HCS11_PROFILE_REFERENCE_MISMATCH");
      }
    } else if (input.expected_profile_reference != null) return fail("HCS11_ACCOUNT_MEMO_UNAVAILABLE");
    return output("pass", null);
  } catch (error) {
    if (error instanceof Hcs11V1Error || error instanceof Hcs14V1Error) return output("fail", error.code);
    throw error;
  }
}
