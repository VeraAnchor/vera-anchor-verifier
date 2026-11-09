/** Pinned HCS-26 Draft v1.1: offline discovery/version/skill checks.
 * Only supported registry operations and content supplied to this module are
 * inspected. No Hedera lookup, ownership, execution, or current-state claim.
 */
import { createHash } from "node:crypto";
import { parseHcs1ReferenceV1 } from "./hcs1V1.js";
import { canonicalHcsJsonV1, cloneHcsJsonV1, HcsJsonV1Error, parseStrictHcsJsonV1 } from "./jsonCanonicalV1.js";

export const MAX_HCS26_V1_MANIFEST_BYTES = 256 * 1024;
const RAW_MANIFEST_BYTES = MAX_HCS26_V1_MANIFEST_BYTES + 64 * 1024;
const TOPIC = /^0\.0\.[0-9]+$/;
const SHA256 = /^[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const KEYS_DISCOVERY = new Set(["p", "op", "t_id", "account_id", "metadata", "m"]);
const KEYS_UPDATE = new Set(["p", "op", "uid", "account_id", "metadata", "m"]);
const KEYS_VERSION = new Set(["p", "op", "skill_uid", "version", "t_id", "checksum", "status", "m"]);
const KEYS_METADATA = new Set(["name", "description", "author", "license", "tags", "languages", "capabilities", "homepage", "icon", "repo", "commit"]);
const KEYS_MANIFEST = new Set(["name", "description", "version", "license", "author", "tags", "languages", "homepage", "repo", "commit", "entrypoints", "files"]);
const KEYS_FILE = new Set(["path", "hrl", "sha256", "mime"]);

export class Hcs26V1Error extends Error {
  constructor(readonly code: string) { super(code); this.name = "Hcs26V1Error"; }
}
function fail(code: string): never { throw new Hcs26V1Error(code); }
function object(value: unknown, code = "HCS26_FIELD_INVALID"): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      ![null, Object.prototype].includes(Object.getPrototypeOf(value))) return fail(code);
  return value as Record<string, unknown>;
}
function keys(value: Record<string, unknown>, allowed: Set<string>): void {
  for (const key of Object.keys(value)) if (!allowed.has(key)) return fail("HCS26_FIELD_UNSUPPORTED");
}
function text(value: unknown, max: number): string {
  if (typeof value !== "string") return fail("HCS26_FIELD_INVALID");
  const out = value.trim();
  if (!out || out.length > max || /[\u0000-\u001f\u007f]/.test(out)) return fail("HCS26_FIELD_INVALID");
  return out;
}
function optional(value: unknown, max: number): string | null {
  return value == null || value === "" || (typeof value === "string" && !value.trim()) ? null : text(value, max);
}
function topic(value: unknown): string {
  const out = text(value, 64);
  if (!TOPIC.test(out)) return fail("HCS26_TOPIC_INVALID");
  return out;
}
function version(value: unknown): string {
  const out = text(value, 64);
  if (!SEMVER.test(out)) return fail("HCS26_VERSION_INVALID");
  return out;
}
function sha(value: unknown): string {
  if (typeof value !== "string") return fail("HCS26_CHECKSUM_INVALID");
  const raw = value.startsWith("sha256:") ? value.slice(7) : value;
  if (!SHA256.test(raw)) return fail("HCS26_CHECKSUM_INVALID");
  return raw;
}
function positive(value: unknown): number {
  const n = Number(value);
  if (value == null || value === "" || !Number.isSafeInteger(n) || n < 1) return fail("HCS26_SKILL_UID_INVALID");
  return n;
}
function uid(value: unknown): string {
  const out = text(value, 256);
  if (!/^[1-9]\d*$/.test(out) || !Number.isSafeInteger(Number(out))) return fail("HCS26_SKILL_UID_INVALID");
  return out;
}
function hcs1ref(value: unknown): string {
  try { return parseHcs1ReferenceV1(text(value, 256)).reference; }
  catch { return fail("HCS1_REF_INVALID"); }
}
function authors(value: unknown): unknown {
  if (typeof value === "string") return text(value, 512);
  const author = object(value);
  keys(author, new Set(["name", "contact", "url"]));
  return {
    name: text(author.name, 256),
    ...(optional(author.contact, 512) == null ? {} : { contact: optional(author.contact, 512)! }),
    ...(optional(author.url, 2048) == null ? {} : { url: optional(author.url, 2048)! }),
  };
}
function ints(value: unknown): number[] {
  if (!Array.isArray(value)) return fail("HCS26_FIELD_INVALID");
  const result = value.map(Number);
  if (result.some((n) => !Number.isSafeInteger(n) || n < 0)) return fail("HCS26_FIELD_INVALID");
  return [...new Set(result)].sort((a, b) => a - b);
}
function strings(value: unknown): string[] {
  if (!Array.isArray(value)) return fail("HCS26_FIELD_INVALID");
  return value.map((v) => text(v, 256));
}
function metadata(value: unknown, update = false): unknown {
  if (typeof value === "string") return hcs1ref(value);
  const obj = object(value);
  keys(obj, KEYS_METADATA);
  if (update && Object.keys(obj).length === 0) return fail("HCS26_FIELD_INVALID");
  const out: Record<string, unknown> = {};
  for (const [key, limit] of [["name", 256], ["description", 4096], ["license", 128]] as const) {
    if (!update || Object.hasOwn(obj, key)) out[key] = text(obj[key], limit);
  }
  if (!update || Object.hasOwn(obj, "author")) out.author = authors(obj.author);
  for (const key of ["tags", "languages", "capabilities"] as const) {
    if (!Object.hasOwn(obj, key)) continue;
    const val = obj[key];
    if (val == null && !update) continue;
    out[key] = val == null ? [] : key === "tags" ? ints(val) : strings(val);
  }
  for (const [key, limit] of [["homepage", 2048], ["icon", 4096], ["repo", 4096]] as const) {
    if (!Object.hasOwn(obj, key)) continue;
    const val = update ? text(obj[key], limit) : optional(obj[key], limit);
    if (val != null) out[key] = val;
  }
  if (Object.hasOwn(obj, "commit")) {
    const value = text(obj.commit, 40);
    if (!COMMIT.test(value)) return fail("HCS26_COMMIT_INVALID");
    out.commit = value;
  }
  return out;
}
function parseWire(value: string | Uint8Array): Record<string, unknown> {
  let parsed: unknown;
  try { parsed = parseStrictHcsJsonV1(value, 1024); }
  catch (error) {
    if (error instanceof HcsJsonV1Error && error.code === "JSON_TOO_LARGE") return fail("HCS26_MESSAGE_TOO_LARGE");
    return fail("HCS26_MESSAGE_INVALID");
  }
  return object(parsed, "HCS26_MESSAGE_INVALID");
}
function wireSize(value: unknown): void {
  if (Buffer.byteLength(JSON.stringify(value), "utf8") > 1024) return fail("HCS26_MESSAGE_TOO_LARGE");
}
function memoText(value: unknown): Record<string, unknown> { return optional(value, 500) == null ? {} : { m: optional(value, 500)! }; }

export type Hcs26MemoV1 = Readonly<{ memo: string; indexed: boolean; ttl: number; type: "discovery" | "version"; type_code: 0 | 1 }>;
export function parseHcs26MemoV1(value: unknown): Hcs26MemoV1 {
  const match = typeof value === "string" ? /^hcs-26:(0|1):(\d+):(0|1)$/.exec(value.trim()) : null;
  if (!match) return fail("HCS26_MEMO_INVALID");
  const ttl = Number(match[2]);
  if (!Number.isSafeInteger(ttl) || ttl > 31_536_000) return fail("HCS26_TTL_INVALID");
  const type_code = Number(match[3]) as 0 | 1;
  return Object.freeze({ memo: (value as string).trim(), indexed: match[1] === "0", ttl,
    type: type_code === 0 ? "discovery" : "version", type_code });
}

/** Supplied historical raw registry message; not a read of current registry state. */
export function parseHcs26DiscoveryRegisterV1(raw: string | Uint8Array): Readonly<Record<string, unknown>> {
  const obj = parseWire(raw);
  if (obj.p !== "hcs-26" || obj.op !== "register" || obj.skill_uid != null || obj.version != null) return fail("HCS26_OPERATION_INVALID");
  keys(obj, KEYS_DISCOVERY);
  const record = { p: "hcs-26", op: "register", t_id: topic(obj.t_id), account_id: topic(obj.account_id),
    metadata: metadata(obj.metadata), ...memoText(obj.m) };
  wireSize(record);
  return Object.freeze(record);
}
export function parseHcs26DiscoveryUpdateV1(raw: string | Uint8Array): Readonly<Record<string, unknown>> {
  const obj = parseWire(raw);
  if (obj.p !== "hcs-26" || obj.op !== "update" || obj.uid == null) return fail("HCS26_OPERATION_INVALID");
  keys(obj, KEYS_UPDATE);
  if (obj.account_id == null && obj.metadata == null) return fail("HCS26_UPDATE_EMPTY");
  const record = { p: "hcs-26", op: "update", uid: uid(obj.uid),
    ...(obj.account_id == null ? {} : { account_id: topic(obj.account_id) }),
    ...(obj.metadata == null ? {} : { metadata: metadata(obj.metadata, true) }), ...memoText(obj.m) };
  wireSize(record);
  return Object.freeze(record);
}
export type Hcs26VersionRegisterV1 = Readonly<{
  p: "hcs-26"; op: "register"; skill_uid: number; version: string;
  t_id: string; checksum: string; status: "active" | "deprecated" | "yanked"; m?: string;
}>;
export function parseHcs26VersionRegisterV1(raw: string | Uint8Array): Hcs26VersionRegisterV1 {
  const obj = parseWire(raw);
  if (obj.p !== "hcs-26" || obj.op !== "register" || obj.skill_uid == null || obj.version == null) return fail("HCS26_OPERATION_INVALID");
  keys(obj, KEYS_VERSION);
  const status = obj.status == null ? "active" : text(obj.status, 40).toLowerCase();
  if (status !== "active" && status !== "deprecated" && status !== "yanked") return fail("HCS26_STATUS_INVALID");
  const record: Hcs26VersionRegisterV1 = { p: "hcs-26", op: "register", skill_uid: positive(obj.skill_uid),
    version: version(obj.version), t_id: topic(obj.t_id), checksum: `sha256:${sha(obj.checksum)}`,
    status, ...memoText(obj.m) };
  wireSize(record);
  return Object.freeze(record);
}

function filePath(value: unknown): string {
  const path = text(value, 512).replace(/\\/g, "/");
  const parts = path.split("/");
  if (path.startsWith("/") || /^[A-Za-z]:/.test(path) || parts.some((p) => !p || p === "." || p === "..")) {
    return fail("HCS26_PATH_INVALID");
  }
  return path;
}
function manifestFile(value: unknown): Readonly<Record<string, string>> {
  const obj = object(value);
  keys(obj, KEYS_FILE);
  const path = filePath(obj.path);
  const digest = text(obj.sha256, 64).toLowerCase();
  if (!SHA256.test(digest)) return fail("HCS26_FILE_HASH_INVALID");
  return { path, hrl: hcs1ref(obj.hrl), sha256: digest, mime: text(obj.mime, 256) };
}
export type Hcs26SkillManifestV1 = Readonly<{
  manifest: Readonly<Record<string, unknown>>; canonical_payload: string; sha256: string; byte_length: number;
}>;
export function finalizeHcs26SkillManifestV1(value: unknown): Hcs26SkillManifestV1 {
  const obj = object(value);
  keys(obj, KEYS_MANIFEST);
  if (!Array.isArray(obj.files) || obj.files.length < 1 || obj.files.length > 256) return fail("HCS26_FILES_INVALID");
  const files = obj.files.map(manifestFile);
  const paths = new Set<string>();
  for (const file of files) {
    if (paths.has(file.path!)) return fail("HCS26_PATH_DUPLICATE");
    paths.add(file.path!);
  }
  if (!paths.has("SKILL.md")) return fail("HCS26_SKILL_MD_REQUIRED");
  files.sort((a, b) => Buffer.compare(Buffer.from(a.path!), Buffer.from(b.path!)));
  const normalized: Record<string, unknown> = {
    name: text(obj.name, 256), description: text(obj.description, 4096),
    version: version(obj.version), license: text(obj.license, 128), author: authors(obj.author),
  };
  if (obj.tags != null) normalized.tags = ints(obj.tags);
  if (obj.languages != null) normalized.languages = strings(obj.languages);
  for (const [key, limit] of [["homepage", 2048], ["repo", 4096]] as const) {
    const val = optional(obj[key], limit);
    if (val != null) normalized[key] = val;
  }
  if (obj.commit != null) {
    const commit = text(obj.commit, 40);
    if (!COMMIT.test(commit)) return fail("HCS26_COMMIT_INVALID");
    normalized.commit = commit;
  }
  if (obj.entrypoints != null) {
    if (!Array.isArray(obj.entrypoints)) return fail("HCS26_FIELD_INVALID");
    normalized.entrypoints = obj.entrypoints;
  }
  normalized.files = files;
  let canonical: string;
  try { canonical = canonicalHcsJsonV1(normalized, MAX_HCS26_V1_MANIFEST_BYTES); }
  catch (error) {
    if (error instanceof HcsJsonV1Error) {
      return fail(error.code === "JSON_TOO_LARGE" ? "HCS26_MANIFEST_TOO_LARGE" : "HCS26_CANONICALIZATION_FAILED");
    }
    throw error;
  }
  const bytes = Buffer.from(canonical, "utf8");
  return Object.freeze({ manifest: cloneHcsJsonV1(normalized), canonical_payload: canonical,
    sha256: createHash("sha256").update(bytes).digest("hex"), byte_length: bytes.byteLength });
}
export function parseHcs26SkillManifestV1(raw: Uint8Array | string): Hcs26SkillManifestV1 {
  let parsed: unknown;
  try { parsed = parseStrictHcsJsonV1(raw, RAW_MANIFEST_BYTES); }
  catch (error) {
    if (error instanceof HcsJsonV1Error) {
      return fail(error.code === "JSON_TOO_LARGE" ? "HCS26_MANIFEST_TOO_LARGE" : "HCS26_MANIFEST_JSON_INVALID");
    }
    throw error;
  }
  return finalizeHcs26SkillManifestV1(parsed);
}

export type Hcs26VersionVerificationV1 = Readonly<{
  status: "pass" | "fail";
  reason_code: string | null;
  skill_uid: number | null;
  version: string | null;
  manifest_topic_id: string | null;
  checksum_match: "match" | "mismatch" | "not_checked";
  /** Version state is recorded as historical register state, not current policy. */
  version_status: Hcs26VersionRegisterV1["status"] | null;
  sha256: string | null;
}>;
/** Cross-check a supplied historical version register against actual SKILL.json
 * canonical content. This does not authenticate where the register came from.
 */
export function verifyHcs26SkillVersionV1(input: Readonly<{
  version_register: string | Uint8Array;
  manifest: string | Uint8Array;
  expected_skill_uid?: number | null;
  expected_version?: string | null;
  expected_manifest_topic_id?: string | null;
  expected_sha256?: string | null;
}>): Hcs26VersionVerificationV1 {
  let register: Hcs26VersionRegisterV1 | null = null;
  let sha256: string | null = null;
  let checksumMatch: Hcs26VersionVerificationV1["checksum_match"] = "not_checked";
  const result = (status: Hcs26VersionVerificationV1["status"], reason: string | null): Hcs26VersionVerificationV1 =>
    Object.freeze({ status, reason_code: reason, skill_uid: register?.skill_uid ?? null,
      version: register?.version ?? null, manifest_topic_id: register?.t_id ?? null,
      version_status: register?.status ?? null, checksum_match: checksumMatch, sha256 });
  try {
    if (!input || typeof input !== "object") return fail("HCS26_INPUT_INVALID");
    register = parseHcs26VersionRegisterV1(input.version_register);
    if (input.expected_skill_uid != null && positive(input.expected_skill_uid) !== register.skill_uid) return fail("HCS26_SKILL_UID_MISMATCH");
    if (input.expected_version != null && version(input.expected_version) !== register.version) return fail("HCS26_VERSION_MISMATCH");
    if (input.expected_manifest_topic_id != null && topic(input.expected_manifest_topic_id) !== register.t_id) return fail("HCS26_TOPIC_MISMATCH");
    const manifest = parseHcs26SkillManifestV1(input.manifest);
    sha256 = manifest.sha256;
    checksumMatch = sha256 === register.checksum.slice(7) ? "match" : "mismatch";
    if (checksumMatch === "mismatch") return fail("HCS26_CHECKSUM_MISMATCH");
    if (manifest.manifest.version !== register.version) return fail("HCS26_VERSION_MISMATCH");
    if (input.expected_sha256 != null && sha(input.expected_sha256) !== sha256) return fail("HCS26_EXPECTED_CHECKSUM_MISMATCH");
    return result("pass", null);
  } catch (error) {
    if (error instanceof Hcs26V1Error) return result("fail", error.code);
    throw error;
  }
}
