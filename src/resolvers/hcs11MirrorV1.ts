/**
 * Bounded public HCS-11 profile resolution. The observed account memo is current
 * Mirror state; an exact HCS-2 sequence is caller-selected historical evidence.
 * Neither observation authenticates Hedera consensus nor DID controller control.
 */
import type { HederaNetwork } from "../contracts/verification.js";
import type { HederaMirrorV1Config } from "./hederaMirrorV1.js";
import { resolveHcs1FileV1, type Hcs1MirrorV1Config } from "./hcs1MirrorV1.js";
import { resolveHcs2RegisterV1 } from "./hcs2MirrorV1.js";
import { parseHcs11AccountMemoV1, verifyHcs11AiAgentProfileV1,
  type Hcs11V1Memo, type Hcs11V1Profile } from "../standards/hcs/hcs11V1.js";
import { parseHcs1ReferenceV1, type Hcs1V1ContentOptions } from "../standards/hcs/hcs1V1.js";
import { parseHcs14DidUaidV1 } from "../standards/hcs/hcs14V1.js";

const BASE: Readonly<Record<HederaNetwork, string>> = Object.freeze({
  mainnet: "https://mainnet-public.mirrornode.hedera.com/api/v1",
  testnet: "https://testnet.mirrornode.hedera.com/api/v1",
});
const ACCOUNT = /^0\.0\.[0-9]+$/;
const SHA256 = /^[0-9a-f]{64}$/;
const B64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const MAX_RESPONSE_BYTES = 256 * 1024;

export type Hcs11MirrorV1Request = Readonly<{
  hedera_network: HederaNetwork;
  account_id: string;
  /** Required for hcs://2 account memos. Never choose a mutable 'latest' record. */
  hcs2_sequence_number?: number;
  /** Explicit relying-party constraints, independent of fetched evidence. */
  expected_profile_reference?: string | null;
  expected_hcs1_reference?: string | null;
  expected_hcs1_sha256?: string | null;
  expected_profile_sha256?: string | null;
  expected_uaid?: string | null;
  expected_base_did?: string | null;
}>;

export type Hcs11MirrorV1Result = Readonly<{
  status: "resolved" | "conflict" | "invalid" | "unavailable" | "unsupported";
  reason_code: string | null;
  hedera_network: HederaNetwork;
  account_id: string;
  resolver_id: "hedera.mirror-rest.hcs11.v1";
  /** Always the observed current account memo, never asserted as historical. */
  account_memo_temporal_scope: "current_observation";
  account_memo: Hcs11V1Memo | null;
  /** Only populated after the exact caller-selected register is verified. */
  registry_entry: Readonly<{
    topic_id: string;
    sequence_number: number;
    consensus_timestamp: string;
  }> | null;
  profile_reference: string | null;
  /** SHA-256 of HCS-1 original bytes, authenticated only relative to Mirror topic memo. */
  content_sha256: string | null;
  /** SHA-256 of canonical normalized HCS-11 profile material. */
  canonical_profile_sha256: string | null;
  profile: Hcs11V1Profile | null;
  /** Caller-supplied DID binding is structural, not DID-controller authentication. */
  did_binding: "match" | "not_checked";
}>;

class AccountReadError extends Error {
  constructor(readonly code: string, readonly invalid = false) { super(code); }
}
function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new AccountReadError("HCS11_ACCOUNT_RESPONSE_INVALID", true);
  }
  return value as Record<string, unknown>;
}
function validatedBase(config: HederaMirrorV1Config, network: HederaNetwork): URL {
  let url: URL;
  try { url = new URL(config.base_urls?.[network] ?? BASE[network]); }
  catch { throw new TypeError("HCS11_MIRROR_BASE_URL_INVALID"); }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if ((url.protocol !== "https:" && !(loopback && url.protocol === "http:")) ||
      url.username || url.password || url.search || url.hash || !url.pathname.endsWith("/api/v1")) {
    throw new TypeError("HCS11_MIRROR_BASE_URL_INVALID");
  }
  return url;
}
function validatedLimits(config: HederaMirrorV1Config): { timeout: number; max: number } {
  const timeout = config.timeout_ms ?? 8000;
  const max = config.max_response_bytes ?? MAX_RESPONSE_BYTES;
  if (!Number.isSafeInteger(timeout) || timeout < 250 || timeout > 15000 ||
      !Number.isSafeInteger(max) || max < 1024 || max > MAX_RESPONSE_BYTES) {
    throw new TypeError("HCS11_MIRROR_BOUNDS_INVALID");
  }
  return { timeout, max };
}
async function readAccount(config: HederaMirrorV1Config, url: URL,
  bounds: { timeout: number; max: number }): Promise<Record<string, unknown> | null> {
  let response: Response;
  try {
    response = await (config.fetch_impl ?? fetch)(url.toString(), {
      method: "GET", headers: { Accept: "application/json" },
      redirect: "error", credentials: "omit", cache: "no-store",
      signal: AbortSignal.timeout(bounds.timeout),
    });
  } catch { throw new AccountReadError("HCS11_ACCOUNT_UNAVAILABLE"); }
  if (response.status === 404) return null;
  if (response.status === 429) throw new AccountReadError("HCS11_ACCOUNT_RATE_LIMITED");
  if (!response.ok) throw new AccountReadError("HCS11_ACCOUNT_UNAVAILABLE");
  const length = response.headers.get("content-length");
  if (length && (!Number.isFinite(Number(length)) || Number(length) > bounds.max)) {
    throw new AccountReadError("HCS11_ACCOUNT_RESPONSE_TOO_LARGE");
  }
  if (!response.body) throw new AccountReadError("HCS11_ACCOUNT_RESPONSE_INVALID", true);
  const reader = response.body.getReader();
  const parts: Uint8Array[] = [];
  let count = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      count += part.value.byteLength;
      if (count > bounds.max) {
        await reader.cancel().catch(() => undefined);
        throw new AccountReadError("HCS11_ACCOUNT_RESPONSE_TOO_LARGE");
      }
      parts.push(part.value);
    }
  } catch (error) {
    if (error instanceof AccountReadError) throw error;
    throw new AccountReadError("HCS11_ACCOUNT_UNAVAILABLE");
  } finally { reader.releaseLock(); }
  const combined = new Uint8Array(count);
  let at = 0;
  for (const part of parts) { combined.set(part, at); at += part.length; }
  try { return record(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(combined))); }
  catch (error) {
    if (error instanceof AccountReadError) throw error;
    throw new AccountReadError("HCS11_ACCOUNT_RESPONSE_INVALID", true);
  }
}
function decodeMemo(value: unknown): string {
  if (typeof value !== "string" || value.length > 1024) {
    throw new AccountReadError("HCS11_ACCOUNT_MEMO_INVALID", true);
  }
  if (!B64.test(value)) throw new AccountReadError("HCS11_ACCOUNT_MEMO_INVALID", true);
  const bytes = Buffer.from(value, "base64");
  let decoded: string;
  try { decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { throw new AccountReadError("HCS11_ACCOUNT_MEMO_INVALID", true); }
  if (bytes.toString("base64") !== value || Buffer.byteLength(decoded, "utf8") > 100) {
    throw new AccountReadError("HCS11_ACCOUNT_MEMO_INVALID", true);
  }
  return decoded;
}
function observedAccountMemo(row: Record<string, unknown>): Hcs11V1Memo {
  const encoded = row.memo_base64;
  let memo: string | null = null;
  if (encoded != null) memo = decodeMemo(encoded);
  if (row.memo != null) {
    if (typeof row.memo !== "string") throw new AccountReadError("HCS11_ACCOUNT_MEMO_INVALID", true);
    const plain = row.memo.startsWith("hcs-11:") ? row.memo : decodeMemo(row.memo);
    if (memo !== null && memo !== plain) throw new AccountReadError("HCS11_ACCOUNT_MEMO_CONFLICT", true);
    memo = plain;
  }
  if (!memo) throw new AccountReadError("HCS11_ACCOUNT_MEMO_UNAVAILABLE");
  try { return parseHcs11AccountMemoV1(memo); }
  catch { throw new AccountReadError("HCS11_ACCOUNT_MEMO_INVALID", true); }
}
function checkedRequest(request: Hcs11MirrorV1Request): void {
  if (!request || (request.hedera_network !== "mainnet" && request.hedera_network !== "testnet") ||
      typeof request.account_id !== "string" || request.account_id.length > 128 ||
      !ACCOUNT.test(request.account_id)) throw new TypeError("HCS11_ACCOUNT_LOCATOR_INVALID");
  if (request.hcs2_sequence_number !== undefined && (!Number.isSafeInteger(request.hcs2_sequence_number) ||
      request.hcs2_sequence_number < 1)) throw new TypeError("HCS11_HCS2_SEQUENCE_INVALID");
  if (request.expected_profile_reference != null) {
    parseHcs11AccountMemoV1(`hcs-11:${request.expected_profile_reference}`);
  }
  if (request.expected_hcs1_reference != null) parseHcs1ReferenceV1(request.expected_hcs1_reference);
  for (const value of [request.expected_hcs1_sha256, request.expected_profile_sha256]) {
    if (value != null && (typeof value !== "string" || !SHA256.test(value))) {
      throw new TypeError("HCS11_EXPECTED_SHA256_INVALID");
    }
  }
  if (request.expected_uaid != null) parseHcs14DidUaidV1(request.expected_uaid);
  if (request.expected_base_did != null && (typeof request.expected_base_did !== "string" ||
      !request.expected_base_did.trim() || request.expected_base_did.length > 2048)) {
    throw new TypeError("HCS11_EXPECTED_DID_INVALID");
  }
}

/** Only follows the observed account memo and, where necessary, an explicit HCS-2 sequence. */
export async function resolveHcs11ProfileV1(
  config: Hcs1MirrorV1Config,
  request: Hcs11MirrorV1Request,
  decodeOptions: Hcs1V1ContentOptions = {},
): Promise<Hcs11MirrorV1Result> {
  checkedRequest(request);
  const base = validatedBase(config, request.hedera_network);
  const bounds = validatedLimits(config);
  const accountId = request.account_id;
  let accountMemo: Hcs11V1Memo | null = null;
  let registryEntry: Hcs11MirrorV1Result["registry_entry"] = null;
  let profileRef: string | null = null;
  let contentSha: string | null = null;
  let canonicalSha: string | null = null;
  let profile: Hcs11V1Profile | null = null;
  let didBinding: Hcs11MirrorV1Result["did_binding"] = "not_checked";
  const output = (status: Hcs11MirrorV1Result["status"], reason: string | null): Hcs11MirrorV1Result =>
    Object.freeze({ status, reason_code: reason, hedera_network: request.hedera_network,
      account_id: accountId, resolver_id: "hedera.mirror-rest.hcs11.v1" as const,
      account_memo_temporal_scope: "current_observation" as const,
      account_memo: accountMemo, registry_entry: registryEntry,
      profile_reference: profileRef, content_sha256: contentSha,
      canonical_profile_sha256: canonicalSha, profile, did_binding: didBinding });
  try {
    const accountUrl = new URL(`${base.toString().replace(/\/$/, "")}/accounts/${accountId}`);
    const row = await readAccount(config, accountUrl, bounds);
    if (!row) return output("unavailable", "HCS11_ACCOUNT_NOT_FOUND");
    if (row.account !== accountId) return output("invalid", "HCS11_ACCOUNT_SCOPE_MISMATCH");
    if (row.deleted === true) return output("unavailable", "HCS11_ACCOUNT_DELETED");
    accountMemo = observedAccountMemo(row);
    if (request.expected_profile_reference != null &&
        accountMemo.profile_reference !== request.expected_profile_reference) {
      return output("conflict", "HCS11_ACCOUNT_REFERENCE_MISMATCH");
    }
    if (accountMemo.protocol === "hcs-2") {
      const sequence = request.hcs2_sequence_number;
      if (sequence === undefined) return output("unavailable", "HCS11_HCS2_SEQUENCE_REQUIRED");
      const expectedTopic = request.expected_hcs1_reference == null ? null :
        parseHcs1ReferenceV1(request.expected_hcs1_reference).topic_id;
      const registry = await resolveHcs2RegisterV1(config, {
        hedera_network: request.hedera_network,
        registry_topic_id: accountMemo.topic_id,
        sequence_number: sequence,
        expected_t_id: expectedTopic,
      });
      if (registry.status !== "resolved" || !registry.verification?.register ||
          !registry.consensus_timestamp) {
        return output(registry.status === "conflict" ? "conflict" :
          registry.status === "invalid" ? "invalid" : "unavailable",
          registry.reason_code ?? "HCS11_HCS2_ENTRY_UNAVAILABLE");
      }
      registryEntry = Object.freeze({ topic_id: accountMemo.topic_id,
        sequence_number: sequence, consensus_timestamp: registry.consensus_timestamp });
      profileRef = `hcs://1/${registry.verification.register.t_id}`;
    } else {
      if (request.hcs2_sequence_number !== undefined) {
        return output("invalid", "HCS11_HCS2_SEQUENCE_NOT_APPLICABLE");
      }
      profileRef = accountMemo.profile_reference;
    }
    if (request.expected_hcs1_reference != null && profileRef !== request.expected_hcs1_reference) {
      return output("conflict", "HCS11_PROFILE_REFERENCE_MISMATCH");
    }
    const hcs1 = await resolveHcs1FileV1(config, {
      network: request.hedera_network, reference: profileRef,
      expected_sha256: request.expected_hcs1_sha256 ?? null,
    }, decodeOptions);
    if (hcs1.status !== "resolved" || !hcs1.verification?.bytes || !hcs1.verification.sha256) {
      return output(hcs1.status === "invalid" && hcs1.reason_code === "HCS1_EXPECTED_CHECKSUM_MISMATCH"
        ? "conflict" : hcs1.status, hcs1.reason_code ?? "HCS11_PROFILE_CONTENT_UNAVAILABLE");
    }
    contentSha = hcs1.verification.sha256;
    const offline = verifyHcs11AiAgentProfileV1({
      profile: hcs1.verification.bytes,
      account_memo: accountMemo.memo,
      ...(request.expected_profile_sha256 == null ? {} : { expected_sha256: request.expected_profile_sha256 }),
      ...(request.expected_uaid == null ? {} : { expected_uaid: request.expected_uaid }),
      ...(request.expected_base_did == null ? {} : { expected_base_did: request.expected_base_did }),
      ...(request.expected_profile_reference == null ? {} : {
        expected_profile_reference: request.expected_profile_reference,
      }),
    });
    profile = offline.profile;
    canonicalSha = offline.sha256;
    if (offline.status !== "pass") {
      return output(offline.status === "unsupported" ? "unsupported" :
        offline.reason_code === "HCS11_CHECKSUM_MISMATCH" || offline.reason_code === "HCS11_UAID_MISMATCH" ||
        offline.reason_code === "HCS11_PROFILE_REFERENCE_MISMATCH" || offline.reason_code?.startsWith("HCS14_")
          ? "conflict" : "invalid", offline.reason_code);
    }
    const nativeId = parseHcs14DidUaidV1(profile!.uaid).params.nativeId;
    const nativeNetwork = typeof nativeId === "string" ? /^hedera:(mainnet|testnet):0\.0\.[0-9]+$/.exec(nativeId) : null;
    if (nativeNetwork && nativeNetwork[1] !== request.hedera_network) {
      return output("conflict", "HCS11_UAID_NETWORK_MISMATCH");
    }
    if (canonicalSha !== contentSha) {
      // The pinned HCS-11 profile publisher emits canonical JSON into HCS-1.
      // A structurally valid but noncanonical third-party profile is not this profile.
      return output("unsupported", "HCS11_PROFILE_CONTENT_NOT_CANONICAL");
    }
    if (request.expected_base_did != null) didBinding = "match";
    return output("resolved", null);
  } catch (error) {
    if (error instanceof AccountReadError) {
      return output(error.invalid ? "invalid" : "unavailable", error.code);
    }
    throw error;
  }
}
