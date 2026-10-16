/** Read-only HCS-2 historical register observation through a configured Hedera Mirror REST API. */
import type { HederaNetwork } from "../contracts/verification.js";
import type { HederaMirrorV1Config } from "./hederaMirrorV1.js";
import { verifyHcs2RegisterV1, type Hcs2V1VerificationResult } from "../standards/hcs/hcs2V1.js";

const DEFAULT_MIRROR: Readonly<Record<HederaNetwork, string>> = Object.freeze({
  mainnet: "https://mainnet-public.mirrornode.hedera.com/api/v1",
  testnet: "https://testnet.mirrornode.hedera.com/api/v1",
});
const TOPIC = /^0\.0\.[0-9]+$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const MEMO = /^hcs-2:[01]:[0-9]+$/;
const TIMESTAMP = /^[0-9]{1,20}\.[0-9]{1,9}$/;
const MAX_RESPONSE_BYTES = 256 * 1024;

type Json = Record<string, unknown>;

export type Hcs2MirrorV1Request = Readonly<{
  hedera_network: HederaNetwork;
  registry_topic_id: string;
  /** Explicit historical sequence; not a request to reconstruct mutable current state. */
  sequence_number: number;
  /** Caller-supplied expected target; unrelated to any value read from the register. */
  expected_t_id?: string | null;
}>;

export type Hcs2MirrorV1Result = Readonly<{
  status: "resolved" | "conflict" | "invalid" | "unavailable";
  reason_code: string | null;
  hedera_network: HederaNetwork;
  registry_topic_id: string;
  sequence_number: number;
  /** Exact timestamp observed from Mirror (not authenticated ledger consensus). */
  consensus_timestamp: string | null;
  resolver_id: "hedera.mirror-rest.hcs2.v1";
  verification: Hcs2V1VerificationResult | null;
}>;

class ReadFailure extends Error {
  constructor(readonly code: string, readonly invalid = false) { super(code); }
}

function record(value: unknown): Json {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ReadFailure("HCS2_MIRROR_RESPONSE_INVALID", true);
  }
  return value as Json;
}

function baseUrl(config: HederaMirrorV1Config, network: HederaNetwork): URL {
  const raw = config.base_urls?.[network] ?? DEFAULT_MIRROR[network];
  let parsed: URL;
  try { parsed = new URL(raw); } catch { throw new TypeError("HCS2_MIRROR_BASE_URL_INVALID"); }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname);
  if ((parsed.protocol !== "https:" && !(loopback && parsed.protocol === "http:")) ||
      parsed.username || parsed.password || parsed.search || parsed.hash ||
      !parsed.pathname.endsWith("/api/v1")) {
    throw new TypeError("HCS2_MIRROR_BASE_URL_INVALID");
  }
  return parsed;
}

function requestBounds(config: HederaMirrorV1Config): { timeout: number; max: number } {
  const timeout = config.timeout_ms ?? 8000;
  const max = config.max_response_bytes ?? MAX_RESPONSE_BYTES;
  if (!Number.isSafeInteger(timeout) || timeout < 250 || timeout > 15000 ||
      !Number.isSafeInteger(max) || max < 1024 || max > MAX_RESPONSE_BYTES) {
    throw new TypeError("HCS2_MIRROR_BOUNDS_INVALID");
  }
  return { timeout, max };
}

async function readJson(config: HederaMirrorV1Config, url: URL,
  bounds: { timeout: number; max: number }): Promise<Json | null> {
  let response: Response;
  try {
    response = await (config.fetch_impl ?? fetch)(url.toString(), {
      method: "GET", headers: { Accept: "application/json" },
      redirect: "error", credentials: "omit", cache: "no-store",
      signal: AbortSignal.timeout(bounds.timeout),
    });
  } catch { throw new ReadFailure("HCS2_MIRROR_UNAVAILABLE"); }
  if (response.status === 404) return null;
  if (response.status === 429) throw new ReadFailure("HCS2_MIRROR_RATE_LIMITED");
  if (!response.ok) throw new ReadFailure("HCS2_MIRROR_UNAVAILABLE");
  const advertised = response.headers.get("content-length");
  if (advertised && (!Number.isFinite(Number(advertised)) || Number(advertised) > bounds.max)) {
    throw new ReadFailure("HCS2_MIRROR_RESPONSE_TOO_LARGE");
  }
  if (!response.body) throw new ReadFailure("HCS2_MIRROR_RESPONSE_INVALID", true);
  const reader = response.body.getReader();
  const pieces: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      size += part.value.byteLength;
      if (size > bounds.max) {
        await reader.cancel().catch(() => undefined);
        throw new ReadFailure("HCS2_MIRROR_RESPONSE_TOO_LARGE");
      }
      pieces.push(part.value);
    }
  } catch (error) {
    if (error instanceof ReadFailure) throw error;
    throw new ReadFailure("HCS2_MIRROR_UNAVAILABLE");
  } finally { reader.releaseLock(); }
  const all = new Uint8Array(size);
  let offset = 0;
  for (const piece of pieces) { all.set(piece, offset); offset += piece.length; }
  try { return record(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(all))); }
  catch (error) {
    if (error instanceof ReadFailure) throw error;
    throw new ReadFailure("HCS2_MIRROR_RESPONSE_INVALID", true);
  }
}

function normalizedMemo(value: unknown): string {
  if (typeof value !== "string" || value.length > 256) {
    throw new ReadFailure("HCS2_TOPIC_MEMO_INVALID", true);
  }
  if (MEMO.test(value)) return value;
  if (!BASE64.test(value)) throw new ReadFailure("HCS2_TOPIC_MEMO_INVALID", true);
  const bytes = Buffer.from(value, "base64");
  let decoded: string;
  try { decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { throw new ReadFailure("HCS2_TOPIC_MEMO_INVALID", true); }
  if (bytes.toString("base64") !== value || !MEMO.test(decoded)) {
    throw new ReadFailure("HCS2_TOPIC_MEMO_INVALID", true);
  }
  return decoded;
}

function output(request: Hcs2MirrorV1Request, status: Hcs2MirrorV1Result["status"],
  reason_code: string | null, verification: Hcs2V1VerificationResult | null,
  consensus_timestamp: string | null = null): Hcs2MirrorV1Result {
  return Object.freeze({ status, reason_code, hedera_network: request.hedera_network,
    registry_topic_id: request.registry_topic_id, sequence_number: request.sequence_number,
    consensus_timestamp, resolver_id: "hedera.mirror-rest.hcs2.v1" as const, verification });
}

/** Verifies an exact historical HCS-2 register; does NOT determine the current registry state. */
export async function resolveHcs2RegisterV1(
  config: HederaMirrorV1Config,
  request: Hcs2MirrorV1Request,
): Promise<Hcs2MirrorV1Result> {
  if (!request || (request.hedera_network !== "mainnet" && request.hedera_network !== "testnet") ||
      !TOPIC.test(request.registry_topic_id) || !Number.isSafeInteger(request.sequence_number) ||
      request.sequence_number < 1) {
    throw new TypeError("HCS2_REGISTRY_LOCATOR_INVALID");
  }
  const base = baseUrl(config, request.hedera_network);
  const bounds = requestBounds(config);
  const prefix = base.toString().replace(/\/$/, "");
  const topic = request.registry_topic_id;
  try {
    const topicRow = await readJson(config, new URL(`${prefix}/topics/${topic}`), bounds);
    if (!topicRow) return output(request, "unavailable", "HCS2_REGISTRY_NOT_FOUND", null);
    if (topicRow.topic_id !== topic) throw new ReadFailure("HCS2_REGISTRY_SCOPE_MISMATCH", true);
    const memo = normalizedMemo(topicRow.memo);
    const row = await readJson(config, new URL(`${prefix}/topics/${topic}/messages/${request.sequence_number}`), bounds);
    if (!row) return output(request, "unavailable", "HCS2_REGISTER_NOT_FOUND", null);
    if (row.topic_id !== topic || row.sequence_number !== request.sequence_number ||
        row.chunk_info != null || typeof row.message !== "string" || !BASE64.test(row.message)) {
      throw new ReadFailure("HCS2_MESSAGE_SCOPE_INVALID", true);
    }
    const timestamp = row.consensus_timestamp;
    if (typeof timestamp !== "string" || !TIMESTAMP.test(timestamp)) {
      throw new ReadFailure("HCS2_MESSAGE_TIMESTAMP_INVALID", true);
    }
    const message = Buffer.from(row.message, "base64");
    if (!message.length || message.length > 1024 || message.toString("base64") !== row.message) {
      throw new ReadFailure("HCS2_MIRROR_MESSAGE_INVALID", true);
    }
    const verification = verifyHcs2RegisterV1({ memo, message,
      expected_t_id: request.expected_t_id ?? null });
    const status = verification.status === "pass" ? "resolved" :
      verification.reason_code === "HCS2_TARGET_MISMATCH" ? "conflict" : "invalid";
    return output(request, status, verification.reason_code, verification, timestamp);
  } catch (error) {
    if (error instanceof ReadFailure) {
      return output(request, error.invalid ? "invalid" : "unavailable", error.code, null);
    }
    throw error;
  }
}
