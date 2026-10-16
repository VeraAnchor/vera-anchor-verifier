/** Bounded, read-only observation of one exact historical HCS-26 registry message.
 * This is Mirror REST corroboration, not authenticated Hedera consensus. Internal
 * adapter: consumers must apply the pinned HCS-26 operation parser themselves.
 */
import type { HederaNetwork } from "../contracts/verification.js";
import type { HederaMirrorV1Config } from "./hederaMirrorV1.js";
import { parseHcs26MemoV1, type Hcs26MemoV1, Hcs26V1Error } from "../standards/hcs/hcs26V1.js";

const DEFAULT_BASE: Readonly<Record<HederaNetwork, string>> = Object.freeze({
  mainnet: "https://mainnet-public.mirrornode.hedera.com/api/v1",
  testnet: "https://testnet.mirrornode.hedera.com/api/v1",
});
const TOPIC = /^0\.0\.[0-9]+$/;
const B64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const TS = /^[0-9]{1,20}\.[0-9]{1,9}$/;
const MAX_RESPONSE = 256 * 1024;

type Json = Record<string, unknown>;
export type Hcs26RegistryMessageV1 = Readonly<{
  topic_id: string;
  sequence_number: number;
  consensus_timestamp: string;
  memo: Hcs26MemoV1;
  message: Uint8Array;
}>;
export type Hcs26RegistryReadV1 = Readonly<{
  status: "resolved" | "unavailable" | "invalid";
  reason_code: string | null;
  evidence: Hcs26RegistryMessageV1 | null;
}>;
class ReadError extends Error {
  constructor(readonly code: string, readonly invalid = false) { super(code); }
}
function object(value: unknown): Json {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ReadError("HCS26_MIRROR_RESPONSE_INVALID", true);
  }
  return value as Json;
}
function baseUrl(config: HederaMirrorV1Config, network: HederaNetwork): URL {
  let url: URL;
  try { url = new URL(config.base_urls?.[network] ?? DEFAULT_BASE[network]); }
  catch { throw new TypeError("HCS26_MIRROR_BASE_URL_INVALID"); }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if ((url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) ||
      url.username || url.password || url.search || url.hash || !url.pathname.endsWith("/api/v1")) {
    throw new TypeError("HCS26_MIRROR_BASE_URL_INVALID");
  }
  return url;
}
function limits(config: HederaMirrorV1Config): { timeout: number; bytes: number } {
  const timeout = config.timeout_ms ?? 8000;
  const bytes = config.max_response_bytes ?? MAX_RESPONSE;
  if (!Number.isSafeInteger(timeout) || timeout < 250 || timeout > 15000 ||
      !Number.isSafeInteger(bytes) || bytes < 1024 || bytes > MAX_RESPONSE) {
    throw new TypeError("HCS26_MIRROR_BOUNDS_INVALID");
  }
  return { timeout, bytes };
}
async function readJson(config: HederaMirrorV1Config, url: URL,
  limit: { timeout: number; bytes: number }): Promise<Json | null> {
  let response: Response;
  try {
    response = await (config.fetch_impl ?? fetch)(url.toString(), {
      method: "GET", headers: { Accept: "application/json" },
      redirect: "error", credentials: "omit", cache: "no-store",
      signal: AbortSignal.timeout(limit.timeout),
    });
  } catch { throw new ReadError("HCS26_MIRROR_UNAVAILABLE"); }
  if (response.status === 404) return null;
  if (response.status === 429) throw new ReadError("HCS26_MIRROR_RATE_LIMITED");
  if (!response.ok) throw new ReadError("HCS26_MIRROR_UNAVAILABLE");
  const length = response.headers.get("content-length");
  if (length && (!Number.isSafeInteger(Number(length)) || Number(length) > limit.bytes)) {
    throw new ReadError("HCS26_MIRROR_RESPONSE_TOO_LARGE");
  }
  if (!response.body) throw new ReadError("HCS26_MIRROR_RESPONSE_INVALID", true);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let count = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      count += part.value.byteLength;
      if (count > limit.bytes) {
        await reader.cancel().catch(() => undefined);
        throw new ReadError("HCS26_MIRROR_RESPONSE_TOO_LARGE");
      }
      chunks.push(part.value);
    }
  } catch (error) {
    if (error instanceof ReadError) throw error;
    throw new ReadError("HCS26_MIRROR_UNAVAILABLE");
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(count);
  let position = 0;
  for (const chunk of chunks) { bytes.set(chunk, position); position += chunk.byteLength; }
  try { return object(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes))); }
  catch (error) {
    if (error instanceof ReadError) throw error;
    throw new ReadError("HCS26_MIRROR_RESPONSE_INVALID", true);
  }
}
function normalizedMemo(value: unknown): Hcs26MemoV1 {
  if (typeof value !== "string" || value.length > 256) throw new ReadError("HCS26_TOPIC_MEMO_INVALID", true);
  let text = value;
  if (!value.startsWith("hcs-26:")) {
    if (!B64.test(value)) throw new ReadError("HCS26_TOPIC_MEMO_INVALID", true);
    const decoded = Buffer.from(value, "base64");
    if (decoded.toString("base64") !== value) throw new ReadError("HCS26_TOPIC_MEMO_INVALID", true);
    try { text = new TextDecoder("utf-8", { fatal: true }).decode(decoded); }
    catch { throw new ReadError("HCS26_TOPIC_MEMO_INVALID", true); }
  }
  try { return parseHcs26MemoV1(text); }
  catch (error) {
    if (error instanceof Hcs26V1Error) throw new ReadError(error.code, true);
    throw error;
  }
}
function decodeMessage(value: unknown): Uint8Array {
  if (typeof value !== "string" || !value || !B64.test(value)) {
    throw new ReadError("HCS26_MIRROR_MESSAGE_INVALID", true);
  }
  const bytes = Buffer.from(value, "base64");
  if (!bytes.length || bytes.length > 1024 || bytes.toString("base64") !== value) {
    throw new ReadError("HCS26_MIRROR_MESSAGE_INVALID", true);
  }
  return new Uint8Array(bytes);
}
function output(status: Hcs26RegistryReadV1["status"], reason: string | null,
  evidence: Hcs26RegistryMessageV1 | null = null): Hcs26RegistryReadV1 {
  return Object.freeze({ status, reason_code: reason, evidence });
}
export async function readHcs26RegistryMessageV1(
  config: HederaMirrorV1Config,
  request: Readonly<{ hedera_network: HederaNetwork; topic_id: string;
    sequence_number: number; registry_type: "discovery" | "version" }>,
): Promise<Hcs26RegistryReadV1> {
  if (!request || (request.hedera_network !== "testnet" && request.hedera_network !== "mainnet") ||
      !TOPIC.test(request.topic_id) || !Number.isSafeInteger(request.sequence_number) ||
      request.sequence_number < 1 || (request.registry_type !== "discovery" && request.registry_type !== "version")) {
    throw new TypeError("HCS26_REGISTRY_LOCATOR_INVALID");
  }
  const base = baseUrl(config, request.hedera_network);
  const bound = limits(config);
  const prefix = base.toString().replace(/\/$/, "");
  const path = `topics/${request.topic_id}`;
  try {
    const topic = await readJson(config, new URL(`${prefix}/${path}`), bound);
    if (!topic) return output("unavailable", "HCS26_REGISTRY_NOT_FOUND");
    if (topic.topic_id !== request.topic_id) throw new ReadError("HCS26_REGISTRY_SCOPE_MISMATCH", true);
    const memo = normalizedMemo(topic.memo);
    if (memo.type !== request.registry_type) return output("invalid", "HCS26_REGISTRY_TYPE_MISMATCH");
    const row = await readJson(config, new URL(`${prefix}/${path}/messages/${request.sequence_number}`), bound);
    if (!row) return output("unavailable", "HCS26_REGISTRY_ENTRY_NOT_FOUND");
    if (row.topic_id !== request.topic_id || row.sequence_number !== request.sequence_number || row.chunk_info != null) {
      throw new ReadError("HCS26_REGISTRY_MESSAGE_SCOPE_MISMATCH", true);
    }
    if (typeof row.consensus_timestamp !== "string" || !TS.test(row.consensus_timestamp)) {
      throw new ReadError("HCS26_REGISTRY_TIMESTAMP_INVALID", true);
    }
    const message = decodeMessage(row.message);
    return output("resolved", null, Object.freeze({ topic_id: request.topic_id,
      sequence_number: request.sequence_number, consensus_timestamp: row.consensus_timestamp,
      memo, message }));
  } catch (error) {
    if (error instanceof ReadError) return output(error.invalid ? "invalid" : "unavailable", error.code);
    throw error;
  }
}
