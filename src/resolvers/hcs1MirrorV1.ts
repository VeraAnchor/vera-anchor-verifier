/** Independent Mirror REST HCS-1 observation, never consensus-signature authentication. */
import type { HederaNetwork } from "../contracts/verification.js";
import type { HederaMirrorV1Config } from "./hederaMirrorV1.js";
import {
  MAX_HCS1_V1_CHUNKS, parseHcs1ReferenceV1, verifyHcs1ContentV1,
  type Hcs1V1ContentOptions, type Hcs1V1ContentResult,
} from "../standards/hcs/hcs1V1.js";

const BASE = Object.freeze({
  mainnet: "https://mainnet-public.mirrornode.hedera.com/api/v1",
  testnet: "https://testnet.mirrornode.hedera.com/api/v1",
});
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
const MAX_PAGES = Math.ceil(MAX_HCS1_V1_CHUNKS / 100) + 1;
const B64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const MEMO = /^[0-9a-f]{64}:zstd:base64$/;

type Json = Record<string, unknown>;

export type Hcs1MirrorV1Config = HederaMirrorV1Config & Readonly<{
  total_timeout_ms?: number;
}>;
export type Hcs1MirrorV1Request = Readonly<{
  reference: string;
  network: HederaNetwork;
  /** Caller expectation, not a claim taken from the fetched document. */
  expected_sha256?: string | null;
}>;
export type Hcs1MirrorV1Result = Readonly<{
  status: "resolved" | "invalid" | "unavailable" | "unsupported";
  reason_code: string | null;
  reference: string;
  hedera_network: HederaNetwork;
  resolver_id: "hedera.mirror-rest.hcs1.v1";
  /** When resolved: recomputed file integrity relative to the observed HCS topic memo. */
  verification: Hcs1V1ContentResult | null;
}>;

class MirrorFailure extends Error {
  constructor(readonly code: string, readonly invalid = false) { super(code); }
}

function record(value: unknown): Json {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new MirrorFailure("HCS1_MIRROR_RESPONSE_INVALID", true);
  }
  return value as Json;
}

function baseUrl(config: Hcs1MirrorV1Config, network: HederaNetwork): URL {
  const raw = config.base_urls?.[network] ?? BASE[network];
  let url: URL;
  try { url = new URL(raw); } catch { throw new TypeError("Invalid HCS-1 Mirror base URL"); }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if ((url.protocol !== "https:" && !(loopback && url.protocol === "http:")) ||
      url.username || url.password || url.search || url.hash ||
      !url.pathname.endsWith("/api/v1")) {
    throw new TypeError("HCS-1 Mirror requires a fixed HTTPS /api/v1 endpoint (or HTTP loopback)");
  }
  return url;
}

function bounds(config: Hcs1MirrorV1Config): { timeout: number; max: number; deadline: number } {
  const timeout = config.timeout_ms ?? 8000;
  const max = config.max_response_bytes ?? 2 * 1024 * 1024;
  const total = config.total_timeout_ms ?? 30000;
  if (!Number.isSafeInteger(timeout) || timeout < 250 || timeout > 15000 ||
      !Number.isSafeInteger(max) || max < 1024 || max > MAX_RESPONSE_BYTES ||
      !Number.isSafeInteger(total) || total < 250 || total > 60000) {
    throw new TypeError("Invalid HCS-1 Mirror read limits");
  }
  return { timeout, max, deadline: Date.now() + total };
}

async function readJson(
  config: Hcs1MirrorV1Config, url: URL, expectedBase: URL,
  topicPath: string, limit: { timeout: number; max: number; deadline: number },
): Promise<Json | null> {
  const prefix = `${expectedBase.pathname}/topics/${topicPath}`;
  if (url.origin !== expectedBase.origin ||
      (url.pathname !== prefix && url.pathname !== `${prefix}/messages`)) {
    throw new MirrorFailure("HCS1_MIRROR_ENDPOINT_INVALID", true);
  }
  const remaining = limit.deadline - Date.now();
  if (remaining <= 0) throw new MirrorFailure("HCS1_MIRROR_TIMEOUT");
  let response: Response;
  try {
    response = await (config.fetch_impl ?? fetch)(url.toString(), {
      method: "GET", headers: { Accept: "application/json" },
      redirect: "error", credentials: "omit", cache: "no-store",
      signal: AbortSignal.timeout(Math.min(remaining, limit.timeout)),
    });
  } catch { throw new MirrorFailure("HCS1_MIRROR_UNAVAILABLE"); }
  if (response.status === 404) return null;
  if (response.status === 429) throw new MirrorFailure("HCS1_MIRROR_RATE_LIMITED");
  if (!response.ok) throw new MirrorFailure("HCS1_MIRROR_UNAVAILABLE");
  const advertised = response.headers.get("content-length");
  if (advertised && Number(advertised) > limit.max) throw new MirrorFailure("HCS1_MIRROR_RESPONSE_TOO_LARGE");
  if (!response.body) throw new MirrorFailure("HCS1_MIRROR_RESPONSE_INVALID", true);
  const reader = response.body.getReader();
  const buffers: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      total += part.value.byteLength;
      if (total > limit.max) {
        await reader.cancel().catch(() => undefined);
        throw new MirrorFailure("HCS1_MIRROR_RESPONSE_TOO_LARGE");
      }
      buffers.push(part.value);
    }
  } catch (error) {
    if (error instanceof MirrorFailure) throw error;
    throw new MirrorFailure("HCS1_MIRROR_UNAVAILABLE");
  } finally { reader.releaseLock(); }
  const data = new Uint8Array(total);
  let offset = 0;
  for (const part of buffers) { data.set(part, offset); offset += part.byteLength; }
  try { return record(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(data))); }
  catch (error) {
    if (error instanceof MirrorFailure) throw error;
    throw new MirrorFailure("HCS1_MIRROR_RESPONSE_INVALID", true);
  }
}

function normalizeMemo(value: unknown): string {
  if (typeof value !== "string" || value.length > 256) throw new MirrorFailure("HCS1_TOPIC_MEMO_INVALID", true);
  if (MEMO.test(value)) return value;
  if (!B64.test(value)) throw new MirrorFailure("HCS1_TOPIC_MEMO_INVALID", true);
  const decoded = Buffer.from(value, "base64");
  const memo = decoded.toString("utf8");
  if (decoded.toString("base64") !== value || !MEMO.test(memo)) {
    throw new MirrorFailure("HCS1_TOPIC_MEMO_INVALID", true);
  }
  return memo;
}

function messageBytes(value: unknown, topic: string, previousSequence: number): { bytes: Uint8Array; sequence: number } {
  const row = record(value);
  if (row.topic_id !== topic || !Number.isSafeInteger(row.sequence_number) ||
      (row.sequence_number as number) <= previousSequence || typeof row.message !== "string" ||
      !B64.test(row.message)) {
    throw new MirrorFailure("HCS1_MIRROR_MESSAGE_INVALID", true);
  }
  const bytes = Buffer.from(row.message, "base64");
  if (!bytes.length || bytes.length > 1024 || bytes.toString("base64") !== row.message) {
    throw new MirrorFailure("HCS1_MIRROR_MESSAGE_INVALID", true);
  }
  return { bytes, sequence: row.sequence_number as number };
}

function result(request: Hcs1MirrorV1Request, status: Hcs1MirrorV1Result["status"],
  reason: string | null, verification: Hcs1V1ContentResult | null): Hcs1MirrorV1Result {
  return Object.freeze({ status, reason_code: reason, reference: request.reference,
    hedera_network: request.network, resolver_id: "hedera.mirror-rest.hcs1.v1" as const, verification });
}

/**
 * Mirror response is independently observed relative to VA services, but is
 * not Hedera consensus-signature authentication. No arbitrary evidence URLs.
 */
export async function resolveHcs1FileV1(
  config: Hcs1MirrorV1Config,
  request: Hcs1MirrorV1Request,
  decodeOptions: Hcs1V1ContentOptions = {},
): Promise<Hcs1MirrorV1Result> {
  const ref = parseHcs1ReferenceV1(request?.reference);
  if (request.network !== "mainnet" && request.network !== "testnet") {
    throw new TypeError("HCS1_NETWORK_INVALID");
  }
  const base = baseUrl(config, request.network);
  const limit = bounds(config);
  const basePath = base.toString().replace(/\/$/, "");
  const topic = ref.topic_id;
  try {
    const topicRow = await readJson(config, new URL(`${basePath}/topics/${topic}`), base, topic, limit);
    if (!topicRow) return result(request, "unavailable", "HCS1_TOPIC_NOT_FOUND", null);
    if (topicRow.topic_id !== topic || !topicRow.submit_key || topicRow.admin_key) {
      throw new MirrorFailure("HCS1_TOPIC_METADATA_INVALID", true);
    }
    const memo = normalizeMemo(topicRow.memo);
    let url: URL | null = new URL(`${basePath}/topics/${topic}/messages?limit=100&order=asc`);
    const messages: Uint8Array[] = [];
    let previousSequence = 0;
    let pages = 0;
    const visited = new Set<string>();
    while (url) {
      if (++pages > MAX_PAGES || visited.has(url.toString())) {
        throw new MirrorFailure("HCS1_MIRROR_PAGINATION_INVALID", true);
      }
      visited.add(url.toString());
      const page = await readJson(config, url, base, topic, limit);
      if (!page || !Array.isArray(page.messages) || page.messages.length > 100) {
        throw new MirrorFailure("HCS1_MIRROR_RESPONSE_INVALID", true);
      }
      for (const message of page.messages) {
        const parsed = messageBytes(message, topic, previousSequence);
        previousSequence = parsed.sequence;
        messages.push(parsed.bytes);
        if (messages.length > MAX_HCS1_V1_CHUNKS) {
          throw new MirrorFailure("HCS1_TOO_MANY_CHUNKS", true);
        }
      }
      const link = page.links == null ? null : record(page.links).next;
      if (link != null && (typeof link !== "string" || !link.length)) {
        throw new MirrorFailure("HCS1_MIRROR_PAGINATION_INVALID", true);
      }
      url = link ? new URL(link, `${basePath}/`) : null;
      if (url && (url.origin !== base.origin ||
          url.pathname !== `${base.pathname}/topics/${topic}/messages`)) {
        throw new MirrorFailure("HCS1_MIRROR_PAGINATION_INVALID", true);
      }
    }
    const verification = await verifyHcs1ContentV1({ memo, messages,
      expected_sha256: request.expected_sha256 ?? null }, decodeOptions);
    const status = verification.status === "pass" ? "resolved" :
      verification.status === "unsupported" ? "unsupported" : "invalid";
    return result(request, status, verification.reason_code, verification);
  } catch (error) {
    if (error instanceof MirrorFailure) {
      return result(request, error.invalid ? "invalid" : "unavailable", error.code, null);
    }
    throw error;
  }
}
