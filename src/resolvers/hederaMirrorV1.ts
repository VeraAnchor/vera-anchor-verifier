import type { HederaNetwork, VerificationObservation, VerificationSubject } from "../contracts/verification.js";
import type { ExplorerPublicationV1 } from "./explorerPublicV1.js";
import { observeMirrorMessageV1 } from "../triangulation/messageObservationV1.js";

const DEFAULT_MIRROR = Object.freeze({
  mainnet: "https://mainnet-public.mirrornode.hedera.com/api/v1",
  testnet: "https://testnet.mirrornode.hedera.com/api/v1",
});
const DEFAULT_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
const MAX_LOGICAL_BYTES = 1024 * 1024;
const MAX_CHUNKS = 100;
const TOPIC = /^0\.0\.[1-9][0-9]*$/;
const TX = /^(0\.0\.\d+)[@-](\d{1,12})[.\-](\d{1,9})$/;
const B64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const CONSENSUS = /^\d{1,12}\.\d{1,9}$/;

type Json = Readonly<Record<string, unknown>>;

export type HederaMirrorV1Config = Readonly<{
  /** Trusted caller configuration, never loaded from an evidence package. */
  base_urls?: Readonly<Partial<Record<HederaNetwork, string>>>;
  fetch_impl?: typeof fetch;
  timeout_ms?: number;
  max_response_bytes?: number;
}>;

export type HederaPublicationObservationV1 = Readonly<{
  status: "resolved" | "unavailable" | "invalid" | "conflict";
  reason_code: string | null;
  /** Digest recomputed over independently retrieved, fully reassembled HCS bytes. */
  observation: VerificationObservation | null;
}>;

type TopicRow = Readonly<{
  topic_id: string;
  sequence_number: number;
  consensus_timestamp: string;
  bytes: Uint8Array;
  chunk_group: string | null;
  chunk_number: number | null;
  chunk_total: number | null;
}>;

class MirrorReadFailure extends Error {
  constructor(readonly code: string) { super(code); }
}

function object(value: unknown): Json {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new MirrorReadFailure("MIRROR_RESPONSE_INVALID");
  return value as Json;
}
function requiredString(value: unknown, max = 256): string {
  if (typeof value !== "string" || value.length === 0 || value.length > max || value.trim() !== value) {
    throw new MirrorReadFailure("MIRROR_RESPONSE_INVALID");
  }
  return value;
}
function positiveInteger(value: unknown): number {
  if ((typeof value !== "number" && typeof value !== "string") || value === "" ||
    !Number.isSafeInteger(Number(value)) || Number(value) < 1) {
    throw new MirrorReadFailure("MIRROR_RESPONSE_INVALID");
  }
  return Number(value);
}
function transactionId(value: string): string {
  const match = TX.exec(value);
  if (!match) throw new TypeError("Invalid Hedera transaction identifier");
  return `${match[1]}@${match[2]}.${match[3]!.padStart(9, "0")}`;
}
function initialTransactionId(value: unknown): string | null {
  if (typeof value === "string") {
    try { return transactionId(value); } catch { return null; }
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const raw = value as Json;
  const direct = raw.transaction_id ?? raw.transactionId ?? raw.transactionID;
  if (typeof direct === "string") return initialTransactionId(direct);
  const account = raw.account_id ?? raw.accountId;
  const start = raw.transaction_valid_start ?? raw.transactionValidStart ?? raw.valid_start_timestamp;
  if (typeof account !== "string" || !/^0\.0\.\d+$/.test(account)) return null;
  let stamp: string | null = typeof start === "string" ? start : null;
  if (start && typeof start === "object" && !Array.isArray(start)) {
    const parts = start as Json;
    if ((typeof parts.seconds === "number" || typeof parts.seconds === "string") &&
      (typeof parts.nanos === "number" || typeof parts.nanos === "string")) {
      stamp = `${parts.seconds}.${String(parts.nanos).padStart(9, "0")}`;
    }
  }
  if (!stamp) return null;
  try {
    const id = transactionId(`${account}@${stamp}`);
    const nonce = raw.nonce == null ? 0 : Number(raw.nonce);
    if (!Number.isSafeInteger(nonce) || nonce < 0) return null;
    return `${id}#${nonce}#${raw.scheduled === true ? "scheduled" : "direct"}`;
  } catch { return null; }
}
function topicRow(value: unknown, topic: string, sequence?: number): TopicRow {
  const row = object(value);
  if (row.topic_id !== topic) throw new MirrorReadFailure("MIRROR_MESSAGE_SCOPE_INVALID");
  const n = positiveInteger(row.sequence_number);
  if (sequence !== undefined && n !== sequence) throw new MirrorReadFailure("MIRROR_MESSAGE_SCOPE_INVALID");
  const timestamp = requiredString(row.consensus_timestamp, 64);
  if (!CONSENSUS.test(timestamp)) throw new MirrorReadFailure("MIRROR_RESPONSE_INVALID");
  const encoded = requiredString(row.message, MAX_RESPONSE_BYTES * 2);
  if (!B64.test(encoded)) throw new MirrorReadFailure("MIRROR_RESPONSE_INVALID");
  const bytes = Buffer.from(encoded, "base64");
  if (bytes.toString("base64") !== encoded || bytes.byteLength > MAX_LOGICAL_BYTES) {
    throw new MirrorReadFailure("MIRROR_RESPONSE_INVALID");
  }
  if (row.chunk_info == null) {
    return { topic_id: topic, sequence_number: n, consensus_timestamp: timestamp, bytes,
      chunk_group: null, chunk_number: null, chunk_total: null };
  }
  const chunk = object(row.chunk_info);
  const number = positiveInteger(chunk.number);
  const total = positiveInteger(chunk.total);
  const group = initialTransactionId(chunk.initial_transaction_id ?? chunk.initialTransactionId);
  if (!group || total > MAX_CHUNKS || number > total) throw new MirrorReadFailure("MIRROR_RESPONSE_INVALID");
  return { topic_id: topic, sequence_number: n, consensus_timestamp: timestamp, bytes,
    chunk_group: group, chunk_number: number, chunk_total: total };
}
function mirrorBase(config: HederaMirrorV1Config, network: HederaNetwork): string {
  const raw = config.base_urls?.[network] ?? DEFAULT_MIRROR[network];
  let parsed: URL;
  try { parsed = new URL(raw); } catch { throw new TypeError("Invalid Mirror base URL"); }
  if ((parsed.protocol !== "https:" && !(parsed.protocol === "http:" &&
    (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1" || parsed.hostname === "[::1]"))) ||
    parsed.username || parsed.password || parsed.search || parsed.hash || !parsed.pathname.endsWith("/api/v1")) {
    throw new TypeError("Mirror requires a fixed HTTPS /api/v1 endpoint (or HTTP loopback)");
  }
  return parsed.toString().replace(/\/$/, "");
}
async function read(config: HederaMirrorV1Config, network: HederaNetwork, path: string): Promise<Json | null> {
  const timeout = config.timeout_ms ?? 8000;
  const max = config.max_response_bytes ?? DEFAULT_RESPONSE_BYTES;
  if (!Number.isSafeInteger(timeout) || timeout < 250 || timeout > 15000 ||
    !Number.isSafeInteger(max) || max < 1024 || max > MAX_RESPONSE_BYTES) {
    throw new TypeError("Invalid Mirror request bounds");
  }
  const base = mirrorBase(config, network);
  const url = new URL(`${base}/${path}`);
  if (url.origin !== new URL(base).origin || !url.pathname.startsWith(`${new URL(base).pathname}/`)) {
    throw new TypeError("Mirror path escaped configured endpoint");
  }
  let response: Response;
  try {
    response = await (config.fetch_impl ?? fetch)(url.toString(), {
      method: "GET", headers: { Accept: "application/json" },
      redirect: "error", credentials: "omit", cache: "no-store", signal: AbortSignal.timeout(timeout),
    });
  } catch { throw new MirrorReadFailure("MIRROR_TRANSPORT_UNAVAILABLE"); }
  if (response.status === 404) return null;
  if (response.status === 429) throw new MirrorReadFailure("MIRROR_RATE_LIMITED");
  if (!response.ok) throw new MirrorReadFailure("MIRROR_HTTP_UNAVAILABLE");
  const length = response.headers.get("content-length");
  if (length && Number(length) > max) throw new MirrorReadFailure("MIRROR_RESPONSE_TOO_LARGE");
  if (!response.body) throw new MirrorReadFailure("MIRROR_RESPONSE_INVALID");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      total += result.value.byteLength;
      if (total > max) { await reader.cancel().catch(() => undefined); throw new MirrorReadFailure("MIRROR_RESPONSE_TOO_LARGE"); }
      chunks.push(result.value);
    }
  } catch (error) {
    if (error instanceof MirrorReadFailure) throw error;
    throw new MirrorReadFailure("MIRROR_TRANSPORT_UNAVAILABLE");
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(total);
  let at = 0;
  for (const part of chunks) { bytes.set(part, at); at += part.byteLength; }
  try { return object(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes))); }
  catch { throw new MirrorReadFailure("MIRROR_RESPONSE_INVALID"); }
}
async function reassembled(config: HederaMirrorV1Config, network: HederaNetwork, topic: string, first: TopicRow): Promise<Uint8Array> {
  if (!first.chunk_total || first.chunk_total === 1) return first.bytes;
  const scan = async (direction: "before" | "after") => {
    const params = new URLSearchParams({
      order: direction === "before" ? "desc" : "asc", limit: "100",
      timestamp: `${direction === "before" ? "lte" : "gte"}:${first.consensus_timestamp}`,
    });
    const list = await read(config, network, `topics/${topic}/messages?${params.toString()}`);
    if (!list || !Array.isArray(list.messages) || list.messages.length > 100) {
      throw new MirrorReadFailure("MIRROR_MESSAGE_REASSEMBLY_UNAVAILABLE");
    }
    return list.messages.map((item) => topicRow(item, topic));
  };
  const windows: TopicRow[][] = await Promise.all([
    first.chunk_number! > 1 ? scan("before") : Promise.resolve([]),
    first.chunk_number! < first.chunk_total ? scan("after") : Promise.resolve([]),
  ]);
  const unique = new Map<number, TopicRow>([[first.sequence_number, first]]);
  for (const window of windows) {
    for (const chunk of window) {
      const existing = unique.get(chunk.sequence_number);
      if (existing && (existing.chunk_number !== chunk.chunk_number ||
        Buffer.compare(Buffer.from(existing.bytes), Buffer.from(chunk.bytes)) !== 0)) {
        throw new MirrorReadFailure("MIRROR_RESPONSE_INVALID");
      }
      unique.set(chunk.sequence_number, chunk);
    }
  }
  const byNumber = new Map<number, TopicRow>();
  for (const chunk of unique.values()) {
    if (chunk.chunk_group !== first.chunk_group) continue;
    if (chunk.chunk_total !== first.chunk_total || chunk.chunk_number === null) {
      throw new MirrorReadFailure("MIRROR_RESPONSE_INVALID");
    }
    if (byNumber.has(chunk.chunk_number)) throw new MirrorReadFailure("MIRROR_RESPONSE_INVALID");
    byNumber.set(chunk.chunk_number, chunk);
  }
  if (byNumber.size !== first.chunk_total) throw new MirrorReadFailure("MIRROR_MESSAGE_REASSEMBLY_UNAVAILABLE");
  const parts: Uint8Array[] = [];
  let size = 0;
  for (let i = 1; i <= first.chunk_total; i++) {
    const chunk = byNumber.get(i);
    if (!chunk) throw new MirrorReadFailure("MIRROR_MESSAGE_REASSEMBLY_UNAVAILABLE");
    size += chunk.bytes.byteLength;
    if (size > MAX_LOGICAL_BYTES) throw new MirrorReadFailure("MIRROR_MESSAGE_TOO_LARGE");
    parts.push(chunk.bytes);
  }
  const result = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) { result.set(part, offset); offset += part.byteLength; }
  return result;
}
function output(status: HederaPublicationObservationV1["status"], reason: string): HederaPublicationObservationV1 {
  return Object.freeze({ status, reason_code: reason, observation: null });
}

/**
 * Directly observe a public publication on a separately configured Hedera Mirror.
 * The publication locator is a CLAIM until resolved; Mirror data is a distinct
 * network observation, not cryptographic consensus authentication.
 */
export async function resolveHederaPublicationV1(
  config: HederaMirrorV1Config,
  publication: ExplorerPublicationV1,
  subject: VerificationSubject,
): Promise<HederaPublicationObservationV1> {
  if (!publication || (publication.hedera_network !== "mainnet" && publication.hedera_network !== "testnet") ||
    publication.hedera_network !== subject.hedera_network || !subject.id ||
    !TOPIC.test(publication.topic_id ?? "") || !Number.isSafeInteger(publication.sequence_number) ||
    publication.sequence_number === null || publication.sequence_number < 1) {
    return output("unavailable", "MIRROR_MESSAGE_LOCATOR_UNAVAILABLE");
  }
  const network = publication.hedera_network;
  const topic = publication.topic_id!;
  const sequence = publication.sequence_number;
  try {
    const reply = await read(config, network, `topics/${topic}/messages/${sequence}`);
    if (!reply) return output("unavailable", "MIRROR_MESSAGE_NOT_FOUND");
    const first = topicRow(reply, topic, sequence);
    const bytes = await reassembled(config, network, topic, first);
    let transaction: string | null = null;
    let txConsensus: string | null = null;
    if (publication.transaction_id) {
      transaction = transactionId(publication.transaction_id);
      const txPath = transaction.replace(/@(\d+)\./, "-$1-");
      const tx = await read(config, network, `transactions/${txPath}`);
      if (!tx) return output("unavailable", "MIRROR_TRANSACTION_NOT_FOUND");
      const transactions = tx.transactions;
      if (!Array.isArray(transactions)) throw new MirrorReadFailure("MIRROR_RESPONSE_INVALID");
      const matching = transactions.filter((item) => {
        if (!item || typeof item !== "object" || Array.isArray(item)) return false;
        try { return transactionId(String((item as Json).transaction_id ?? "")) === transaction; }
        catch { return false; }
      });
      if (matching.length !== 1) throw new MirrorReadFailure("MIRROR_RESPONSE_INVALID");
      const resolved = object(matching[0]);
      const result = requiredString(resolved.result, 64).toUpperCase();
      if (result !== "SUCCESS") return output("conflict", "MIRROR_TRANSACTION_FAILED");
      if (resolved.consensus_timestamp !== undefined && resolved.consensus_timestamp !== null) {
        txConsensus = requiredString(resolved.consensus_timestamp, 64);
        if (!CONSENSUS.test(txConsensus)) throw new MirrorReadFailure("MIRROR_RESPONSE_INVALID");
      }
    }
    const original = observeMirrorMessageV1({ id: `${subject.kind}.hedera_mirror`, subject,
      topic_id: topic, sequence_number: sequence, message_bytes: bytes });
    return Object.freeze({ status: "resolved", reason_code: null,
      observation: Object.freeze({ ...original, resolver_id: "hedera.mirror-rest.v1", facts: Object.freeze([
        ...original.facts,
        { key: "hedera.consensus_timestamp_exact", state: "available" as const, value: first.consensus_timestamp },
        ...(transaction ? [{ key: "hedera.transaction_id", state: "available" as const, value: transaction }] : []),
        ...(txConsensus ? [{ key: "hedera.transaction_consensus_timestamp_exact", state: "available" as const, value: txConsensus }] : []),
      ]) }),
    });
  } catch (error) {
    if (error instanceof MirrorReadFailure) return output("unavailable", error.code);
    if (error instanceof TypeError) return output("invalid", "MIRROR_REFERENCE_INVALID");
    throw error;
  }
}
