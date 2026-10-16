import type { VerificationFact, VerificationObservation, VerificationSubject } from "../contracts/verification.js";
import type { HederaMirrorV1Config } from "./hederaMirrorV1.js";
import { EXECUTION_HEDERA_OBSERVATION_V1_ID, type ExecutionHederaTargetV1 } from "../triangulation/executionPlanV1.js";

const DEFAULT_MIRROR = Object.freeze({
  mainnet: "https://mainnet-public.mirrornode.hedera.com/api/v1",
  testnet: "https://testnet.mirrornode.hedera.com/api/v1",
});
const TX = /^(0\.0\.\d+)[@-](\d{1,12})[.\-](\d{1,9})$/;
const TOPIC = /^0\.0\.\d+$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const TIMESTAMP = /^\d{1,12}\.\d{1,9}$/;
const MAX_BYTES = 256 * 1024;
const MAX_TARGETS = 8;

type Json = Record<string, unknown>;
type Status = "resolved" | "unavailable" | "conflict" | "invalid";
export type ExecutionMirrorV1Result = Readonly<{
  status: Status;
  reason_code: string | null;
  observation: VerificationObservation;
}>;

function record(value: unknown): Json | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Json : null;
}
function transaction(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const match = TX.exec(value);
  return match ? `${match[1]}@${match[2]}.${match[3]!.padStart(9, "0")}` : null;
}
function base(config: HederaMirrorV1Config, network: "mainnet" | "testnet"): string {
  const value = config.base_urls?.[network] ?? DEFAULT_MIRROR[network];
  const url = new URL(value);
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if ((url.protocol !== "https:" && !(loopback && url.protocol === "http:")) ||
      url.username || url.password || url.search || url.hash ||
      !/^\/api\/v1\/?$/.test(url.pathname)) {
    throw new TypeError("Mirror base URL must be a fixed HTTPS /api/v1 endpoint");
  }
  return `${url.origin}/api/v1`;
}

async function get(config: HederaMirrorV1Config, network: "mainnet" | "testnet", path: string): Promise<{
  status: "found" | "not_found" | "unavailable" | "invalid";
  body: Json | null;
}> {
  const timeout = config.timeout_ms ?? 8000;
  const limit = config.max_response_bytes ?? MAX_BYTES;
  if (!Number.isSafeInteger(timeout) || timeout < 250 || timeout > 15_000 ||
      !Number.isSafeInteger(limit) || limit < 1024 || limit > MAX_BYTES) throw new TypeError("Invalid Mirror transport bounds");
  const url = `${base(config, network)}/${path}`;
  try {
    const response = await (config.fetch_impl ?? fetch)(url, {
      method: "GET", redirect: "error", credentials: "omit", cache: "no-store",
      headers: { Accept: "application/json" }, signal: AbortSignal.timeout(timeout),
    });
    if (response.status === 404) return { status: "not_found", body: null };
    if (!response.ok) return { status: "unavailable", body: null };
    const header = response.headers.get("content-length");
    if (header && (!/^\d+$/.test(header) || Number(header) > limit)) return { status: "invalid", body: null };
    if (!response.body) return { status: "invalid", body: null };
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let count = 0;
    try {
      while (true) {
        const next = await reader.read();
        if (next.done) break;
        count += next.value.byteLength;
        if (count > limit) { await reader.cancel().catch(() => undefined); return { status: "invalid", body: null }; }
        chunks.push(next.value);
      }
    } finally { reader.releaseLock(); }
    const bytes = new Uint8Array(count);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    try {
      const body = record(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)));
      return body ? { status: "found", body } : { status: "invalid", body: null };
    } catch { return { status: "invalid", body: null }; }
  } catch { return { status: "unavailable", body: null }; }
}

function available(key: string, value: string): VerificationFact {
  return Object.freeze({ key, state: "available" as const, value });
}
function unavailable(key: string, reason_code: string): VerificationFact {
  return Object.freeze({ key, state: "unavailable" as const, reason_code });
}

export async function resolveExecutionHederaV1(
  config: HederaMirrorV1Config,
  input: Readonly<{ subject: VerificationSubject; targets: readonly ExecutionHederaTargetV1[] }>,
): Promise<ExecutionMirrorV1Result> {
  const network = input.subject.hedera_network;
  if ((network !== "mainnet" && network !== "testnet") || input.subject.kind !== "execution" ||
      typeof input.subject.id !== "string" || !input.subject.id ||
      !Array.isArray(input.targets) || input.targets.length > MAX_TARGETS) {
    throw new TypeError("Invalid Hedera execution resolution scope");
  }
  const facts: VerificationFact[] = [];
  const observed = new Set<string>();
  if (input.targets.length === 0) {
    return Object.freeze({ status: "unavailable" as const, reason_code: "MIRROR_LEDGER_TARGETS_MISSING",
      observation: Object.freeze({ id: EXECUTION_HEDERA_OBSERVATION_V1_ID, source: "hedera_mirror" as const,
        subject: input.subject, resolver_id: "hedera.execution-mirror.v1", facts: Object.freeze([]) }),
    });
  }
  let status: Status = "resolved";
  let reason: string | null = null;
  for (const target of input.targets) {
    if (!target || target.network !== network || !["provided_evidence", "public_record"].includes(target.source) ||
        !["acceptance_anchor", "result_evidence_anchor"].includes(target.role) ||
        target.observation_fact_prefix !== `ledger.${target.source}.${target.role}` ||
        (target.transaction_id && transaction(target.transaction_id) !== target.transaction_id) ||
        (target.topic_id !== null && (typeof target.topic_id !== "string" || !TOPIC.test(target.topic_id))) ||
        (target.transaction_id !== null && typeof target.transaction_id !== "string") ||
        (target.sequence_number !== null && (typeof target.sequence_number !== "number")) ||
        ((target.topic_id === null) !== (target.sequence_number === null)) ||
        (target.sequence_number !== null && (!Number.isSafeInteger(target.sequence_number) || target.sequence_number < 1)) ||
        (!target.transaction_id && !target.topic_id)) {
      throw new TypeError("Invalid scoped Hedera execution target");
    }
    const prefix = target.observation_fact_prefix;
    if (observed.has(prefix)) throw new TypeError("Duplicate Hedera execution target");
    observed.add(prefix);
    if (target.transaction_id) {
      const match = TX.exec(target.transaction_id)!;
      const resolved = await get(config, network, `transactions/${match[1]}-${match[2]}-${match[3]}`);
      const key = `${prefix}.transaction_id`;
      if (resolved.status === "found") {
        const rows = resolved.body!.transactions;
        if (!Array.isArray(rows) || rows.length > 32) {
          facts.push(unavailable(key, "MIRROR_RESPONSE_INVALID"));
          if (status !== "conflict") status = "invalid"; reason ??= "MIRROR_RESPONSE_INVALID";
        } else {
          const candidates = rows.map(record).filter((row): row is Json => row !== null);
          const exact = candidates.filter((row) => transaction(row.transaction_id) === target.transaction_id);
          if (exact.length !== 1 || exact[0]!.result !== "SUCCESS") {
            facts.push(unavailable(key, "MIRROR_TRANSACTION_CONFLICT"));
            status = "conflict"; reason = "MIRROR_TRANSACTION_CONFLICT";
          } else {
            facts.push(available(key, transaction(exact[0]!.transaction_id)!));
          }
        }
      } else {
        facts.push(unavailable(key, `MIRROR_TRANSACTION_${resolved.status.toUpperCase()}`));
        if (status === "resolved" || (status === "unavailable" && resolved.status === "invalid")) {
          status = resolved.status === "invalid" ? "invalid" : "unavailable";
        }
        reason ??= `MIRROR_TRANSACTION_${resolved.status.toUpperCase()}`;
      }
    }
    if (target.topic_id && target.sequence_number !== null) {
      const resolved = await get(config, network, `topics/${target.topic_id}/messages/${target.sequence_number}`);
      const topicKey = `${prefix}.topic_id`;
      const sequenceKey = `${prefix}.sequence_number`;
      if (resolved.status === "found") {
        const row = resolved.body!;
        if (typeof row.topic_id !== "string" || !TOPIC.test(row.topic_id) ||
            !Number.isSafeInteger(Number(row.sequence_number)) || Number(row.sequence_number) < 1 ||
            typeof row.consensus_timestamp !== "string" || !TIMESTAMP.test(row.consensus_timestamp) ||
            typeof row.message !== "string" || row.message.length > 1368 || !BASE64.test(row.message) ||
            Buffer.from(row.message, "base64").toString("base64") !== row.message) {
          facts.push(unavailable(topicKey, "MIRROR_RESPONSE_INVALID"), unavailable(sequenceKey, "MIRROR_RESPONSE_INVALID"));
          if (status !== "conflict") status = "invalid"; reason ??= "MIRROR_RESPONSE_INVALID";
        } else {
          facts.push(available(topicKey, row.topic_id), available(sequenceKey, String(row.sequence_number)));
          if (row.topic_id !== target.topic_id || Number(row.sequence_number) !== target.sequence_number) {
            status = "conflict"; reason = "MIRROR_MESSAGE_SCOPE_MISMATCH";
          }
        }
      } else {
        const code = `MIRROR_MESSAGE_${resolved.status.toUpperCase()}`;
        facts.push(unavailable(topicKey, code), unavailable(sequenceKey, code));
        if (status === "resolved" || (status === "unavailable" && resolved.status === "invalid")) {
          status = resolved.status === "invalid" ? "invalid" : "unavailable";
        }
        reason ??= code;
      }
    }
  }
  const observation: VerificationObservation = Object.freeze({
    id: EXECUTION_HEDERA_OBSERVATION_V1_ID,
    source: "hedera_mirror" as const,
    subject: input.subject,
    resolver_id: "hedera.execution-mirror.v1",
    facts: Object.freeze(facts),
  });
  return Object.freeze({ status, reason_code: reason, observation });
}
