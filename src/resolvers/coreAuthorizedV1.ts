import type { HederaNetwork } from "../contracts/verification.js";
import {
  AuthProviderContractErrorV1,
  resolveCoreAuthorizationV1,
  type AuthProviderV1,
  type CoreAuthorizationRequestV1,
} from "../auth/authProviderV1.js";

const CORE_PATH = "/v1/hcs/verify-decrypt" as const;
const DEFAULT_TIMEOUT_MS = 12_000;
const DEFAULT_RESPONSE_BYTES = 1024 * 1024;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_IDENTIFIER_BYTES = 256;
const MAX_TEXT = 4096;
const HASH = /^[0-9a-f]{128}$/i;
const TOPIC = /^0\.0\.\d+$/;
const CONSENSUS = /^\d{1,12}\.\d{1,9}$/;

type Json = Readonly<Record<string, unknown>>;

export type CoreAuthorizedV1Config = Readonly<{
  /** Fixed Core origin only; no path, query, credentials, or fragment. */
  base_url: string;
  auth_provider: AuthProviderV1;
  fetch_impl?: typeof fetch;
  timeout_ms?: number;
  max_response_bytes?: number;
}>;

export type AuthorizedHcsEvidenceV1Request = Readonly<{
  network: HederaNetwork;
  message_id?: string;
  transaction_id?: string;
  /** Plaintext retrieval is opt-in. The resolver never persists it. */
  include_decrypted?: boolean;
}>;

export type AuthorizedHcsEvidenceV1 = Readonly<{
  acquisition: Readonly<{
    resolver_id: "core.authorized-hcs.v1";
    access_context: "authorized";
    retrieval_provider: "vera_anchor_core";
    decryption_method: "service_assisted" | "not_requested";
    recoverability: "service_dependent";
  }>;
  hedera_network: HederaNetwork;
  topic: Readonly<{
    name: string;
    topic_id: string | null;
    key_version: number | null;
  }>;
  encryption: Readonly<{
    topic_key_version: number | null;
    user_key_version: number | null;
  }>;
  tx: Readonly<{
    id: string;
    message_id: string | null;
    transaction_id: string | null;
    sequence_number: number | null;
    consensus_timestamp: string | null;
    status: string | null;
    mirror_verified: boolean;
    mirror_verified_at: string | null;
  }>;
  /** Core-reported hash values are retained only as source observations. */
  core_hash_observation: Readonly<{
    expected: string | null;
    computed: string | null;
  }>;
  message_binding: Readonly<{
    schema_version: "vera.hcs-message-binding.v1";
    algorithm: "sha3-512";
    message_sha3_512: string;
    message_bytes: number;
  }>;
  payload_included: boolean;
  payload: unknown | null;
}>;

export type AuthorizedHcsEvidenceV1Result = Readonly<{
  status: "resolved" | "unauthorized" | "forbidden" | "not_found" | "rate_limited" | "unavailable" | "invalid";
  reason_code: string | null;
  evidence: AuthorizedHcsEvidenceV1 | null;
}>;

class AuthorizedCoreReadFailure extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

function utf8Bytes(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function coreOrigin(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError("Core base_url must be an absolute URL");
  }
  const local = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
  if ((url.protocol !== "https:" && !(local && url.protocol === "http:")) ||
    url.username || url.password || url.search || url.hash || url.pathname !== "/") {
    throw new TypeError("Core base_url must identify a fixed HTTPS origin (HTTP loopback permitted)");
  }
  return url.origin;
}

function bounds(config: CoreAuthorizedV1Config): { timeout: number; budget: number } {
  const timeout = config.timeout_ms ?? DEFAULT_TIMEOUT_MS;
  const budget = config.max_response_bytes ?? DEFAULT_RESPONSE_BYTES;
  if (!Number.isSafeInteger(timeout) || timeout < 250 || timeout > 60_000 ||
    !Number.isSafeInteger(budget) || budget < 1024 || budget > MAX_RESPONSE_BYTES) {
    throw new TypeError("Invalid authorized Core transport bounds");
  }
  return { timeout, budget };
}

function identifier(value: unknown, name: string): string | null {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value ||
    utf8Bytes(value) > MAX_IDENTIFIER_BYTES || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new TypeError(`Invalid ${name}`);
  }
  return value;
}

function requestBody(request: AuthorizedHcsEvidenceV1Request): Readonly<Record<string, unknown>> {
  if (!request || (request.network !== "mainnet" && request.network !== "testnet")) {
    throw new TypeError("Authorized HCS evidence requires an explicit Hedera network");
  }
  const messageId = identifier(request.message_id, "message_id");
  const transactionId = identifier(request.transaction_id, "transaction_id");
  if ((messageId === null) === (transactionId === null)) {
    throw new TypeError("Exactly one of message_id or transaction_id is required");
  }
  return Object.freeze({
    hedera_network: request.network,
    ...(messageId ? { message_id: messageId } : { transaction_id: transactionId }),
    mode: "decrypt_only",
    include_decrypted: request.include_decrypted === true,
  });
}

function object(value: unknown): Json {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new AuthorizedCoreReadFailure("CORE_AUTHORIZED_RESPONSE_INVALID");
  }
  return value as Json;
}

function text(value: unknown, max = MAX_TEXT): string {
  if (typeof value !== "string" || value.length === 0 || value.length > max || value.trim() !== value ||
    /[\u0000-\u001f\u007f]/.test(value)) {
    throw new AuthorizedCoreReadFailure("CORE_AUTHORIZED_RESPONSE_INVALID");
  }
  return value;
}

function nullableText(value: unknown, max = MAX_TEXT): string | null {
  return value === null || value === undefined ? null : text(value, max);
}

function nullablePositiveInt(value: unknown): number | null {
  if (value === null || value === undefined) return null;
  if (!Number.isSafeInteger(value) || Number(value) < 1) {
    throw new AuthorizedCoreReadFailure("CORE_AUTHORIZED_RESPONSE_INVALID");
  }
  return Number(value);
}

function nullableHash(value: unknown): string | null {
  if (value === null || value === undefined || value === "") return null;
  const digest = text(value, 128);
  if (!HASH.test(digest)) throw new AuthorizedCoreReadFailure("CORE_AUTHORIZED_RESPONSE_INVALID");
  return digest.toLowerCase();
}

function validateSuccess(
  body: unknown,
  request: AuthorizedHcsEvidenceV1Request,
): AuthorizedHcsEvidenceV1 {
  const row = object(body);
  if (row.ok !== true || row.hedera_network !== request.network || row.mode !== "decrypt_only" || row.verified !== null) {
    throw new AuthorizedCoreReadFailure("CORE_AUTHORIZED_RESPONSE_INVALID");
  }

  const topic = object(row.topic);
  const encryption = object(row.encryption);
  const tx = object(row.tx);
  const hash = object(row.hash);
  const binding = object(row.message_binding);

  if (hash.match !== null || typeof tx.mirror_verified !== "boolean" ||
    binding.schema_version !== "vera.hcs-message-binding.v1" || binding.algorithm !== "sha3-512") {
    throw new AuthorizedCoreReadFailure("CORE_AUTHORIZED_RESPONSE_INVALID");
  }

  const topicId = nullableText(topic.topic_id, 64);
  if (topicId !== null && !TOPIC.test(topicId)) throw new AuthorizedCoreReadFailure("CORE_AUTHORIZED_RESPONSE_INVALID");
  const consensus = nullableText(tx.consensus_timestamp, 64);
  if (consensus !== null && !CONSENSUS.test(consensus)) {
    throw new AuthorizedCoreReadFailure("CORE_AUTHORIZED_RESPONSE_INVALID");
  }

  const messageId = nullableText(tx.message_id, MAX_IDENTIFIER_BYTES);
  const transactionId = nullableText(tx.transaction_id, MAX_IDENTIFIER_BYTES);
  if (request.message_id !== undefined && messageId !== request.message_id) {
    throw new AuthorizedCoreReadFailure("CORE_AUTHORIZED_LOCATOR_MISMATCH");
  }
  if (request.transaction_id !== undefined && transactionId !== request.transaction_id) {
    throw new AuthorizedCoreReadFailure("CORE_AUTHORIZED_LOCATOR_MISMATCH");
  }

  const messageDigest = text(binding.message_sha3_512, 128);
  if (!HASH.test(messageDigest) || !Number.isSafeInteger(binding.message_bytes) ||
    Number(binding.message_bytes) < 1 || Number(binding.message_bytes) > 256 * 1024) {
    throw new AuthorizedCoreReadFailure("CORE_AUTHORIZED_RESPONSE_INVALID");
  }

  const includePayload = request.include_decrypted === true;
  const hasPayload = Object.prototype.hasOwnProperty.call(row, "payload");
  if (includePayload !== hasPayload) {
    throw new AuthorizedCoreReadFailure("CORE_AUTHORIZED_DISCLOSURE_MISMATCH");
  }

  return Object.freeze({
    acquisition: Object.freeze({
      resolver_id: "core.authorized-hcs.v1" as const,
      access_context: "authorized" as const,
      retrieval_provider: "vera_anchor_core" as const,
      decryption_method: includePayload ? "service_assisted" as const : "not_requested" as const,
      recoverability: "service_dependent" as const,
    }),
    hedera_network: request.network,
    topic: Object.freeze({
      name: text(topic.name, 256),
      topic_id: topicId,
      key_version: nullablePositiveInt(topic.key_version),
    }),
    encryption: Object.freeze({
      topic_key_version: nullablePositiveInt(encryption.topic_key_version),
      user_key_version: nullablePositiveInt(encryption.user_key_version),
    }),
    tx: Object.freeze({
      id: text(tx.id, 128),
      message_id: messageId,
      transaction_id: transactionId,
      sequence_number: nullablePositiveInt(tx.sequence_number),
      consensus_timestamp: consensus,
      status: nullableText(tx.status, 64),
      mirror_verified: tx.mirror_verified,
      mirror_verified_at: nullableText(tx.mirror_verified_at, 64),
    }),
    core_hash_observation: Object.freeze({
      expected: nullableHash(hash.expected),
      computed: nullableHash(hash.computed),
    }),
    message_binding: Object.freeze({
      schema_version: "vera.hcs-message-binding.v1" as const,
      algorithm: "sha3-512" as const,
      message_sha3_512: messageDigest.toLowerCase(),
      message_bytes: Number(binding.message_bytes),
    }),
    payload_included: includePayload,
    payload: includePayload ? row.payload : null,
  });
}

async function readJsonBounded(response: Response, budget: number): Promise<unknown> {
  const contentType = String(response.headers.get("content-type") ?? "").toLowerCase();
  if (!contentType.includes("application/json")) {
    throw new AuthorizedCoreReadFailure("CORE_AUTHORIZED_RESPONSE_INVALID");
  }
  const declared = response.headers.get("content-length");
  if (declared !== null) {
    const n = Number(declared);
    if (!Number.isFinite(n) || n < 0 || n > budget) {
      throw new AuthorizedCoreReadFailure("CORE_AUTHORIZED_RESPONSE_TOO_LARGE");
    }
  }
  if (!response.body) throw new AuthorizedCoreReadFailure("CORE_AUTHORIZED_RESPONSE_INVALID");

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      size += next.value.byteLength;
      if (size > budget) {
        await reader.cancel().catch(() => undefined);
        throw new AuthorizedCoreReadFailure("CORE_AUTHORIZED_RESPONSE_TOO_LARGE");
      }
      chunks.push(next.value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new AuthorizedCoreReadFailure("CORE_AUTHORIZED_RESPONSE_INVALID");
  }
}

function failure(status: AuthorizedHcsEvidenceV1Result["status"], reason: string): AuthorizedHcsEvidenceV1Result {
  return Object.freeze({ status, reason_code: reason, evidence: null });
}

function httpFailure(status: number): AuthorizedHcsEvidenceV1Result {
  if (status === 401) return failure("unauthorized", "CORE_AUTH_REQUIRED");
  if (status === 403) return failure("forbidden", "CORE_AUTH_FORBIDDEN");
  if (status === 404) return failure("not_found", "CORE_AUTHORIZED_EVIDENCE_NOT_FOUND");
  if (status === 429) return failure("rate_limited", "CORE_RATE_LIMITED");
  if (status >= 400 && status < 500) return failure("invalid", "CORE_AUTHORIZED_REQUEST_REJECTED");
  return failure("unavailable", "CORE_AUTHORIZED_HTTP_UNAVAILABLE");
}

/**
 * Retrieves actor-authorized HCS evidence from Core without trusting Core's
 * verification verdict. Core is an evidence/decryption provider on this path.
 */
export async function resolveAuthorizedHcsEvidenceV1(
  config: CoreAuthorizedV1Config,
  request: AuthorizedHcsEvidenceV1Request,
): Promise<AuthorizedHcsEvidenceV1Result> {
  if (!config || !config.auth_provider) throw new TypeError("Authorized Core resolver requires auth_provider");
  const origin = coreOrigin(config.base_url);
  const { timeout, budget } = bounds(config);
  const body = requestBody(request);
  const authRequest: CoreAuthorizationRequestV1 = Object.freeze({
    origin,
    path: CORE_PATH,
    method: "POST",
    network: request.network,
  });

  let authorization: string;
  try {
    authorization = (await resolveCoreAuthorizationV1(config.auth_provider, authRequest)).authorization;
  } catch (error) {
    if (error instanceof AuthProviderContractErrorV1) throw error;
    return failure("unavailable", "AUTH_PROVIDER_UNAVAILABLE");
  }

  let response: Response;
  try {
    response = await (config.fetch_impl ?? fetch)(new URL(CORE_PATH, origin).toString(), {
      method: "POST",
      redirect: "error",
      credentials: "omit",
      cache: "no-store",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        Authorization: authorization,
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeout),
    });
  } catch (error) {
    const name = error instanceof Error ? error.name : "";
    return failure("unavailable", name === "AbortError" || name === "TimeoutError"
      ? "CORE_AUTHORIZED_REQUEST_TIMEOUT"
      : "CORE_AUTHORIZED_REQUEST_UNAVAILABLE");
  }

  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined);
    return httpFailure(response.status);
  }

  try {
    const parsed = await readJsonBounded(response, budget);
    return Object.freeze({ status: "resolved", reason_code: null, evidence: validateSuccess(parsed, request) });
  } catch (error) {
    if (error instanceof AuthorizedCoreReadFailure) return failure("invalid", error.code);
    return failure("invalid", "CORE_AUTHORIZED_RESPONSE_INVALID");
  }
}
