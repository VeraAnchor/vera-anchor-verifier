/** Pinned HCS-1 zstd/base64 integrity verification; offline, with no network I/O. */
import { createHash } from "node:crypto";
import * as zlib from "node:zlib";

export const MAX_HCS1_V1_FILE_BYTES = 8 * 1024 * 1024;
export const MAX_HCS1_V1_CHUNKS = 4096;
const MAX_MESSAGE_BYTES = 1024;
const MAX_COMPRESSED_BYTES = MAX_HCS1_V1_CHUNKS * MAX_MESSAGE_BYTES;
const REF = /^hcs:\/\/1\/(0\.0\.[0-9]+)$/;
const MEMO = /^([0-9a-f]{64}):zstd:base64$/;
const SHA256 = /^[0-9a-f]{64}$/;
const MIME = /^[A-Za-z0-9][A-Za-z0-9!#$&^_.+\-/]{0,126}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export type Hcs1V1ContentInput = Readonly<{
  /** Supplied topic memo; not independently authenticated in offline mode. */
  memo: unknown;
  /** Original HCS message bytes containing {o,c} chunk JSON. */
  messages: readonly Uint8Array[];
  /** Optional independently established checksum. */
  expected_sha256?: string | null;
}>;

export type Hcs1V1ContentOptions = Readonly<{
  max_file_bytes?: number;
  /** Explicit optional runtime adapter; never obtained from untrusted evidence. */
  decompress_zstd?: (compressed: Uint8Array, maxOutputBytes: number) => Uint8Array | Promise<Uint8Array>;
}>;

export type Hcs1V1ContentResult = Readonly<{
  status: "pass" | "fail" | "unsupported";
  reason_code: string | null;
  sha256: string | null;
  mime_type: string | null;
  chunk_count: number;
  /** Returned only after the checksum is recomputed and matches all expectations. */
  bytes: Uint8Array | null;
}>;

class Hcs1Failure extends Error {
  constructor(readonly code: string, readonly unsupported = false) { super(code); }
}

export function parseHcs1ReferenceV1(value: unknown): Readonly<{ reference: string; topic_id: string }> {
  const match = typeof value === "string" ? REF.exec(value) : null;
  if (!match) throw new TypeError("HCS1_REFERENCE_INVALID");
  return Object.freeze({ reference: value as string, topic_id: match[1]! });
}

function failed(code: string, count = 0, unsupported = false): Hcs1V1ContentResult {
  return Object.freeze({ status: unsupported ? "unsupported" as const : "fail" as const,
    reason_code: code, sha256: null, mime_type: null, chunk_count: count, bytes: null });
}

function boundFileBytes(options: Hcs1V1ContentOptions): number {
  const n = options.max_file_bytes ?? MAX_HCS1_V1_FILE_BYTES;
  if (!Number.isSafeInteger(n) || n < 1 || n > MAX_HCS1_V1_FILE_BYTES) {
    throw new TypeError("HCS1_FILE_LIMIT_INVALID");
  }
  return n;
}

async function decompress(compressed: Buffer, limit: number, options: Hcs1V1ContentOptions): Promise<Buffer> {
  if (options.decompress_zstd) {
    const out = await options.decompress_zstd(new Uint8Array(compressed), limit);
    if (!(out instanceof Uint8Array)) throw new Hcs1Failure("HCS1_DECOMPRESSION_INVALID");
    if (out.byteLength > limit) throw new Hcs1Failure("HCS1_FILE_TOO_LARGE");
    return Buffer.from(out);
  }
  const fn = (zlib as unknown as { zstdDecompressSync?: (
    input: Uint8Array, options: { maxOutputLength: number }
  ) => Buffer }).zstdDecompressSync;
  if (typeof fn !== "function") throw new Hcs1Failure("HCS1_ZSTD_UNAVAILABLE", true);
  try {
    return fn(compressed, { maxOutputLength: limit });
  } catch (error) {
    if ((error as { code?: string })?.code === "ERR_BUFFER_TOO_LARGE") {
      throw new Hcs1Failure("HCS1_FILE_TOO_LARGE");
    }
    throw new Hcs1Failure("HCS1_DECOMPRESSION_INVALID");
  }
}

export async function verifyHcs1ContentV1(
  input: Hcs1V1ContentInput,
  options: Hcs1V1ContentOptions = {},
): Promise<Hcs1V1ContentResult> {
  const limit = boundFileBytes(options);
  const count = Array.isArray(input?.messages) ? input.messages.length : 0;
  try {
    const memo = typeof input?.memo === "string" ? MEMO.exec(input.memo) : null;
    if (!memo) throw new Hcs1Failure("HCS1_MEMO_INVALID");
    const expected = input.expected_sha256 == null ? null :
      typeof input.expected_sha256 === "string" ? input.expected_sha256.toLowerCase() : "";
    if (expected !== null && !SHA256.test(expected)) throw new Hcs1Failure("HCS1_EXPECTED_CHECKSUM_INVALID");
    if (!Array.isArray(input.messages) || count < 1 || count > MAX_HCS1_V1_CHUNKS) {
      throw new Hcs1Failure("HCS1_CHUNKS_INVALID");
    }
    const byOrder = new Map<number, string>();
    for (const message of input.messages) {
      if (!(message instanceof Uint8Array) || message.byteLength > MAX_MESSAGE_BYTES || !message.byteLength) {
        throw new Hcs1Failure("HCS1_MESSAGE_INVALID");
      }
      let chunk: unknown;
      try { chunk = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(message)); }
      catch { throw new Hcs1Failure("HCS1_CHUNK_INVALID"); }
      if (!chunk || typeof chunk !== "object" || Array.isArray(chunk)) {
        throw new Hcs1Failure("HCS1_CHUNK_INVALID");
      }
      const obj = chunk as Record<string, unknown>;
      if (Object.keys(obj).sort().join("\0") !== "c\0o" ||
          !Number.isSafeInteger(obj.o) || (obj.o as number) < 0 ||
          typeof obj.c !== "string" || !obj.c) {
        throw new Hcs1Failure("HCS1_CHUNK_INVALID");
      }
      if (byOrder.has(obj.o as number)) throw new Hcs1Failure("HCS1_CHUNK_DUPLICATE");
      byOrder.set(obj.o as number, obj.c);
    }
    const parts: string[] = [];
    for (let i = 0; i < count; i += 1) {
      const chunk = byOrder.get(i);
      if (chunk === undefined) throw new Hcs1Failure("HCS1_CHUNK_GAP");
      parts.push(chunk);
    }
    const prefix = /^data:([^;]+);base64,/.exec(parts[0]!);
    if (!prefix || !MIME.test(prefix[1]!)) throw new Hcs1Failure("HCS1_PREFIX_INVALID");
    parts[0] = parts[0]!.slice(prefix[0].length);
    const encoded = parts.join("");
    if (!encoded || encoded.length > Math.ceil(MAX_COMPRESSED_BYTES * 4 / 3) + 4 ||
        encoded.length % 4 !== 0 || !BASE64.test(encoded)) {
      throw new Hcs1Failure("HCS1_BASE64_INVALID");
    }
    const compressed = Buffer.from(encoded, "base64");
    if (compressed.toString("base64") !== encoded || compressed.byteLength > MAX_COMPRESSED_BYTES) {
      throw new Hcs1Failure("HCS1_BASE64_INVALID");
    }
    const bytes = await decompress(compressed, limit, options);
    if (!bytes.byteLength || bytes.byteLength > limit) throw new Hcs1Failure("HCS1_FILE_TOO_LARGE");
    const actual = createHash("sha256").update(bytes).digest("hex");
    if (actual !== memo[1]) throw new Hcs1Failure("HCS1_CHECKSUM_MISMATCH");
    if (expected && actual !== expected) throw new Hcs1Failure("HCS1_EXPECTED_CHECKSUM_MISMATCH");
    return Object.freeze({ status: "pass" as const, reason_code: null, sha256: actual,
      mime_type: prefix[1]!, chunk_count: count, bytes: new Uint8Array(bytes) });
  } catch (error) {
    if (error instanceof Hcs1Failure) return failed(error.code, count, error.unsupported);
    // An explicitly supplied decompressor may throw on malformed bytes.
    if (options.decompress_zstd) return failed("HCS1_DECOMPRESSION_INVALID", count);
    throw error;
  }
}
