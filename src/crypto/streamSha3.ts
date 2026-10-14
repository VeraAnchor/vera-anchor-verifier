import { createHash } from "node:crypto";
import { normalizeSha3_512Digest, type DigestVerificationResult } from "./sha3.js";

/** Byte chunks from a caller-owned source (including Node readable streams). */
export type ByteChunkSource = Iterable<Uint8Array> | AsyncIterable<Uint8Array>;

export type Sha3_512StreamHashResult = Readonly<{
  digest: string;
  bytes_hashed: number;
}>;

export type Sha3_512StreamVerificationResult = DigestVerificationResult &
  Readonly<{ bytes_hashed: number }>;

function safeByteCount(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new TypeError(`${name} must be a non-negative safe integer`);
  }
  return value as number;
}

/**
 * SHA3-512 over the exact byte stream, with constant auxiliary memory.
 * No canonicalization, framing, filesystem access, or network requests.
 * The source owns chunk buffering and cancellation.
 */
export async function sha3_512Stream(
  source: ByteChunkSource,
  options: Readonly<{ max_bytes?: number }> = {},
): Promise<Sha3_512StreamHashResult> {
  const maxBytes =
    options.max_bytes === undefined
      ? Number.MAX_SAFE_INTEGER
      : safeByteCount(options.max_bytes, "max_bytes");
  const hash = createHash("sha3-512");
  let bytesHashed = 0;

  for await (const chunk of source) {
    if (!(chunk instanceof Uint8Array)) {
      throw new TypeError("SHA3-512 stream chunks must be Uint8Array");
    }
    if (chunk.byteLength > maxBytes - bytesHashed) {
      throw new RangeError("SHA3-512 stream exceeds max_bytes");
    }
    hash.update(chunk);
    bytesHashed += chunk.byteLength;
  }

  return Object.freeze({ digest: hash.digest("hex"), bytes_hashed: bytesHashed });
}

/** Verify a stream against an independently supplied SHA3-512 commitment. */
export async function verifySha3_512Stream(
  input: Readonly<{
    source: ByteChunkSource;
    expected_digest: string;
    expected_bytes?: number;
    max_bytes?: number;
  }>,
): Promise<Sha3_512StreamVerificationResult> {
  const expected = normalizeSha3_512Digest(input.expected_digest);
  const expectedBytes =
    input.expected_bytes === undefined
      ? undefined
      : safeByteCount(input.expected_bytes, "expected_bytes");
  const { digest, bytes_hashed } = await sha3_512Stream(
    input.source,
    input.max_bytes === undefined ? undefined : { max_bytes: input.max_bytes },
  );
  const reasonCode =
    digest !== expected
      ? "DIGEST_MISMATCH"
      : expectedBytes !== undefined && bytes_hashed !== expectedBytes
        ? "BYTE_COUNT_MISMATCH"
        : null;

  return Object.freeze({
    outcome: reasonCode === null ? "pass" : "fail",
    reason_code: reasonCode,
    expected_digest: expected,
    computed_digest: digest,
    bytes_hashed,
  });
}
