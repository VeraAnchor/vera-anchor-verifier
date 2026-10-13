import { createHash } from "node:crypto";
import type { VerificationOutcome } from "../contracts/verification.js";

const DIGEST_RE = /^[0-9a-f]{128}$/i;

export type DigestVerificationResult = Readonly<{
  outcome: Extract<VerificationOutcome, "pass" | "fail">;
  reason_code: string | null;
  expected_digest: string;
  computed_digest: string;
}>;

export function normalizeSha3_512Digest(value: unknown): string {
  if (typeof value !== "string" || !DIGEST_RE.test(value)) {
    throw new TypeError("SHA3-512 digest must contain exactly 128 hex characters");
  }
  return value.toLowerCase();
}

/** SHA3-512 over exact bytes. No JSON canonicalization or domain framing. */
export function sha3_512Hex(bytes: Uint8Array): string {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError("SHA3-512 input must be Uint8Array");
  }
  return createHash("sha3-512").update(bytes).digest("hex");
}

export function verifySha3_512Bytes(input: Readonly<{
  bytes: Uint8Array;
  expected_digest: string;
}>): DigestVerificationResult {
  const expected = normalizeSha3_512Digest(input.expected_digest);
  const computed = sha3_512Hex(input.bytes);
  const matches = computed === expected;
  return Object.freeze({
    outcome: matches ? "pass" : "fail",
    reason_code: matches ? null : "DIGEST_MISMATCH",
    expected_digest: expected,
    computed_digest: computed,
  });
}
