// ============================================================================
// File: src/profiles/execution/recomputationV1.ts
// Version: 1.0.0 | 2026-10-15
// Purpose: Pure, deterministic execution verification primitives extracted from
//   Explorer's executionVerificationRecomputation.ts baseline (2026-10-07).
// Notes:
//   - No Explorer, Core, DB, resolver, or network imports.
//   - This is NOT the HF hashing contract (which uses different framing).
//   - UTC/Hedera ordering uses bigint nanoseconds, never floating milliseconds.
//   - These helpers do not establish an execution, acceptance, or identity claim.
// ============================================================================

import { createHash } from "node:crypto";

function plainObject(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function assertPairedSurrogates(value: string, path: string): void {
  for (let i = 0; i < value.length; i += 1) {
    const unit = value.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new TypeError(`Unpaired UTF-16 surrogate at ${path}.`);
      }
      i += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new TypeError(`Unpaired UTF-16 surrogate at ${path}.`);
    }
  }
}

function canonical(value: unknown, path: string, depth: number): string {
  if (depth > 64) throw new TypeError(`Maximum canonical JSON depth exceeded at ${path}.`);
  if (value === null) return "null";
  if (typeof value === "string") {
    assertPairedSurrogates(value, path);
    return JSON.stringify(value);
  }
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError(`Non-finite canonical JSON number at ${path}.`);
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item, index) => canonical(item, `${path}[${index}]`, depth + 1)).join(",")}]`;
  }
  if (!plainObject(value)) throw new TypeError(`Unsupported canonical JSON value at ${path}.`);
  const keys = Object.keys(value).sort();
  const parts: string[] = [];
  for (const key of keys) {
    assertPairedSurrogates(key, `${path}.{key}`);
    const child = value[key];
    if (child === undefined || typeof child === "function" || typeof child === "symbol" || typeof child === "bigint") {
      throw new TypeError(`Unsupported canonical JSON value at ${path}.${key}.`);
    }
    parts.push(`${JSON.stringify(key)}:${canonical(child, `${path}.${key}`, depth + 1)}`);
  }
  return `{${parts.join(",")}}`;
}

/** Canonicalization must match the frozen Explorer execution contract, not HF v1. */
export function canonicalizeExecutionVerificationValue(value: unknown): string {
  return canonical(value, "$", 0);
}

/** SHA3-512(UTF8(domain) || 0x00 || UTF8(canonical JSON)). */
export function computeExecutionDomainSeparatedSha3_512(domainSeparator: string, value: unknown): string {
  if (typeof domainSeparator !== "string") throw new TypeError("Domain separator must be a string");
  return createHash("sha3-512")
    .update(Buffer.from(domainSeparator, "utf8"))
    .update(Buffer.from([0]))
    .update(Buffer.from(canonicalizeExecutionVerificationValue(value), "utf8"))
    .digest("hex");
}

const UTC_RE = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(?:Z|\+00(?::?00)?)$/;
const HEDERA_RE = /^(\d{1,20})\.(\d{9})$/;
const NANOS_PER_SECOND = 1_000_000_000n;
const NANOS_PER_MILLISECOND = 1_000_000n;

/** Exact Hedera consensus seconds.nanoseconds. Returns null if unsupported. */
export function hederaConsensusTimestampNanos(value: unknown): bigint | null {
  if (typeof value !== "string") return null;
  const match = HEDERA_RE.exec(value.trim());
  if (!match) return null;
  const seconds = match[1];
  const nanos = match[2];
  if (seconds === undefined || nanos === undefined) return null;
  try {
    return BigInt(seconds) * NANOS_PER_SECOND + BigInt(nanos);
  } catch {
    return null;
  }
}

/** Exact UTC ISO-like timestamp; does not round fractional seconds. */
export function executionTimestampNanos(value: unknown): bigint | null {
  if (value instanceof Date) {
    const ms = value.getTime();
    return Number.isFinite(ms) ? BigInt(ms) * NANOS_PER_MILLISECOND : null;
  }
  if (typeof value !== "string") return null;
  const match = UTC_RE.exec(value.trim());
  if (!match) return null;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  if (![year, month, day, hour, minute, second].every(Number.isInteger)) return null;
  if (year < 1970 || year > 9999 || month < 1 || month > 12 || day < 1 || day > 31 ||
      hour > 23 || minute > 59 || second > 59) return null;
  const wholeMs = Date.UTC(year, month - 1, day, hour, minute, second, 0);
  if (!Number.isFinite(wholeMs)) return null;
  const date = new Date(wholeMs);
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 ||
      date.getUTCDate() !== day || date.getUTCHours() !== hour ||
      date.getUTCMinutes() !== minute || date.getUTCSeconds() !== second) return null;
  const fraction = (match[7] ?? "").padEnd(9, "0");
  return BigInt(Math.trunc(wholeMs / 1000)) * NANOS_PER_SECOND + BigInt(fraction || "0");
}

/** Display-only UTC ISO normalization; never use for exact ordering. */
export function executionTimestampIso(value: unknown): string | null {
  const nanos = executionTimestampNanos(value);
  if (nanos === null) return null;
  const ms = Number(nanos / 1_000_000n);
  return Number.isSafeInteger(ms) ? new Date(ms).toISOString() : null;
}
