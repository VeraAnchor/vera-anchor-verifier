import type { VerificationReport } from "../contracts/verification.js";
import { sha3_512Hex } from "../crypto/sha3.js";

export const VERIFICATION_CORE_SCHEMA_VERSION = "va.verification-core.v1";
const DOMAIN = "va:verification-core:v1";
const CHECK_ID = /^[a-z][a-z0-9._:-]{0,159}$/;
const OBSERVATION_ID = /^[a-z][a-z0-9._:-]{0,127}$/;
const EXPECTED_KEY = /^[a-z][a-z0-9_]{0,63}$/;
const HEX_512 = /^[0-9a-f]{128}$/i;
const SUBJECT_KINDS = ["artifact", "dataset", "ingest", "evidence_package", "merkle_anchor",
  "merkle_root", "merkle_leaf", "execution", "result"];
const OUTCOMES = ["pass", "fail", "indeterminate", "unsupported", "skipped"];
const SOURCES = ["provided_evidence", "public_record", "authorized_service", "hedera_mirror", "local_computation"];
const MAX_CANONICAL_BYTES = 1024 * 1024;

type JsonRecord = Record<string, unknown>;

function record(value: unknown, name: string): JsonRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError(`Invalid ${name}`);
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) throw new TypeError(`Invalid ${name}`);
  return value as JsonRecord;
}

function fields(value: JsonRecord, allowed: readonly string[], name: string): void {
  if (Object.keys(value).some((key) => !allowed.includes(key))) throw new TypeError(`Unknown ${name} field`);
}

function items(value: unknown, max: number, name: string): unknown[] {
  if (!Array.isArray(value) || value.length > max) throw new TypeError(`Invalid ${name}`);
  for (let i = 0; i < value.length; i += 1) {
    if (!Object.hasOwn(value, i)) throw new TypeError(`Sparse ${name}`);
  }
  return value;
}

function text(value: unknown, name: string, max: number, nonempty = true): string {
  if (typeof value !== "string" || value.length > max || (nonempty && !value.length)) {
    throw new TypeError(`Invalid ${name}`);
  }
  for (let i = 0; i < value.length; i += 1) {
    const u = value.charCodeAt(i);
    if (u >= 0xd800 && u <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new TypeError(`Invalid ${name}`);
    } else if (u >= 0xdc00 && u <= 0xdfff) throw new TypeError(`Invalid ${name}`);
  }
  return value;
}

function identifier(value: unknown, name: string, pattern: RegExp): string {
  const result = text(value, name, 160);
  if (!pattern.test(result)) throw new TypeError(`Invalid ${name}`);
  return result;
}

function digest(value: unknown, name: string): string {
  const result = text(value, name, 128);
  if (!HEX_512.test(result)) throw new TypeError(`Invalid ${name}`);
  return result.toLowerCase();
}

function subject(value: unknown) {
  const row = record(value, "verification subject");
  fields(row, ["kind", "id", "hedera_network"], "subject");
  if (!SUBJECT_KINDS.includes(row.kind as string)) throw new TypeError("Invalid subject kind");
  const id = text(row.id, "subject id", 256);
  if (id.trim() !== id) throw new TypeError("Invalid subject id");
  if (Object.hasOwn(row, "hedera_network")) {
    if (row.hedera_network !== "mainnet" && row.hedera_network !== "testnet") {
      throw new TypeError("Invalid subject network");
    }
    return { kind: row.kind, id, hedera_network: row.hedera_network };
  }
  return { kind: row.kind, id };
}

function commitment(value: unknown) {
  const row = record(value, "expected commitment");
  const key = identifier(row.key, "expected commitment key", EXPECTED_KEY);
  if (row.kind === "merkle-root") {
    fields(row, ["key", "kind", "tree_alg", "root_hash", "leaf_count"], "merkle commitment");
    if (!["binary-sorted", "binary-sorted-v2", "hf-dataset-v1", "hf-ingest-v1"].includes(row.tree_alg as string) ||
      !Number.isSafeInteger(row.leaf_count) || (row.leaf_count as number) < 1) {
      throw new TypeError("Invalid Merkle commitment");
    }
    return { key, kind: "merkle-root", tree_alg: row.tree_alg,
      root_hash: digest(row.root_hash, "root hash"), leaf_count: row.leaf_count };
  }
  if (row.kind !== "digest") throw new TypeError("Invalid commitment kind");
  if (row.contract === "hf-contract-v1") {
    fields(row, ["key", "kind", "contract", "material", "domain", "digest"], "HF commitment");
    if (!["json", "utf8", "raw"].includes(row.material as string)) throw new TypeError("Invalid HF material");
    const domain = text(row.domain, "HF domain", 256);
    return { key, kind: "digest", contract: "hf-contract-v1", material: row.material,
      domain, digest: digest(row.digest, "expected digest") };
  }
  fields(row, ["key", "kind", "contract", "digest"], "digest commitment");
  if (row.contract !== "raw-sha3-512" && row.contract !== "core-canonical-json") {
    throw new TypeError("Invalid digest contract");
  }
  return { key, kind: "digest", contract: row.contract, digest: digest(row.digest, "expected digest") };
}

function fact(value: unknown) {
  const row = record(value, "verification fact");
  const key = identifier(row.key, "fact key", CHECK_ID);
  if (row.state === "available") {
    fields(row, ["key", "state", "value"], "available fact");
    if (!Object.hasOwn(row, "value")) throw new TypeError("Missing fact value");
    const v = row.value;
    if (typeof v === "number" && (!Number.isFinite(v) || Object.is(v, -0))) {
      throw new TypeError("Invalid numeric fact");
    }
    if (typeof v === "string") text(v, "fact value", 4096, false);
    else if (v !== null && typeof v !== "number" && typeof v !== "boolean") {
      throw new TypeError("Invalid fact value");
    }
    return { key, state: "available", value: v };
  }
  if (row.state !== "unavailable" && row.state !== "not_applicable") {
    throw new TypeError("Invalid fact state");
  }
  fields(row, ["key", "state", "reason_code"], "unavailable fact");
  if (Object.hasOwn(row, "reason_code")) {
    return { key, state: row.state,
      reason_code: row.reason_code === null ? null : text(row.reason_code, "fact reason", 160) };
  }
  return { key, state: row.state };
}

function unique<T>(values: T[], key: (value: T) => string, name: string): T[] {
  values.sort((a, b) => key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0);
  for (let i = 1; i < values.length; i += 1) {
    if (key(values[i]!) === key(values[i - 1]!)) throw new TypeError(`Duplicate ${name}`);
  }
  return values;
}

function observation(value: unknown) {
  const row = record(value, "observation");
  fields(row, ["id", "subject", "source", "resolver_id", "observed_at", "facts"], "observation");
  const id = identifier(row.id, "observation id", OBSERVATION_ID);
  if (!SOURCES.includes(row.source as string)) throw new TypeError("Invalid observation source");
  const facts = unique(items(row.facts, 256, "observation facts").map(fact), (v) => v.key, "fact key");
  const result: JsonRecord = { id, subject: subject(row.subject), source: row.source };
  if (Object.hasOwn(row, "resolver_id")) result.resolver_id = text(row.resolver_id, "resolver id", 256);
  if (Object.hasOwn(row, "observed_at")) {
    result.observed_at = row.observed_at === null ? null : text(row.observed_at, "observation time", 128);
  }
  result.facts = facts;
  return result;
}

function finding(value: unknown) {
  const row = record(value, "finding");
  fields(row, ["check_id", "outcome", "reason_code", "observation_ids"], "finding");
  const check_id = identifier(row.check_id, "check id", CHECK_ID);
  if (!OUTCOMES.includes(row.outcome as string)) throw new TypeError("Invalid finding outcome");
  const reason_code = row.reason_code === null ? null : text(row.reason_code, "finding reason", 160);
  const observation_ids = unique(items(row.observation_ids, 32, "finding observation ids")
    .map((id) => identifier(id, "finding observation id", OBSERVATION_ID)), (id) => id, "finding observation id");
  return { check_id, outcome: row.outcome, reason_code, observation_ids };
}

/** Canonical shared findings/observations only; profile-specific assurance is NOT included. */
export function canonicalizeVerificationCoreV1(input: VerificationReport): string {
  const report = record(input, "verification report");
  const intent = record(report.intent, "verification intent");
  fields(intent, ["subject", "expected"], "intent");
  const expected = unique(items(intent.expected, 32, "expectations").map(commitment), (v) => v.key, "expectation key");
  const observations = unique(items(report.observations, 32, "observations").map(observation),
    (v) => v.id as string, "observation id");
  const findings = unique(items(report.findings, 512, "findings").map(finding),
    (v) => v.check_id, "check id");
  const ids = new Set(observations.map((v) => v.id as string));
  for (const entry of findings) {
    if (entry.observation_ids.some((id) => !ids.has(id))) throw new TypeError("Finding references missing observation");
  }
  const canonical = JSON.stringify({ schema_version: VERIFICATION_CORE_SCHEMA_VERSION,
    intent: { subject: subject(intent.subject), expected }, findings, observations });
  if (Buffer.byteLength(canonical, "utf8") > MAX_CANONICAL_BYTES) {
    throw new RangeError("Verification core exceeds size limit");
  }
  return canonical;
}

/** Unauthenticated content digest, NOT proof that these checks were performed. */
export function computeVerificationCoreDigestV1(input: VerificationReport): string {
  const canonical = canonicalizeVerificationCoreV1(input);
  return sha3_512Hex(Buffer.concat([Buffer.from(DOMAIN, "utf8"), Buffer.from([0]),
    Buffer.from(canonical, "utf8")]));
}
