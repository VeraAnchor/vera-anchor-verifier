import { hashHfV1 } from "../../hf/hashContractV1.js";

const HEX = /^[0-9a-f]{128}$/;
const DATASET_KEY = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/;
const PROGRAM = /^[a-z][a-z0-9_:-]{1,63}$/;
const MAX_FILES = 5_000;
const MAX_JSON_DEPTH = 16;
const MAX_METADATA_NODES = 20_000;

export type DatasetV1Mismatch = Readonly<{
  field: string;
  expected: unknown;
  actual: unknown;
}>;

export type DatasetV1BundleComputed = Readonly<{
  dataset_key: string;
  program: string | null;
  version_label: string | null;
  bundle_digest: string;
  dataset_fingerprint: string;
  merkle_root: string;
  idempotency_key: string;
  file_count: number;
  total_bytes: number;
}>;

export type DatasetV1ReceiptComputed = Readonly<{
  dataset_key: string;
  program: string | null;
  version_label: string | null;
  receipt_id: string;
  hedera_network: "testnet" | "mainnet" | null;
  idempotency_key: string;
  dataset_fingerprint: string;
  bundle_digest: string;
  merkle_root: string;
  file_count: number;
  total_bytes: number;
}>;

export type DatasetV1VerificationResult<T> = Readonly<{
  ok: boolean;
  mismatches: readonly DatasetV1Mismatch[];
  computed: T;
}>;

type JsonRecord = Record<string, unknown>;
type DatasetFile = Readonly<{
  path_rel?: string;
  path_hash?: string;
  bytes: number;
  sha3_512: string;
  leaf_hash: string;
}>;

type DatasetBundle = Readonly<{
  bundle_version: "v1";
  hash_contract: Readonly<{
    contract_id: "hf-contract-v1";
    frame: "hf:frame:v1";
    canonical_json: "hf:canonical-json:v1";
    algorithm: "sha3-512";
    encoding: "hex_lower";
  }>;
  dataset_identity: Readonly<{ dataset_key: string; version_label?: string; program?: string }>;
  rules: Readonly<{
    path_normalization: "posix_rel_no_dotdot";
    follow_symlinks: boolean;
    redact_paths: boolean;
    ordering: "path_rel_ascii_asc";
    merkle_rule: "dup_last_on_odd";
    include_globs?: readonly string[];
    exclude_globs?: readonly string[];
    allowed_suffixes?: readonly string[];
  }>;
  files: readonly DatasetFile[];
  merkle: Readonly<{ leaf_count: number; root: string }>;
  summary: Readonly<{ file_count: number; total_bytes: number }>;
}>;

const HASH_CONTRACT: DatasetBundle["hash_contract"] = Object.freeze({
  contract_id: "hf-contract-v1",
  frame: "hf:frame:v1",
  canonical_json: "hf:canonical-json:v1",
  algorithm: "sha3-512",
  encoding: "hex_lower",
});

function invalid(field: string): never {
  throw new TypeError(`Invalid Dataset v1 evidence: ${field}`);
}

function record(value: unknown, field: string): JsonRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) return invalid(field);
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return invalid(field);
  return value as JsonRecord;
}

function exactKeys(value: JsonRecord, allowed: readonly string[], field: string): void {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) invalid(`${field}.${key}`);
  }
}

function requiredString(value: unknown, field: string, max: number): string {
  if (typeof value !== "string") return invalid(field);
  const text = value.trim();
  if (!text || text.length > max) return invalid(field);
  return text;
}

function optionalString(value: unknown, field: string, max: number): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string") return invalid(field);
  const text = value.trim();
  if (text.length > max) return invalid(field);
  return text || undefined;
}

function digest(value: unknown, field: string): string {
  const text = requiredString(value, field, 128).toLowerCase();
  if (!HEX.test(text)) return invalid(field);
  return text;
}

function count(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) return invalid(field);
  return value;
}

function flag(value: unknown, field: string): boolean {
  if (typeof value === "boolean") return value;
  if (typeof value === "string" && value.trim().toLowerCase() === "true") return true;
  if (typeof value === "string" && value.trim().toLowerCase() === "false") return false;
  return invalid(field);
}

function literal<T extends string>(value: unknown, expected: T, field: string): T {
  if (requiredString(value, field, 128) !== expected) return invalid(field);
  return expected;
}

function identity(input: unknown): DatasetBundle["dataset_identity"] {
  const value = record(input, "dataset_identity");
  exactKeys(value, ["dataset_key", "version_label", "program"], "dataset_identity");
  const dataset_key = requiredString(value.dataset_key, "dataset_key", 256);
  if (!DATASET_KEY.test(dataset_key)) invalid("dataset_key");
  const version_label = optionalString(value.version_label, "version_label", 64);
  const program = optionalString(value.program, "program", 64);
  if (program !== undefined && !PROGRAM.test(program)) invalid("program");
  return {
    dataset_key,
    ...(version_label !== undefined ? { version_label } : {}),
    ...(program !== undefined ? { program } : {}),
  };
}

function stringArray(value: unknown, field: string, max: number, lowercase = false): readonly string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > 256) return invalid(field);
  const values: string[] = [];
  for (const item of value) {
    if (typeof item !== "string") return invalid(field);
    const text = item.trim();
    if (!text) continue;
    if (text.length > max) return invalid(field);
    values.push(lowercase ? text.toLowerCase() : text);
  }
  return values;
}

function rules(input: unknown): DatasetBundle["rules"] {
  const value = record(input, "rules");
  exactKeys(value, ["path_normalization", "follow_symlinks", "redact_paths", "ordering", "merkle_rule", "include_globs", "exclude_globs", "allowed_suffixes"], "rules");
  const include_globs = stringArray(value.include_globs, "include_globs", 256);
  const exclude_globs = stringArray(value.exclude_globs, "exclude_globs", 256);
  const allowed_suffixes = stringArray(value.allowed_suffixes, "allowed_suffixes", 64, true);
  return {
    path_normalization: literal(value.path_normalization, "posix_rel_no_dotdot", "path_normalization"),
    follow_symlinks: flag(value.follow_symlinks, "follow_symlinks"),
    redact_paths: flag(value.redact_paths, "redact_paths"),
    ordering: literal(value.ordering, "path_rel_ascii_asc", "ordering"),
    merkle_rule: literal(value.merkle_rule, "dup_last_on_odd", "merkle_rule"),
    ...(include_globs !== undefined ? { include_globs } : {}),
    ...(exclude_globs !== undefined ? { exclude_globs } : {}),
    ...(allowed_suffixes !== undefined ? { allowed_suffixes } : {}),
  };
}

function parseFile(input: unknown, redact: boolean): DatasetFile {
  const value = record(input, "file");
  exactKeys(value, ["path_rel", "path_hash", "bytes", "sha3_512", "leaf_hash"], "file");
  const path_rel = optionalString(value.path_rel, "path_rel", 4096);
  const path_hash = value.path_hash === undefined ? undefined : digest(value.path_hash, "path_hash");
  if (Boolean(path_rel) === Boolean(path_hash)) invalid("file.path_variant");
  if (redact !== Boolean(path_hash)) invalid("file.redact_paths");
  return {
    ...(path_rel ? { path_rel } : {}),
    ...(path_hash ? { path_hash } : {}),
    bytes: count(value.bytes, "file.bytes"),
    sha3_512: digest(value.sha3_512, "file.sha3_512"),
    leaf_hash: digest(value.leaf_hash, "file.leaf_hash"),
  };
}

function parseBundle(input: unknown): DatasetBundle {
  const value = record(input, "bundle");
  exactKeys(value, ["bundle_version", "hash_contract", "dataset_identity", "rules", "files", "merkle", "summary"], "bundle");
  literal(value.bundle_version, "v1", "bundle_version");
  const contract = record(value.hash_contract, "hash_contract");
  exactKeys(contract, Object.keys(HASH_CONTRACT), "hash_contract");
  for (const [key, expected] of Object.entries(HASH_CONTRACT)) {
    if (contract[key] !== expected) invalid(`hash_contract.${key}`);
  }
  const parsedIdentity = identity(value.dataset_identity);
  const parsedRules = rules(value.rules);
  if (!Array.isArray(value.files) || value.files.length === 0 || value.files.length > MAX_FILES) invalid("files");
  const files = value.files.map((file) => parseFile(file, parsedRules.redact_paths));
  // The producer orders by original relative path. Redacted path hashes are not sort keys.
  if (!parsedRules.redact_paths) {
    for (let index = 1; index < files.length; index++) {
      if ((files[index - 1]?.path_rel ?? "") >= (files[index]?.path_rel ?? "")) invalid("files.path_order");
    }
  }
  const merkle = record(value.merkle, "merkle");
  exactKeys(merkle, ["leaf_count", "root"], "merkle");
  const summary = record(value.summary, "summary");
  exactKeys(summary, ["file_count", "total_bytes"], "summary");
  return {
    bundle_version: "v1",
    hash_contract: HASH_CONTRACT,
    dataset_identity: parsedIdentity,
    rules: parsedRules,
    files,
    merkle: { leaf_count: count(merkle.leaf_count, "merkle.leaf_count"), root: digest(merkle.root, "merkle.root") },
    summary: { file_count: count(summary.file_count, "summary.file_count"), total_bytes: count(summary.total_bytes, "summary.total_bytes") },
  };
}

/** Safely duplicate receipt metadata while retaining the bytes relevant to its digest. */
function jsonValue(value: unknown, depth: number, budget: { nodes: number }): unknown {
  budget.nodes += 1;
  if (budget.nodes > MAX_METADATA_NODES || depth > MAX_JSON_DEPTH) invalid("receipt.metadata_limit");
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) {
    if (value.length > 256) invalid("receipt.metadata_array");
    return value.map((item) => jsonValue(item, depth + 1, budget));
  }
  const source = record(value, "receipt.metadata");
  const output: JsonRecord = Object.create(null) as JsonRecord;
  for (const key of Object.keys(source)) {
    if (key === "__proto__" || key === "prototype" || key === "constructor") invalid("receipt.metadata_key");
    output[key] = jsonValue(source[key], depth + 1, budget);
  }
  return output;
}

function optionalNetwork(value: unknown): "testnet" | "mainnet" | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string") return invalid("hedera_network");
  const network = value.trim().toLowerCase();
  if (network !== "testnet" && network !== "mainnet") invalid("hedera_network");
  return network as "testnet" | "mainnet";
}

function parsedReceipt(input: unknown): Readonly<{
  body: JsonRecord;
  dataset_identity: DatasetBundle["dataset_identity"];
  evidence: Readonly<{ dataset_fingerprint: string; bundle_digest: string; merkle_root: string; idempotency_key: string; file_count: number; total_bytes: number }>;
  hedera_network?: "mainnet" | "testnet";
}> {
  const value = record(input, "receipt");
  exactKeys(value, ["v", "kind", "receipt_id", "mode", "hedera_network", "dataset_identity", "rules", "evidence", "pointers", "core"], "receipt");
  literal(value.v, "v1", "v");
  literal(value.kind, "dataset_anchor_receipt", "kind");
  const receiptId = digest(value.receipt_id, "receipt_id");
  const mode = value.mode;
  if (mode !== "hash_only" && mode !== "register_and_anchor") invalid("mode");
  const network = optionalNetwork(value.hedera_network);
  if (mode === "hash_only" && network) invalid("hash_only.hedera_network");
  const parsedIdentity = identity(value.dataset_identity);
  const receiptRules = jsonValue(value.rules, 0, { nodes: 0 });
  record(receiptRules, "receipt.rules");
  const rawEvidence = record(value.evidence, "receipt.evidence");
  exactKeys(rawEvidence, ["dataset_fingerprint", "bundle_digest", "merkle_root", "idempotency_key", "file_count", "total_bytes"], "receipt.evidence");
  const evidence = {
    dataset_fingerprint: digest(rawEvidence.dataset_fingerprint, "evidence.dataset_fingerprint"),
    bundle_digest: digest(rawEvidence.bundle_digest, "evidence.bundle_digest"),
    merkle_root: digest(rawEvidence.merkle_root, "evidence.merkle_root"),
    idempotency_key: digest(rawEvidence.idempotency_key, "evidence.idempotency_key"),
    file_count: count(rawEvidence.file_count, "evidence.file_count"),
    total_bytes: count(rawEvidence.total_bytes, "evidence.total_bytes"),
  };
  const output: JsonRecord = {
    v: "v1",
    kind: "dataset_anchor_receipt",
    receipt_id: receiptId,
    mode,
    ...(network ? { hedera_network: network } : {}),
    dataset_identity: parsedIdentity,
    rules: receiptRules,
    evidence,
  };
  if (value.pointers !== undefined) {
    const rawPointers = record(value.pointers, "receipt.pointers");
    exactKeys(rawPointers, ["evidence_pointer"], "receipt.pointers");
    const pointer = optionalString(rawPointers.evidence_pointer, "evidence_pointer", 2048);
    output.pointers = pointer === undefined ? {} : { evidence_pointer: pointer };
  }
  if (value.core !== undefined && value.core !== null) output.core = jsonValue(value.core, 0, { nodes: 0 });
  return { body: output, dataset_identity: parsedIdentity, evidence, ...(network ? { hedera_network: network } : {}) };
}

function jsonDigest(domain: string, value: unknown): string {
  return hashHfV1({ material: "json", domain, value });
}

function idempotencyKey(datasetKey: string, fingerprint: string): string {
  return jsonDigest("va:dataset:idem:v1", {
    dataset_key: datasetKey,
    fingerprint,
    sep: "\u0000",
    combined: `${datasetKey}\u0000${fingerprint}`,
  });
}

function mismatch(field: string, expected: unknown, actual: unknown): DatasetV1Mismatch {
  return Object.freeze({ field, expected, actual });
}

/** Verify Dataset v1 bundle commitments without filesystem or network access. */
export function verifyDatasetV1Bundle(input: unknown): DatasetV1VerificationResult<DatasetV1BundleComputed> {
  const bundle = parseBundle(input);
  const mismatches: DatasetV1Mismatch[] = [];
  const leaves: string[] = [];
  let totalBytes = 0;
  for (const [index, file] of bundle.files.entries()) {
    const recomputed = jsonDigest("va:dataset:leaf:v1", {
      ...(file.path_rel ? { path_rel: file.path_rel } : {}),
      ...(file.path_hash ? { path_hash: file.path_hash } : {}),
      bytes: file.bytes,
      sha3_512: file.sha3_512,
    });
    if (file.leaf_hash !== recomputed) mismatches.push(mismatch(`files[${index}].leaf_hash`, recomputed, file.leaf_hash));
    leaves.push(recomputed);
    totalBytes += file.bytes;
    if (!Number.isSafeInteger(totalBytes)) invalid("summary.total_bytes_overflow");
  }
  let level = leaves;
  while (level.length > 1) {
    const next: string[] = [];
    for (let index = 0; index < level.length; index += 2) {
      const left = level[index];
      if (!left) invalid("merkle.left");
      const right = level[index + 1] ?? left;
      next.push(hashHfV1({ material: "raw", domain: "va:dataset:node:v1", bytes: Buffer.from(left + right, "hex") }));
    }
    level = next;
  }
  const merkleRoot = level[0];
  if (!merkleRoot) invalid("merkle.empty");
  const bundleDigest = jsonDigest("va:dataset:bundle:v1", bundle);
  const fingerprint = jsonDigest("va:dataset:fingerprint:v1", bundle);
  const idempotency = idempotencyKey(bundle.dataset_identity.dataset_key, fingerprint);
  if (bundle.merkle.leaf_count !== bundle.files.length) mismatches.push(mismatch("merkle.leaf_count", bundle.files.length, bundle.merkle.leaf_count));
  if (bundle.merkle.root !== merkleRoot) mismatches.push(mismatch("merkle.root", merkleRoot, bundle.merkle.root));
  if (bundle.summary.file_count !== bundle.files.length) mismatches.push(mismatch("summary.file_count", bundle.files.length, bundle.summary.file_count));
  if (bundle.summary.total_bytes !== totalBytes) mismatches.push(mismatch("summary.total_bytes", totalBytes, bundle.summary.total_bytes));
  return Object.freeze({
    ok: mismatches.length === 0,
    mismatches: Object.freeze(mismatches),
    computed: Object.freeze({
      dataset_key: bundle.dataset_identity.dataset_key,
      program: bundle.dataset_identity.program ?? null,
      version_label: bundle.dataset_identity.version_label ?? null,
      bundle_digest: bundleDigest,
      dataset_fingerprint: fingerprint,
      merkle_root: merkleRoot,
      idempotency_key: idempotency,
      file_count: bundle.files.length,
      total_bytes: totalBytes,
    }),
  });
}

/** Verify receipt consistency; no claim of external anchoring or content availability. */
export function verifyDatasetV1Receipt(input: unknown): DatasetV1VerificationResult<DatasetV1ReceiptComputed> {
  const parsed = parsedReceipt(input);
  const { receipt_id: receiptId, ...body } = parsed.body;
  const recalculatedReceiptId = jsonDigest("va:dataset:receipt:v1", body);
  const recalculatedIdem = idempotencyKey(parsed.dataset_identity.dataset_key, parsed.evidence.dataset_fingerprint);
  const mismatches: DatasetV1Mismatch[] = [];
  if (receiptId !== recalculatedReceiptId) mismatches.push(mismatch("receipt_id", recalculatedReceiptId, receiptId));
  if (parsed.evidence.idempotency_key !== recalculatedIdem) mismatches.push(mismatch("evidence.idempotency_key", recalculatedIdem, parsed.evidence.idempotency_key));
  return Object.freeze({
    ok: mismatches.length === 0,
    mismatches: Object.freeze(mismatches),
    computed: Object.freeze({
      dataset_key: parsed.dataset_identity.dataset_key,
      program: parsed.dataset_identity.program ?? null,
      version_label: parsed.dataset_identity.version_label ?? null,
      receipt_id: recalculatedReceiptId,
      hedera_network: parsed.hedera_network ?? null,
      idempotency_key: recalculatedIdem,
      dataset_fingerprint: parsed.evidence.dataset_fingerprint,
      bundle_digest: parsed.evidence.bundle_digest,
      merkle_root: parsed.evidence.merkle_root,
      file_count: parsed.evidence.file_count,
      total_bytes: parsed.evidence.total_bytes,
    }),
  });
}
