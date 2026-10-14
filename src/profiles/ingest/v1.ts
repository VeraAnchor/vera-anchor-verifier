import { hashHfV1 } from "../../hf/hashContractV1.js";

const HEX = /^[0-9a-f]{128}$/;
const OBJECT_KEY = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/;
const PROGRAM = /^[a-z][a-z0-9_:-]{1,63}$/;
const YMD = /^\d{4}-\d{2}-\d{2}$/;
const MAX_ITEMS = 5_000;
const MAX_META_DEPTH = 8;
const MAX_META_NODES = 20_000;

type RecordValue = Record<string, unknown>;
type Network = "testnet" | "mainnet";
type ObjectKind = "json" | "text" | "file" | "file_set";
type ItemKind = Exclude<ObjectKind, "file_set">;

export type IngestV1Mismatch = Readonly<{ field: string; expected: unknown; actual: unknown }>;
export type IngestV1Result<T> = Readonly<{
  ok: boolean;
  mismatches: readonly IngestV1Mismatch[];
  computed: T;
}>;
export type IngestV1BundleComputed = Readonly<{
  object_key: string;
  object_kind: ObjectKind;
  program: string | null;
  version_label: string | null;
  bundle_digest: string;
  fingerprint: string;
  idempotency_key: string;
  merkle_root?: string;
  item_count: number;
  total_bytes: number;
}>;
export type IngestV1ReceiptComputed = Readonly<{
  hedera_network: Network | null;
  object_key: string;
  object_kind: ObjectKind;
  program: string | null;
  version_label: string | null;
  receipt_id: string;
  idempotency_key: string;
  fingerprint: string;
  bundle_digest: string;
  merkle_root: string | null;
  item_count: number;
  total_bytes: number;
  receipt_anchor_id: unknown;
  receipt_anchor_hash: unknown;
  receipt_leaf_id: unknown;
  receipt_leaf_hash: unknown;
  receipt_payload_hash: unknown;
  receipt_hcs_transaction_id: unknown;
  receipt_hcs_message_id: unknown;
  root_anchor_id: unknown;
  root_anchor_hash: unknown;
  root_id: unknown;
  anchored_root_hash: unknown;
  root_hcs_transaction_id: unknown;
  root_hcs_message_id: unknown;
}>;

const HASH_CONTRACT = Object.freeze({
  contract_id: "hf-contract-v1",
  frame: "hf:frame:v1",
  canonical_json: "hf:canonical-json:v1",
  algorithm: "sha3-512",
  encoding: "hex_lower",
});

type Identity = Readonly<{ object_key: string; object_kind: ObjectKind; program?: string; version_label?: string }>;
type Rules = Readonly<{
  path_normalization: "posix_rel_no_dotdot";
  follow_symlinks: boolean;
  redact_paths: boolean;
  normalize_line_endings: boolean;
  ordering: "deterministic_sort_v1";
  merkle_rule: "dup_last_on_odd";
  include_globs?: readonly string[];
  exclude_globs?: readonly string[];
  allowed_suffixes?: readonly string[];
}>;
type Item = Readonly<{
  item_kind: ItemKind;
  path_rel?: string;
  path_hash?: string;
  media_type?: string;
  bytes: number;
  sha3_512: string;
  leaf_hash: string;
}>;
type Bundle = Readonly<{
  bundle_version: "v1";
  hash_contract: typeof HASH_CONTRACT;
  identity: Identity;
  rules: Rules;
  items: readonly Item[];
  merkle?: Readonly<{ leaf_count: number; root: string }>;
  summary: Readonly<{ item_count: number; total_bytes: number }>;
}>;
type Receipt = Readonly<{
  body: RecordValue;
  receipt_id: string;
  hedera_network?: Network;
  identity: Identity;
  rules: Rules;
  evidence: Readonly<{
    fingerprint: string;
    bundle_digest: string;
    merkle_root?: string;
    idempotency_key: string;
    item_count: number;
    total_bytes: number;
  }>;
  receipt_anchor?: RecordValue;
  root_anchor?: RecordValue;
}>;

function invalid(field: string): never {
  throw new TypeError(`Invalid Ingest v1 evidence: ${field}`);
}
function object(input: unknown, field: string): RecordValue {
  if (input === null || typeof input !== "object" || Array.isArray(input)) return invalid(field);
  const proto: unknown = Object.getPrototypeOf(input);
  if (proto !== Object.prototype && proto !== null) return invalid(field);
  return input as RecordValue;
}
function keys(input: RecordValue, allowed: readonly string[], field: string): void {
  for (const key of Object.keys(input)) if (!allowed.includes(key)) invalid(`${field}.${key}`);
}
function text(input: unknown, field: string, max: number): string {
  if (typeof input !== "string") return invalid(field);
  const value = input.trim();
  if (!value || value.length > max) return invalid(field);
  return value;
}
function optionalText(input: unknown, field: string, max: number): string | undefined {
  if (input === undefined || input === null) return undefined;
  if (typeof input !== "string") return invalid(field);
  const value = input.trim();
  if (value.length > max) return invalid(field);
  return value || undefined;
}
function digest(input: unknown, field: string): string {
  const value = text(input, field, 128).toLowerCase();
  if (!HEX.test(value)) return invalid(field);
  return value;
}
function optionalDigest(input: unknown, field: string): string | undefined {
  return input === undefined || input === null ? undefined : digest(input, field);
}
function integer(input: unknown, field: string): number {
  if (typeof input !== "number" || !Number.isSafeInteger(input) || input < 0) return invalid(field);
  return input;
}
function bool(input: unknown, field: string): boolean {
  if (typeof input === "boolean") return input;
  if (typeof input === "string") {
    const value = input.trim().toLowerCase();
    if (value === "true") return true;
    if (value === "false") return false;
  }
  return invalid(field);
}
function literal<T extends string>(input: unknown, expected: T, field: string): T {
  if (input !== expected) return invalid(field);
  return expected;
}
function kind(input: unknown): ObjectKind {
  if (input !== "json" && input !== "text" && input !== "file" && input !== "file_set") return invalid("object_kind");
  return input;
}
function identity(input: unknown): Identity {
  const value = object(input, "identity");
  keys(value, ["object_key", "object_kind", "version_label", "program"], "identity");
  const object_key = text(value.object_key, "identity.object_key", 256);
  if (!OBJECT_KEY.test(object_key)) invalid("identity.object_key");
  const object_kind = kind(value.object_kind);
  const version_label = optionalText(value.version_label, "identity.version_label", 64);
  const program = optionalText(value.program, "identity.program", 64);
  if (program !== undefined && !PROGRAM.test(program)) invalid("identity.program");
  return { object_key, object_kind, ...(version_label !== undefined ? { version_label } : {}), ...(program !== undefined ? { program } : {}) };
}
function stringArray(input: unknown, field: string, max: number, lower = false): readonly string[] | undefined {
  if (input === undefined || input === null) return undefined;
  if (!Array.isArray(input) || input.length > 256) return invalid(field);
  const output: string[] = [];
  for (const item of input) {
    if (typeof item !== "string") return invalid(field);
    const value = item.trim();
    if (!value) continue;
    if (value.length > max) invalid(field);
    output.push(lower ? value.toLowerCase() : value);
  }
  return output;
}
function rules(input: unknown): Rules {
  const value = object(input, "rules");
  keys(value, ["path_normalization", "follow_symlinks", "redact_paths", "normalize_line_endings", "ordering", "merkle_rule", "include_globs", "exclude_globs", "allowed_suffixes"], "rules");
  const include_globs = stringArray(value.include_globs, "rules.include_globs", 256);
  const exclude_globs = stringArray(value.exclude_globs, "rules.exclude_globs", 256);
  const allowed_suffixes = stringArray(value.allowed_suffixes, "rules.allowed_suffixes", 64, true);
  if (allowed_suffixes?.some((suffix) => !suffix.startsWith("."))) invalid("rules.allowed_suffixes");
  return {
    path_normalization: literal(value.path_normalization, "posix_rel_no_dotdot", "rules.path_normalization"),
    follow_symlinks: bool(value.follow_symlinks, "rules.follow_symlinks"),
    redact_paths: bool(value.redact_paths, "rules.redact_paths"),
    normalize_line_endings: bool(value.normalize_line_endings, "rules.normalize_line_endings"),
    ordering: literal(value.ordering, "deterministic_sort_v1", "rules.ordering"),
    merkle_rule: literal(value.merkle_rule, "dup_last_on_odd", "rules.merkle_rule"),
    ...(include_globs !== undefined ? { include_globs } : {}),
    ...(exclude_globs !== undefined ? { exclude_globs } : {}),
    ...(allowed_suffixes !== undefined ? { allowed_suffixes } : {}),
  };
}
function normalizedPath(input: unknown): string {
  const path = text(input, "item.path_rel", 1024).replace(/\\/g, "/");
  if (path.startsWith("/") || path.split("/").some((segment) => !segment || segment === "." || segment === "..")) invalid("item.path_rel");
  if (path.includes("\0") || path.includes("..")) invalid("item.path_rel");
  return path;
}
function item(input: unknown, redact: boolean): Item {
  const value = object(input, "item");
  keys(value, ["item_kind", "path_rel", "path_hash", "media_type", "bytes", "sha3_512", "leaf_hash"], "item");
  const item_kind = kind(value.item_kind);
  if (item_kind === "file_set") invalid("item.item_kind");
  const path_rel = value.path_rel === undefined || value.path_rel === null ? undefined : normalizedPath(value.path_rel);
  const path_hash = optionalDigest(value.path_hash, "item.path_hash");
  const media_type = optionalText(value.media_type, "item.media_type", 256);
  if (item_kind === "file") {
    if (Boolean(path_rel) === Boolean(path_hash)) invalid("item.path_variant");
    if (redact !== Boolean(path_hash)) invalid("item.redact_paths");
  } else if (path_rel || path_hash) invalid("item.path_variant");
  return {
    item_kind,
    ...(path_rel ? { path_rel } : {}),
    ...(path_hash ? { path_hash } : {}),
    ...(media_type ? { media_type } : {}),
    bytes: integer(value.bytes, "item.bytes"),
    sha3_512: digest(value.sha3_512, "item.sha3_512"),
    leaf_hash: digest(value.leaf_hash, "item.leaf_hash"),
  };
}
function jsonValue(input: unknown, depth: number, budget: { nodes: number }): unknown {
  budget.nodes += 1;
  if (budget.nodes > MAX_META_NODES || depth > MAX_META_DEPTH) invalid("json.limit");
  if (input === null || typeof input === "string" || typeof input === "boolean") return input;
  if (typeof input === "number" && Number.isFinite(input)) return input;
  if (Array.isArray(input)) {
    if (input.length > 256) invalid("json.array");
    return input.map((value) => jsonValue(value, depth + 1, budget));
  }
  const source = object(input, "json");
  const output: RecordValue = Object.create(null) as RecordValue;
  for (const key of Object.keys(source)) {
    if (key === "__proto__" || key === "prototype" || key === "constructor" || key.length > 256) invalid("json.key");
    output[key] = jsonValue(source[key], depth + 1, budget);
  }
  return output;
}
function bundle(input: unknown): Bundle {
  const value = object(input, "bundle");
  keys(value, ["bundle_version", "hash_contract", "identity", "rules", "items", "merkle", "summary"], "bundle");
  literal(value.bundle_version, "v1", "bundle_version");
  const contract = object(value.hash_contract, "hash_contract");
  keys(contract, Object.keys(HASH_CONTRACT), "hash_contract");
  for (const [name, expected] of Object.entries(HASH_CONTRACT)) if (contract[name] !== expected) invalid(`hash_contract.${name}`);
  const parsedIdentity = identity(value.identity);
  const parsedRules = rules(value.rules);
  if (!Array.isArray(value.items) || value.items.length === 0 || value.items.length > MAX_ITEMS) invalid("items");
  const items = value.items.map((entry) => item(entry, parsedRules.redact_paths));
  if (parsedIdentity.object_kind === "file_set" && items.some((entry) => entry.item_kind !== "file")) invalid("items.item_kind");
  if (parsedIdentity.object_kind !== "file_set" && (items.length !== 1 || items[0]?.item_kind !== parsedIdentity.object_kind)) invalid("items.item_kind");
  const rawSummary = object(value.summary, "summary");
  keys(rawSummary, ["item_count", "total_bytes"], "summary");
  let merkle: Bundle["merkle"];
  if (value.merkle !== undefined) {
    const raw = object(value.merkle, "merkle");
    keys(raw, ["leaf_count", "root"], "merkle");
    merkle = { leaf_count: integer(raw.leaf_count, "merkle.leaf_count"), root: digest(raw.root, "merkle.root") };
  }
  return {
    bundle_version: "v1",
    hash_contract: HASH_CONTRACT,
    identity: parsedIdentity,
    rules: parsedRules,
    items,
    ...(merkle ? { merkle } : {}),
    summary: { item_count: integer(rawSummary.item_count, "summary.item_count"), total_bytes: integer(rawSummary.total_bytes, "summary.total_bytes") },
  };
}
function network(input: unknown): Network | undefined {
  if (input === undefined || input === null) return undefined;
  if (typeof input !== "string") return invalid("hedera_network");
  const value = input.trim().toLowerCase();
  if (value !== "mainnet" && value !== "testnet") invalid("hedera_network");
  return value as Network;
}
function receipt(input: unknown): Receipt {
  const value = object(input, "receipt");
  keys(value, ["v", "kind", "receipt_id", "hedera_network", "mode", "identity", "rules", "evidence", "anchor", "pointers", "metadata", "core"], "receipt");
  literal(value.v, "v1", "receipt.v");
  literal(value.kind, "ingest_receipt", "receipt.kind");
  const receipt_id = digest(value.receipt_id, "receipt.receipt_id");
  const mode = value.mode;
  if (mode !== "hash_only" && mode !== "merkle_only" && mode !== "register_and_anchor") invalid("receipt.mode");
  const hedera_network = network(value.hedera_network);
  if (hedera_network && mode !== "register_and_anchor") invalid("receipt.local_network");
  const parsedIdentity = identity(value.identity);
  const parsedRules = rules(value.rules);
  const rawEvidence = object(value.evidence, "receipt.evidence");
  keys(rawEvidence, ["fingerprint", "bundle_digest", "merkle_root", "idempotency_key", "item_count", "total_bytes"], "receipt.evidence");
  const evidence = {
    fingerprint: digest(rawEvidence.fingerprint, "evidence.fingerprint"),
    bundle_digest: digest(rawEvidence.bundle_digest, "evidence.bundle_digest"),
    ...(rawEvidence.merkle_root !== undefined ? { merkle_root: digest(rawEvidence.merkle_root, "evidence.merkle_root") } : {}),
    idempotency_key: digest(rawEvidence.idempotency_key, "evidence.idempotency_key"),
    item_count: integer(rawEvidence.item_count, "evidence.item_count"),
    total_bytes: integer(rawEvidence.total_bytes, "evidence.total_bytes"),
  };
  const body: RecordValue = {
    v: "v1", kind: "ingest_receipt", ...(hedera_network ? { hedera_network } : {}), mode,
    identity: parsedIdentity, rules: parsedRules, evidence,
  };
  if (value.anchor !== undefined) {
    const raw = object(value.anchor, "receipt.anchor");
    keys(raw, ["domain", "proof_date"], "receipt.anchor");
    const domain = optionalText(raw.domain, "anchor.domain", 256);
    const proof_date = optionalText(raw.proof_date, "anchor.proof_date", 10);
    if (proof_date && !YMD.test(proof_date)) invalid("anchor.proof_date");
    body.anchor = { ...(domain ? { domain } : {}), ...(proof_date ? { proof_date } : {}) };
  }
  if (mode === "register_and_anchor") {
    const anchor = body.anchor as RecordValue | undefined;
    if (!anchor?.domain || !anchor?.proof_date) invalid("receipt.anchor_required");
  }
  if (value.pointers !== undefined) {
    const raw = object(value.pointers, "receipt.pointers");
    keys(raw, ["evidence_pointer"], "receipt.pointers");
    const pointer = optionalText(raw.evidence_pointer, "pointers.evidence_pointer", 2048);
    if (pointer) body.pointers = { evidence_pointer: pointer };
  }
  if (value.metadata !== undefined) body.metadata = jsonValue(value.metadata, 0, { nodes: 0 });
  let receipt_anchor: RecordValue | undefined;
  let root_anchor: RecordValue | undefined;
  if (value.core !== undefined) {
    const raw = object(value.core, "receipt.core");
    keys(raw, ["receipt_anchor", "root_anchor"], "receipt.core");
    const projected: RecordValue = {};
    if (raw.receipt_anchor !== undefined) {
      receipt_anchor = jsonValue(raw.receipt_anchor, 0, { nodes: 0 }) as RecordValue;
      object(receipt_anchor, "core.receipt_anchor");
      projected.receipt_anchor = receipt_anchor;
    }
    if (raw.root_anchor !== undefined) {
      root_anchor = jsonValue(raw.root_anchor, 0, { nodes: 0 }) as RecordValue;
      object(root_anchor, "core.root_anchor");
      projected.root_anchor = root_anchor;
    }
    if (Object.keys(projected).length) body.core = projected;
  }
  return { body, receipt_id, identity: parsedIdentity, rules: parsedRules, evidence, ...(hedera_network ? { hedera_network } : {}), ...(receipt_anchor ? { receipt_anchor } : {}), ...(root_anchor ? { root_anchor } : {}) };
}
function jsonHash(domain: string, value: unknown): string {
  return hashHfV1({ material: "json", domain, value });
}
function idem(key: string, fingerprint: string): string {
  return jsonHash("va:ingest:idem:v1", { object_key: key, fingerprint, sep: "\u0000", combined: `${key}\u0000${fingerprint}` });
}
function mismatch(field: string, expected: unknown, actual: unknown): IngestV1Mismatch {
  return Object.freeze({ field, expected, actual });
}
function computedRoot(items: readonly Item[]): string {
  let level = items.map((entry) => entry.leaf_hash);
  while (level.length > 1) {
    const next: string[] = [];
    for (let index = 0; index < level.length; index += 2) {
      const left = level[index];
      if (!left) invalid("merkle.left");
      const right = level[index + 1] ?? left;
      next.push(hashHfV1({ material: "raw", domain: "va:ingest:node:v1", bytes: Buffer.from(left + right, "hex") }));
    }
    level = next;
  }
  const root = level[0];
  if (!root) invalid("merkle.empty");
  return root;
}

/** Check Ingest bundle commitments and declared Merkle root; leaf hashes remain supplied claims. */
export function verifyIngestV1Bundle(input: unknown): IngestV1Result<IngestV1BundleComputed> {
  const parsed = bundle(input);
  const mismatches: IngestV1Mismatch[] = [];
  const root = parsed.merkle ? computedRoot(parsed.items) : undefined;
  let totalBytes = 0;
  for (const entry of parsed.items) {
    totalBytes += entry.bytes;
    if (!Number.isSafeInteger(totalBytes)) invalid("summary.total_bytes_overflow");
  }
  if (parsed.summary.item_count !== parsed.items.length) mismatches.push(mismatch("summary.item_count", parsed.items.length, parsed.summary.item_count));
  if (parsed.summary.total_bytes !== totalBytes) mismatches.push(mismatch("summary.total_bytes", totalBytes, parsed.summary.total_bytes));
  if (parsed.merkle && parsed.merkle.leaf_count !== parsed.items.length) mismatches.push(mismatch("merkle.leaf_count", parsed.items.length, parsed.merkle.leaf_count));
  if (parsed.merkle && parsed.merkle.root !== root) mismatches.push(mismatch("merkle.root", root, parsed.merkle.root));
  const fingerprint = jsonHash("va:ingest:fingerprint:v1", parsed);
  return Object.freeze({
    ok: mismatches.length === 0,
    mismatches: Object.freeze(mismatches),
    computed: Object.freeze({
      object_key: parsed.identity.object_key,
      object_kind: parsed.identity.object_kind,
      program: parsed.identity.program ?? null,
      version_label: parsed.identity.version_label ?? null,
      bundle_digest: jsonHash("va:ingest:bundle:v1", parsed),
      fingerprint,
      idempotency_key: idem(parsed.identity.object_key, fingerprint),
      ...(root ? { merkle_root: root } : {}),
      item_count: parsed.items.length,
      total_bytes: totalBytes,
    }),
  });
}

function embeddedNetwork(mismatches: IngestV1Mismatch[], expected: Network | undefined, field: string, raw: unknown): void {
  if (!expected || raw === undefined) return;
  const source = object(raw, field);
  if (Object.hasOwn(source, "hedera_network")) {
    const actual = String(source.hedera_network ?? "").trim().toLowerCase();
    if (actual !== expected) mismatches.push(mismatch(`${field}.hedera_network`, expected, source.hedera_network ?? null));
  }
  if (Object.hasOwn(source, "publish")) {
    const publish = object(source.publish, `${field}.publish`);
    if (Object.hasOwn(publish, "hedera_network")) {
      const actual = String(publish.hedera_network ?? "").trim().toLowerCase();
      if (actual !== expected) mismatches.push(mismatch(`${field}.publish.hedera_network`, expected, publish.hedera_network ?? null));
    }
  }
}

/** Check Ingest receipt cryptographic self-consistency; not Hedera corroboration. */
export function verifyIngestV1Receipt(input: unknown): IngestV1Result<IngestV1ReceiptComputed> {
  const parsed = receipt(input);
  const calculatedReceiptId = jsonHash("va:ingest:receipt:v1", parsed.body);
  const calculatedIdem = idem(parsed.identity.object_key, parsed.evidence.fingerprint);
  const mismatches: IngestV1Mismatch[] = [];
  if (parsed.receipt_id !== calculatedReceiptId) mismatches.push(mismatch("receipt_id", calculatedReceiptId, parsed.receipt_id));
  if (parsed.evidence.idempotency_key !== calculatedIdem) mismatches.push(mismatch("evidence.idempotency_key", calculatedIdem, parsed.evidence.idempotency_key));
  embeddedNetwork(mismatches, parsed.hedera_network, "core.receipt_anchor", parsed.receipt_anchor);
  embeddedNetwork(mismatches, parsed.hedera_network, "core.root_anchor", parsed.root_anchor);
  const ra = parsed.receipt_anchor;
  const root = parsed.root_anchor;
  return Object.freeze({
    ok: mismatches.length === 0,
    mismatches: Object.freeze(mismatches),
    computed: Object.freeze({
      hedera_network: parsed.hedera_network ?? null,
      object_key: parsed.identity.object_key,
      object_kind: parsed.identity.object_kind,
      program: parsed.identity.program ?? null,
      version_label: parsed.identity.version_label ?? null,
      receipt_id: calculatedReceiptId,
      idempotency_key: calculatedIdem,
      fingerprint: parsed.evidence.fingerprint,
      bundle_digest: parsed.evidence.bundle_digest,
      merkle_root: parsed.evidence.merkle_root ?? null,
      item_count: parsed.evidence.item_count,
      total_bytes: parsed.evidence.total_bytes,
      receipt_anchor_id: ra?.id ?? null,
      receipt_anchor_hash: ra?.anchor_hash ?? null,
      receipt_leaf_id: ra?.leaf_id ?? null,
      receipt_leaf_hash: ra?.leaf_hash ?? null,
      receipt_payload_hash: ra?.payload_hash ?? null,
      receipt_hcs_transaction_id: ra?.hcs_transaction_id ?? null,
      receipt_hcs_message_id: ra?.hcs_message_id ?? null,
      root_anchor_id: root?.id ?? null,
      root_anchor_hash: root?.anchor_hash ?? null,
      root_id: root?.root_id ?? null,
      anchored_root_hash: root?.root_hash ?? null,
      root_hcs_transaction_id: root?.hcs_transaction_id ?? null,
      root_hcs_message_id: root?.hcs_message_id ?? null,
    }),
  });
}

/** Cross-check separately supplied bundle and receipt; neither is an external authenticity witness. */
export function verifyIngestV1Pair(input: Readonly<{ bundle: unknown; receipt: unknown }>): IngestV1Result<Readonly<{
  bundle: IngestV1BundleComputed;
  receipt: IngestV1ReceiptComputed;
}>> {
  const bundleResult = verifyIngestV1Bundle(input.bundle);
  const receiptResult = verifyIngestV1Receipt(input.receipt);
  const parsedBundle = bundle(input.bundle);
  const parsedReceipt = receipt(input.receipt);
  const mismatches: IngestV1Mismatch[] = [
    ...bundleResult.mismatches.map((entry) => mismatch(`bundle.${entry.field}`, entry.expected, entry.actual)),
    ...receiptResult.mismatches.map((entry) => mismatch(`receipt.${entry.field}`, entry.expected, entry.actual)),
  ];
  const actual = receiptResult.computed;
  const expected = bundleResult.computed;
  for (const field of ["object_key", "object_kind", "program", "version_label", "fingerprint", "bundle_digest", "merkle_root", "idempotency_key", "item_count", "total_bytes"] as const) {
    const fromBundle = field === "merkle_root" ? expected.merkle_root ?? null : expected[field];
    const fromReceipt = actual[field];
    if (fromBundle !== fromReceipt) mismatches.push(mismatch(`binding.${field}`, fromBundle, fromReceipt));
  }
  if (jsonHash("va:ingest:bundle:v1", parsedBundle.rules) !== jsonHash("va:ingest:bundle:v1", parsedReceipt.rules)) {
    mismatches.push(mismatch("binding.rules", "matches bundle rules", "mismatch"));
  }
  return Object.freeze({ ok: mismatches.length === 0, mismatches: Object.freeze(mismatches), computed: Object.freeze({ bundle: expected, receipt: actual }) });
}
