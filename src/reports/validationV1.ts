import type { VerificationReport, VerificationOutcome } from "../contracts/verification.js";
import { sha3_512Hex } from "../crypto/sha3.js";
import { canonicalizeVerificationCoreV1, computeVerificationCoreDigestV1 } from "./coreV1.js";
import { PORTABLE_VERIFICATION_REPORT_SCHEMA_VERSION } from "./portableV1.js";

const DOMAIN = "va:portable-verification-report:v1";
const MAX_BYTES = 1024 * 1024;
const TOPIC = /^0\.0\.[0-9]+$/;
const TRANSACTION = /^0\.0\.[0-9]+@[0-9]{1,12}\.[0-9]{9}$/;
const MAX_DEPTH = 32;
const MAX_NODES = 65_536;
const DIGEST = /^[0-9a-f]{128}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const ID = /^[a-z][a-z0-9._:-]{0,159}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const OUTCOMES = ["pass", "fail", "indeterminate", "unsupported", "skipped"];
const KINDS = ["verification", "execution", "independent_standards", "public_triangulation", "authorized_dataset_triangulation", "authorized_ingest_triangulation", "execution_triangulation"];
const RESOLUTION = ["resolved", "not_found", "unavailable", "invalid", "conflict", "verification_material_unavailable", "unsupported"];
const PUBLIC_RELATIONSHIPS = ["provided_public_record", "public_record_hedera", "provided_hedera"];
const AUTHORIZED_RELATIONSHIPS = ["provided_authorized", "authorized_hedera"];

type Json = null | string | number | boolean | Json[] | { [key: string]: Json };
type Row = Record<string, Json>;

export type PortableVerificationReportValidationV1 = Readonly<{
  status: "valid" | "invalid";
  reason_code: "PORTABLE_REPORT_INVALID" | "PORTABLE_CORE_DIGEST_MISMATCH" |
    "PORTABLE_REPORT_DIGEST_MISMATCH" | null;
  /** Validity means internal structure and content digests only. */
  authenticity: "not_checked";
  evidence_recomputation: "not_performed";
}>;

export type PortableVerificationReportComparisonV1 = Readonly<{
  status: "equivalent" | "different";
  differences: readonly ("kind" | "subject" | "intent" | "findings" | "observations" | "context")[];
  /** Comparing two saved reports does not independently verify either report's claims. */
  authenticity: "not_checked";
  evidence_recomputation: "not_performed";
}>;

type Checked = Readonly<{ kind: string; core: Row; context: Row; serialized: string }>;

function object(value: Json | undefined, name: string): Row {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`Invalid ${name}`);
  }
  return value as Row;
}

function shape(value: Json | undefined, name: string, keys: readonly string[]): Row {
  const row = object(value, name);
  const actual = Object.keys(row);
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) {
    throw new TypeError(`Invalid ${name} fields`);
  }
  return row;
}

function array(value: Json | undefined, name: string, limit: number): Json[] {
  if (!Array.isArray(value) || value.length > limit) throw new TypeError(`Invalid ${name}`);
  return value;
}

function string(value: Json | undefined, name: string, max = 256): string {
  if (typeof value !== "string" || !value || value.length > max || value.trim() !== value) {
    throw new TypeError(`Invalid ${name}`);
  }
  return value;
}

function maybeString(value: Json | undefined, name: string, max = 256): void {
  if (value !== null) string(value, name, max);
}

function oneOf(value: Json | undefined, name: string, allowed: readonly string[]): string {
  if (typeof value !== "string" || !allowed.includes(value)) throw new TypeError(`Invalid ${name}`);
  return value;
}

function identifier(value: Json | undefined, name: string): string {
  const result = string(value, name, 160);
  if (!ID.test(result)) throw new TypeError(`Invalid ${name}`);
  return result;
}

function hash(value: Json | undefined, name: string, re = DIGEST): string {
  if (typeof value !== "string" || !re.test(value)) throw new TypeError(`Invalid ${name}`);
  return value;
}

function cloneJson(value: unknown): Json {
  let nodes = 0;
  const ancestors = new Set<object>();
  const visit = (entry: unknown, depth: number): Json => {
    if (++nodes > MAX_NODES || depth > MAX_DEPTH) throw new RangeError("Portable report exceeds resource limit");
    if (entry === null || typeof entry === "boolean") return entry;
    if (typeof entry === "number") {
      if (!Number.isFinite(entry) || Object.is(entry, -0)) throw new TypeError("Invalid portable report number");
      return entry;
    }
    if (typeof entry === "string") {
      if (entry.length > MAX_BYTES || /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(entry)) {
        throw new TypeError("Invalid portable report string");
      }
      return entry;
    }
    if (!entry || typeof entry !== "object") throw new TypeError("Invalid portable report JSON value");
    if (ancestors.has(entry)) throw new TypeError("Cyclic portable report");
    ancestors.add(entry);
    try {
      if (Array.isArray(entry)) {
        if (entry.length > 512) throw new RangeError("Portable report array exceeds limit");
        return Array.from({ length: entry.length }, (_, i) => {
          if (!Object.hasOwn(entry, i)) throw new TypeError("Sparse portable report array");
          const descriptor = Object.getOwnPropertyDescriptor(entry, String(i));
          if (!descriptor || !("value" in descriptor)) throw new TypeError("Accessor in portable report");
          return visit(descriptor.value, depth + 1);
        });
      }
      const proto = Object.getPrototypeOf(entry);
      if (proto !== Object.prototype && proto !== null) throw new TypeError("Invalid portable report object");
      const keys = Object.keys(entry).sort();
      if (keys.length > 512) throw new RangeError("Portable report object exceeds limit");
      const pairs: [string, Json][] = [];
      for (const key of keys) {
        if (!key || key.length > 160 || /[\u0000-\u001f\u007f]/.test(key)) throw new TypeError("Invalid portable report field");
        const descriptor = Object.getOwnPropertyDescriptor(entry, key);
        if (!descriptor || !("value" in descriptor)) throw new TypeError("Accessor in portable report");
        pairs.push([key, visit(descriptor.value, depth + 1)]);
      }
      return Object.fromEntries(pairs) as Row;
    } finally {
      ancestors.delete(entry);
    }
  };
  const copy = visit(value, 0);
  // The on-disk envelope adds one digest field to the bounded canonical base.
  if (Buffer.byteLength(JSON.stringify(copy), "utf8") > MAX_BYTES + 256) {
    throw new RangeError("Portable report exceeds size limit");
  }
  return copy;
}

function finding(report: VerificationReport, id: string, outcome: VerificationOutcome, reason?: Json): void {
  const match = report.findings.find((f) => f.check_id === id);
  if (!match || match.outcome !== outcome || (reason !== undefined && match.reason_code !== reason)) {
    throw new TypeError(`Inconsistent portable finding: ${id}`);
  }
}

function scope(value: Json | undefined, report: VerificationReport): void {
  const row = shape(value, "execution scope", ["profile", "expected_program", "requested_result_id"]);
  if (report.intent.subject.kind !== "execution" || !report.intent.subject.hedera_network) {
    throw new TypeError("Invalid execution report subject");
  }
  const profile = oneOf(row.profile, "execution profile", ["execution-v1", "sage-standards-v1"]);
  maybeString(row.expected_program, "expected program", 128);
  if (row.requested_result_id !== null) {
    if (!UUID.test(string(row.requested_result_id, "result ID", 64))) throw new TypeError("Invalid result ID");
    const selected = report.findings.some((f) => f.check_id === "intent.result");
    if (!selected) throw new TypeError("Missing result-scope finding");
  }
  if (profile === "execution-v1" && row.expected_program === null) {
    throw new TypeError("Generic execution requires an expected program");
  }
}

function standards(value: Json | undefined, report: VerificationReport): void {
  const row = shape(value, "independent standards", ["network", "status", "assurance", "items"]);
  if (row.network !== report.intent.subject.hedera_network) throw new TypeError("Standards network mismatch");
  const state = oneOf(row.status, "standards status", ["verified", "failed", "unavailable", "not_performed"]);
  const assurance = oneOf(row.assurance, "standards assurance", ["mirror_corroborated", "not_established"]);
  const items = array(row.items, "standards items", 16);
  const seen = new Set<string>();
  let anyFailed = false;
  let allResolved = items.length > 0;
  items.forEach((item, index) => {
    const part = shape(item, "standards item", ["key", "standard", "reference", "status", "reason_code",
      "resolver_id", "historical_consensus_timestamps_exact", "current_topic_or_account_memo_observed",
      "content_sha256", "assurance"]);
    const key = string(part.key, "standards key");
    if (seen.has(key)) throw new TypeError("Duplicate standards key");
    seen.add(key);
    string(part.standard, "standard", 128);
    string(part.reference, "standards reference", 256);
    maybeString(part.reason_code, "standards reason", 160);
    maybeString(part.resolver_id, "resolver ID", 256);
    if (typeof part.current_topic_or_account_memo_observed !== "boolean") throw new TypeError("Invalid memo observation");
    if (part.content_sha256 !== null) hash(part.content_sha256, "standards content digest", SHA256);
    const status = oneOf(part.status, "standards item status", ["resolved", "conflict", "invalid", "unavailable", "unsupported"]);
    const times = array(part.historical_consensus_timestamps_exact, "historical timestamps", 16);
    times.forEach((time) => string(time, "historical timestamp", 128));
    if (part.assurance !== (status === "resolved" ? "mirror_corroborated" : "not_established")) {
      throw new TypeError("Inconsistent standards assurance");
    }
    anyFailed ||= status === "conflict" || status === "invalid";
    allResolved &&= status === "resolved";
    const expected: VerificationOutcome = status === "resolved" ? "pass" :
      status === "conflict" || status === "invalid" ? "fail" :
        status === "unsupported" ? "unsupported" : "indeterminate";
    finding(report, `standards.reference.${index}`, expected);
  });
  const expected = anyFailed ? "failed" : allResolved ? "verified" : items.length === 0 ? "not_performed" : "unavailable";
  if (state !== expected || assurance !== (state === "verified" ? "mirror_corroborated" : "not_established")) {
    throw new TypeError("Inconsistent standards summary");
  }
  finding(report, "standards.references_resolved", state === "verified" ? "pass" : state === "failed" ? "fail" : "indeterminate");
}

function relationships(
  value: Json | undefined,
  report: VerificationReport,
  allowedIds: readonly string[],
): Json[] {
  const entries = array(value, "triangulation relationships", 3);
  const seen = new Set<string>();
  for (const item of entries) {
    const rel = shape(item, "triangulation relationship", ["id", "status", "fact_comparisons"]);
    const id = oneOf(rel.id, "triangulation relationship ID", allowedIds);
    if (seen.has(id)) throw new TypeError("Duplicate triangulation relationship");
    seen.add(id);
    const state = oneOf(rel.status, "relationship status", ["consistent", "conflict", "incomplete", "not_applicable"]);
    const facts = array(rel.fact_comparisons, "fact comparisons", 64);
    const keys = new Set<string>();
    const outcomes: string[] = [];
    for (const comparison of facts) {
      const row = shape(comparison, "fact comparison", ["key", "outcome", "reason_code"]);
      const key = identifier(row.key, "comparison key");
      if (keys.has(key)) throw new TypeError("Duplicate comparison key");
      keys.add(key);
      const outcome = oneOf(row.outcome, "comparison outcome", OUTCOMES) as VerificationOutcome;
      if (row.reason_code !== null) string(row.reason_code, "comparison reason", 160);
      outcomes.push(outcome);
      finding(report, `triangulation.${id}.${key}`, outcome, row.reason_code);
    }
    const aggregate = outcomes.length === 0 || outcomes.every((o) => o === "skipped") ? "not_applicable" :
      outcomes.includes("fail") ? "conflict" :
        outcomes.some((o) => o === "indeterminate" || o === "unsupported") ? "incomplete" : "consistent";
    if (state !== aggregate) throw new TypeError("Inconsistent triangulation relationship");
  }
  return entries;
}

function consistency(value: Json | undefined, rels: Json[]): string {
  const state = oneOf(value, "triangulation consistency", ["consistent", "conflict", "incomplete"]);
  if (state === "consistent" && (rels.length === 0 || rels.some((rel) => object(rel, "relationship").status !== "consistent"))) {
    throw new TypeError("Incomplete triangulation cannot be consistent");
  }
  return state;
}

function publicExecution(value: Json | undefined, resolved: boolean): Row {
  const keys = ["status", "reason_code", "public_record_acquisition", "hedera_resolution"];
  if (resolved) keys.push("mirror_status", "mirror_reason_code");
  const row = shape(value, "public execution", keys);
  const status = oneOf(row.status, "execution resolution status", RESOLUTION);
  oneOf(row.public_record_acquisition, "public record acquisition", RESOLUTION);
  if (row.reason_code !== null) string(row.reason_code, "execution reason", 160);
  if (resolved) {
    if (row.public_record_acquisition !== "resolved") throw new TypeError("Unresolved execution acquisition");
    const mirror = oneOf(row.mirror_status, "Mirror status", RESOLUTION);
    if (row.hedera_resolution !== mirror) throw new TypeError("Mirror status mismatch");
    if (row.mirror_reason_code !== null) string(row.mirror_reason_code, "Mirror reason", 160);
    if (status === "not_found" && mirror === "resolved") throw new TypeError("Inconsistent execution status");
  } else if (row.public_record_acquisition === "resolved" || row.hedera_resolution !== "not_checked" ||
      status !== row.public_record_acquisition) {
    throw new TypeError("Invalid unresolved execution status");
  }
  return row;
}

function planRelationships(value: Json | undefined): void {
  const rows = array(value, "triangulation plan relationships", 3);
  const ids = new Set<string>();
  for (const value of rows) {
    const item = shape(value, "relationship plan", ["id", "left_observation_id", "right_observation_id", "comparisons"]);
    const id = oneOf(item.id, "plan relationship ID", PUBLIC_RELATIONSHIPS);
    if (ids.has(id)) throw new TypeError("Duplicate plan relationship");
    ids.add(id);
    const leftId = identifier(item.left_observation_id, "left observation ID");
    const rightId = identifier(item.right_observation_id, "right observation ID");
    if (leftId === rightId) throw new TypeError("Self-referential plan relationship");
    const keys = new Set<string>();
    for (const part of array(item.comparisons, "planned comparisons", 64)) {
      const comparison = shape(part, "comparison plan", ["key", "left_key", "right_key"]);
      const key = identifier(comparison.key, "plan comparison key");
      if (keys.has(key)) throw new TypeError("Duplicate planned comparison");
      keys.add(key);
      identifier(comparison.left_key, "planned left key");
      identifier(comparison.right_key, "planned right key");
    }
  }
}

function executionTargets(value: Json | undefined, report: VerificationReport): void {
  for (const targetValue of array(value, "Hedera targets", 64)) {
    const target = shape(targetValue, "Hedera target", ["source", "role", "network", "transaction_id", "topic_id", "sequence_number", "observation_fact_prefix"]);
    oneOf(target.source, "target source", ["provided_evidence", "public_record"]);
    oneOf(target.role, "target role", ["acceptance_anchor", "result_evidence_anchor"]);
    if (target.network !== report.intent.subject.hedera_network) throw new TypeError("Target network mismatch");
    maybeString(target.transaction_id, "target transaction", 128);
    maybeString(target.topic_id, "target topic", 64);
    if (target.transaction_id !== null && !TRANSACTION.test(target.transaction_id as string)) {
      throw new TypeError("Invalid Hedera transaction locator");
    }
    if (target.topic_id !== null && !TOPIC.test(target.topic_id as string)) {
      throw new TypeError("Invalid Hedera topic locator");
    }
    if ((target.topic_id === null) !== (target.sequence_number === null) ||
        (target.topic_id === null && target.transaction_id === null)) {
      throw new TypeError("Incomplete Hedera target locator");
    }
    if (target.sequence_number !== null && (!Number.isSafeInteger(target.sequence_number) ||
      (target.sequence_number as number) < 1)) throw new TypeError("Invalid target sequence");
    const prefix = identifier(target.observation_fact_prefix, "target observation prefix");
    if (prefix !== `ledger.${target.source}.${target.role}`) {
      throw new TypeError("Invalid target observation prefix");
    }
  }
}

function context(kind: string, value: Json | undefined, report: VerificationReport): Row {
  const row = object(value, "portable report context");
  if (kind === "verification") {
    shape(value, "verification context", []);
    if (report.intent.subject.kind === "execution") throw new TypeError("Execution requires scoped report");
  } else if (kind === "execution") {
    shape(value, "execution context", ["verification_scope"]);
    scope(row.verification_scope, report);
  } else if (kind === "independent_standards") {
    shape(value, "standards context", ["verification_scope", "independent_standards"]);
    scope(row.verification_scope, report);
    standards(row.independent_standards, report);
  } else if (kind === "public_triangulation") {
    shape(value, "public triangulation context", ["consistency", "relationships", "resolution"]);
    if (report.intent.subject.kind !== "dataset" && report.intent.subject.kind !== "ingest") {
      throw new TypeError("Invalid public triangulation subject");
    }
    const rels = relationships(row.relationships, report, PUBLIC_RELATIONSHIPS);
    consistency(row.consistency, rels);
    const resolution = shape(row.resolution, "public resolution", ["public_record", "publication_disclosure", "hedera_mirror"]);
    oneOf(resolution.public_record, "public record status", RESOLUTION);
    oneOf(resolution.publication_disclosure, "publication disclosure status", RESOLUTION);
    oneOf(resolution.hedera_mirror, "Hedera Mirror status", [...RESOLUTION, "not_requested"]);
  } else if (kind === "authorized_dataset_triangulation") {
    shape(value, "authorized Dataset triangulation context", ["consistency", "relationships", "resolution"]);
    if (report.intent.subject.kind !== "dataset" ||
        (report.intent.subject.hedera_network !== "mainnet" && report.intent.subject.hedera_network !== "testnet")) {
      throw new TypeError("Invalid authorized Dataset triangulation subject");
    }
    const rels = relationships(row.relationships, report, AUTHORIZED_RELATIONSHIPS);
    const state = consistency(row.consistency, rels);
    const ids = new Set(rels.map((entry) => object(entry, "relationship").id));
    for (const id of AUTHORIZED_RELATIONSHIPS) {
      if (!ids.has(id)) throw new TypeError("Missing authorized Dataset relationship");
    }
    const resolution = shape(row.resolution, "authorized Dataset resolution",
      ["authorized_core", "hedera_mirror", "dataset_registry_event"]);
    const coreStatus = oneOf(resolution.authorized_core, "authorized Core status",
      ["resolved", "unauthorized", "forbidden", "not_found", "rate_limited", "unavailable", "invalid"]);
    const mirrorStatus = oneOf(resolution.hedera_mirror, "authorized Dataset Mirror status",
      ["resolved", "unavailable", "invalid", "conflict", "not_requested", "not_resolved", "locator_unavailable"]);
    const eventStatus = oneOf(resolution.dataset_registry_event, "Dataset Registry event status",
      ["resolved", "unavailable", "unsupported", "invalid", "conflict"]);
    finding(report, "triangulation.authorized_dataset.registry_event_profile",
      eventStatus === "resolved" ? "pass" : eventStatus === "invalid" || eventStatus === "conflict" ? "fail" :
        eventStatus === "unsupported" ? "unsupported" : "indeterminate");
    const relationshipConflict = rels.some((entry) => object(entry, "relationship").status === "conflict");
    const resolutionConflict = mirrorStatus === "conflict" ||
      eventStatus === "invalid" || eventStatus === "conflict";
    const complete = coreStatus === "resolved" && mirrorStatus === "resolved" && eventStatus === "resolved" &&
      rels.every((entry) => object(entry, "relationship").status === "consistent");
    const expectedState = relationshipConflict || resolutionConflict ? "conflict" : complete ? "consistent" : "incomplete";
    if (state !== expectedState) throw new TypeError("Inconsistent authorized Dataset aggregate");
  } else if (kind === "authorized_ingest_triangulation") {
    shape(value, "authorized Ingest triangulation context", ["consistency", "relationships", "resolution"]);
    if (report.intent.subject.kind !== "ingest" ||
        (report.intent.subject.hedera_network !== "mainnet" && report.intent.subject.hedera_network !== "testnet")) {
      throw new TypeError("Invalid authorized Ingest triangulation subject");
    }
    const rels = relationships(row.relationships, report, AUTHORIZED_RELATIONSHIPS);
    const state = consistency(row.consistency, rels);
    const ids = new Set(rels.map((entry) => object(entry, "relationship").id));
    for (const id of AUTHORIZED_RELATIONSHIPS) {
      if (!ids.has(id)) throw new TypeError("Missing authorized Ingest relationship");
    }
    const resolution = shape(row.resolution, "authorized Ingest resolution",
      ["authorized_core", "hedera_mirror", "ingest_receipt"]);
    const coreStatus = oneOf(resolution.authorized_core, "authorized Core status",
      ["resolved", "unauthorized", "forbidden", "not_found", "rate_limited", "unavailable", "invalid"]);
    const mirrorStatus = oneOf(resolution.hedera_mirror, "authorized Ingest Mirror status",
      ["resolved", "unavailable", "invalid", "conflict", "not_requested", "not_resolved", "locator_unavailable"]);
    const receiptStatus = oneOf(resolution.ingest_receipt, "Ingest receipt status",
      ["resolved", "unavailable", "unsupported", "invalid", "conflict"]);
    finding(report, "triangulation.authorized_ingest.receipt_profile",
      receiptStatus === "resolved" ? "pass" : receiptStatus === "invalid" || receiptStatus === "conflict" ? "fail" :
        receiptStatus === "unsupported" ? "unsupported" : "indeterminate");
    const relationshipConflict = rels.some((entry) => object(entry, "relationship").status === "conflict");
    const resolutionConflict = mirrorStatus === "conflict" ||
      receiptStatus === "invalid" || receiptStatus === "conflict";
    const complete = coreStatus === "resolved" && mirrorStatus === "resolved" && receiptStatus === "resolved" &&
      rels.every((entry) => object(entry, "relationship").status === "consistent");
    const expectedState = relationshipConflict || resolutionConflict ? "conflict" : complete ? "consistent" : "incomplete";
    if (state !== expectedState) throw new TypeError("Inconsistent authorized Ingest aggregate");
  } else if (kind === "execution_triangulation") {
    if (report.intent.subject.kind !== "execution") throw new TypeError("Invalid execution triangulation subject");
    const resolved = Object.hasOwn(row, "triangulation");
    const keys = resolved ? ["verification_scope", "source_core_sha3_512", "public_execution", "triangulation"] :
      ["verification_scope", "public_execution"];
    shape(value, "execution triangulation context", keys);
    scope(row.verification_scope, report);
    const pub = publicExecution(row.public_execution, resolved);
    if (resolved) {
      hash(row.source_core_sha3_512, "source core digest");
      const tri = shape(row.triangulation, "execution triangulation", ["consistency", "relationships", "targets", "plan_relationships"]);
      const rels = relationships(tri.relationships, report, PUBLIC_RELATIONSHIPS);
      consistency(tri.consistency, rels);
      executionTargets(tri.targets, report);
      planRelationships(tri.plan_relationships);
      const resolvedStatus = tri.consistency === "conflict" || pub.mirror_status === "conflict" ? "conflict" : pub.mirror_status;
      if (pub.status !== resolvedStatus) throw new TypeError("Inconsistent resolved execution status");
    }
  } else {
    throw new TypeError("Unsupported portable report kind");
  }
  return row;
}

function checked(value: unknown): Checked {
  const clone = object(cloneJson(value), "portable report");
  shape(clone, "portable report", ["schema_version", "kind", "core_sha3_512", "report_sha3_512", "core", "context"]);
  if (clone.schema_version !== PORTABLE_VERIFICATION_REPORT_SCHEMA_VERSION) throw new TypeError("Unsupported portable report version");
  const kind = oneOf(clone.kind, "portable report kind", KINDS);
  const coreHash = hash(clone.core_sha3_512, "core digest");
  const reportHash = hash(clone.report_sha3_512, "report digest");
  const core = shape(clone.core, "portable core", ["schema_version", "intent", "findings", "observations"]);
  const expectedCore = JSON.parse(canonicalizeVerificationCoreV1(core as unknown as VerificationReport)) as Row;
  if (JSON.stringify(core) !== JSON.stringify(cloneJson(expectedCore))) {
    throw new TypeError("Noncanonical portable core");
  }
  const computedCore = computeVerificationCoreDigestV1(core as unknown as VerificationReport);
  if (computedCore !== coreHash) throw new DigestError("PORTABLE_CORE_DIGEST_MISMATCH");
  const report = core as unknown as VerificationReport;
  const ctx = context(kind, clone.context, report);
  const base = Object.fromEntries(Object.entries(clone).filter(([key]) => key !== "report_sha3_512")) as Row;
  const serialized = JSON.stringify(base);
  if (Buffer.byteLength(serialized, "utf8") > MAX_BYTES) throw new RangeError("Portable report exceeds size limit");
  const digest = sha3_512Hex(Buffer.concat([Buffer.from(DOMAIN, "utf8"), Buffer.from([0]), Buffer.from(serialized, "utf8")]));
  if (digest !== reportHash) throw new DigestError("PORTABLE_REPORT_DIGEST_MISMATCH");
  return { kind, core, context: ctx, serialized };
}

class DigestError extends Error {
  constructor(readonly code: "PORTABLE_CORE_DIGEST_MISMATCH" | "PORTABLE_REPORT_DIGEST_MISMATCH") {
    super(code);
  }
}

/** Checks only saved-document structure and self-consistency, never evidence authenticity. */
export function validatePortableVerificationReportV1(value: unknown): PortableVerificationReportValidationV1 {
  try {
    checked(value);
    return Object.freeze({ status: "valid", reason_code: null,
      authenticity: "not_checked", evidence_recomputation: "not_performed" });
  } catch (error) {
    if (!(error instanceof TypeError || error instanceof RangeError || error instanceof DigestError)) throw error;
    return Object.freeze({ status: "invalid",
      reason_code: error instanceof DigestError ? error.code : "PORTABLE_REPORT_INVALID",
      authenticity: "not_checked", evidence_recomputation: "not_performed" });
  }
}

/** Compares internally valid saved documents. Throws on invalid input; does not authenticate either report. */
export function comparePortableVerificationReportsV1(left: unknown, right: unknown): PortableVerificationReportComparisonV1 {
  const a = checked(left);
  const b = checked(right);
  const differences: PortableVerificationReportComparisonV1["differences"][number][] = [];
  if (a.kind !== b.kind) differences.push("kind");
  const leftIntent = object(a.core.intent, "left intent");
  const rightIntent = object(b.core.intent, "right intent");
  if (JSON.stringify(leftIntent.subject) !== JSON.stringify(rightIntent.subject)) differences.push("subject");
  if (JSON.stringify(leftIntent) !== JSON.stringify(rightIntent)) differences.push("intent");
  if (JSON.stringify(a.core.findings) !== JSON.stringify(b.core.findings)) differences.push("findings");
  if (JSON.stringify(a.core.observations) !== JSON.stringify(b.core.observations)) differences.push("observations");
  if (JSON.stringify(a.context) !== JSON.stringify(b.context)) differences.push("context");
  return Object.freeze({ status: a.serialized === b.serialized ? "equivalent" : "different",
    differences: Object.freeze(differences), authenticity: "not_checked", evidence_recomputation: "not_performed" });
}
