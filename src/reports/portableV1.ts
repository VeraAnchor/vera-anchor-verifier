import type { VerificationReport, VerificationOutcome } from "../contracts/verification.js";
import { sha3_512Hex } from "../crypto/sha3.js";
import { canonicalizeVerificationCoreV1, computeVerificationCoreDigestV1 } from "./coreV1.js";
import type { ExecutionV1Report } from "../profiles/execution/verificationV1.js";
import type { IndependentStandardsV1Report } from "../profiles/execution/independentStandardsV1.js";
import type { PublicTriangulationV1Result } from "../triangulation/publicV1.js";
import type { PublicExecutionTriangulationV1Result } from "../triangulation/executionPublicV1.js";
import type { AuthorizedDatasetTriangulationV1Result } from "../triangulation/authorizedDatasetV1.js";
import type { AuthorizedIngestTriangulationV1Result } from "../triangulation/authorizedIngestV1.js";
import type { TriangulationRelationshipResultV1 } from "../triangulation/compareV1.js";

export const PORTABLE_VERIFICATION_REPORT_SCHEMA_VERSION = "va.portable-verification-report.v1";
const DOMAIN = "va:portable-verification-report:v1";
const MAX_BYTES = 1024 * 1024;
const MAX_DEPTH = 32;
const SHA256 = /^[a-f0-9]{64}$/;
const ID = /^[a-z][a-z0-9._:-]{0,159}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const OUTCOMES = new Set<VerificationOutcome>(["pass", "fail", "indeterminate", "unsupported", "skipped"]);
const STATUS = ["resolved", "conflict", "invalid", "unavailable", "unsupported"];
const PUBLIC_RELATIONSHIPS = ["provided_public_record", "public_record_hedera", "provided_hedera"] as const;
const AUTHORIZED_RELATIONSHIPS = ["provided_authorized", "authorized_hedera"] as const;

type Json = null | string | number | boolean | Json[] | { [key: string]: Json };
type JsonObject = { [key: string]: Json };

export type PortableVerificationReportV1Input =
  | Readonly<{ kind: "verification"; result: VerificationReport }>
  | Readonly<{ kind: "execution"; result: ExecutionV1Report }>
  | Readonly<{ kind: "independent_standards"; result: IndependentStandardsV1Report }>
  | Readonly<{ kind: "public_triangulation"; result: PublicTriangulationV1Result }>
  | Readonly<{ kind: "authorized_dataset_triangulation"; result: AuthorizedDatasetTriangulationV1Result }>
  | Readonly<{ kind: "authorized_ingest_triangulation"; result: AuthorizedIngestTriangulationV1Result }>
  | Readonly<{ kind: "execution_triangulation"; result: PublicExecutionTriangulationV1Result;
      /** Required only when the public execution was not acquired and no plan exists. */
      source_report?: ExecutionV1Report }>;

export type PortableVerificationReportV1 = Readonly<{
  schema_version: typeof PORTABLE_VERIFICATION_REPORT_SCHEMA_VERSION;
  kind: PortableVerificationReportV1Input["kind"];
  core_sha3_512: string;
  report_sha3_512: string;
  core: VerificationReport & Readonly<{ schema_version: string }>;
  /** Profile-specific, bounded and digest-bound assurance context. */
  context: Readonly<JsonObject>;
}>;

function object(value: unknown, name: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new TypeError(`Invalid ${name}`);
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) throw new TypeError(`Invalid ${name}`);
  return value as Record<string, unknown>;
}

function string(value: unknown, name: string, max = 256): string {
  if (typeof value !== "string" || !value || value.length > max || value.trim() !== value) {
    throw new TypeError(`Invalid ${name}`);
  }
  return value;
}

function optionalString(value: unknown, name: string, max = 256): string | null {
  return value === null ? null : string(value, name, max);
}

/** Clone supported JSON only; never stringify raw, potentially cyclic caller input. */
function json(value: unknown, depth = 0): Json {
  if (depth > MAX_DEPTH) throw new TypeError("Portable report exceeds nesting limit");
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (value.length > MAX_BYTES || /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)) {
      throw new TypeError("Invalid portable report string");
    }
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || Object.is(value, -0)) {
      throw new TypeError("Invalid portable report number");
    }
    return value;
  }
  if (Array.isArray(value)) {
    if (value.length > 512) throw new TypeError("Portable report array exceeds limit");
    return Array.from({ length: value.length }, (_, i) => {
      if (!Object.hasOwn(value, i)) throw new TypeError("Sparse portable report array");
      return json(value[i], depth + 1);
    });
  }
  const row = object(value, "portable report JSON object");
  const keys = Object.keys(row).sort();
  if (keys.length > 512) throw new TypeError("Portable report object exceeds field limit");
  const entries: [string, Json][] = [];
  for (const key of keys) {
    if (!key || key.length > 160 || /[\u0000-\u001f\u007f]/.test(key)) throw new TypeError("Invalid portable report field");
    entries.push([key, json(row[key], depth + 1)]);
  }
  return Object.fromEntries(entries) as JsonObject;
}

function checkedCore(report: VerificationReport) {
  const canonical = canonicalizeVerificationCoreV1(report);
  return {
    core: JSON.parse(canonical) as PortableVerificationReportV1["core"],
    core_sha3_512: computeVerificationCoreDigestV1(report),
  };
}

function checkedExecutionScope(report: ExecutionV1Report): JsonObject {
  const scope = object(report.verification_scope, "execution scope");
  if (report.intent.subject.kind !== "execution" ||
      (scope.profile !== "execution-v1" && scope.profile !== "sage-standards-v1")) {
    throw new TypeError("Invalid execution report scope");
  }
  if (scope.expected_program !== null) string(scope.expected_program, "expected program", 128);
  if (scope.requested_result_id !== null &&
      !UUID.test(string(scope.requested_result_id, "requested result ID", 64))) {
    throw new TypeError("Invalid execution result scope");
  }
  if (scope.profile === "execution-v1" && scope.expected_program === null) {
    throw new TypeError("Generic execution profile requires expected program");
  }
  const selected = report.findings.find((f) => f.check_id === "intent.result");
  if (scope.requested_result_id !== null && !selected) throw new TypeError("Missing result-scope finding");
  return json({ profile: scope.profile, expected_program: scope.expected_program,
    requested_result_id: scope.requested_result_id }) as JsonObject;
}

function expectedOutcome(status: string): VerificationOutcome {
  return status === "resolved" ? "pass" : status === "conflict" || status === "invalid" ? "fail" :
    status === "unsupported" ? "unsupported" : "indeterminate";
}

function requireFinding(report: VerificationReport, check_id: string, outcome: VerificationOutcome): void {
  const found = report.findings.find((item) => item.check_id === check_id);
  if (!found || found.outcome !== outcome) throw new TypeError(`Inconsistent report finding: ${check_id}`);
}

function standardsContext(report: IndependentStandardsV1Report): JsonObject {
  const standards = report.independent_standards;
  if (!standards || standards.network !== report.intent.subject.hedera_network ||
      !["verified", "failed", "unavailable", "not_performed"].includes(standards.status) ||
      !["mirror_corroborated", "not_established"].includes(standards.assurance) ||
      !Array.isArray(standards.items) || standards.items.length > 16) {
    throw new TypeError("Invalid independent standards summary");
  }
  const allResolved = standards.items.length > 0 && standards.items.every((item) => item.status === "resolved");
  const anyFailed = standards.items.some((item) => item.status === "conflict" || item.status === "invalid");
  if ((standards.status === "verified") !== allResolved ||
      (standards.status === "failed") !== anyFailed ||
      (standards.status === "not_performed") !== (standards.items.length === 0) ||
      (standards.assurance === "mirror_corroborated") !== (standards.status === "verified")) {
    throw new TypeError("Inconsistent independent standards aggregate");
  }
  const seen = new Set<string>();
  standards.items.forEach((item, i) => {
    const key = string(item.key, "standards plan key");
    if (seen.has(key) || !STATUS.includes(item.status) ||
        item.assurance !== (item.status === "resolved" ? "mirror_corroborated" : "not_established") ||
        (item.content_sha256 !== null && !SHA256.test(item.content_sha256))) {
      throw new TypeError("Invalid independent standards item");
    }
    seen.add(key);
    requireFinding(report, `standards.reference.${i}`, expectedOutcome(item.status));
  });
  requireFinding(report, "standards.references_resolved", standards.status === "verified" ? "pass" :
    standards.status === "failed" ? "fail" : "indeterminate");
  return json({ verification_scope: checkedExecutionScope(report), independent_standards: standards }) as JsonObject;
}

function relationshipContext(
  report: VerificationReport,
  relationships: readonly TriangulationRelationshipResultV1[],
  allowedIds: readonly string[],
): Json {
  if (!Array.isArray(relationships) || relationships.length > 3) throw new TypeError("Invalid triangulation relationships");
  const used = new Set<string>();
  for (const rel of relationships) {
    if (!allowedIds.includes(rel.id) ||
        used.has(rel.id) || !["consistent", "conflict", "incomplete", "not_applicable"].includes(rel.status) ||
        !Array.isArray(rel.fact_comparisons) || rel.fact_comparisons.length > 64) {
      throw new TypeError("Invalid triangulation relationship");
    }
    used.add(rel.id);
    const keys = new Set<string>();
    for (const fact of rel.fact_comparisons) {
      if (!ID.test(fact.key) || keys.has(fact.key) || !OUTCOMES.has(fact.outcome)) {
        throw new TypeError("Invalid triangulation fact result");
      }
      keys.add(fact.key);
      requireFinding(report, `triangulation.${rel.id}.${fact.key}`, fact.outcome);
    }
    const checks: VerificationOutcome[] = rel.fact_comparisons.map((f: { outcome: VerificationOutcome }) => f.outcome);
    const aggregate = checks.length === 0 || checks.every((outcome) => outcome === "skipped") ? "not_applicable" :
      checks.includes("fail") ? "conflict" :
      checks.some((outcome) => outcome === "indeterminate" || outcome === "unsupported") ? "incomplete" : "consistent";
    if (rel.status !== aggregate) throw new TypeError("Inconsistent triangulation relationship status");
  }
  return json(relationships);
}

function consistency(value: unknown): "consistent" | "conflict" | "incomplete" {
  if (value !== "consistent" && value !== "conflict" && value !== "incomplete") {
    throw new TypeError("Invalid triangulation consistency");
  }
  return value;
}

function context(input: PortableVerificationReportV1Input): { report: VerificationReport; context: JsonObject } {
  if (input.kind === "verification") {
    const row = object(input.result, "shared verification result");
    if ("verification_scope" in row || "independent_standards" in row ||
        input.result.intent?.subject?.kind === "execution") {
      throw new TypeError("Execution assurance requires an explicit portable report kind");
    }
    return { report: input.result, context: {} };
  }
  if (input.kind === "execution") {
    if ("independent_standards" in object(input.result, "execution result")) {
      throw new TypeError("Independent standards require an explicit portable report kind");
    }
    return { report: input.result, context: { verification_scope: checkedExecutionScope(input.result) } };
  }
  if (input.kind === "independent_standards") {
    return { report: input.result, context: standardsContext(input.result) };
  }
  if (input.kind === "public_triangulation") {
    const result = input.result;
    const state = consistency(result.consistency);
    if (state === "consistent" && (!result.relationships.length ||
        result.relationships.some((r) => r.status !== "consistent"))) {
      throw new TypeError("Incomplete triangulation cannot be consistent");
    }
    return { report: result.report, context: {
      consistency: state,
      relationships: relationshipContext(result.report, result.relationships, PUBLIC_RELATIONSHIPS),
      resolution: json(result.resolution),
    } };
  }
  if (input.kind === "authorized_dataset_triangulation") {
    const result = input.result;
    const state = consistency(result.consistency);
    if (result.report.intent.subject.kind !== "dataset" ||
        (result.report.intent.subject.hedera_network !== "mainnet" &&
         result.report.intent.subject.hedera_network !== "testnet")) {
      throw new TypeError("Authorized Dataset triangulation requires a network-scoped Dataset subject");
    }
    const relationships = relationshipContext(
      result.report, result.relationships, AUTHORIZED_RELATIONSHIPS,
    );
    const ids = new Set(result.relationships.map((entry) => entry.id));
    const resolution = result.resolution;
    for (const id of AUTHORIZED_RELATIONSHIPS) {
      if (!ids.has(id)) throw new TypeError("Authorized Dataset triangulation is missing a required relationship");
    }
    if (!["resolved", "unauthorized", "forbidden", "not_found", "rate_limited", "unavailable", "invalid"].includes(resolution.authorized_core) ||
        !["resolved", "unavailable", "invalid", "conflict", "not_requested", "not_resolved", "locator_unavailable"].includes(resolution.hedera_mirror) ||
        !["resolved", "unavailable", "unsupported", "invalid", "conflict"].includes(resolution.dataset_registry_event)) {
      throw new TypeError("Invalid authorized Dataset resolution");
    }
    requireFinding(
      result.report,
      "triangulation.authorized_dataset.registry_event_profile",
      expectedOutcome(resolution.dataset_registry_event),
    );
    const relationshipConflict = result.relationships.some((entry) => entry.status === "conflict");
    const resolutionConflict = resolution.hedera_mirror === "conflict" ||
      resolution.dataset_registry_event === "invalid" || resolution.dataset_registry_event === "conflict";
    const complete = resolution.authorized_core === "resolved" &&
      resolution.hedera_mirror === "resolved" && resolution.dataset_registry_event === "resolved" &&
      result.relationships.every((entry) => entry.status === "consistent");
    const expectedState = relationshipConflict || resolutionConflict ? "conflict" : complete ? "consistent" : "incomplete";
    if (state !== expectedState) throw new TypeError("Inconsistent authorized Dataset aggregate");
    return { report: result.report, context: {
      consistency: state,
      relationships,
      resolution: json(resolution),
    } };
  }
  if (input.kind === "authorized_ingest_triangulation") {
    const result = input.result;
    const state = consistency(result.consistency);
    if (result.report.intent.subject.kind !== "ingest" ||
        (result.report.intent.subject.hedera_network !== "mainnet" &&
         result.report.intent.subject.hedera_network !== "testnet")) {
      throw new TypeError("Authorized Ingest triangulation requires a network-scoped Ingest subject");
    }
    const relationships = relationshipContext(
      result.report, result.relationships, AUTHORIZED_RELATIONSHIPS,
    );
    const ids = new Set(result.relationships.map((entry) => entry.id));
    const resolution = result.resolution;
    for (const id of AUTHORIZED_RELATIONSHIPS) {
      if (!ids.has(id)) throw new TypeError("Authorized Ingest triangulation is missing a required relationship");
    }
    if (!["resolved", "unauthorized", "forbidden", "not_found", "rate_limited", "unavailable", "invalid"].includes(resolution.authorized_core) ||
        !["resolved", "unavailable", "invalid", "conflict", "not_requested", "not_resolved", "locator_unavailable"].includes(resolution.hedera_mirror) ||
        !["resolved", "unavailable", "unsupported", "invalid", "conflict"].includes(resolution.ingest_receipt)) {
      throw new TypeError("Invalid authorized Ingest resolution");
    }
    requireFinding(
      result.report,
      "triangulation.authorized_ingest.receipt_profile",
      expectedOutcome(resolution.ingest_receipt),
    );
    const relationshipConflict = result.relationships.some((entry) => entry.status === "conflict");
    const resolutionConflict = resolution.hedera_mirror === "conflict" ||
      resolution.ingest_receipt === "invalid" || resolution.ingest_receipt === "conflict";
    const complete = resolution.authorized_core === "resolved" &&
      resolution.hedera_mirror === "resolved" && resolution.ingest_receipt === "resolved" &&
      result.relationships.every((entry) => entry.status === "consistent");
    const expectedState = relationshipConflict || resolutionConflict ? "conflict" : complete ? "consistent" : "incomplete";
    if (state !== expectedState) throw new TypeError("Inconsistent authorized Ingest aggregate");
    return { report: result.report, context: {
      consistency: state,
      relationships,
      resolution: json(resolution),
    } };
  }
  if (input.kind !== "execution_triangulation") throw new TypeError("Unsupported portable report kind");
  const result = input.result;
  if (!["resolved", "not_found", "unavailable", "invalid", "conflict", "verification_material_unavailable"].includes(result.status) ||
      !["resolved", "not_found", "unavailable", "invalid", "conflict", "verification_material_unavailable"].includes(result.public_record_acquisition)) {
    throw new TypeError("Invalid public execution acquisition");
  }
  if (result.plan === null) {
    if (result.comparison !== null || result.mirror !== null || result.hedera_resolution !== "not_checked" ||
        result.public_record_acquisition === "resolved" || !input.source_report) {
      throw new TypeError("Unresolved execution requires independently computed offline report");
    }
    const report = input.source_report;
    return { report, context: {
      verification_scope: checkedExecutionScope(report),
      public_execution: json({ status: result.status, reason_code: result.reason_code,
        public_record_acquisition: result.public_record_acquisition,
        hedera_resolution: result.hedera_resolution }),
    } };
  }
  if (!result.comparison || !result.mirror || result.public_record_acquisition !== "resolved" ||
      result.plan.stage !== "unresolved_authority_plan" ||
      result.plan.hedera_resolution !== "not_checked" || result.plan.public_record_acquisition !== "not_checked") {
    throw new TypeError("Invalid resolved execution triangulation structure");
  }
  const report = result.comparison.report;
  const source = result.plan.source_report;
  if (report.intent.subject.kind !== "execution" ||
      JSON.stringify(report.intent) !== JSON.stringify(source.intent) ||
      result.hedera_resolution !== result.mirror.status) {
    throw new TypeError("Execution triangulation subject or resolver mismatch");
  }
  for (const target of result.plan.hedera_targets) {
    if (target.network !== report.intent.subject.hedera_network) {
      throw new TypeError("Execution Hedera target network mismatch");
    }
  }
  const state = consistency(result.comparison.consistency);
  if (state === "consistent" && (!result.comparison.relationships.length ||
      result.comparison.relationships.some((r) => r.status !== "consistent"))) {
    throw new TypeError("Incomplete execution triangulation cannot be consistent");
  }
  return { report, context: {
    verification_scope: checkedExecutionScope(source),
    source_core_sha3_512: computeVerificationCoreDigestV1(source),
    public_execution: json({ status: result.status, reason_code: result.reason_code,
      public_record_acquisition: result.public_record_acquisition, hedera_resolution: result.hedera_resolution,
      mirror_status: result.mirror.status, mirror_reason_code: result.mirror.reason_code }),
    triangulation: json({ consistency: state, relationships: relationshipContext(report, result.comparison.relationships, PUBLIC_RELATIONSHIPS),
      targets: result.plan.hedera_targets, plan_relationships: result.plan.triangulation.relationships }),
  } };
}

/** A content-addressed record of claimed findings, not proof of their authenticity. */
export function createPortableVerificationReportV1(input: PortableVerificationReportV1Input): PortableVerificationReportV1 {
  if (!input || typeof input !== "object") throw new TypeError("Portable report input is required");
  const selected = context(input);
  const normalized = checkedCore(selected.report);
  const base = json({ schema_version: PORTABLE_VERIFICATION_REPORT_SCHEMA_VERSION,
    kind: input.kind, core_sha3_512: normalized.core_sha3_512,
    core: normalized.core, context: selected.context }) as JsonObject;
  const canonical = JSON.stringify(base);
  if (Buffer.byteLength(canonical, "utf8") > MAX_BYTES) throw new RangeError("Portable report exceeds size limit");
  const report_sha3_512 = sha3_512Hex(Buffer.concat([
    Buffer.from(DOMAIN, "utf8"), Buffer.from([0]), Buffer.from(canonical, "utf8"),
  ]));
  return Object.freeze({ schema_version: PORTABLE_VERIFICATION_REPORT_SCHEMA_VERSION,
    kind: input.kind, core_sha3_512: normalized.core_sha3_512, report_sha3_512,
    core: Object.freeze(normalized.core), context: Object.freeze(selected.context) });
}

/** Deterministic serialized report, including the digest of its material conclusions. */
export function canonicalizePortableVerificationReportV1(input: PortableVerificationReportV1Input): string {
  return JSON.stringify(json(createPortableVerificationReportV1(input)));
}

export function computePortableVerificationReportDigestV1(input: PortableVerificationReportV1Input): string {
  return createPortableVerificationReportV1(input).report_sha3_512;
}
