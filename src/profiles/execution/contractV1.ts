// SDK-local execution evidence and verification rule contracts (v1).
// Pure structural types and bounded validators; no Explorer, Core, or network I/O.
// Derived from the October 2026 Explorer execution verification baseline.

type HederaNetwork = "testnet" | "mainnet";
import {
  EXECUTION_VERIFICATION_REASON_CODES as REASONS,
  type ExecutionVerificationReasonCode,
} from "./reasonCodesV1.js";

export const EXECUTION_VERIFICATION_SCHEMA_VERSION =
  "vera.execution-verification.v1";

export const EXECUTION_VERIFIER_VERSION = "1.0.0";

export const SUPPORTED_PUBLIC_STANDARDS_CONTRACT_VERSIONS: readonly string[] =
  Object.freeze(["1.0.0"]);

export const EXECUTION_VERIFICATION_STATUSES = Object.freeze([
  "consistent",
  "incomplete",
  "failed",
] as const);

export const EXECUTION_VERIFICATION_CHECK_STATUSES = Object.freeze([
  "pass",
  "fail",
  "unavailable",
  "not_applicable",
] as const);

export const EXECUTION_VERIFICATION_REQUIREMENTS = Object.freeze([
  "required",
  "optional",
  "conditional",
] as const);

export type ExecutionVerificationStatus =
  (typeof EXECUTION_VERIFICATION_STATUSES)[number];

export type ExecutionVerificationCheckStatus =
  (typeof EXECUTION_VERIFICATION_CHECK_STATUSES)[number];

export type ExecutionVerificationRequirement =
  (typeof EXECUTION_VERIFICATION_REQUIREMENTS)[number];

export type PublicStandardsSourceDocument = {
  standard?: string | null;
  version?: string | null;
  path?: string | null;
  sha256?: string | null;
};

export type PublicStandardsBaselineEvidence = {
  baseline_id?: string | null;
  title?: string | null;
  source_repository?: string | null;
  source_commit?: string | null;
  frozen_at?: string | Date | null;
  source_documents?: PublicStandardsSourceDocument[] | null;
};

export type PublicHcs11Evidence = {
  profile_version?: string | null;
  account_id?: string | null;
  profile_registry_topic_id?: string | null;
  profile_registry_sequence?: number | null;
  profile_hcs1_ref?: string | null;
  profile_checksum_sha256?: string | null;
};

export type PublicAgentEvidence = {
  logical_id?: string | null;
  display_name?: string | null;
  base_did?: string | null;
  hcs14_uaid?: string | null;
  hcs11?: PublicHcs11Evidence | null;
};

export type PublicCapabilityEvidence = {
  standard?: string | null;
  capability_version_id?: string | null;
  display_name?: string | null;
  discovery_registry_topic_id?: string | null;
  skill_uid?: string | null;
  skill_version?: string | null;
  version_registry_topic_id?: string | null;
  version_sequence_number?: number | null;
  manifest_hcs1_ref?: string | null;
  manifest_checksum_sha256?: string | null;
  repository_uri?: string | null;
  repository_commit?: string | null;
  published_at?: string | Date | null;
};

export type PublicSchemaEvidence = {
  role?: string | null;
  ordinal?: number | null;
  schema_uid?: string | null;
  display_name?: string | null;
  semantic_version?: string | null;
  registry_topic_id?: string | null;
  registry_sequence_number?: number | null;
  hcs13_ref?: string | null;
  schema_checksum_sha256?: string | null;
  instance_digest_sha3_512?: string | null;
};

export type PublicExecutionDatasetEvidence = {
  dataset_key?: string | null;
  dataset_version?: number | null;
  dataset_fingerprint_sha3_512?: string | null;
  dataset_manifest_sha3_512?: string | null;
};

export type PublicExecutionEvidence = {
  job_id?: string | null;
  result_id?: string | null;
  proof_date?: string | null;
  program?: string | null;
  status?: string | null;
  hedera_network?: HederaNetwork | string | null;
  pipeline_hash?: string | null;
  dataset?: PublicExecutionDatasetEvidence | null;
};

export type PublicParameterInstanceVerificationMaterial = {
  role?: string | null;
  hcs13_ref?: string | null;
  domain_separator?: string | null;
  payload?: unknown;
};

export type PublicExecutionStartVerificationMaterial = {
  started_at?: string | Date | null;
  hcs_transaction_id?: string | null;
  hcs_topic_id?: string | null;
  consensus_timestamp_exact?: string | null;
};

export type PublicStandardsResolutionState = "verified" | "failed" | "unavailable";

export type PublicStandardsResolutionItem = Readonly<{
  key?: string | null;
  standard?: string | null;
  reference?: string | null;
  state?: PublicStandardsResolutionState | null;
  reason?: string | null;
}>;

export type PublicStandardsResolutionMaterial = Readonly<{
  schema_version?: string | null;
  hedera_network?: HederaNetwork | string | null;
  state?: PublicStandardsResolutionState | null;
  items?: readonly PublicStandardsResolutionItem[] | null;
}>;

export type PublicExecutionVerificationMaterial = {
  parameter_instance?: PublicParameterInstanceVerificationMaterial | null;
  execution_start?: PublicExecutionStartVerificationMaterial | null;
  standards_resolution?: PublicStandardsResolutionMaterial | null;
};

export type PublicSoftwareReleaseEvidence = {
  repository_uri?: string | null;
  git_commit?: string | null;
  pipeline_hash_sha3_512?: string | null;
};

export type PublicContractMetadataRecord = {
  schema?: string | null;
  digest?: string | null;
  digest_payload?: Record<string, unknown> | null;
  canonicalization?: string | null;
  digest_algorithm?: string | null;
  domain_separator?: string | null;
};

export type PublicBindingEvidence = PublicContractMetadataRecord & {
  id?: string | null;
  finalized_at?: string | Date | null;
};

export type PublicAcceptanceHcsEvidence = {
  topic_id?: string | null;
  transaction_id?: string | null;
  message_id?: string | null;
  sequence_number?: number | null;
  consensus_timestamp?: string | Date | null;
  consensus_timestamp_exact?: string | null;
  data_hash_sha3_512?: string | null;
};

export type PublicAcceptanceEvidence = PublicContractMetadataRecord & {
  id?: string | null;
  state?: string | null;
  admission_policy_id?: string | null;
  requires_hcs_confirmation?: boolean | null;
  binding_digest?: string | null;
  accepted_at?: string | Date | null;
  confirmed_at?: string | Date | null;
  failure_code?: string | null;
  hcs?: PublicAcceptanceHcsEvidence | null;
};

export type PublicResultEvidenceHcsEvidence = {
  transaction_id?: string | null;
  topic_id?: string | null;
};

export type PublicResultEvidence = PublicContractMetadataRecord & {
  id?: string | null;
  result_id?: string | null;
  binding_digest?: string | null;
  acceptance_digest?: string | null;
  pipeline_hash?: string | null;
  result_hash?: string | null;
  service_hash?: string | null;
  global_hash?: string | null;
  artifact_count?: number | null;
  sealed_at?: string | Date | null;
  hcs?: PublicResultEvidenceHcsEvidence | null;
};

export type PublicExecutionStandardsEvidence = {
  available?: boolean;
  contract_version?: string | null;
  reason?: string | null;
  execution?: PublicExecutionEvidence | null;
  standards?: {
    baseline?: PublicStandardsBaselineEvidence | null;
    schemas?: PublicSchemaEvidence[] | null;
    reference_complete?: boolean | null;
    publicly_resolvable?: boolean | null;
  } | null;
  agents?: {
    requester?: PublicAgentEvidence | null;
    executor?: PublicAgentEvidence | null;
  } | null;
  capability?: PublicCapabilityEvidence | null;
  software_release?: PublicSoftwareReleaseEvidence | null;
  binding?: PublicBindingEvidence | null;
  acceptance?: PublicAcceptanceEvidence | null;
  result_evidence?: PublicResultEvidence | null;
};

export type ExecutionVerificationSubject = Readonly<{
  hedera_network: HederaNetwork | null;
  program: string | null;
  job_id: string | null;
  result_id: string | null;
}>;

export type ExecutionVerificationCheck = Readonly<{
  id: string;
  group: string;
  label: string;
  requirement: ExecutionVerificationRequirement;
  status: ExecutionVerificationCheckStatus;
  reason_code: ExecutionVerificationReasonCode;
  evidence_refs: readonly string[];
}>;

export type ExecutionVerificationSummary = Readonly<{
  total: number;
  outcome_relevant: number;
  passed: number;
  failed: number;
  unavailable: number;
  not_applicable: number;
}>;

export type ExecutionVerificationReport = Readonly<{
  schema_version: typeof EXECUTION_VERIFICATION_SCHEMA_VERSION;
  verifier_version: typeof EXECUTION_VERIFIER_VERSION;
  subject: ExecutionVerificationSubject;
  status: ExecutionVerificationStatus;
  summary: ExecutionVerificationSummary;
  checks: readonly ExecutionVerificationCheck[];
}>;

export type ExecutionVerificationRuleResult = Readonly<{
  status: ExecutionVerificationCheckStatus;
  reasonCode: ExecutionVerificationReasonCode;
}>;

export type ExecutionVerificationContext = Readonly<{
  evidence: PublicExecutionStandardsEvidence;
  verificationMaterial: PublicExecutionVerificationMaterial | null;
  expectedNetwork: HederaNetwork | "";
  requestedResultId: string;
  supportedContractVersions: readonly string[];
}>;

export type ExecutionVerificationRule = Readonly<{
  id: string;
  group: string;
  label: string;
  requirement: ExecutionVerificationRequirement;
  evidenceRefs: readonly string[];
  evaluate: (context: ExecutionVerificationContext) => ExecutionVerificationRuleResult;
}>;

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const SHA3_512_RE = /^[0-9a-f]{128}$/;

const SHA256_RE = /^[0-9a-f]{64}$/;

const GIT_COMMIT_RE = /^[0-9a-f]{40}$/;

const HEDERA_ID_RE = /^0\.0\.[0-9]+$/;

const HCS_TX_ID_RE = /^0\.0\.[0-9]+@[0-9]+\.[0-9]+$/;

const HCS1_REF_RE = /^hcs:\/\/1\/0\.0\.[0-9]+(?:\/.*)?$/;

const HCS13_REF_RE = /^hcs:\/\/13\/0\.0\.[0-9]+#[1-9][0-9]*$/;

const DATE_RE = /^(\d{4})-(\d{2})-(\d{2})$/;

const INPUT_LIMITS = Object.freeze({
  maxDepth: 20,
  maxObjectKeys: 4096,
  maxArrayLength: 256,
  maxStringLength: 8192,
  maxVisitedValues: 20000,
});

export function cleanString(value: unknown): string {
  if (typeof value !== "string") return "";
  const out = value.trim();
  return out.length ? out : "";
}

export function normalizeIdentifier(value: unknown): string {
  return cleanString(value).toLowerCase();
}

export function sameIdentifier(left: unknown, right: unknown): boolean {
  const a = normalizeIdentifier(left);
  const b = normalizeIdentifier(right);
  return Boolean(a && b && a === b);
}

export function isUuid(value: unknown): value is string {
  return UUID_RE.test(cleanString(value));
}

export function isSha3_512(value: unknown): value is string {
  return SHA3_512_RE.test(cleanString(value));
}

export function isSha256(value: unknown): value is string {
  return SHA256_RE.test(cleanString(value));
}

export function isGitCommit(value: unknown): value is string {
  return GIT_COMMIT_RE.test(cleanString(value));
}

export function isHederaId(value: unknown): value is string {
  return HEDERA_ID_RE.test(cleanString(value));
}

export function isHcsTransactionId(value: unknown): value is string {
  return HCS_TX_ID_RE.test(cleanString(value));
}

export function isHcs1Ref(value: unknown): value is string {
  return HCS1_REF_RE.test(cleanString(value));
}

export function isHcs13Ref(value: unknown): value is string {
  return HCS13_REF_RE.test(cleanString(value));
}

export function isSupportedHederaNetwork(
  value: unknown
): value is HederaNetwork {
  const network = normalizeIdentifier(value);
  return network === "testnet" || network === "mainnet";
}

export function isValidDate(value: unknown): value is string {
  const text = cleanString(value);
  const match = DATE_RE.exec(text);
  if (!match) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const date = new Date(Date.UTC(year, month - 1, day));
  return (
    date.getUTCFullYear() === year &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day
  );
}

export function hasTimestamp(value: unknown): boolean {
  if (value instanceof Date) return Number.isFinite(value.getTime());
  return Boolean(cleanString(value));
}

export function isPositiveSafeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) > 0;
}

export function isPlainObject(
  value: unknown
): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

export type ExecutionVerificationInputBoundsResult = Readonly<{
  ok: boolean;
  reasonCode: ExecutionVerificationReasonCode;
}>;

export function validateExecutionVerificationInputBounds(
  value: unknown
): ExecutionVerificationInputBoundsResult {
  if (!isPlainObject(value)) {
    return Object.freeze({
      ok: false,
      reasonCode: REASONS.INPUT_STRUCTURE_INVALID,
    });
  }
  const stack: Array<{ value: unknown; depth: number }> = [
    { value, depth: 0 },
  ];
  const seen = new Set<object>();
  let visited = 0;
  let objectKeys = 0;
  while (stack.length) {
    const current = stack.pop();
    if (!current) break;
    const item = current.value;
    visited += 1;
    if (visited > INPUT_LIMITS.maxVisitedValues) {
      return Object.freeze({
        ok: false,
        reasonCode: REASONS.INPUT_LIMIT_EXCEEDED,
      });
    }
    if (
      item === null ||
      typeof item === "boolean" ||
      typeof item === "number"
    ) {
      if (typeof item === "number" && !Number.isFinite(item)) {
        return Object.freeze({
          ok: false,
          reasonCode: REASONS.INPUT_STRUCTURE_INVALID,
        });
      }
      continue;
    }
    if (typeof item === "string") {
      if (item.length > INPUT_LIMITS.maxStringLength) {
        return Object.freeze({
          ok: false,
          reasonCode: REASONS.INPUT_LIMIT_EXCEEDED,
        });
      }
      continue;
    }
    if (item instanceof Date) {
      if (!Number.isFinite(item.getTime())) {
        return Object.freeze({
          ok: false,
          reasonCode: REASONS.INPUT_STRUCTURE_INVALID,
        });
      }
      continue;
    }
    if (typeof item !== "object") {
      return Object.freeze({
        ok: false,
        reasonCode: REASONS.INPUT_STRUCTURE_INVALID,
      });
    }
    if (current.depth >= INPUT_LIMITS.maxDepth) {
      return Object.freeze({
        ok: false,
        reasonCode: REASONS.INPUT_LIMIT_EXCEEDED,
      });
    }
    if (seen.has(item)) {
      return Object.freeze({
        ok: false,
        reasonCode: REASONS.INPUT_STRUCTURE_INVALID,
      });
    }
    seen.add(item);
    if (Array.isArray(item)) {
      if (item.length > INPUT_LIMITS.maxArrayLength) {
        return Object.freeze({
          ok: false,
          reasonCode: REASONS.INPUT_LIMIT_EXCEEDED,
        });
      }
      for (let i = item.length - 1; i >= 0; i -= 1) {
        stack.push({ value: item[i], depth: current.depth + 1 });
      }
      continue;
    }
    if (!isPlainObject(item)) {
      return Object.freeze({
        ok: false,
        reasonCode: REASONS.INPUT_STRUCTURE_INVALID,
      });
    }
    const keys = Object.keys(item);
    objectKeys += keys.length;
    if (objectKeys > INPUT_LIMITS.maxObjectKeys) {
      return Object.freeze({
        ok: false,
        reasonCode: REASONS.INPUT_LIMIT_EXCEEDED,
      });
    }
    for (const key of keys) {
      if (key.length > 256) {
        return Object.freeze({
          ok: false,
          reasonCode: REASONS.INPUT_LIMIT_EXCEEDED,
        });
      }
      stack.push({ value: item[key], depth: current.depth + 1 });
    }
  }
  return Object.freeze({
    ok: true,
    reasonCode: REASONS.CHECK_PASSED,
  });
}

function deepFreeze<T>(value: T): T {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  Object.freeze(value);
  for (const child of Object.values(value as Record<string, unknown>)) {
    deepFreeze(child);
  }
  return value;
}

export function makeVerificationCheck({
  id,
  group,
  label,
  requirement,
  status,
  reasonCode,
  evidenceRefs = [],
}: {
  id: string;
  group: string;
  label: string;
  requirement: ExecutionVerificationRequirement;
  status: ExecutionVerificationCheckStatus;
  reasonCode: ExecutionVerificationReasonCode;
  evidenceRefs?: readonly string[];
}): ExecutionVerificationCheck {
  if (!cleanString(id) || !cleanString(group) || !cleanString(label)) {
    throw new TypeError("Verification checks require id, group, and label.");
  }
  if (!EXECUTION_VERIFICATION_REQUIREMENTS.includes(requirement)) {
    throw new TypeError(`Unsupported verification requirement: ${requirement}.`);
  }
  if (!EXECUTION_VERIFICATION_CHECK_STATUSES.includes(status)) {
    throw new TypeError(`Unsupported verification check status: ${status}.`);
  }
  if (!cleanString(reasonCode)) {
    throw new TypeError("Verification checks require a reason code.");
  }
  return deepFreeze({
    id: cleanString(id),
    group: cleanString(group),
    label: cleanString(label),
    requirement,
    status,
    reason_code: reasonCode,
    evidence_refs: [...new Set(evidenceRefs.map(cleanString).filter(Boolean))].sort(),
  });
}

export function pass(
  reasonCode: ExecutionVerificationReasonCode = REASONS.CHECK_PASSED
): ExecutionVerificationRuleResult {
  return Object.freeze({ status: "pass", reasonCode });
}

export function fail(
  reasonCode: ExecutionVerificationReasonCode
): ExecutionVerificationRuleResult {
  return Object.freeze({ status: "fail", reasonCode });
}

export function unavailable(
  reasonCode: ExecutionVerificationReasonCode = REASONS.REQUIRED_EVIDENCE_MISSING
): ExecutionVerificationRuleResult {
  return Object.freeze({ status: "unavailable", reasonCode });
}

export function notApplicable(
  reasonCode: ExecutionVerificationReasonCode = REASONS.NOT_APPLICABLE
): ExecutionVerificationRuleResult {
  return Object.freeze({ status: "not_applicable", reasonCode });
}

export function outcomeStatus(
  checks: readonly ExecutionVerificationCheck[]
): ExecutionVerificationStatus {
  const applicable = checks.filter(
    (check) =>
      check.requirement === "required" ||
      (check.requirement === "conditional" &&
        check.status !== "not_applicable")
  );
  if (applicable.some((check) => check.status === "fail")) {
    return "failed";
  }
  if (applicable.some((check) => check.status === "unavailable")) {
    return "incomplete";
  }
  return "consistent";
}

export function verificationSummary(
  checks: readonly ExecutionVerificationCheck[]
): ExecutionVerificationSummary {
  const counts: Record<ExecutionVerificationCheckStatus, number> = {
    pass: 0,
    fail: 0,
    unavailable: 0,
    not_applicable: 0,
  };
  let outcomeRelevant = 0;
  for (const check of checks) {
    counts[check.status] += 1;
    if (
      check.requirement === "required" ||
      (check.requirement === "conditional" &&
        check.status !== "not_applicable")
    ) {
      outcomeRelevant += 1;
    }
  }
  return Object.freeze({
    total: checks.length,
    outcome_relevant: outcomeRelevant,
    passed: counts.pass,
    failed: counts.fail,
    unavailable: counts.unavailable,
    not_applicable: counts.not_applicable,
  });
}

export function freezeVerificationReport(
  report: ExecutionVerificationReport
): ExecutionVerificationReport {
  return deepFreeze(report);
}

function assertNoUnpairedSurrogates(value: string, path: string): void {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new TypeError(`Unpaired UTF-16 surrogate at ${path}.`);
      }
      i += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new TypeError(`Unpaired UTF-16 surrogate at ${path}.`);
    }
  }
}

function canonicalizeReportValue(value: unknown, path: string): string {
  if (value === null) return "null";
  if (typeof value === "string") {
    assertNoUnpairedSurrogates(value, path);
    return JSON.stringify(value);
  }
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError(`Non-finite number at ${path}.`);
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    const parts = value.map((item, index) =>
      canonicalizeReportValue(item, `${path}[${index}]`)
    );
    return `[${parts.join(",")}]`;
  }
  if (!isPlainObject(value)) {
    throw new TypeError(`Unsupported canonical report value at ${path}.`);
  }
  const keys = Object.keys(value).sort();
  const parts: string[] = [];
  for (const key of keys) {
    assertNoUnpairedSurrogates(key, `${path}.{key}`);
    const child = value[key];
    if (
      child === undefined ||
      typeof child === "function" ||
      typeof child === "symbol" ||
      typeof child === "bigint"
    ) {
      throw new TypeError(`Unsupported canonical report value at ${path}.${key}.`);
    }
    parts.push(
      `${JSON.stringify(key)}:${canonicalizeReportValue(child, `${path}.${key}`)}`
    );
  }
  return `{${parts.join(",")}}`;
}

export function canonicalizeExecutionVerificationReport(
  report: ExecutionVerificationReport
): string {
  return canonicalizeReportValue(report, "$");
}
