/**
 * Online, read-only SAGE standards resolution over the SDK's pinned open HCS
 * verifiers. The execution evidence supplies CLAIMED locators, never trusted
 * resolver outcomes. Exact historical locators are required; no 'latest' reads.
 *
 * Mirror REST establishes corroboration relative to VA, not authenticated
 * Hedera consensus, DID control, or historical account-memo ownership.
 */
import type { HederaNetwork, VerificationFact, VerificationFinding, VerificationObservation,
  VerificationOutcome } from "../../contracts/verification.js";
import type { Hcs1MirrorV1Config } from "../../resolvers/hcs1MirrorV1.js";
import type { Hcs1V1ContentOptions } from "../../standards/hcs/hcs1V1.js";
import { parseHcs1ReferenceV1 } from "../../standards/hcs/hcs1V1.js";
import { parseHcs13ReferenceV1 } from "../../standards/hcs/hcs13V1.js";
import { parseHcs14DidUaidV1, Hcs14V1Error } from "../../standards/hcs/hcs14V1.js";
import { resolveHcs11ProfileV1 } from "../../resolvers/hcs11MirrorV1.js";
import { resolveHcs2RegisterV1 } from "../../resolvers/hcs2MirrorV1.js";
import { resolveHcs13SchemaV1 } from "../../resolvers/hcs13MirrorV1.js";
import { resolveHcs26SkillVersionV1 } from "../../resolvers/hcs26MirrorV1.js";
import type { PublicExecutionStandardsEvidence, PublicAgentEvidence,
  PublicCapabilityEvidence, PublicSchemaEvidence } from "./contractV1.js";
import { buildStandardsResolutionPlan, type StandardsResolutionPlanItem } from "./standardsPlanV1.js";
import { verifyExecutionV1WithIntent, type ExecutionV1Input,
  type ExecutionV1Report } from "./verificationV1.js";

const TOPIC = /^0\.0\.[0-9]+$/;
const SHA256 = /^[0-9a-f]{64}$/;
const POSITIVE = /^[1-9][0-9]*$/;
const MAX_REFERENCES = 16;

export type IndependentStandardsV1Item = Readonly<{
  key: string;
  standard: string;
  reference: string;
  status: "resolved" | "conflict" | "invalid" | "unavailable" | "unsupported";
  reason_code: string | null;
  resolver_id: string | null;
  /** Exact historical message timestamp when available, not a current-state claim. */
  historical_consensus_timestamps_exact: readonly string[];
  /** HCS-11 account and registry topic memos are observed current state. */
  current_topic_or_account_memo_observed: boolean;
  /** SHA-256 of independently retrieved canonical HCS-1 content, when established. */
  content_sha256: string | null;
  /** Only Mirror REST corroboration; no Hedera consensus-signature authentication. */
  assurance: "mirror_corroborated" | "not_established";
}>;

export type IndependentStandardsV1Report = ExecutionV1Report & Readonly<{
  independent_standards: Readonly<{
    network: HederaNetwork;
    status: "verified" | "failed" | "unavailable" | "not_performed";
    assurance: "mirror_corroborated" | "not_established";
    items: readonly IndependentStandardsV1Item[];
    /** This pass DOES NOT mean DID-controller control or historical account memo validity. */
    did_controller_authentication: "not_checked";
    hedera_consensus_authentication: "not_checked";
    historical_account_memo_binding: "not_checked";
    manifest_files_resolution: "not_checked";
    json_schema_instance_validation: "not_checked";
  }>;
}>;

type ObservationData = Readonly<{
  status: IndependentStandardsV1Item["status"];
  code: string | null;
  resolver: string | null;
  times: readonly string[];
  currentMemo: boolean;
  sha256: string | null;
  /** Additional resolved facts; never raw profile, schema, manifest or credentials. */
  facts?: readonly VerificationFact[];
}>;

function text(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}
function positive(value: unknown): number | null {
  if (typeof value !== "number" && typeof value !== "string") return null;
  const s = String(value);
  if (!POSITIVE.test(s)) return null;
  const n = Number(s);
  return Number.isSafeInteger(n) && n > 0 ? n : null;
}
function hex(value: unknown): string | null {
  return typeof value === "string" && SHA256.test(value) ? value : null;
}
function topic(value: unknown): string | null {
  return typeof value === "string" && TOPIC.test(value) && value.length <= 64 ? value : null;
}
function fact(key: string, value: string | number | boolean): VerificationFact {
  return Object.freeze({ key, state: "available" as const, value });
}
function unavailable(code: string): ObservationData {
  return { status: "unavailable", code, resolver: null, times: [], currentMemo: false, sha256: null };
}
function invalid(code: string): ObservationData {
  return { status: "invalid", code, resolver: null, times: [], currentMemo: false, sha256: null };
}
function mismatch(code: string): ObservationData {
  return { status: "conflict", code, resolver: null, times: [], currentMemo: false, sha256: null };
}
function networkMatch(input: PublicExecutionStandardsEvidence, net: HederaNetwork, job: string): boolean {
  return input.execution?.hedera_network === net &&
    text(input.execution?.job_id).toLowerCase() === job &&
    text(input.execution?.program).toLowerCase() === "sage";
}
function hasReference(ref: unknown): ref is string {
  try { parseHcs1ReferenceV1(ref); return true; } catch { return false; }
}

async function agent(config: Hcs1MirrorV1Config, net: HederaNetwork,
  evidence: PublicAgentEvidence | null | undefined,
  item: StandardsResolutionPlanItem, decode: Hcs1V1ContentOptions): Promise<ObservationData> {
  const h = evidence?.hcs11;
  if (!h || !item.reference || !evidence?.hcs14_uaid || !evidence.base_did) {
    return unavailable("HCS11_EXECUTION_REFERENCE_MISSING");
  }
  const account = topic(h.account_id);
  const registryTopic = topic(h.profile_registry_topic_id);
  const sequence = positive(h.profile_registry_sequence);
  const checksum = hex(h.profile_checksum_sha256);
  if (!account || !registryTopic || !sequence || !checksum || !hasReference(item.reference) ||
      item.reference !== h.profile_hcs1_ref) return invalid("HCS11_EXECUTION_REFERENCE_INVALID");
  try { parseHcs14DidUaidV1(evidence.hcs14_uaid); }
  catch { return invalid("HCS11_EXECUTION_UAID_INVALID"); }
  const expectations = {
    hedera_network: net, account_id: account,
    expected_hcs1_reference: item.reference,
    expected_hcs1_sha256: checksum,
    expected_profile_sha256: checksum,
    expected_uaid: evidence.hcs14_uaid,
    expected_base_did: evidence.base_did,
  };
  let result;
  let directRegistryTime: string | null = null;
  try {
    // Prefer the exact HCS-2 account-memo route. An independently observed
    // direct HCS-1 memo is also supported by the pinned HCS-11 contract, but
    // its separately claimed historical HCS-2 registration still needs proof.
    result = await resolveHcs11ProfileV1(config, {
      ...expectations, hcs2_sequence_number: sequence,
      expected_profile_reference: `hcs://2/${registryTopic}`,
    }, decode);
    if (result.status === "conflict" && result.reason_code === "HCS11_ACCOUNT_REFERENCE_MISMATCH" &&
        result.account_memo?.profile_reference === item.reference &&
        result.account_memo.protocol === "hcs-1") {
      result = await resolveHcs11ProfileV1(config, {
        ...expectations, expected_profile_reference: item.reference,
      }, decode);
      if (result.status === "resolved") {
        const expectedTopic = parseHcs1ReferenceV1(item.reference).topic_id;
        const historical = await resolveHcs2RegisterV1(config, {
          hedera_network: net, registry_topic_id: registryTopic,
          sequence_number: sequence, expected_t_id: expectedTopic,
        });
        if (historical.status !== "resolved" || !historical.consensus_timestamp) {
          return { status: historical.status === "resolved" ? "unavailable" : historical.status,
            code: historical.reason_code ?? "HCS11_HISTORICAL_REGISTRY_UNAVAILABLE",
            resolver: historical.resolver_id, times: [], currentMemo: true,
            sha256: result.content_sha256 };
        }
        directRegistryTime = historical.consensus_timestamp;
      }
    }
  } catch (error) {
    if (error instanceof Hcs14V1Error) return invalid(error.code);
    throw error;
  }
  const time = result.registry_entry?.consensus_timestamp ?? directRegistryTime;
  return {
    status: result.status, code: result.reason_code, resolver: result.resolver_id,
    times: time ? [time] : [], currentMemo: result.account_memo !== null,
    sha256: result.content_sha256,
    facts: result.status === "resolved" ? [
      fact("hedera.account_id", result.account_id),
      fact("hcs11.profile_reference", result.profile_reference!),
      fact("hcs11.profile_sha256", result.content_sha256!),
      fact("hcs11.account_memo_temporal_scope", "current_observation"),
      fact("hcs14.did_binding", result.did_binding),
    ] : [],
  };
}

async function schema(config: Hcs1MirrorV1Config, net: HederaNetwork,
  evidence: PublicSchemaEvidence | null | undefined,
  item: StandardsResolutionPlanItem, decode: Hcs1V1ContentOptions): Promise<ObservationData> {
  if (!evidence || !item.reference) return unavailable("HCS13_EXECUTION_REFERENCE_MISSING");
  const topicId = topic(evidence.registry_topic_id);
  const seq = positive(evidence.registry_sequence_number);
  const checksum = hex(evidence.schema_checksum_sha256);
  if (!topicId || !seq || !checksum || item.reference !== evidence.hcs13_ref) {
    return invalid("HCS13_EXECUTION_REFERENCE_INVALID");
  }
  let ref;
  try { ref = parseHcs13ReferenceV1(item.reference); }
  catch { return invalid("HCS13_EXECUTION_REFERENCE_INVALID"); }
  if (ref.registry_topic_id !== topicId || ref.sequence_number !== seq) {
    return mismatch("HCS13_EXECUTION_REFERENCE_SCOPE_MISMATCH");
  }
  const result = await resolveHcs13SchemaV1(config, {
    hedera_network: net, reference: item.reference, expected_schema_sha256: checksum,
  }, decode);
  return {
    status: result.status, code: result.reason_code, resolver: result.resolver_id,
    times: result.registry_consensus_timestamp_exact ? [result.registry_consensus_timestamp_exact] : [],
    currentMemo: result.registry_consensus_timestamp_exact !== null, sha256: result.content_sha256,
    facts: result.status === "resolved" ? [
      fact("hcs13.reference", result.reference.ref),
      fact("hcs13.schema_sha256", result.schema_sha256!),
      fact("hcs13.registry_memo_temporal_scope", "current_observation"),
    ] : [],
  };
}

async function capability(config: Hcs1MirrorV1Config, net: HederaNetwork,
  evidence: PublicCapabilityEvidence | null | undefined,
  item: StandardsResolutionPlanItem, decode: Hcs1V1ContentOptions): Promise<ObservationData> {
  if (!evidence || !item.reference) return unavailable("HCS26_EXECUTION_REFERENCE_MISSING");
  const discovery = topic(evidence.discovery_registry_topic_id);
  const versionTopic = topic(evidence.version_registry_topic_id);
  const uid = positive(evidence.skill_uid);
  const sequence = positive(evidence.version_sequence_number);
  const checksum = hex(evidence.manifest_checksum_sha256);
  const version = text(evidence.skill_version);
  if (!discovery || !versionTopic || !uid || !sequence || !checksum || !version ||
      !hasReference(item.reference) || item.reference !== evidence.manifest_hcs1_ref ||
      version.length > 64 || text(evidence.standard) !== "HCS-26") {
    return invalid("HCS26_EXECUTION_REFERENCE_INVALID");
  }
  const result = await resolveHcs26SkillVersionV1(config, {
    hedera_network: net, discovery_topic_id: discovery,
    discovery_sequence_number: uid, version_sequence_number: sequence,
    expected_skill_uid: uid, expected_version_topic_id: versionTopic,
    expected_version: version, expected_manifest_reference: item.reference,
    expected_manifest_sha256: checksum,
  }, decode);
  if (result.status === "resolved" && evidence.repository_commit && typeof result.manifest?.commit === "string" &&
      evidence.repository_commit !== result.manifest.commit) {
    return { status: "conflict", code: "HCS26_EXECUTION_RELEASE_COMMIT_MISMATCH",
      resolver: result.resolver_id,
      times: [result.discovery_consensus_timestamp_exact, result.version_consensus_timestamp_exact]
        .filter((v): v is string => v !== null),
      currentMemo: true, sha256: result.content_sha256,
      facts: [fact("hcs26.manifest_release_commit", result.manifest.commit)] };
  }
  return {
    status: result.status, code: result.reason_code, resolver: result.resolver_id,
    times: [result.discovery_consensus_timestamp_exact, result.version_consensus_timestamp_exact]
      .filter((v): v is string => v !== null),
    currentMemo: result.discovery_consensus_timestamp_exact !== null, sha256: result.content_sha256,
    facts: result.status === "resolved" ? [
      fact("hcs26.skill_uid", result.skill_uid!),
      fact("hcs26.version", result.version!),
      fact("hcs26.manifest_sha256", result.manifest_sha256!),
      fact("hcs26.historical_version_status", result.historical_version_status!),
      fact("hcs26.registry_memo_temporal_scope", "current_observation"),
      ...(typeof result.manifest?.commit === "string" ?
        [fact("hcs26.manifest_release_commit", result.manifest.commit)] : []),
    ] : [],
  };
}

function outcome(status: IndependentStandardsV1Item["status"]): VerificationOutcome {
  if (status === "resolved") return "pass";
  if (status === "conflict" || status === "invalid") return "fail";
  if (status === "unsupported") return "unsupported";
  return "indeterminate";
}
function aggregate(items: readonly IndependentStandardsV1Item[]):
  IndependentStandardsV1Report["independent_standards"]["status"] {
  if (items.some((i) => i.status === "invalid" || i.status === "conflict")) return "failed";
  if (items.length === 0 || items.some((i) => i.status !== "resolved")) return "unavailable";
  return "verified";
}
function summaryOutcome(state: IndependentStandardsV1Report["independent_standards"]["status"]): VerificationOutcome {
  return state === "verified" ? "pass" : state === "failed" ? "fail" : "indeterminate";
}

/**
 * Resolve the exact SAGE standards reference plan using the built-in Hedera
 * resolvers only. Does NOT accept an externally supplied resolver success map.
 * Caller-supplied intent is checked before any network I/O. The provided
 * execution evidence itself is NEVER authenticated merely by this operation.
 */
export async function verifyExecutionWithIndependentStandardsV1(
  config: Hcs1MirrorV1Config,
  input: ExecutionV1Input,
  decodeOptions: Hcs1V1ContentOptions = {},
): Promise<IndependentStandardsV1Report> {
  if (input?.profile !== undefined && input.profile !== "sage-standards-v1") {
    throw new TypeError("Independent SAGE standards require sage-standards-v1 profile");
  }
  const report = verifyExecutionV1WithIntent(input);
  const net = report.intent.subject.hedera_network;
  if (net !== "testnet" && net !== "mainnet") throw new TypeError("Execution network is required");
  const evidence = input.evidence as PublicExecutionStandardsEvidence;
  const preflight = report.findings.find((f) => f.check_id === "input.bounds")?.outcome === "pass" &&
    report.findings.find((f) => f.check_id === "intent.subject")?.outcome === "pass" &&
    report.findings.find((f) => f.check_id === "profile.program_scope")?.outcome === "pass" &&
    report.findings.find((f) => f.check_id === "intent.program")?.outcome !== "fail" &&
    report.findings.find((f) => f.check_id === "intent.result")?.outcome !== "fail" &&
    evidence?.available === true && networkMatch(evidence, net, report.intent.subject.id);
  let plan: readonly StandardsResolutionPlanItem[] = [];
  if (preflight) plan = buildStandardsResolutionPlan(evidence);
  const unique = new Set(plan.map((item) => item.key));
  const schemas = evidence?.standards?.schemas;
  const schemasValid = Array.isArray(schemas) && schemas.length > 0 && schemas.every((entry, index) => {
    const role = text(entry?.role);
    const ordinal = entry?.ordinal == null ? index : entry.ordinal;
    return role.length > 0 && role.length <= 128 && !/[\u0000-\u001f\u007f]/.test(role) &&
      Number.isSafeInteger(ordinal) && ordinal >= 0;
  });
  const planValid = schemasValid && plan.length >= 4 && plan.length <= MAX_REFERENCES &&
    unique.size === plan.length && plan.every((item) =>
      item.key.length > 0 && item.key.length <= 256 && item.reference.length <= 256);
  const run = Boolean(preflight && planValid);
  const items: IndependentStandardsV1Item[] = [];
  const observations: VerificationObservation[] = [...report.observations];
  const findings: VerificationFinding[] = [...report.findings];
  const subject = report.intent.subject;
  if (run) {
    // Sequential by design: bounds outstanding network requests and makes
    // observation ordering deterministic across hosts and timeouts.
    for (const [index, item] of plan.entries()) {
      let observed: ObservationData;
      if (item.target.kind === "agent") {
        observed = await agent(config, net, evidence.agents?.[item.target.role], item, decodeOptions);
      } else if (item.target.kind === "capability") {
        observed = await capability(config, net, evidence.capability, item, decodeOptions);
      } else {
        observed = await schema(config, net, evidence.standards?.schemas?.[item.target.index], item, decodeOptions);
      }
      const observationId = `standards.mirror.${index}`;
      const present = observed.resolver !== null;
      if (present) {
        observations.push(Object.freeze({ id: observationId, subject, source: "hedera_mirror" as const,
          resolver_id: observed.resolver!,
          facts: Object.freeze([
            fact("standards.plan_key", item.key), fact("standards.requested_reference", item.reference),
            fact("hedera.requested_network", net), fact("standards.resolution_status", observed.status),
            ...observed.times.map((t, i) => fact(`hedera.consensus_timestamp_exact.${i}`, t)),
            ...(observed.sha256 ? [fact("standards.content_sha256", observed.sha256)] : []),
            ...(observed.facts ?? []),
          ]),
        }));
      }
      items.push(Object.freeze({ key: item.key, standard: item.standard, reference: item.reference,
        status: observed.status, reason_code: observed.code, resolver_id: observed.resolver,
        historical_consensus_timestamps_exact: Object.freeze([...observed.times]),
        current_topic_or_account_memo_observed: observed.currentMemo,
        content_sha256: observed.sha256,
        assurance: observed.status === "resolved" ? "mirror_corroborated" : "not_established" }));
      findings.push(Object.freeze({ check_id: `standards.reference.${index}`,
        outcome: outcome(observed.status), reason_code: observed.code,
        observation_ids: Object.freeze(present ? [observationId] : []),
      }));
    }
  }
  const state = run ? aggregate(items) : "not_performed";
  const reason = !preflight ? "STANDARDS_EXECUTION_PREFLIGHT_FAILED" :
    !planValid ? "STANDARDS_RESOLUTION_PLAN_INVALID" :
    state === "verified" ? null : state === "failed" ? "STANDARDS_INDEPENDENT_REFERENCE_CONFLICT" :
    "STANDARDS_INDEPENDENT_REFERENCE_UNAVAILABLE";
  const summaryId = "standards.references_resolved";
  const summaryFinding: VerificationFinding = Object.freeze({ check_id: summaryId,
    outcome: summaryOutcome(state), reason_code: reason,
    observation_ids: Object.freeze(items.map((_v, i) => `standards.mirror.${i}`)
      .filter((id) => observations.some((obs) => obs.id === id))),
  });
  const existing = findings.findIndex((item) => item.check_id === summaryId);
  if (existing >= 0) findings[existing] = summaryFinding;
  else findings.push(summaryFinding);
  return Object.freeze({
    ...report,
    observations: Object.freeze(observations),
    findings: Object.freeze(findings),
    independent_standards: Object.freeze({ network: net, status: state,
      assurance: state === "verified" ? "mirror_corroborated" as const : "not_established" as const,
      items: Object.freeze(items), did_controller_authentication: "not_checked" as const,
      hedera_consensus_authentication: "not_checked" as const,
      historical_account_memo_binding: "not_checked" as const,
      manifest_files_resolution: "not_checked" as const,
      json_schema_instance_validation: "not_checked" as const,
    }),
  });
}
