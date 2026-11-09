/**
 * Pure execution triangulation preparation.
 * Claimed locations are never treated as independently resolved evidence.
 * Original/private HCS anchors establish provenance identifiers only, not
 * plaintext-publication or application-data-hash integrity.
 */
import type { HederaNetwork, VerificationFact, VerificationObservation } from "../contracts/verification.js";
import type { PublicExecutionStandardsEvidence } from "../profiles/execution/contractV1.js";
import { verifyExecutionV1WithIntent, type ExecutionV1Input, type ExecutionV1Report } from "../profiles/execution/verificationV1.js";
import type { TriangulationV1Input, TriangulationFactPlanV1, TriangulationRelationshipPlanV1 } from "./compareV1.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH = /^[0-9a-f]{128}$/i;
const TOPIC = /^0\.0\.[0-9]+$/;
const TX = /^(0\.0\.[0-9]+)[@-]([0-9]{1,12})[.-]([0-9]{1,9})$/;
const MESSAGE = /^(?:([1-9][0-9]*)@(0\.0\.[0-9]+)|(0\.0\.[0-9]+)@([1-9][0-9]*))$/;
const PROVIDED_ID = "execution.provided.claims";
const PUBLIC_ID = "execution.public";
export const EXECUTION_HEDERA_OBSERVATION_V1_ID = "execution.hedera";

type Side = "provided_evidence" | "public_record";
type Role = "acceptance_anchor" | "result_evidence_anchor";
export type ExecutionHederaTargetV1 = Readonly<{
  source: Side;
  role: Role;
  network: HederaNetwork;
  transaction_id: string | null;
  topic_id: string | null;
  sequence_number: number | null;
  /** Mirrors must derive facts from actual retrieved bytes/metadata, not from this claim. */
  observation_fact_prefix: string;
}>;
export type ExecutionTriangulationPlanV1 = Readonly<{
  stage: "unresolved_authority_plan";
  /** Public input has not yet been acquired or authenticated by an SDK resolver. */
  public_record_acquisition: "not_checked";
  hedera_resolution: "not_checked";
  source_report: ExecutionV1Report;
  triangulation: TriangulationV1Input;
  hedera_targets: readonly ExecutionHederaTargetV1[];
}>;

function record(value: unknown, field: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError(`${field} must be an object`);
  return value as Record<string, unknown>;
}
function optional(value: unknown, field: string, limit = 256): string | null {
  if (value == null || value === "") return null;
  if (typeof value !== "string" || value.length > limit || value !== value.trim()) {
    throw new TypeError(`${field} must be a bounded canonical string`);
  }
  return value || null;
}
function scopedUuid(value: unknown, field: string, required = false): string | null {
  const str = optional(value, field, 64)?.toLowerCase() ?? null;
  if ((required && !str) || (str && !UUID.test(str))) throw new TypeError(`${field} must be a UUID`);
  return str;
}
function digest(value: unknown, field: string): string | null {
  const str = optional(value, field, 128)?.toLowerCase() ?? null;
  if (str && !HASH.test(str)) throw new TypeError(`${field} must be SHA3-512 hex`);
  return str;
}
function transaction(value: unknown, field: string): string | null {
  const str = optional(value, field, 128);
  if (!str) return null;
  const match = TX.exec(str);
  if (!match) throw new TypeError(`${field} must be a Hedera transaction identifier`);
  return `${match[1]}@${match[2]}.${match[3]!.padStart(9, "0")}`;
}
function messageScope(value: unknown): { topic_id: string; sequence_number: number } | null {
  const str = optional(value, "acceptance.hcs.message_id", 128);
  if (!str) return null;
  const match = MESSAGE.exec(str);
  if (!match) throw new TypeError("Invalid acceptance HCS message identifier");
  const number = Number(match[1] ?? match[4]);
  if (!Number.isSafeInteger(number) || number < 1) throw new TypeError("Invalid HCS message sequence");
  return { topic_id: (match[2] ?? match[3])!, sequence_number: number };
}
function ledgerClaim(
  value: unknown, source: Side, role: Role, network: HederaNetwork,
): ExecutionHederaTargetV1 | null {
  if (value == null) return null;
  const hcs = record(value, `${role}.hcs`);
  const tx = transaction(hcs.transaction_id, `${role}.hcs.transaction_id`);
  const msg = role === "acceptance_anchor" ? messageScope(hcs.message_id) : null;
  const rawTopic = optional(hcs.topic_id, `${role}.hcs.topic_id`, 64);
  if (rawTopic && !TOPIC.test(rawTopic)) throw new TypeError("Invalid HCS topic identifier");
  const rawSequence = hcs.sequence_number;
  const seq = rawSequence == null ? null : rawSequence;
  if (seq != null && (typeof seq !== "number" || !Number.isSafeInteger(seq) || seq < 1)) {
    throw new TypeError("Invalid HCS sequence number");
  }
  if (msg && ((rawTopic && rawTopic !== msg.topic_id) || (seq && seq !== msg.sequence_number))) {
    throw new TypeError("HCS message locator conflict");
  }
  let topic_id = rawTopic ?? msg?.topic_id ?? null;
  let sequence_number = (seq as number | null) ?? msg?.sequence_number ?? null;
  if ((topic_id === null) !== (sequence_number === null)) {
    // Topic without exact message sequence is not independently resolvable.
    // A separate transaction can still be observed, but never infer its sequence.
    if (!tx) throw new TypeError("Incomplete HCS message locator");
    topic_id = null;
    sequence_number = null;
  }
  if (!tx && !topic_id) return null;
  return Object.freeze({ source, role, network, transaction_id: tx, topic_id, sequence_number,
    observation_fact_prefix: `ledger.${source}.${role}` });
}
function fact(key: string, value: string | null): VerificationFact {
  return value === null ? Object.freeze({ key, state: "unavailable" as const, reason_code: "EXECUTION_COMMITMENT_UNAVAILABLE" }) :
    Object.freeze({ key, state: "available" as const, value });
}
function addFact(facts: VerificationFact[], key: string, value: string | null) {
  facts.push(fact(key, value));
}
function scopeFacts(evidence: PublicExecutionStandardsEvidence, resultId: string | null): VerificationFact[] {
  const exe = evidence.execution;
  const facts: VerificationFact[] = [];
  addFact(facts, "execution.job_id", scopedUuid(exe?.job_id, "execution.job_id"));
  addFact(facts, "execution.hedera_network", optional(exe?.hedera_network, "execution.hedera_network", 16));
  addFact(facts, "execution.program", optional(exe?.program, "execution.program", 128)?.toLowerCase() ?? null);
  addFact(facts, "execution.pipeline_hash", digest(exe?.pipeline_hash, "execution.pipeline_hash"));
  addFact(facts, "dataset.fingerprint_sha3_512", digest(exe?.dataset?.dataset_fingerprint_sha3_512, "dataset.fingerprint"));
  addFact(facts, "dataset.manifest_sha3_512", digest(exe?.dataset?.dataset_manifest_sha3_512, "dataset.manifest"));
  addFact(facts, "binding.digest", digest(evidence.binding?.digest, "binding.digest"));
  addFact(facts, "acceptance.digest", digest(evidence.acceptance?.digest, "acceptance.digest"));
  if (resultId) {
    addFact(facts, "execution.result_id", scopedUuid(evidence.result_evidence?.result_id ?? exe?.result_id, "result_id"));
    addFact(facts, "result_evidence.digest", digest(evidence.result_evidence?.digest, "result_evidence.digest"));
    addFact(facts, "result_evidence.result_hash", digest(evidence.result_evidence?.result_hash, "result_hash"));
    addFact(facts, "result_evidence.service_hash", digest(evidence.result_evidence?.service_hash, "service_hash"));
    addFact(facts, "result_evidence.global_hash", digest(evidence.result_evidence?.global_hash, "global_hash"));
  }
  return facts;
}
function claimFacts(facts: VerificationFact[], claims: readonly ExecutionHederaTargetV1[], resultId: string | null) {
  for (const role of (["acceptance_anchor", ...(resultId ? ["result_evidence_anchor"] : [])] as Role[])) {
    const claim = claims.find((candidate) => candidate.role === role);
    addFact(facts, `${role}.transaction_id`, claim?.transaction_id ?? null);
    addFact(facts, `${role}.topic_id`, claim?.topic_id ?? null);
    addFact(facts, `${role}.sequence_number`, claim?.sequence_number?.toString() ?? null);
  }
}
function observations(
  evidence: PublicExecutionStandardsEvidence, side: Side, subject: ExecutionV1Report["intent"]["subject"],
  resultId: string | null, targets: readonly ExecutionHederaTargetV1[],
): VerificationObservation {
  const facts = scopeFacts(evidence, resultId);
  claimFacts(facts, targets, resultId);
  return Object.freeze({ id: side === "public_record" ? PUBLIC_ID : PROVIDED_ID, subject,
    source: side, facts: Object.freeze(facts) });
}
function targetsOf(evidence: PublicExecutionStandardsEvidence, side: Side,
  network: HederaNetwork, resultId: string | null): ExecutionHederaTargetV1[] {
  const acceptance = ledgerClaim(evidence.acceptance?.hcs, side, "acceptance_anchor", network);
  const result = resultId ? ledgerClaim(evidence.result_evidence?.hcs, side, "result_evidence_anchor", network) : null;
  return [acceptance, result].filter((v): v is ExecutionHederaTargetV1 => v !== null);
}
function pairs(left: VerificationObservation, right: VerificationObservation): TriangulationFactPlanV1[] {
  const rightKeys = new Set(right.facts.map((f) => f.key));
  return left.facts.filter((f) => f.state === "available" && rightKeys.has(f.key))
    .map((f) => Object.freeze({ key: f.key, left_key: f.key, right_key: f.key }));
}
function hederaComparisons(targets: readonly ExecutionHederaTargetV1[]): TriangulationFactPlanV1[] {
  return targets.flatMap((target) => {
    const comparison: TriangulationFactPlanV1[] = [];
    const base = target.observation_fact_prefix;
    if (target.transaction_id) comparison.push(Object.freeze({ key: `${target.role}.transaction_id`,
      left_key: `${target.role}.transaction_id`, right_key: `${base}.transaction_id` }));
    if (target.topic_id && target.sequence_number) {
      comparison.push(Object.freeze({ key: `${target.role}.topic_id`, left_key: `${target.role}.topic_id`, right_key: `${base}.topic_id` }));
      comparison.push(Object.freeze({ key: `${target.role}.sequence_number`, left_key: `${target.role}.sequence_number`, right_key: `${base}.sequence_number` }));
    }
    return comparison;
  });
}

/** Prepare a plan. The returned Mirror observation id is RESERVED, not populated. */
export function prepareExecutionTriangulationV1(input: Readonly<{
  execution: ExecutionV1Input;
  public_evidence: PublicExecutionStandardsEvidence;
}>): ExecutionTriangulationPlanV1 {
  const source = verifyExecutionV1WithIntent(input.execution);
  if (source.findings.find((f) => f.check_id === "input.bounds")?.outcome !== "pass") {
    throw new TypeError("Provided execution evidence failed structural bounds");
  }
  const subject = source.intent.subject;
  const network = subject.hedera_network;
  if (network !== "testnet" && network !== "mainnet") throw new TypeError("Execution network is required");
  const requestedResult = source.verification_scope.requested_result_id;
  const pub = input.public_evidence;
  if (!pub || pub.available !== true) throw new TypeError("Public execution evidence is unavailable");
  if (scopedUuid(pub.execution?.job_id, "public.execution.job_id", true) !== subject.id ||
      pub.execution?.hedera_network !== network) throw new TypeError("Public execution scope mismatch");
  if (requestedResult) {
    const actual = scopedUuid(pub.result_evidence?.result_id ?? pub.execution?.result_id,
      "public.result_id", true);
    if (actual !== requestedResult) throw new TypeError("Public execution result scope mismatch");
  }
  const provided = record(input.execution.evidence, "provided execution evidence") as PublicExecutionStandardsEvidence;
  const providedResult = requestedResult ? scopedUuid(provided.result_evidence?.result_id ?? provided.execution?.result_id,
    "provided.result_id") : null;
  if (providedResult && providedResult !== requestedResult) throw new TypeError("Provided result scope mismatch");
  if (provided.execution?.job_id && scopedUuid(provided.execution.job_id, "provided.job_id") !== subject.id) {
    throw new TypeError("Provided execution job scope mismatch");
  }
  if (provided.execution?.hedera_network && provided.execution.hedera_network !== network) {
    throw new TypeError("Provided execution network scope mismatch");
  }
  const publicTargets = targetsOf(pub, "public_record", network, requestedResult);
  const providedTargets = targetsOf(provided, "provided_evidence", network, requestedResult);
  const publicObservation = observations(pub, "public_record", subject, requestedResult, publicTargets);
  const providedObservation = observations(provided, "provided_evidence", subject, requestedResult, providedTargets);
  const pp = pairs(providedObservation, publicObservation);
  const relationships: TriangulationRelationshipPlanV1[] = [
    Object.freeze({ id: "provided_public_record", left_observation_id: PROVIDED_ID,
      right_observation_id: PUBLIC_ID, comparisons: Object.freeze(pp) }),
    Object.freeze({ id: "public_record_hedera", left_observation_id: PUBLIC_ID,
      right_observation_id: EXECUTION_HEDERA_OBSERVATION_V1_ID,
      comparisons: Object.freeze(hederaComparisons(publicTargets)) }),
    Object.freeze({ id: "provided_hedera", left_observation_id: PROVIDED_ID,
      right_observation_id: EXECUTION_HEDERA_OBSERVATION_V1_ID,
      comparisons: Object.freeze(hederaComparisons(providedTargets)) }),
  ];
  return Object.freeze({ stage: "unresolved_authority_plan" as const,
    public_record_acquisition: "not_checked" as const, hedera_resolution: "not_checked" as const,
    source_report: source,
    triangulation: Object.freeze({ source_report: source,
      observations: Object.freeze([providedObservation, publicObservation]),
      relationships: Object.freeze(relationships) }),
    hedera_targets: Object.freeze([...publicTargets, ...providedTargets]),
  });
}
