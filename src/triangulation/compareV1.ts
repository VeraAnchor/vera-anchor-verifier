import type {
  EvidenceConsistency,
  VerificationFact,
  VerificationFinding,
  VerificationObservation,
  VerificationOutcome,
  VerificationReport,
  VerificationSubject,
} from "../contracts/verification.js";

/**
 * Pure scalar-consistency comparison for already normalized observations.
 * A matching observation is NOT proof that its provider is authentic or that
 * Explorer-disclosed plaintext is cryptographically bound to HCS ciphertext.
 * Plans must come from a trusted evidence profile, not an untrusted receipt.
 */
export type TriangulationRelationshipId =
  | "provided_public_record"
  | "public_record_hedera"
  | "provided_hedera"
  | "provided_authorized"
  | "authorized_hedera";

export type TriangulationFactPlanV1 = Readonly<{
  key: string;
  left_key: string;
  right_key: string;
}>;

export type TriangulationRelationshipPlanV1 = Readonly<{
  id: TriangulationRelationshipId;
  left_observation_id: string;
  right_observation_id: string;
  comparisons: readonly TriangulationFactPlanV1[];
}>;

export type TriangulationV1Input = Readonly<{
  /** Produced by an actual offline verifier invocation, not an authenticated attestation. */
  source_report: VerificationReport;
  /** Resolver/Mirror observations obtained outside this pure function. */
  observations: readonly VerificationObservation[];
  /** Explicit field mappings defined by the verifier's evidence profile. */
  relationships: readonly TriangulationRelationshipPlanV1[];
}>;

export type TriangulationFactResultV1 = Readonly<{
  key: string;
  outcome: VerificationOutcome;
  reason_code: string | null;
}>;

export type TriangulationRelationshipResultV1 = Readonly<{
  id: TriangulationRelationshipId;
  status: EvidenceConsistency | "not_applicable";
  fact_comparisons: readonly TriangulationFactResultV1[];
}>;

export type TriangulationV1Result = Readonly<{
  /** Consistency only, NOT cryptographic ledger authentication or policy approval. */
  consistency: EvidenceConsistency;
  relationships: readonly TriangulationRelationshipResultV1[];
  report: VerificationReport;
}>;

const MAX_OBSERVATIONS = 32;
const MAX_FACTS = 256;
const MAX_RELATIONSHIPS = 3;
const MAX_COMPARISONS = 64;
const MAX_SOURCE_FINDINGS = 256;
const ID_RE = /^[a-z][a-z0-9._:-]{0,127}$/;
const FACT_KEY_RE = /^[a-z][a-z0-9._:-]{0,159}$/;

function checkedId(value: unknown, field: string, pattern: RegExp): string {
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new TypeError(`Invalid ${field}`);
  }
  return value;
}

function matchesSubject(actual: VerificationSubject, expected: VerificationSubject): boolean {
  return actual.kind === expected.kind && actual.id === expected.id;
}

function factsByKey(observation: VerificationObservation): ReadonlyMap<string, VerificationFact> {
  if (!Array.isArray(observation.facts) || observation.facts.length > MAX_FACTS) {
    throw new TypeError("Triangulation observation exceeds the fact limit");
  }
  const facts = new Map<string, VerificationFact>();
  for (const fact of observation.facts) {
    const key = checkedId(fact?.key, "fact key", FACT_KEY_RE);
    if (facts.has(key)) throw new TypeError(`Duplicate observation fact: ${key}`);
    if (fact.state === "available") {
      if (
        !Object.hasOwn(fact, "value") ||
        (typeof fact.value === "number" && !Number.isFinite(fact.value)) ||
        (typeof fact.value !== "string" && typeof fact.value !== "number" &&
          typeof fact.value !== "boolean" && fact.value !== null) ||
        (typeof fact.value === "string" && fact.value.length > 4096)
      ) {
        throw new TypeError(`Invalid available fact: ${key}`);
      }
    } else if (fact.state === "unavailable" || fact.state === "not_applicable") {
      if (fact.reason_code !== undefined && fact.reason_code !== null &&
        (typeof fact.reason_code !== "string" || fact.reason_code.length > 160)) {
        throw new TypeError(`Invalid fact reason: ${key}`);
      }
    } else {
      throw new TypeError(`Invalid fact state: ${key}`);
    }
    facts.set(key, fact);
  }
  return facts;
}

function observationIndex(input: TriangulationV1Input): ReadonlyMap<string, VerificationObservation> {
  const all = [...input.source_report.observations, ...input.observations];
  if (all.length > MAX_OBSERVATIONS) throw new TypeError("Too many triangulation observations");
  const map = new Map<string, VerificationObservation>();
  for (const entry of all) {
    const id = checkedId(entry?.id, "observation id", ID_RE);
    if (map.has(id)) throw new TypeError(`Duplicate triangulation observation: ${id}`);
    if (!entry.subject || typeof entry.subject.id !== "string" ||
      typeof entry.subject.kind !== "string") {
      throw new TypeError(`Invalid triangulation observation subject: ${id}`);
    }
    factsByKey(entry);
    map.set(id, entry);
  }
  // An external caller may not replace an offline source observation.
  for (const entry of input.observations) {
    if (entry.source === "local_computation") {
      throw new TypeError("External observations cannot assert local computation");
    }
  }
  return map;
}

function roleAllowed(
  relationship: TriangulationRelationshipId,
  left: VerificationObservation,
  right: VerificationObservation,
): boolean {
  if (relationship === "provided_public_record") {
    return (left.source === "provided_evidence" || left.source === "local_computation") &&
      right.source === "public_record";
  }
  if (relationship === "provided_hedera") {
    return (left.source === "provided_evidence" || left.source === "local_computation") &&
      right.source === "hedera_mirror";
  }
  if (relationship === "provided_authorized") {
    return (left.source === "provided_evidence" || left.source === "local_computation") &&
      right.source === "authorized_service";
  }
  if (relationship === "authorized_hedera") {
    return left.source === "authorized_service" && right.source === "hedera_mirror";
  }
  return left.source === "public_record" && right.source === "hedera_mirror";
}

function scopeOutcome(
  actual: VerificationObservation,
  expected: VerificationSubject,
): Readonly<{ outcome: VerificationOutcome; reason: string | null }> {
  if (!matchesSubject(actual.subject, expected)) {
    return { outcome: "fail", reason: "OBSERVATION_SUBJECT_MISMATCH" };
  }
  if (!expected.hedera_network) {
    return { outcome: "indeterminate", reason: "EXPECTED_NETWORK_UNAVAILABLE" };
  }
  if (!actual.subject.hedera_network) {
    return { outcome: "indeterminate", reason: "OBSERVATION_NETWORK_UNAVAILABLE" };
  }
  if (actual.subject.hedera_network !== expected.hedera_network) {
    return { outcome: "fail", reason: "OBSERVATION_NETWORK_MISMATCH" };
  }
  return { outcome: "pass", reason: null };
}

function unavailableReason(fact: VerificationFact): string | null {
  return fact.state === "available" ? null : fact.reason_code ?? null;
}

function compareFacts(
  left: VerificationFact | undefined,
  right: VerificationFact | undefined,
): Readonly<{ outcome: VerificationOutcome; reason: string | null }> {
  if (!left || !right) return { outcome: "indeterminate", reason: "FACT_MISSING" };
  if (left.state === "not_applicable" || right.state === "not_applicable") {
    return { outcome: "skipped", reason: unavailableReason(left) ?? unavailableReason(right) ?? "FACT_NOT_APPLICABLE" };
  }
  if (left.state !== "available" || right.state !== "available") {
    return { outcome: "indeterminate", reason: unavailableReason(left) ?? unavailableReason(right) ?? "FACT_UNAVAILABLE" };
  }
  const matches = Object.is(left.value, right.value);
  return { outcome: matches ? "pass" : "fail", reason: matches ? null : "FACT_MISMATCH" };
}

function aggregate(results: readonly TriangulationFactResultV1[]): TriangulationRelationshipResultV1["status"] {
  if (results.length === 0 || results.every((check) => check.outcome === "skipped")) return "not_applicable";
  if (results.some((check) => check.outcome === "fail")) return "conflict";
  if (results.some((check) => check.outcome === "indeterminate" || check.outcome === "unsupported")) return "incomplete";
  return "consistent";
}

function check(
  id: string,
  outcome: VerificationOutcome,
  reason: string | null,
  observationIds: readonly string[],
): VerificationFinding {
  return Object.freeze({
    check_id: id,
    outcome,
    reason_code: reason,
    observation_ids: Object.freeze([...observationIds]),
  });
}

/**
 * Compare bounded scalar facts with explicitly mapped, asymmetric field keys.
 * Network/subject checks apply independently of the requested fact comparisons.
 * This does not verify the authenticity of a resolver or of source_report itself.
 */
export function compareEvidenceTriangulationV1(input: TriangulationV1Input): TriangulationV1Result {
  if (!input || !input.source_report?.intent?.subject ||
    !Array.isArray(input.source_report.findings) ||
    input.source_report.findings.length > MAX_SOURCE_FINDINGS ||
    !Array.isArray(input.source_report.observations) ||
    !Array.isArray(input.relationships) || input.relationships.length > MAX_RELATIONSHIPS ||
    !Array.isArray(input.observations)) {
    throw new TypeError("Invalid triangulation input");
  }
  const map = observationIndex(input);
  const usedRelationships = new Set<TriangulationRelationshipId>();
  const findings = [...input.source_report.findings];
  const usedCheckIds = new Set(findings.map((entry) => entry.check_id));
  const results: TriangulationRelationshipResultV1[] = [];

  for (const relationship of input.relationships) {
    if (!["provided_public_record", "public_record_hedera", "provided_hedera", "provided_authorized", "authorized_hedera"].includes(relationship.id) ||
      usedRelationships.has(relationship.id)) {
      throw new TypeError("Unknown or duplicated triangulation relationship");
    }
    usedRelationships.add(relationship.id);
    if (!Array.isArray(relationship.comparisons) || relationship.comparisons.length > MAX_COMPARISONS) {
      throw new TypeError("Too many triangulation fact comparisons");
    }
    const leftId = checkedId(relationship.left_observation_id, "left observation id", ID_RE);
    const rightId = checkedId(relationship.right_observation_id, "right observation id", ID_RE);
    if (leftId === rightId) throw new TypeError("Triangulation cannot compare an observation with itself");
    const left = map.get(leftId);
    const right = map.get(rightId);
    if (left && right && !roleAllowed(relationship.id, left, right)) {
      throw new TypeError("Triangulation observation sources do not match their relationship roles");
    }
    const leftFacts = left ? factsByKey(left) : null;
    const rightFacts = right ? factsByKey(right) : null;
    const compared: TriangulationFactResultV1[] = [];
    const usedKeys = new Set<string>();

    for (const comparison of relationship.comparisons) {
      const key = checkedId(comparison.key, "comparison key", FACT_KEY_RE);
      const leftKey = checkedId(comparison.left_key, "left comparison key", FACT_KEY_RE);
      const rightKey = checkedId(comparison.right_key, "right comparison key", FACT_KEY_RE);
      if (usedKeys.has(key)) throw new TypeError(`Duplicate triangulation comparison: ${key}`);
      usedKeys.add(key);
      const checkId = `triangulation.${relationship.id}.${key}`;
      if (usedCheckIds.has(checkId)) throw new TypeError(`Duplicate triangulation check: ${checkId}`);
      usedCheckIds.add(checkId);

      let evaluated: Readonly<{ outcome: VerificationOutcome; reason: string | null }>;
      if (!left || !right) {
        evaluated = { outcome: "indeterminate", reason: "OBSERVATION_UNAVAILABLE" };
      } else {
        const leftScope = scopeOutcome(left, input.source_report.intent.subject);
        const rightScope = scopeOutcome(right, input.source_report.intent.subject);
        if (leftScope.outcome === "fail" || rightScope.outcome === "fail") {
          evaluated = { outcome: "fail", reason: leftScope.outcome === "fail" ? leftScope.reason : rightScope.reason };
        } else if (
          (leftScope.outcome !== "pass" && left.source !== "local_computation") ||
          (rightScope.outcome !== "pass" && right.source !== "local_computation")
        ) {
          evaluated = { outcome: "indeterminate", reason: "NETWORK_SCOPE_UNAVAILABLE" };
        } else {
          evaluated = compareFacts(leftFacts?.get(leftKey), rightFacts?.get(rightKey));
        }
      }
      compared.push(Object.freeze({ key, outcome: evaluated.outcome, reason_code: evaluated.reason }));
      findings.push(check(checkId, evaluated.outcome, evaluated.reason, [leftId, rightId].filter((id) => map.has(id))));
    }
    results.push(Object.freeze({
      id: relationship.id,
      status: aggregate(compared),
      fact_comparisons: Object.freeze(compared),
    }));
  }

  // Source verification is a prerequisite, not a fourth independent authority.
  // A supplied report is NOT an authenticated attestation: callers must obtain
  // it through the SDK's own source-verification entry points.
  const requiredSourceChecks = [
    `${input.source_report.intent.subject.kind}.source_binding`,
    `${input.source_report.intent.subject.kind}.bundle_consistency`,
    "intent.subject",
  ];
  const requiredResults = requiredSourceChecks.map((id) =>
    input.source_report.findings.find((entry) => entry.check_id === id)?.outcome,
  );
  const consistency: EvidenceConsistency =
    input.source_report.findings.some((entry) => entry.outcome === "fail") ||
    results.some((entry) => entry.status === "conflict")
      ? "conflict"
      : requiredResults.some((outcome) => outcome !== "pass") ||
          results.length === 0 || results.some((entry) => entry.status !== "consistent")
        ? "incomplete"
        : "consistent";
  const observations = [...input.source_report.observations, ...input.observations];
  return Object.freeze({
    consistency,
    relationships: Object.freeze(results),
    report: Object.freeze({
      intent: input.source_report.intent,
      findings: Object.freeze(findings),
      observations: Object.freeze(observations),
    }),
  });
}
