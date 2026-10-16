// Pure, offline execution verification; SAGE adds required standards checks.
// No Core, Explorer, Hedera or network I/O.
import type {
  VerificationFact, VerificationFinding, VerificationIntent,
  VerificationObservation, VerificationOutcome, VerificationReport,
} from "../../contracts/verification.js";
import {
  EXECUTION_VERIFICATION_SCHEMA_VERSION, EXECUTION_VERIFIER_VERSION,
  SUPPORTED_PUBLIC_STANDARDS_CONTRACT_VERSIONS,
  freezeVerificationReport, makeVerificationCheck, outcomeStatus,
  validateExecutionVerificationInputBounds, verificationSummary,
  type ExecutionVerificationCheck, type ExecutionVerificationReport,
  type PublicExecutionStandardsEvidence, type PublicExecutionVerificationMaterial,
  type ExecutionVerificationContext,
} from "./contractV1.js";
import { EXECUTION_VERIFICATION_REASON_CODES as REASONS } from "./reasonCodesV1.js";
import { COMMON_EXECUTION_VERIFICATION_RULES, EXECUTION_VERIFICATION_RULES } from "./rulesV1.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_PROGRAM = 128;

/** Explicitly supported verification profiles; not arbitrary compute contract versions. */
export type ExecutionV1Profile = "execution-v1" | "sage-standards-v1";

export type ExecutionV1Report = VerificationReport & Readonly<{
  /** Independent caller constraints retained for audit and future portable reports. */
  verification_scope: Readonly<{
    profile: ExecutionV1Profile;
    expected_program: string | null;
    requested_result_id: string | null;
  }>;
}>;

export type ExecutionV1Input = Readonly<{
  /** Defaults to SAGE for compatibility with the initial unreleased offline API. */
  profile?: ExecutionV1Profile;
  evidence: unknown;
  intent: VerificationIntent;
  result_id?: string | null;
  verification_material?: PublicExecutionVerificationMaterial | null;
  /** Independently supplied expected program, when required by the caller. */
  expected_program?: string;
}>;

function finding(check_id: string, outcome: VerificationOutcome, reason_code: string | null,
  observation_ids: readonly string[]): VerificationFinding {
  return Object.freeze({ check_id, outcome, reason_code, observation_ids: Object.freeze([...observation_ids]) });
}

function fact(key: string, value: string | number | boolean | null): VerificationFact {
  return Object.freeze({ key, state: "available" as const, value });
}

function mapStatus(check: ExecutionVerificationCheck): VerificationOutcome {
  switch (check.status) {
    case "pass": return "pass";
    case "fail": return "fail";
    case "unavailable": return "indeterminate";
    case "not_applicable": return "skipped";
  }
}

function checkedInput(input: ExecutionV1Input): {
  network: "mainnet" | "testnet";
  jobId: string;
  resultId: string;
  expectedProgram: string;
  profile: ExecutionV1Profile;
} {
  if (!input || typeof input !== "object" || !input.intent || typeof input.intent !== "object") {
    throw new TypeError("Execution verification requires caller intent");
  }
  const profile = input.profile ?? "sage-standards-v1";
  if (profile !== "execution-v1" && profile !== "sage-standards-v1") {
    throw new TypeError("Unsupported execution verification profile");
  }
  const intent = input.intent;
  if (intent.subject?.kind !== "execution" || !UUID.test(intent.subject.id) ||
      (intent.subject.hedera_network !== "mainnet" && intent.subject.hedera_network !== "testnet")) {
    throw new TypeError("Execution intent requires an exact job UUID and Hedera network");
  }
  if (!Array.isArray(intent.expected) || intent.expected.length) {
    // No execution-specific expected commitment vocabulary is defined yet.
    // Never silently ignore caller requirements or claim an HF digest domain.
    throw new TypeError("Execution v1 does not support generic expected commitments; supply explicit supported inputs");
  }
  const resultId = input.result_id == null ? "" : input.result_id.trim().toLowerCase();
  if (resultId && !UUID.test(resultId)) throw new TypeError("Requested result_id must be a UUID");
  const expectedProgram = input.expected_program ?? "";
  if (typeof expectedProgram !== "string" || expectedProgram.length > MAX_PROGRAM ||
      (expectedProgram && expectedProgram.trim() !== expectedProgram)) {
    throw new TypeError("Expected program must be a bounded canonical string");
  }
  // Generic profile cannot infer the expected program from untrusted evidence.
  // A caller explicitly asking for SAGE must use the standards-backed profile.
  if (profile === "execution-v1" && !expectedProgram) {
    throw new TypeError("execution-v1 requires an independently supplied expected_program");
  }
  if (profile === "execution-v1" && expectedProgram.toLowerCase() === "sage") {
    throw new TypeError("SAGE requires sage-standards-v1 verification profile");
  }
  return {
    network: intent.subject.hedera_network,
    jobId: intent.subject.id.toLowerCase(),
    resultId,
    expectedProgram: expectedProgram.toLowerCase(),
    profile,
  };
}

/** Explorer-compatible rule evaluation: pure, ordered and no network reads. */
function checkExecutionStandardsV1(
  evidenceInput: unknown,
  options: Readonly<{
    network: "mainnet" | "testnet";
    profile: ExecutionV1Profile;
    result_id?: string | null;
    verification_material?: PublicExecutionVerificationMaterial | null;
  }>,
): ExecutionVerificationReport {
  const bounds = validateExecutionVerificationInputBounds(evidenceInput);
  const material = options.verification_material ?? null;
  const materialBounds = material == null ? null : validateExecutionVerificationInputBounds(material);
  const inputError = !bounds.ok ? bounds.reasonCode : materialBounds && !materialBounds.ok ? materialBounds.reasonCode : null;
  if (inputError) {
    const check = makeVerificationCheck({
      id: "input.bounds", group: "contract", label: "Verification input is safely bounded and structurally supported",
      requirement: "required", status: "fail", reasonCode: inputError, evidenceRefs: [],
    });
    return freezeVerificationReport({
      schema_version: EXECUTION_VERIFICATION_SCHEMA_VERSION, verifier_version: EXECUTION_VERIFIER_VERSION,
      subject: { hedera_network: options.network, program: null, job_id: null, result_id: options.result_id ?? null },
      status: "failed", summary: verificationSummary([check]), checks: Object.freeze([check]),
    });
  }
  const evidence = evidenceInput as PublicExecutionStandardsEvidence;
  const requestedResultId = (options.result_id ?? "").trim().toLowerCase();
  const ctx: ExecutionVerificationContext = Object.freeze({
    evidence, verificationMaterial: material, expectedNetwork: options.network,
    requestedResultId, supportedContractVersions: SUPPORTED_PUBLIC_STANDARDS_CONTRACT_VERSIONS,
  });
  const checks: ExecutionVerificationCheck[] = [makeVerificationCheck({
    id: "input.bounds", group: "contract", label: "Verification input is safely bounded and structurally supported",
    requirement: "required", status: "pass", reasonCode: REASONS.CHECK_PASSED, evidenceRefs: [],
  })];
  const applicable = options.profile === "sage-standards-v1"
    ? EXECUTION_VERIFICATION_RULES
    : COMMON_EXECUTION_VERIFICATION_RULES;
  const rules = evidence.available === true ? applicable :
    applicable.filter((rule) => rule.id === "public_evidence.available" || rule.id === "public_evidence.contract_version");
  for (const rule of rules) {
    const result = rule.evaluate(ctx);
    checks.push(makeVerificationCheck({
      id: rule.id, group: rule.group, label: rule.label, requirement: rule.requirement,
      status: result.status, reasonCode: result.reasonCode, evidenceRefs: rule.evidenceRefs,
    }));
  }
  const network = evidence.execution?.hedera_network;
  const subjectNetwork = network === "testnet" || network === "mainnet" ? network : null;
  return freezeVerificationReport({
    schema_version: EXECUTION_VERIFICATION_SCHEMA_VERSION,
    verifier_version: EXECUTION_VERIFIER_VERSION,
    subject: {
      hedera_network: subjectNetwork,
      program: typeof evidence.execution?.program === "string" ? evidence.execution.program.trim().toLowerCase() || null : null,
      job_id: typeof evidence.execution?.job_id === "string" ? evidence.execution.job_id.trim().toLowerCase() || null : null,
      result_id: requestedResultId || null,
    },
    status: outcomeStatus(checks), summary: verificationSummary(checks), checks: Object.freeze(checks),
  });
}

/**
 * SDK-native findings. The supplied evidence is not authenticated or independently
 * resolved, even when structural checks or recomputations pass.
 */
export function verifyExecutionV1WithIntent(input: ExecutionV1Input): ExecutionV1Report {
  const opts = checkedInput(input);
  const raw = checkExecutionStandardsV1(input.evidence, {
    network: opts.network, profile: opts.profile, result_id: opts.resultId,
    // Exact optional properties: never pass explicit undefined.
    verification_material: input.verification_material ?? null,
  });
  const safe = raw.checks[0]?.status === "pass";
  const evidence = safe ? input.evidence as PublicExecutionStandardsEvidence : null;
  const execution = evidence?.execution;
  const sourceId = "execution.provided";
  const computedId = "execution.recomputed";
  const subject = Object.freeze({ kind: "execution" as const, id: opts.jobId, hedera_network: opts.network });
  const sourceFacts: VerificationFact[] = [];
  if (raw.subject.job_id) sourceFacts.push(fact("job_id", raw.subject.job_id));
  if (raw.subject.hedera_network) sourceFacts.push(fact("hedera_network", raw.subject.hedera_network));
  if (raw.subject.program) sourceFacts.push(fact("program", raw.subject.program));
  const observations: VerificationObservation[] = [Object.freeze({
    id: sourceId, subject, source: "provided_evidence" as const, facts: Object.freeze(sourceFacts),
  })];
  const recomputed = raw.checks.filter((check) =>
    check.status === "pass" && (check.id.endsWith(".digest_recomputed") || check.id === "acceptance.digest_recomputed" || check.id === "parameters.commitment_matches"));
  if (recomputed.length) observations.push(Object.freeze({
    id: computedId, subject, source: "local_computation" as const,
    facts: Object.freeze(recomputed.map((check) => fact(`check.${check.id}`, true))),
  }));
  const findings: VerificationFinding[] = raw.checks.map((check) => {
    // Explorer may receive standards_resolution from its trusted resolver.
    // Offline SDK callers supply this material directly: neither a "verified"
    // nor a "failed" resolver assertion establishes the independent outcome.
    // Structural claims are still checked separately by the other standards rules.
    const untrustedResolution = check.id === "standards.references_resolved";
    return finding(check.id, untrustedResolution ? "indeterminate" : mapStatus(check),
      untrustedResolution ? "STANDARDS_RESOLUTION_NOT_INDEPENDENTLY_VERIFIED" :
        check.reason_code === REASONS.CHECK_PASSED || check.reason_code === REASONS.NOT_APPLICABLE ? null : check.reason_code,
      check.id === "input.bounds" ? [] : recomputed.some((item) => item.id === check.id) ? [sourceId, computedId] : [sourceId]);
  });
  // Restrict SAGE to the standards-backed profile. Checking a declared program
  // is a scope guard, not independent authentication of the program identity.
  const declaredProgram = raw.subject.program;
  const profileMatches = opts.profile === "sage-standards-v1"
    ? declaredProgram === "sage"
    : declaredProgram !== "sage";
  findings.push(finding("profile.program_scope",
    !safe || !declaredProgram ? "indeterminate" : profileMatches ? "pass" : "fail",
    !safe || !declaredProgram ? "EXECUTION_PROGRAM_UNAVAILABLE" :
      profileMatches ? null : "EXECUTION_PROFILE_PROGRAM_MISMATCH",
    safe ? [sourceId] : [],
  ));
  if (opts.profile === "execution-v1") {
    findings.push(finding("profile.standards_scope", "skipped", "STANDARDS_PROFILE_NOT_SELECTED", []));
  }

  const actualJob = raw.subject.job_id;
  findings.push(finding("intent.subject", !safe || !actualJob ? "indeterminate" : actualJob === opts.jobId ? "pass" : "fail",
    !safe || !actualJob ? "EXECUTION_SUBJECT_UNAVAILABLE" : actualJob === opts.jobId ? null : "SUBJECT_MISMATCH", safe ? [sourceId] : []));
  if (opts.resultId) {
    const actualResult = typeof evidence?.result_evidence?.result_id === "string" ? evidence.result_evidence.result_id.trim().toLowerCase() : "";
    findings.push(finding("intent.result", !safe || !actualResult ? "indeterminate" : actualResult === opts.resultId ? "pass" : "fail",
      !safe || !actualResult ? "RESULT_EVIDENCE_UNAVAILABLE" : actualResult === opts.resultId ? null : "RESULT_SCOPE_MISMATCH", safe ? [sourceId] : []));
  }
  if (opts.expectedProgram) {
    const program = typeof execution?.program === "string" ? execution.program.trim().toLowerCase() : "";
    findings.push(finding("intent.program", !safe || !program ? "indeterminate" : program === opts.expectedProgram ? "pass" : "fail",
      !safe || !program ? "EXECUTION_PROGRAM_UNAVAILABLE" : program === opts.expectedProgram ? null : "PROGRAM_MISMATCH", safe ? [sourceId] : []));
  }
  return Object.freeze({
    intent: Object.freeze({ subject, expected: Object.freeze([]) }),
    verification_scope: Object.freeze({
      profile: opts.profile,
      expected_program: opts.expectedProgram || null,
      requested_result_id: opts.resultId || null,
    }),
    observations: Object.freeze(observations), findings: Object.freeze(findings),
  });
}
