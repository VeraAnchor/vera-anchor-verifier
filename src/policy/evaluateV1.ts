import { createPortableVerificationReportV1, type PortableVerificationReportV1 } from "../reports/portableV1.js";
import { verifyDatasetV1WithIntent, verifyIngestV1WithIntent,
  type DatasetV1IntentInput, type IngestV1IntentInput } from "../verification/sourceIntentV1.js";
import { verifyExecutionV1WithIntent, type ExecutionV1Input } from "../profiles/execution/verificationV1.js";
import { verifyExecutionWithIndependentStandardsV1 } from "../profiles/execution/independentStandardsV1.js";
import { validatePortableVerificationReportV1 } from "../reports/validationV1.js";
import { triangulateDatasetV1, triangulateIngestV1,
  type PublicTriangulationV1Config, type PublicIngestTriangulationV1Input } from "../triangulation/publicV1.js";
import { triangulatePublicExecutionV1,
  type PublicExecutionTriangulationV1Config } from "../triangulation/executionPublicV1.js";
import { triangulateAuthorizedDatasetV1,
  type AuthorizedDatasetTriangulationV1Config, type AuthorizedDatasetTriangulationV1Input }
  from "../triangulation/authorizedDatasetV1.js";
import { triangulateAuthorizedIngestV1,
  type AuthorizedIngestTriangulationV1Config, type AuthorizedIngestTriangulationV1Input }
  from "../triangulation/authorizedIngestV1.js";
import { VERIFICATION_POLICY_SCHEMA_VERSION, type VerificationPolicyAssuranceV1,
  type VerificationPolicyDecisionV1, type VerificationPolicyRequirementV1, type VerificationPolicyWorkflowV1,
  type VerificationPolicyV1 } from "./contractV1.js";

const CHECK_ID = /^[a-z][a-z0-9._:-]{0,159}$/;
const ASSURANCE: readonly VerificationPolicyAssuranceV1[] = ["mirror_corroboration"];
const KINDS = ["verification", "execution", "independent_standards", "public_triangulation", "authorized_dataset_triangulation", "authorized_ingest_triangulation", "execution_triangulation"];

type Row = Record<string, unknown>;
type Requirement = VerificationPolicyRequirementV1;

function object(value: unknown, name: string): Row {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError(`Invalid ${name}`);
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) throw new TypeError(`Invalid ${name}`);
  if (Reflect.ownKeys(value).some((key) => typeof key !== "string")) throw new TypeError(`Invalid ${name}`);
  for (const key of Object.keys(value)) {
    const field = Object.getOwnPropertyDescriptor(value, key);
    if (!field || !("value" in field) || field.value === undefined) throw new TypeError(`Invalid ${name} field`);
  }
  return value as Row;
}
function exact(row: Row, allowed: readonly string[], name: string): void {
  if (Object.keys(row).some((key) => !allowed.includes(key))) throw new TypeError(`Unknown ${name} field`);
}
function identifier(value: unknown, name: string, max = 160): string {
  if (typeof value !== "string" || !value || value.length > max || value.trim() !== value) {
    throw new TypeError(`Invalid ${name}`);
  }
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new TypeError(`Invalid ${name}`);
    } else if (unit >= 0xdc00 && unit <= 0xdfff) throw new TypeError(`Invalid ${name}`);
  }
  return value;
}
function boundedList<T extends string>(value: unknown, name: string, max: number,
  parse: (value: unknown) => T): readonly T[] {
  if (!Array.isArray(value) || value.length > max || value.length === 0) throw new TypeError(`Invalid ${name}`);
  const result: T[] = [];
  for (let i = 0; i < value.length; i++) {
    if (!Object.hasOwn(value, i)) throw new TypeError(`Sparse ${name}`);
    result.push(parse(value[i]));
  }
  result.sort();
  if (result.some((item, index) => index > 0 && item === result[index - 1])) throw new TypeError(`Duplicate ${name}`);
  return Object.freeze(result);
}
function checkedPolicy(value: VerificationPolicyV1): VerificationPolicyV1 {
  const p = object(value, "verification policy");
  exact(p, ["schema_version", "subject", "report_kind", "required_checks", "required_assurance",
    "execution_scope", "on_unresolved"], "policy");
  if (p.schema_version !== VERIFICATION_POLICY_SCHEMA_VERSION || !KINDS.includes(p.report_kind as string)) {
    throw new TypeError("Unsupported verification policy contract");
  }
  const subject = object(p.subject, "policy subject");
  exact(subject, ["kind", "id", "hedera_network"], "policy subject");
  if (!["artifact", "dataset", "ingest", "evidence_package", "merkle_anchor", "merkle_root", "merkle_leaf", "execution", "result"].includes(subject.kind as string)) {
    throw new TypeError("Invalid policy subject kind");
  }
  const id = identifier(subject.id, "policy subject ID", 256);
  const network = subject.hedera_network;
  if (network !== undefined && network !== "testnet" && network !== "mainnet") throw new TypeError("Invalid policy network");
  if (["execution", "independent_standards", "public_triangulation", "authorized_dataset_triangulation", "authorized_ingest_triangulation", "execution_triangulation"].includes(p.report_kind as string) && !network) {
    throw new TypeError("Network-scoped policy requires explicit Hedera network");
  }
  const required_checks = boundedList(p.required_checks, "required checks", 64, (x) => {
    const key = identifier(x, "required check");
    if (!CHECK_ID.test(key)) throw new TypeError("Invalid required check");
    return key;
  });
  const required_assurance = p.required_assurance === undefined ||
    (Array.isArray(p.required_assurance) && p.required_assurance.length === 0) ?
    Object.freeze([] as VerificationPolicyAssuranceV1[]) :
    boundedList(p.required_assurance, "required assurance", 1, (x) => {
      if (!ASSURANCE.includes(x as VerificationPolicyAssuranceV1)) throw new TypeError("Unsupported assurance dimension");
      return x as VerificationPolicyAssuranceV1;
    });
  if (p.on_unresolved !== undefined && p.on_unresolved !== "review" && p.on_unresolved !== "deny") {
    throw new TypeError("Invalid unresolved policy behavior");
  }
  const executionKind = ["execution", "independent_standards", "execution_triangulation"].includes(p.report_kind as string);
  if (executionKind !== (p.execution_scope !== undefined)) {
    throw new TypeError("Execution policy requires exact execution scope; non-execution policy must omit it");
  }
  let execution_scope: VerificationPolicyV1["execution_scope"];
  if (executionKind) {
    const scope = object(p.execution_scope, "policy execution scope");
    exact(scope, ["profile", "expected_program", "requested_result_id"], "execution scope");
    if (scope.profile !== "execution-v1" && scope.profile !== "sage-standards-v1") throw new TypeError("Invalid policy execution profile");
    if (scope.expected_program !== null) identifier(scope.expected_program, "expected program", 128);
    if (scope.profile === "execution-v1" && scope.expected_program === null) throw new TypeError("Generic execution requires expected program");
    if (scope.requested_result_id !== null &&
      (typeof scope.requested_result_id !== "string" || !/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(scope.requested_result_id))) {
      throw new TypeError("Invalid expected result UUID");
    }
    execution_scope = Object.freeze({ profile: scope.profile, expected_program: scope.expected_program as string | null,
      requested_result_id: scope.requested_result_id as string | null });
  }
  return Object.freeze({ schema_version: VERIFICATION_POLICY_SCHEMA_VERSION,
    subject: Object.freeze({ kind: subject.kind as VerificationPolicyV1["subject"]["kind"], id,
      ...(network === undefined ? {} : { hedera_network: network as "mainnet" | "testnet" }) }),
    report_kind: p.report_kind as VerificationPolicyV1["report_kind"], required_checks, required_assurance,
    ...(execution_scope ? { execution_scope } : {}), on_unresolved: p.on_unresolved === "deny" ? "deny" : "review" });
}
function outcome(key: string, state: Requirement["outcome"], reason_code: string | null): Requirement {
  return Object.freeze({ key, outcome: state, reason_code });
}
function equalScope(a: unknown, b: unknown): boolean {
  const actual = object(a, "report execution scope");
  const expected = object(b, "policy execution scope");
  return actual.profile === expected.profile && actual.expected_program === expected.expected_program &&
    actual.requested_result_id === expected.requested_result_id;
}
function assurance(report: PortableVerificationReportV1, requirement: VerificationPolicyAssuranceV1): Requirement {
  const ctx = report.context as Row;
  let established = false;
  if (requirement === "mirror_corroboration") {
    if (report.kind === "independent_standards") {
      const standards = ctx.independent_standards as Row | undefined;
      established = standards?.status === "verified" && standards.assurance === "mirror_corroborated";
    } else if (report.kind === "public_triangulation") {
      const resolution = ctx.resolution as Row | undefined;
      const rels = ctx.relationships as { id: string; status: string }[] | undefined;
      established = resolution?.hedera_mirror === "resolved" && rels?.some((r) => r.id === "public_record_hedera" && r.status === "consistent") === true;
    } else if (report.kind === "authorized_dataset_triangulation" ||
        report.kind === "authorized_ingest_triangulation") {
      const resolution = ctx.resolution as Row | undefined;
      const rels = ctx.relationships as { id: string; status: string }[] | undefined;
      established = resolution?.hedera_mirror === "resolved" && rels?.some((r) =>
        r.id === "authorized_hedera" && r.status === "consistent") === true;
    } else if (report.kind === "execution_triangulation") {
      const pub = ctx.public_execution as Row | undefined;
      const tri = ctx.triangulation as Row | undefined;
      const rels = tri?.relationships as { id: string; status: string }[] | undefined;
      established = pub?.mirror_status === "resolved" && rels?.some((r) =>
        (r.id === "provided_hedera" || r.id === "public_record_hedera") && r.status === "consistent") === true;
    }
  }
  // Mirror corroboration is the only policy assurance established by v1.
  return outcome(`assurance.${requirement}`, established ? "pass" : "unresolved",
    established ? null : "POLICY_ASSURANCE_NOT_ESTABLISHED");
}

/** Public-source acquisition is an additional requirement of a public workflow.
 * Offline recomputation alone cannot complete the requested triangulation. */
function publicEvidence(report: PortableVerificationReportV1): Requirement | null {
  if (report.kind === "public_triangulation") {
    const ctx = report.context as Row;
    const resolution = ctx.resolution as Row;
    const rels = ctx.relationships as { id: string; status: string }[];
    const statuses = [resolution.public_record, resolution.publication_disclosure, resolution.hedera_mirror];
    const conflicting = ctx.consistency === "conflict" || statuses.some((status) => status === "conflict" || status === "invalid");
    const complete = ctx.consistency === "consistent" && statuses.every((status) => status === "resolved") &&
      ["provided_public_record", "public_record_hedera"].every((id) =>
        rels.some((rel) => rel.id === id && rel.status === "consistent"));
    return outcome("verification.public_evidence", conflicting ? "fail" : complete ? "pass" : "unresolved",
      conflicting ? "POLICY_PUBLIC_EVIDENCE_CONFLICT" : complete ? null : "POLICY_PUBLIC_EVIDENCE_INCOMPLETE");
  }
  if (report.kind === "execution_triangulation") {
    const ctx = report.context as Row;
    const acquisition = ctx.public_execution as Row;
    const tri = ctx.triangulation as Row | undefined;
    const rels = tri?.relationships as { id: string; status: string }[] | undefined;
    const conflicting = acquisition.status === "conflict" || acquisition.status === "invalid" ||
      tri?.consistency === "conflict";
    const complete = acquisition.status === "resolved" && acquisition.public_record_acquisition === "resolved" &&
      acquisition.mirror_status === "resolved" && tri?.consistency === "consistent" &&
      rels?.some((rel) => (rel.id === "provided_hedera" || rel.id === "public_record_hedera") &&
        rel.status === "consistent") === true;
    return outcome("verification.public_evidence", conflicting ? "fail" : complete ? "pass" : "unresolved",
      conflicting ? "POLICY_PUBLIC_EVIDENCE_CONFLICT" : complete ? null : "POLICY_PUBLIC_EVIDENCE_INCOMPLETE");
  }
  return null;
}

/** Authorized acquisition must complete private profile binding and independent HCS corroboration. */
function authorizedEvidence(report: PortableVerificationReportV1): Requirement | null {
  if (report.kind !== "authorized_dataset_triangulation" &&
      report.kind !== "authorized_ingest_triangulation") return null;
  const ctx = report.context as Row;
  const resolution = ctx.resolution as Row;
  const rels = ctx.relationships as { id: string; status: string }[];
  const profileStatus = report.kind === "authorized_dataset_triangulation"
    ? resolution.dataset_registry_event
    : resolution.ingest_receipt;
  const conflicting = ctx.consistency === "conflict" ||
    resolution.authorized_core === "invalid" ||
    resolution.hedera_mirror === "invalid" || resolution.hedera_mirror === "conflict" ||
    profileStatus === "invalid" || profileStatus === "conflict";
  const complete = ctx.consistency === "consistent" &&
    resolution.authorized_core === "resolved" && resolution.hedera_mirror === "resolved" &&
    profileStatus === "resolved" &&
    ["provided_authorized", "authorized_hedera"].every((id) =>
      rels.some((rel) => rel.id === id && rel.status === "consistent"));
  return outcome("verification.authorized_evidence", conflicting ? "fail" : complete ? "pass" : "unresolved",
    conflicting ? "POLICY_AUTHORIZED_EVIDENCE_CONFLICT" : complete ? null : "POLICY_AUTHORIZED_EVIDENCE_INCOMPLETE");
}

function decide(reportValue: unknown, value: VerificationPolicyV1,
  authority: VerificationPolicyDecisionV1["authority"]): VerificationPolicyDecisionV1 {
  const policy = checkedPolicy(value);
  const validity = validatePortableVerificationReportV1(reportValue);
  if (validity.status !== "valid") {
    return Object.freeze({ decision: "deny", report_sha3_512: null, authority,
      requirements: Object.freeze([outcome("report.integrity", "fail", validity.reason_code)]),
      reason_codes: Object.freeze(["POLICY_REPORT_INVALID"]) });
  }
  const report = reportValue as PortableVerificationReportV1;
  const req: Requirement[] = [];
  const subject = report.core.intent.subject;
  const expected = policy.subject;
  const sameSubject = subject.kind === expected.kind && subject.id === expected.id &&
    subject.hedera_network === expected.hedera_network;
  req.push(outcome("intent.subject", sameSubject ? "pass" : "fail", sameSubject ? null : "POLICY_SUBJECT_MISMATCH"));
  req.push(outcome("report.kind", report.kind === policy.report_kind ? "pass" : "fail",
    report.kind === policy.report_kind ? null : "POLICY_PROFILE_MISMATCH"));
  if (policy.execution_scope) {
    const scoped = (report.context as Row).verification_scope;
    const matched = scoped !== undefined && report.kind === policy.report_kind && equalScope(scoped, policy.execution_scope);
    req.push(outcome("execution.scope", matched ? "pass" : "fail", matched ? null : "POLICY_EXECUTION_SCOPE_MISMATCH"));
  }
  const intentFinding = report.core.findings.find((f) => f.check_id === "intent.subject");
  req.push(outcome("verification.intent.subject", intentFinding?.outcome === "pass" ? "pass" :
    intentFinding?.outcome === "fail" ? "fail" : "unresolved",
    intentFinding?.outcome === "pass" ? null : intentFinding?.outcome === "fail" ? "POLICY_INTENT_FAILED" : "POLICY_INTENT_UNRESOLVED"));
  for (const check of policy.required_checks) {
    const f = report.core.findings.find((item) => item.check_id === check);
    req.push(outcome(`check.${check}`, f?.outcome === "pass" ? "pass" : f?.outcome === "fail" ? "fail" : "unresolved",
      f?.outcome === "pass" ? null : f?.outcome === "fail" ? "POLICY_REQUIRED_CHECK_FAILED" : "POLICY_REQUIRED_CHECK_UNRESOLVED"));
  }
  for (const check of policy.required_assurance ?? []) req.push(assurance(report, check));
  const publicRequirement = publicEvidence(report);
  if (publicRequirement) req.push(publicRequirement);
  const authorizedRequirement = authorizedEvidence(report);
  if (authorizedRequirement) req.push(authorizedRequirement);
  // An SDK invocation alone is not substantive proof. At least one *required*
  // successful check must cite material recomputed by the verifier itself.
  // A scope match or a producer-supplied claim is not enough to authorize.
  if (authority === "sdk_verification") {
    const locallySupported = policy.required_checks.some((key) => {
      const check = report.core.findings.find((f) => f.check_id === key);
      return check?.outcome === "pass" && check.observation_ids.some((id) =>
        report.core.observations.some((obs) => obs.id === id && obs.source === "local_computation"));
    });
    if (!locallySupported) req.push(outcome("verification.local_support", "unresolved", "POLICY_LOCAL_VERIFICATION_NOT_ESTABLISHED"));
  }
  // A conflicting finding is never ignored merely because it wasn't named in policy.
  if (report.core.findings.some((f) => f.outcome === "fail")) {
    req.push(outcome("verification.conflict", "fail", "POLICY_VERIFICATION_CONFLICT"));
  }
  const failed = req.some((entry) => entry.outcome === "fail");
  const unresolved = req.some((entry) => entry.outcome === "unresolved");
  const canAllow = authority === "sdk_verification";
  const decision = failed || (unresolved && policy.on_unresolved === "deny") ? "deny" :
    unresolved || !canAllow ? "review" : "allow";
  const reason_codes = Array.from(new Set([
    ...req.filter((r) => r.reason_code !== null).map((r) => r.reason_code!),
    ...(!failed && !unresolved && !canAllow ? ["POLICY_REPORT_NOT_AUTHENTICATED"] : []),
  ])).sort();
  return Object.freeze({ decision, report_sha3_512: report.report_sha3_512, authority,
    requirements: Object.freeze(req), reason_codes: Object.freeze(reason_codes) });
}

/** Assess a saved report's *claims*. This cannot approve evidence: anyone can forge an unsigned report. */
export function assessPortableVerificationPolicyV1(report: unknown, policy: VerificationPolicyV1): VerificationPolicyDecisionV1 {
  return decide(report, policy, "unauthenticated_report");
}

/** These entry points actually invoke the SDK verifier. There is no public
 * function that can mark an arbitrary caller-owned report as SDK-verified. */
export async function verifyDatasetWithPolicyV1(input: DatasetV1IntentInput,
  policy: VerificationPolicyV1): Promise<VerificationPolicyWorkflowV1> {
  checkedPolicy(policy);
  const result = await verifyDatasetV1WithIntent(input);
  const report = createPortableVerificationReportV1({ kind: "verification", result });
  return Object.freeze({ report, policy: decide(report, policy, "sdk_verification") });
}

export async function verifyIngestWithPolicyV1(input: IngestV1IntentInput,
  policy: VerificationPolicyV1): Promise<VerificationPolicyWorkflowV1> {
  checkedPolicy(policy);
  const result = await verifyIngestV1WithIntent(input);
  const report = createPortableVerificationReportV1({ kind: "verification", result });
  return Object.freeze({ report, policy: decide(report, policy, "sdk_verification") });
}

export function verifyExecutionWithPolicyV1(input: ExecutionV1Input,
  policy: VerificationPolicyV1): VerificationPolicyWorkflowV1 {
  checkedPolicy(policy);
  const result = verifyExecutionV1WithIntent(input);
  const report = createPortableVerificationReportV1({ kind: "execution", result });
  return Object.freeze({ report, policy: decide(report, policy, "sdk_verification") });
}


/** Reject incompatible caller expectations before any public resolver is invoked. */
function checkedPublicPolicy(input: { readonly intent: { readonly subject: VerificationPolicyV1["subject"] } },
  policy: VerificationPolicyV1, kind: "public_triangulation" | "execution_triangulation",
  subjectKind: "dataset" | "ingest" | "execution"): VerificationPolicyV1 {
  const checked = checkedPolicy(policy);
  const actual = input.intent?.subject;
  const expected = checked.subject;
  if (checked.report_kind !== kind || !actual || actual.kind !== subjectKind ||
      expected.kind !== subjectKind || actual.id !== expected.id ||
      !actual.hedera_network || actual.hedera_network !== expected.hedera_network) {
    throw new TypeError("Public verification request does not match relying-party policy intent");
  }
  return checked;
}

/** SDK-owned source recomputation, Explorer publication resolution and Hedera corroboration. */
export async function triangulateDatasetWithPolicyV1(config: PublicTriangulationV1Config,
  input: DatasetV1IntentInput, policy: VerificationPolicyV1): Promise<VerificationPolicyWorkflowV1> {
  const checked = checkedPublicPolicy(input, policy, "public_triangulation", "dataset");
  const result = await triangulateDatasetV1(config, input);
  const report = createPortableVerificationReportV1({ kind: "public_triangulation", result });
  return Object.freeze({ report, policy: decide(report, checked, "sdk_verification") });
}

/** Authenticated Dataset verification is network-scoped and must match the relying-party subject exactly. */
function checkedAuthorizedDatasetPolicy(
  input: AuthorizedDatasetTriangulationV1Input,
  policy: VerificationPolicyV1,
): VerificationPolicyV1 {
  const checked = checkedPolicy(policy);
  const actual = input.intent?.subject;
  const expected = checked.subject;
  if (checked.report_kind !== "authorized_dataset_triangulation" || !actual || actual.kind !== "dataset" ||
      expected.kind !== "dataset" || actual.id !== expected.id ||
      !actual.hedera_network || actual.hedera_network !== expected.hedera_network) {
    throw new TypeError("Authorized Dataset verification request does not match relying-party policy intent");
  }
  return checked;
}

/** SDK-owned Dataset recomputation, caller-authorized Core decryption, and independent Hedera corroboration. */
export async function triangulateAuthorizedDatasetWithPolicyV1(
  config: AuthorizedDatasetTriangulationV1Config,
  input: AuthorizedDatasetTriangulationV1Input,
  policy: VerificationPolicyV1,
): Promise<VerificationPolicyWorkflowV1> {
  const checked = checkedAuthorizedDatasetPolicy(input, policy);
  const result = await triangulateAuthorizedDatasetV1(config, input);
  const report = createPortableVerificationReportV1({ kind: "authorized_dataset_triangulation", result });
  return Object.freeze({ report, policy: decide(report, checked, "sdk_verification") });
}

function checkedAuthorizedIngestPolicy(
  input: AuthorizedIngestTriangulationV1Input,
  policy: VerificationPolicyV1,
): VerificationPolicyV1 {
  const checked = checkedPolicy(policy);
  const actual = input.intent?.subject;
  const expected = checked.subject;
  if (checked.report_kind !== "authorized_ingest_triangulation" || !actual || actual.kind !== "ingest" ||
      expected.kind !== "ingest" || actual.id !== expected.id ||
      !actual.hedera_network || actual.hedera_network !== expected.hedera_network) {
    throw new TypeError("Authorized Ingest verification request does not match relying-party policy intent");
  }
  return checked;
}

/** SDK-owned Ingest recomputation, caller-authorized Core decryption, and independent Hedera corroboration. */
export async function triangulateAuthorizedIngestWithPolicyV1(
  config: AuthorizedIngestTriangulationV1Config,
  input: AuthorizedIngestTriangulationV1Input,
  policy: VerificationPolicyV1,
): Promise<VerificationPolicyWorkflowV1> {
  const checked = checkedAuthorizedIngestPolicy(input, policy);
  const result = await triangulateAuthorizedIngestV1(config, input);
  const report = createPortableVerificationReportV1({ kind: "authorized_ingest_triangulation", result });
  return Object.freeze({ report, policy: decide(report, checked, "sdk_verification") });
}

/** Ingest source identity is independent of the Core Merkle anchor request ID. */
export async function triangulateIngestWithPolicyV1(config: PublicTriangulationV1Config,
  input: PublicIngestTriangulationV1Input, policy: VerificationPolicyV1): Promise<VerificationPolicyWorkflowV1> {
  const checked = checkedPublicPolicy(input, policy, "public_triangulation", "ingest");
  const result = await triangulateIngestV1(config, input);
  const report = createPortableVerificationReportV1({ kind: "public_triangulation", result });
  return Object.freeze({ report, policy: decide(report, checked, "sdk_verification") });
}

/** Original HCS anchors remain provenance only, not public plaintext authority.
 * Recompute offline verification on unresolved acquisition to preserve its scope. */
export async function triangulateExecutionWithPolicyV1(config: PublicExecutionTriangulationV1Config,
  input: ExecutionV1Input, policy: VerificationPolicyV1): Promise<VerificationPolicyWorkflowV1> {
  const checked = checkedPublicPolicy(input, policy, "execution_triangulation", "execution");
  const result = await triangulatePublicExecutionV1(config, input);
  const report = createPortableVerificationReportV1({ kind: "execution_triangulation", result,
    ...(result.plan === null ? { source_report: verifyExecutionV1WithIntent(input) } : {}) });
  return Object.freeze({ report, policy: decide(report, checked, "sdk_verification") });
}


/** Resolve pinned independent HCS standards before applying relying-party policy.
 * A Mirror-corroborated standards result does not authenticate consensus or DID control. */
export async function verifyExecutionStandardsWithPolicyV1(
  config: Parameters<typeof verifyExecutionWithIndependentStandardsV1>[0],
  input: Parameters<typeof verifyExecutionWithIndependentStandardsV1>[1],
  options: Parameters<typeof verifyExecutionWithIndependentStandardsV1>[2],
  policy: VerificationPolicyV1,
): Promise<VerificationPolicyWorkflowV1> {
  const checked = checkedPolicy(policy);
  const subject = input.intent?.subject;
  if (checked.report_kind !== "independent_standards" ||
      checked.subject.kind !== "execution" || subject?.kind !== "execution" ||
      subject.id !== checked.subject.id ||
      !subject.hedera_network || subject.hedera_network !== checked.subject.hedera_network ||
      checked.execution_scope?.profile !== "sage-standards-v1" ||
      input.profile !== "sage-standards-v1") {
    throw new TypeError("Independent standards request does not match relying-party policy intent");
  }
  const result = await verifyExecutionWithIndependentStandardsV1(config, input, options);
  const report = createPortableVerificationReportV1({ kind: "independent_standards", result });
  return Object.freeze({ report, policy: decide(report, checked, "sdk_verification") });
}
