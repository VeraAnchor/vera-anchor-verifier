// SDK-local pure port of Explorer executionVerificationRules.ts (Oct 7 baseline).
// ============================================================================
// File: src/verifier/execution/executionVerificationRules.ts
// Version: 1.4.0-exact-temporal-ordering | 2026-10-07
// Purpose:
//   Ordered, deterministic rule registry for public standards-backed execution
//   evidence. Rules verify explicit public facts only; no external resolution or
//   cryptographic recomputation is implied where canonical payloads are absent.
// ============================================================================

import {
  cleanString,
  fail,
  hasTimestamp,
  isGitCommit,
  isHcs1Ref,
  isHcs13Ref,
  isHcsTransactionId,
  isHederaId,
  isPlainObject,
  isPositiveSafeInteger,
  isSha256,
  isSha3_512,
  isSupportedHederaNetwork,
  isUuid,
  isValidDate,
  normalizeIdentifier,
  notApplicable,
  pass,
  sameIdentifier,
  unavailable,
  type ExecutionVerificationContext,
  type ExecutionVerificationRule,
  type ExecutionVerificationRuleResult,
  type PublicAgentEvidence,
  type PublicCapabilityEvidence,
  type PublicContractMetadataRecord,
  type PublicExecutionStandardsEvidence,
  type PublicSchemaEvidence,
  type PublicStandardsSourceDocument,
} from "./contractV1.js";
import {
  EXECUTION_VERIFICATION_REASON_CODES as REASONS,
  type ExecutionVerificationReasonCode,
} from "./reasonCodesV1.js";
import {
  computeExecutionDomainSeparatedSha3_512,
  hederaConsensusTimestampNanos,
  executionTimestampIso,
  executionTimestampNanos,
} from "./recomputationV1.js";
import { buildStandardsResolutionPlan } from "./standardsPlanV1.js";

function present(value: unknown): boolean {
  return Boolean(cleanString(value));
}

function validSourceDocument(
  document: PublicStandardsSourceDocument | null | undefined
): boolean {
  return Boolean(
    document &&
      present(document.standard) &&
      present(document.path) &&
      isSha256(document.sha256)
  );
}

function validAgentReference(
  agent: PublicAgentEvidence | null | undefined
): boolean {
  return Boolean(
    agent &&
      present(agent.logical_id) &&
      cleanString(agent.hcs14_uaid).startsWith("uaid:") &&
      isHederaId(agent.hcs11?.account_id) &&
      isHederaId(agent.hcs11?.profile_registry_topic_id) &&
      isPositiveSafeInteger(agent.hcs11?.profile_registry_sequence) &&
      isHcs1Ref(agent.hcs11?.profile_hcs1_ref) &&
      isSha256(agent.hcs11?.profile_checksum_sha256)
  );
}

function validCapabilityReference(
  capability: PublicCapabilityEvidence | null | undefined
): boolean {
  return Boolean(
    capability &&
      cleanString(capability.standard) === "HCS-26" &&
      isHederaId(capability.discovery_registry_topic_id) &&
      present(capability.skill_uid) &&
      present(capability.skill_version) &&
      isHederaId(capability.version_registry_topic_id) &&
      isPositiveSafeInteger(capability.version_sequence_number) &&
      isHcs1Ref(capability.manifest_hcs1_ref) &&
      isSha256(capability.manifest_checksum_sha256) &&
      present(capability.repository_uri) &&
      isGitCommit(capability.repository_commit)
  );
}

function validSchemaReference(
  schema: PublicSchemaEvidence | null | undefined
): boolean {
  return Boolean(
    schema &&
      present(schema.role) &&
      isHederaId(schema.registry_topic_id) &&
      isPositiveSafeInteger(Number(schema.registry_sequence_number)) &&
      isHcs13Ref(schema.hcs13_ref) &&
      isSha256(schema.schema_checksum_sha256) &&
      (
        !present(schema.instance_digest_sha3_512) ||
        isSha3_512(schema.instance_digest_sha3_512)
      )
  );
}

function recomputeReferenceComplete(
  evidence: PublicExecutionStandardsEvidence
): boolean {
  const baseline = evidence?.standards?.baseline;
  const documents = Array.isArray(baseline?.source_documents)
    ? baseline.source_documents
    : [];
  const schemas = Array.isArray(evidence?.standards?.schemas)
    ? evidence.standards.schemas
    : [];

  return Boolean(
    baseline &&
      present(baseline.baseline_id) &&
      isGitCommit(baseline.source_commit) &&
      documents.length > 0 &&
      documents.every(validSourceDocument) &&
      validAgentReference(evidence?.agents?.requester) &&
      validAgentReference(evidence?.agents?.executor) &&
      validCapabilityReference(evidence?.capability) &&
      schemas.length > 0 &&
      schemas.every(validSchemaReference)
  );
}

function expectedStandardsResolutionItems(
  evidence: PublicExecutionStandardsEvidence
): Map<string, { standard: string; reference: string }> | null {
  const expected = new Map<string, { standard: string; reference: string }>();
  for (const item of buildStandardsResolutionPlan(evidence)) {
    if (!item.key || expected.has(item.key)) return null;
    expected.set(item.key, {
      standard: item.standard,
      reference: item.reference,
    });
  }
  return expected;
}

function evaluateStandardsResolution(
  context: ExecutionVerificationContext
): ExecutionVerificationRuleResult {
  const material = context.verificationMaterial?.standards_resolution;
  if (!material) return unavailable(REASONS.STANDARDS_RESOLUTION_UNAVAILABLE);

  if (
    cleanString(material.schema_version) !== "vera.standards-resolution.v1" ||
    !isSupportedHederaNetwork(material.hedera_network) ||
    !Array.isArray(material.items)
  ) {
    return fail(REASONS.MALFORMED_EVIDENCE);
  }

  if (
    context.expectedNetwork &&
    normalizeIdentifier(material.hedera_network) !== context.expectedNetwork
  ) {
    return fail(REASONS.NETWORK_SCOPE_MISMATCH);
  }

  const expected = expectedStandardsResolutionItems(context.evidence);
  if (!expected) return fail(REASONS.MALFORMED_EVIDENCE);

  // Legacy/foreign resolvers may still surface resolver-wide unavailability
  // without materializing the expected item plan. Do not misclassify that as a
  // reference-set integrity failure. Vera Anchor's resolver always preserves
  // the full plan, including on failed/unavailable preflight paths.
  if (material.items.length === 0) {
    return material.state === "unavailable"
      ? unavailable(REASONS.STANDARDS_RESOLUTION_UNAVAILABLE)
      : fail(REASONS.MALFORMED_EVIDENCE);
  }

  const observed = new Map<string, (typeof material.items)[number]>();
  for (const item of material.items) {
    const key = cleanString(item?.key);
    if (!key || observed.has(key)) return fail(REASONS.MALFORMED_EVIDENCE);
    observed.set(key, item);
  }

  if (observed.size !== expected.size) return fail(REASONS.REFERENCE_SET_INCOMPLETE);

  let hasUnavailable = false;
  let hasFailed = false;
  for (const [key, expectedItem] of expected.entries()) {
    const item = observed.get(key);
    if (!item) return fail(REASONS.REFERENCE_SET_INCOMPLETE);
    if (
      cleanString(item.standard) !== expectedItem.standard ||
      cleanString(item.reference) !== expectedItem.reference
    ) {
      return fail(REASONS.MALFORMED_EVIDENCE);
    }
    if (item.state === "failed") hasFailed = true;
    else if (item.state === "unavailable") hasUnavailable = true;
    else if (item.state !== "verified") return fail(REASONS.MALFORMED_EVIDENCE);
  }

  const derivedState = hasFailed
    ? "failed"
    : hasUnavailable
      ? "unavailable"
      : "verified";
  if (material.state !== derivedState) return fail(REASONS.MALFORMED_EVIDENCE);
  if (derivedState === "failed") return fail(REASONS.MALFORMED_EVIDENCE);
  if (derivedState === "unavailable") {
    return unavailable(REASONS.STANDARDS_RESOLUTION_UNAVAILABLE);
  }
  return pass();
}

function resultApplies(context: ExecutionVerificationContext): boolean {
  // Result-scoped checks are enabled only by an explicit verifier request.
  // Public job-level standards evidence may legitimately include a latest
  // ResultEvidence row for display/provenance purposes; that must not silently
  // turn a job verification into verification of a particular result.
  return Boolean(context.requestedResultId);
}

function missingOrMalformedDigest(
  value: unknown
): ExecutionVerificationRuleResult | null {
  return !present(value)
    ? unavailable()
    : !isSha3_512(value)
      ? fail(REASONS.MALFORMED_EVIDENCE)
      : null;
}

function exactMetadata(
  record: PublicContractMetadataRecord | null | undefined,
  expected: {
    schema: string;
    canonicalization: string;
    digestAlgorithm: string;
    domainSeparator: string;
  }
): ExecutionVerificationRuleResult {
  if (!record) return unavailable();

  const required: ReadonlyArray<[keyof PublicContractMetadataRecord, string]> = [
    ["schema", expected.schema],
    ["canonicalization", expected.canonicalization],
    ["digest_algorithm", expected.digestAlgorithm],
    ["domain_separator", expected.domainSeparator],
  ];

  for (const [field, expectedValue] of required) {
    if (!present(record[field])) return unavailable();
    if (record[field] !== expectedValue) {
      return fail(REASONS.MALFORMED_EVIDENCE);
    }
  }

  const digestState = missingOrMalformedDigest(record.digest);
  if (digestState) return digestState;

  return pass();
}

function recomputePublicContractDigest(
  context: ExecutionVerificationContext,
  record: PublicContractMetadataRecord | null | undefined,
  {
    domainSeparator,
    unavailableReason,
    mismatchReason,
  }: Readonly<{
    domainSeparator: string;
    unavailableReason: ExecutionVerificationReasonCode;
    mismatchReason: ExecutionVerificationReasonCode;
  }>
): ExecutionVerificationRuleResult {
  if (!record?.digest_payload) {
    return unavailable(unavailableReason);
  }

  if (!isPlainObject(record.digest_payload)) {
    return fail(REASONS.MALFORMED_EVIDENCE);
  }

  const digestState = missingOrMalformedDigest(record.digest);
  if (digestState) return digestState;

  try {
    const computedDigest = computeExecutionDomainSeparatedSha3_512(
      domainSeparator,
      record.digest_payload
    );
    return computedDigest === record.digest
      ? pass()
      : fail(mismatchReason);
  } catch {
    return fail(REASONS.MALFORMED_EVIDENCE);
  }
}

function datasetRule(
  context: ExecutionVerificationContext
): ExecutionVerificationRuleResult {
  const dataset = context.evidence?.execution?.dataset;
  if (!dataset) return notApplicable();

  const values = [
    dataset.dataset_key,
    dataset.dataset_version,
    dataset.dataset_fingerprint_sha3_512,
    dataset.dataset_manifest_sha3_512,
  ];

  if (values.every((value) => value == null || value === "")) {
    return notApplicable();
  }

  if (
    !present(dataset.dataset_key) ||
    !isPositiveSafeInteger(dataset.dataset_version) ||
    !isSha3_512(dataset.dataset_fingerprint_sha3_512) ||
    !isSha3_512(dataset.dataset_manifest_sha3_512)
  ) {
    return fail(REASONS.MALFORMED_EVIDENCE);
  }

  return pass();
}

export const EXECUTION_VERIFICATION_RULES: readonly ExecutionVerificationRule[] = Object.freeze([
  Object.freeze({
    id: "public_evidence.available",
    group: "contract",
    label: "Standards-backed evidence is available",
    requirement: "required",
    evidenceRefs: ["public_standards_evidence"],
    evaluate(context: ExecutionVerificationContext) {
      if (context.evidence?.available === true) return pass();
      return unavailable(REASONS.REQUIRED_EVIDENCE_MISSING);
    },
  }),
  Object.freeze({
    id: "public_evidence.contract_version",
    group: "contract",
    label: "Public evidence contract version is supported",
    requirement: "required",
    evidenceRefs: ["public_standards_evidence"],
    evaluate(context: ExecutionVerificationContext) {
      const version = cleanString(context.evidence?.contract_version);
      if (!version) return unavailable();
      return context.supportedContractVersions.includes(version)
        ? pass()
        : fail(REASONS.PUBLIC_CONTRACT_UNSUPPORTED);
    },
  }),
  Object.freeze({
    id: "execution.identity",
    group: "execution",
    label: "Execution identity is structurally valid",
    requirement: "required",
    evidenceRefs: ["execution"],
    evaluate(context: ExecutionVerificationContext) {
      const execution = context.evidence?.execution;
      if (!execution) return unavailable();

      if (
        !isUuid(execution.job_id) ||
        !present(execution.program) ||
        !isValidDate(execution.proof_date) ||
        !isSupportedHederaNetwork(execution.hedera_network)
      ) {
        return fail(REASONS.MALFORMED_EVIDENCE);
      }

      return pass();
    },
  }),
  Object.freeze({
    id: "execution.network_scope",
    group: "execution",
    label: "Execution network matches the requested verification scope",
    requirement: "required",
    evidenceRefs: ["execution"],
    evaluate(context: ExecutionVerificationContext) {
      const network = normalizeIdentifier(
        context.evidence?.execution?.hedera_network
      );
      if (!network) return unavailable();
      if (!isSupportedHederaNetwork(network)) {
        return fail(REASONS.MALFORMED_EVIDENCE);
      }

      if (
        context.expectedNetwork &&
        network !== context.expectedNetwork
      ) {
        return fail(REASONS.NETWORK_SCOPE_MISMATCH);
      }

      return pass();
    },
  }),
  Object.freeze({
    id: "execution.dataset_commitment",
    group: "execution",
    label: "Execution dataset commitment is structurally valid",
    requirement: "conditional",
    evidenceRefs: ["execution.dataset"],
    evaluate: datasetRule,
  }),
  Object.freeze({
    id: "standards.baseline_reference",
    group: "standards",
    label: "Frozen standards baseline is complete",
    requirement: "required",
    evidenceRefs: ["standards.baseline"],
    evaluate(context: ExecutionVerificationContext) {
      const baseline = context.evidence?.standards?.baseline;
      if (!baseline) return unavailable();

      const documents = Array.isArray(baseline.source_documents)
        ? baseline.source_documents
        : [];

      if (
        !present(baseline.baseline_id) ||
        !isGitCommit(baseline.source_commit) ||
        documents.length === 0 ||
        !documents.every(validSourceDocument)
      ) {
        return fail(REASONS.REFERENCE_SET_INCOMPLETE);
      }

      return pass();
    },
  }),
  Object.freeze({
    id: "standards.requester_reference",
    group: "standards",
    label: "Requester identity references are complete",
    requirement: "required",
    evidenceRefs: ["agents.requester"],
    evaluate(context: ExecutionVerificationContext) {
      const requester = context.evidence?.agents?.requester;
      if (!requester) return unavailable();
      return validAgentReference(requester)
        ? pass()
        : fail(REASONS.REFERENCE_SET_INCOMPLETE);
    },
  }),
  Object.freeze({
    id: "standards.executor_reference",
    group: "standards",
    label: "Executor identity references are complete",
    requirement: "required",
    evidenceRefs: ["agents.executor"],
    evaluate(context: ExecutionVerificationContext) {
      const executor = context.evidence?.agents?.executor;
      if (!executor) return unavailable();
      return validAgentReference(executor)
        ? pass()
        : fail(REASONS.REFERENCE_SET_INCOMPLETE);
    },
  }),
  Object.freeze({
    id: "standards.capability_reference",
    group: "standards",
    label: "HCS-26 capability reference is complete",
    requirement: "required",
    evidenceRefs: ["capability"],
    evaluate(context: ExecutionVerificationContext) {
      const capability = context.evidence?.capability;
      if (!capability) return unavailable();
      return validCapabilityReference(capability)
        ? pass()
        : fail(REASONS.REFERENCE_SET_INCOMPLETE);
    },
  }),
  Object.freeze({
    id: "standards.schema_references",
    group: "standards",
    label: "HCS-13 schema references are complete",
    requirement: "required",
    evidenceRefs: ["standards.schemas"],
    evaluate(context: ExecutionVerificationContext) {
      const schemas = context.evidence?.standards?.schemas;
      if (!Array.isArray(schemas) || schemas.length === 0) {
        return unavailable();
      }

      return schemas.every(validSchemaReference)
        ? pass()
        : fail(REASONS.REFERENCE_SET_INCOMPLETE);
    },
  }),
  Object.freeze({
    id: "standards.reference_summary",
    group: "standards",
    label: "Reference completeness summary matches public evidence",
    requirement: "required",
    evidenceRefs: ["standards"],
    evaluate(context: ExecutionVerificationContext) {
      const reported = context.evidence?.standards?.reference_complete;
      if (typeof reported !== "boolean") return unavailable();

      return reported === recomputeReferenceComplete(context.evidence)
        ? pass()
        : fail(REASONS.REFERENCE_SUMMARY_MISMATCH);
    },
  }),
  Object.freeze({
    id: "standards.references_resolved",
    group: "standards",
    label: "Standards references independently resolve",
    requirement: "optional",
    evidenceRefs: [
      "standards.baseline",
      "agents.requester",
      "agents.executor",
      "capability",
      "standards.schemas",
    ],
    evaluate(context: ExecutionVerificationContext) {
      return evaluateStandardsResolution(context);
    },
  }),
  Object.freeze({
    id: "binding.contract_metadata",
    group: "binding",
    label: "Execution binding contract metadata is valid",
    requirement: "required",
    evidenceRefs: ["binding"],
    evaluate(context: ExecutionVerificationContext) {
      const result = exactMetadata(context.evidence?.binding, {
        schema: "ExecutionBindingV1",
        canonicalization: "RFC8785-JCS",
        digestAlgorithm: "SHA3-512",
        domainSeparator: "vera-anchor:execution-binding:v1",
      });
      if (result.status !== "pass") return result;

      return hasTimestamp(context.evidence.binding?.finalized_at)
        ? pass()
        : unavailable();
    },
  }),
  Object.freeze({
    id: "binding.digest_recomputed",
    group: "binding",
    label: "Execution binding digest is recomputed from canonical content",
    requirement: "conditional",
    evidenceRefs: ["binding.digest_payload", "binding.digest"],
    evaluate(context: ExecutionVerificationContext) {
      return recomputePublicContractDigest(context, context.evidence?.binding, {
        domainSeparator: "vera-anchor:execution-binding:v1",
        unavailableReason: REASONS.BINDING_RECOMPUTATION_UNAVAILABLE,
        mismatchReason: REASONS.BINDING_DIGEST_MISMATCH,
      });
    },
  }),
  Object.freeze({
    id: "acceptance.contract_metadata",
    group: "acceptance",
    label: "Execution acceptance contract metadata is valid",
    requirement: "required",
    evidenceRefs: ["acceptance"],
    evaluate(context: ExecutionVerificationContext) {
      return exactMetadata(context.evidence?.acceptance, {
        schema: "ExecutionAcceptanceV1",
        canonicalization: "RFC8785-JCS",
        digestAlgorithm: "SHA3-512",
        domainSeparator: "vera-anchor:execution-acceptance:v1",
      });
    },
  }),
  Object.freeze({
    id: "acceptance.digest_recomputed",
    group: "acceptance",
    label: "Execution acceptance digest is recomputed from canonical content",
    requirement: "required",
    evidenceRefs: ["execution", "binding", "acceptance"],
    evaluate(context: ExecutionVerificationContext) {
      const execution = context.evidence?.execution;
      const binding = context.evidence?.binding;
      const acceptance = context.evidence?.acceptance;
      if (!execution || !binding || !acceptance) return unavailable();

      const acceptedAt = executionTimestampIso(acceptance.accepted_at);
      if (
        !isUuid(execution.job_id) ||
        !isValidDate(execution.proof_date) ||
        !isSupportedHederaNetwork(execution.hedera_network) ||
        !isSha3_512(binding.digest) ||
        !isSha3_512(acceptance.digest) ||
        !present(acceptance.admission_policy_id) ||
        typeof acceptance.requires_hcs_confirmation !== "boolean" ||
        !acceptedAt
      ) {
        return fail(REASONS.MALFORMED_EVIDENCE);
      }

      try {
        const computedDigest = computeExecutionDomainSeparatedSha3_512(
          "vera-anchor:execution-acceptance:v1",
          {
            record_type: "vera_anchor.execution_acceptance",
            acceptance_schema: "ExecutionAcceptanceV1",
            binding_digest_sha3_512: binding.digest,
            job_id: execution.job_id,
            proof_date: execution.proof_date,
            hedera_network: execution.hedera_network,
            admission_policy: {
              policy_id: acceptance.admission_policy_id,
              require_hcs_confirmation_before_execution:
                acceptance.requires_hcs_confirmation,
            },
            accepted_at: acceptedAt,
          }
        );
        return computedDigest === acceptance.digest
          ? pass()
          : fail(REASONS.ACCEPTANCE_RECOMPUTATION_MISMATCH);
      } catch {
        return fail(REASONS.MALFORMED_EVIDENCE);
      }
    },
  }),
  Object.freeze({
    id: "acceptance.binding_link",
    group: "acceptance",
    label: "Acceptance references the finalized execution binding",
    requirement: "required",
    evidenceRefs: ["binding", "acceptance"],
    evaluate(context: ExecutionVerificationContext) {
      const bindingDigest = context.evidence?.binding?.digest;
      const acceptanceDigest = context.evidence?.acceptance?.binding_digest;

      const bindingState = missingOrMalformedDigest(bindingDigest);
      if (bindingState) return bindingState;
      const acceptanceState = missingOrMalformedDigest(acceptanceDigest);
      if (acceptanceState) return acceptanceState;

      return bindingDigest === acceptanceDigest
        ? pass()
        : fail(REASONS.BINDING_DIGEST_MISMATCH);
    },
  }),
  Object.freeze({
    id: "acceptance.state_confirmed",
    group: "acceptance",
    label: "Pre-execution acceptance is confirmed",
    requirement: "required",
    evidenceRefs: ["acceptance"],
    evaluate(context: ExecutionVerificationContext) {
      const acceptance = context.evidence?.acceptance;
      if (!acceptance || !present(acceptance.state)) return unavailable();
      return acceptance.state === "confirmed"
        ? pass()
        : fail(REASONS.ACCEPTANCE_NOT_CONFIRMED);
    },
  }),
  Object.freeze({
    id: "acceptance.hcs_confirmation",
    group: "acceptance",
    label: "Required acceptance HCS confirmation is present",
    requirement: "conditional",
    evidenceRefs: ["acceptance.hcs"],
    evaluate(context: ExecutionVerificationContext) {
      const acceptance = context.evidence?.acceptance;
      if (!acceptance) return unavailable();

      if (acceptance.requires_hcs_confirmation !== true) {
        return notApplicable();
      }

      const hcs = acceptance.hcs;
      if (!hcs) return unavailable(REASONS.HCS_CONFIRMATION_REQUIRED);

      if (
        !isHederaId(hcs.topic_id) ||
        !isHcsTransactionId(hcs.transaction_id) ||
        !present(hcs.message_id) ||
        !isPositiveSafeInteger(hcs.sequence_number)
      ) {
        return fail(REASONS.HCS_CONFIRMATION_REQUIRED);
      }

      if (!present(hcs.consensus_timestamp_exact)) {
        return unavailable(REASONS.HCS_CONFIRMATION_REQUIRED);
      }

      return hederaConsensusTimestampNanos(hcs.consensus_timestamp_exact) != null
        ? pass()
        : fail(REASONS.MALFORMED_EVIDENCE);
    },
  }),
  Object.freeze({
    id: "acceptance.precedes_execution",
    group: "acceptance",
    label: "Acceptance precedes authoritative execution time",
    requirement: "optional",
    evidenceRefs: ["acceptance", "acceptance.hcs", "verification_material.execution_start"],
    evaluate(context: ExecutionVerificationContext) {
      const acceptance = context.evidence?.acceptance;
      const executionStart = context.verificationMaterial?.execution_start;

      if (!acceptance || !executionStart) {
        return unavailable(REASONS.AUTHORITATIVE_EXECUTION_TIME_UNAVAILABLE);
      }

      if (acceptance.requires_hcs_confirmation === true) {
        const acceptanceExact = acceptance.hcs?.consensus_timestamp_exact;
        const executionExact = executionStart.consensus_timestamp_exact;

        if (!present(acceptanceExact)) {
          return unavailable(REASONS.HCS_CONFIRMATION_REQUIRED);
        }
        if (
          !present(executionStart.hcs_transaction_id) ||
          !present(executionStart.hcs_topic_id) ||
          !present(executionExact)
        ) {
          return unavailable(REASONS.AUTHORITATIVE_EXECUTION_TIME_UNAVAILABLE);
        }
        if (
          !isHcsTransactionId(executionStart.hcs_transaction_id) ||
          !isHederaId(executionStart.hcs_topic_id)
        ) {
          return fail(REASONS.MALFORMED_EVIDENCE);
        }

        const acceptanceNanos = hederaConsensusTimestampNanos(acceptanceExact);
        const executionNanos = hederaConsensusTimestampNanos(executionExact);
        if (acceptanceNanos == null || executionNanos == null) {
          return fail(REASONS.MALFORMED_EVIDENCE);
        }

        return acceptanceNanos < executionNanos
          ? pass()
          : fail(REASONS.ACCEPTANCE_AFTER_EXECUTION_START);
      }

      const acceptedNanos = executionTimestampNanos(acceptance.accepted_at);
      const startedNanos = executionTimestampNanos(executionStart.started_at);
      if (acceptedNanos == null) return fail(REASONS.MALFORMED_EVIDENCE);
      if (startedNanos == null) {
        return unavailable(REASONS.AUTHORITATIVE_EXECUTION_TIME_UNAVAILABLE);
      }

      if (acceptedNanos === startedNanos) {
        return unavailable(REASONS.AUTHORITATIVE_EXECUTION_TIME_UNAVAILABLE);
      }
      return acceptedNanos < startedNanos
        ? pass()
        : fail(REASONS.ACCEPTANCE_AFTER_EXECUTION_START);
    },
  }),
  Object.freeze({
    id: "software.pipeline_link",
    group: "software",
    label: "Bound software release matches the execution pipeline",
    requirement: "required",
    evidenceRefs: ["software_release", "execution"],
    evaluate(context: ExecutionVerificationContext) {
      const release = context.evidence?.software_release;
      const pipelineHash = context.evidence?.execution?.pipeline_hash;

      if (!release || !present(pipelineHash)) return unavailable();

      if (
        !present(release.repository_uri) ||
        !isGitCommit(release.git_commit) ||
        !isSha3_512(release.pipeline_hash_sha3_512) ||
        !isSha3_512(pipelineHash)
      ) {
        return fail(REASONS.MALFORMED_EVIDENCE);
      }

      return release.pipeline_hash_sha3_512 === pipelineHash
        ? pass()
        : fail(REASONS.PIPELINE_HASH_MISMATCH);
    },
  }),
  Object.freeze({
    id: "parameters.commitment_matches",
    group: "execution",
    label: "Parameter instance commitment matches execution parameters",
    requirement: "optional",
    evidenceRefs: ["standards.schemas", "verification_material.parameter_instance"],
    evaluate(context: ExecutionVerificationContext) {
      const material = context.verificationMaterial?.parameter_instance;
      if (!material) {
        return unavailable(REASONS.PARAMETER_COMPARISON_UNAVAILABLE);
      }

      const role = cleanString(material.role);
      const hcs13Ref = cleanString(material.hcs13_ref);
      const domainSeparator = cleanString(material.domain_separator);
      const schemas = Array.isArray(context.evidence?.standards?.schemas)
        ? context.evidence.standards.schemas
        : [];
      const schema = schemas.find((entry) => cleanString(entry?.role) === role);

      if (
        !role ||
        !isHcs13Ref(hcs13Ref) ||
        domainSeparator !== "vera-anchor:hcs13-instance:v1" ||
        material.payload == null ||
        !schema
      ) {
        return fail(REASONS.MALFORMED_EVIDENCE);
      }

      const expectedDigest = schema.instance_digest_sha3_512;
      if (!present(expectedDigest)) {
        return unavailable(REASONS.PARAMETER_COMPARISON_UNAVAILABLE);
      }
      if (!isSha3_512(expectedDigest) || cleanString(schema.hcs13_ref) !== hcs13Ref) {
        return fail(REASONS.MALFORMED_EVIDENCE);
      }

      try {
        const computedDigest = computeExecutionDomainSeparatedSha3_512(
          domainSeparator,
          { role, hcs13_ref: hcs13Ref, payload: material.payload }
        );
        return computedDigest === expectedDigest
          ? pass()
          : fail(REASONS.PARAMETER_COMMITMENT_MISMATCH);
      } catch {
        return fail(REASONS.MALFORMED_EVIDENCE);
      }
    },
  }),
  Object.freeze({
    id: "result_evidence.scope",
    group: "result",
    label: "Result evidence identifies the requested result",
    requirement: "conditional",
    evidenceRefs: ["execution", "result_evidence"],
    evaluate(context: ExecutionVerificationContext) {
      if (!resultApplies(context)) return notApplicable();

      const resultEvidence = context.evidence?.result_evidence;
      if (!resultEvidence) return unavailable();

      const actual = cleanString(resultEvidence.result_id);
      const expected = context.requestedResultId;

      if (!actual || !isUuid(actual)) {
        return fail(REASONS.MALFORMED_EVIDENCE);
      }

      if (expected && !sameIdentifier(actual, expected)) {
        return fail(REASONS.RESULT_SCOPE_MISMATCH);
      }

      return pass();
    },
  }),
  Object.freeze({
    id: "result_evidence.contract_metadata",
    group: "result",
    label: "Result evidence contract metadata is valid",
    requirement: "conditional",
    evidenceRefs: ["result_evidence"],
    evaluate(context: ExecutionVerificationContext) {
      if (!resultApplies(context)) return notApplicable();
      return exactMetadata(context.evidence?.result_evidence, {
        schema: "ResultEvidenceV1",
        canonicalization: "RFC8785-JCS",
        digestAlgorithm: "SHA3-512",
        domainSeparator: "vera-anchor:result-evidence:v1",
      });
    },
  }),
  Object.freeze({
    id: "result_evidence.sealed",
    group: "result",
    label: "Result evidence is sealed",
    requirement: "conditional",
    evidenceRefs: ["result_evidence"],
    evaluate(context: ExecutionVerificationContext) {
      if (!resultApplies(context)) return notApplicable();
      const resultEvidence = context.evidence?.result_evidence;
      if (!resultEvidence) return unavailable();

      return hasTimestamp(resultEvidence.sealed_at)
        ? pass()
        : fail(REASONS.RESULT_EVIDENCE_UNSEALED);
    },
  }),
  Object.freeze({
    id: "result_evidence.binding_link",
    group: "result",
    label: "Result evidence references the finalized execution binding",
    requirement: "conditional",
    evidenceRefs: ["binding", "result_evidence"],
    evaluate(context: ExecutionVerificationContext) {
      if (!resultApplies(context)) return notApplicable();

      const bindingDigest = context.evidence?.binding?.digest;
      const resultBindingDigest =
        context.evidence?.result_evidence?.binding_digest;

      const bindingState = missingOrMalformedDigest(bindingDigest);
      if (bindingState) return bindingState;
      const resultState = missingOrMalformedDigest(resultBindingDigest);
      if (resultState) return resultState;

      return bindingDigest === resultBindingDigest
        ? pass()
        : fail(REASONS.BINDING_DIGEST_MISMATCH);
    },
  }),
  Object.freeze({
    id: "result_evidence.acceptance_link",
    group: "result",
    label: "Result evidence references the confirmed acceptance",
    requirement: "conditional",
    evidenceRefs: ["acceptance", "result_evidence"],
    evaluate(context: ExecutionVerificationContext) {
      if (!resultApplies(context)) return notApplicable();

      const acceptanceDigest = context.evidence?.acceptance?.digest;
      const resultAcceptanceDigest =
        context.evidence?.result_evidence?.acceptance_digest;

      const acceptanceState = missingOrMalformedDigest(acceptanceDigest);
      if (acceptanceState) return acceptanceState;
      const resultState = missingOrMalformedDigest(resultAcceptanceDigest);
      if (resultState) return resultState;

      return acceptanceDigest === resultAcceptanceDigest
        ? pass()
        : fail(REASONS.ACCEPTANCE_DIGEST_MISMATCH);
    },
  }),
  Object.freeze({
    id: "result_evidence.pipeline_link",
    group: "result",
    label: "Result evidence references the executed software pipeline",
    requirement: "conditional",
    evidenceRefs: ["execution", "result_evidence"],
    evaluate(context: ExecutionVerificationContext) {
      if (!resultApplies(context)) return notApplicable();

      const executionPipeline = context.evidence?.execution?.pipeline_hash;
      const evidencePipeline =
        context.evidence?.result_evidence?.pipeline_hash;

      if (!present(executionPipeline) || !present(evidencePipeline)) {
        return unavailable();
      }

      if (
        !isSha3_512(executionPipeline) ||
        !isSha3_512(evidencePipeline)
      ) {
        return fail(REASONS.MALFORMED_EVIDENCE);
      }

      return executionPipeline === evidencePipeline
        ? pass()
        : fail(REASONS.PIPELINE_HASH_MISMATCH);
    },
  }),
  Object.freeze({
    id: "result_evidence.hcs_receipt",
    group: "result",
    label: "Result evidence includes an HCS receipt reference",
    requirement: "conditional",
    evidenceRefs: ["result_evidence.hcs"],
    evaluate(context: ExecutionVerificationContext) {
      if (!resultApplies(context)) return notApplicable();

      const hcs = context.evidence?.result_evidence?.hcs;
      if (!hcs) return unavailable();

      return isHcsTransactionId(hcs.transaction_id) &&
        isHederaId(hcs.topic_id)
        ? pass()
        : fail(REASONS.MALFORMED_EVIDENCE);
    },
  }),
  Object.freeze({
    id: "result_evidence.digest_recomputed",
    group: "result",
    label: "Result evidence digest is recomputed from canonical content",
    requirement: "conditional",
    evidenceRefs: ["result_evidence.digest_payload", "result_evidence.digest"],
    evaluate(context: ExecutionVerificationContext) {
      if (!resultApplies(context)) return notApplicable();
      return recomputePublicContractDigest(
        context,
        context.evidence?.result_evidence,
        {
          domainSeparator: "vera-anchor:result-evidence:v1",
          unavailableReason: REASONS.RESULT_EVIDENCE_RECOMPUTATION_UNAVAILABLE,
          mismatchReason: REASONS.RESULT_EVIDENCE_DIGEST_MISMATCH,
        }
      );
    },
  }),
]);

export default EXECUTION_VERIFICATION_RULES;

/** Common Vera Anchor execution checks, excluding standards-backed SAGE rules. */
export const COMMON_EXECUTION_VERIFICATION_RULES: readonly ExecutionVerificationRule[] = Object.freeze(
  EXECUTION_VERIFICATION_RULES.filter((rule) => rule.group !== "standards"),
);
