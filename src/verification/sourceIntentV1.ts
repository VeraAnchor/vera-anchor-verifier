import type {
  ExpectedCommitment,
  VerificationFact,
  VerificationFinding,
  VerificationIntent,
  VerificationObservation,
  VerificationOutcome,
  VerificationReport,
  VerificationSubject,
} from "../contracts/verification.js";
import {
  verifyDatasetV1Bundle,
  verifyDatasetV1Receipt,
  type DatasetV1BundleComputed,
  type DatasetV1ReceiptComputed,
} from "../profiles/dataset/v1.js";
import {
  verifyDatasetV1Sources,
  type DatasetV1SourceInput,
} from "../profiles/dataset/sourceV1.js";
import {
  verifyIngestV1Bundle,
  verifyIngestV1Pair,
  type IngestV1BundleComputed,
  type IngestV1ReceiptComputed,
} from "../profiles/ingest/v1.js";
import {
  verifyIngestV1Sources,
  type IngestV1SourceInput,
} from "../profiles/ingest/sourceV1.js";

type Profile = "dataset" | "ingest";
type BundleValues = DatasetV1BundleComputed | IngestV1BundleComputed;
type ReceiptValues = DatasetV1ReceiptComputed | IngestV1ReceiptComputed;
type CommitmentClaim = Readonly<{ value: string; domain: string }>;
type NormalizedMaterial = Readonly<{
  subject: VerificationSubject;
  profile: Profile;
  bundle: BundleValues;
  receipt?: ReceiptValues;
  sourceRoot: string | undefined;
  sourceCount: number;
  sourceBytes: number;
  sourceValid: boolean;
  bundleValid: boolean;
  receiptBindingValid: boolean | null;
}>;

/** Offline, read-only verification. Neither API authenticates a receipt's issuer or ledger publication. */
export type DatasetV1IntentInput = DatasetV1SourceInput & Readonly<{ intent: VerificationIntent }>;
export type IngestV1IntentInput = IngestV1SourceInput & Readonly<{ intent: VerificationIntent }>;

const HEX_512 = /^[a-f0-9]{128}$/i;
const EXPECTED_KEY = /^[a-z][a-z0-9_]{0,63}$/;
const MAX_EXPECTATIONS = 32;

function fact(key: string, value: string | number | boolean | null): VerificationFact {
  return Object.freeze({ key, state: "available" as const, value });
}

function observation(
  id: string,
  subject: VerificationSubject,
  source: VerificationObservation["source"],
  facts: readonly VerificationFact[],
): VerificationObservation {
  return Object.freeze({ id, subject: Object.freeze({ ...subject }), source, facts: Object.freeze([...facts]) });
}

function finding(
  check_id: string,
  outcome: VerificationOutcome,
  reason_code: string | null,
  observation_ids: readonly string[],
): VerificationFinding {
  return Object.freeze({ check_id, outcome, reason_code, observation_ids: Object.freeze([...observation_ids]) });
}

function checkedIntent(intent: VerificationIntent): VerificationIntent {
  if (!intent || typeof intent !== "object" || !intent.subject || typeof intent.subject !== "object") {
    throw new TypeError("Verification intent must have a subject");
  }
  const subject = intent.subject;
  if (typeof subject.id !== "string" || subject.id.length === 0 || subject.id.length > 256 || subject.id.trim() !== subject.id) {
    throw new TypeError("Verification subject must have a bounded, canonical ID");
  }
  if (subject.hedera_network !== undefined && subject.hedera_network !== "testnet" && subject.hedera_network !== "mainnet") {
    throw new TypeError("Invalid expected Hedera network");
  }
  if (!Array.isArray(intent.expected) || intent.expected.length > MAX_EXPECTATIONS) {
    throw new TypeError("Verification expectations must be a bounded array");
  }
  const used = new Set<string>();
  for (const commitment of intent.expected) {
    if (!commitment || typeof commitment !== "object" || typeof commitment.key !== "string" || !EXPECTED_KEY.test(commitment.key)) {
      throw new TypeError("Invalid commitment expectation key");
    }
    if (used.has(commitment.key)) throw new TypeError("Duplicate commitment expectation key");
    used.add(commitment.key);
    if (commitment.kind !== "digest" && commitment.kind !== "merkle-root") {
      throw new TypeError("Unsupported commitment expectation kind");
    }
    if (commitment.kind === "digest" && (typeof commitment.digest !== "string" || !HEX_512.test(commitment.digest))) {
      throw new TypeError("Expected digest must be a SHA3-512 hex commitment");
    }
    if (commitment.kind === "merkle-root" && (
      typeof commitment.root_hash !== "string" || !HEX_512.test(commitment.root_hash) ||
      !Number.isSafeInteger(commitment.leaf_count) || commitment.leaf_count < 1
    )) {
      throw new TypeError("Invalid expected Merkle root or leaf count");
    }
  }
  return intent;
}

function commitmentClaim(profile: Profile, key: string, bundle: BundleValues): CommitmentClaim | undefined {
  if (key === "bundle_digest") {
    return { value: bundle.bundle_digest, domain: `va:${profile}:bundle:v1` };
  }
  if (key === "idempotency_key") {
    return { value: bundle.idempotency_key, domain: `va:${profile}:idem:v1` };
  }
  if (profile === "dataset" && key === "dataset_fingerprint") {
    return { value: (bundle as DatasetV1BundleComputed).dataset_fingerprint, domain: "va:dataset:fingerprint:v1" };
  }
  if (profile === "ingest" && key === "fingerprint") {
    return { value: (bundle as IngestV1BundleComputed).fingerprint, domain: "va:ingest:fingerprint:v1" };
  }
  return undefined;
}

function compareExpected(
  expected: ExpectedCommitment,
  values: NormalizedMaterial,
  observations: readonly string[],
): VerificationFinding {
  const check = `intent.commitment.${expected.key}`;
  if (expected.kind === "merkle-root") {
    const algorithm = values.profile === "dataset" ? "hf-dataset-v1" : "hf-ingest-v1";
    if (expected.key !== "merkle_root" || expected.tree_alg !== algorithm) {
      return finding(check, "unsupported", "COMMITMENT_CONTRACT_UNSUPPORTED", []);
    }
    if (values.sourceRoot === undefined || !values.sourceValid || !values.bundleValid) {
      return finding(check, "indeterminate", "SOURCE_BINDING_NOT_ESTABLISHED", observations);
    }
    const matches = expected.root_hash.toLowerCase() === values.sourceRoot && expected.leaf_count === values.sourceCount;
    return finding(check, matches ? "pass" : "fail", matches ? null : "EXPECTED_MERKLE_MISMATCH", observations);
  }
  const claim = commitmentClaim(values.profile, expected.key, values.bundle);
  if (!claim || expected.contract !== "hf-contract-v1" || expected.material !== "json" || expected.domain !== claim.domain) {
    return finding(check, "unsupported", "COMMITMENT_CONTRACT_UNSUPPORTED", []);
  }
  if (!values.sourceValid || !values.bundleValid) {
    return finding(check, "indeterminate", "SOURCE_BINDING_NOT_ESTABLISHED", observations);
  }
  const matches = expected.digest.toLowerCase() === claim.value;
  return finding(check, matches ? "pass" : "fail", matches ? null : "EXPECTED_DIGEST_MISMATCH", observations);
}

function report(intent: VerificationIntent, values: NormalizedMaterial): VerificationReport {
  checkedIntent(intent);
  const prefix = values.profile;
  const sourceId = `${prefix}.source`;
  const bundleId = `${prefix}.bundle`;
  const receiptId = `${prefix}.receipt`;
  const bundle = values.bundle;
  const sourceFacts = [
    fact("source_file_or_item_count", values.sourceCount),
    fact("source_total_bytes", values.sourceBytes),
    ...(values.sourceRoot === undefined ? [] : [fact("source_merkle_root", values.sourceRoot)]),
  ];
  const bundleFacts = [
    fact("bundle_digest", bundle.bundle_digest),
    fact("idempotency_key", bundle.idempotency_key),
    fact("declared_file_or_item_count", "file_count" in bundle ? bundle.file_count : bundle.item_count),
    fact("declared_total_bytes", bundle.total_bytes),
    fact(values.profile === "dataset" ? "dataset_fingerprint" : "fingerprint",
      "dataset_fingerprint" in bundle ? bundle.dataset_fingerprint : bundle.fingerprint),
  ];
  const contentSubject: VerificationSubject = { kind: values.subject.kind, id: values.subject.id };
  const observations: VerificationObservation[] = [
    observation(sourceId, contentSubject, "local_computation", sourceFacts),
    observation(bundleId, contentSubject, "local_computation", bundleFacts),
  ];
  if (values.receipt) {
    observations.push(observation(receiptId, values.subject, "provided_evidence", [
      fact("receipt_id_recomputed", values.receipt.receipt_id),
      fact("receipt_declared_network", values.receipt.hedera_network),
    ]));
  }
  const findings: VerificationFinding[] = [
    finding(`${prefix}.source_binding`, values.sourceValid ? "pass" : "fail", values.sourceValid ? null : "SOURCE_MISMATCH", [sourceId, bundleId]),
    finding(`${prefix}.bundle_consistency`, values.bundleValid ? "pass" : "fail", values.bundleValid ? null : "BUNDLE_MISMATCH", [bundleId]),
    finding(`${prefix}.receipt_binding`, values.receiptBindingValid === null ? "indeterminate" : values.receiptBindingValid ? "pass" : "fail",
      values.receiptBindingValid === null ? "RECEIPT_NOT_SUPPLIED" : values.receiptBindingValid ? null : "RECEIPT_OR_BINDING_MISMATCH",
      values.receipt ? [bundleId, receiptId] : []),
  ];

  const subjectMatch = intent.subject.kind === values.subject.kind && intent.subject.id === values.subject.id;
  findings.push(finding(
    "intent.subject",
    !subjectMatch ? "fail" : values.sourceValid && values.bundleValid ? "pass" : "indeterminate",
    !subjectMatch ? "SUBJECT_MISMATCH" : values.sourceValid && values.bundleValid ? null : "SOURCE_BINDING_NOT_ESTABLISHED",
    [sourceId, bundleId],
  ));

  if (intent.subject.hedera_network !== undefined) {
    const claimedNetwork = values.receipt?.hedera_network;
    if (!claimedNetwork) {
      findings.push(finding("intent.declared_network", "indeterminate", "NETWORK_EVIDENCE_UNAVAILABLE", values.receipt ? [receiptId] : []));
    } else if (claimedNetwork !== intent.subject.hedera_network) {
      findings.push(finding("intent.declared_network", "fail", "NETWORK_MISMATCH", [receiptId]));
    } else if (!values.receiptBindingValid) {
      findings.push(finding("intent.declared_network", "indeterminate", "RECEIPT_BINDING_NOT_ESTABLISHED", [receiptId]));
    } else {
      findings.push(finding("intent.declared_network", "pass", null, [receiptId]));
    }
  }

  for (const expected of intent.expected) {
    findings.push(compareExpected(expected, values, [sourceId, bundleId]));
  }
  return Object.freeze({
    intent: Object.freeze({
      subject: Object.freeze({ ...intent.subject }),
      expected: Object.freeze(intent.expected.map((expectation) => Object.freeze({ ...expectation }))),
    }),
    findings: Object.freeze(findings),
    observations: Object.freeze(observations),
  });
}

/** Source bytes and caller expectations, without claiming independent receipt authentication. */
export async function verifyDatasetV1WithIntent(input: DatasetV1IntentInput): Promise<VerificationReport> {
  checkedIntent(input.intent);
  const source = await verifyDatasetV1Sources(input);
  const bundle = verifyDatasetV1Bundle(input.bundle);
  const receipt = input.receipt === undefined ? undefined : verifyDatasetV1Receipt(input.receipt);
  const actual = bundle.computed;
  const sourceValid = !source.mismatches.some((entry) =>
    !entry.field.startsWith("bundle.") && !entry.field.startsWith("receipt.") &&
    !entry.field.startsWith("binding.") && entry.field !== "sources.receipt_merkle_root");
  const receiptBindingValid = receipt === undefined ? null :
    receipt.ok && bundle.ok && !source.mismatches.some((entry) =>
      entry.field.startsWith("binding.") || entry.field === "sources.receipt_merkle_root");
  return report(input.intent, {
    profile: "dataset",
    subject: { kind: "dataset", id: actual.dataset_key, ...(receipt?.computed.hedera_network ? { hedera_network: receipt.computed.hedera_network } : {}) },
    bundle: actual,
    ...(receipt ? { receipt: receipt.computed } : {}),
    sourceRoot: source.computed.source_merkle_root,
    sourceCount: source.computed.source_file_count,
    sourceBytes: source.computed.source_total_bytes,
    sourceValid,
    bundleValid: bundle.ok,
    receiptBindingValid,
  });
}

/** Source material and caller expectations, with independent bundle/receipt comparison. */
export async function verifyIngestV1WithIntent(input: IngestV1IntentInput): Promise<VerificationReport> {
  checkedIntent(input.intent);
  const source = await verifyIngestV1Sources(input);
  const bundle = verifyIngestV1Bundle(input.bundle);
  const pair = input.receipt === undefined ? undefined : verifyIngestV1Pair({ bundle: input.bundle, receipt: input.receipt });
  const receipt = pair?.computed.receipt;
  const sourceMismatches = input.receipt === undefined
    ? source.mismatches.slice(bundle.mismatches.length)
    : source.mismatches.filter((entry) => !entry.field.startsWith("bundle.") &&
      !entry.field.startsWith("receipt.") && !entry.field.startsWith("binding.") &&
      entry.field !== "sources.receipt_merkle_root");
  const sourceValid = sourceMismatches.length === 0;
  const receiptBindingValid = pair === undefined ? null :
    pair.ok && !source.mismatches.some((entry) => entry.field === "sources.receipt_merkle_root");
  return report(input.intent, {
    profile: "ingest",
    subject: { kind: "ingest", id: bundle.computed.object_key, ...(receipt?.hedera_network ? { hedera_network: receipt.hedera_network } : {}) },
    bundle: bundle.computed,
    ...(receipt ? { receipt } : {}),
    sourceRoot: source.computed.source_merkle_root,
    sourceCount: source.computed.source_item_count,
    sourceBytes: source.computed.source_total_bytes,
    sourceValid,
    bundleValid: bundle.ok,
    receiptBindingValid,
  });
}
