import type {
  EvidenceConsistency,
  VerificationFact,
  VerificationFinding,
  VerificationObservation,
  VerificationReport,
} from "../contracts/verification.js";
import {
  verifyIngestV1Receipt,
  type IngestV1ReceiptComputed,
} from "../profiles/ingest/v1.js";
import {
  resolveAuthorizedHcsObservationsV1,
  type AuthorizedHcsObservationsV1Config,
  type AuthorizedHcsObservationsV1Result,
} from "../resolvers/authorizedObservationV1.js";
import {
  verifyIngestV1WithIntent,
  type IngestV1IntentInput,
} from "../verification/sourceIntentV1.js";
import { triangulateAuthorizedHcsV1 } from "./authorizedHcsV1.js";
import {
  compareEvidenceTriangulationV1,
  type TriangulationRelationshipPlanV1,
  type TriangulationRelationshipResultV1,
} from "./compareV1.js";

export type AuthorizedIngestHcsReferenceV1 =
  | Readonly<{ message_id: string; transaction_id?: never }>
  | Readonly<{ transaction_id: string; message_id?: never }>;

export type AuthorizedIngestTriangulationV1Config = AuthorizedHcsObservationsV1Config;

export type AuthorizedIngestTriangulationV1Input = Omit<IngestV1IntentInput, "receipt"> & Readonly<{
  /** The authenticated workflow never accepts caller-supplied receipt authority. */
  receipt?: never;
  /** Caller-selected private Ingest receipt HCS message. Network comes only from verification intent. */
  hcs_reference: AuthorizedIngestHcsReferenceV1;
}>;

export type AuthorizedIngestReceiptV1Result = Readonly<{
  status: "resolved" | "unavailable" | "unsupported" | "invalid" | "conflict";
  reason_code: string | null;
  receipt: IngestV1ReceiptComputed | null;
}>;

export type AuthorizedIngestTriangulationV1Result = Readonly<{
  consistency: EvidenceConsistency;
  relationships: readonly TriangulationRelationshipResultV1[];
  report: VerificationReport;
  resolution: Readonly<{
    authorized_core: AuthorizedHcsObservationsV1Result["core"]["status"];
    hedera_mirror: AuthorizedHcsObservationsV1Result["mirror_resolution"];
    ingest_receipt: AuthorizedIngestReceiptV1Result["status"];
  }>;
}>;

const LOCAL_OBSERVATION_ID = "ingest.local_commitments";
const RECEIPT_OBSERVATION_ID = "ingest.receipt";
const SOURCE_OBSERVATION_ID = "ingest.source";
const BUNDLE_OBSERVATION_ID = "ingest.bundle";

function object(value: unknown): Readonly<Record<string, unknown>> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null
    ? value as Readonly<Record<string, unknown>>
    : null;
}

function available(key: string, value: string | number): VerificationFact {
  return Object.freeze({ key, state: "available" as const, value });
}

function unavailable(key: string, reason: string): VerificationFact {
  return Object.freeze({ key, state: "unavailable" as const, reason_code: reason });
}

function value(
  report: VerificationReport,
  observationId: string,
  key: string,
): string | number | null {
  const observation = report.observations.find((entry) => entry.id === observationId);
  if (!observation) throw new TypeError(`Ingest source report is missing ${observationId}`);
  if (observation.source !== "local_computation") {
    throw new TypeError(`Ingest source observation ${observationId} must be local computation`);
  }
  const fact = observation.facts.find((entry) => entry.key === key);
  if (!fact || fact.state !== "available") return null;
  return typeof fact.value === "string" || typeof fact.value === "number" ? fact.value : null;
}

function localObservation(report: VerificationReport): VerificationObservation {
  const fingerprint = value(report, BUNDLE_OBSERVATION_ID, "fingerprint");
  const bundleDigest = value(report, BUNDLE_OBSERVATION_ID, "bundle_digest");
  const idempotencyKey = value(report, BUNDLE_OBSERVATION_ID, "idempotency_key");
  const itemCount = value(report, BUNDLE_OBSERVATION_ID, "declared_file_or_item_count");
  const totalBytes = value(report, BUNDLE_OBSERVATION_ID, "declared_total_bytes");
  const merkleRoot = value(report, SOURCE_OBSERVATION_ID, "source_merkle_root");

  const fact = (key: string, entry: string | number | null, reason: string): VerificationFact =>
    entry === null ? unavailable(key, reason) : available(key, entry);

  return Object.freeze({
    id: LOCAL_OBSERVATION_ID,
    subject: Object.freeze({ ...report.intent.subject }),
    source: "local_computation" as const,
    facts: Object.freeze([
      available("ingest.local.object_key", report.intent.subject.id),
      fact("ingest.local.fingerprint", fingerprint, "INGEST_LOCAL_FINGERPRINT_UNAVAILABLE"),
      fact("ingest.local.bundle_digest", bundleDigest, "INGEST_LOCAL_BUNDLE_DIGEST_UNAVAILABLE"),
      fact("ingest.local.merkle_root", merkleRoot, "INGEST_LOCAL_MERKLE_ROOT_UNAVAILABLE"),
      fact("ingest.local.idempotency_key", idempotencyKey, "INGEST_LOCAL_IDEMPOTENCY_KEY_UNAVAILABLE"),
      fact("ingest.local.item_count", itemCount, "INGEST_LOCAL_ITEM_COUNT_UNAVAILABLE"),
      fact("ingest.local.total_bytes", totalBytes, "INGEST_LOCAL_TOTAL_BYTES_UNAVAILABLE"),
    ]),
  });
}

function receiptResult(
  status: AuthorizedIngestReceiptV1Result["status"],
  reason_code: string,
): AuthorizedIngestReceiptV1Result {
  return Object.freeze({ status, reason_code, receipt: null });
}

/**
 * Validate the exact plaintext contract HF stores through anchorPayload().
 * The producer anchors the deterministic local IngestReceiptV1 before root
 * build/publish, so a null receipt hedera_network is valid here; Core/Hedera
 * message resolution supplies the independent network binding.
 */
export function parseAuthorizedIngestReceiptV1(
  payload: unknown,
  expectedNetwork: "mainnet" | "testnet",
): AuthorizedIngestReceiptV1Result {
  if (payload === null || payload === undefined) {
    return receiptResult("unavailable", "AUTHORIZED_INGEST_RECEIPT_UNAVAILABLE");
  }
  const raw = object(payload);
  if (!raw) return receiptResult("invalid", "AUTHORIZED_INGEST_RECEIPT_INVALID");
  if (raw.v !== "v1" || raw.kind !== "ingest_receipt") {
    return receiptResult("unsupported", "AUTHORIZED_INGEST_RECEIPT_UNSUPPORTED");
  }
  if (raw.mode !== "register_and_anchor") {
    return receiptResult("unsupported", "AUTHORIZED_INGEST_RECEIPT_MODE_UNSUPPORTED");
  }

  try {
    const verified = verifyIngestV1Receipt(payload);
    if (!verified.ok) {
      return receiptResult("conflict", "AUTHORIZED_INGEST_RECEIPT_SELF_INCONSISTENT");
    }
    if (verified.computed.hedera_network !== null && verified.computed.hedera_network !== expectedNetwork) {
      return receiptResult("conflict", "AUTHORIZED_INGEST_RECEIPT_NETWORK_MISMATCH");
    }
    return Object.freeze({ status: "resolved" as const, reason_code: null, receipt: verified.computed });
  } catch (error) {
    if (error instanceof TypeError || error instanceof RangeError) {
      return receiptResult("invalid", "AUTHORIZED_INGEST_RECEIPT_INVALID");
    }
    throw error;
  }
}

function sourceReportWithAuthorizedReceipt(
  report: VerificationReport,
  parsed: AuthorizedIngestReceiptV1Result,
): VerificationReport {
  if (parsed.status !== "resolved" || !parsed.receipt) return report;
  const receipt = parsed.receipt;
  let found = false;
  const observations = report.observations.map((entry) => {
    if (entry.id !== RECEIPT_OBSERVATION_ID) return entry;
    if (entry.source !== "provided_evidence") {
      throw new TypeError("Authenticated Ingest receipt observation must originate from verifier-supplied evidence");
    }
    found = true;
    const merkleRoot = receipt.merkle_root === null
      ? unavailable("ingest.receipt.merkle_root", "AUTHORIZED_INGEST_MERKLE_ROOT_UNAVAILABLE")
      : available("ingest.receipt.merkle_root", receipt.merkle_root);
    const network = receipt.hedera_network === null
      ? unavailable("ingest.receipt.declared_network", "AUTHORIZED_INGEST_RECEIPT_NETWORK_NOT_EMBEDDED")
      : available("ingest.receipt.declared_network", receipt.hedera_network);
    return Object.freeze({
      ...entry,
      source: "authorized_service" as const,
      resolver_id: "core.authorized-hcs.v1",
      facts: Object.freeze([
        ...entry.facts,
        available("ingest.receipt.object_key", receipt.object_key),
        available("ingest.receipt.fingerprint", receipt.fingerprint),
        available("ingest.receipt.bundle_digest", receipt.bundle_digest),
        merkleRoot,
        available("ingest.receipt.idempotency_key", receipt.idempotency_key),
        available("ingest.receipt.item_count", receipt.item_count),
        available("ingest.receipt.total_bytes", receipt.total_bytes),
        network,
      ]),
    });
  });
  if (!found) throw new TypeError("Authenticated Ingest verifier report is missing ingest.receipt observation");
  return Object.freeze({ ...report, observations: Object.freeze(observations) });
}

function profileFinding(parsed: AuthorizedIngestReceiptV1Result): VerificationFinding {
  const outcome = parsed.status === "resolved"
    ? "pass" as const
    : parsed.status === "unavailable"
      ? "indeterminate" as const
      : parsed.status === "unsupported"
        ? "unsupported" as const
        : "fail" as const;
  return Object.freeze({
    check_id: "triangulation.authorized_ingest.receipt_profile",
    outcome,
    reason_code: parsed.reason_code,
    observation_ids: Object.freeze(parsed.status === "resolved" ? [RECEIPT_OBSERVATION_ID] : []),
  });
}

function aggregate(
  hcs: EvidenceConsistency,
  ingest: EvidenceConsistency,
  parsed: AuthorizedIngestReceiptV1Result,
): EvidenceConsistency {
  if (hcs === "conflict" || ingest === "conflict" || parsed.status === "invalid" || parsed.status === "conflict") {
    return "conflict";
  }
  if (hcs !== "consistent" || ingest !== "consistent" || parsed.status !== "resolved") {
    return "incomplete";
  }
  return "consistent";
}

function checkedReference(reference: AuthorizedIngestHcsReferenceV1): AuthorizedIngestHcsReferenceV1 {
  const message = "message_id" in reference ? reference.message_id : undefined;
  const transaction = "transaction_id" in reference ? reference.transaction_id : undefined;
  if ((typeof message === "string") === (typeof transaction === "string") ||
    (message !== undefined && (message.length === 0 || message.length > 256 || message.trim() !== message)) ||
    (transaction !== undefined && (transaction.length === 0 || transaction.length > 256 || transaction.trim() !== transaction))) {
    throw new TypeError("Authorized Ingest triangulation requires exactly one bounded HCS reference");
  }
  return reference;
}

/**
 * Recompute Ingest v1 source evidence, retrieve the caller-authorized private
 * deterministic Ingest receipt, independently corroborate its exact HCS
 * ciphertext, and compare only commitments already established by the local
 * Ingest verifier. Raw decrypted payload is never copied into the report.
 */
export async function triangulateAuthorizedIngestV1(
  config: AuthorizedIngestTriangulationV1Config,
  input: AuthorizedIngestTriangulationV1Input,
): Promise<AuthorizedIngestTriangulationV1Result> {
  if (!config?.core || !input?.intent?.subject || input.intent.subject.kind !== "ingest") {
    throw new TypeError("Authorized Ingest triangulation requires Ingest intent and Core config");
  }
  if (Object.prototype.hasOwnProperty.call(input, "receipt")) {
    throw new TypeError("Authorized Ingest triangulation does not accept caller-supplied receipt authority");
  }
  const network = input.intent.subject.hedera_network;
  if (network !== "mainnet" && network !== "testnet") {
    throw new TypeError("Authorized Ingest triangulation requires an explicit Hedera network");
  }
  const reference = checkedReference(input.hcs_reference);
  const { hcs_reference: _reference, ...sourceInput } = input;
  void _reference;

  const resolution = await resolveAuthorizedHcsObservationsV1(config, {
    subject: input.intent.subject,
    request: Object.freeze({
      network,
      include_decrypted: true,
      ...(reference.message_id !== undefined ? { message_id: reference.message_id } : {}),
      ...(reference.transaction_id !== undefined ? { transaction_id: reference.transaction_id } : {}),
    }),
  });
  const payload = resolution.core.evidence?.payload_included === true
    ? resolution.core.evidence.payload
    : null;
  const parsed = parseAuthorizedIngestReceiptV1(payload, network);
  const verifiedSource = await verifyIngestV1WithIntent({
    ...(sourceInput as IngestV1IntentInput),
    ...(parsed.status === "resolved" ? { receipt: payload } : {}),
  });
  const source = sourceReportWithAuthorizedReceipt(verifiedSource, parsed);
  const hcs = triangulateAuthorizedHcsV1({ source_report: source, resolution });
  const local = localObservation(hcs.report);
  const sourceWithLocal = Object.freeze({
    ...hcs.report,
    observations: Object.freeze([...hcs.report.observations, local]),
  });
  const relationship: TriangulationRelationshipPlanV1 = Object.freeze({
    id: "provided_authorized",
    left_observation_id: LOCAL_OBSERVATION_ID,
    right_observation_id: RECEIPT_OBSERVATION_ID,
    comparisons: Object.freeze([
      Object.freeze({ key: "object_key", left_key: "ingest.local.object_key", right_key: "ingest.receipt.object_key" }),
      Object.freeze({ key: "fingerprint", left_key: "ingest.local.fingerprint", right_key: "ingest.receipt.fingerprint" }),
      Object.freeze({ key: "bundle_digest", left_key: "ingest.local.bundle_digest", right_key: "ingest.receipt.bundle_digest" }),
      Object.freeze({ key: "merkle_root", left_key: "ingest.local.merkle_root", right_key: "ingest.receipt.merkle_root" }),
      Object.freeze({ key: "idempotency_key", left_key: "ingest.local.idempotency_key", right_key: "ingest.receipt.idempotency_key" }),
      Object.freeze({ key: "item_count", left_key: "ingest.local.item_count", right_key: "ingest.receipt.item_count" }),
      Object.freeze({ key: "total_bytes", left_key: "ingest.local.total_bytes", right_key: "ingest.receipt.total_bytes" }),
    ]),
  });
  const compared = compareEvidenceTriangulationV1({
    source_report: sourceWithLocal,
    observations: Object.freeze([]),
    relationships: Object.freeze([relationship]),
  });
  const finding = profileFinding(parsed);

  return Object.freeze({
    consistency: aggregate(hcs.consistency, compared.consistency, parsed),
    relationships: Object.freeze([...hcs.relationships, ...compared.relationships]),
    report: Object.freeze({
      ...compared.report,
      findings: Object.freeze([...compared.report.findings, finding]),
    }),
    resolution: Object.freeze({
      authorized_core: resolution.core.status,
      hedera_mirror: resolution.mirror_resolution,
      ingest_receipt: parsed.status,
    }),
  });
}
