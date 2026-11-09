import { beforeEach, describe, expect, it, vi } from "vitest";
import type { VerificationObservation, VerificationReport } from "../../src/contracts/verification.js";
import type { IngestV1ReceiptComputed } from "../../src/profiles/ingest/v1.js";
import type { AuthorizedHcsObservationsV1Result } from "../../src/resolvers/authorizedObservationV1.js";
import { verifyIngestV1Receipt } from "../../src/profiles/ingest/v1.js";
import { resolveAuthorizedHcsObservationsV1 } from "../../src/resolvers/authorizedObservationV1.js";
import { verifyIngestV1WithIntent } from "../../src/verification/sourceIntentV1.js";
import {
  parseAuthorizedIngestReceiptV1,
  triangulateAuthorizedIngestV1,
} from "../../src/triangulation/authorizedIngestV1.js";

vi.mock("../../src/profiles/ingest/v1.js", async (original) => {
  const actual = await original<typeof import("../../src/profiles/ingest/v1.js")>();
  return { ...actual, verifyIngestV1Receipt: vi.fn() };
});
vi.mock("../../src/resolvers/authorizedObservationV1.js", () => ({
  resolveAuthorizedHcsObservationsV1: vi.fn(),
}));
vi.mock("../../src/verification/sourceIntentV1.js", () => ({
  verifyIngestV1WithIntent: vi.fn(),
}));

const NETWORK = "testnet" as const;
const SUBJECT = Object.freeze({ kind: "ingest" as const, id: "research.ingest", hedera_network: NETWORK });
const HASH = "a".repeat(128);
const ROOT = "b".repeat(128);
const BUNDLE = "c".repeat(128);
const FINGERPRINT = "d".repeat(128);
const IDEM = "e".repeat(128);

function sourceReport(withReceipt = false): VerificationReport {
  return Object.freeze({
    intent: Object.freeze({ subject: SUBJECT, expected: Object.freeze([]) }),
    observations: Object.freeze([
      Object.freeze({ id: "ingest.source", subject: Object.freeze({ kind: "ingest" as const, id: SUBJECT.id }),
        source: "local_computation" as const, facts: Object.freeze([
          Object.freeze({ key: "source_file_or_item_count", state: "available" as const, value: 2 }),
          Object.freeze({ key: "source_total_bytes", state: "available" as const, value: 25 }),
          Object.freeze({ key: "source_merkle_root", state: "available" as const, value: ROOT }),
        ]) }),
      Object.freeze({ id: "ingest.bundle", subject: Object.freeze({ kind: "ingest" as const, id: SUBJECT.id }),
        source: "local_computation" as const, facts: Object.freeze([
          Object.freeze({ key: "bundle_digest", state: "available" as const, value: BUNDLE }),
          Object.freeze({ key: "idempotency_key", state: "available" as const, value: IDEM }),
          Object.freeze({ key: "declared_file_or_item_count", state: "available" as const, value: 2 }),
          Object.freeze({ key: "declared_total_bytes", state: "available" as const, value: 25 }),
          Object.freeze({ key: "fingerprint", state: "available" as const, value: FINGERPRINT }),
        ]) }),
      ...(withReceipt ? [Object.freeze({ id: "ingest.receipt", subject: SUBJECT,
        source: "provided_evidence" as const, facts: Object.freeze([
          Object.freeze({ key: "receipt_id_recomputed", state: "available" as const, value: "f".repeat(128) }),
          Object.freeze({ key: "receipt_declared_network", state: "available" as const, value: null }),
        ]) })] : []),
    ]),
    findings: Object.freeze([
      Object.freeze({ check_id: "ingest.source_binding", outcome: "pass" as const, reason_code: null,
        observation_ids: Object.freeze(["ingest.source", "ingest.bundle"]) }),
      Object.freeze({ check_id: "ingest.bundle_consistency", outcome: "pass" as const, reason_code: null,
        observation_ids: Object.freeze(["ingest.bundle"]) }),
      Object.freeze({ check_id: "ingest.receipt_binding",
        outcome: withReceipt ? "pass" as const : "indeterminate" as const,
        reason_code: withReceipt ? null : "RECEIPT_NOT_SUPPLIED",
        observation_ids: Object.freeze(withReceipt ? ["ingest.bundle", "ingest.receipt"] : []) }),
      Object.freeze({ check_id: "intent.subject", outcome: "pass" as const, reason_code: null,
        observation_ids: Object.freeze(["ingest.source", "ingest.bundle"]) }),
      Object.freeze({ check_id: "intent.declared_network", outcome: "indeterminate" as const,
        reason_code: "NETWORK_EVIDENCE_UNAVAILABLE", observation_ids: Object.freeze([]) }),
    ]),
  });
}

function receipt(overrides: Partial<IngestV1ReceiptComputed> = {}): IngestV1ReceiptComputed {
  return Object.freeze({
    hedera_network: null,
    object_key: SUBJECT.id,
    object_kind: "file_set",
    program: null,
    version_label: null,
    receipt_id: "f".repeat(128),
    idempotency_key: IDEM,
    fingerprint: FINGERPRINT,
    bundle_digest: BUNDLE,
    merkle_root: ROOT,
    item_count: 2,
    total_bytes: 25,
    receipt_anchor_id: null,
    receipt_anchor_hash: null,
    receipt_leaf_id: null,
    receipt_leaf_hash: null,
    receipt_payload_hash: null,
    receipt_hcs_transaction_id: null,
    receipt_hcs_message_id: null,
    root_anchor_id: null,
    root_anchor_hash: null,
    root_id: null,
    anchored_root_hash: null,
    root_hcs_transaction_id: null,
    root_hcs_message_id: null,
    ...overrides,
  });
}

function hcsObservation(source: "authorized_service" | "hedera_mirror", digest = HASH): VerificationObservation {
  const authorized = source === "authorized_service";
  return Object.freeze({
    id: authorized ? "ingest.authorized_core" : "ingest.hedera_mirror",
    subject: SUBJECT,
    source,
    facts: Object.freeze([
      Object.freeze({ key: authorized ? "publication.topic_id" : "hedera.topic_id", state: "available" as const, value: "0.0.12345" }),
      Object.freeze({ key: authorized ? "publication.sequence_number" : "hedera.sequence_number", state: "available" as const, value: 7 }),
      Object.freeze({ key: "publication.message_sha3_512", state: "available" as const, value: digest }),
      Object.freeze({ key: "publication.message_bytes", state: "available" as const, value: 256 }),
    ]),
  });
}

function resolution(payload: unknown, mirrorStatus: "resolved" | "unavailable" = "resolved"): AuthorizedHcsObservationsV1Result {
  const authorized = hcsObservation("authorized_service");
  const mirror = hcsObservation("hedera_mirror");
  return {
    core: {
      status: "resolved",
      reason_code: null,
      evidence: {
        acquisition: { resolver_id: "core.authorized-hcs.v1", access_context: "authorized",
          retrieval_provider: "vera_anchor_core", decryption_method: "service_assisted", recoverability: "service_dependent" },
        hedera_network: NETWORK,
        topic: { name: "merkle_anchor", topic_id: "0.0.12345", key_version: null },
        encryption: { topic_key_version: null, user_key_version: null },
        tx: { id: "11111111-1111-4111-8111-111111111111", message_id: "7@0.0.12345",
          transaction_id: "0.0.77@1234567890.123456789", sequence_number: 7,
          consensus_timestamp: "1234567890.123456789", status: "confirmed", mirror_verified: false, mirror_verified_at: null },
        core_hash_observation: { expected: null, computed: null },
        message_binding: { schema_version: "vera.hcs-message-binding.v1", algorithm: "sha3-512",
          message_sha3_512: HASH, message_bytes: 256 },
        payload_included: true,
        payload,
      },
    },
    authorized_observation: authorized,
    mirror: mirrorStatus === "resolved"
      ? { status: "resolved", reason_code: null, observation: mirror }
      : { status: "unavailable", reason_code: "MIRROR_UNAVAILABLE", observation: null },
    mirror_resolution: mirrorStatus,
  };
}

const rawReceipt = Object.freeze({ v: "v1", kind: "ingest_receipt", mode: "register_and_anchor" });

function input() {
  return {
    intent: { subject: SUBJECT, expected: [] },
    bundle: {},
    material: { kind: "json" as const, value: {} },
    hcs_reference: { message_id: "7@0.0.12345" },
  };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("authenticated Ingest triangulation", () => {
  it("binds locally recomputed Ingest commitments to the authorized receipt and exact Hedera message", async () => {
    vi.mocked(verifyIngestV1WithIntent).mockImplementationOnce(async (value) => sourceReport(value.receipt !== undefined));
    vi.mocked(resolveAuthorizedHcsObservationsV1).mockResolvedValueOnce(resolution(rawReceipt));
    vi.mocked(verifyIngestV1Receipt).mockReturnValueOnce({ ok: true, mismatches: [], computed: receipt() });

    const out = await triangulateAuthorizedIngestV1({ core: {} as never }, input());
    expect(out.consistency).toBe("consistent");
    expect(out.relationships.map((entry) => entry.id)).toEqual(["authorized_hedera", "provided_authorized"]);
    expect(out.report.findings.find((entry) => entry.check_id === "triangulation.provided_authorized.merkle_root"))
      .toMatchObject({ outcome: "pass" });
    expect(out.report.findings.find((entry) => entry.check_id === "triangulation.authorized_ingest.receipt_profile"))
      .toMatchObject({ outcome: "pass" });
    expect(out.report.observations.find((entry) => entry.id === "ingest.receipt")?.source)
      .toBe("authorized_service");
    expect(JSON.stringify(out.report)).not.toContain("private-user-metadata");
  });

  it("fails closed when an authenticated receipt commitment conflicts with local recomputation", async () => {
    vi.mocked(verifyIngestV1WithIntent).mockImplementationOnce(async (value) => sourceReport(value.receipt !== undefined));
    vi.mocked(resolveAuthorizedHcsObservationsV1).mockResolvedValueOnce(resolution(rawReceipt));
    vi.mocked(verifyIngestV1Receipt).mockReturnValueOnce({ ok: true, mismatches: [],
      computed: receipt({ fingerprint: "0".repeat(128) }) });

    const out = await triangulateAuthorizedIngestV1({ core: {} as never }, input());
    expect(out.consistency).toBe("conflict");
    expect(out.report.findings.find((entry) => entry.check_id === "triangulation.provided_authorized.fingerprint"))
      .toMatchObject({ outcome: "fail" });
  });

  it("treats self-inconsistent authenticated receipts as conflict without promoting their commitments", async () => {
    vi.mocked(verifyIngestV1WithIntent).mockImplementationOnce(async (value) => sourceReport(value.receipt !== undefined));
    vi.mocked(resolveAuthorizedHcsObservationsV1).mockResolvedValueOnce(resolution(rawReceipt));
    vi.mocked(verifyIngestV1Receipt).mockReturnValueOnce({ ok: false,
      mismatches: [{ field: "receipt_id", expected: "a", actual: "b" }], computed: receipt() });

    const out = await triangulateAuthorizedIngestV1({ core: {} as never }, input());
    expect(out.consistency).toBe("conflict");
    expect(out.resolution.ingest_receipt).toBe("conflict");
    expect(out.report.observations.some((entry) => entry.id === "ingest.receipt")).toBe(false);
  });

  it("keeps Mirror unavailability incomplete instead of weakening the authenticated workflow", async () => {
    vi.mocked(verifyIngestV1WithIntent).mockImplementationOnce(async (value) => sourceReport(value.receipt !== undefined));
    vi.mocked(resolveAuthorizedHcsObservationsV1).mockResolvedValueOnce(resolution(rawReceipt, "unavailable"));
    vi.mocked(verifyIngestV1Receipt).mockReturnValueOnce({ ok: true, mismatches: [], computed: receipt() });

    const out = await triangulateAuthorizedIngestV1({ core: {} as never }, input());
    expect(out.consistency).toBe("incomplete");
    expect(out.resolution.hedera_mirror).toBe("unavailable");
  });

  it("rejects caller-supplied receipt authority and requires explicit network-scoped intent", async () => {
    await expect(triangulateAuthorizedIngestV1({ core: {} as never }, { ...input(), receipt: rawReceipt } as never))
      .rejects.toThrow(/does not accept caller-supplied receipt/);
    await expect(triangulateAuthorizedIngestV1({ core: {} as never }, {
      ...input(), intent: { subject: { kind: "ingest", id: SUBJECT.id }, expected: [] },
    } as never)).rejects.toThrow(/explicit Hedera network/);
  });

  it("classifies unsupported receipt contracts before invoking the Ingest verifier", () => {
    const out = parseAuthorizedIngestReceiptV1({ v: "v2", kind: "ingest_receipt", mode: "register_and_anchor" }, NETWORK);
    expect(out).toMatchObject({ status: "unsupported", reason_code: "AUTHORIZED_INGEST_RECEIPT_UNSUPPORTED" });
    expect(verifyIngestV1Receipt).not.toHaveBeenCalled();
  });
});