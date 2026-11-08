import { describe, expect, it, vi } from "vitest";
import type { VerificationObservation, VerificationReport } from "../../src/contracts/verification.js";
import type { AuthorizedHcsObservationsV1Result } from "../../src/resolvers/authorizedObservationV1.js";
import { parseDatasetRegistryVersionCreatedV1 } from "../../src/profiles/dataset/registryEventV1.js";
import { triangulateAuthorizedDatasetV1 } from "../../src/triangulation/authorizedDatasetV1.js";
import { verifyDatasetV1WithIntent } from "../../src/verification/sourceIntentV1.js";
import { resolveAuthorizedHcsObservationsV1 } from "../../src/resolvers/authorizedObservationV1.js";

vi.mock("../../src/verification/sourceIntentV1.js", () => ({
  verifyDatasetV1WithIntent: vi.fn(),
}));
vi.mock("../../src/resolvers/authorizedObservationV1.js", () => ({
  resolveAuthorizedHcsObservationsV1: vi.fn(),
}));

const NETWORK = "testnet" as const;
const DATASET_KEY = "research.dataset.v1";
const FINGERPRINT = "a".repeat(128);
const MESSAGE_DIGEST = "b".repeat(128);
const VERSION_ID = "11111111-1111-4111-8111-111111111111";
const SUBJECT = Object.freeze({ kind: "dataset" as const, id: DATASET_KEY, hedera_network: NETWORK });
const CORE = Object.freeze({ base_url: "https://core.example.test", auth_provider: { authorize: vi.fn() } });

function registryPayload(fingerprint = FINGERPRINT, event = "dataset_version.created") {
  return {
    _type: "core.dataset_registry.event.v1",
    event,
    entity_id: `${DATASET_KEY}@3`,
    ts: "2026-11-05T00:00:00.000Z",
    actor_user_id: "22222222-2222-4222-8222-222222222222",
    hedera_network: NETWORK,
    service_event_hash: "c".repeat(128),
    payload: {
      dataset_version_id: VERSION_ID,
      dataset_key: DATASET_KEY,
      version: 3,
      dataset_fingerprint: fingerprint,
      manifest_hash: "d".repeat(128),
      schema_hash: "e".repeat(128),
      bytes_estimate: 128,
      row_count: 4,
      col_count: 2,
      set_active: false,
    },
  };
}

function sourceReport(): VerificationReport {
  return Object.freeze({
    intent: Object.freeze({ subject: SUBJECT, expected: Object.freeze([]) }),
    observations: Object.freeze([
      Object.freeze({
        id: "dataset.source",
        subject: Object.freeze({ kind: "dataset" as const, id: DATASET_KEY }),
        source: "local_computation" as const,
        facts: Object.freeze([]),
      }),
      Object.freeze({
        id: "dataset.bundle",
        subject: Object.freeze({ kind: "dataset" as const, id: DATASET_KEY }),
        source: "local_computation" as const,
        facts: Object.freeze([
          Object.freeze({ key: "dataset_fingerprint", state: "available" as const, value: FINGERPRINT }),
        ]),
      }),
    ]),
    findings: Object.freeze([
      Object.freeze({ check_id: "dataset.source_binding", outcome: "pass" as const, reason_code: null, observation_ids: Object.freeze(["dataset.source", "dataset.bundle"]) }),
      Object.freeze({ check_id: "dataset.bundle_consistency", outcome: "pass" as const, reason_code: null, observation_ids: Object.freeze(["dataset.bundle"]) }),
      Object.freeze({ check_id: "intent.subject", outcome: "pass" as const, reason_code: null, observation_ids: Object.freeze(["dataset.source", "dataset.bundle"]) }),
    ]),
  });
}

function messageObservation(source: "authorized_service" | "hedera_mirror"): VerificationObservation {
  const authorized = source === "authorized_service";
  return Object.freeze({
    id: authorized ? "dataset.authorized_core" : "dataset.hedera_mirror",
    subject: SUBJECT,
    source,
    facts: Object.freeze([
      Object.freeze({ key: authorized ? "publication.topic_id" : "hedera.topic_id", state: "available" as const, value: "0.0.12345" }),
      Object.freeze({ key: authorized ? "publication.sequence_number" : "hedera.sequence_number", state: "available" as const, value: 7 }),
      Object.freeze({ key: "publication.message_sha3_512", state: "available" as const, value: MESSAGE_DIGEST }),
      Object.freeze({ key: "publication.message_bytes", state: "available" as const, value: 256 }),
    ]),
  });
}

function resolution(payload: unknown): AuthorizedHcsObservationsV1Result {
  const authorized = messageObservation("authorized_service");
  const mirror = messageObservation("hedera_mirror");
  return {
    core: {
      status: "resolved",
      reason_code: null,
      evidence: {
        acquisition: {
          resolver_id: "core.authorized-hcs.v1",
          access_context: "authorized",
          retrieval_provider: "vera_anchor_core",
          decryption_method: "service_assisted",
          recoverability: "service_dependent",
        },
        hedera_network: NETWORK,
        topic: { name: "dataset_registry_events", topic_id: "0.0.12345", key_version: 1 },
        encryption: { topic_key_version: 1, user_key_version: 1 },
        tx: {
          id: "tx-row",
          message_id: "7@0.0.12345",
          transaction_id: "0.0.123@1793836800.000000001",
          sequence_number: 7,
          consensus_timestamp: "1793836800.000000001",
          status: "SUCCESS",
          mirror_verified: true,
          mirror_verified_at: null,
        },
        core_hash_observation: { expected: null, computed: null },
        message_binding: {
          schema_version: "vera.hcs-message-binding.v1",
          algorithm: "sha3-512",
          message_sha3_512: MESSAGE_DIGEST,
          message_bytes: 256,
        },
        payload_included: true,
        payload,
      },
    },
    authorized_observation: authorized,
    mirror: { status: "resolved", reason_code: null, observation: mirror },
    mirror_resolution: "resolved",
  };
}

const input = {
  bundle: {},
  files: [],
  intent: { subject: SUBJECT, expected: [] },
  hcs_reference: { message_id: "7@0.0.12345" },
};

describe("authorized Dataset v1 profile", () => {
  it("parses the current private dataset_version.created registry envelope", () => {
    const parsed = parseDatasetRegistryVersionCreatedV1(registryPayload(), NETWORK);
    expect(parsed.status).toBe("resolved");
    expect(parsed.event?.dataset_key).toBe(DATASET_KEY);
    expect(parsed.event?.dataset_fingerprint).toBe(FINGERPRINT);
    expect(parsed.event?.version).toBe(3);
  });

  it("treats another Dataset Registry event as unsupported instead of relabeling it", () => {
    expect(parseDatasetRegistryVersionCreatedV1(registryPayload(FINGERPRINT, "dataset.upserted"), NETWORK)).toMatchObject({
      status: "unsupported",
      reason_code: "AUTHORIZED_DATASET_EVENT_UNSUPPORTED",
    });
  });

  it("binds locally recomputed Dataset identity/fingerprint to authorized registry evidence and Hedera", async () => {
    vi.mocked(verifyDatasetV1WithIntent).mockResolvedValue(sourceReport());
    vi.mocked(resolveAuthorizedHcsObservationsV1).mockResolvedValue(resolution(registryPayload()));

    const out = await triangulateAuthorizedDatasetV1({ core: CORE }, input);
    expect(out.consistency).toBe("consistent");
    expect(out.relationships.map((entry) => entry.id)).toEqual(["authorized_hedera", "provided_authorized"]);
    expect(out.report.findings.find((entry) => entry.check_id === "triangulation.provided_authorized.dataset_key")?.outcome).toBe("pass");
    expect(out.report.findings.find((entry) => entry.check_id === "triangulation.provided_authorized.dataset_fingerprint")?.outcome).toBe("pass");
    expect(out.report.findings.find((entry) => entry.check_id === "triangulation.authorized_dataset.registry_event_profile")?.outcome).toBe("pass");
    expect(JSON.stringify(out.report)).not.toContain("actor_user_id");
    expect(JSON.stringify(out.report)).not.toContain("service_event_hash");
    expect(vi.mocked(resolveAuthorizedHcsObservationsV1)).toHaveBeenCalledWith(
      { core: CORE },
      expect.objectContaining({ request: expect.objectContaining({ network: NETWORK, include_decrypted: true, message_id: "7@0.0.12345" }) }),
    );
  });

  it("reports a conflicting authenticated Dataset fingerprint", async () => {
    vi.mocked(verifyDatasetV1WithIntent).mockResolvedValue(sourceReport());
    vi.mocked(resolveAuthorizedHcsObservationsV1).mockResolvedValue(resolution(registryPayload("f".repeat(128))));

    const out = await triangulateAuthorizedDatasetV1({ core: CORE }, input);
    expect(out.consistency).toBe("conflict");
    expect(out.report.findings.find((entry) => entry.check_id === "triangulation.provided_authorized.dataset_fingerprint")?.outcome).toBe("fail");
  });

  it("fails closed on a malformed claimed dataset_version.created payload", async () => {
    vi.mocked(verifyDatasetV1WithIntent).mockResolvedValue(sourceReport());
    const malformed = registryPayload() as { payload: Record<string, unknown> };
    malformed.payload.dataset_fingerprint = "not-a-digest";
    vi.mocked(resolveAuthorizedHcsObservationsV1).mockResolvedValue(resolution(malformed));

    const out = await triangulateAuthorizedDatasetV1({ core: CORE }, input);
    expect(out.consistency).toBe("conflict");
    expect(out.resolution.dataset_registry_event).toBe("invalid");
    expect(out.report.findings.find((entry) => entry.check_id === "triangulation.authorized_dataset.registry_event_profile")).toMatchObject({
      outcome: "fail",
      reason_code: "AUTHORIZED_DATASET_EVENT_PAYLOAD_INVALID",
    });
  });
});
