import { describe, expect, it } from "vitest";
import { compareEvidenceTriangulationV1 } from "../../src/triangulation/compareV1.js";
import type { VerificationReport } from "../../src/contracts/verification.js";
import {
  resolveExplorerDatasetV1,
  resolveExplorerIngestV1,
  resolveExplorerMerkleRootV1,
} from "../../src/resolvers/explorerPublicV1.js";
import {
  resolveExplorerDatasetPublicationV1,
  resolveExplorerIngestPublicationV1,
} from "../../src/resolvers/explorerPublicationV1.js";
import type { ExplorerPublicTransportV1 } from "../../src/resolvers/explorerTransportV1.js";

const HEX_A = "a".repeat(128);
const HEX_B = "b".repeat(128);
const ANCHOR = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const ROOT = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const VERSION = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const DATASET = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";

function datasetRow() {
  return {
    hedera_network: "testnet",
    dataset_key: "research.dataset",
    dataset_id: DATASET,
    dataset_version_id: VERSION,
    dataset_fingerprint: HEX_A,
    manifest_hash: HEX_B,
    publication_version_transaction_id: "0.0.77@1234567890.123456789",
    publication_version_message_id: "5@0.0.12345",
    publication_version_topic_id: "0.0.12345",
    publication_version_sequence_number: 5,
  };
}

function anchorRow() {
  return {
    hedera_network: "testnet",
    anchor_request_id: ANCHOR,
    ingest_object_key: "research.ingest",
    ingest_fingerprint: HEX_A,
    ingest_bundle_digest: HEX_B,
    ingest_merkle_root: HEX_A,
    ingest_total_bytes: "52",
    root_id: ROOT,
    root_hash: HEX_B,
    publication_anchor_transaction_id: "0.0.77@1234567890.123456789",
    publication_anchor_message_id: "5@0.0.12345",
    publication_anchor_topic_id: "0.0.12345",
    publication_anchor_sequence_number: 5,
  };
}

function disclosurePayload(entityKind = "dataset_version", entityId = VERSION): object {
  return {
    hedera_network: "testnet",
    tx: { transaction_id: "0.0.77@1234567890.123456789", message_id: "5@0.0.12345" },
    topic: { topic_id: "0.0.12345" },
    verified: true,
    hash: { match: true },
    message_binding: { schema_version: "vera.hcs-message-binding.v1", algorithm: "sha3-512", message_sha3_512: HEX_A, message_bytes: 123 },
    payload: {
      schema: "va:explorer_publication_receipt:v1",
      event_type: "published",
      event_version: 1,
      entity_kind: entityKind,
      entity_id: entityId,
      visibility: "public",
      proof: { dataset_key: "research.dataset", fingerprint: HEX_A, ingest_bundle_digest: HEX_B },
    },
  };
}

function mocked(
  handler: (url: URL, init?: RequestInit) => Response | Promise<Response>,
): Readonly<{ config: ExplorerPublicTransportV1; calls: Array<{ url: URL; init?: RequestInit }> }> {
  const calls: Array<{ url: URL; init?: RequestInit }> = [];
  const fetchImpl = async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const parsed = new URL(String(url));
    calls.push({ url: parsed, ...(init === undefined ? {} : { init }) });
    return handler(parsed, init);
  };
  return { config: { base_url: "https://explorer.example.test", fetch_impl: fetchImpl as typeof fetch }, calls };
}

function json(value: unknown, status = 200, network?: string): Response {
  return Response.json(value, { status, ...(network ? { headers: { "x-hedera-network": network } } : {}) });
}

function factValue(facts: readonly { key: string; state: string; value?: unknown }[], key: string): unknown {
  const found = facts.find((entry) => entry.key === key);
  return found?.state === "available" ? found.value : null;
}

describe("Explorer public record resolver v1", () => {
  it("retrieves Dataset active manifest on explicit testnet and prefers version publication", async () => {
    const { config, calls } = mocked(() => json(datasetRow(), 200, "testnet"));
    const out = await resolveExplorerDatasetV1(config, { dataset_key: "research.dataset", network: "testnet" });
    expect(out.status).toBe("resolved");
    expect(out.publication?.entity_kind).toBe("dataset_version");
    expect(out.publication?.entity_id).toBe(VERSION);
    expect(out.publication?.message_id).toBe("5@0.0.12345");
    expect(out.observation?.subject.id).toBe("research.dataset");
    expect(factValue(out.observation?.facts ?? [], "dataset_fingerprint")).toBe(HEX_A);
    expect(factValue(out.observation?.facts ?? [], "dataset.manifest_hash")).toBe(HEX_B);
    expect(factValue(out.observation?.facts ?? [], "bundle_digest")).toBeNull();
    expect(calls[0]?.url.pathname).toBe("/v1/datasets/research.dataset");
    expect(calls[0]?.url.searchParams.get("network")).toBe("testnet");
    expect(calls[0]?.init?.credentials).toBe("omit");
    expect(calls[0]?.init?.redirect).toBe("error");
  });

  it("falls back to the Dataset publication when a version is not published", async () => {
    const row = datasetRow() as Record<string, unknown>;
    for (const key of Object.keys(row)) if (key.startsWith("publication_version_")) delete row[key];
    row.publication_dataset_message_id = "0.0.456@7";
    row.publication_dataset_topic_id = "0.0.456";
    row.publication_dataset_sequence_number = 7;
    const { config } = mocked(() => json(row));
    const out = await resolveExplorerDatasetV1(config, { dataset_key: "research.dataset", network: "testnet" });
    expect(out.publication?.entity_kind).toBe("dataset");
    expect(out.publication?.entity_id).toBe(DATASET);
    expect(out.publication?.message_id).toBe("7@0.0.456");
  });

  it("allows public records without a publication but never invents its locator", async () => {
    const row = datasetRow() as Record<string, unknown>;
    for (const key of Object.keys(row)) if (key.startsWith("publication_")) delete row[key];
    const { config } = mocked(() => json(row));
    const out = await resolveExplorerDatasetV1(config, { dataset_key: "research.dataset", network: "testnet" });
    expect(out.status).toBe("resolved");
    expect(out.publication).toBeNull();
    expect(out.observation?.facts.find((f) => f.key === "publication.topic_id")?.state).toBe("unavailable");
  });

  it("rejects different subject identity or network, never silently crossing network", async () => {
    const { config } = mocked(() => json({ ...datasetRow(), dataset_key: "unrelated" }));
    expect((await resolveExplorerDatasetV1(config, { dataset_key: "research.dataset", network: "testnet" })).status).toBe("conflict");
    const other = mocked(() => json({ ...datasetRow(), hedera_network: "mainnet" }));
    expect((await resolveExplorerDatasetV1(other.config, { dataset_key: "research.dataset", network: "testnet" })).status).toBe("invalid");
    const header = mocked(() => json(datasetRow(), 200, "mainnet"));
    expect((await resolveExplorerDatasetV1(header.config, { dataset_key: "research.dataset", network: "testnet" })).reason_code).toBe("EXPLORER_NETWORK_MISMATCH");
  });

  it("maps real public Dataset fields into the existing Phase 3A comparison contract", async () => {
    const { config } = mocked(() => json(datasetRow()));
    const resolved = await resolveExplorerDatasetV1(config, { dataset_key: "research.dataset", network: "testnet" });
    if (!resolved.observation) throw new Error("Expected public Dataset observation");
    const source: VerificationReport = {
      intent: { subject: { kind: "dataset", id: "research.dataset", hedera_network: "testnet" }, expected: [] },
      findings: [
        { check_id: "dataset.source_binding", outcome: "pass", reason_code: null, observation_ids: ["dataset.bundle"] },
        { check_id: "dataset.bundle_consistency", outcome: "pass", reason_code: null, observation_ids: ["dataset.bundle"] },
        { check_id: "intent.subject", outcome: "pass", reason_code: null, observation_ids: ["dataset.bundle"] },
      ],
      observations: [{
        id: "dataset.bundle", source: "local_computation",
        subject: { kind: "dataset", id: "research.dataset" },
        facts: [{ key: "dataset_fingerprint", state: "available", value: HEX_A }],
      }],
    };
    const compared = compareEvidenceTriangulationV1({
      source_report: source,
      observations: [resolved.observation],
      relationships: [{
        id: "provided_public_record",
        left_observation_id: "dataset.bundle", right_observation_id: "dataset.public_record",
        comparisons: [{ key: "dataset_fingerprint", left_key: "dataset_fingerprint", right_key: "dataset_fingerprint" }],
      }],
    });
    expect(compared.relationships[0]?.status).toBe("consistent");
    expect(compared.consistency).toBe("consistent");
  });

  it("resolves Ingest using explicitly scoped Merkle anchor and exact object key", async () => {
    const { config, calls } = mocked(() => json(anchorRow()));
    const out = await resolveExplorerIngestV1(config, { anchor_request_id: ANCHOR, ingest_object_key: "research.ingest", network: "testnet" });
    expect(out.status).toBe("resolved");
    expect(out.observation?.subject).toEqual({ kind: "ingest", id: "research.ingest", hedera_network: "testnet" });
    expect(factValue(out.observation?.facts ?? [], "fingerprint")).toBe(HEX_A);
    expect(factValue(out.observation?.facts ?? [], "bundle_digest")).toBe(HEX_B);
    expect(out.publication?.entity_kind).toBe("merkle_anchor");
    expect(calls[0]?.url.pathname).toBe(`/v1/merkle/anchors/${ANCHOR}`);
  });

  it("rejects Ingest anchored under a different object key", async () => {
    const { config } = mocked(() => json({ ...anchorRow(), ingest_object_key: "unrelated" }));
    const out = await resolveExplorerIngestV1(config, { anchor_request_id: ANCHOR, ingest_object_key: "research.ingest", network: "testnet" });
    expect(out.status).toBe("conflict");
    expect(out.publication).toBeNull();
  });

  it("resolves a Core Merkle root without treating original HCS as its publication", async () => {
    const { config } = mocked(() => json({
      hedera_network: "testnet", id: ROOT, root_hash: HEX_A, leaf_count: 8,
      hash_alg: "sha3-512", tree_alg: "binary-sorted",
      hcs_transaction_id: "original-encrypted-provenance",
      publication_root_message_id: "5@0.0.12345",
      publication_root_topic_id: "0.0.12345",
      publication_root_sequence_number: 5,
    }));
    const out = await resolveExplorerMerkleRootV1(config, { root_id: ROOT, network: "testnet" });
    expect(out.status).toBe("resolved");
    expect(out.publication?.transaction_id).toBeNull();
    expect(out.publication?.message_id).toBe("5@0.0.12345");
    expect(factValue(out.observation?.facts ?? [], "merkle.root_hash")).toBe(HEX_A);
  });

  it("preserves 404, 503, malformed JSON, and invalid commitments as non-passing outcomes", async () => {
    const req = { dataset_key: "research.dataset", network: "testnet" } as const;
    expect((await resolveExplorerDatasetV1(mocked(() => json({ error: "not_found" }, 404)).config, req)).status).toBe("not_found");
    expect((await resolveExplorerDatasetV1(mocked(() => json({ error: "db_unavailable" }, 503)).config, req)).status).toBe("unavailable");
    expect((await resolveExplorerDatasetV1(mocked(() => new Response("{", { status: 200 })).config, req)).status).toBe("invalid");
    expect((await resolveExplorerDatasetV1(mocked(() => json({ ...datasetRow(), dataset_fingerprint: "not-a-hash" })).config, req)).status).toBe("invalid");
  });

  it("fails closed on oversized public responses without buffering the full body", async () => {
    const oversized = "x".repeat(640 * 1024);
    const { config } = mocked(() => new Response(oversized, { status: 200 }));
    const out = await resolveExplorerDatasetV1(config, { dataset_key: "research.dataset", network: "testnet" });
    expect(out.status).toBe("invalid");
    expect(out.reason_code).toBe("EXPLORER_RESPONSE_TOO_LARGE");
  });

  it("rejects unsafe origins and unexpected input before any fetch", async () => {
    await expect(resolveExplorerDatasetV1({ base_url: "http://remote.example" }, { dataset_key: "research.dataset", network: "testnet" })).rejects.toThrow(TypeError);
    await expect(resolveExplorerDatasetV1({ base_url: "https://explorer.example.test/private" }, { dataset_key: "research.dataset", network: "testnet" })).rejects.toThrow(TypeError);
    await expect(resolveExplorerDatasetV1({ base_url: "https://explorer.example.test" }, { dataset_key: "../../private", network: "testnet" })).rejects.toThrow(TypeError);
  });
});

describe("Explorer-assisted public HCS publication disclosure", () => {
  it("fetches only the Dataset public publication locator and projects no raw plaintext", async () => {
    const { config, calls } = mocked((url, init) => {
      if (url.pathname === "/v1/datasets/research.dataset") return json(datasetRow());
      if (url.pathname === "/v1/hcs/verify-decrypt" && init?.method === "POST") return json(disclosurePayload());
      throw new Error(`Unexpected request ${url.pathname}`);
    });
    const out = await resolveExplorerDatasetPublicationV1(config, { dataset_key: "research.dataset", network: "testnet" });
    expect(out.public_record.status).toBe("resolved");
    expect(out.disclosure.status).toBe("resolved");
    expect(factValue(out.disclosure.receipt_observation?.facts ?? [], "publication.proof.fingerprint")).toBe(HEX_A);
    expect(factValue(out.disclosure.message_binding_observation?.facts ?? [], "publication.message_sha3_512")).toBe(HEX_A);
    expect(calls.length).toBe(2);
    expect(calls[1]?.url.pathname).toBe("/v1/hcs/verify-decrypt");
    const sent = JSON.parse(String(calls[1]?.init?.body)) as Record<string, unknown>;
    expect(sent).toEqual({
      hedera_network: "testnet", mode: "decrypt_and_verify", include_decrypted: true,
      transaction_id: "0.0.77@1234567890.123456789",
    });
    expect(JSON.stringify(out)).not.toContain("raw secret");
    expect(out.disclosure.receipt_observation?.source).toBe("public_record");
  });

  it("never calls decrypt when publication is missing", async () => {
    const row = datasetRow() as Record<string, unknown>;
    for (const key of Object.keys(row)) if (key.startsWith("publication_")) delete row[key];
    const { config, calls } = mocked(() => json(row));
    const out = await resolveExplorerDatasetPublicationV1(config, { dataset_key: "research.dataset", network: "testnet" });
    expect(out.disclosure.status).toBe("unavailable");
    expect(calls.length).toBe(1);
  });

  it("rejects a disclosed receipt for the wrong entity", async () => {
    const { config } = mocked((url) => url.pathname.includes("verify-decrypt")
      ? json(disclosurePayload("dataset_version", DATASET)) : json(datasetRow()));
    const out = await resolveExplorerDatasetPublicationV1(config, { dataset_key: "research.dataset", network: "testnet" });
    expect(out.disclosure.status).toBe("invalid");
  });

  it("fails closed on a wrong-network Core response or failed provider hash check", async () => {
    const network = mocked((url) => url.pathname.includes("verify-decrypt")
      ? json({ ...disclosurePayload(), hedera_network: "mainnet" }) : json(datasetRow()));
    const a = await resolveExplorerDatasetPublicationV1(network.config, { dataset_key: "research.dataset", network: "testnet" });
    expect(a.disclosure.status).toBe("conflict");
    const hash = mocked((url) => url.pathname.includes("verify-decrypt")
      ? json({ ...disclosurePayload(), hash: { match: false } }) : json(datasetRow()));
    const b = await resolveExplorerDatasetPublicationV1(hash.config, { dataset_key: "research.dataset", network: "testnet" });
    expect(b.disclosure.status).toBe("unavailable");
    expect(b.disclosure.reason_code).toBe("PUBLICATION_PROVIDER_VERIFICATION_FAILED");
  });

  it("keeps Core message binding unavailable rather than inventing it", async () => {
    const core = disclosurePayload() as Record<string, unknown>;
    delete core.message_binding;
    const { config } = mocked((url) => url.pathname.includes("verify-decrypt") ? json(core) : json(datasetRow()));
    const out = await resolveExplorerDatasetPublicationV1(config, { dataset_key: "research.dataset", network: "testnet" });
    expect(out.disclosure.status).toBe("resolved");
    expect(out.disclosure.message_binding_observation?.facts[0]?.state).toBe("unavailable");
  });

  it("resolves an Ingest publication through its public anchor only", async () => {
    const { config, calls } = mocked((url) => url.pathname.includes("verify-decrypt")
      ? json(disclosurePayload("merkle_anchor", ANCHOR)) : json(anchorRow()));
    const out = await resolveExplorerIngestPublicationV1(config, { anchor_request_id: ANCHOR, ingest_object_key: "research.ingest", network: "testnet" });
    expect(out.disclosure.status).toBe("resolved");
    expect(calls[0]?.url.pathname).toBe(`/v1/merkle/anchors/${ANCHOR}`);
    expect(out.disclosure.receipt_observation?.subject.id).toBe("research.ingest");
  });
});
