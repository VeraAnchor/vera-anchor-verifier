import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { sha3_512Hex } from "../../src/crypto/sha3.js";
import { resolveHederaPublicationV1 } from "../../src/resolvers/hederaMirrorV1.js";
import { triangulateDatasetV1, triangulateIngestV1 } from "../../src/triangulation/publicV1.js";
import { triangulateDatasetWithPolicyV1, triangulateIngestWithPolicyV1,
  assessPortableVerificationPolicyV1 } from "../../src/policy/evaluateV1.js";
import { VERIFICATION_POLICY_SCHEMA_VERSION, type VerificationPolicyV1 } from "../../src/policy/contractV1.js";
import { validatePortableVerificationReportV1 } from "../../src/reports/validationV1.js";

const NETWORK = "testnet" as const;
const TOPIC = "0.0.12345";
const TX = "0.0.77@1234567890.123456789";
const ANCHOR = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const VERSION = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const DATASET = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const PAYLOAD = Buffer.from("encrypted-publication-envelope", "utf8");
const HASH = sha3_512Hex(PAYLOAD);
const URL_EXPLORER = "https://explorer.example.test";
const URL_MIRROR = "https://mirror.example.test/api/v1";
const pub = {
  hedera_network: NETWORK, entity_kind: "dataset_version" as const, entity_id: VERSION,
  transaction_id: TX, message_id: `5@${TOPIC}`, topic_id: TOPIC, sequence_number: 5,
};
const subject = { kind: "dataset" as const, id: "research.dataset", hedera_network: NETWORK };
function json(value: unknown, status = 200): Response { return Response.json(value, { status }); }
function message(override: Record<string, unknown> = {}): Record<string, unknown> {
  return { topic_id: TOPIC, sequence_number: 5, consensus_timestamp: "1234567890.123456789",
    message: PAYLOAD.toString("base64"), ...override };
}
function tx() { return { transactions: [{ transaction_id: "0.0.77-1234567890-123456789", result: "SUCCESS",
  consensus_timestamp: "1234567890.123456790" }] }; }
function mirror(impl: (url: URL) => Response | Promise<Response> = (url) =>
  url.pathname.includes("/transactions/") ? json(tx()) : json(message())) {
  const urls: URL[] = [];
  return { urls, config: { base_urls: { testnet: URL_MIRROR }, fetch_impl: vi.fn(async (url: string | URL | Request) => {
    const parsed = new URL(String(url)); urls.push(parsed); return impl(parsed);
  }) as typeof fetch } };
}
function value(out: { observation: { facts: readonly { key: string; state: string; value?: unknown }[] } | null }, key: string) {
  return out.observation?.facts.find((fact) => fact.key === key && fact.state === "available")?.value;
}

describe("Independent Hedera publication observation", () => {
  it("independently recomputes the exact ciphertext digest and preserves nanosecond timestamps", async () => {
    const mock = mirror();
    const out = await resolveHederaPublicationV1(mock.config, pub, subject);
    expect(out.status).toBe("resolved");
    expect(value(out, "publication.message_sha3_512")).toBe(HASH);
    expect(value(out, "publication.message_bytes")).toBe(PAYLOAD.length);
    expect(value(out, "hedera.consensus_timestamp_exact")).toBe("1234567890.123456789");
    expect(value(out, "hedera.transaction_id")).toBe(TX);
    expect(mock.urls.map((url) => url.pathname)).toEqual([
      "/api/v1/topics/0.0.12345/messages/5",
      "/api/v1/transactions/0.0.77-1234567890-123456789",
    ]);
    expect(out.observation?.source).toBe("hedera_mirror");
  });

  it("reassembles chunked HCS before SHA3-512 and never hashes one chunk as the logical message", async () => {
    const chunks = [Buffer.from("encrypted-"), Buffer.from("logical-message")];
    const group = TX;
    const first = message({ message: chunks[0]!.toString("base64"),
      chunk_info: { number: 1, total: 2, initial_transaction_id: group } });
    const second = message({ sequence_number: 6, consensus_timestamp: "1234567890.123456790",
      message: chunks[1]!.toString("base64"),
      chunk_info: { number: 2, total: 2, initial_transaction_id: group } });
    const mock = mirror((url) => url.pathname.endsWith("/messages/5") ? json(first) :
      url.pathname.endsWith("/messages") ? json({ messages: [first, second] }) : json(tx()));
    const out = await resolveHederaPublicationV1(mock.config, pub, subject);
    expect(out.status).toBe("resolved");
    expect(value(out, "publication.message_sha3_512")).toBe(sha3_512Hex(Buffer.concat(chunks)));
    expect(mock.urls.find((url) => url.pathname.endsWith("/messages"))?.searchParams.get("timestamp"))
      .toBe("gte:1234567890.123456789");
  });

  it("fails closed for missing chunks, wrong topic, invalid base64 and missing transaction", async () => {
    const cases = [
      mirror((url) => url.pathname.endsWith("/messages/5") ? json(message({
        chunk_info: { number: 1, total: 2, initial_transaction_id: TX },
      })) : json({ messages: [] })),
      mirror(() => json(message({ topic_id: "0.0.999" }))),
      mirror(() => json(message({ message: "%%%%" }))),
      mirror((url) => url.pathname.includes("transactions/") ? json({ error: "not_found" }, 404) : json(message())),
    ];
    for (const example of cases) {
      const out = await resolveHederaPublicationV1(example.config, pub, subject);
      expect(out.status).not.toBe("resolved");
      expect(out.observation).toBeNull();
    }
  });

  it("does not probe another network or try a transaction-only locator as message bytes", async () => {
    const mock = mirror(() => json({ error: "not_found" }, 404));
    const missing = await resolveHederaPublicationV1(mock.config, pub, subject);
    expect(missing.status).toBe("unavailable");
    expect(mock.urls).toHaveLength(1);
    expect(mock.urls.every((url) => url.origin === "https://mirror.example.test")).toBe(true);
    const txOnly = await resolveHederaPublicationV1(mock.config, {
      ...pub, topic_id: null, sequence_number: null, message_id: null,
    }, subject);
    expect(txOnly.status).toBe("unavailable");
    expect(mock.urls).toHaveLength(1);
  });

  it("rejects a failed requested ledger transaction, without substituting another transaction", async () => {
    const mock = mirror((url) => url.pathname.includes("transactions/") ? json({ transactions: [
      { transaction_id: "0.0.77-1234567890-123456789", result: "INVALID_SIGNATURE" },
    ] }) : json(message()));
    const out = await resolveHederaPublicationV1(mock.config, pub, subject);
    expect(out.status).toBe("conflict");
    expect(out.reason_code).toBe("MIRROR_TRANSACTION_FAILED");
  });
});

type Vector = { case_id: string; bundle: Record<string, unknown>; hash_only_receipt: Record<string, unknown> };
const dataset = JSON.parse(readFileSync(new URL("./fixtures/datasetV1SelectedVectors.json", import.meta.url), "utf8")) as { cases: Vector[] };
const ingest = JSON.parse(readFileSync(new URL("./fixtures/ingestV1SelectedVectors.json", import.meta.url), "utf8")) as { cases: Vector[] };
const material = JSON.parse(readFileSync(new URL("./fixtures/sourceV1Materials.json", import.meta.url), "utf8")) as {
  dataset: Record<string, Array<{ path_rel: string; content_base64: string }>>;
  ingest: Record<string, unknown>;
};
function fixture(cases: Vector[], id: string): Vector { const found = cases.find((entry) => entry.case_id === id);
  if (!found) throw new Error(`Missing ${id}`); return found; }

function explorer(respond: (url: URL, init?: RequestInit) => Response) {
  const requests: { url: URL; init?: RequestInit }[] = [];
  return { requests, config: { base_url: URL_EXPLORER, fetch_impl: vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    const parsed = new URL(String(url)); requests.push({ url: parsed, ...(init ? { init } : {}) }); return respond(parsed, init);
  }) as typeof fetch } };
}
function successfulDisclosure(kind: string, id: string, proof: Record<string, unknown>, payloadHash = HASH) {
  return { hedera_network: NETWORK,
    tx: { transaction_id: TX, message_id: `5@${TOPIC}` }, topic: { topic_id: TOPIC },
    verified: true, hash: { match: true },
    message_binding: { schema_version: "vera.hcs-message-binding.v1", algorithm: "sha3-512",
      message_sha3_512: payloadHash, message_bytes: PAYLOAD.length },
    payload: { schema: "va:explorer_publication_receipt:v1", event_type: "published", event_version: 1,
      entity_kind: kind, entity_id: id, visibility: "public", proof },
  };
}
function check(out: { report: { findings: readonly { check_id: string; outcome: string }[] } }, key: string) {
  return out.report.findings.find((entry) => entry.check_id === key)?.outcome;
}

describe("Phase 3C source-aware public triangulation", () => {
  it("recomputes Dataset source and matches public fingerprint, disclosed fingerprint and Mirror ciphertext", async () => {
    const entry = fixture(dataset.cases, "basic-v1");
    const key = (entry.bundle.dataset_identity as { dataset_key: string }).dataset_key;
    const fingerprint = (entry.hash_only_receipt.evidence as { dataset_fingerprint: string }).dataset_fingerprint;
    const exp = explorer((url) => url.pathname.startsWith("/v1/datasets/") ? json({
      hedera_network: NETWORK, dataset_key: key, dataset_id: DATASET, dataset_version_id: VERSION,
      dataset_fingerprint: fingerprint, publication_version_transaction_id: TX,
      publication_version_message_id: `5@${TOPIC}`, publication_version_topic_id: TOPIC,
      publication_version_sequence_number: 5,
    }) : json(successfulDisclosure("dataset_version", VERSION, { dataset_key: key, fingerprint })));
    const hd = mirror();
    const out = await triangulateDatasetV1({ explorer: exp.config, mirror: hd.config }, {
      bundle: entry.bundle,
      files: material.dataset[entry.case_id]!.map((file) => ({
        path_rel: file.path_rel, source: [Buffer.from(file.content_base64, "base64")],
      })), receipt: entry.hash_only_receipt,
      intent: { subject: { kind: "dataset", id: key, hedera_network: NETWORK }, expected: [] },
    });
    expect(out.consistency).toBe("consistent");
    expect(out.relationships.map((item) => item.status)).toEqual(["consistent", "consistent"]);
    expect(check(out, "triangulation.public_record_hedera.message_sha3_512")).toBe("pass");
    expect(check(out, "triangulation.provided_public_record.publication_fingerprint")).toBe("pass");
    expect(check(out, "triangulation.plaintext_ciphertext_binding")).toBe("indeterminate");
    expect(exp.requests.every((req) => req.init?.credentials === "omit")).toBe(true);
  });

  it("detects a provable ciphertext digest conflict without claiming independent plaintext recovery", async () => {
    const entry = fixture(dataset.cases, "basic-v1");
    const key = (entry.bundle.dataset_identity as { dataset_key: string }).dataset_key;
    const fingerprint = (entry.hash_only_receipt.evidence as { dataset_fingerprint: string }).dataset_fingerprint;
    const exp = explorer((url) => url.pathname.startsWith("/v1/datasets/") ? json({
      hedera_network: NETWORK, dataset_key: key, dataset_version_id: VERSION,
      dataset_fingerprint: fingerprint, publication_version_transaction_id: TX,
      publication_version_message_id: `5@${TOPIC}`, publication_version_topic_id: TOPIC,
      publication_version_sequence_number: 5,
    }) : json(successfulDisclosure("dataset_version", VERSION, { fingerprint }, "a".repeat(128))));
    const out = await triangulateDatasetV1({ explorer: exp.config, mirror: mirror().config }, {
      bundle: entry.bundle, files: material.dataset[entry.case_id]!.map((file) => ({
        path_rel: file.path_rel, source: [Buffer.from(file.content_base64, "base64")],
      })), receipt: entry.hash_only_receipt,
      intent: { subject: { kind: "dataset", id: key, hedera_network: NETWORK }, expected: [] },
    });
    expect(out.consistency).toBe("conflict");
    expect(check(out, "triangulation.public_record_hedera.message_sha3_512")).toBe("fail");
  });

  it("rejects a decrypted receipt with a different Dataset key even when fingerprint matches", async () => {
    const entry = fixture(dataset.cases, "basic-v1");
    const key = (entry.bundle.dataset_identity as { dataset_key: string }).dataset_key;
    const fingerprint = (entry.hash_only_receipt.evidence as { dataset_fingerprint: string }).dataset_fingerprint;
    const exp = explorer((url) => url.pathname.startsWith("/v1/datasets/") ? json({
      hedera_network: NETWORK, dataset_key: key, dataset_version_id: VERSION,
      dataset_fingerprint: fingerprint, publication_version_transaction_id: TX,
      publication_version_message_id: `5@${TOPIC}`, publication_version_topic_id: TOPIC,
      publication_version_sequence_number: 5,
    }) : json(successfulDisclosure("dataset_version", VERSION, {
      dataset_key: "unrelated.dataset", fingerprint,
    })));
    const out = await triangulateDatasetV1({ explorer: exp.config, mirror: mirror().config }, {
      bundle: entry.bundle, files: material.dataset[entry.case_id]!.map((file) => ({
        path_rel: file.path_rel, source: [Buffer.from(file.content_base64, "base64")],
      })), receipt: entry.hash_only_receipt,
      intent: { subject: { kind: "dataset", id: key, hedera_network: NETWORK }, expected: [] },
    });
    expect(out.consistency).toBe("conflict");
    expect(check(out, "triangulation.provided_public_record.publication_subject")).toBe("fail");
  });

  it("produces incomplete rather than a false success when Explorer disclosure is unavailable", async () => {
    const entry = fixture(dataset.cases, "basic-v1");
    const key = (entry.bundle.dataset_identity as { dataset_key: string }).dataset_key;
    const fingerprint = (entry.hash_only_receipt.evidence as { dataset_fingerprint: string }).dataset_fingerprint;
    const exp = explorer((url) => url.pathname.startsWith("/v1/datasets/") ? json({
      hedera_network: NETWORK, dataset_key: key, dataset_version_id: VERSION,
      dataset_fingerprint: fingerprint, publication_version_transaction_id: TX,
      publication_version_message_id: `5@${TOPIC}`, publication_version_topic_id: TOPIC,
      publication_version_sequence_number: 5,
    }) : json({ error: "not_found" }, 404));
    const out = await triangulateDatasetV1({ explorer: exp.config, mirror: mirror().config }, {
      bundle: entry.bundle, files: material.dataset[entry.case_id]!.map((file) => ({
        path_rel: file.path_rel, source: [Buffer.from(file.content_base64, "base64")],
      })), receipt: entry.hash_only_receipt,
      intent: { subject: { kind: "dataset", id: key, hedera_network: NETWORK }, expected: [] },
    });
    expect(out.consistency).toBe("incomplete");
    expect(check(out, "triangulation.public_record_hedera.message_sha3_512")).toBe("indeterminate");
  });

  it("binds independently verified Ingest fingerprint and bundle digest to public and disclosed evidence", async () => {
    const entry = fixture(ingest.cases, "json-v1");
    const key = (entry.bundle.identity as { object_key: string }).object_key;
    const evidence = entry.hash_only_receipt.evidence as { fingerprint: string; bundle_digest: string };
    const exp = explorer((url) => url.pathname.startsWith("/v1/merkle/anchors/") ? json({
      hedera_network: NETWORK, anchor_request_id: ANCHOR, ingest_object_key: key,
      ingest_fingerprint: evidence.fingerprint, ingest_bundle_digest: evidence.bundle_digest,
      publication_anchor_transaction_id: TX, publication_anchor_message_id: `5@${TOPIC}`,
      publication_anchor_topic_id: TOPIC, publication_anchor_sequence_number: 5,
    }) : json(successfulDisclosure("merkle_anchor", ANCHOR, {
      ingest_object_key: key, ingest_fingerprint: evidence.fingerprint,
      ingest_bundle_digest: evidence.bundle_digest,
    })));
    const out = await triangulateIngestV1({ explorer: exp.config, mirror: mirror().config }, {
      bundle: entry.bundle, material: material.ingest[entry.case_id] as { kind: "json"; value: unknown },
      receipt: entry.hash_only_receipt, anchor_request_id: ANCHOR,
      intent: { subject: { kind: "ingest", id: key, hedera_network: NETWORK }, expected: [] },
    });
    expect(out.consistency).toBe("consistent");
    expect(check(out, "triangulation.provided_public_record.publication_bundle_digest")).toBe("pass");
    expect(check(out, "triangulation.public_record_hedera.message_sha3_512")).toBe("pass");
  });
});

describe("source-byte to public policy conformance", () => {
  it("recomputes a dataset and makes a reproducible policy decision over Explorer and Mirror evidence", async () => {
    const entry = fixture(dataset.cases, "basic-v1");
    const key = (entry.bundle.dataset_identity as { dataset_key: string }).dataset_key;
    const fingerprint = (entry.hash_only_receipt.evidence as { dataset_fingerprint: string }).dataset_fingerprint;
    const policy: VerificationPolicyV1 = { schema_version: VERIFICATION_POLICY_SCHEMA_VERSION,
      subject: { kind: "dataset", id: key, hedera_network: NETWORK }, report_kind: "public_triangulation",
      required_checks: ["dataset.source_binding", "dataset.bundle_consistency"],
      required_assurance: ["mirror_corroboration"] };
    const run = () => {
      const exp = explorer((url) => url.pathname.startsWith("/v1/datasets/") ? json({
        hedera_network: NETWORK, dataset_key: key, dataset_id: DATASET, dataset_version_id: VERSION,
        dataset_fingerprint: fingerprint, publication_version_transaction_id: TX,
        publication_version_message_id: `5@${TOPIC}`, publication_version_topic_id: TOPIC,
        publication_version_sequence_number: 5,
      }) : json(successfulDisclosure("dataset_version", VERSION, { dataset_key: key, fingerprint })));
      return triangulateDatasetWithPolicyV1({ explorer: exp.config, mirror: mirror().config }, {
        bundle: entry.bundle, files: material.dataset[entry.case_id]!.map((file) => ({
          path_rel: file.path_rel, source: [Buffer.from(file.content_base64, "base64")],
        })), receipt: entry.hash_only_receipt,
        intent: { subject: policy.subject, expected: [] },
      }, policy);
    };
    const first = await run();
    const second = await run();
    expect(first.policy).toEqual(second.policy);
    expect(first.report.report_sha3_512).toBe(second.report.report_sha3_512);
    expect(validatePortableVerificationReportV1(first.report).status).toBe("valid");
    expect(first.policy.requirements.find((r) => r.key === "verification.public_evidence")?.outcome).toBe("pass");
    expect(first.policy.requirements.find((r) => r.key === "assurance.mirror_corroboration")?.outcome).toBe("pass");
    expect(first.policy.decision).toBe("allow");
    expect(first.report.context).not.toHaveProperty("publication_payload_binding");
    expect(assessPortableVerificationPolicyV1(first.report, policy).decision).toBe("review");
  });

  it("never authorizes a dataset when Explorer disclosure is missing, even if local files verify", async () => {
    const entry = fixture(dataset.cases, "basic-v1");
    const key = (entry.bundle.dataset_identity as { dataset_key: string }).dataset_key;
    const fingerprint = (entry.hash_only_receipt.evidence as { dataset_fingerprint: string }).dataset_fingerprint;
    const exp = explorer((url) => url.pathname.startsWith("/v1/datasets/") ? json({
      hedera_network: NETWORK, dataset_key: key, dataset_version_id: VERSION,
      dataset_fingerprint: fingerprint, publication_version_transaction_id: TX,
      publication_version_message_id: `5@${TOPIC}`, publication_version_topic_id: TOPIC,
      publication_version_sequence_number: 5,
    }) : json({ error: "not_found" }, 404));
    const policy: VerificationPolicyV1 = { schema_version: VERIFICATION_POLICY_SCHEMA_VERSION,
      subject: { kind: "dataset", id: key, hedera_network: NETWORK }, report_kind: "public_triangulation",
      required_checks: ["dataset.source_binding"] };
    const output = await triangulateDatasetWithPolicyV1({ explorer: exp.config, mirror: mirror().config }, {
      bundle: entry.bundle, files: material.dataset[entry.case_id]!.map((file) => ({
        path_rel: file.path_rel, source: [Buffer.from(file.content_base64, "base64")],
      })), receipt: entry.hash_only_receipt,
      intent: { subject: policy.subject, expected: [] },
    }, policy);
    expect(output.policy.decision).not.toBe("allow");
    expect(output.policy.reason_codes).toContain("POLICY_PUBLIC_EVIDENCE_INCOMPLETE");
  });

  it("binds ingest policy to its independent source and Core anchor identities", async () => {
    const entry = fixture(ingest.cases, "json-v1");
    const key = (entry.bundle.identity as { object_key: string }).object_key;
    const evidence = entry.hash_only_receipt.evidence as { fingerprint: string; bundle_digest: string };
    const exp = explorer((url) => url.pathname.startsWith("/v1/merkle/anchors/") ? json({
      hedera_network: NETWORK, anchor_request_id: ANCHOR, ingest_object_key: key,
      ingest_fingerprint: evidence.fingerprint, ingest_bundle_digest: evidence.bundle_digest,
      publication_anchor_transaction_id: TX, publication_anchor_message_id: `5@${TOPIC}`,
      publication_anchor_topic_id: TOPIC, publication_anchor_sequence_number: 5,
    }) : json(successfulDisclosure("merkle_anchor", ANCHOR, { ingest_object_key: key,
      ingest_fingerprint: evidence.fingerprint, ingest_bundle_digest: evidence.bundle_digest })));
    const policy: VerificationPolicyV1 = { schema_version: VERIFICATION_POLICY_SCHEMA_VERSION,
      subject: { kind: "ingest", id: key, hedera_network: NETWORK }, report_kind: "public_triangulation",
      required_checks: ["ingest.source_binding", "ingest.bundle_consistency"],
      required_assurance: ["mirror_corroboration"] };
    const input = { bundle: entry.bundle, material: material.ingest[entry.case_id] as { kind: "json"; value: unknown },
      receipt: entry.hash_only_receipt, anchor_request_id: ANCHOR,
      intent: { subject: policy.subject, expected: [] } };
    const output = await triangulateIngestWithPolicyV1({ explorer: exp.config, mirror: mirror().config }, input, policy);
    expect(validatePortableVerificationReportV1(output.report).status).toBe("valid");
    expect(output.policy.decision).toBe("allow");
    expect(output.report.core.intent.subject.id).toBe(key);
    expect(output.report.context).not.toHaveProperty("publication_payload_binding");
    await expect(triangulateIngestWithPolicyV1({ explorer: exp.config, mirror: mirror().config }, input,
      { ...policy, subject: { ...policy.subject, id: "unrelated" } })).rejects.toThrow(/policy intent/);
  });
});