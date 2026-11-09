import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { VerificationObservation, VerificationReport } from "../../src/contracts/verification.js";
import { sha3_512Hex } from "../../src/crypto/sha3.js";
import { observeCoreMessageBindingV1, observeMirrorMessageV1 } from "../../src/triangulation/messageObservationV1.js";
import {
  compareEvidenceTriangulationV1,
  type TriangulationRelationshipPlanV1,
} from "../../src/triangulation/compareV1.js";
import { verifyDatasetV1WithIntent, verifyIngestV1WithIntent } from "../../src/verification/sourceIntentV1.js";

type Vector = Readonly<{
  case_id: string;
  bundle: Record<string, unknown>;
  hash_only_receipt: Record<string, unknown>;
}>;
const dataset = JSON.parse(readFileSync(new URL("./fixtures/datasetV1SelectedVectors.json", import.meta.url), "utf8")) as { cases: Vector[] };
const ingest = JSON.parse(readFileSync(new URL("./fixtures/ingestV1SelectedVectors.json", import.meta.url), "utf8")) as { cases: Vector[] };
const material = JSON.parse(readFileSync(new URL("./fixtures/sourceV1Materials.json", import.meta.url), "utf8")) as {
  dataset: Record<string, readonly { path_rel: string; content_base64: string }[]>;
  ingest: Record<string, { kind: "json"; value: unknown }>;
};

function vector(cases: Vector[], id: string): Vector {
  const item = cases.find((entry) => entry.case_id === id);
  if (!item) throw new Error("Missing source conformance vector");
  return item;
}

async function datasetReport(network: "mainnet" | "testnet" = "testnet"): Promise<VerificationReport> {
  const entry = vector(dataset.cases, "basic-v1");
  const key = (entry.bundle.dataset_identity as { dataset_key: string }).dataset_key;
  const sources = material.dataset[entry.case_id];
  if (!sources) throw new Error("Missing source materials");
  return verifyDatasetV1WithIntent({
    bundle: entry.bundle,
    files: sources.map((file) => ({ path_rel: file.path_rel, source: [Buffer.from(file.content_base64, "base64")] })),
    receipt: entry.hash_only_receipt,
    intent: { subject: { kind: "dataset", id: key, hedera_network: network }, expected: [] },
  });
}

async function ingestReport(): Promise<VerificationReport> {
  const entry = vector(ingest.cases, "json-v1");
  const key = (entry.bundle.identity as { object_key: string }).object_key;
  return verifyIngestV1WithIntent({
    bundle: entry.bundle,
    material: material.ingest[entry.case_id]!,
    receipt: entry.hash_only_receipt,
    intent: { subject: { kind: "ingest", id: key, hedera_network: "testnet" }, expected: [] },
  });
}

function available(key: string, value: string | number | boolean) {
  return { key, state: "available" as const, value };
}

function publicRecord(report: VerificationReport, facts: VerificationObservation["facts"]): VerificationObservation {
  return {
    id: "explorer.public",
    subject: { ...report.intent.subject },
    source: "public_record",
    resolver_id: "explorer.public-dataset-record.v1",
    facts,
  };
}

function sourcePlan(key: string, left_key: string, right_key: string): TriangulationRelationshipPlanV1 {
  return {
    id: "provided_public_record",
    left_observation_id: "dataset.bundle",
    right_observation_id: "explorer.public",
    comparisons: [{ key, left_key, right_key }],
  };
}

function messagePlan(): TriangulationRelationshipPlanV1 {
  return {
    id: "public_record_hedera",
    left_observation_id: "explorer.public",
    right_observation_id: "mirror.message",
    comparisons: [
      { key: "publication_digest", left_key: "publication.message_sha3_512", right_key: "publication.message_sha3_512" },
      { key: "topic_id", left_key: "hedera.topic_id", right_key: "hedera.topic_id" },
      { key: "sequence_number", left_key: "hedera.sequence_number", right_key: "hedera.sequence_number" },
    ],
  };
}

function mirror(report: VerificationReport, bytes: Uint8Array) {
  return observeMirrorMessageV1({
    id: "mirror.message",
    subject: report.intent.subject,
    topic_id: "0.0.12345",
    sequence_number: 7,
    message_bytes: bytes,
  });
}

describe("Phase 3A: pure source-aware triangulation comparison", () => {
  it("matches Dataset source fingerprint and separately recomputed HCS message bytes", async () => {
    const report = await datasetReport();
    const bytes = Buffer.from("encrypted HCS envelope bytes");
    const fingerprint = report.observations.find((entry) => entry.id === "dataset.bundle")?.facts
      .find((entry) => entry.key === "dataset_fingerprint");
    if (!fingerprint || fingerprint.state !== "available") throw new Error("Missing computed fingerprint");
    const publicObservation = publicRecord(report, [
      available("dataset.fingerprint", String(fingerprint.value)),
      available("publication.message_sha3_512", sha3_512Hex(bytes)),
      available("hedera.topic_id", "0.0.12345"),
      available("hedera.sequence_number", 7),
    ]);
    const result = compareEvidenceTriangulationV1({
      source_report: report,
      observations: [publicObservation, mirror(report, bytes)],
      relationships: [sourcePlan("fingerprint", "dataset_fingerprint", "dataset.fingerprint"), messagePlan()],
    });
    expect(result.consistency).toBe("consistent");
    expect(result.relationships.map((entry) => entry.status)).toEqual(["consistent", "consistent"]);
    expect(result.report.findings.find((entry) => entry.check_id === "triangulation.public_record_hedera.publication_digest")?.outcome).toBe("pass");
    expect(result.report.findings.some((entry) => entry.check_id.includes("ledger_authentication"))).toBe(false);
    expect(result.report.observations.map((entry) => entry.source).slice(-2)).toEqual(["public_record", "hedera_mirror"]);
  });

  it("fails a mismatched fingerprint even when independent message bytes match", async () => {
    const report = await datasetReport();
    const result = compareEvidenceTriangulationV1({
      source_report: report,
      observations: [publicRecord(report, [available("dataset.fingerprint", "0".repeat(128))])],
      relationships: [sourcePlan("fingerprint", "dataset_fingerprint", "dataset.fingerprint")],
    });
    expect(result.consistency).toBe("conflict");
    expect(result.relationships[0]?.fact_comparisons[0]?.reason_code).toBe("FACT_MISMATCH");
  });

  it("reports missing observations as incomplete without pretending to observe Hedera", async () => {
    const report = await datasetReport();
    const result = compareEvidenceTriangulationV1({
      source_report: report, observations: [], relationships: [messagePlan()],
    });
    expect(result.consistency).toBe("incomplete");
    expect(result.report.findings.at(-1)?.reason_code).toBe("OBSERVATION_UNAVAILABLE");
  });

  it("rejects a mismatched mainnet/testnet observation regardless of matching fact values", async () => {
    const report = await datasetReport("testnet");
    const result = compareEvidenceTriangulationV1({
      source_report: report,
      observations: [{ ...publicRecord(report, [available("dataset.fingerprint", "a".repeat(128))]),
        subject: { ...report.intent.subject, hedera_network: "mainnet" } }],
      relationships: [sourcePlan("fingerprint", "dataset_fingerprint", "dataset.fingerprint")],
    });
    expect(result.consistency).toBe("conflict");
    expect(result.report.findings.at(-1)?.reason_code).toBe("OBSERVATION_NETWORK_MISMATCH");
  });

  it("returns an explicit conflict for an unrelated public subject", async () => {
    const report = await datasetReport();
    const foreign = publicRecord(report, [available("dataset.fingerprint", "a".repeat(128))]);
    const result = compareEvidenceTriangulationV1({
      source_report: report,
      observations: [{ ...foreign, subject: { ...foreign.subject, id: "different-dataset" } }],
      relationships: [sourcePlan("fingerprint", "dataset_fingerprint", "dataset.fingerprint")],
    });
    expect(result.consistency).toBe("conflict");
    expect(result.report.findings.at(-1)?.reason_code).toBe("OBSERVATION_SUBJECT_MISMATCH");
  });

  it("does not consider missing network intent a cross-source match", async () => {
    const report = await datasetReport();
    const bare: VerificationReport = { ...report, intent: { ...report.intent, subject: { kind: report.intent.subject.kind, id: report.intent.subject.id } } };
    const result = compareEvidenceTriangulationV1({
      source_report: bare,
      observations: [publicRecord(bare, [available("dataset.fingerprint", "a".repeat(128))])],
      relationships: [sourcePlan("fingerprint", "dataset_fingerprint", "dataset.fingerprint")],
    });
    expect(result.consistency).toBe("incomplete");
    expect(result.report.findings.at(-1)?.reason_code).toBe("NETWORK_SCOPE_UNAVAILABLE");
  });

  it("does not silently match unavailable or not-applicable facts", async () => {
    const report = await datasetReport();
    const base = publicRecord(report, [{ key: "dataset.fingerprint", state: "unavailable", reason_code: "RECORD_UNAVAILABLE" }]);
    const result = compareEvidenceTriangulationV1({
      source_report: report, observations: [base],
      relationships: [sourcePlan("fingerprint", "dataset_fingerprint", "dataset.fingerprint")],
    });
    expect(result.consistency).toBe("incomplete");
    expect(result.report.findings.at(-1)?.reason_code).toBe("RECORD_UNAVAILABLE");
    const skipped = compareEvidenceTriangulationV1({
      source_report: report,
      observations: [{ ...base, facts: [{ key: "dataset.fingerprint", state: "not_applicable" }] }],
      relationships: [sourcePlan("fingerprint", "dataset_fingerprint", "dataset.fingerprint")],
    });
    expect(skipped.relationships[0]?.status).toBe("not_applicable");
    expect(skipped.consistency).toBe("incomplete");
  });

  it("prevents external observations from impersonating local recomputation", async () => {
    const report = await datasetReport();
    expect(() => compareEvidenceTriangulationV1({
      source_report: report,
      observations: [{ ...publicRecord(report, []), source: "local_computation" }],
      relationships: [],
    })).toThrow("External observations cannot assert local computation");
  });

  it("rejects duplicate evidence IDs and duplicate fact keys", async () => {
    const report = await datasetReport();
    const publicObservation = publicRecord(report, []);
    expect(() => compareEvidenceTriangulationV1({
      source_report: report, observations: [publicObservation, publicObservation], relationships: [],
    })).toThrow("Duplicate triangulation observation");
    expect(() => compareEvidenceTriangulationV1({
      source_report: report,
      observations: [{ ...publicObservation, facts: [available("x", 1), available("x", 2)] }],
      relationships: [],
    })).toThrow("Duplicate observation fact");
  });

  it("rejects source-role substitution instead of counting one public service twice", async () => {
    const report = await datasetReport();
    expect(() => compareEvidenceTriangulationV1({
      source_report: report,
      observations: [publicRecord(report, [])],
      relationships: [{ ...messagePlan(), right_observation_id: "dataset.bundle" }],
    })).toThrow("sources do not match");
  });

  it("rejects a missing/empty plan as complete verification", async () => {
    const report = await datasetReport();
    const result = compareEvidenceTriangulationV1({ source_report: report, observations: [], relationships: [] });
    expect(result.consistency).toBe("incomplete");
    expect(result.report.findings).toEqual(report.findings);
  });

  it("marks a false source integrity finding as conflict even if a comparison matches", async () => {
    const report = await datasetReport();
    const flawed: VerificationReport = {
      ...report,
      findings: report.findings.map((entry) => entry.check_id === "dataset.source_binding"
        ? { ...entry, outcome: "fail", reason_code: "SOURCE_MISMATCH" } : entry),
    };
    const fingerprint = report.observations.find((entry) => entry.id === "dataset.bundle")?.facts
      .find((entry) => entry.key === "dataset_fingerprint");
    if (!fingerprint || fingerprint.state !== "available") throw new Error("Missing source fingerprint");
    const result = compareEvidenceTriangulationV1({
      source_report: flawed,
      observations: [publicRecord(flawed, [available("dataset.fingerprint", String(fingerprint.value))])],
      relationships: [sourcePlan("fingerprint", "dataset_fingerprint", "dataset.fingerprint")],
    });
    expect(result.consistency).toBe("conflict");
    expect(result.relationships[0]?.status).toBe("consistent");
  });

  it("accepts asymmetric Ingest fingerprint/bundle mappings without equating different contracts", async () => {
    const report = await ingestReport();
    const bundle = report.observations.find((entry) => entry.id === "ingest.bundle");
    const fingerprint = bundle?.facts.find((entry) => entry.key === "fingerprint");
    const digest = bundle?.facts.find((entry) => entry.key === "bundle_digest");
    if (fingerprint?.state !== "available" || digest?.state !== "available") throw new Error("Missing Ingest commitments");
    const result = compareEvidenceTriangulationV1({
      source_report: report,
      observations: [publicRecord(report, [
        available("ingest.fingerprint", String(fingerprint.value)),
        available("ingest.bundle_digest", String(digest.value)),
      ])],
      relationships: [{
        id: "provided_public_record", left_observation_id: "ingest.bundle", right_observation_id: "explorer.public",
        comparisons: [
          { key: "ingest_fingerprint", left_key: "fingerprint", right_key: "ingest.fingerprint" },
          { key: "ingest_bundle_digest", left_key: "bundle_digest", right_key: "ingest.bundle_digest" },
        ],
      }],
    });
    expect(result.consistency).toBe("consistent");
  });
});

describe("Phase 3A: bounded exact Mirror-byte observation", () => {
  it("recomputes SHA3-512 rather than accepting a claimed digest", async () => {
    const report = await datasetReport();
    const bytes = Buffer.from("ciphertext, not plaintext", "utf8");
    const observed = mirror(report, bytes);
    expect(observed.facts.find((entry) => entry.key === "publication.message_sha3_512")).toEqual(
      { key: "publication.message_sha3_512", state: "available", value: sha3_512Hex(bytes) },
    );
    const other = mirror(report, Buffer.from("ciphertext tampered", "utf8"));
    expect(other.facts.find((entry) => entry.key === "publication.message_sha3_512")).not.toEqual(
      observed.facts.find((entry) => entry.key === "publication.message_sha3_512"),
    );
  });

  it("compares exact Core ciphertext digest and byte length with locally recomputed Mirror bytes", async () => {
    const report = await datasetReport();
    const bytes = Buffer.from("encrypted publication bytes");
    const core = observeCoreMessageBindingV1({
      id: "explorer.core",
      subject: report.intent.subject,
      binding: { schema_version: "vera.hcs-message-binding.v1", algorithm: "sha3-512",
        message_sha3_512: sha3_512Hex(bytes), message_bytes: bytes.length },
    });
    const relationship: TriangulationRelationshipPlanV1 = {
      id: "public_record_hedera",
      left_observation_id: "explorer.core",
      right_observation_id: "mirror.message",
      comparisons: [
        { key: "ciphertext_digest", left_key: "publication.message_sha3_512", right_key: "publication.message_sha3_512" },
        { key: "ciphertext_length", left_key: "publication.message_bytes", right_key: "publication.message_bytes" },
      ],
    };
    const matching = compareEvidenceTriangulationV1({
      source_report: report, observations: [core, mirror(report, bytes)], relationships: [relationship],
    });
    expect(matching.consistency).toBe("consistent");
    const tampered = compareEvidenceTriangulationV1({
      source_report: report, observations: [core, mirror(report, Buffer.from("tampered"))],
      relationships: [relationship],
    });
    expect(tampered.consistency).toBe("conflict");
    expect(tampered.report.findings.some((item) => item.check_id.includes("plaintext"))).toBe(false);
  });

  it("does not treat missing or unsupported Core message bindings as successful checks", async () => {
    const report = await datasetReport();
    const missing = observeCoreMessageBindingV1({ id: "explorer.core", subject: report.intent.subject, binding: null });
    const unsupported = observeCoreMessageBindingV1({ id: "explorer.core", subject: report.intent.subject,
      binding: { schema_version: "unknown", algorithm: "sha3-512", message_sha3_512: "a".repeat(128), message_bytes: 2 } });
    for (const core of [missing, unsupported]) {
      const result = compareEvidenceTriangulationV1({
        source_report: report,
        observations: [core, mirror(report, Buffer.from("abc"))],
        relationships: [{ id: "public_record_hedera", left_observation_id: "explorer.core",
          right_observation_id: "mirror.message", comparisons: [
            { key: "ciphertext_digest", left_key: "publication.message_sha3_512", right_key: "publication.message_sha3_512" },
          ] }],
      });
      expect(result.consistency).toBe("incomplete");
      expect(result.report.findings.at(-1)?.outcome).toBe("indeterminate");
    }
  });

  it("enforces message byte and locator bounds", async () => {
    const report = await datasetReport();
    expect(() => observeMirrorMessageV1({ id: "bad", subject: report.intent.subject, topic_id: "0.0.1", sequence_number: 1,
      message_bytes: new Uint8Array(1024 * 1024 + 1) })).toThrow(TypeError);
    expect(() => observeMirrorMessageV1({ id: "bad", subject: report.intent.subject, topic_id: "0.0.1", sequence_number: 0,
      message_bytes: new Uint8Array(0) })).toThrow(TypeError);
  });
});
