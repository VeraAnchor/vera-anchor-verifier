import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { VerificationIntent, VerificationReport } from "../../src/contracts/verification.js";
import { verifyDatasetV1WithIntent, verifyIngestV1WithIntent } from "../../src/verification/sourceIntentV1.js";

type FixtureCase = Readonly<{
  case_id: string;
  bundle: Record<string, unknown>;
  hash_only_receipt: Record<string, unknown>;
  anchored_receipts?: readonly Record<string, unknown>[];
}>;
type SourceFile = Readonly<{ path_rel: string; content_base64: string }>;
const datasetFixtures = JSON.parse(readFileSync(new URL("./fixtures/datasetV1SelectedVectors.json", import.meta.url), "utf8")) as { cases: FixtureCase[] };
const ingestFixtures = JSON.parse(readFileSync(new URL("./fixtures/ingestV1SelectedVectors.json", import.meta.url), "utf8")) as { cases: FixtureCase[] };
const materials = JSON.parse(readFileSync(new URL("./fixtures/sourceV1Materials.json", import.meta.url), "utf8")) as {
  dataset: Record<string, SourceFile[]>;
  ingest: Record<string, unknown>;
};

type IngestMaterial =
  | Readonly<{ kind: "json"; value: unknown }>
  | Readonly<{ kind: "text"; text: string; media_type?: string }>
  | Readonly<{ kind: "file"; file: SourceFile }>
  | Readonly<{ kind: "file_set"; files: SourceFile[] }>;
function fixture(cases: readonly FixtureCase[], id: string): FixtureCase {
  const entry = cases.find((item) => item.case_id === id);
  if (!entry) throw new Error(`Missing fixture ${id}`);
  return entry;
}
function files(id: string) {
  const list = materials.dataset[id];
  if (!list) throw new Error(`Missing Dataset material ${id}`);
  return list.map(({ path_rel, content_base64 }) => ({ path_rel, source: [Buffer.from(content_base64, "base64")] }));
}
function material(id: string) {
  const input = materials.ingest[id] as IngestMaterial;
  if (input.kind === "json" || input.kind === "text") return input;
  if (input.kind === "file") return { kind: "file" as const, file: { path_rel: input.file.path_rel, source: [Buffer.from(input.file.content_base64, "base64")] } };
  return { kind: "file_set" as const, files: input.files.map(({ path_rel, content_base64 }) => ({ path_rel, source: [Buffer.from(content_base64, "base64")] })) };
}
function outcome(report: VerificationReport, id: string): string {
  const check = report.findings.find((entry) => entry.check_id === id);
  if (!check) throw new Error(`Missing finding ${id}`);
  return check.outcome;
}
function datasetIntent(id: string, network?: "mainnet" | "testnet"): VerificationIntent {
  return { subject: { kind: "dataset", id, ...(network ? { hedera_network: network } : {}) }, expected: [] };
}
function ingestIntent(id: string, network?: "mainnet" | "testnet"): VerificationIntent {
  return { subject: { kind: "ingest", id, ...(network ? { hedera_network: network } : {}) }, expected: [] };
}

describe("Dataset v1 intent and normalized findings", () => {
  for (const entry of datasetFixtures.cases) {
    it(`${entry.case_id}: reports verified source, bundle and receipt with explicit intent`, async () => {
      const datasetKey = (entry.bundle.dataset_identity as { dataset_key: string }).dataset_key;
      const result = await verifyDatasetV1WithIntent({
        bundle: entry.bundle, files: files(entry.case_id), receipt: entry.hash_only_receipt,
        intent: datasetIntent(datasetKey),
      });
      expect(outcome(result, "dataset.source_binding")).toBe("pass");
      expect(outcome(result, "dataset.bundle_consistency")).toBe("pass");
      expect(outcome(result, "dataset.receipt_binding")).toBe("pass");
      expect(outcome(result, "intent.subject")).toBe("pass");
      expect(result.observations.map((entry) => entry.source)).toEqual(["local_computation", "local_computation", "provided_evidence"]);
    });
  }

  it("rejects a valid but unrelated dataset identifier", async () => {
    const entry = fixture(datasetFixtures.cases, "basic-v1");
    const result = await verifyDatasetV1WithIntent({
      bundle: entry.bundle, files: files(entry.case_id), receipt: entry.hash_only_receipt,
      intent: datasetIntent("another-dataset"),
    });
    expect(outcome(result, "dataset.source_binding")).toBe("pass");
    expect(outcome(result, "intent.subject")).toBe("fail");
  });

  it("matches an independently expected Dataset fingerprint and source Merkle root", async () => {
    const entry = fixture(datasetFixtures.cases, "basic-v1");
    const evidence = entry.bundle as unknown as { dataset_identity: { dataset_key: string }; files: unknown[]; merkle: { root: string } };
    const expectedFingerprint = (entry.hash_only_receipt.evidence as { dataset_fingerprint: string }).dataset_fingerprint;
    const result = await verifyDatasetV1WithIntent({
      bundle: entry.bundle, files: files(entry.case_id), receipt: entry.hash_only_receipt,
      intent: {
        subject: { kind: "dataset", id: evidence.dataset_identity.dataset_key },
        expected: [
          { kind: "digest", key: "dataset_fingerprint", contract: "hf-contract-v1", material: "json", domain: "va:dataset:fingerprint:v1", digest: expectedFingerprint },
          { kind: "merkle-root", key: "merkle_root", tree_alg: "hf-dataset-v1", root_hash: evidence.merkle.root, leaf_count: evidence.files.length },
        ],
      },
    });
    expect(outcome(result, "intent.commitment.dataset_fingerprint")).toBe("pass");
    expect(outcome(result, "intent.commitment.merkle_root")).toBe("pass");
    expect(result.findings.some((finding) => finding.check_id === "intent.declared_network")).toBe(false);
  });

  it("fails independently expected digest and leaf count mismatches", async () => {
    const entry = fixture(datasetFixtures.cases, "basic-v1");
    const id = (entry.bundle.dataset_identity as { dataset_key: string }).dataset_key;
    const root = (entry.bundle.merkle as { root: string }).root;
    const result = await verifyDatasetV1WithIntent({
      bundle: entry.bundle, files: files(entry.case_id),
      intent: { subject: { kind: "dataset", id }, expected: [
        { kind: "digest", key: "bundle_digest", contract: "hf-contract-v1", material: "json", domain: "va:dataset:bundle:v1", digest: "0".repeat(128) },
        { kind: "merkle-root", key: "merkle_root", tree_alg: "hf-dataset-v1", root_hash: root, leaf_count: 999 },
      ] },
    });
    expect(outcome(result, "intent.commitment.bundle_digest")).toBe("fail");
    expect(outcome(result, "intent.commitment.merkle_root")).toBe("fail");
    expect(outcome(result, "dataset.receipt_binding")).toBe("indeterminate");
  });

  it("never passes a Core tree algorithm as an HF Dataset Merkle commitment", async () => {
    const entry = fixture(datasetFixtures.cases, "basic-v1");
    const id = (entry.bundle.dataset_identity as { dataset_key: string }).dataset_key;
    const result = await verifyDatasetV1WithIntent({
      bundle: entry.bundle, files: files(entry.case_id),
      intent: { subject: { kind: "dataset", id }, expected: [
        { kind: "merkle-root", key: "merkle_root", tree_alg: "binary-sorted", root_hash: (entry.bundle.merkle as { root: string }).root, leaf_count: 1 },
      ] },
    });
    expect(outcome(result, "intent.commitment.merkle_root")).toBe("unsupported");
  });

  it("does not pass expected commitments or subject binding when source bytes are corrupted", async () => {
    const entry = fixture(datasetFixtures.cases, "basic-v1");
    const id = (entry.bundle.dataset_identity as { dataset_key: string }).dataset_key;
    const result = await verifyDatasetV1WithIntent({
      bundle: entry.bundle, files: [{ path_rel: "hello.txt", source: [Buffer.from("corrupted")] }],
      intent: { subject: { kind: "dataset", id }, expected: [
        { kind: "digest", key: "bundle_digest", contract: "hf-contract-v1", material: "json", domain: "va:dataset:bundle:v1", digest: (entry.hash_only_receipt.evidence as { bundle_digest: string }).bundle_digest },
      ] },
    });
    expect(outcome(result, "dataset.source_binding")).toBe("fail");
    expect(outcome(result, "intent.subject")).toBe("indeterminate");
    expect(outcome(result, "intent.commitment.bundle_digest")).toBe("indeterminate");
  });

  it("treats missing declared network as indeterminate, not a mismatch or ledger proof", async () => {
    const entry = fixture(datasetFixtures.cases, "basic-v1");
    const id = (entry.bundle.dataset_identity as { dataset_key: string }).dataset_key;
    const result = await verifyDatasetV1WithIntent({
      bundle: entry.bundle, files: files(entry.case_id), receipt: entry.hash_only_receipt,
      intent: datasetIntent(id, "mainnet"),
    });
    expect(outcome(result, "intent.declared_network")).toBe("indeterminate");
  });

  it("distinguishes matching from contradictory declared networks", async () => {
    const entry = fixture(datasetFixtures.cases, "basic-v1");
    const id = (entry.bundle.dataset_identity as { dataset_key: string }).dataset_key;
    const receipt = entry.anchored_receipts?.find((candidate) => candidate.hedera_network === "testnet");
    if (!receipt) throw new Error("Missing networked Dataset receipt fixture");
    const correct = await verifyDatasetV1WithIntent({ bundle: entry.bundle, files: files(entry.case_id), receipt, intent: datasetIntent(id, "testnet") });
    expect(outcome(correct, "intent.declared_network")).toBe("pass");
    const wrong = await verifyDatasetV1WithIntent({ bundle: entry.bundle, files: files(entry.case_id), receipt, intent: datasetIntent(id, "mainnet") });
    expect(outcome(wrong, "intent.declared_network")).toBe("fail");
  });

  it("rejects duplicate commitment requirements", async () => {
    const entry = fixture(datasetFixtures.cases, "basic-v1");
    const id = (entry.bundle.dataset_identity as { dataset_key: string }).dataset_key;
    const requirement = { kind: "digest" as const, key: "bundle_digest", contract: "hf-contract-v1" as const, material: "json" as const, domain: "va:dataset:bundle:v1", digest: "0".repeat(128) };
    await expect(verifyDatasetV1WithIntent({ bundle: entry.bundle, files: files(entry.case_id), intent: { subject: { kind: "dataset", id }, expected: [requirement, requirement] } })).rejects.toThrow(TypeError);
  });
});

describe("Ingest v1 intent and normalized findings", () => {
  for (const entry of ingestFixtures.cases) {
    it(`${entry.case_id}: produces deterministic offline report findings`, async () => {
      const key = (entry.bundle.identity as { object_key: string }).object_key;
      const make = () => verifyIngestV1WithIntent({
        bundle: entry.bundle, material: material(entry.case_id), receipt: entry.hash_only_receipt,
        intent: ingestIntent(key),
      });
      const first = await make();
      const second = await make();
      expect(first).toEqual(second);
      expect(outcome(first, "ingest.source_binding")).toBe("pass");
      expect(outcome(first, "ingest.bundle_consistency")).toBe("pass");
      expect(outcome(first, "ingest.receipt_binding")).toBe("pass");
      expect(outcome(first, "intent.subject")).toBe("pass");
    });
  }

  it("fails wrong Ingest subject even when all commitments are valid", async () => {
    const entry = fixture(ingestFixtures.cases, "json-v1");
    const result = await verifyIngestV1WithIntent({
      bundle: entry.bundle, material: material(entry.case_id), receipt: entry.hash_only_receipt,
      intent: ingestIntent("unrelated.ingest.object"),
    });
    expect(outcome(result, "intent.subject")).toBe("fail");
  });

  it("enforces Ingest framed fingerprint and dedicated Merkle algorithm", async () => {
    const entry = fixture(ingestFixtures.cases, "json-v1");
    const key = (entry.bundle.identity as { object_key: string }).object_key;
    const receiptEvidence = entry.hash_only_receipt.evidence as { fingerprint: string };
    const result = await verifyIngestV1WithIntent({
      bundle: entry.bundle, material: material(entry.case_id),
      intent: { subject: { kind: "ingest", id: key }, expected: [
        { kind: "digest", key: "fingerprint", contract: "hf-contract-v1", material: "json", domain: "va:ingest:fingerprint:v1", digest: receiptEvidence.fingerprint },
        { kind: "merkle-root", key: "merkle_root", tree_alg: "hf-ingest-v1", root_hash: (entry.bundle.merkle as { root: string }).root, leaf_count: 1 },
      ] },
    });
    expect(outcome(result, "intent.commitment.fingerprint")).toBe("pass");
    expect(outcome(result, "intent.commitment.merkle_root")).toBe("pass");
    expect(outcome(result, "ingest.receipt_binding")).toBe("indeterminate");
  });

  it("rejects mismatched Ingest network from a valid anchored receipt", async () => {
    const entry = fixture(ingestFixtures.cases, "json-v1");
    const key = (entry.bundle.identity as { object_key: string }).object_key;
    const receipt = entry.anchored_receipts?.find((candidate) => candidate.hedera_network === "testnet");
    if (!receipt) throw new Error("Missing networked Ingest receipt fixture");
    const report = await verifyIngestV1WithIntent({
      bundle: entry.bundle, material: material(entry.case_id), receipt,
      intent: ingestIntent(key, "mainnet"),
    });
    expect(outcome(report, "intent.declared_network")).toBe("fail");
    expect(outcome(report, "ingest.receipt_binding")).toBe("pass");
  });

  it("does not silently accept invalid contract domains or algorithms", async () => {
    const entry = fixture(ingestFixtures.cases, "json-v1");
    const key = (entry.bundle.identity as { object_key: string }).object_key;
    const report = await verifyIngestV1WithIntent({
      bundle: entry.bundle, material: material(entry.case_id),
      intent: { subject: { kind: "ingest", id: key }, expected: [
        { kind: "digest", key: "fingerprint", contract: "hf-contract-v1", material: "json", domain: "va:dataset:fingerprint:v1", digest: "0".repeat(128) },
        { kind: "merkle-root", key: "merkle_root", tree_alg: "binary-sorted-v2", root_hash: (entry.bundle.merkle as { root: string }).root, leaf_count: 1 },
      ] },
    });
    expect(outcome(report, "intent.commitment.fingerprint")).toBe("unsupported");
    expect(outcome(report, "intent.commitment.merkle_root")).toBe("unsupported");
  });

  it("an invalid receipt cannot establish a matching declared-network expectation", async () => {
    const entry = fixture(ingestFixtures.cases, "json-v1");
    const key = (entry.bundle.identity as { object_key: string }).object_key;
    const original = entry.anchored_receipts?.find((candidate) => candidate.hedera_network === "testnet");
    if (!original) throw new Error("Missing networked Ingest receipt fixture");
    const receipt = JSON.parse(JSON.stringify(original)) as Record<string, unknown>;
    receipt.receipt_id = "0".repeat(128);
    const report = await verifyIngestV1WithIntent({
      bundle: entry.bundle, material: material(entry.case_id), receipt,
      intent: ingestIntent(key, "testnet"),
    });
    expect(outcome(report, "ingest.receipt_binding")).toBe("fail");
    expect(outcome(report, "intent.declared_network")).toBe("indeterminate");
  });
});
