import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { verifyDatasetV1Sources } from "../../src/profiles/dataset/sourceV1.js";
import { verifyIngestV1Sources, type IngestV1SourceMaterial } from "../../src/profiles/ingest/sourceV1.js";
import { verifyIngestV1Bundle } from "../../src/profiles/ingest/v1.js";

const sources = JSON.parse(readFileSync(new URL("./fixtures/sourceV1Materials.json", import.meta.url), "utf8")) as {
  dataset: Record<string, readonly { path_rel: string; content_base64: string }[]>;
  ingest: Record<string, unknown>;
};
type Vector = Readonly<{
  case_id: string;
  bundle: Record<string, unknown>;
  hash_only_receipt: Record<string, unknown>;
}>;
const datasets = (JSON.parse(readFileSync(new URL("./fixtures/datasetV1SelectedVectors.json", import.meta.url), "utf8")) as { cases: Vector[] }).cases;
const ingests = (JSON.parse(readFileSync(new URL("./fixtures/ingestV1SelectedVectors.json", import.meta.url), "utf8")) as { cases: Vector[] }).cases;

type EncodedFile = Readonly<{ path_rel: string; content_base64: string }>;
type IngestFixture =
  | Readonly<{ kind: "json"; value: unknown }>
  | Readonly<{ kind: "text"; text: string; media_type?: string }>
  | Readonly<{ kind: "file"; file: EncodedFile }>
  | Readonly<{ kind: "file_set"; files: readonly EncodedFile[] }>;

function chunks(base64: string): readonly Uint8Array[] {
  const bytes = Buffer.from(base64, "base64");
  return [bytes.subarray(0, Math.min(3, bytes.byteLength)), bytes.subarray(Math.min(3, bytes.byteLength))];
}
function datasetFiles(caseId: string) {
  const files = sources.dataset[caseId];
  if (!files) throw new Error(`Missing Dataset source fixture: ${caseId}`);
  return files.map((file) => ({ path_rel: file.path_rel, source: chunks(file.content_base64) }));
}
function ingestMaterial(caseId: string): IngestV1SourceMaterial {
  const material = sources.ingest[caseId] as IngestFixture | undefined;
  if (!material) throw new Error(`Missing Ingest source fixture: ${caseId}`);
  switch (material.kind) {
    case "json": return material;
    case "text": return material;
    case "file": return { kind: "file", file: { path_rel: material.file.path_rel, source: chunks(material.file.content_base64) } };
    case "file_set": return { kind: "file_set", files: material.files.map((file) => ({ path_rel: file.path_rel, source: chunks(file.content_base64) })) };
  }
}
function vector(cases: readonly Vector[], id: string): Vector {
  const selected = cases.find((entry) => entry.case_id === id);
  if (!selected) throw new Error(`Missing vector: ${id}`);
  return selected;
}
function copy<T>(value: T): T { return JSON.parse(JSON.stringify(value)) as T; }
function fields(result: { mismatches: readonly { field: string }[] }): string[] {
  return result.mismatches.map((item) => item.field);
}

describe("Dataset v1 source-to-evidence binding", () => {
  for (const entry of datasets) {
    it(`${entry.case_id}: reconstructs commitments from actual bytes and binds receipt`, async () => {
      const result = await verifyDatasetV1Sources({
        bundle: entry.bundle, receipt: entry.hash_only_receipt, files: datasetFiles(entry.case_id),
      });
      expect(result.ok).toBe(true);
      expect(result.mismatches).toEqual([]);
      expect(result.computed.source_merkle_root).toBe((entry.bundle.merkle as { root: string }).root);
      expect(result.computed.source_file_count).toBe((entry.bundle.files as unknown[]).length);
    });
  }

  it("detects modified file bytes despite internally consistent bundle and receipt", async () => {
    const entry = vector(datasets, "basic-v1");
    const result = await verifyDatasetV1Sources({
      bundle: entry.bundle, receipt: entry.hash_only_receipt,
      files: [{ path_rel: "hello.txt", source: [Buffer.from("hello WORLD\n")] }],
    });
    expect(result.ok).toBe(false);
    expect(fields(result)).toEqual(expect.arrayContaining(["files[0].sha3_512", "files[0].leaf_hash", "sources.merkle_root"]));
  });

  it("rejects missing, extra or duplicated source files", async () => {
    const entry = vector(datasets, "zero-byte-v1");
    const files = datasetFiles("zero-byte-v1");
    expect((await verifyDatasetV1Sources({ bundle: entry.bundle, files: files.slice(0, 1) })).ok).toBe(false);
    expect((await verifyDatasetV1Sources({ bundle: entry.bundle, files: [...files, { path_rel: "extra.txt", source: [Buffer.alloc(0)] }] })).ok).toBe(false);
    await expect(verifyDatasetV1Sources({ bundle: entry.bundle, files: [files[0]!, files[0]!] })).rejects.toThrow(/Duplicate/);
  });

  it("does not accept unrelated but individually valid Dataset receipt", async () => {
    const entry = vector(datasets, "basic-v1");
    const other = vector(datasets, "zero-byte-v1");
    const result = await verifyDatasetV1Sources({ bundle: entry.bundle, receipt: other.hash_only_receipt, files: datasetFiles("basic-v1") });
    expect(result.ok).toBe(false);
    expect(fields(result)).toContain("binding.dataset_key");
  });

  it("rejects traversal paths and enforces caller limits", async () => {
    const entry = vector(datasets, "basic-v1");
    await expect(verifyDatasetV1Sources({ bundle: entry.bundle, files: [{ path_rel: "../hello.txt", source: [Buffer.alloc(12)] }] })).rejects.toThrow(TypeError);
    await expect(verifyDatasetV1Sources({ bundle: entry.bundle, files: datasetFiles("basic-v1"), limits: { max_total_bytes: 4 } })).rejects.toThrow(RangeError);
  });
});

describe("Ingest v1 material-to-evidence binding", () => {
  for (const entry of ingests) {
    it(`${entry.case_id}: independently recomputes content digest, leaf, root and receipt binding`, async () => {
      const result = await verifyIngestV1Sources({
        bundle: entry.bundle, receipt: entry.hash_only_receipt, material: ingestMaterial(entry.case_id),
      });
      expect(result.ok).toBe(true);
      expect(result.mismatches).toEqual([]);
      expect(result.computed.source_merkle_root).toBe((entry.bundle.merkle as { root: string }).root);
    });
  }

  it("detects modified JSON material independently of declared bundle", async () => {
    const entry = vector(ingests, "json-v1");
    const original = ingestMaterial("json-v1");
    if (original.kind !== "json") throw new Error("Fixture kind mismatch");
    const result = await verifyIngestV1Sources({ bundle: entry.bundle, material: { kind: "json", value: { ...(original.value as object), alpha: 999 } } });
    expect(result.ok).toBe(false);
    expect(fields(result)).toContain("items[0].sha3_512");
  });

  it("detects text mutation independently of declared bundle", async () => {
    const entry = vector(ingests, "text-v1");
    const original = ingestMaterial("text-v1");
    if (original.kind !== "text") throw new Error("Fixture kind mismatch");
    const result = await verifyIngestV1Sources({ bundle: entry.bundle, material: { ...original, text: `${original.text}extra` } });
    expect(result.ok).toBe(false);
    expect(fields(result)).toContain("items[0].sha3_512");
  });

  it("does not mistake normalized text digest equality for equal original byte count", async () => {
    const entry = vector(ingests, "file-set-v1");
    const original = ingestMaterial("file-set-v1");
    if (original.kind !== "file_set") throw new Error("Fixture kind mismatch");
    const files = original.files.map((file) => file.path_rel === "a/alpha.txt"
      ? { ...file, source: [Buffer.from("alpha\nbeta\n")] }
      : file);
    const result = await verifyIngestV1Sources({ bundle: entry.bundle, material: { kind: "file_set", files } });
    expect(result.ok).toBe(false);
    expect(fields(result).some((field) => field.endsWith(".bytes"))).toBe(true);
  });

  it("detects redacted path substitution and missing file-set members", async () => {
    const entry = vector(ingests, "file-set-v1");
    const original = ingestMaterial("file-set-v1");
    if (original.kind !== "file_set") throw new Error("Fixture kind mismatch");
    const substituted = original.files.map((file) => file.path_rel === "b/data.csv"
      ? { ...file, path_rel: "b/other.csv" }
      : file);
    expect((await verifyIngestV1Sources({ bundle: entry.bundle, material: { kind: "file_set", files: substituted } })).ok).toBe(false);
    const incomplete = await verifyIngestV1Sources({ bundle: entry.bundle, material: { kind: "file_set", files: original.files.slice(1) } });
    expect(incomplete.ok).toBe(false);
    expect(fields(incomplete)).toContain("sources.item_count");
  });

  it("rejects malformed source paths, duplicates, and oversized streams", async () => {
    const entry = vector(ingests, "file-set-v1");
    const original = ingestMaterial("file-set-v1");
    if (original.kind !== "file_set") throw new Error("Fixture kind mismatch");
    const duplicate = [original.files[0]!, original.files[0]!];
    await expect(verifyIngestV1Sources({ bundle: entry.bundle, material: { kind: "file_set", files: duplicate } })).rejects.toThrow(/Duplicate/);
    await expect(verifyIngestV1Sources({ bundle: entry.bundle, material: { kind: "file_set", files: [{ path_rel: "../escape", source: [Buffer.alloc(0)] }] } })).rejects.toThrow(TypeError);
    await expect(verifyIngestV1Sources({ bundle: entry.bundle, material: original, limits: { max_total_bytes: 4 } })).rejects.toThrow(RangeError);
  });

  it("checks declared Ingest leaves from metadata even without original source material", () => {
    const entry = vector(ingests, "json-v1");
    const altered = copy(entry.bundle) as { items: Array<{ leaf_hash: string }> };
    altered.items[0]!.leaf_hash = "0".repeat(128);
    const result = verifyIngestV1Bundle(altered);
    expect(result.ok).toBe(false);
    expect(fields(result)).toContain("items[0].leaf_hash");
  });

  it("does not bind a valid receipt for a different Ingest object", async () => {
    const entry = vector(ingests, "json-v1");
    const other = vector(ingests, "text-v1");
    const result = await verifyIngestV1Sources({ bundle: entry.bundle, receipt: other.hash_only_receipt, material: ingestMaterial("json-v1") });
    expect(result.ok).toBe(false);
    expect(fields(result)).toContain("binding.object_key");
  });
});
