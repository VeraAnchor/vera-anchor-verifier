import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  verifyDatasetV1Bundle,
  verifyDatasetV1Receipt,
} from "../../src/profiles/dataset/v1.js";

type MutableBundle = {
  files: Array<{ path_rel?: string; path_hash?: string; sha3_512: string; leaf_hash: string }>;
  merkle: { root: string; leaf_count: number };
  summary: { total_bytes: number };
  hash_contract: { frame: string };
  extra_field?: boolean;
};

type MutableReceipt = { receipt_id: string; hedera_network?: string };

type Vector = {
  case_id: string;
  bundle: Record<string, unknown>;
  bundle_expectations: Record<string, string>;
  hash_only_receipt: Record<string, unknown>;
  anchored_receipts?: Array<Record<string, unknown>>;
};

// Selected values copied from the existing Dataset v1 producer corpus.
// The original distribution manifest will be checked when pristine files are imported.
const snapshots = JSON.parse(
  readFileSync(new URL("./fixtures/datasetV1SelectedVectors.json", import.meta.url), "utf8"),
) as { cases: Vector[] };

function copy<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function changeDigest(original: string): string {
  return `${original.startsWith("0") ? "1" : "0"}${original.slice(1)}`;
}

describe("Dataset v1 independently recomputed commitments", () => {
  for (const vector of snapshots.cases) {
    it(`${vector.case_id}: matches frozen bundle digest, fingerprint, Merkle root and idempotency key`, () => {
      const result = verifyDatasetV1Bundle(vector.bundle);
      expect(result.ok).toBe(true);
      expect(result.mismatches).toEqual([]);
      expect(result.computed).toMatchObject(vector.bundle_expectations);
    });

    it(`${vector.case_id}: verifies hash-only receipt independently`, () => {
      const result = verifyDatasetV1Receipt(vector.hash_only_receipt);
      expect(result.ok).toBe(true);
      expect(result.computed.hedera_network).toBeNull();
      expect(result.computed.receipt_id).toBe(vector.hash_only_receipt.receipt_id);
      expect(result.computed.dataset_fingerprint).toBe(vector.bundle_expectations.dataset_fingerprint);
    });
  }

  it("keeps identical content commitments across explicitly network-bound receipts", () => {
    const vector = snapshots.cases.find((item) => item.case_id === "basic-v1");
    expect(vector?.anchored_receipts).toHaveLength(2);
    const [testnet, mainnet] = vector?.anchored_receipts ?? [];
    expect(testnet).toBeDefined();
    expect(mainnet).toBeDefined();
    if (!testnet || !mainnet) return;
    expect(verifyDatasetV1Receipt(testnet).ok).toBe(true);
    expect(verifyDatasetV1Receipt(mainnet).ok).toBe(true);
    expect(testnet.hedera_network).toBe("testnet");
    expect(mainnet.hedera_network).toBe("mainnet");
    expect(testnet.receipt_id).not.toBe(mainnet.receipt_id);
    expect(testnet.evidence).toEqual(mainnet.evidence);
  });

  it("detects tampered file digest without accepting the stored leaf or root", () => {
    const vector = snapshots.cases[0];
    if (!vector) throw new Error("missing dataset vector");
    const bundle = copy(vector.bundle) as unknown as MutableBundle;
    const first = bundle.files[0];
    if (!first) throw new Error("missing first file");
    first.sha3_512 = changeDigest(first.sha3_512);
    const result = verifyDatasetV1Bundle(bundle);
    expect(result.ok).toBe(false);
    expect(result.mismatches.map((entry) => entry.field)).toEqual(
      expect.arrayContaining(["files[0].leaf_hash", "merkle.root"]),
    );
  });

  it("detects altered root, leaf count and summary independently", () => {
    const vector = snapshots.cases[1];
    if (!vector) throw new Error("missing dataset vector");
    const bundle = copy(vector.bundle) as unknown as MutableBundle;
    bundle.merkle.root = changeDigest(bundle.merkle.root);
    bundle.merkle.leaf_count += 1;
    bundle.summary.total_bytes += 1;
    const result = verifyDatasetV1Bundle(bundle);
    expect(result.ok).toBe(false);
    expect(result.mismatches.map((entry) => entry.field)).toEqual(
      expect.arrayContaining(["merkle.root", "merkle.leaf_count", "summary.total_bytes"]),
    );
  });

  it("rejects inconsistent redaction, unsupported contract and unknown fields", () => {
    const vector = snapshots.cases[0];
    if (!vector) throw new Error("missing dataset vector");
    const bundle = copy(vector.bundle) as unknown as MutableBundle;
    const first = bundle.files[0];
    if (!first) throw new Error("missing first file");
    first.path_hash = "a".repeat(128);
    expect(() => verifyDatasetV1Bundle(bundle)).toThrow(TypeError);
    delete first.path_hash;
    bundle.hash_contract.frame = "unsupported";
    expect(() => verifyDatasetV1Bundle(bundle)).toThrow(TypeError);
    bundle.hash_contract.frame = "hf:frame:v1";
    bundle.extra_field = true;
    expect(() => verifyDatasetV1Bundle(bundle)).toThrow(TypeError);
  });

  it("rejects empty datasets and duplicate relative paths", () => {
    const vector = snapshots.cases[0];
    if (!vector) throw new Error("missing dataset vector");
    const empty = copy(vector.bundle) as unknown as MutableBundle;
    empty.files = [];
    expect(() => verifyDatasetV1Bundle(empty)).toThrow(TypeError);
    const duplicate = copy(vector.bundle) as unknown as MutableBundle;
    const first = duplicate.files[0];
    if (!first) throw new Error("missing first file");
    duplicate.files.push(copy(first));
    expect(() => verifyDatasetV1Bundle(duplicate)).toThrow(TypeError);
  });

  it("rejects tampered receipt IDs and contradictory hash-only network identity", () => {
    const vector = snapshots.cases[0];
    if (!vector) throw new Error("missing dataset vector");
    const receipt = copy(vector.hash_only_receipt) as unknown as MutableReceipt;
    receipt.receipt_id = changeDigest(receipt.receipt_id);
    const result = verifyDatasetV1Receipt(receipt);
    expect(result.ok).toBe(false);
    expect(result.mismatches.map((entry) => entry.field)).toContain("receipt_id");
    receipt.hedera_network = "mainnet";
    expect(() => verifyDatasetV1Receipt(receipt)).toThrow(TypeError);
  });

  it("does not promote a self-consistent receipt into content or ledger verification", () => {
    const vector = snapshots.cases[0];
    if (!vector) throw new Error("missing dataset vector");
    const receipt = verifyDatasetV1Receipt(vector.hash_only_receipt);
    expect(receipt.ok).toBe(true);
    // No artifact-byte or Hedera observations are returned by this offline check.
    expect(receipt.computed).not.toHaveProperty("verified_on_hedera");
    expect(receipt.computed).not.toHaveProperty("artifact_bytes_verified");
  });
});
