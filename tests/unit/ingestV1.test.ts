import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  verifyIngestV1Bundle,
  verifyIngestV1Pair,
  verifyIngestV1Receipt,
} from "../../src/profiles/ingest/v1.js";

type Vector = Readonly<{
  case_id: string;
  bundle: Record<string, unknown>;
  bundle_expectations: Readonly<{
    bundle_digest: string;
    fingerprint: string;
    idempotency_key: string;
    merkle_root: string;
  }>;
  hash_only_receipt: Record<string, unknown>;
  anchored_receipts?: readonly Record<string, unknown>[];
}>;

// Source-derived expected values, not a checksum-verified copy of the distribution.
const vectors = JSON.parse(
  readFileSync(new URL("./fixtures/ingestV1SelectedVectors.json", import.meta.url), "utf8"),
) as { cases: Vector[] };

function copy<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}
function changed(digest: string): string {
  return `${digest.startsWith("0") ? "1" : "0"}${digest.slice(1)}`;
}
function first(): Vector {
  const value = vectors.cases[0];
  if (!value) throw new Error("Missing Ingest vector");
  return value;
}

describe("Ingest v1 independently recomputed bundle and receipt commitments", () => {
  for (const vector of vectors.cases) {
    it(`${vector.case_id}: reproduces fixed expected bundle commitments`, () => {
      const result = verifyIngestV1Bundle(vector.bundle);
      expect(result.ok).toBe(true);
      expect(result.mismatches).toEqual([]);
      expect(result.computed).toMatchObject(vector.bundle_expectations);
    });

    it(`${vector.case_id}: checks the hash-only receipt`, () => {
      const result = verifyIngestV1Receipt(vector.hash_only_receipt);
      expect(result.ok).toBe(true);
      expect(result.computed.receipt_id).toBe(vector.hash_only_receipt.receipt_id);
      expect(result.computed.hedera_network).toBeNull();
    });

    it(`${vector.case_id}: binds bundle and receipt commitments`, () => {
      const result = verifyIngestV1Pair({ bundle: vector.bundle, receipt: vector.hash_only_receipt });
      expect(result.ok).toBe(true);
      expect(result.mismatches).toEqual([]);
    });
  }

  it("preserves network-independent content commitments across anchored receipts", () => {
    const receipts = first().anchored_receipts;
    expect(receipts).toHaveLength(2);
    for (const entry of receipts ?? []) {
      expect(verifyIngestV1Receipt(entry).ok).toBe(true);
      expect(verifyIngestV1Pair({ bundle: first().bundle, receipt: entry }).ok).toBe(true);
    }
    expect(receipts?.[0]?.receipt_id).not.toBe(receipts?.[1]?.receipt_id);
    expect(receipts?.[0]?.evidence).toEqual(receipts?.[1]?.evidence);
  });

  it("detects altered leaf commitments independently of the stored root", () => {
    const entry = vectors.cases.find((vector) => vector.case_id === "file-set-v1");
    if (!entry) throw new Error("Missing file-set vector");
    const bundle = copy(entry.bundle) as { items: Array<{ leaf_hash: string }> } & Record<string, unknown>;
    const item = bundle.items[0];
    if (!item) throw new Error("Missing first item");
    item.leaf_hash = changed(item.leaf_hash);
    const result = verifyIngestV1Bundle(bundle);
    expect(result.ok).toBe(false);
    expect(result.mismatches.map((mismatch) => mismatch.field)).toContain("items[0].leaf_hash");
  });

  it("reports summary and merkle leaf-count inconsistencies", () => {
    const bundle = copy(first().bundle) as { summary: { item_count: number; total_bytes: number }; merkle: { leaf_count: number } };
    bundle.summary.item_count += 1;
    bundle.summary.total_bytes += 3;
    bundle.merkle.leaf_count += 1;
    expect(verifyIngestV1Bundle(bundle).mismatches.map((entry) => entry.field)).toEqual(
      expect.arrayContaining(["summary.item_count", "summary.total_bytes", "merkle.leaf_count"]),
    );
  });

  it("rejects unsupported contract IDs, malformed items and unknown keys", () => {
    const unsupported = copy(first().bundle) as { hash_contract: { frame: string } };
    unsupported.hash_contract.frame = "other";
    expect(() => verifyIngestV1Bundle(unsupported)).toThrow(TypeError);
    const invalid = copy(first().bundle) as { items: Array<{ bytes: number }> };
    const item = invalid.items[0];
    if (!item) throw new Error("Missing first item");
    item.bytes = -1;
    expect(() => verifyIngestV1Bundle(invalid)).toThrow(TypeError);
    const extra = { ...first().bundle, injected_field: true };
    expect(() => verifyIngestV1Bundle(extra)).toThrow(TypeError);
  });

  it("rejects non-file item paths and wrong object/item kinds", () => {
    const bundle = copy(first().bundle) as { items: Array<{ path_rel?: string }>; identity: { object_kind: string } };
    const item = bundle.items[0];
    if (!item) throw new Error("Missing first item");
    item.path_rel = "test.json";
    expect(() => verifyIngestV1Bundle(bundle)).toThrow(TypeError);
    delete item.path_rel;
    bundle.identity.object_kind = "file_set";
    expect(() => verifyIngestV1Bundle(bundle)).toThrow(TypeError);
  });

  it("rejects unsupported receipt networks on local modes", () => {
    const receipt = { ...copy(first().hash_only_receipt), hedera_network: "testnet" };
    expect(() => verifyIngestV1Receipt(receipt)).toThrow(TypeError);
  });

  it("detects receipt-ID tampering and embedded network contradictions", () => {
    const receipt = copy(first().hash_only_receipt) as { receipt_id: string };
    receipt.receipt_id = changed(receipt.receipt_id);
    expect(verifyIngestV1Receipt(receipt).mismatches.map((entry) => entry.field)).toContain("receipt_id");

    const anchored = first().anchored_receipts?.[0];
    if (!anchored) throw new Error("Missing anchored receipt");
    const conflict = copy(anchored) as {
      core?: { receipt_anchor?: { hedera_network?: string; publish?: { hedera_network?: string } } };
    };
    conflict.core = { receipt_anchor: { hedera_network: "mainnet", publish: { hedera_network: "mainnet" } } };
    const result = verifyIngestV1Receipt(conflict);
    expect(result.ok).toBe(false);
    expect(result.mismatches.map((entry) => entry.field)).toEqual(
      expect.arrayContaining(["core.receipt_anchor.hedera_network", "core.receipt_anchor.publish.hedera_network"]),
    );
  });

  it("rejects mismatched but individually valid bundle and receipt", () => {
    const another = vectors.cases.find((entry) => entry.case_id === "text-v1");
    if (!another) throw new Error("Missing text vector");
    expect(verifyIngestV1Bundle(first().bundle).ok).toBe(true);
    expect(verifyIngestV1Receipt(another.hash_only_receipt).ok).toBe(true);
    const pair = verifyIngestV1Pair({ bundle: first().bundle, receipt: another.hash_only_receipt });
    expect(pair.ok).toBe(false);
    expect(pair.mismatches.map((entry) => entry.field)).toEqual(
      expect.arrayContaining(["binding.object_key", "binding.bundle_digest", "binding.fingerprint"]),
    );
  });

  it("rejects tampered metadata and invalid anchored receipt scope", () => {
    const receipt = copy(first().hash_only_receipt) as { metadata?: Record<string, unknown> };
    receipt.metadata = { extra: true };
    expect(verifyIngestV1Receipt(receipt).mismatches.map((entry) => entry.field)).toContain("receipt_id");
    const anchored = copy(first().anchored_receipts?.[0]);
    if (!anchored) throw new Error("Missing anchored receipt");
    (anchored as Record<string, unknown>).anchor = {};
    expect(() => verifyIngestV1Receipt(anchored)).toThrow(TypeError);
  });
});
