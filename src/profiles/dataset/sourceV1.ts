import type { SourceV1File, SourceV1Limits, SourceV1Mismatch } from "../sourceV1Helpers.js";
import {
  sourceV1Compare,
  sourceV1HashFile,
  sourceV1Leaf,
  sourceV1Limits,
  sourceV1Mismatch,
  sourceV1Path,
  sourceV1PathDigest,
  sourceV1Root,
} from "../sourceV1Helpers.js";
import {
  verifyDatasetV1Bundle,
  verifyDatasetV1Receipt,
  type DatasetV1BundleComputed,
  type DatasetV1ReceiptComputed,
} from "./v1.js";
import { canonicalizeHfV1Json } from "../../hf/hashContractV1.js";

export type DatasetV1SourceInput = Readonly<{
  bundle: unknown;
  files: readonly SourceV1File[];
  receipt?: unknown;
  limits?: SourceV1Limits;
}>;
export type DatasetV1SourceResult = Readonly<{
  ok: boolean;
  mismatches: readonly SourceV1Mismatch[];
  computed: Readonly<{
    bundle: DatasetV1BundleComputed;
    receipt?: DatasetV1ReceiptComputed;
    source_merkle_root?: string;
    source_file_count: number;
    source_total_bytes: number;
  }>;
}>;

type ExpectedFile = Readonly<{
  path_rel?: string;
  path_hash?: string;
  bytes: number;
  sha3_512: string;
  leaf_hash: string;
}>;
type BundleView = Readonly<{
  dataset_identity: Readonly<{ dataset_key: string; program?: string; version_label?: string }>;
  rules: Readonly<{ redact_paths: boolean }> & Record<string, unknown>;
  files: readonly ExpectedFile[];
  merkle: Readonly<{ root: string }>;
}>;
type ReceiptView = Readonly<{ rules: Record<string, unknown> }>;

/** Independently bind all supplied file bytes to Dataset v1 leaves, root, bundle and optional receipt. */
export async function verifyDatasetV1Sources(input: DatasetV1SourceInput): Promise<DatasetV1SourceResult> {
  const checkedBundle = verifyDatasetV1Bundle(input.bundle);
  const bundle = input.bundle as BundleView;
  const mismatches: SourceV1Mismatch[] = checkedBundle.mismatches.map((entry) =>
    sourceV1Mismatch(`bundle.${entry.field}`, entry.expected, entry.actual));
  if (!Array.isArray(input.files)) throw new TypeError("Dataset source files must be an array");
  const { total: maxTotal, file: maxFile } = sourceV1Limits(input.limits);
  if (input.files.length > 5_000) throw new RangeError("Too many Dataset source files");

  const sourcePaths = new Set<string>();
  const sources = input.files.map((entry) => {
    const path = sourceV1Path(entry.path_rel, 4096);
    if (path.includes("..")) throw new TypeError("Dataset source path is not producer-canonical");
    if (sourcePaths.has(path)) throw new TypeError("Duplicate Dataset source path");
    sourcePaths.add(path);
    return { path, source: entry.source };
  }).sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);

  sourceV1Compare(mismatches, "sources.file_count", bundle.files.length, sources.length);
  const leaves: string[] = [];
  let totalBytes = 0;
  for (const [index, entry] of sources.entries()) {
    const item = bundle.files[index];
    const remaining = maxTotal - totalBytes;
    const hashed = await sourceV1HashFile(entry.source, Math.min(maxFile, remaining), false);
    totalBytes += hashed.bytes;
    const pathKey = bundle.rules.redact_paths ? "path_hash" : "path_rel";
    const pathValue = bundle.rules.redact_paths ? sourceV1PathDigest(entry.path, "dataset") : entry.path;
    sourceV1Compare(mismatches, `files[${index}].${pathKey}`, pathValue, item?.[pathKey] ?? null);
    sourceV1Compare(mismatches, `files[${index}].bytes`, hashed.bytes, item?.bytes ?? null);
    sourceV1Compare(mismatches, `files[${index}].sha3_512`, hashed.sha3_512, item?.sha3_512 ?? null);
    const leaf = sourceV1Leaf("dataset", {
      ...(bundle.rules.redact_paths ? { path_hash: pathValue } : { path_rel: pathValue }),
      bytes: hashed.bytes,
      sha3_512: hashed.sha3_512,
    });
    leaves.push(leaf);
    sourceV1Compare(mismatches, `files[${index}].leaf_hash`, leaf, item?.leaf_hash ?? null);
  }
  const sourceRoot = leaves.length ? sourceV1Root("dataset", leaves) : undefined;
  sourceV1Compare(mismatches, "sources.total_bytes", checkedBundle.computed.total_bytes, totalBytes);
  if (sourceRoot) sourceV1Compare(mismatches, "sources.merkle_root", bundle.merkle.root, sourceRoot);

  let receipt: DatasetV1ReceiptComputed | undefined;
  if (input.receipt !== undefined) {
    const receiptResult = verifyDatasetV1Receipt(input.receipt);
    receipt = receiptResult.computed;
    mismatches.push(...receiptResult.mismatches.map((entry) =>
      sourceV1Mismatch(`receipt.${entry.field}`, entry.expected, entry.actual)));
    for (const field of ["dataset_key", "program", "version_label", "bundle_digest", "dataset_fingerprint", "merkle_root", "idempotency_key", "file_count", "total_bytes"] as const) {
      sourceV1Compare(mismatches, `binding.${field}`, checkedBundle.computed[field], receipt[field]);
    }
    const receiptRules = (input.receipt as ReceiptView).rules;
    const bundleRulesDigest = Buffer.from(canonicalizeHfV1Json(bundle.rules)).toString("hex");
    const receiptRulesDigest = Buffer.from(canonicalizeHfV1Json(receiptRules)).toString("hex");
    if (bundleRulesDigest !== receiptRulesDigest) {
      mismatches.push(sourceV1Mismatch("binding.rules", "matches bundle rules", "mismatch"));
    }
  }
  const computed = Object.freeze({
    bundle: checkedBundle.computed,
    ...(receipt ? { receipt } : {}),
    ...(sourceRoot ? { source_merkle_root: sourceRoot } : {}),
    source_file_count: sources.length,
    source_total_bytes: totalBytes,
  });
  return Object.freeze({ ok: mismatches.length === 0, mismatches: Object.freeze(mismatches), computed });
}
