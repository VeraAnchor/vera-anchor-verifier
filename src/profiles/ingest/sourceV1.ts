import type { SourceV1File, SourceV1Limits, SourceV1Mismatch } from "../sourceV1Helpers.js";
import {
  sourceV1Compare,
  sourceV1HashFile,
  sourceV1JsonMaterial,
  sourceV1Leaf,
  sourceV1Limits,
  sourceV1MediaType,
  sourceV1Mismatch,
  sourceV1Path,
  sourceV1PathDigest,
  sourceV1Root,
  sourceV1TextFile,
  sourceV1TextMaterial,
} from "../sourceV1Helpers.js";
import {
  verifyIngestV1Bundle,
  verifyIngestV1Pair,
  type IngestV1BundleComputed,
  type IngestV1ReceiptComputed,
} from "./v1.js";

export type IngestV1SourceMaterial =
  | Readonly<{ kind: "json"; value: unknown }>
  | Readonly<{ kind: "text"; text: string; media_type?: string | null }>
  | Readonly<{ kind: "file"; file: SourceV1File }>
  | Readonly<{ kind: "file_set"; files: readonly SourceV1File[] }>;
export type IngestV1SourceInput = Readonly<{
  bundle: unknown;
  material: IngestV1SourceMaterial;
  receipt?: unknown;
  limits?: SourceV1Limits;
}>;
export type IngestV1SourceResult = Readonly<{
  ok: boolean;
  mismatches: readonly SourceV1Mismatch[];
  computed: Readonly<{
    bundle: IngestV1BundleComputed;
    receipt?: IngestV1ReceiptComputed;
    source_merkle_root: string;
    source_item_count: number;
    source_total_bytes: number;
  }>;
}>;

type Item = Readonly<{
  item_kind: "json" | "text" | "file";
  path_rel?: string;
  path_hash?: string;
  media_type?: string;
  bytes: number;
  sha3_512: string;
  leaf_hash: string;
}>;
type BundleView = Readonly<{
  identity: Readonly<{ object_kind: "json" | "text" | "file" | "file_set" }>;
  rules: Readonly<{ redact_paths: boolean; normalize_line_endings: boolean }>;
  items: readonly Item[];
  merkle?: Readonly<{ root: string }>;
}>;

type ComputedItem = Readonly<Omit<Item, "leaf_hash"> & { leaf_hash: string }>;

/** Bind actual Ingest v1 material to its item hashes, leaf commitments, Merkle root and optional receipt. */
export async function verifyIngestV1Sources(input: IngestV1SourceInput): Promise<IngestV1SourceResult> {
  const checked = input.receipt === undefined
    ? verifyIngestV1Bundle(input.bundle)
    : verifyIngestV1Pair({ bundle: input.bundle, receipt: input.receipt });
  const checkedBundle = input.receipt === undefined ? (checked.computed as IngestV1BundleComputed)
    : (checked.computed as Readonly<{ bundle: IngestV1BundleComputed; receipt: IngestV1ReceiptComputed }>).bundle;
  const checkedReceipt = input.receipt === undefined ? undefined
    : (checked.computed as Readonly<{ bundle: IngestV1BundleComputed; receipt: IngestV1ReceiptComputed }>).receipt;
  const bundle = input.bundle as BundleView;
  const mismatches: SourceV1Mismatch[] = checked.mismatches.map((entry) =>
    sourceV1Mismatch(entry.field, entry.expected, entry.actual));
  if (!input.material || input.material.kind !== bundle.identity.object_kind) {
    throw new TypeError("Ingest material kind does not match bundle identity");
  }
  const { total: maxTotal, file: maxFile } = sourceV1Limits(input.limits);
  const computedItems: ComputedItem[] = [];
  let totalBytes = 0;

  if (input.material.kind === "json") {
    const material = sourceV1JsonMaterial(input.material.value);
    if (material.bytes > maxFile || material.bytes > maxTotal) throw new RangeError("Ingest source material exceeds byte limit");
    totalBytes = material.bytes;
    const base = { item_kind: "json" as const, media_type: "application/json", ...material };
    computedItems.push({ ...base, leaf_hash: sourceV1Leaf("ingest", base) });
  } else if (input.material.kind === "text") {
    const material = sourceV1TextMaterial(input.material.text);
    if (material.bytes > maxFile || material.bytes > maxTotal) throw new RangeError("Ingest source material exceeds byte limit");
    totalBytes = material.bytes;
    const rawMediaType = input.material.media_type ?? undefined;
    if (rawMediaType !== undefined && typeof rawMediaType !== "string") throw new TypeError("Invalid Ingest text media type");
    const media_type = rawMediaType?.trim() || undefined;
    const base = { item_kind: "text" as const, ...(media_type ? { media_type } : {}), ...material };
    computedItems.push({ ...base, leaf_hash: sourceV1Leaf("ingest", base) });
  } else {
    const providedFiles = input.material.kind === "file" ? [input.material.file] : input.material.files;
    if (!Array.isArray(providedFiles) || providedFiles.length === 0 || providedFiles.length > 5_000) {
      throw new TypeError("Ingest source files must be a nonempty bounded array");
    }
    const seen = new Set<string>();
    for (const entry of providedFiles) {
      const path = sourceV1Path(entry.path_rel, 1024);
      if (seen.has(path)) throw new TypeError("Duplicate Ingest source path");
      if (input.material.kind === "file" && path.includes("/")) {
        throw new TypeError("Single-file Ingest source must use a basename");
      }
      seen.add(path);
      const normalizeText = input.material.kind === "file_set" && bundle.rules.normalize_line_endings && sourceV1TextFile(path);
      const hashed = await sourceV1HashFile(entry.source, Math.min(maxFile, maxTotal - totalBytes), normalizeText);
      totalBytes += hashed.bytes;
      const pathFields = input.material.kind === "file_set" && bundle.rules.redact_paths
        ? { path_hash: sourceV1PathDigest(path, "ingest") }
        : { path_rel: path };
      const media_type = sourceV1MediaType(path);
      const base = { item_kind: "file" as const, ...pathFields, ...(media_type ? { media_type } : {}), ...hashed };
      computedItems.push({ ...base, leaf_hash: sourceV1Leaf("ingest", base) });
    }
  }

  computedItems.sort((a, b) => {
    const aKey = a.path_rel ?? a.path_hash ?? "";
    const bKey = b.path_rel ?? b.path_hash ?? "";
    if (aKey !== bKey) return aKey < bKey ? -1 : 1;
    if (a.item_kind !== b.item_kind) return a.item_kind < b.item_kind ? -1 : 1;
    return a.sha3_512 < b.sha3_512 ? -1 : a.sha3_512 > b.sha3_512 ? 1 : 0;
  });

  sourceV1Compare(mismatches, "sources.item_count", bundle.items.length, computedItems.length);
  sourceV1Compare(mismatches, "sources.total_bytes", checkedBundle.total_bytes, totalBytes);
  for (const [index, computed] of computedItems.entries()) {
    const declared = bundle.items[index];
    for (const field of ["item_kind", "path_rel", "path_hash", "media_type", "bytes", "sha3_512", "leaf_hash"] as const) {
      sourceV1Compare(mismatches, `items[${index}].${field}`, computed[field] ?? null, declared?.[field] ?? null);
    }
  }
  const sourceRoot = sourceV1Root("ingest", computedItems.map((item) => item.leaf_hash));
  if (bundle.merkle) sourceV1Compare(mismatches, "sources.merkle_root", bundle.merkle.root, sourceRoot);
  if (checkedReceipt) sourceV1Compare(mismatches, "sources.receipt_merkle_root", checkedReceipt.merkle_root, sourceRoot);
  return Object.freeze({
    ok: mismatches.length === 0,
    mismatches: Object.freeze(mismatches),
    computed: Object.freeze({
      bundle: checkedBundle,
      ...(checkedReceipt ? { receipt: checkedReceipt } : {}),
      source_merkle_root: sourceRoot,
      source_item_count: computedItems.length,
      source_total_bytes: totalBytes,
    }),
  });
}
