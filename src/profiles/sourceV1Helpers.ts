import { posix } from "node:path";
import { sha3_512Stream, type ByteChunkSource } from "../crypto/streamSha3.js";
import { canonicalizeHfV1Json, hashHfV1, MAX_HF_V1_PAYLOAD_BYTES } from "../hf/hashContractV1.js";

export type SourceV1File = Readonly<{ path_rel: string; source: ByteChunkSource }>;
export type SourceV1Mismatch = Readonly<{ field: string; expected: unknown; actual: unknown }>;
export type SourceV1Limits = Readonly<{ max_total_bytes?: number; max_file_bytes?: number }>;
export const DEFAULT_SOURCE_V1_MAX_BYTES = 1024 * 1024 * 1024;

const DIGEST = /^[0-9a-f]{128}$/;
const TEXT_SUFFIXES = new Set([
  ".txt", ".text", ".csv", ".tsv", ".fasta", ".fa", ".fna", ".ffn", ".faa", ".frn",
  ".json", ".jsonl", ".ndjson", ".md", ".yaml", ".yml", ".xml", ".html", ".htm",
]);
const MEDIA_BY_SUFFIX: Readonly<Record<string, string>> = {
  ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp",
  ".gif": "image/gif", ".bmp": "image/bmp", ".tif": "image/tiff", ".tiff": "image/tiff",
  ".svg": "image/svg+xml", ".txt": "text/plain", ".text": "text/plain", ".csv": "text/csv",
  ".tsv": "text/tab-separated-values", ".fasta": "chemical/seq-na-fasta", ".fa": "chemical/seq-na-fasta",
  ".fna": "chemical/seq-na-fasta", ".ffn": "chemical/seq-na-fasta", ".faa": "chemical/seq-aa-fasta",
  ".frn": "chemical/seq-na-fasta", ".json": "application/json", ".jsonl": "application/x-ndjson",
  ".ndjson": "application/x-ndjson", ".md": "text/markdown", ".yaml": "application/yaml",
  ".yml": "application/yaml", ".xml": "application/xml", ".html": "text/html", ".htm": "text/html",
};

function hasControlChars(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code <= 31 || code === 127) return true;
  }
  return false;
}

export function sourceV1Path(value: unknown, maxLength: number): string {
  if (typeof value !== "string" || !value || value.length > maxLength || hasControlChars(value)) {
    throw new TypeError("Source path must be a bounded relative path");
  }
  if (value.trim() !== value || value.includes("\\") || value.startsWith("/") || /^[a-zA-Z]:/.test(value)) {
    throw new TypeError("Source path is not canonical POSIX relative form");
  }
  if (value.split("/").some((segment) => !segment || segment === "." || segment === "..")) {
    throw new TypeError("Source path contains invalid segments");
  }
  if (posix.normalize(value) !== value) throw new TypeError("Source path is not normalized");
  return value;
}

export function sourceV1MediaType(pathRel: string): string | undefined {
  const suffix = posix.extname(pathRel).trim().toLowerCase();
  return MEDIA_BY_SUFFIX[suffix];
}
export function sourceV1TextFile(pathRel: string): boolean {
  return TEXT_SUFFIXES.has(posix.extname(pathRel).trim().toLowerCase());
}
export function sourceV1PathDigest(pathRel: string, profile: "dataset" | "ingest"): string {
  if (profile === "dataset") {
    return hashHfV1({ domain: "va:dataset:path:v1", material: "raw", bytes: Buffer.from(pathRel, "utf8") });
  }
  return hashHfV1({ domain: "va:ingest:path:v1", material: "json", value: { path_rel: pathRel } });
}
export function sourceV1Leaf(
  profile: "dataset" | "ingest",
  value: Readonly<{ item_kind?: "json" | "text" | "file"; path_rel?: string; path_hash?: string; media_type?: string; bytes: number; sha3_512: string }>,
): string {
  return hashHfV1({
    domain: profile === "dataset" ? "va:dataset:leaf:v1" : "va:ingest:leaf:v1",
    material: "json",
    value: {
      ...(profile === "ingest" ? { item_kind: value.item_kind } : {}),
      ...(value.path_rel ? { path_rel: value.path_rel } : {}),
      ...(value.path_hash ? { path_hash: value.path_hash } : {}),
      ...(value.media_type ? { media_type: value.media_type } : {}),
      bytes: value.bytes,
      sha3_512: value.sha3_512,
    },
  });
}
export function sourceV1Root(profile: "dataset" | "ingest", leaves: readonly string[]): string {
  if (!leaves.length || leaves.some((leaf) => !DIGEST.test(leaf))) throw new TypeError("Invalid source Merkle leaves");
  let level = leaves.slice();
  while (level.length > 1) {
    const next: string[] = [];
    for (let index = 0; index < level.length; index += 2) {
      const left = level[index];
      if (!left) throw new TypeError("Invalid Merkle level");
      const right = level[index + 1] ?? left;
      next.push(hashHfV1({ domain: `va:${profile}:node:v1`, material: "raw", bytes: Buffer.from(left + right, "hex") }));
    }
    level = next;
  }
  const root = level[0];
  if (!root) throw new TypeError("Invalid source Merkle tree");
  return root;
}
export function sourceV1Mismatch(field: string, expected: unknown, actual: unknown): SourceV1Mismatch {
  return Object.freeze({ field, expected, actual });
}
export function sourceV1Compare(
  mismatches: SourceV1Mismatch[], field: string, expected: unknown, actual: unknown,
): void {
  if (expected !== actual) mismatches.push(sourceV1Mismatch(field, expected, actual));
}
export function sourceV1SafeLimit(value: unknown, field: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new TypeError(`${field} must be a non-negative safe integer`);
  return value as number;
}
export function sourceV1Limits(limits?: SourceV1Limits): Readonly<{ total: number; file: number }> {
  return {
    total: sourceV1SafeLimit(limits?.max_total_bytes ?? DEFAULT_SOURCE_V1_MAX_BYTES, "max_total_bytes"),
    file: sourceV1SafeLimit(limits?.max_file_bytes ?? DEFAULT_SOURCE_V1_MAX_BYTES, "max_file_bytes"),
  };
}

export async function sourceV1HashFile(
  source: ByteChunkSource, maxBytes: number, normalizeText: boolean,
): Promise<Readonly<{ bytes: number; sha3_512: string }>> {
  if (!normalizeText) {
    const result = await sha3_512Stream(source, { max_bytes: maxBytes });
    return { bytes: result.bytes_hashed, sha3_512: result.digest };
  }
  const ceiling = Math.min(maxBytes, MAX_HF_V1_PAYLOAD_BYTES);
  const chunks: Buffer[] = [];
  let bytes = 0;
  for await (const chunk of source) {
    if (!(chunk instanceof Uint8Array)) throw new TypeError("Source chunks must be Uint8Array");
    if (chunk.byteLength > ceiling - bytes) throw new RangeError("Normalized text exceeds source byte limit");
    bytes += chunk.byteLength;
    chunks.push(Buffer.from(chunk));
  }
  const normalized = Buffer.concat(chunks, bytes).toString("utf8").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  return { bytes, sha3_512: hashHfV1({ domain: "va:ingest:file-text:v1", material: "utf8", text: normalized }) };
}

export function sourceV1JsonMaterial(value: unknown): Readonly<{ bytes: number; sha3_512: string }> {
  const canonical = canonicalizeHfV1Json(value);
  return {
    bytes: canonical.byteLength,
    sha3_512: hashHfV1({ domain: "va:ingest:json:v1", material: "raw", bytes: canonical }),
  };
}
export function sourceV1TextMaterial(text: string): Readonly<{ bytes: number; sha3_512: string }> {
  if (typeof text !== "string") throw new TypeError("Ingest text material must be a string");
  return {
    bytes: Buffer.byteLength(text, "utf8"),
    sha3_512: hashHfV1({ domain: "va:ingest:text:v1", material: "utf8", text }),
  };
}
