/** Internal bounded, strict I-JSON/JCS substrate for pinned open HCS schemas/skills.
 * Do not use this as a generic JSON Schema evaluator or as an authenticated source.
 */
export class HcsJsonV1Error extends Error {
  constructor(readonly code: "JSON_INVALID" | "JSON_AMBIGUOUS" | "JSON_TOO_LARGE") {
    super(code);
    this.name = "HcsJsonV1Error";
  }
}

function invalid(code: HcsJsonV1Error["code"]): never { throw new HcsJsonV1Error(code); }

function plain(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function validUnicode(value: string): boolean {
  return !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value);
}

/** Canonical JSON ordering uses ECMAScript UTF-16 code-unit order as required by RFC 8785. */
export function canonicalHcsJsonV1(value: unknown, maxBytes: number): string {
  const seen = new Set<object>();
  let visited = 0;
  const walk = (item: unknown, depth: number): string => {
    if (++visited > 100_000 || depth > 64) return invalid("JSON_TOO_LARGE");
    if (item === null) return "null";
    if (typeof item === "string") {
      if (!validUnicode(item)) return invalid("JSON_INVALID");
      return JSON.stringify(item);
    }
    if (typeof item === "boolean") return item ? "true" : "false";
    if (typeof item === "number") {
      if (!Number.isFinite(item)) return invalid("JSON_INVALID");
      return JSON.stringify(item);
    }
    if (!item || typeof item !== "object" || seen.has(item)) return invalid("JSON_INVALID");
    if (!Array.isArray(item) && !plain(item)) return invalid("JSON_INVALID");
    seen.add(item);
    let result: string;
    if (Array.isArray(item)) {
      result = `[${item.map((child) => walk(child, depth + 1)).join(",")}]`;
    } else {
      const object = item as Record<string, unknown>;
      result = `{${Object.keys(object).sort().map((key) =>
        `${walk(key, depth + 1)}:${walk(object[key], depth + 1)}`).join(",")}}`;
    }
    seen.delete(item);
    if (Buffer.byteLength(result, "utf8") > maxBytes) return invalid("JSON_TOO_LARGE");
    return result;
  };
  return walk(value, 0);
}

/** Parse after strict UTF-8 decoding and before any canonicalization.
 * Duplicate property names (including Unicode escape aliases) are rejected.
 */
export function parseStrictHcsJsonV1(value: Uint8Array | string, maxBytes: number): unknown {
  let text: string;
  try {
    text = typeof value === "string" ? value : new TextDecoder("utf-8", { fatal: true }).decode(value);
  } catch { return invalid("JSON_INVALID"); }
  if (Buffer.byteLength(text, "utf8") > maxBytes) return invalid("JSON_TOO_LARGE");
  let result: unknown;
  try { result = JSON.parse(text); } catch { return invalid("JSON_INVALID"); }
  // JSON.parse silently retains the last occurrence of duplicate keys. Check the
  // source independently instead of canonically hashing an ambiguous object.
  let index = 0;
  const space = () => { while (index < text.length && /\s/.test(text[index]!)) index++; };
  const quoted = (): string => {
    const start = index++;
    while (index < text.length) {
      if (text[index] === "\\") { index += 2; continue; }
      if (text[index++] === '"') return JSON.parse(text.slice(start, index)) as string;
    }
    return invalid("JSON_INVALID");
  };
  let nodes = 0;
  const visit = (depth: number): void => {
    if (++nodes > 100_000 || depth > 64) return invalid("JSON_TOO_LARGE");
    space();
    if (text[index] === "{") {
      index++; space();
      const keys = new Set<string>();
      while (text[index] !== "}") {
        const key = quoted();
        if (keys.has(key)) return invalid("JSON_AMBIGUOUS");
        keys.add(key); space();
        if (text[index++] !== ":") return invalid("JSON_INVALID");
        visit(depth + 1); space();
        if (text[index] !== ",") break;
        index++; space();
      }
      if (text[index++] !== "}") return invalid("JSON_INVALID");
    } else if (text[index] === "[") {
      index++; space();
      while (text[index] !== "]") {
        visit(depth + 1); space();
        if (text[index] !== ",") break;
        index++; space();
      }
      if (text[index++] !== "]") return invalid("JSON_INVALID");
    } else if (text[index] === '"') {
      quoted();
    } else {
      while (index < text.length && !/[\s,}\]]/.test(text[index]!)) index++;
    }
  };
  visit(0); space();
  if (index !== text.length) return invalid("JSON_INVALID");
  return result;
}

export function cloneHcsJsonV1<T>(item: T): T {
  // Safe only after successful canonicalization; stringification gives a fresh,
  // JSON-native tree and leaves caller-owned objects and nested arrays untouched.
  return JSON.parse(JSON.stringify(item)) as T;
}
