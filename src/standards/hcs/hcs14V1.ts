/** Pinned HCS-14 Draft: deterministic DID-backed UAID checks (uaid:did only).
 *  Structural consistency does not authenticate DID control or a Hedera account.
 */
const DID = /^did:([a-z0-9]+):(.+)$/;
const PREFIX = "uaid:did:";
const ORDER = ["uid", "registry", "proto", "nativeId", "domain", "src"] as const;
const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
type Parameter = (typeof ORDER)[number];
export type Hcs14DidUaidV1 = Readonly<{
  uaid: string;
  target: "did";
  id: string;
  params: Readonly<Partial<Record<Parameter, string>>>;
}>;
export type Hcs14BindingV1Result = Readonly<{
  status: "pass" | "fail";
  reason_code: string | null;
  /** Consistency of supplied values only; NOT DID controller authentication. */
  binding: Hcs14DidUaidV1 | null;
}>;
export class Hcs14V1Error extends Error {
  constructor(readonly code: string) { super(code); this.name = "Hcs14V1Error"; }
}
function fail(code: string): never { throw new Hcs14V1Error(code); }
function text(value: unknown, _name: string, max: number): string {
  if (typeof value !== "string" || !value.trim() || value.trim().length > max ||
      /[\u0000-\u001f\u007f;]/.test(value)) return fail("HCS14_FIELD_INVALID");
  return value.trim();
}
function didParts(value: unknown): { did: string; id: string; sanitized: boolean } {
  if (typeof value !== "string") return fail("HCS14_DID_INVALID");
  const did = value.trim();
  const match = DID.exec(did);
  if (!match) return fail("HCS14_DID_INVALID");
  const methodSpecificId = match[2]!;
  const cut = methodSpecificId.search(/[;?#]/);
  const id = cut < 0 ? methodSpecificId : methodSpecificId.slice(0, cut);
  if (!id || id.includes(";")) return fail("HCS14_DID_ID_INVALID");
  return { did, id, sanitized: cut >= 0 };
}
function base58encode(bytes: Uint8Array): string {
  let leading = 0;
  while (leading < bytes.length && bytes[leading] === 0) leading++;
  let n = 0n;
  for (const value of bytes) n = (n << 8n) + BigInt(value);
  let out = "";
  while (n > 0n) { out = ALPHABET[Number(n % 58n)]! + out; n /= 58n; }
  return `z${"1".repeat(leading)}${out || (leading ? "" : "1")}`;
}
function base58decode(input: string): Uint8Array {
  if (!/^z[1-9A-HJ-NP-Za-km-z]+$/.test(input)) return fail("HCS14_SRC_INVALID");
  const encoded = input.slice(1);
  let leading = 0;
  while (leading < encoded.length && encoded[leading] === "1") leading++;
  let n = 0n;
  for (const c of encoded) { const digit = ALPHABET.indexOf(c); if (digit < 0) return fail("HCS14_SRC_INVALID"); n = n * 58n + BigInt(digit); }
  const reversed: number[] = [];
  while (n > 0n) { reversed.push(Number(n & 255n)); n >>= 8n; }
  reversed.reverse();
  const result = Uint8Array.from([...Array<number>(leading).fill(0), ...reversed]);
  if (base58encode(result) !== input) return fail("HCS14_SRC_INVALID");
  return result;
}

export function parseHcs14DidUaidV1(value: unknown): Hcs14DidUaidV1 {
  if (typeof value !== "string") return fail("HCS14_UAID_INVALID");
  if (value.length > 8192) return fail("HCS14_UAID_INVALID");
  const uaid = value.trim();
  if (!uaid.startsWith(PREFIX)) {
    return fail(uaid.startsWith("uaid:aid:") ? "HCS14_TARGET_UNSUPPORTED" : "HCS14_UAID_INVALID");
  }
  if (uaid.length > 8192) return fail("HCS14_UAID_INVALID");
  const body = uaid.slice(PREFIX.length);
  const pos = body.indexOf(";");
  if (pos < 1) return fail("HCS14_UAID_INVALID");
  const id = body.slice(0, pos);
  if (/[\u0000-\u001f\u007f]/.test(id)) return fail("HCS14_UAID_INVALID");
  const rawParams = body.slice(pos + 1).split(";");
  const params: Partial<Record<Parameter, string>> = {};
  const seen: Parameter[] = [];
  for (const entry of rawParams) {
    const eq = entry.indexOf("=");
    if (eq <= 0) return fail("HCS14_PARAMETER_INVALID");
    const key = entry.slice(0, eq) as Parameter;
    if (!ORDER.includes(key) || Object.prototype.hasOwnProperty.call(params, key)) {
      return fail("HCS14_PARAMETER_INVALID");
    }
    // The pinned parser accepts up to 512 chars for every parameter except nativeId.
    const limit = key === "nativeId" ? 2048 : 512;
    const value = text(entry.slice(eq + 1), key, limit);
    params[key] = value;
    seen.push(key);
  }
  if (seen.join("\0") !== ORDER.filter((key) => params[key] !== undefined).join("\0")) {
    return fail("HCS14_PARAMETER_ORDER_INVALID");
  }
  for (const key of ["uid", "registry", "proto", "nativeId"] as const) {
    if (!params[key]) return fail("HCS14_PARAMETER_MISSING");
  }
  return Object.freeze({ uaid, target: "did", id, params: Object.freeze(params) });
}

/** Build a deterministic UAID for supplied DID material; this does not issue an identity. */
export function buildHcs14DidUaidV1(input: Readonly<{
  base_did: string; uid?: string; registry?: string; proto: string; native_id: string; domain?: string | null;
}>): Hcs14DidUaidV1 {
  const did = didParts(input.base_did);
  const params: Partial<Record<Parameter, string>> = {
    uid: text(input.uid ?? "0", "uid", 256),
    registry: text(input.registry ?? "self", "registry", 128),
    proto: text(input.proto, "proto", 64),
    nativeId: text(input.native_id, "nativeId", 2048),
  };
  if (input.domain != null && input.domain.trim()) params.domain = text(input.domain, "domain", 253);
  if (did.sanitized) params.src = base58encode(Buffer.from(did.did, "utf8"));
  return parseHcs14DidUaidV1(`${PREFIX}${did.id};${ORDER.filter((k) => params[k] !== undefined).map((k) => `${k}=${params[k]}`).join(";")}`);
}

/** Compare against a separately supplied base DID. This does not resolve or authenticate it. */
export function verifyHcs14DidBindingV1(input: Readonly<{ uaid: unknown; base_did: unknown }>): Hcs14BindingV1Result {
  let binding: Hcs14DidUaidV1 | null = null;
  try {
    binding = parseHcs14DidUaidV1(input?.uaid);
    const did = didParts(input?.base_did);
    if (binding.id !== did.id) return fail("HCS14_DID_BINDING_MISMATCH");
    const src = binding.params.src;
    if (did.sanitized) {
      if (!src) return fail("HCS14_SRC_REQUIRED");
      const bytes = base58decode(src);
      let recovered: string;
      try { recovered = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
      catch { return fail("HCS14_SRC_INVALID"); }
      if (recovered !== did.did) return fail("HCS14_SRC_MISMATCH");
    } else if (src) return fail("HCS14_SRC_UNEXPECTED");
    return Object.freeze({ status: "pass", reason_code: null, binding });
  } catch (error) {
    if (error instanceof Hcs14V1Error) return Object.freeze({ status: "fail", reason_code: error.code, binding });
    throw error;
  }
}
