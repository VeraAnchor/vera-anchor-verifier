/** Pinned HCS-2 registry memo and historical register verification. Pure; no network I/O. */

const TOPIC_ID = /^0\.0\.[0-9]+$/;
const MEMO = /^hcs-2:(0|1):([0-9]+)$/;
const CONTROL = /[\u0000-\u001f\u007f]/;
const MAX_MESSAGE_BYTES = 1024;
const MAX_TTL = 31_536_000;
const ALLOWED_KEYS = new Set(["p", "op", "t_id", "metadata", "m"]);

export type Hcs2V1Memo = Readonly<{
  memo: string;
  indexed: boolean;
  ttl: number;
}>;

export type Hcs2V1Register = Readonly<{
  p: "hcs-2";
  op: "register";
  t_id: string;
  metadata?: string;
  m?: string;
}>;

export type Hcs2V1VerificationInput = Readonly<{
  /** Unauthenticated in offline mode, unless independently established by caller. */
  memo: unknown;
  /** Original registry message bytes. A single register operation is supported. */
  message: string | Uint8Array;
  /** Independent relying-party expectation, not extracted from the register itself. */
  expected_t_id?: string | null;
}>;

export type Hcs2V1VerificationResult = Readonly<{
  status: "pass" | "fail";
  reason_code: string | null;
  memo: Hcs2V1Memo | null;
  register: Hcs2V1Register | null;
  target_match: "match" | "not_checked" | "mismatch";
}>;

export class Hcs2V1Error extends Error {
  constructor(readonly code: string) { super(code); this.name = "Hcs2V1Error"; }
}

function invalid(code: string): never { throw new Hcs2V1Error(code); }

export function parseHcs2MemoV1(value: unknown): Hcs2V1Memo {
  if (typeof value !== "string" || value.length > 256) invalid("HCS2_MEMO_INVALID");
  const memo = value.trim();
  const match = MEMO.exec(memo);
  if (!match) invalid("HCS2_MEMO_INVALID");
  const ttl = Number(match[2]);
  if (!Number.isSafeInteger(ttl) || ttl > MAX_TTL) invalid("HCS2_TTL_INVALID");
  return Object.freeze({ memo, indexed: match[1] === "0", ttl });
}

function topicId(value: unknown): string {
  if (typeof value !== "string" || value.length > 128 || !TOPIC_ID.test(value.trim())) {
    invalid("HCS2_TOPIC_INVALID");
  }
  return value.trim();
}

function optionalText(value: unknown, max: number): string | null {
  if (value == null) return null;
  if (typeof value !== "string") invalid("HCS2_TEXT_INVALID");
  const text = value.trim();
  if (!text) return null;
  if (text.length > max || CONTROL.test(text)) invalid("HCS2_TEXT_INVALID");
  return text;
}

/** Scan JSON strings to reject ambiguous duplicate top-level keys (including escaped aliases). */
function readString(text: string, offset: number): { value: string; end: number } {
  if (text[offset] !== '"') invalid("HCS2_MESSAGE_INVALID");
  let end = offset + 1;
  while (end < text.length) {
    if (text[end] === "\\") { end += 2; continue; }
    if (text[end] === '"') {
      let value: unknown;
      try { value = JSON.parse(text.slice(offset, end + 1)); }
      catch { invalid("HCS2_MESSAGE_INVALID"); }
      if (typeof value !== "string") invalid("HCS2_MESSAGE_INVALID");
      return { value, end: end + 1 };
    }
    end++;
  }
  return invalid("HCS2_MESSAGE_INVALID");
}

function parseFlatRegister(message: unknown): Record<string, unknown> {
  if (!(message instanceof Uint8Array) && typeof message !== "string") {
    invalid("HCS2_MESSAGE_INVALID");
  }
  if (typeof message === "string" && message.length > MAX_MESSAGE_BYTES) {
    invalid("HCS2_MESSAGE_TOO_LARGE");
  }
  const bytes = typeof message === "string" ? Buffer.from(message, "utf8") : message;
  if (bytes.byteLength > MAX_MESSAGE_BYTES) invalid("HCS2_MESSAGE_TOO_LARGE");
  if (bytes.byteLength < 2) invalid("HCS2_MESSAGE_INVALID");
  let text: string;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { invalid("HCS2_MESSAGE_INVALID"); }
  let json: unknown;
  try { json = JSON.parse(text); }
  catch { invalid("HCS2_MESSAGE_INVALID"); }
  if (!json || typeof json !== "object" || Array.isArray(json)) invalid("HCS2_MESSAGE_INVALID");
  // All supported register values are strings or optional null. Reject nested
  // objects, ambiguous duplicate properties, and non-string coercions.
  let i = 0;
  const skip = () => { while (/\s/.test(text[i] ?? "") && i < text.length) i++; };
  skip();
  if (text[i++] !== "{") invalid("HCS2_MESSAGE_INVALID");
  const seen = new Set<string>();
  skip();
  if (text[i] === "}") invalid("HCS2_MESSAGE_INVALID");
  while (i < text.length) {
    skip();
    const key = readString(text, i);
    if (seen.has(key.value) || !ALLOWED_KEYS.has(key.value)) invalid("HCS2_MESSAGE_INVALID");
    seen.add(key.value);
    i = key.end;
    skip();
    if (text[i++] !== ":") invalid("HCS2_MESSAGE_INVALID");
    skip();
    if (text[i] === '"') {
      i = readString(text, i).end;
    } else if (text.slice(i, i + 4) === "null") {
      i += 4;
    } else {
      invalid("HCS2_MESSAGE_INVALID");
    }
    skip();
    if (text[i] === "}") { i++; break; }
    if (text[i++] !== ",") invalid("HCS2_MESSAGE_INVALID");
  }
  skip();
  if (i !== text.length) invalid("HCS2_MESSAGE_INVALID");
  return json as Record<string, unknown>;
}

export function parseHcs2RegisterV1(message: unknown): Hcs2V1Register {
  const record = parseFlatRegister(message);
  if (record.p !== "hcs-2" || record.op !== "register") invalid("HCS2_OPERATION_INVALID");
  const t_id = topicId(record.t_id);
  const metadata = optionalText(record.metadata, 4096);
  const m = optionalText(record.m, 500);
  // The pinned publisher's 1024-byte ceiling applies to the normalized wire form.
  const normalized = { p: "hcs-2" as const, op: "register" as const, t_id,
    ...(metadata === null ? {} : { metadata }), ...(m === null ? {} : { m }) };
  if (Buffer.byteLength(JSON.stringify(normalized), "utf8") > MAX_MESSAGE_BYTES) {
    invalid("HCS2_MESSAGE_TOO_LARGE");
  }
  return Object.freeze(normalized);
}

export function verifyHcs2RegisterV1(input: Hcs2V1VerificationInput): Hcs2V1VerificationResult {
  let memo: Hcs2V1Memo | null = null;
  let register: Hcs2V1Register | null = null;
  try {
    memo = parseHcs2MemoV1(input?.memo);
    register = parseHcs2RegisterV1(input?.message);
    if (input.expected_t_id != null && topicId(input.expected_t_id) !== register.t_id) {
      return Object.freeze({ status: "fail", reason_code: "HCS2_TARGET_MISMATCH", memo,
        register, target_match: "mismatch" });
    }
    return Object.freeze({ status: "pass", reason_code: null, memo, register,
      target_match: input.expected_t_id == null ? "not_checked" : "match" });
  } catch (error) {
    if (!(error instanceof Hcs2V1Error)) throw error;
    return Object.freeze({ status: "fail", reason_code: error.code, memo, register,
      target_match: "not_checked" });
  }
}
