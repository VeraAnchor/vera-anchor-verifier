import { describe, expect, it, vi } from "vitest";
import {
  Hcs2V1Error, parseHcs2MemoV1, parseHcs2RegisterV1, verifyHcs2RegisterV1,
} from "../../src/standards/hcs/hcs2V1.js";
import { resolveHcs2RegisterV1 } from "../../src/resolvers/hcs2MirrorV1.js";

const registry = "0.0.10791100";
const target = "0.0.10765268";
const network = "testnet" as const;
const sequence = 42;
const memo = "hcs-2:0:86400";
const raw = (overrides: Record<string, unknown> = {}): Uint8Array =>
  Buffer.from(JSON.stringify({ p: "hcs-2", op: "register", t_id: target, ...overrides }));
const request = () => ({ hedera_network: network, registry_topic_id: registry,
  sequence_number: sequence, expected_t_id: target });
const mirrorBase = "https://testnet.mirrornode.hedera.com/api/v1";
const topicRow = () => ({ topic_id: registry, memo });
const messageRow = () => ({ topic_id: registry, sequence_number: sequence,
  consensus_timestamp: "1792039124.000000003", message: Buffer.from(raw()).toString("base64") });

function mockMirror(topic: unknown = topicRow(), message: unknown = messageRow()): typeof fetch {
  return vi.fn(async (url: string | URL | Request) => {
    const address = String(url);
    if (address === `${mirrorBase}/topics/${registry}`) return Response.json(topic);
    if (address === `${mirrorBase}/topics/${registry}/messages/${sequence}`) return Response.json(message);
    throw new Error(`Unexpected request: ${address}`);
  }) as unknown as typeof fetch;
}

describe("pinned HCS-2 offline register", () => {
  it("parses indexed/non-indexed memo with precise ttl boundaries", () => {
    expect(parseHcs2MemoV1(" hcs-2:0:86400 ")).toEqual({ memo, indexed: true, ttl: 86400 });
    expect(parseHcs2MemoV1("hcs-2:1:0")).toMatchObject({ indexed: false, ttl: 0 });
    expect(parseHcs2MemoV1("hcs-2:1:31536000")).toMatchObject({ ttl: 31536000 });
    expect(() => parseHcs2MemoV1("hcs-2:0:31536001")).toThrow("HCS2_TTL_INVALID");
    expect(() => parseHcs2MemoV1("hcs-2:2:10")).toThrow("HCS2_MEMO_INVALID");
    expect(() => parseHcs2MemoV1("HCS-2:0:10")).toThrow("HCS2_MEMO_INVALID");
  });

  it("validates a register without inventing an independently expected target", () => {
    const parsed = verifyHcs2RegisterV1({ memo, message: raw() });
    expect(parsed).toMatchObject({ status: "pass", reason_code: null,
      target_match: "not_checked", register: { t_id: target } });
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed.register)).toBe(true);
  });

  it("compares a caller-supplied target and detects substitution", () => {
    expect(verifyHcs2RegisterV1({ memo, message: raw(), expected_t_id: target }))
      .toMatchObject({ status: "pass", target_match: "match" });
    expect(verifyHcs2RegisterV1({ memo, message: raw(), expected_t_id: "0.0.999" }))
      .toMatchObject({ status: "fail", reason_code: "HCS2_TARGET_MISMATCH", target_match: "mismatch" });
  });

  it("accepts reordered keys and trims legal optional text", () => {
    const obj = JSON.stringify({ m: " test ", metadata: " hcs://1/0.0.5 ",
      t_id: ` ${target} `, op: "register", p: "hcs-2" });
    expect(parseHcs2RegisterV1(obj)).toEqual({ p: "hcs-2", op: "register", t_id: target,
      metadata: "hcs://1/0.0.5", m: "test" });
    expect(parseHcs2RegisterV1(raw({ metadata: "   ", m: "" }))).toEqual({
      p: "hcs-2", op: "register", t_id: target,
    });
  });

  it.each([
    ["unsupported update", { op: "update" }, "HCS2_OPERATION_INVALID"],
    ["unexpected field", { injected: "yes" }, "HCS2_MESSAGE_INVALID"],
    ["invalid topic", { t_id: "1.0.123" }, "HCS2_TOPIC_INVALID"],
    ["control character", { m: "has\nline" }, "HCS2_TEXT_INVALID"],
    ["non-string metadata", { metadata: 1 }, "HCS2_MESSAGE_INVALID"],
    ["nested value", { metadata: { url: "https://example.com" } }, "HCS2_MESSAGE_INVALID"],
  ])("rejects %s", (_name: string, fields: Record<string, unknown>, reason: string) => {
    expect(verifyHcs2RegisterV1({ memo, message: raw(fields) }).reason_code).toBe(reason);
  });

  it("rejects ambiguous duplicate keys, even when one is escaped", () => {
    const payload = `{"p":"hcs-2","op":"register","t_id":"${target}","t_id":"0.0.999"}`;
    expect(verifyHcs2RegisterV1({ memo, message: payload })).toMatchObject({
      status: "fail", reason_code: "HCS2_MESSAGE_INVALID",
    });
    const escaped = `{"p":"hcs-2","op":"register","t_id":"${target}","t_\\u0069d":"0.0.999"}`;
    expect(verifyHcs2RegisterV1({ memo, message: escaped }).reason_code).toBe("HCS2_MESSAGE_INVALID");
  });

  it("enforces the 1024-byte message ceiling and invalid UTF-8", () => {
    expect(verifyHcs2RegisterV1({ memo, message: raw({ metadata: "x".repeat(962) }) }).reason_code)
      .toBe("HCS2_MESSAGE_TOO_LARGE");
    expect(verifyHcs2RegisterV1({ memo, message: new Uint8Array([123, 255, 125]) }).reason_code)
      .toBe("HCS2_MESSAGE_INVALID");
  });

  it("exports a stable typed HCS-2 input validation error", () => {
    expect(() => parseHcs2RegisterV1(Buffer.from("[]"))).toThrow(Hcs2V1Error);
  });
});

describe("HCS-2 exact historical Hedera Mirror observation", () => {
  it("reads one network-scoped topic and exact message; validates the independently expected target", async () => {
    const fetch_impl = mockMirror();
    const result = await resolveHcs2RegisterV1({ fetch_impl }, request());
    expect(result).toMatchObject({ status: "resolved", reason_code: null,
      hedera_network: network, registry_topic_id: registry, sequence_number: sequence,
      consensus_timestamp: "1792039124.000000003",
      verification: { target_match: "match", register: { t_id: target } } });
    expect(fetch_impl).toHaveBeenCalledTimes(2);
    for (const [url, options] of (fetch_impl as ReturnType<typeof vi.fn>).mock.calls) {
      expect(url).toMatch(/^https:\/\/testnet\.mirrornode\.hedera\.com\/api\/v1\/topics\//);
      expect(options).toMatchObject({ method: "GET", redirect: "error", credentials: "omit" });
    }
  });

  it("accepts a base64-encoded Mirror memo and preserves indexed/ttl semantics", async () => {
    const encoded = Buffer.from(memo).toString("base64");
    const result = await resolveHcs2RegisterV1({ fetch_impl: mockMirror({ ...topicRow(), memo: encoded }) }, request());
    expect(result.verification?.memo).toEqual({ memo, indexed: true, ttl: 86400 });
  });

  it("distinguishes a wrong target from malformed registry material", async () => {
    const result = await resolveHcs2RegisterV1({ fetch_impl: mockMirror() },
      { ...request(), expected_t_id: "0.0.999" });
    expect(result).toMatchObject({ status: "conflict", reason_code: "HCS2_TARGET_MISMATCH" });
    const malformed = await resolveHcs2RegisterV1({ fetch_impl: mockMirror(topicRow(), {
      ...messageRow(), message: Buffer.from(raw({ op: "delete" })).toString("base64"),
    }) }, request());
    expect(malformed).toMatchObject({ status: "invalid", reason_code: "HCS2_OPERATION_INVALID" });
  });

  it("rejects wrong topic, wrong sequence and chunked message claims", async () => {
    for (const row of [
      { ...messageRow(), topic_id: "0.0.999" },
      { ...messageRow(), sequence_number: sequence + 1 },
      { ...messageRow(), chunk_info: { total: 2, number: 1 } },
    ]) {
      expect(await resolveHcs2RegisterV1({ fetch_impl: mockMirror(topicRow(), row) }, request()))
        .toMatchObject({ status: "invalid", reason_code: "HCS2_MESSAGE_SCOPE_INVALID" });
    }
  });

  it("distinguishes 404 missing and 429 rate limit from invalid observed evidence", async () => {
    expect(await resolveHcs2RegisterV1({ fetch_impl: async () => new Response(null, { status: 404 }) }, request()))
      .toMatchObject({ status: "unavailable", reason_code: "HCS2_REGISTRY_NOT_FOUND" });
    expect(await resolveHcs2RegisterV1({ fetch_impl: async () => new Response(null, { status: 429 }) }, request()))
      .toMatchObject({ status: "unavailable", reason_code: "HCS2_MIRROR_RATE_LIMITED" });
  });

  it("rejects unsupported Mirror base URLs and invalid locators before fetching", async () => {
    const fetch_impl = vi.fn();
    await expect(resolveHcs2RegisterV1({ fetch_impl }, { ...request(), registry_topic_id: "0.0.5/../../private" }))
      .rejects.toThrow("HCS2_REGISTRY_LOCATOR_INVALID");
    await expect(resolveHcs2RegisterV1({ fetch_impl, base_urls: { testnet: "http://example.com/api/v1" } }, request()))
      .rejects.toThrow("HCS2_MIRROR_BASE_URL_INVALID");
    expect(fetch_impl).not.toHaveBeenCalled();
  });

  it("does not treat Mirror corroboration as authenticated consensus or current registry state", async () => {
    const out = await resolveHcs2RegisterV1({ fetch_impl: mockMirror() },
      { hedera_network: network, registry_topic_id: registry, sequence_number: sequence });
    expect(out.status).toBe("resolved");
    expect(out.verification?.target_match).toBe("not_checked");
    expect(out).not.toHaveProperty("current_registry_state");
    expect(out).not.toHaveProperty("consensus_authenticated");
  });
});
