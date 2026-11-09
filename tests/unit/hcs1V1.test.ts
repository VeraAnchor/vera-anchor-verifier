
import { createHash } from "node:crypto";
import { compress as zstdCompress, decompress as zstdDecompress } from "@mongodb-js/zstd";
import { describe, expect, it, vi } from "vitest";
import {
  parseHcs1ReferenceV1, verifyHcs1ContentV1,
  type Hcs1V1ContentOptions,
} from "../../src/standards/hcs/hcs1V1.js";
import { resolveHcs1FileV1 } from "../../src/resolvers/hcs1MirrorV1.js";

const topic = "0.0.10765268";
const reference = `hcs://1/${topic}`;
const mirror = "https://testnet.mirrornode.hedera.com/api/v1";
const content = Buffer.from('{"name":"SAGE","version":"1.0.0"}');
const sha256 = createHash("sha256").update(content).digest("hex");
const memo = `${sha256}:zstd:base64`;

const decodeOptions: Hcs1V1ContentOptions = {
  decompress_zstd: async (compressed) =>
    new Uint8Array(await zstdDecompress(Buffer.from(compressed))),
};

const chunk = (o: number, c: string): Uint8Array =>
  Buffer.from(JSON.stringify({ o, c }));

async function fixture() {
  const compressed = await zstdCompress(content, 10);
  const base64 = compressed.toString("base64");
  const first = chunk(0, `data:application/json;base64,${base64.slice(0, 8)}`);
  const second = chunk(1, base64.slice(8));

  const input = () => ({ memo, messages: [first, second] });

  const topicJson = () => ({
    topic_id: topic,
    memo,
    submit_key: { key: "present" },
    admin_key: null,
  });

  const messagesJson = () => ({
    messages: [
      { topic_id: topic, sequence_number: 1, message: Buffer.from(first).toString("base64") },
      { topic_id: topic, sequence_number: 2, message: Buffer.from(second).toString("base64") },
    ],
    links: { next: null },
  });

  function mirrorFetch(): typeof fetch {
    return vi.fn(async (url: string | URL | Request) => {
      const u = String(url);
      if (u === `${mirror}/topics/${topic}`) return Response.json(topicJson());
      if (u.startsWith(`${mirror}/topics/${topic}/messages?`)) return Response.json(messagesJson());
      throw Error(`Unexpected Mirror URL: ${u}`);
    }) as unknown as typeof fetch;
  }

  return { first, second, input, topicJson, messagesJson, mirrorFetch };
}

type TestFixture = Awaited<ReturnType<typeof fixture>>;

describe("pinned HCS-1 v1 integrity", () => {
  it("reassembles out-of-order supplied chunks and verifies SHA-256", async () => {
    const f = await fixture();
    const out = await verifyHcs1ContentV1({
      memo,
      messages: [f.second, f.first],
      expected_sha256: sha256,
    }, decodeOptions);

    expect(out).toMatchObject({
      status: "pass",
      reason_code: null,
      sha256,
      chunk_count: 2,
      mime_type: "application/json",
    });
    expect(Buffer.from(out.bytes!)).toEqual(content);
  });

  const invalidCases: ReadonlyArray<readonly [
    string,
    (f: TestFixture) => readonly Uint8Array[],
    (f: TestFixture) => string,
    string,
  ]> = [
    ["duplicate order", (f) => [f.first, f.first], () => memo, "HCS1_CHUNK_DUPLICATE"],
    ["missing first chunk", (f) => [f.second], () => memo, "HCS1_CHUNK_GAP"],
    ["incorrect memo", (f) => [f.first, f.second],
      () => `${"a".repeat(64)}:zstd:base64`, "HCS1_CHECKSUM_MISMATCH"],
    ["extra chunk field", () => [
      Buffer.from(JSON.stringify({
        o: 0,
        c: "data:application/json;base64,AAAA",
        injected: true,
      })),
    ], () => memo, "HCS1_CHUNK_INVALID"],
  ];

  for (const [label, getMessages, getMemo, reason] of invalidCases) {
    it(`rejects ${label}`, async () => {
      const f = await fixture();
      const out = await verifyHcs1ContentV1({
        messages: getMessages(f),
        memo: getMemo(f),
      }, decodeOptions);

      expect(out.reason_code).toBe(reason);
    });
  }

  it("detects expected checksum mismatch and bounded decompression", async () => {
    const f = await fixture();

    expect((await verifyHcs1ContentV1({
      ...f.input(),
      expected_sha256: "a".repeat(64),
    }, decodeOptions)).reason_code).toBe("HCS1_EXPECTED_CHECKSUM_MISMATCH");

    expect((await verifyHcs1ContentV1(f.input(), {
      ...decodeOptions,
      max_file_bytes: 4,
    })).reason_code).toBe("HCS1_FILE_TOO_LARGE");
  });

  it("never resolves arbitrary or cross-standard content references", () => {
    expect(parseHcs1ReferenceV1(reference).topic_id).toBe(topic);
    expect(() => parseHcs1ReferenceV1("https://example.com/private")).toThrow();
    expect(() => parseHcs1ReferenceV1("hcs://13/0.0.100#1")).toThrow();
  });
});

describe("independent HCS-1 Mirror resolution", () => {
  it("fetches a fixed network-scoped topic, verifies its chunks, and returns bytes", async () => {
    const f = await fixture();
    const fetch_impl = f.mirrorFetch();

    const out = await resolveHcs1FileV1(
      { fetch_impl },
      { reference, network: "testnet", expected_sha256: sha256 },
      decodeOptions,
    );

    expect(out).toMatchObject({
      status: "resolved",
      reason_code: null,
      hedera_network: "testnet",
    });
    expect(out.verification?.sha256).toBe(sha256);
    expect(Buffer.from(out.verification?.bytes ?? [])).toEqual(content);
    expect(fetch_impl).toHaveBeenCalledTimes(2);

    for (const [url, options] of (fetch_impl as ReturnType<typeof vi.fn>).mock.calls) {
      expect(url).toMatch(/^https:\/\/testnet\.mirrornode\.hedera\.com\/api\/v1\/topics\//);
      expect(options).toMatchObject({
        method: "GET",
        redirect: "error",
        credentials: "omit",
      });
    }
  });

  it("rejects cross-origin pagination instead of fetching injected URLs", async () => {
    const f = await fixture();

    const fetch_impl = vi.fn(async (url: string) => Response.json(
      url.includes("/messages?")
        ? { ...f.messagesJson(), links: { next: "https://evil.example/private" } }
        : f.topicJson(),
    )) as unknown as typeof fetch;

    const out = await resolveHcs1FileV1(
      { fetch_impl },
      { reference, network: "testnet" },
      decodeOptions,
    );

    expect(out).toMatchObject({
      status: "invalid",
      reason_code: "HCS1_MIRROR_PAGINATION_INVALID",
    });
    expect(fetch_impl).toHaveBeenCalledTimes(2);
  });

  it("distinguishes not found, corrupt HCS topic metadata, and bad chunk content", async () => {
    const f = await fixture();

    const absent = await resolveHcs1FileV1(
      { fetch_impl: async () => new Response(null, { status: 404 }) },
      { reference, network: "testnet" },
      decodeOptions,
    );
    expect(absent.status).toBe("unavailable");

    const mutable = await resolveHcs1FileV1(
      {
        fetch_impl: async () => Response.json({
          ...f.topicJson(),
          admin_key: { key: "present" },
        }),
      },
      { reference, network: "testnet" },
      decodeOptions,
    );
    expect(mutable).toMatchObject({
      status: "invalid",
      reason_code: "HCS1_TOPIC_METADATA_INVALID",
    });

    const tampered = await resolveHcs1FileV1(
      {
        fetch_impl: async (url) => Response.json(
          String(url).includes("/messages?")
            ? {
                ...f.messagesJson(),
                messages: [{
                  topic_id: topic,
                  sequence_number: 1,
                  message: Buffer.from(
                    chunk(0, "data:application/json;base64,AAAA"),
                  ).toString("base64"),
                }],
              }
            : f.topicJson(),
        ),
      },
      { reference, network: "testnet" },
      decodeOptions,
    );
    expect(tampered.status).toBe("invalid");
  });
});
