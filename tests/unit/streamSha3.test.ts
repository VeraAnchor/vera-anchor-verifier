import { Readable } from "node:stream";
import { describe, expect, it } from "vitest";
import {
  sha3_512Stream,
  verifySha3_512Stream,
} from "../../src/crypto/streamSha3.js";

// SHA3-512 reference digests calculated independently with Python hashlib.
const EMPTY =
  "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
const HELLO =
  "75d527c368f2efe848ecf6b073a36767800805e9eef2b1857d5f984f036eb6df891d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84976";
const BINARY =
  "51c1025ca5a7078d97bf641c13cdf42c158eb29d0793f1e2f7b29a45068eb0ef209fcdb5133cc472a93a51ae720c1e2a22dd55831a4f37d8121fe9e351d1e976";
const EIGHT_MIB =
  "1bf3e211408bd201c4cae4d411b6d2e73cac7f6316d0a92226cb927529bd31db2163186ddea5930c12738fd645ef30c160b372552518ae4fdba4d1001466a288";

describe("streaming SHA3-512 artifact verification", () => {
  it("matches fixed empty and split-byte vectors", async () => {
    await expect(sha3_512Stream([])).resolves.toEqual({
      digest: EMPTY,
      bytes_hashed: 0,
    });
    await expect(
      sha3_512Stream([Buffer.from("he"), Buffer.alloc(0), Buffer.from("llo")]),
    ).resolves.toEqual({ digest: HELLO, bytes_hashed: 5 });
  });

  it("accepts async generators, Node streams, and exact binary bytes", async () => {
    async function* chunks(): AsyncGenerator<Uint8Array> {
      yield Uint8Array.of(0, 255);
      await Promise.resolve();
      yield Uint8Array.of(128, 5);
    }
    expect((await sha3_512Stream(chunks())).digest).toBe(BINARY);
    const nodeStream = Readable.from([Buffer.from("hel"), Buffer.from("lo")]);
    expect((await sha3_512Stream(nodeStream)).digest).toBe(HELLO);
  });

  it("processes an 8 MiB artifact incrementally without collecting all chunks", async () => {
    function* chunks(): Generator<Uint8Array> {
      const oneChunk = new Uint8Array(4096).fill(0x6d);
      for (let i = 0; i < 2048; i++) yield oneChunk;
    }
    const actual = await sha3_512Stream(chunks(), { max_bytes: 8 * 1024 * 1024 });
    expect(actual).toEqual({ digest: EIGHT_MIB, bytes_hashed: 8 * 1024 * 1024 });
  });

  it("verifies independent expected digest and expected byte count", async () => {
    await expect(
      verifySha3_512Stream({
        source: [Buffer.from("he"), Buffer.from("llo")],
        expected_digest: HELLO.toUpperCase(),
        expected_bytes: 5,
      }),
    ).resolves.toEqual({
      outcome: "pass",
      reason_code: null,
      expected_digest: HELLO,
      computed_digest: HELLO,
      bytes_hashed: 5,
    });
  });

  it("reports tampered content rather than a false pass", async () => {
    await expect(
      verifySha3_512Stream({
        source: [Buffer.from("HELLO")],
        expected_digest: HELLO,
      }),
    ).resolves.toMatchObject({
      outcome: "fail",
      reason_code: "DIGEST_MISMATCH",
      expected_digest: HELLO,
      bytes_hashed: 5,
    });
  });

  it("detects expected-size disagreement even when the digest matches", async () => {
    await expect(
      verifySha3_512Stream({
        source: [Buffer.from("hello")],
        expected_digest: HELLO,
        expected_bytes: 6,
      }),
    ).resolves.toMatchObject({
      outcome: "fail",
      reason_code: "BYTE_COUNT_MISMATCH",
      computed_digest: HELLO,
    });
  });

  it("enforces configured byte limits without returning a partial digest", async () => {
    await expect(
      sha3_512Stream([Uint8Array.of(1, 2), Uint8Array.of(3)], {
        max_bytes: 2,
      }),
    ).rejects.toThrow(RangeError);
    await expect(
      sha3_512Stream([], { max_bytes: Number.POSITIVE_INFINITY }),
    ).rejects.toThrow(TypeError);
    await expect(sha3_512Stream([], { max_bytes: -1 })).rejects.toThrow(
      TypeError,
    );
  });

  it("rejects invalid digests and invalid expected byte counts before reading", async () => {
    let reads = 0;
    function* source(): Generator<Uint8Array> {
      reads++;
      yield Buffer.from("hello");
    }
    await expect(
      verifySha3_512Stream({ source: source(), expected_digest: "bad" }),
    ).rejects.toThrow(TypeError);
    await expect(
      verifySha3_512Stream({
        source: source(),
        expected_digest: HELLO,
        expected_bytes: 1.5,
      }),
    ).rejects.toThrow(TypeError);
    expect(reads).toBe(0);
  });

  it("rejects non-byte chunks and upstream stream errors", async () => {
    await expect(
      sha3_512Stream(["hello"] as unknown as Iterable<Uint8Array>),
    ).rejects.toThrow(TypeError);
    async function* broken(): AsyncGenerator<Uint8Array> {
      yield Buffer.from("hello");
      throw new Error("source read failed");
    }
    await expect(sha3_512Stream(broken())).rejects.toThrow("source read failed");
  });
});
