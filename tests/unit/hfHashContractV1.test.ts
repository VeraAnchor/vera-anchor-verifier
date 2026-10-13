import { describe, expect, it } from "vitest";
import {
  HF_V1_CANONICAL_JSON_ID,
  HF_V1_CONTRACT_ID,
  HF_V1_FRAME_ID,
  canonicalizeHfV1Json,
  frameHfV1,
  hashHfV1,
  verifyHfV1Digest,
  type HfV1ExpectedCommitment,
} from "../../src/hf/hashContractV1.js";

// Fixed expected SHA3-512 digests computed from independent byte-level framing.
const EMPTY_RAW = "7dbfee3a6265a92819e8d0e6e8963c55d9d305512198a63064ac2bf777fb7be78ec2dbb17472647f577be01351724c3ff65f3eef6e5a87bfc77b43b87e884b7c";
const HELLO_WORLD = "c16d17a8302e20dc62a775944565a9c00bf411a645724d45bac0db70787f23c762e1d64910857c7626cb96b89eacf6434daa2b4c0d57fa82e9aae98b07687de8";
const JSON_DIGEST = "6b66909dfca1b4bc143cacd6f69f40806462a1f7e40cd4642f12205e5b89dc1206459bae4187524f8f8c7d42e3e11e219ddbc36ce55d783f1ab1bbd5d95675e5";
const DATASET_NODE = "9f8b4a38baec44d4b1b470c1c98912a0df74a67c34d20aabb2f3ff3ee28be6d9aeed1a29c312972a563ec973185f27d5cdd9f10bb656d317cf7ad6509c9d47da";
const INGEST_RAW = "4d218221d6fe9c4c96c0bf86f138ee8ed54edac69125b771db71fbf71cf683951dd6313e72a36dbc07ce10701f57ddf9037bd4ddffb7de964feaa600563897a8";

function expected(
  domain: string,
  material: HfV1ExpectedCommitment["material"],
  digest: string,
): HfV1ExpectedCommitment {
  return { key: "test", kind: "digest", contract: "hf-contract-v1", material, domain, digest };
}

describe("HF hash contract v1", () => {
  it("pins distinct, explicit contract identifiers", () => {
    expect(HF_V1_CONTRACT_ID).toBe("hf-contract-v1");
    expect(HF_V1_FRAME_ID).toBe("hf:frame:v1");
    expect(HF_V1_CANONICAL_JSON_ID).toBe("hf:canonical-json:v1");
  });

  it("serializes the exact big-endian framing byte format", () => {
    const framed = frameHfV1("a", Buffer.from([0, 255]));
    expect(Buffer.from(framed).toString("hex")).toBe(
      `${Buffer.from("hf:frame:v1", "utf8").toString("hex")}000001610000000200ff`,
    );
  });

  it("matches fixed framed SHA3-512 vectors for empty, binary and UTF-8 inputs", () => {
    expect(hashHfV1({ domain: "va:dataset:node:v1", material: "raw", bytes: new Uint8Array() })).toBe(EMPTY_RAW);
    expect(hashHfV1({ domain: "va:dataset:node:v1", material: "raw", bytes: new Uint8Array(128).fill(1) })).toBe(DATASET_NODE);
    expect(hashHfV1({ domain: "va:ingest:leaf:v1", material: "raw", bytes: Buffer.from("abc") })).toBe(INGEST_RAW);
    expect(hashHfV1({ domain: "example:test:v1", material: "utf8", text: "hello 🌎" })).toBe(HELLO_WORLD);
  });

  it("canonicalizes JSON with stable ordering and unchanged scalar encodings", () => {
    const value = { b: [true, null, "é"], a: 1 };
    expect(Buffer.from(canonicalizeHfV1Json(value)).toString("utf8")).toBe('{"a":1,"b":[true,null,"é"]}');
    expect(hashHfV1({ domain: "example:json:v1", material: "json", value })).toBe(JSON_DIGEST);
    expect(Buffer.from(canonicalizeHfV1Json({ z: -0, a: 7n })).toString("utf8")).toBe('{"a":"7","z":0}');
  });

  it("compares exact material, domain and expected digest", () => {
    const baseline = expected("va:ingest:leaf:v1", "raw", INGEST_RAW);
    expect(verifyHfV1Digest({ expected: baseline, evidence: { material: "raw", bytes: Buffer.from("abc") } })).toMatchObject({
      outcome: "pass",
      reason_code: null,
      expected_digest: INGEST_RAW,
      computed_digest: INGEST_RAW,
    });
    expect(verifyHfV1Digest({ expected: baseline, evidence: { material: "raw", bytes: Buffer.from("abd") } })).toMatchObject({
      outcome: "fail",
      reason_code: "DIGEST_MISMATCH",
    });
    expect(verifyHfV1Digest({ expected: baseline, evidence: { material: "utf8", text: "abc" } })).toMatchObject({
      outcome: "fail",
      reason_code: "HF_MATERIAL_MISMATCH",
      computed_digest: null,
    });
    expect(verifyHfV1Digest({ expected: { ...baseline, domain: "other:domain:v1" }, evidence: { material: "raw", bytes: Buffer.from("abc") } }).outcome).toBe("fail");
  });

  it("rejects coercive canonicalization and unsafe input structures", () => {
    expect(() => canonicalizeHfV1Json({ bad: undefined })).toThrow(TypeError);
    expect(() => canonicalizeHfV1Json({ bad: Number.NaN })).toThrow(TypeError);
    expect(() => canonicalizeHfV1Json(new Uint8Array([1]))).toThrow(TypeError);
    expect(() => canonicalizeHfV1Json(new Date())).toThrow(TypeError);
    expect(() => canonicalizeHfV1Json([,])).toThrow(TypeError);
    const shared = { value: 1 };
    expect(() => canonicalizeHfV1Json([shared, shared])).toThrow(TypeError);
    const circular: { self?: unknown } = {};
    circular.self = circular;
    expect(() => canonicalizeHfV1Json(circular)).toThrow(TypeError);
  });

  it("rejects unsafe domains, oversized payloads and malformed expectations", () => {
    expect(() => frameHfV1("Uppercase", new Uint8Array())).toThrow(TypeError);
    expect(() => frameHfV1("va:é", new Uint8Array())).toThrow(TypeError);
    expect(() => frameHfV1("", new Uint8Array())).toThrow(TypeError);
    expect(() => frameHfV1("ok", new Uint8Array(16 * 1024 * 1024 + 1))).toThrow(RangeError);
    expect(() => verifyHfV1Digest({ expected: expected("good:domain", "raw", "invalid"), evidence: { material: "raw", bytes: new Uint8Array() } })).toThrow(TypeError);
  });
});
