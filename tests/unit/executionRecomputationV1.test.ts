import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import {
  canonicalizeExecutionVerificationValue,
  computeExecutionDomainSeparatedSha3_512,
  executionTimestampNanos,
  hederaConsensusTimestampNanos,
} from "../../src/profiles/execution/recomputationV1.js";

describe("execution recomputation v1 (Explorer parity contract)", () => {
  it("canonicalizes nested objects regardless of insertion order", () => {
    const a = { z: [1, { beta: true, alpha: "ok" }], a: null };
    const b = { a: null, z: [1, { alpha: "ok", beta: true }] };
    expect(canonicalizeExecutionVerificationValue(a)).toBe('{"a":null,"z":[1,{"alpha":"ok","beta":true}]}');
    expect(canonicalizeExecutionVerificationValue(a)).toBe(canonicalizeExecutionVerificationValue(b));
  });

  it("recomputes domain-separated SHA3-512 from exact canonical material", () => {
    const evidence = { b: 2, a: 1 };
    const expected = createHash("sha3-512")
      .update(Buffer.from("va:execution:binding:v1", "utf8"))
      .update(Buffer.from([0]))
      .update(Buffer.from('{"a":1,"b":2}', "utf8"))
      .digest("hex");
    expect(computeExecutionDomainSeparatedSha3_512("va:execution:binding:v1", evidence)).toBe(expected);
    expect(computeExecutionDomainSeparatedSha3_512("va:execution:other:v1", evidence)).not.toBe(expected);
  });

  it("rejects unsupported and malformed canonical values", () => {
    expect(() => canonicalizeExecutionVerificationValue({ a: undefined })).toThrow(TypeError);
    expect(() => canonicalizeExecutionVerificationValue({ a: Number.POSITIVE_INFINITY })).toThrow(TypeError);
    expect(() => canonicalizeExecutionVerificationValue({ a: 2n })).toThrow(TypeError);
    expect(() => canonicalizeExecutionVerificationValue({ a: "\ud800" })).toThrow(TypeError);
    expect(() => canonicalizeExecutionVerificationValue(new Date())).toThrow(TypeError);
    let deep: unknown = null;
    for (let i = 0; i < 66; i += 1) deep = { x: deep };
    expect(() => canonicalizeExecutionVerificationValue(deep)).toThrow(/depth/);
  });

  it("preserves consensus timestamp differences of one nanosecond", () => {
    const first = hederaConsensusTimestampNanos("1792033594.745290900");
    const second = hederaConsensusTimestampNanos("1792033594.745290901");
    expect(first).not.toBeNull();
    expect(second! - first!).toBe(1n);
    expect(hederaConsensusTimestampNanos("1792033594.74529090")).toBeNull();
    expect(hederaConsensusTimestampNanos("1792033594.745290900Z")).toBeNull();
  });

  it("preserves UTC fractional nanoseconds without floating point conversion", () => {
    const first = executionTimestampNanos("2026-10-15T04:36:19.000000001Z");
    const next = executionTimestampNanos("2026-10-15T04:36:19.000000002Z");
    expect(next! - first!).toBe(1n);
    expect(executionTimestampNanos("2026-10-15T04:36:19.001Z")! - first!).toBe(999_999n);
    expect(executionTimestampNanos("2026-10-15T04:36:19+00:00")).toBe(executionTimestampNanos("2026-10-15T04:36:19Z"));
  });

  it("rejects malformed, impossible, and ambiguous UTC timestamps", () => {
    expect(executionTimestampNanos("2026-02-30T00:00:00Z")).toBeNull();
    expect(executionTimestampNanos("2026-10-15T25:00:00Z")).toBeNull();
    expect(executionTimestampNanos("2026-10-15T04:36:19.0000000001Z")).toBeNull();
    expect(executionTimestampNanos("2026-10-15T04:36:19-06:00")).toBeNull();
    expect(executionTimestampNanos(1792033594)).toBeNull();
    expect(executionTimestampNanos(new Date("invalid"))).toBeNull();
  });
});
