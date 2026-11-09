import { describe, expect, it } from "vitest";
import {
  MAX_MERKLE_PROOF_STEPS,
  sha3_512Hex,
  verifyMerkleMembership,
  verifySha3_512Bytes,
  type MerkleMembershipInput,
} from "../../src/index.js";

// Fixed SHA3-512 reference values and tree roots, calculated independently
// from this TypeScript verifier using the specified hashing rules.
const A = "131b62081fb8e163993ff0ad4337cad4cf2549a814727a68b62301d651f2119f84a618e783c90f926d1cc44b61a2ee874954fb30b16832de030b8685ec14ce67";
const B = "63a7870e57ec76d855445bbda91654955c87f9f12019dbbf5358270b5df01bdc3e76fc7927ff2bb9e774cb284ba8e4fface007923daf97c0ca81524335fe6d41";
const C = "d7d28fea46dc9a66a516ecb3881850f19c6e510297deab116c2f5a9747ff03006ff01333514986662cc2782393fcfb76642a972da5d3702d811c2c7d1f7eb837";
const V2_A = "7c5fad8711e3c79a713bffe77e1533f6297df933617578f029c0de6a58d1ba085b35ac39594fc2534a605be9ae6c0eff40453998df0eb50a0e49f80eab2cc2c8";
const V2_B = "faec1974da4f9219bd14b3565fbca2d479d8f667a48bfe631e74dcaf16a9b3fb088955216975d67164971a84699bb3395127bca825d6764bdabc4116eef3b2f9";
const V2_C = "5f88b140e82984695dced5bae5e29b048b2f4d870121c7ea86ec30602716f3d8549380514a30a070c72d165ebbed539095f9cbb296fd2b94ac701e2033014c4c";
const V1_PAIR_AB = "1b8cbda810d754280f9788d50fcbe4855dadaf2c38109fbd7f7f04a2693c97a518e594638a3dee350e61c6e18a29a07fa7ee5c348be296bac351d28c69e217d6";
const V1_THREE = "80d837e83f8e8c7e49d923b3619ea52c0700c1add3453ada57d3dd33fb7c6064b33fd7d14afa240d46837e9e8df5575a340f4a4315f2da0f4e5ba1834c86e07a";
const V2_PAIR_AB = "f6fc2b259ad4333f7d302fdabfac5fb13d7fc476eb6529e1a5ac35097f49f67d5c21bd67e51cfe755bee05bb84a566999baa753fc754245ea45e1f0111c0c022";
const V2_THREE = "2b719fa65e9bc9e0df6d4aae7d8200b95f586da9ecfa898d00b506f145b8e91d562eb7f425b99f3df9b4895d4cb054a459fb164fa7e3dd96b677bc9e96251238";

function membership(
  tree_alg: "binary-sorted" | "binary-sorted-v2",
  root_hash: string,
  leaf_count: number,
  leaf_index: number,
  leaf_hash: string,
  path: MerkleMembershipInput["proof"]["path"],
): MerkleMembershipInput {
  return {
    expected: {
      key: "root",
      kind: "merkle-root",
      tree_alg,
      root_hash,
      leaf_count,
    },
    proof: { leaf_hash, leaf_index, path },
  };
}

function mutateDigest(value: string): string {
  return `${value[0] === "0" ? "1" : "0"}${value.slice(1)}`;
}

describe("offline SHA3-512", () => {
  it("matches independently established empty and UTF-8 digest vectors", () => {
    expect(sha3_512Hex(new Uint8Array())).toBe(
      "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
    );
    expect(sha3_512Hex(Buffer.from("hello", "utf8"))).toBe(
      "75d527c368f2efe848ecf6b073a36767800805e9eef2b1857d5f984f036eb6df891d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84976",
    );
  });

  it("compares supplied bytes to a caller-provided digest", () => {
    const expected_digest = sha3_512Hex(Buffer.from("hello"));
    expect(
      verifySha3_512Bytes({ bytes: Buffer.from("hello"), expected_digest })
        .outcome,
    ).toBe("pass");
    expect(
      verifySha3_512Bytes({ bytes: Buffer.from("HELLO"), expected_digest }),
    ).toMatchObject({
      outcome: "fail",
      reason_code: "DIGEST_MISMATCH",
    });
  });

  it("rejects malformed digests and non-byte inputs", () => {
    expect(() =>
      verifySha3_512Bytes({ bytes: new Uint8Array(), expected_digest: "abc" }),
    ).toThrow(TypeError);
    expect(() => sha3_512Hex("hello" as unknown as Uint8Array)).toThrow(
      TypeError,
    );
  });
});

describe("offline Core Merkle membership", () => {
  const legacyPair = membership("binary-sorted", V1_PAIR_AB, 2, 0, A, [
    { position: "right", hash: B },
  ]);
  const v2Pair = membership("binary-sorted-v2", V2_PAIR_AB, 2, 0, A, [
    { position: "right", hash: V2_B },
  ]);
  const legacyOdd = membership("binary-sorted", V1_THREE, 3, 2, C, [
    { position: "right", hash: C },
    { position: "left", hash: V1_PAIR_AB },
  ]);
  const v2Odd = membership("binary-sorted-v2", V2_THREE, 3, 2, C, [
    { position: "right", hash: V2_C },
    { position: "left", hash: V2_PAIR_AB },
  ]);

  it("verifies both algorithms and a single-leaf tree", () => {
    expect(verifyMerkleMembership(legacyPair).outcome).toBe("pass");
    expect(verifyMerkleMembership(v2Pair).outcome).toBe("pass");
    expect(
      verifyMerkleMembership(membership("binary-sorted", A, 1, 0, A, []))
        .outcome,
    ).toBe("pass");
    expect(
      verifyMerkleMembership(
        membership("binary-sorted-v2", V2_A, 1, 0, A, []),
      ).outcome,
    ).toBe("pass");
  });

  it("verifies odd-width trees with explicit final-node duplication", () => {
    expect(verifyMerkleMembership(legacyOdd).outcome).toBe("pass");
    expect(verifyMerkleMembership(v2Odd).outcome).toBe("pass");
  });

  it("rejects changed leaf, sibling, root, and incorrect algorithm", () => {
    expect(
      verifyMerkleMembership({
        ...legacyPair,
        proof: { ...legacyPair.proof, leaf_hash: B },
      }).outcome,
    ).toBe("fail");
    expect(
      verifyMerkleMembership({
        ...legacyPair,
        proof: {
          ...legacyPair.proof,
          path: [{ position: "right", hash: C }],
        },
      }).outcome,
    ).toBe("fail");
    expect(
      verifyMerkleMembership({
        ...legacyPair,
        expected: {
          ...legacyPair.expected,
          root_hash: mutateDigest(V1_PAIR_AB),
        },
      }).outcome,
    ).toBe("fail");
    expect(
      verifyMerkleMembership({
        ...legacyPair,
        expected: { ...legacyPair.expected, tree_alg: "binary-sorted-v2" },
      }).outcome,
    ).toBe("fail");
  });

  it("enforces index direction and odd-node duplication", () => {
    expect(
      verifyMerkleMembership({
        ...legacyPair,
        proof: { ...legacyPair.proof, leaf_index: 1 },
      }).reason_code,
    ).toBe("MERKLE_PATH_POSITION_MISMATCH");
    expect(
      verifyMerkleMembership({
        ...legacyOdd,
        proof: {
          ...legacyOdd.proof,
          path: [
            { position: "right", hash: B },
            ...legacyOdd.proof.path.slice(1),
          ],
        },
      }).reason_code,
    ).toBe("MERKLE_ODD_SIBLING_MISMATCH");
  });

  it("rejects structural errors without attempting verification", () => {
    expect(() =>
      verifyMerkleMembership({
        ...legacyPair,
        expected: { ...legacyPair.expected, leaf_count: 0 },
      }),
    ).toThrow(TypeError);
    expect(() =>
      verifyMerkleMembership({
        ...legacyPair,
        proof: { ...legacyPair.proof, leaf_index: 2 },
      }),
    ).toThrow(TypeError);
    expect(() =>
      verifyMerkleMembership({
        ...legacyPair,
        proof: { ...legacyPair.proof, path: [] },
      }),
    ).toThrow(TypeError);
    expect(() =>
      verifyMerkleMembership({
        ...legacyPair,
        proof: { ...legacyPair.proof, leaf_hash: "invalid" },
      }),
    ).toThrow(TypeError);
    expect(() =>
      verifyMerkleMembership({
        ...legacyPair,
        proof: {
          ...legacyPair.proof,
          path: Array.from({ length: MAX_MERKLE_PROOF_STEPS + 1 }, () => ({
            position: "right",
            hash: B,
          })),
        },
      }),
    ).toThrow(TypeError);
  });

  it("reports unknown algorithms as unsupported", () => {
    const altered = {
      ...legacyPair,
      expected: { ...legacyPair.expected, tree_alg: "unknown" },
    };
    expect(
      verifyMerkleMembership(altered as unknown as MerkleMembershipInput),
    ).toMatchObject({
      outcome: "unsupported",
      reason_code: "MERKLE_ALGORITHM_UNSUPPORTED",
      computed_root: null,
    });
  });
});
