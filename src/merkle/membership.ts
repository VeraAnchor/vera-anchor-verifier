import { createHash } from "node:crypto";
import type { ExpectedCommitment, VerificationOutcome } from "../contracts/verification.js";
import { normalizeSha3_512Digest } from "../crypto/sha3.js";

export const MAX_MERKLE_PROOF_STEPS = 64;

export type MerkleProofStep = Readonly<{
  position: "left" | "right";
  hash: string;
}>;

export type MerkleMembershipInput = Readonly<{
  /** This commitment must come from the caller's trusted expectations. */
  expected: Extract<ExpectedCommitment, { kind: "merkle-root" }>;
  proof: Readonly<{
    /** Stored leaf digest; v2 applies a separate leaf-node hash. */
    leaf_hash: string;
    leaf_index: number;
    path: readonly MerkleProofStep[];
  }>;
}>;

export type MerkleMembershipResult = Readonly<{
  outcome: Extract<VerificationOutcome, "pass" | "fail" | "unsupported">;
  reason_code: string | null;
  expected_root: string;
  computed_root: string | null;
}>;

function result(
  outcome: MerkleMembershipResult["outcome"],
  reason_code: string | null,
  expected_root: string,
  computed_root: string | null,
): MerkleMembershipResult {
  return Object.freeze({ outcome, reason_code, expected_root, computed_root });
}

function digestBytes(hex: string): Buffer {
  return Buffer.from(hex, "hex");
}

function sha3(parts: readonly Uint8Array[]): string {
  const hash = createHash("sha3-512");
  for (const part of parts) hash.update(part);
  return hash.digest("hex");
}

function leafNode(digest: string, isV2: boolean): string {
  return isV2 ? sha3([Buffer.from([0]), digestBytes(digest)]) : digest;
}

function parentNode(left: string, right: string, isV2: boolean): string {
  if (isV2) {
    return sha3([Buffer.from([1]), digestBytes(left), digestBytes(right)]);
  }
  // Both keys are fixed and ordered: identical to the historical sorted-key
  // canonical JSON pair hash, without accepting general-purpose JSON inputs.
  return sha3([Buffer.from(JSON.stringify({ left, right }), "utf8")]);
}

function parseProof(value: MerkleMembershipInput["proof"], count: number): {
  leaf: string;
  index: number;
  path: readonly MerkleProofStep[];
} {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("Merkle proof must be an object");
  }
  const leaf = normalizeSha3_512Digest(value.leaf_hash);
  const index = value.leaf_index;
  if (!Number.isSafeInteger(index) || index < 0 || index >= count) {
    throw new TypeError("Merkle leaf_index must be within the expected leaf_count");
  }
  if (!Array.isArray(value.path) || value.path.length > MAX_MERKLE_PROOF_STEPS) {
    throw new TypeError("Merkle path must be a bounded array");
  }
  let width = count;
  let depth = 0;
  while (width > 1) {
    width = Math.ceil(width / 2);
    depth++;
  }
  if (value.path.length !== depth) {
    throw new TypeError("Merkle path depth does not match expected leaf_count");
  }
  const path = value.path.map((step, i) => {
    if (!step || typeof step !== "object" || Array.isArray(step)) {
      throw new TypeError(`Merkle path step ${i} must be an object`);
    }
    if (Object.keys(step).some((key) => key !== "position" && key !== "hash")) {
      throw new TypeError(`Merkle path step ${i} contains unexpected fields`);
    }
    if (step.position !== "left" && step.position !== "right") {
      throw new TypeError(`Merkle path step ${i} has invalid position`);
    }
    return Object.freeze({
      position: step.position,
      hash: normalizeSha3_512Digest(step.hash),
    });
  });
  return { leaf, index, path };
}

/**
 * Verify membership against a separately trusted root, algorithm, and leaf count.
 * This establishes a mathematical commitment relationship, not ledger authenticity.
 */
export function verifyMerkleMembership(input: MerkleMembershipInput): MerkleMembershipResult {
  const expected = input?.expected;
  if (!expected || expected.kind !== "merkle-root") {
    throw new TypeError("Expected a Merkle root commitment");
  }
  const expectedRoot = normalizeSha3_512Digest(expected.root_hash);
  const count = expected.leaf_count;
  if (!Number.isSafeInteger(count) || count < 1) {
    throw new TypeError("Expected Merkle leaf_count must be a positive safe integer");
  }
  if (
    expected.tree_alg !== "binary-sorted" &&
    expected.tree_alg !== "binary-sorted-v2"
  ) {
    return result("unsupported", "MERKLE_ALGORITHM_UNSUPPORTED", expectedRoot, null);
  }
  const isV2 = expected.tree_alg === "binary-sorted-v2";
  const { leaf, path, index } = parseProof(input.proof, count);

  let current = leafNode(leaf, isV2);
  let width = count;
  let position = index;

  for (const sibling of path) {
    const isRight = position % 2 === 1;
    if (sibling.position !== (isRight ? "left" : "right")) {
      return result("fail", "MERKLE_PATH_POSITION_MISMATCH", expectedRoot, null);
    }
    if (!isRight && position + 1 === width && sibling.hash !== current) {
      return result("fail", "MERKLE_ODD_SIBLING_MISMATCH", expectedRoot, null);
    }
    const left = isRight ? sibling.hash : current;
    const right = isRight ? current : sibling.hash;
    current = parentNode(left, right, isV2);
    position = Math.floor(position / 2);
    width = Math.ceil(width / 2);
  }

  const matches = current === expectedRoot;
  return result(
    matches ? "pass" : "fail",
    matches ? null : "MERKLE_ROOT_MISMATCH",
    expectedRoot,
    current,
  );
}
