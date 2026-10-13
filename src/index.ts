/**
 * Public entry point for read-only verification contracts
 * and offline cryptographic verification primitives.
 */

export type * from "./contracts/verification.js";

export {
  normalizeSha3_512Digest,
  sha3_512Hex,
  verifySha3_512Bytes,
} from "./crypto/sha3.js";

export type { DigestVerificationResult } from "./crypto/sha3.js";

export {
  MAX_MERKLE_PROOF_STEPS,
  verifyMerkleMembership,
} from "./merkle/membership.js";

export type {
  MerkleMembershipInput,
  MerkleMembershipResult,
  MerkleProofStep,
} from "./merkle/membership.js";

export {
  HF_V1_CANONICAL_JSON_ID,
  HF_V1_CONTRACT_ID,
  HF_V1_FRAME_ID,
  MAX_HF_V1_PAYLOAD_BYTES,
  canonicalizeHfV1Json,
  frameHfV1,
  hashHfV1,
  normalizeHfV1Domain,
  verifyHfV1Digest,
} from "./hf/hashContractV1.js";
export type {
  HfV1DigestVerificationResult,
  HfV1ExpectedCommitment,
  HfV1HashInput,
  HfV1Material,
} from "./hf/hashContractV1.js";