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

export { sha3_512Stream, verifySha3_512Stream } from "./crypto/streamSha3.js";
export type {
  ByteChunkSource,
  Sha3_512StreamHashResult,
  Sha3_512StreamVerificationResult,
} from "./crypto/streamSha3.js";

export { verifyDatasetV1Bundle, verifyDatasetV1Receipt } from "./profiles/dataset/v1.js";
export type {
  DatasetV1BundleComputed,
  DatasetV1Mismatch,
  DatasetV1ReceiptComputed,
  DatasetV1VerificationResult,
} from "./profiles/dataset/v1.js";

export { verifyIngestV1Bundle, verifyIngestV1Receipt, verifyIngestV1Pair } from "./profiles/ingest/v1.js";
export type {
  IngestV1BundleComputed,
  IngestV1Mismatch,
  IngestV1ReceiptComputed,
  IngestV1Result,
} from "./profiles/ingest/v1.js";
