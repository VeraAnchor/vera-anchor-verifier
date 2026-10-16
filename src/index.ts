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

export { verifyDatasetV1Sources } from "./profiles/dataset/sourceV1.js";
export type { DatasetV1SourceInput, DatasetV1SourceResult } from "./profiles/dataset/sourceV1.js";
export { verifyIngestV1Sources } from "./profiles/ingest/sourceV1.js";
export type { IngestV1SourceInput, IngestV1SourceMaterial, IngestV1SourceResult } from "./profiles/ingest/sourceV1.js";
export type { SourceV1File, SourceV1Limits, SourceV1Mismatch } from "./profiles/sourceV1Helpers.js";

export { verifyDatasetV1WithIntent, verifyIngestV1WithIntent } from "./verification/sourceIntentV1.js";
export type { DatasetV1IntentInput, IngestV1IntentInput } from "./verification/sourceIntentV1.js";

export { compareEvidenceTriangulationV1 } from "./triangulation/compareV1.js";
export type {
  TriangulationFactPlanV1,
  TriangulationFactResultV1,
  TriangulationRelationshipId,
  TriangulationRelationshipPlanV1,
  TriangulationRelationshipResultV1,
  TriangulationV1Input,
  TriangulationV1Result,
} from "./triangulation/compareV1.js";
export { observeCoreMessageBindingV1, observeMirrorMessageV1 } from "./triangulation/messageObservationV1.js";
export type { CoreMessageBindingV1Input, MirrorMessageV1Input } from "./triangulation/messageObservationV1.js";

export {
  resolveExplorerDatasetV1,
  resolveExplorerIngestV1,
  resolveExplorerMerkleRootV1,
} from "./resolvers/explorerPublicV1.js";
export type {
  ExplorerDatasetV1Request,
  ExplorerIngestV1Request,
  ExplorerMerkleRootV1Request,
  ExplorerPublicRecordV1,
  ExplorerPublicationV1,
} from "./resolvers/explorerPublicV1.js";
export {
  resolveExplorerDatasetPublicationV1,
  resolveExplorerIngestPublicationV1,
  resolveExplorerMerkleRootPublicationV1,
} from "./resolvers/explorerPublicationV1.js";
export type { ExplorerPublicationDisclosureV1, ExplorerPublishedEvidenceV1 } from "./resolvers/explorerPublicationV1.js";
export type { ExplorerPublicTransportV1 } from "./resolvers/explorerTransportV1.js";

export { resolveHederaPublicationV1 } from "./resolvers/hederaMirrorV1.js";
export type { HederaMirrorV1Config, HederaPublicationObservationV1 } from "./resolvers/hederaMirrorV1.js";
export { triangulateDatasetV1, triangulateIngestV1 } from "./triangulation/publicV1.js";
export type { PublicTriangulationV1Config, PublicTriangulationV1Result, PublicIngestTriangulationV1Input } from "./triangulation/publicV1.js";

// Deterministic primitives for supported SAGE execution evidence.
// These are not themselves acceptance or identity verification.
export {
  canonicalizeExecutionVerificationValue,
  computeExecutionDomainSeparatedSha3_512,
  executionTimestampNanos,
  hederaConsensusTimestampNanos,
} from "./profiles/execution/recomputationV1.js";

// Independent offline SAGE execution profile; rule outcomes are SDK-native findings.
export { verifyExecutionV1WithIntent } from "./profiles/execution/verificationV1.js";
export type { ExecutionV1Input, ExecutionV1Profile, ExecutionV1Report } from "./profiles/execution/verificationV1.js";
export type { PublicExecutionStandardsEvidence, PublicExecutionVerificationMaterial } from "./profiles/execution/contractV1.js";

// Supported pinned HCS-1 file integrity and independent Mirror observation.
export { MAX_HCS1_V1_CHUNKS, MAX_HCS1_V1_FILE_BYTES, parseHcs1ReferenceV1, verifyHcs1ContentV1 } from "./standards/hcs/hcs1V1.js";
export type { Hcs1V1ContentInput, Hcs1V1ContentOptions, Hcs1V1ContentResult } from "./standards/hcs/hcs1V1.js";
export { resolveHcs1FileV1 } from "./resolvers/hcs1MirrorV1.js";
export type { Hcs1MirrorV1Config, Hcs1MirrorV1Request, Hcs1MirrorV1Result } from "./resolvers/hcs1MirrorV1.js";

// Pinned HCS-2 historical registry entry checks; independent of VA evidence production.
export { parseHcs2MemoV1, parseHcs2RegisterV1, verifyHcs2RegisterV1, Hcs2V1Error } from "./standards/hcs/hcs2V1.js";
export type { Hcs2V1Memo, Hcs2V1Register, Hcs2V1VerificationInput, Hcs2V1VerificationResult } from "./standards/hcs/hcs2V1.js";
export { resolveHcs2RegisterV1 } from "./resolvers/hcs2MirrorV1.js";
export type { Hcs2MirrorV1Request, Hcs2MirrorV1Result } from "./resolvers/hcs2MirrorV1.js";

// Pinned open HCS-14 DID-backed UAID structural binding; no DID controller authentication.
export { Hcs14V1Error, parseHcs14DidUaidV1, buildHcs14DidUaidV1, verifyHcs14DidBindingV1 } from "./standards/hcs/hcs14V1.js";
export type { Hcs14DidUaidV1, Hcs14BindingV1Result } from "./standards/hcs/hcs14V1.js";
// Pinned open HCS-11 AI-agent profile integrity and reference checks; no account ownership assertion.
export { Hcs11V1Error, MAX_HCS11_V1_PROFILE_BYTES, parseHcs11AccountMemoV1, parseHcs11AiAgentProfileV1, verifyHcs11AiAgentProfileV1 } from "./standards/hcs/hcs11V1.js";
export type { Hcs11V1Memo, Hcs11V1Profile, Hcs11V1Input, Hcs11V1Result } from "./standards/hcs/hcs11V1.js";

// Account -> current HCS-11 memo -> optional historical HCS-2 -> HCS-1 -> HCS-11/HCS-14.
export { resolveHcs11ProfileV1 } from "./resolvers/hcs11MirrorV1.js";
export type { Hcs11MirrorV1Request, Hcs11MirrorV1Result } from "./resolvers/hcs11MirrorV1.js";

// Open pinned HCS-13 schema references and canonical document integrity (offline).
export { Hcs13V1Error, MAX_HCS13_V1_SCHEMA_BYTES, buildHcs13ReferenceV1, parseHcs13ReferenceV1,
  finalizeHcs13SchemaV1, parseHcs13SchemaV1, verifyHcs13SchemaV1 } from "./standards/hcs/hcs13V1.js";
export type { Hcs13ReferenceV1, Hcs13SchemaV1, Hcs13SchemaVerificationV1 } from "./standards/hcs/hcs13V1.js";

// Open pinned HCS-26 discovery/version registers and SKILL.json integrity (offline).
export { Hcs26V1Error, MAX_HCS26_V1_MANIFEST_BYTES, parseHcs26MemoV1,
  parseHcs26DiscoveryRegisterV1, parseHcs26DiscoveryUpdateV1, parseHcs26VersionRegisterV1,
  finalizeHcs26SkillManifestV1, parseHcs26SkillManifestV1, verifyHcs26SkillVersionV1 } from "./standards/hcs/hcs26V1.js";
export type { Hcs26MemoV1, Hcs26VersionRegisterV1, Hcs26SkillManifestV1,
  Hcs26VersionVerificationV1 } from "./standards/hcs/hcs26V1.js";

// Historical HCS-13 HCS-2 registration -> HCS-1 schema resolution.
export { resolveHcs13SchemaV1 } from "./resolvers/hcs13MirrorV1.js";
export type { Hcs13MirrorV1Request, Hcs13MirrorV1Result } from "./resolvers/hcs13MirrorV1.js";

// Historical HCS-26 discovery -> version registration -> HCS-1 skill manifest.
export { resolveHcs26SkillVersionV1 } from "./resolvers/hcs26MirrorV1.js";
export type { Hcs26MirrorV1Request, Hcs26MirrorV1Result } from "./resolvers/hcs26MirrorV1.js";

// SDK-owned online integration: exact HCS-11/14, HCS-13 and HCS-26 reference
// observations augment the offline SAGE report without trusting producer summaries.
export { verifyExecutionWithIndependentStandardsV1 } from "./profiles/execution/independentStandardsV1.js";
export type { IndependentStandardsV1Item, IndependentStandardsV1Report } from "./profiles/execution/independentStandardsV1.js";

export { prepareExecutionTriangulationV1, EXECUTION_HEDERA_OBSERVATION_V1_ID } from "./triangulation/executionPlanV1.js";
export type { ExecutionHederaTargetV1, ExecutionTriangulationPlanV1 } from "./triangulation/executionPlanV1.js";

export { resolveExplorerExecutionV1 } from "./resolvers/explorerExecutionV1.js";
export type { ExplorerExecutionV1Request, ExplorerExecutionV1Result } from "./resolvers/explorerExecutionV1.js";
export { resolveExecutionHederaV1 } from "./resolvers/executionMirrorV1.js";
export type { ExecutionMirrorV1Result } from "./resolvers/executionMirrorV1.js";
export { triangulatePublicExecutionV1 } from "./triangulation/executionPublicV1.js";
export type { PublicExecutionTriangulationV1Config, PublicExecutionTriangulationV1Result } from "./triangulation/executionPublicV1.js";
