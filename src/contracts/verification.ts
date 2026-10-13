/**
 * Shared structural contracts for read-only verification.
 * Pre-release: these types are not a runtime validator or a verification claim.
 */

export type HederaNetwork = "mainnet" | "testnet";

export type VerificationSubjectKind =
  | "artifact"
  | "dataset"
  | "ingest"
  | "evidence_package"
  | "merkle_anchor"
  | "merkle_root"
  | "merkle_leaf"
  | "execution"
  | "result";

/** Network is required by network-bound profiles, not by content-only evidence. */
export type VerificationSubject = Readonly<{
  kind: VerificationSubjectKind;
  id: string;
  hedera_network?: HederaNetwork;
}>;

/**
 * Explicit commitment families. Never substitute one hashing/framing contract
 * for another merely because both produce SHA3-512 digests.
 */
export type ExpectedCommitment =
  | Readonly<{
      key: string;
      kind: "digest";
      contract: "raw-sha3-512" | "core-canonical-json";
      digest: string;
    }>
  | Readonly<{
      key: string;
      kind: "digest";
      contract: "hf-contract-v1";
      material: "json" | "utf8" | "raw";
      domain: string;
      digest: string;
    }>
  | Readonly<{
      key: string;
      kind: "merkle-root";
      tree_alg: "binary-sorted" | "binary-sorted-v2";
      root_hash: string;
      leaf_count: number;
    }>;

/** Expectations must be supplied by the caller or explicitly trusted context. */
export type VerificationIntent = Readonly<{
  subject: VerificationSubject;
  expected: readonly ExpectedCommitment[];
}>;

export type VerificationFactValue = string | number | boolean | null;

export type VerificationFact =
  | Readonly<{
      key: string;
      state: "available";
      value: VerificationFactValue;
    }>
  | Readonly<{
      key: string;
      state: "unavailable" | "not_applicable";
      reason_code?: string | null;
    }>;

/** Source designation is provenance metadata, not proof of source authenticity. */
export type VerificationObservation = Readonly<{
  id: string;
  subject: VerificationSubject;
  source:
    | "provided_evidence"
    | "public_record"
    | "hedera_mirror"
    | "local_computation";
  resolver_id?: string;
  observed_at?: string | null;
  facts: readonly VerificationFact[];
}>;

/** Check outcomes are distinct from evidence consistency and policy decisions. */
export type VerificationOutcome =
  | "pass"
  | "fail"
  | "indeterminate"
  | "unsupported"
  | "skipped";

/** Findings carry no timestamps or raw source payloads. */
export type VerificationFinding = Readonly<{
  check_id: string;
  outcome: VerificationOutcome;
  reason_code: string | null;
  observation_ids: readonly string[];
}>;

/** Relationship consistency is not an overall verification or policy verdict. */
export type EvidenceConsistency = "consistent" | "conflict" | "incomplete";

/** No aggregate success flag until profile-specific required checks are defined. */
export type VerificationReport = Readonly<{
  intent: VerificationIntent;
  findings: readonly VerificationFinding[];
  observations: readonly VerificationObservation[];
}>;
