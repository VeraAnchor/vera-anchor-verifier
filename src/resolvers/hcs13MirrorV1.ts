/** Exact historical HCS-13 registration -> HCS-1 schema integrity observation.
 * No current registry state, JSON Schema instance-validation or consensus proof.
 */
import type { HederaNetwork } from "../contracts/verification.js";
import { resolveHcs2RegisterV1 } from "./hcs2MirrorV1.js";
import { resolveHcs1FileV1, type Hcs1MirrorV1Config } from "./hcs1MirrorV1.js";
import { parseHcs1ReferenceV1, type Hcs1V1ContentOptions } from "../standards/hcs/hcs1V1.js";
import { parseHcs13ReferenceV1, parseHcs13SchemaV1, verifyHcs13SchemaV1,
  type Hcs13ReferenceV1, type Hcs13SchemaV1, Hcs13V1Error } from "../standards/hcs/hcs13V1.js";

const SHA256 = /^[0-9a-f]{64}$/;
export type Hcs13MirrorV1Request = Readonly<{
  hedera_network: HederaNetwork;
  reference: string;
  /** Optional independent relying-party commitments. */
  expected_hcs1_reference?: string | null;
  expected_schema_sha256?: string | null;
}>;
export type Hcs13MirrorV1Result = Readonly<{
  status: "resolved" | "conflict" | "invalid" | "unavailable" | "unsupported";
  reason_code: string | null;
  hedera_network: HederaNetwork;
  resolver_id: "hedera.mirror-rest.hcs13.v1";
  reference: Hcs13ReferenceV1;
  registry_consensus_timestamp_exact: string | null;
  registry_memo_temporal_scope: "current_observation";
  /** Exact HCS-1 reference selected by the historical HCS-2 register. */
  schema_hcs1_reference: string | null;
  /** Hash of bytes fetched from HCS-1 relative to the observed topic memo. */
  content_sha256: string | null;
  /** SHA-256 of the deterministic canonicalized schema document. */
  schema_sha256: string | null;
  schema: Hcs13SchemaV1["schema"] | null;
  /** Registry observations are not consensus authentication. */
  assurance: "mirror_corroborated";
}>;

/** Caller selects the historical reference explicitly. No 'latest' selection. */
export async function resolveHcs13SchemaV1(
  config: Hcs1MirrorV1Config,
  request: Hcs13MirrorV1Request,
  decodeOptions: Hcs1V1ContentOptions = {},
): Promise<Hcs13MirrorV1Result> {
  if (!request || (request.hedera_network !== "mainnet" && request.hedera_network !== "testnet")) {
    throw new TypeError("HCS13_NETWORK_INVALID");
  }
  const reference = parseHcs13ReferenceV1(request.reference);
  if (request.expected_hcs1_reference != null) parseHcs1ReferenceV1(request.expected_hcs1_reference);
  if (request.expected_schema_sha256 != null && !SHA256.test(request.expected_schema_sha256)) {
    throw new TypeError("HCS13_EXPECTED_CHECKSUM_INVALID");
  }
  let registryTime: string | null = null;
  let contentRef: string | null = null;
  let contentHash: string | null = null;
  let schemaHash: string | null = null;
  let schema: Hcs13SchemaV1["schema"] | null = null;
  const output = (status: Hcs13MirrorV1Result["status"], reason_code: string | null): Hcs13MirrorV1Result =>
    Object.freeze({ status, reason_code, hedera_network: request.hedera_network,
      resolver_id: "hedera.mirror-rest.hcs13.v1" as const, reference,
      registry_consensus_timestamp_exact: registryTime,
      registry_memo_temporal_scope: "current_observation" as const,
      schema_hcs1_reference: contentRef,
      content_sha256: contentHash, schema_sha256: schemaHash, schema,
      assurance: "mirror_corroborated" as const });

  const expectedTopic = request.expected_hcs1_reference == null ? null :
    parseHcs1ReferenceV1(request.expected_hcs1_reference).topic_id;
  const registry = await resolveHcs2RegisterV1(config, {
    hedera_network: request.hedera_network, registry_topic_id: reference.registry_topic_id,
    sequence_number: reference.sequence_number, expected_t_id: expectedTopic,
  });
  if (registry.status !== "resolved" || !registry.verification?.register || !registry.consensus_timestamp) {
    return output(registry.status === "conflict" ? "conflict" : registry.status,
      registry.reason_code ?? "HCS13_REGISTRY_ENTRY_UNAVAILABLE");
  }
  registryTime = registry.consensus_timestamp;
  contentRef = `hcs://1/${registry.verification.register.t_id}`;
  const content = await resolveHcs1FileV1(config, {
    network: request.hedera_network, reference: contentRef,
    expected_sha256: request.expected_schema_sha256 ?? null,
  }, decodeOptions);
  if (content.status !== "resolved" || !content.verification?.bytes || !content.verification.sha256) {
    return output(content.reason_code === "HCS1_EXPECTED_CHECKSUM_MISMATCH" ? "conflict" : content.status,
      content.reason_code ?? "HCS13_SCHEMA_CONTENT_UNAVAILABLE");
  }
  contentHash = content.verification.sha256;
  const verification = verifyHcs13SchemaV1({ reference: reference.ref,
    schema: content.verification.bytes, expected_sha256: request.expected_schema_sha256 ?? null });
  if (verification.status !== "pass") {
    return output(verification.reason_code === "HCS13_CHECKSUM_MISMATCH" ? "conflict" : "invalid",
      verification.reason_code);
  }
  try {
    const parsed = parseHcs13SchemaV1(content.verification.bytes);
    schemaHash = parsed.sha256;
    // The pinned HCS-13 publisher stores its canonical document in HCS-1.
    // A merely equivalent noncanonical JSON document is not a verified pinned publication.
    if (parsed.canonical_payload !== Buffer.from(content.verification.bytes).toString("utf8")) {
      return output("unsupported", "HCS13_SCHEMA_CONTENT_NOT_CANONICAL");
    }
    if (schemaHash !== contentHash) return output("conflict", "HCS13_CANONICAL_CONTENT_MISMATCH");
    schema = parsed.schema;
    return output("resolved", null);
  } catch (error) {
    if (error instanceof Hcs13V1Error) return output("invalid", error.code);
    throw error;
  }
}
