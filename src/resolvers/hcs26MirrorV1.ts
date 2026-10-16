/** Exact historical HCS-26 discovery/version registers -> HCS-1 SKILL.json.
 * Does not reconstruct current registry state, verify files declared in the
 * manifest, authenticate a publisher, or authenticate Hedera consensus.
 */
import type { HederaNetwork } from "../contracts/verification.js";
import { resolveHcs1FileV1, type Hcs1MirrorV1Config } from "./hcs1MirrorV1.js";
import { readHcs26RegistryMessageV1 } from "./hcs26RegistryMirrorV1.js";
import { parseHcs1ReferenceV1, type Hcs1V1ContentOptions } from "../standards/hcs/hcs1V1.js";
import { Hcs26V1Error, parseHcs26DiscoveryRegisterV1, parseHcs26VersionRegisterV1,
  parseHcs26SkillManifestV1, verifyHcs26SkillVersionV1,
  type Hcs26VersionRegisterV1, type Hcs26SkillManifestV1 } from "../standards/hcs/hcs26V1.js";

const TOPIC = /^0\.0\.[0-9]+$/;
const SHA256 = /^[0-9a-f]{64}$/;
export type Hcs26MirrorV1Request = Readonly<{
  hedera_network: HederaNetwork;
  discovery_topic_id: string;
  /** Historical discovery entry, which assigns the skill UID. */
  discovery_sequence_number: number;
  /** Exact historical entry in the registered per-skill version topic. */
  version_sequence_number: number;
  expected_skill_uid?: number | null;
  expected_account_id?: string | null;
  expected_version_topic_id?: string | null;
  expected_version?: string | null;
  expected_manifest_reference?: string | null;
  expected_manifest_sha256?: string | null;
}>;
export type Hcs26MirrorV1Result = Readonly<{
  status: "resolved" | "conflict" | "invalid" | "unavailable" | "unsupported";
  reason_code: string | null;
  hedera_network: HederaNetwork;
  resolver_id: "hedera.mirror-rest.hcs26.v1";
  discovery_topic_id: string;
  discovery_sequence_number: number;
  discovery_consensus_timestamp_exact: string | null;
  publisher_account_id: string | null;
  version_topic_id: string | null;
  registry_memo_temporal_scope: "current_observation";
  version_sequence_number: number;
  version_consensus_timestamp_exact: string | null;
  /** This is the historical registration status, NOT its current status. */
  historical_version_status: Hcs26VersionRegisterV1["status"] | null;
  skill_uid: number | null;
  version: string | null;
  manifest_reference: string | null;
  content_sha256: string | null;
  manifest_sha256: string | null;
  manifest: Hcs26SkillManifestV1["manifest"] | null;
  discovery_metadata_resolution: "not_checked";
  manifest_files_resolution: "not_checked";
  assurance: "mirror_corroborated";
}>;

export async function resolveHcs26SkillVersionV1(
  config: Hcs1MirrorV1Config,
  request: Hcs26MirrorV1Request,
  decodeOptions: Hcs1V1ContentOptions = {},
): Promise<Hcs26MirrorV1Result> {
  if (!request || (request.hedera_network !== "mainnet" && request.hedera_network !== "testnet") ||
      !TOPIC.test(request.discovery_topic_id) ||
      !Number.isSafeInteger(request.discovery_sequence_number) || request.discovery_sequence_number < 1 ||
      !Number.isSafeInteger(request.version_sequence_number) || request.version_sequence_number < 1 ||
      (request.expected_skill_uid != null && (!Number.isSafeInteger(request.expected_skill_uid) || request.expected_skill_uid < 1)) ||
      (request.expected_account_id != null && !TOPIC.test(request.expected_account_id)) ||
      (request.expected_version_topic_id != null && !TOPIC.test(request.expected_version_topic_id)) ||
      (request.expected_manifest_sha256 != null && !SHA256.test(request.expected_manifest_sha256))) {
    throw new TypeError("HCS26_VERIFICATION_LOCATOR_INVALID");
  }
  if (request.expected_manifest_reference != null) parseHcs1ReferenceV1(request.expected_manifest_reference);
  if (request.expected_version != null && (typeof request.expected_version !== "string" ||
      !request.expected_version.length || request.expected_version.length > 64)) {
    throw new TypeError("HCS26_EXPECTED_VERSION_INVALID");
  }
  let discoveryTime: string | null = null;
  let publisherAccount: string | null = null;
  let versionTopic: string | null = null;
  let versionTime: string | null = null;
  let register: Hcs26VersionRegisterV1 | null = null;
  let manifestRef: string | null = null;
  let contentHash: string | null = null;
  let manifestHash: string | null = null;
  let manifest: Hcs26SkillManifestV1["manifest"] | null = null;
  const output = (status: Hcs26MirrorV1Result["status"], reason_code: string | null): Hcs26MirrorV1Result =>
    Object.freeze({ status, reason_code, hedera_network: request.hedera_network,
      resolver_id: "hedera.mirror-rest.hcs26.v1" as const,
      discovery_topic_id: request.discovery_topic_id, discovery_sequence_number: request.discovery_sequence_number,
      discovery_consensus_timestamp_exact: discoveryTime, publisher_account_id: publisherAccount,
      version_topic_id: versionTopic, registry_memo_temporal_scope: "current_observation" as const,
      version_sequence_number: request.version_sequence_number,
      version_consensus_timestamp_exact: versionTime, historical_version_status: register?.status ?? null,
      skill_uid: register?.skill_uid ?? null, version: register?.version ?? null,
      manifest_reference: manifestRef, content_sha256: contentHash, manifest_sha256: manifestHash,
      manifest, discovery_metadata_resolution: "not_checked" as const,
      manifest_files_resolution: "not_checked" as const, assurance: "mirror_corroborated" as const });

  if (request.expected_skill_uid != null && request.expected_skill_uid !== request.discovery_sequence_number) {
    return output("conflict", "HCS26_SKILL_UID_MISMATCH");
  }
  const discovery = await readHcs26RegistryMessageV1(config, {
    hedera_network: request.hedera_network, topic_id: request.discovery_topic_id,
    sequence_number: request.discovery_sequence_number, registry_type: "discovery",
  });
  if (discovery.status !== "resolved" || !discovery.evidence) {
    return output(discovery.status, discovery.reason_code ?? "HCS26_DISCOVERY_UNAVAILABLE");
  }
  discoveryTime = discovery.evidence.consensus_timestamp;
  let decodedDiscovery: Readonly<Record<string, unknown>>;
  try { decodedDiscovery = parseHcs26DiscoveryRegisterV1(discovery.evidence.message); }
  catch (error) {
    if (error instanceof Hcs26V1Error) return output("invalid", error.code);
    throw error;
  }
  versionTopic = decodedDiscovery.t_id as string;
  publisherAccount = decodedDiscovery.account_id as string;
  if (request.expected_version_topic_id != null && versionTopic !== request.expected_version_topic_id) {
    return output("conflict", "HCS26_VERSION_TOPIC_MISMATCH");
  }
  if (request.expected_account_id != null && publisherAccount !== request.expected_account_id) {
    return output("conflict", "HCS26_PUBLISHER_ACCOUNT_MISMATCH");
  }
  const version = await readHcs26RegistryMessageV1(config, {
    hedera_network: request.hedera_network, topic_id: versionTopic,
    sequence_number: request.version_sequence_number, registry_type: "version",
  });
  if (version.status !== "resolved" || !version.evidence) {
    return output(version.status, version.reason_code ?? "HCS26_VERSION_UNAVAILABLE");
  }
  versionTime = version.evidence.consensus_timestamp;
  try { register = parseHcs26VersionRegisterV1(version.evidence.message); }
  catch (error) {
    if (error instanceof Hcs26V1Error) return output("invalid", error.code);
    throw error;
  }
  if (register.skill_uid !== request.discovery_sequence_number) {
    return output("conflict", "HCS26_SKILL_UID_MISMATCH");
  }
  if (request.expected_version != null && register.version !== request.expected_version) {
    return output("conflict", "HCS26_VERSION_MISMATCH");
  }
  manifestRef = `hcs://1/${register.t_id}`;
  if (request.expected_manifest_reference != null && manifestRef !== request.expected_manifest_reference) {
    return output("conflict", "HCS26_MANIFEST_REFERENCE_MISMATCH");
  }
  const content = await resolveHcs1FileV1(config, {
    network: request.hedera_network, reference: manifestRef,
    expected_sha256: request.expected_manifest_sha256 ?? null,
  }, decodeOptions);
  if (content.status !== "resolved" || !content.verification?.bytes || !content.verification.sha256) {
    return output(content.reason_code === "HCS1_EXPECTED_CHECKSUM_MISMATCH" ? "conflict" : content.status,
      content.reason_code ?? "HCS26_MANIFEST_UNAVAILABLE");
  }
  contentHash = content.verification.sha256;
  const verified = verifyHcs26SkillVersionV1({
    version_register: version.evidence.message, manifest: content.verification.bytes,
    expected_skill_uid: request.discovery_sequence_number,
    ...(request.expected_version == null ? {} : { expected_version: request.expected_version }),
    ...(request.expected_manifest_sha256 == null ? {} : { expected_sha256: request.expected_manifest_sha256 }),
  });
  manifestHash = verified.sha256;
  if (verified.status !== "pass") {
    return output(["HCS26_CHECKSUM_MISMATCH", "HCS26_VERSION_MISMATCH", "HCS26_EXPECTED_CHECKSUM_MISMATCH"].includes(
      verified.reason_code ?? "") ? "conflict" : "invalid", verified.reason_code);
  }
  try {
    const parsed = parseHcs26SkillManifestV1(content.verification.bytes);
    manifestHash = parsed.sha256;
    if (parsed.canonical_payload !== Buffer.from(content.verification.bytes).toString("utf8")) {
      return output("unsupported", "HCS26_MANIFEST_CONTENT_NOT_CANONICAL");
    }
    if (manifestHash !== contentHash) return output("conflict", "HCS26_CANONICAL_CONTENT_MISMATCH");
    manifest = parsed.manifest;
    return output("resolved", null);
  } catch (error) {
    if (error instanceof Hcs26V1Error) return output("invalid", error.code);
    throw error;
  }
}
