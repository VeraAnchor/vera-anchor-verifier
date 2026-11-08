import type { HederaNetwork } from "../../contracts/verification.js";

const TYPE = "core.dataset_registry.event.v1";
const EVENT = "dataset_version.created";
const DATASET_KEY = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/;
const HEX_512 = /^[0-9a-f]{128}$/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_ENTITY_ID = 320;

type Json = Readonly<Record<string, unknown>>;

export type DatasetRegistryVersionCreatedV1 = Readonly<{
  schema_version: typeof TYPE;
  event: typeof EVENT;
  entity_id: string;
  hedera_network: HederaNetwork;
  dataset_version_id: string;
  dataset_key: string;
  version: number;
  dataset_fingerprint: string;
  manifest_hash: string | null;
  schema_hash: string | null;
}>;

export type DatasetRegistryVersionCreatedV1Result = Readonly<{
  status: "resolved" | "unavailable" | "unsupported" | "invalid" | "conflict";
  reason_code: string | null;
  event: DatasetRegistryVersionCreatedV1 | null;
}>;

function object(value: unknown): Json | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Json
    : null;
}

function optionalDigest(value: unknown): string | null | undefined {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string" || !HEX_512.test(value)) return undefined;
  return value.toLowerCase();
}

function result(
  status: DatasetRegistryVersionCreatedV1Result["status"],
  reason: string,
): DatasetRegistryVersionCreatedV1Result {
  return Object.freeze({ status, reason_code: reason, event: null });
}

/**
 * Parse the current private Dataset Registry version-creation envelope.
 * This is pure profile normalization: it does not authenticate Core, Hedera,
 * or the producer, and it never preserves actor/timestamp/private payload data.
 */
export function parseDatasetRegistryVersionCreatedV1(
  payload: unknown,
  expectedNetwork?: HederaNetwork,
): DatasetRegistryVersionCreatedV1Result {
  if (payload === null || payload === undefined) {
    return result("unavailable", "AUTHORIZED_DATASET_PAYLOAD_UNAVAILABLE");
  }
  const envelope = object(payload);
  if (!envelope) return result("invalid", "AUTHORIZED_DATASET_PAYLOAD_INVALID");

  if (envelope._type !== TYPE || envelope.event !== EVENT) {
    return result("unsupported", "AUTHORIZED_DATASET_EVENT_UNSUPPORTED");
  }
  const network = envelope.hedera_network;
  if (network !== "mainnet" && network !== "testnet") {
    return result("invalid", "AUTHORIZED_DATASET_NETWORK_INVALID");
  }
  if (expectedNetwork !== undefined && network !== expectedNetwork) {
    return result("conflict", "AUTHORIZED_DATASET_NETWORK_MISMATCH");
  }

  const body = object(envelope.payload);
  if (!body) return result("invalid", "AUTHORIZED_DATASET_EVENT_PAYLOAD_INVALID");

  const datasetKey = body.dataset_key;
  const version = body.version;
  const fingerprint = body.dataset_fingerprint;
  const versionId = body.dataset_version_id;
  const entityId = envelope.entity_id;

  if (typeof datasetKey !== "string" || datasetKey.trim() !== datasetKey || !DATASET_KEY.test(datasetKey) ||
    typeof version !== "number" || !Number.isSafeInteger(version) || version < 1 ||
    typeof fingerprint !== "string" || !HEX_512.test(fingerprint) ||
    typeof versionId !== "string" || !UUID.test(versionId) ||
    typeof entityId !== "string" || entityId.length === 0 || entityId.length > MAX_ENTITY_ID ||
    entityId !== `${datasetKey}@${version}`) {
    return result("invalid", "AUTHORIZED_DATASET_EVENT_PAYLOAD_INVALID");
  }

  const manifestHash = optionalDigest(body.manifest_hash);
  const schemaHash = optionalDigest(body.schema_hash);
  if (manifestHash === undefined || schemaHash === undefined) {
    return result("invalid", "AUTHORIZED_DATASET_EVENT_PAYLOAD_INVALID");
  }

  return Object.freeze({
    status: "resolved" as const,
    reason_code: null,
    event: Object.freeze({
      schema_version: TYPE,
      event: EVENT,
      entity_id: entityId,
      hedera_network: network,
      dataset_version_id: versionId.toLowerCase(),
      dataset_key: datasetKey,
      version,
      dataset_fingerprint: fingerprint.toLowerCase(),
      manifest_hash: manifestHash,
      schema_hash: schemaHash,
    }),
  });
}
