import { readFile } from "node:fs/promises";
import { describe, expect, it, vi } from "vitest";
import {
  VERIFICATION_POLICY_SCHEMA_VERSION,
  createStaticBearerAuthProviderV1,
  hashHfV1,
  sha3_512Hex,
  triangulateAuthorizedDatasetWithPolicyV1,
  triangulateAuthorizedIngestWithPolicyV1,
  validatePortableVerificationReportV1,
  verifyIngestV1Receipt,
  type AuthorizedDatasetTriangulationV1Input,
  type AuthorizedIngestTriangulationV1Input,
  type VerificationPolicyV1,
} from "../../src/index.js";

type DatasetMaterial = Readonly<{ path_rel: string; content_base64: string }>;
type DatasetCase = Readonly<{
  case_id: string;
  bundle: unknown;
  hash_only_receipt: unknown;
  bundle_expectations: Readonly<{
    dataset_key: string;
    dataset_fingerprint: string;
    bundle_digest: string;
    merkle_root: string;
  }>;
}>;

type FileMaterial = Readonly<{ path_rel: string; content_base64: string }>;
type IngestMaterial =
  | Readonly<{ kind: "json"; value: unknown }>
  | Readonly<{ kind: "text"; text: string; media_type?: string }>
  | Readonly<{ kind: "file"; file: FileMaterial }>
  | Readonly<{ kind: "file_set"; files: readonly FileMaterial[] }>;
type IngestCase = Readonly<{
  case_id: string;
  bundle: unknown;
  anchored_receipts: readonly unknown[];
  bundle_expectations: Readonly<{
    fingerprint: string;
    bundle_digest: string;
    idempotency_key: string;
    merkle_root: string;
  }>;
}>;

type Fixtures = Readonly<{
  datasets: readonly DatasetCase[];
  ingests: readonly IngestCase[];
  dataset_materials: Readonly<Record<string, DatasetMaterial[]>>;
  ingest_materials: Readonly<Record<string, IngestMaterial>>;
}>;

type TransportState = "consistent" | "forbidden" | "mirror_unavailable" | "mirror_conflict";

const CORE = "https://core.example.test";
const MIRROR = "https://mirror.example.test/api/v1";
const TOPIC = "0.0.12345";
const SEQUENCE = 7;
const TX = "0.0.77@1234567890.123456789";
const MESSAGE = Buffer.from("authorized-private-evidence-envelope", "utf8");
const MESSAGE_DIGEST = sha3_512Hex(MESSAGE);
const TEST_TOKEN = "verifier-integration-test-token";
const PRIVATE_ACTOR = "22222222-2222-4222-8222-222222222222";
const DATASET_VERSION = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

async function fixtures(): Promise<Fixtures> {
  const [datasetVectors, ingestVectors, sourceMaterials] = await Promise.all([
    readFile(new URL("../unit/fixtures/datasetV1SelectedVectors.json", import.meta.url), "utf8"),
    readFile(new URL("../unit/fixtures/ingestV1SelectedVectors.json", import.meta.url), "utf8"),
    readFile(new URL("../unit/fixtures/sourceV1Materials.json", import.meta.url), "utf8"),
  ]);
  const sources = JSON.parse(sourceMaterials) as {
    dataset: Record<string, DatasetMaterial[]>;
    ingest: Record<string, IngestMaterial>;
  };
  return {
    datasets: (JSON.parse(datasetVectors) as { cases: DatasetCase[] }).cases,
    ingests: (JSON.parse(ingestVectors) as { cases: IngestCase[] }).cases,
    dataset_materials: sources.dataset,
    ingest_materials: sources.ingest,
  };
}

function datasetCase(all: Fixtures, id: string): DatasetCase {
  const entry = all.datasets.find((item) => item.case_id === id);
  if (!entry || !all.dataset_materials[id]) throw new Error(`Missing Dataset fixture: ${id}`);
  return entry;
}

function ingestCase(all: Fixtures, id: string): IngestCase {
  const entry = all.ingests.find((item) => item.case_id === id);
  if (!entry || !all.ingest_materials[id]) throw new Error(`Missing Ingest fixture: ${id}`);
  return entry;
}

function datasetInput(all: Fixtures, id: string): AuthorizedDatasetTriangulationV1Input {
  const entry = datasetCase(all, id);
  return {
    bundle: structuredClone(entry.bundle),
    receipt: structuredClone(entry.hash_only_receipt),
    files: all.dataset_materials[id]!.map((file) => ({
      path_rel: file.path_rel,
      source: (async function* () {
        yield Buffer.from(file.content_base64, "base64");
      })(),
    })),
    intent: {
      subject: {
        kind: "dataset",
        id: entry.bundle_expectations.dataset_key,
        hedera_network: "testnet",
      },
      expected: [],
    },
    hcs_reference: { message_id: `${SEQUENCE}@${TOPIC}` },
  };
}

function ingestSource(value: IngestMaterial): AuthorizedIngestTriangulationV1Input["material"] {
  if (value.kind === "json") return {
    kind: "json",
    value: structuredClone(value.value),
  };
  if (value.kind === "text") return {
    kind: "text",
    text: value.text,
    ...(value.media_type === undefined ? {} : { media_type: value.media_type }),
  };
  if (value.kind === "file") return {
    kind: "file",
    file: {
      path_rel: value.file.path_rel,
      source: [Buffer.from(value.file.content_base64, "base64")],
    },
  };
  return {
    kind: "file_set",
    files: value.files.map((file) => ({
      path_rel: file.path_rel,
      source: [Buffer.from(file.content_base64, "base64")],
    })),
  };
}

function ingestInput(all: Fixtures, id: string): AuthorizedIngestTriangulationV1Input {
  const entry = ingestCase(all, id);
  const material = all.ingest_materials[id];
  if (!material) throw new Error(`Missing Ingest material: ${id}`);
  return {
    bundle: structuredClone(entry.bundle),
    material: ingestSource(material),
    intent: {
      subject: {
        kind: "ingest",
        id: (entry.bundle as { identity: { object_key: string } }).identity.object_key,
        hedera_network: "testnet",
      },
      expected: [],
    },
    hcs_reference: { message_id: `${SEQUENCE}@${TOPIC}` },
  };
}

function object(value: unknown, name: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Invalid ${name} fixture`);
  }
  return structuredClone(value) as Record<string, unknown>;
}

function testnetIngestReceipt(entry: IngestCase): unknown {
  const receipt = entry.anchored_receipts.find((candidate) => {
    if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return false;
    const row = candidate as Record<string, unknown>;
    return row.mode === "register_and_anchor" && row.hedera_network === "testnet";
  });
  if (!receipt) throw new Error(`Missing testnet anchored receipt: ${entry.case_id}`);
  return structuredClone(receipt);
}

function conflictingIngestReceipt(entry: IngestCase, merkleRoot: string): unknown {
  const original = object(testnetIngestReceipt(entry), "testnet anchored Ingest receipt");
  const evidence = object(original.evidence, "testnet anchored Ingest receipt evidence");
  const { receipt_id: _receiptId, ...originalBody } = original;
  void _receiptId;

  const body = {
    ...originalBody,
    evidence: {
      ...evidence,
      merkle_root: merkleRoot,
    },
  };

  return {
    ...body,
    receipt_id: hashHfV1({
      material: "json",
      domain: "va:ingest:receipt:v1",
      value: body,
    }),
  };
}

function datasetRegistryPayload(entry: DatasetCase, fingerprint = entry.bundle_expectations.dataset_fingerprint) {
  const key = entry.bundle_expectations.dataset_key;
  return {
    _type: "core.dataset_registry.event.v1",
    event: "dataset_version.created",
    entity_id: `${key}@3`,
    ts: "2026-11-06T00:00:00.000Z",
    actor_user_id: PRIVATE_ACTOR,
    hedera_network: "testnet",
    service_event_hash: "c".repeat(128),
    payload: {
      dataset_version_id: DATASET_VERSION,
      dataset_key: key,
      version: 3,
      dataset_fingerprint: fingerprint,
      manifest_hash: null,
      schema_hash: null,
      bytes_estimate: 128,
      row_count: 4,
      col_count: 2,
      set_active: false,
    },
  };
}

function datasetPolicy(key: string): VerificationPolicyV1 {
  return {
    schema_version: VERIFICATION_POLICY_SCHEMA_VERSION,
    subject: { kind: "dataset", id: key, hedera_network: "testnet" },
    report_kind: "authorized_dataset_triangulation",
    required_checks: [
      "dataset.source_binding",
      "triangulation.provided_authorized.dataset_fingerprint",
    ],
    required_assurance: ["mirror_corroboration"],
    on_unresolved: "review",
  };
}

function ingestPolicy(key: string): VerificationPolicyV1 {
  return {
    schema_version: VERIFICATION_POLICY_SCHEMA_VERSION,
    subject: { kind: "ingest", id: key, hedera_network: "testnet" },
    report_kind: "authorized_ingest_triangulation",
    required_checks: [
      "ingest.source_binding",
      "triangulation.provided_authorized.merkle_root",
    ],
    required_assurance: ["mirror_corroboration"],
    on_unresolved: "review",
  };
}

function coreResponse(payload: unknown, topicName: string) {
  return {
    ok: true,
    hedera_network: "testnet",
    mode: "decrypt_only",
    verified: null,
    topic: {
      name: topicName,
      topic_id: TOPIC,
      key_version: null,
    },
    encryption: {
      topic_key_version: null,
      user_key_version: null,
    },
    tx: {
      id: "authorized-integration-tx",
      message_id: `${SEQUENCE}@${TOPIC}`,
      transaction_id: TX,
      sequence_number: SEQUENCE,
      consensus_timestamp: "1234567890.123456789",
      status: "confirmed",
      mirror_verified: false,
      mirror_verified_at: null,
    },
    hash: {
      expected: null,
      computed: null,
      match: null,
    },
    message_binding: {
      schema_version: "vera.hcs-message-binding.v1",
      algorithm: "sha3-512",
      message_sha3_512: MESSAGE_DIGEST,
      message_bytes: MESSAGE.length,
    },
    payload,
  };
}

/** Only external Core and Mirror HTTP are simulated; authenticated verifier behavior remains real. */
function authorizedTransport(
  payload: unknown,
  topicName: string,
  state: TransportState = "consistent",
) {
  const requests: Array<{ url: URL; init: RequestInit }> = [];
  const fetch_impl = vi.fn(async (
    raw: string | URL | Request,
    init: RequestInit = {},
  ): Promise<Response> => {
    const url = new URL(String(raw));
    requests.push({ url, init });

    if (url.host === "core.example.test" && url.pathname === "/v1/hcs/verify-decrypt") {
      if (state === "forbidden") {
        return Response.json({ error: "forbidden" }, { status: 403 });
      }
      return Response.json(coreResponse(payload, topicName));
    }

    if (url.host === "mirror.example.test" &&
      url.pathname === `/api/v1/topics/${TOPIC}/messages/${SEQUENCE}`) {
      if (state === "mirror_unavailable") {
        return Response.json({}, { status: 404 });
      }
      const bytes = state === "mirror_conflict"
        ? Buffer.from("conflicting-authorized-message", "utf8")
        : MESSAGE;
      return Response.json({
        topic_id: TOPIC,
        sequence_number: SEQUENCE,
        consensus_timestamp: "1234567890.123456789",
        message: bytes.toString("base64"),
      });
    }

    if (url.host === "mirror.example.test" &&
      url.pathname === "/api/v1/transactions/0.0.77-1234567890-123456789") {
      return Response.json({
        transactions: [{
          transaction_id: "0.0.77-1234567890-123456789",
          result: "SUCCESS",
          consensus_timestamp: "1234567890.123456790",
        }],
      });
    }

    throw new Error(`Unexpected authenticated integration endpoint: ${url.toString()}`);
  });

  return {
    requests,
    config: {
      core: {
        base_url: CORE,
        auth_provider: createStaticBearerAuthProviderV1(TEST_TOKEN),
        fetch_impl: fetch_impl as typeof fetch,
      },
      mirror: {
        base_urls: { testnet: MIRROR },
        fetch_impl: fetch_impl as typeof fetch,
      },
    },
  };
}

function authorization(init: RequestInit): string | null {
  return new Headers(init.headers).get("authorization");
}

describe("Authenticated private workflow integration", () => {
  it("INT-A01 verifies a private Dataset through Core, Mirror, portable report and policy", async () => {
    const all = await fixtures();
    const sample = datasetCase(all, "basic-v1");
    const key = sample.bundle_expectations.dataset_key;
    const transport = authorizedTransport(datasetRegistryPayload(sample), "dataset_registry_events");

    const result = await triangulateAuthorizedDatasetWithPolicyV1(
      transport.config,
      datasetInput(all, "basic-v1"),
      datasetPolicy(key),
    );

    expect(result.policy).toMatchObject({ decision: "allow", authority: "sdk_verification" });
    expect(result.report.kind).toBe("authorized_dataset_triangulation");
    expect(result.report.core.findings.find((finding) =>
      finding.check_id === "triangulation.provided_authorized.dataset_fingerprint")?.outcome).toBe("pass");
    expect(result.report.core.findings.find((finding) =>
      finding.check_id === "triangulation.authorized_hedera.message_sha3_512")?.outcome).toBe("pass");
    expect(validatePortableVerificationReportV1(result.report).status).toBe("valid");

    const coreRequests = transport.requests.filter((request) => request.url.host === "core.example.test");
    const mirrorRequests = transport.requests.filter((request) => request.url.host === "mirror.example.test");
    expect(coreRequests).toHaveLength(1);
    expect(mirrorRequests).toHaveLength(2);
    expect(authorization(coreRequests[0]!.init)).toBe(`Bearer ${TEST_TOKEN}`);
    expect(mirrorRequests.every((request) => authorization(request.init) === null)).toBe(true);
    expect(coreRequests[0]!.init).toMatchObject({
      method: "POST",
      redirect: "error",
      credentials: "omit",
      cache: "no-store",
    });
    expect(JSON.parse(String(coreRequests[0]!.init.body))).toEqual({
      hedera_network: "testnet",
      message_id: `${SEQUENCE}@${TOPIC}`,
      mode: "decrypt_only",
      include_decrypted: true,
    });

    const serialized = JSON.stringify(result.report);
    expect(serialized).not.toContain(TEST_TOKEN);
    expect(serialized).not.toContain(PRIVATE_ACTOR);
  });

  it("INT-A02 verifies private Ingest commitments including the Merkle root", async () => {
    const all = await fixtures();
    const sample = ingestCase(all, "json-v1");
    const key = (sample.bundle as { identity: { object_key: string } }).identity.object_key;
    const receipt = testnetIngestReceipt(sample);
    expect(verifyIngestV1Receipt(receipt).ok).toBe(true);
    const transport = authorizedTransport(receipt, "merkle_anchor");

    const result = await triangulateAuthorizedIngestWithPolicyV1(
      transport.config,
      ingestInput(all, "json-v1"),
      ingestPolicy(key),
    );

    expect(result.policy).toMatchObject({ decision: "allow", authority: "sdk_verification" });
    expect(result.report.kind).toBe("authorized_ingest_triangulation");
    expect(result.report.core.findings.find((finding) =>
      finding.check_id === "triangulation.provided_authorized.merkle_root")?.outcome).toBe("pass");
    expect(result.report.core.findings.find((finding) =>
      finding.check_id === "triangulation.authorized_ingest.receipt_profile")?.outcome).toBe("pass");
    expect(validatePortableVerificationReportV1(result.report).status).toBe("valid");
    expect(JSON.stringify(result.report)).not.toContain("evidence_pointer");
  });

  it("INT-A03 treats Core authorization failure as unresolved and never falls back", async () => {
    const all = await fixtures();
    const sample = datasetCase(all, "basic-v1");
    const key = sample.bundle_expectations.dataset_key;
    const transport = authorizedTransport(
      datasetRegistryPayload(sample),
      "dataset_registry_events",
      "forbidden",
    );

    const result = await triangulateAuthorizedDatasetWithPolicyV1(
      transport.config,
      datasetInput(all, "basic-v1"),
      datasetPolicy(key),
    );

    expect(result.policy.decision).toBe("review");
    expect(result.policy.reason_codes).toContain("POLICY_AUTHORIZED_EVIDENCE_INCOMPLETE");
    expect(transport.requests).toHaveLength(1);
    expect(transport.requests[0]!.url.host).toBe("core.example.test");
    expect(authorization(transport.requests[0]!.init)).toBe(`Bearer ${TEST_TOKEN}`);
  });

  it("INT-A04 keeps unavailable Mirror corroboration non-authorizing", async () => {
    const all = await fixtures();
    const sample = datasetCase(all, "basic-v1");
    const key = sample.bundle_expectations.dataset_key;
    const transport = authorizedTransport(
      datasetRegistryPayload(sample),
      "dataset_registry_events",
      "mirror_unavailable",
    );

    const result = await triangulateAuthorizedDatasetWithPolicyV1(
      transport.config,
      datasetInput(all, "basic-v1"),
      datasetPolicy(key),
    );

    expect(result.policy.decision).toBe("review");
    expect(result.policy.reason_codes).toContain("POLICY_AUTHORIZED_EVIDENCE_INCOMPLETE");
    expect(result.report.core.findings.find((finding) =>
      finding.check_id === "triangulation.authorized_hedera.message_sha3_512")?.outcome).not.toBe("pass");
    expect(validatePortableVerificationReportV1(result.report).status).toBe("valid");
  });

  it("INT-A05 denies Core evidence that conflicts with independently retrieved Hedera bytes", async () => {
    const all = await fixtures();
    const sample = datasetCase(all, "basic-v1");
    const key = sample.bundle_expectations.dataset_key;
    const transport = authorizedTransport(
      datasetRegistryPayload(sample),
      "dataset_registry_events",
      "mirror_conflict",
    );

    const result = await triangulateAuthorizedDatasetWithPolicyV1(
      transport.config,
      datasetInput(all, "basic-v1"),
      datasetPolicy(key),
    );

    expect(result.policy.decision).toBe("deny");
    expect(result.report.core.findings.find((finding) =>
      finding.check_id === "triangulation.authorized_hedera.message_sha3_512")?.outcome).toBe("fail");
    expect(validatePortableVerificationReportV1(result.report).status).toBe("valid");
  });

  it("INT-A06 denies a self-consistent authorized Ingest receipt whose Merkle root contradicts local recomputation", async () => {
    const all = await fixtures();
    const sample = ingestCase(all, "json-v1");
    const key = (sample.bundle as { identity: { object_key: string } }).identity.object_key;
    const receipt = conflictingIngestReceipt(sample, "0".repeat(128));
    expect(verifyIngestV1Receipt(receipt).ok).toBe(true);
    const transport = authorizedTransport(receipt, "merkle_anchor");

    const result = await triangulateAuthorizedIngestWithPolicyV1(
      transport.config,
      ingestInput(all, "json-v1"),
      ingestPolicy(key),
    );

    expect(result.policy.decision).toBe("deny");
    expect(result.report.core.findings.find((finding) =>
      finding.check_id === "triangulation.provided_authorized.merkle_root")?.outcome).toBe("fail");
    expect(result.report.core.findings.find((finding) =>
      finding.check_id === "triangulation.authorized_hedera.message_sha3_512")?.outcome).toBe("pass");
    expect(validatePortableVerificationReportV1(result.report).status).toBe("valid");
  });
});