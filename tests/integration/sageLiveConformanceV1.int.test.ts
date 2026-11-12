import { readFile } from "node:fs/promises";
import { decompress as zstdDecompress } from "@mongodb-js/zstd";
import { describe, expect, it } from "vitest";
import {
  VERIFICATION_POLICY_SCHEMA_VERSION,
  assessPortableVerificationPolicyV1,
  resolveExplorerExecutionV1,
  triangulateExecutionWithPolicyV1,
  validatePortableVerificationReportV1,
  verifyExecutionStandardsWithPolicyV1,
  verifyExecutionWithPolicyV1,
  type VerificationPolicyV1,
} from "../../src/index.js";
import type { ExecutionV1Input } from "../../src/profiles/execution/verificationV1.js";

/** Pinned October 21, 2026 mainnet live conformance. */
const JOB = "4e4f624d-25b6-577f-93c6-075292e722d6";
const RESULT = "b7e96d64-c2b0-5739-90e5-36cfeecc95bb";
const NETWORK = "mainnet" as const;
const fixtureDir = new URL(
  "./fixtures/conformance/sage/mainnet/2026-10-21/",
  import.meta.url,
);

const explorer = "https://explorer.veraanchor.com";
const LIVE_TEST_TIMEOUT_MS = 60_000;
const mirrors = {
  mainnet: "https://mainnet-public.mirrornode.hedera.com/api/v1",
  testnet: "https://testnet.mirrornode.hedera.com/api/v1",
} as const;
type Network = keyof typeof mirrors;
type Json = Record<string, unknown>;

/** Test-runtime HCS-1 decoder for Node versions without native Zstd. */
async function decompressZstd(
  compressed: Uint8Array,
  maxOutputBytes: number,
): Promise<Uint8Array> {
  const decoded = await zstdDecompress(Buffer.from(compressed));
  if (decoded.byteLength > maxOutputBytes) {
    throw new RangeError("HCS1_FILE_TOO_LARGE");
  }
  return decoded;
}

function object(value: unknown, label: string): Json {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be a JSON object`);
  }
  return value as Json;
}

function string(value: unknown, label: string): string {
  if (typeof value !== "string" || !value.length) {
    throw new TypeError(`${label} is missing`);
  }
  return value;
}

function item(parent: Json, key: string): Json {
  return object(parent[key], key);
}

async function snapshot(name: "result" | "standards"): Promise<Json> {
  // PowerShell 5.1 UTF-8 exports may include a BOM.
  const bytes = (
    await readFile(new URL(`${name}.json`, fixtureDir), "utf8")
  ).replace(/^\uFEFF/, "");
  return object(JSON.parse(bytes) as unknown, name);
}

async function pinned() {
  const network = NETWORK;
  const [result, standards] = await Promise.all([
    snapshot("result"),
    snapshot("standards"),
  ]);

  const execution = item(standards, "execution");
  const resultEvidence = item(standards, "result_evidence");
  const jobId = string(result.job_id, "result.job_id");
  const resultId = string(result.result_id, "result.result_id");

  expect(result.id).toBe(resultId);
  expect(result.hedera_network).toBe(network);
  expect(execution.hedera_network).toBe(network);
  expect(execution.job_id).toBe(jobId);
  expect(execution.result_id).toBe(resultId);
  expect(resultEvidence.result_id).toBe(resultId);
  expect(execution.pipeline_hash).toBe(result.pipeline_hash);
  expect(item(execution, "dataset").dataset_key).toBe(result.dataset_key);
  expect(item(resultEvidence, "hcs").transaction_id).toBe(result.hcs_transaction_id);
  expect(item(resultEvidence, "hcs").topic_id).toBe(result.hcs_topic_id);
  expect(item(resultEvidence, "digest_payload")).toHaveProperty("result");
  expect(
    item(item(resultEvidence, "digest_payload"), "result").result_hash_sha3_512,
  ).toBe(result.data_hash);
  expect(resultEvidence.result_hash).toBe(result.data_hash);
  expect(resultEvidence.pipeline_hash).toBe(result.pipeline_hash);
  expect(resultEvidence.binding_digest).toBe(item(standards, "binding").digest);
  expect(resultEvidence.acceptance_digest).toBe(item(standards, "acceptance").digest);

  expect(jobId).toBe(JOB);
  expect(resultId).toBe(RESULT);
  expect(result.proof_date).toBe("2026-10-21");

  // The original result HCS record is not a separately disclosed public publication.
  expect(result.publication_result_transaction_id).toBeNull();
  expect(result.publication_result_message_id).toBeNull();

  const input: ExecutionV1Input = {
    profile: "sage-standards-v1",
    expected_program: "sage",
    evidence: standards,
    intent: {
      subject: {
        kind: "execution",
        id: jobId,
        hedera_network: network,
      },
      expected: [],
    },
    result_id: resultId,
  };

  return { network, jobId, resultId, standards, result, input };
}

type Sample = Awaited<ReturnType<typeof pinned>>;
type Kind = "execution" | "execution_triangulation" | "independent_standards";

function policy(sample: Sample, kind: Kind): VerificationPolicyV1 {
  return {
    schema_version: VERIFICATION_POLICY_SCHEMA_VERSION,
    subject: sample.input.intent.subject,
    report_kind: kind,
    required_checks: kind === "independent_standards"
      ? ["binding.digest_recomputed", "standards.references_resolved"]
      : [
          "binding.digest_recomputed",
          "acceptance.digest_recomputed",
          "result_evidence.digest_recomputed",
        ],
    ...(kind === "execution"
      ? {}
      : { required_assurance: ["mirror_corroboration" as const] }),
    execution_scope: {
      profile: "sage-standards-v1",
      expected_program: "sage",
      requested_result_id: sample.resultId,
    },
    on_unresolved: "review",
  };
}

function summary(report: {
  core: {
    findings: readonly {
      check_id: string;
      outcome: string;
      reason_code: string | null;
    }[];
  };
}) {
  return report.core.findings
    .filter((finding) => finding.outcome === "fail")
    .map((finding) => ({
      check_id: finding.check_id,
      reason_code: finding.reason_code,
    }));
}

function context(value: unknown, field: string): Json {
  return item(object(value, "report.context"), field);
}

/**
 * Produce reference-level diagnostics for failed live standards checks.
 * No raw HCS-1 documents, account contents, or fetched payloads are emitted.
 */
function independentStandardsDiagnostics(
  standards: Json,
  findings: readonly {
    check_id: string;
    outcome: string;
    reason_code: string | null;
  }[],
): string {
  const references = Array.isArray(standards.items)
    ? standards.items.map((value, index) => {
        const entry = object(value, `standards.items[${index}]`);
        return {
          index,
          key: entry.key,
          standard: entry.standard,
          reference: entry.reference,
          status: entry.status,
          reason_code: entry.reason_code,
          resolver_id: entry.resolver_id,
          assurance: entry.assurance,
          historical_consensus_timestamps_exact:
            entry.historical_consensus_timestamps_exact,
        };
      })
    : [];

  return JSON.stringify({
    network: standards.network,
    status: standards.status,
    assurance: standards.assurance,
    references,
    failed_findings: findings
      .filter((finding) => finding.outcome === "fail")
      .map((finding) => ({
        check_id: finding.check_id,
        reason_code: finding.reason_code,
      })),
    unresolved_findings: findings
      .filter((finding) =>
        finding.check_id.startsWith("standards.") &&
        finding.outcome !== "pass" &&
        finding.outcome !== "fail"
      )
      .map((finding) => ({
        check_id: finding.check_id,
        outcome: finding.outcome,
        reason_code: finding.reason_code,
      })),
  }, null, 2);
}

describe("SAGE mainnet conformance: 2026-10-21 pinned execution", () => {
  it("LIVE-S01 validates the pinned job/result, hashes, and explicit network", async () => {
    const sample = await pinned();

    expect(item(sample.standards, "execution").program).toBe("sage");
    expect(sample.result.program).toBe("sage");
    expect(item(sample.standards, "result_evidence").sealed_at).toBeTruthy();
  });

  it("LIVE-S02 resolves exact Explorer evidence and detects wrong-network routing", async () => {
    const sample = await pinned();
    const config = { base_url: explorer };
    const selected = {
      job_id: sample.jobId,
      result_id: sample.resultId,
      network: sample.network,
    };

    const first = await resolveExplorerExecutionV1(config, selected);

    expect(first.status, first.reason_code ?? "Explorer lookup").toBe("resolved");

    const live = item(object(first.evidence, "live standards"), "execution");

    expect(live.job_id).toBe(sample.jobId);
    expect(live.result_id).toBe(sample.resultId);
    expect(live.hedera_network).toBe(sample.network);
    expect(item(object(first.evidence, "live standards"), "binding").digest)
      .toBe(item(sample.standards, "binding").digest);
    expect(item(object(first.evidence, "live standards"), "result_evidence").digest)
      .toBe(item(sample.standards, "result_evidence").digest);

    const substituted = await resolveExplorerExecutionV1(config, {
      ...selected,
      result_id: "11111111-1111-4111-8111-111111111111",
    });

    expect(
      substituted.status,
      "Unselected result must never fall back to the latest result",
    ).not.toBe("resolved");

    const other: Network = sample.network === "mainnet" ? "testnet" : "mainnet";
    const crossed = await resolveExplorerExecutionV1(config, {
      ...selected,
      network: other,
    });

    expect(
      crossed.status,
      "An explicitly wrong-network lookup must not resolve",
    ).not.toBe("resolved");

    const again = await resolveExplorerExecutionV1(config, selected);

    expect(again.status, again.reason_code ?? "repeat lookup").toBe("resolved");
  }, LIVE_TEST_TIMEOUT_MS);

  it("LIVE-S03 independently recomputes the pinned execution, acceptance and result commitments", async () => {
    const sample = await pinned();
    const workflow = verifyExecutionWithPolicyV1(
      sample.input,
      policy(sample, "execution"),
    );

    expect(workflow.report.kind).toBe("execution");

    for (const check of [
      "binding.digest_recomputed",
      "acceptance.digest_recomputed",
      "result_evidence.digest_recomputed",
      "intent.subject",
      "intent.result",
    ]) {
      expect(
        workflow.report.core.findings.find(
          (finding) => finding.check_id === check,
        )?.outcome,
        check,
      ).toBe("pass");
    }

    expect(summary(workflow.report)).toEqual([]);
    expect(validatePortableVerificationReportV1(workflow.report).status)
      .toBe("valid");

    // Offline evidence alone does not establish independent public authority.
    expect(
      assessPortableVerificationPolicyV1(
        workflow.report,
        policy(sample, "execution"),
      ).decision,
    ).not.toBe("allow");
  });

  it("LIVE-S04 independently triangulates the selected execution against the correct Hedera Mirror", async () => {
    const sample = await pinned();
    const requirement = policy(sample, "execution_triangulation");

    const workflow = await triangulateExecutionWithPolicyV1({
      explorer: { base_url: explorer },
      mirror: {
        base_urls: { [sample.network]: mirrors[sample.network] },
      },
    }, sample.input, requirement);

    expect(workflow.report.kind).toBe("execution_triangulation");

    const publicExecution = context(
      workflow.report.context,
      "public_execution",
    );

    expect(publicExecution).toMatchObject({
      public_record_acquisition: "resolved",
      hedera_resolution: "resolved",
    });
    expect(publicExecution).not.toHaveProperty(
      "publication_payload_binding",
    );

    expect(publicExecution.status).toBe("resolved");
    expect(summary(workflow.report)).toEqual([]);

    expect(
      workflow.policy.requirements.find(
        (requirement) =>
          requirement.key === "assurance.mirror_corroboration",
      )?.outcome,
    ).toBe("pass");

    expect(validatePortableVerificationReportV1(workflow.report).status)
      .toBe("valid");

    // Neither plaintext publication binding nor Merkle membership is established.
    expect(
      assessPortableVerificationPolicyV1(
        workflow.report,
        requirement,
      ).decision,
    ).not.toBe("allow");
  });

  it("LIVE-S05 resolves the actual historical HCS standards independently on the selected network", async () => {
    const sample = await pinned();

    const workflow = await verifyExecutionStandardsWithPolicyV1(
      {
        base_urls: { [sample.network]: mirrors[sample.network] },
      },
      sample.input,
      { decompress_zstd: decompressZstd },
      policy(sample, "independent_standards"),
    );

    expect(workflow.report.kind).toBe("independent_standards");

    const standards = context(
      workflow.report.context,
      "independent_standards",
    );

    const diagnostics = independentStandardsDiagnostics(
      standards,
      workflow.report.core.findings,
    );

    const expectedKeys = [
      "agent:requester",
      "agent:executor",
      "capability:hcs26",
      "schema:sage_parameters:0",
      "schema:execution_binding:1",
      "schema:result_evidence:2",
    ];

    const references = Array.isArray(standards.items)
      ? standards.items.map((value, index) =>
          object(value, `standards.items[${index}]`)
        )
      : [];

    expect(
      references.map((entry) => entry.key),
      diagnostics,
    ).toEqual(expectedKeys);

    expect(
      references
        .filter((entry) => entry.status !== "resolved")
        .map((entry) => ({
          key: entry.key,
          reference: entry.reference,
          status: entry.status,
          reason_code: entry.reason_code,
          resolver_id: entry.resolver_id,
        })),
      diagnostics,
    ).toEqual([]);

    expect(standards.status, diagnostics).toBe("verified");
    expect(standards.assurance, diagnostics).toBe("mirror_corroborated");

    expect(standards).toMatchObject({
      network: sample.network,
    });
    for (const field of [
      "did_controller_authentication",
      "hedera_consensus_authentication",
      "historical_account_memo_binding",
      "manifest_files_resolution",
      "json_schema_instance_validation",
    ]) {
      expect(standards, field).not.toHaveProperty(field);
    }

    expect(
      workflow.report.core.findings.find(
        (finding) =>
          finding.check_id === "standards.references_resolved",
      )?.outcome,
      diagnostics,
    ).toBe("pass");

    expect(summary(workflow.report), diagnostics).toEqual([]);
    expect(validatePortableVerificationReportV1(workflow.report).status)
      .toBe("valid");
  }, LIVE_TEST_TIMEOUT_MS);

  it("LIVE-S06 rejects contradictory reliance scope without performing any network I/O", async () => {
    const sample = await pinned();
    const wrong: Network = sample.network === "mainnet" ? "testnet" : "mainnet";

    const forbiddenFetch: typeof fetch = async () => {
      throw new Error("Network I/O must not occur before scope validation");
    };

    const changed: VerificationPolicyV1 = {
      ...policy(sample, "execution_triangulation"),
      subject: {
        kind: "execution",
        id: sample.jobId,
        hedera_network: wrong,
      },
    };

    await expect(triangulateExecutionWithPolicyV1({
      explorer: {
        base_url: explorer,
        fetch_impl: forbiddenFetch,
      },
      mirror: {
        base_urls: { [sample.network]: mirrors[sample.network] },
        fetch_impl: forbiddenFetch,
      },
    }, sample.input, changed)).rejects.toThrow(/policy intent/);
  });
});