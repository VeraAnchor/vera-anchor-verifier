import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  VERIFICATION_POLICY_SCHEMA_VERSION,
  hashHfV1,
  resolveExplorerDatasetV1,
  triangulateDatasetV1,
  triangulateDatasetWithPolicyV1,
  validatePortableVerificationReportV1,
  verifyDatasetV1Bundle,
  verifyDatasetV1Receipt,
  verifyDatasetV1WithIntent,
  type VerificationPolicyV1,
} from "../../src/index.js";

import type { DatasetV1IntentInput } from "../../src/verification/sourceIntentV1.js";


/**
 * Pinned October 30, 2026 mainnet Dataset conformance.
 *
 * The fixture is a real Vera Anchor mainnet Dataset created from a public
 * execution-verification JSON example and published through Explorer.
 *
 * Source bytes are verified locally before any live public resolution occurs.
 */
const DATASET_KEY =
  "07be0cf7-4cab-40ca-aa70-87840df4d3e7.example.verification.demo.v1";

const VERSION_ID = "690cddfd-4f4c-434c-8bbe-6b195e59a571";

const NETWORK = "mainnet" as const;

const PRODUCER_PATH_PREFIX = "verification_demo";

const EXPECTED_SOURCE_BYTES = 32_786;

const EXPECTED_SOURCE_SHA3_512 =
  "04fb07f43cd1d4e89a39090eca8918b584377d4739f4f06888ecf7d1ba0ea27bf118c3c9d75c5bc6cf09c5cee32a5c20db65b6a4ee756b647ce0b597af761058";

const EXPECTED_FINGERPRINT =
  "e751f690339c388e31287c0005301b23379a96880636292ccf83e6d408d8010b0ff7fc3a45957bb8aa2725194688afa5491df16c957158ae59d4ae1ff0bfecfd";

const EXPECTED_MERKLE_ROOT =
  "d9a3fd8af269f1804865d0128826f60af25102660688af45e0dedd621d6c6a0877a254c7d175c5a407359f92176b3c7666a820834968be7c00671959e0c3e057";

const EXPECTED_BUNDLE_DIGEST =
  "21058d6e893f0e5a020336102643d92208d1c324aab60b7ac98094e4b499598dca1642c9f11ca736678fa0715a1ddc735a846636a1b1f6f056e5f1f2e0b0560d";

const EXPECTED_PATH_HASH =
  "34880399ee7d0ec954d94f6a26282f13898d005727056318a70d37475e94da626ea0411c74eef9d9f83fdb0b7202294d700d82b695daad7f91346c5b16e9228d";

const PUBLICATION_MESSAGE_ID = "51187@0.0.10740907";

const PUBLICATION_TRANSACTION_ID =
  "0.0.9316879@1793332861.048755640";

const PUBLICATION_TOPIC_ID = "0.0.10740907";

const PUBLICATION_SEQUENCE_NUMBER = 51_187;

const EXPLORER = "https://explorer.veraanchor.com";

const LIVE_HTTP_TIMEOUT_MS = 15_000;
const LIVE_TEST_TIMEOUT_MS = 60_000;

const MIRRORS = {
  mainnet: "https://mainnet-public.mirrornode.hedera.com/api/v1",
  testnet: "https://testnet.mirrornode.hedera.com/api/v1",
} as const;

type Network = keyof typeof MIRRORS;
type Json = Record<string, unknown>;

const fixtureDir = new URL(
  "./fixtures/conformance/dataset/mainnet/2026-10-30/",
  import.meta.url,
);

const fixturePath = fileURLToPath(fixtureDir);
const sourceRoot = join(fixturePath, "source");


function object(value: unknown, label: string): Json {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be a JSON object`);
  }

  return value as Json;
}


function item(parent: Json, key: string): Json {
  return object(parent[key], key);
}


async function jsonFixture(name: "bundle" | "receipt"): Promise<Json> {
  const text = (
    await readFile(new URL(`${name}.json`, fixtureDir), "utf8")
  ).replace(/^\uFEFF/, "");

  return object(JSON.parse(text) as unknown, name);
}


type DiscoveredSource = Readonly<{
  absolute: string;
  path_rel: string;
}>;


async function collectSourceFiles(root: string): Promise<DiscoveredSource[]> {
  const output: DiscoveredSource[] = [];

  async function walk(directory: string): Promise<void> {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const absolute = join(directory, entry.name);

      if (entry.isSymbolicLink()) {
        throw new TypeError(
          "Pinned Dataset source fixture must not contain symlinks",
        );
      }

      if (entry.isDirectory()) {
        await walk(absolute);
        continue;
      }

      if (!entry.isFile()) {
        throw new TypeError(
          "Pinned Dataset source fixture contains an unsupported entry",
        );
      }

      const path_rel = relative(root, absolute)
        .split(sep)
        .join("/");

      if (
        !path_rel ||
        path_rel.startsWith("../") ||
        path_rel.includes("/../")
      ) {
        throw new TypeError(
          "Pinned Dataset source fixture escapes its source root",
        );
      }

      output.push({
        absolute,
        path_rel,
      });
    }
  }

  await walk(root);

  output.sort((left, right) =>
    left.path_rel < right.path_rel
      ? -1
      : left.path_rel > right.path_rel
        ? 1
        : 0,
  );

  return output;
}


/**
 * Restore the producer-relative source prefix that was committed when this
 * pinned Dataset was created. The local fixture directory name is intentionally
 * irrelevant; verification uses the original producer-relative path.
 */
function selectCommittedPaths(
  discovered: readonly DiscoveredSource[],
  bundle: Json,
): readonly DiscoveredSource[] {
  const committed = bundle.files;

  if (!Array.isArray(committed) || committed.length !== discovered.length) {
    throw new TypeError(
      "Pinned Dataset fixture file count does not match bundle",
    );
  }

  const files = discovered.map((entry) => ({
    ...entry,
    path_rel: `${PRODUCER_PATH_PREFIX}/${entry.path_rel}`,
  }));

  const mismatches = files.flatMap((file, index) => {
    const expected = object(
      committed[index],
      `bundle.files[${index}]`,
    );

    const actual = hashHfV1({
      domain: "va:dataset:path:v1",
      material: "raw",
      bytes: Buffer.from(file.path_rel, "utf8"),
    });

    return actual === expected.path_hash
      ? []
      : [
          {
            index,
            path_rel: file.path_rel,
            expected: expected.path_hash,
            actual,
          },
        ];
  });

  if (mismatches.length) {
    throw new Error(
      `Pinned producer-relative paths do not reproduce the Dataset commitments:\n${JSON.stringify(
        mismatches,
        null,
        2,
      )}`,
    );
  }

  return files;
}


async function pinned() {
  const [bundle, receipt, discovered] = await Promise.all([
    jsonFixture("bundle"),
    jsonFixture("receipt"),
    collectSourceFiles(sourceRoot),
  ]);

  expect(discovered).toHaveLength(1);

  const files = selectCommittedPaths(discovered, bundle);

  expect(files).toHaveLength(1);

  const selected = files[0]!;

  const sourceBytes = await readFile(selected.absolute);

  const intent = {
    subject: {
      kind: "dataset" as const,
      id: DATASET_KEY,
      hedera_network: NETWORK,
    },
    expected: [],
  };

  const input = (): DatasetV1IntentInput => ({
    bundle,
    receipt,
    intent,
    files: [
      {
        path_rel: selected.path_rel,
        source: [Buffer.from(sourceBytes)],
      },
    ],
  });

  return {
    bundle,
    receipt,
    sourceBytes,
    pathRel: selected.path_rel,
    input,
  };
}


function finding(
  report: {
    findings: readonly {
      check_id: string;
      outcome: string;
      reason_code: string | null;
    }[];
  },
  checkId: string,
) {
  return report.findings.find(
    (entry) => entry.check_id === checkId,
  );
}


function failedFindings(
  report: {
    findings: readonly {
      check_id: string;
      outcome: string;
      reason_code: string | null;
    }[];
  },
) {
  return report.findings
    .filter((entry) => entry.outcome === "fail")
    .map((entry) => ({
      check_id: entry.check_id,
      reason_code: entry.reason_code,
    }));
}


function policy(): VerificationPolicyV1 {
  return {
    schema_version: VERIFICATION_POLICY_SCHEMA_VERSION,
    subject: {
      kind: "dataset",
      id: DATASET_KEY,
      hedera_network: NETWORK,
    },
    report_kind: "public_triangulation",
    required_checks: [
      "dataset.source_binding",
      "dataset.bundle_consistency",
      "dataset.receipt_binding",
      "intent.subject",
      "intent.declared_network",
      "triangulation.public_record_hedera.message_sha3_512",
    ],
    required_assurance: ["mirror_corroboration"],
    on_unresolved: "review",
  };
}


function publicConfig() {
  return {
    explorer: {
      base_url: EXPLORER,
      timeout_ms: LIVE_HTTP_TIMEOUT_MS,
    },
    mirror: {
      base_urls: {
        [NETWORK]: MIRRORS[NETWORK],
      },
      timeout_ms: LIVE_HTTP_TIMEOUT_MS,
    },
  };
}


describe(
  "Dataset mainnet conformance: 2026-10-30 pinned verification example",
  () => {
    it(
      "LIVE-D01 validates the pinned bundle, receipt, source bytes, and explicit mainnet identity",
      async () => {
        const sample = await pinned();

        const bundleResult = verifyDatasetV1Bundle(sample.bundle);
        const receiptResult = verifyDatasetV1Receipt(sample.receipt);

        expect(
          bundleResult.ok,
          JSON.stringify(bundleResult.mismatches, null, 2),
        ).toBe(true);

        expect(
          receiptResult.ok,
          JSON.stringify(receiptResult.mismatches, null, 2),
        ).toBe(true);

        expect(bundleResult.mismatches).toEqual([]);
        expect(receiptResult.mismatches).toEqual([]);

        const identity = item(
          sample.bundle,
          "dataset_identity",
        );

        const receiptIdentity = item(
          sample.receipt,
          "dataset_identity",
        );

        const evidence = item(
          sample.receipt,
          "evidence",
        );

        const merkle = item(
          sample.bundle,
          "merkle",
        );

        expect(identity.dataset_key).toBe(DATASET_KEY);
        expect(receiptIdentity.dataset_key).toBe(DATASET_KEY);
        expect(sample.receipt.hedera_network).toBe(NETWORK);

        expect(sample.sourceBytes.byteLength).toBe(
          EXPECTED_SOURCE_BYTES,
        );

        expect(
          createHash("sha3-512")
            .update(sample.sourceBytes)
            .digest("hex"),
        ).toBe(EXPECTED_SOURCE_SHA3_512);

        expect(evidence.dataset_fingerprint).toBe(
          EXPECTED_FINGERPRINT,
        );

        expect(evidence.bundle_digest).toBe(
          EXPECTED_BUNDLE_DIGEST,
        );

        expect(merkle.root).toBe(
          EXPECTED_MERKLE_ROOT,
        );

        const bundleFiles = sample.bundle.files;

        if (
          !Array.isArray(bundleFiles) ||
          bundleFiles.length !== 1
        ) {
          throw new TypeError(
            "Pinned bundle must contain exactly one source file",
          );
        }

        const committedFile = object(
          bundleFiles[0],
          "bundle.files[0]",
        );

        expect(committedFile.path_hash).toBe(
          EXPECTED_PATH_HASH,
        );

        expect(committedFile.bytes).toBe(
          EXPECTED_SOURCE_BYTES,
        );

        expect(committedFile.sha3_512).toBe(
          EXPECTED_SOURCE_SHA3_512,
        );

        expect(
          hashHfV1({
            domain: "va:dataset:path:v1",
            material: "raw",
            bytes: Buffer.from(
              sample.pathRel,
              "utf8",
            ),
          }),
        ).toBe(EXPECTED_PATH_HASH);

        const core = item(sample.receipt, "core");
        const version = item(core, "version");

        expect(version.id).toBe(VERSION_ID);
        expect(version.dataset_key).toBe(DATASET_KEY);
        expect(version.hedera_network).toBe(NETWORK);
        expect(version.dataset_fingerprint).toBe(
          EXPECTED_FINGERPRINT,
        );
      },
    );

    it(
      "LIVE-D02 independently recomputes the pinned source, bundle, receipt, and declared network",
      async () => {
        const sample = await pinned();

        const report = await verifyDatasetV1WithIntent(
          sample.input(),
        );

        for (const checkId of [
          "dataset.source_binding",
          "dataset.bundle_consistency",
          "dataset.receipt_binding",
          "intent.subject",
          "intent.declared_network",
        ]) {
          expect(
            finding(report, checkId)?.outcome,
            checkId,
          ).toBe("pass");
        }

        expect(failedFindings(report)).toEqual([]);
      },
    );

    it(
      "LIVE-D03 resolves the exact active Explorer publication and rejects key or network substitution",
      async () => {
        const selected = {
          dataset_key: DATASET_KEY,
          network: NETWORK,
        };

        const config = {
          base_url: EXPLORER,
          timeout_ms: LIVE_HTTP_TIMEOUT_MS,
        };

        const first = await resolveExplorerDatasetV1(
          config,
          selected,
        );

        expect(
          first.status,
          first.reason_code ?? "Explorer Dataset lookup",
        ).toBe("resolved");

        expect(first.publication).toMatchObject({
          entity_kind: "dataset_version",
          entity_id: VERSION_ID,
          message_id: PUBLICATION_MESSAGE_ID,
          transaction_id: PUBLICATION_TRANSACTION_ID,
          topic_id: PUBLICATION_TOPIC_ID,
          sequence_number: PUBLICATION_SEQUENCE_NUMBER,
        });

        const unrelated = await resolveExplorerDatasetV1(
          config,
          {
            ...selected,
            dataset_key:
              "07be0cf7-4cab-40ca-aa70-87840df4d3e7.unrelated.dataset.v1",
          },
        );

        expect(
          unrelated.status,
          "An unselected Dataset must never fall back to another public Dataset",
        ).not.toBe("resolved");

        const other: Network =
          NETWORK === "mainnet"
            ? "testnet"
            : "mainnet";

        const crossed = await resolveExplorerDatasetV1(
          config,
          {
            ...selected,
            network: other,
          },
        );

        expect(
          crossed.status,
          "An explicitly wrong-network Dataset lookup must not resolve",
        ).not.toBe("resolved");

        const again = await resolveExplorerDatasetV1(
          config,
          selected,
        );

        expect(
          again.status,
          again.reason_code ?? "repeat Dataset lookup",
        ).toBe("resolved");
      },
      LIVE_TEST_TIMEOUT_MS,
    );

    it(
      "LIVE-D04 independently triangulates the selected Dataset against Hedera mainnet Mirror",
      async () => {
        const sample = await pinned();

        const result = await triangulateDatasetV1(
          publicConfig(),
          sample.input(),
        );

        expect(result.consistency).toBe("consistent");

        expect(result.resolution).toMatchObject({
          public_record: "resolved",
          publication_disclosure: "resolved",
          hedera_mirror: "resolved",
        });

        expect(
          finding(
            result.report,
            "triangulation.public_record_hedera.message_sha3_512",
          )?.outcome,
        ).toBe("pass");

        expect(failedFindings(result.report)).toEqual([]);

        const unresolved = result.report.findings.filter(
          (entry) => entry.outcome !== "pass",
        );

        expect(unresolved).toEqual([
          expect.objectContaining({
            check_id:
              "triangulation.plaintext_ciphertext_binding",
            outcome: "indeterminate",
            reason_code:
              "EXPLORER_ASSISTED_DECRYPTION",
          }),
        ]);
      },
      LIVE_TEST_TIMEOUT_MS,
    );

    it(
      "LIVE-D05 evaluates the real public Dataset pathway through the SDK policy boundary",
      async () => {
        const sample = await pinned();
        const requirement = policy();

        const workflow =
          await triangulateDatasetWithPolicyV1(
            publicConfig(),
            sample.input(),
            requirement,
          );

        expect(workflow.report.kind).toBe(
          "public_triangulation",
        );

        expect(
          validatePortableVerificationReportV1(
            workflow.report,
          ).status,
        ).toBe("valid");

        expect(workflow.policy).toMatchObject({
          decision: "allow",
          authority: "sdk_verification",
        });

        expect(
          workflow.policy.requirements.find(
            (entry) =>
              entry.key ===
              "assurance.mirror_corroboration",
          )?.outcome,
        ).toBe("pass");

        expect(
          workflow.report.core.findings.find(
            (entry) =>
              entry.check_id ===
              "triangulation.public_record_hedera.message_sha3_512",
          )?.outcome,
        ).toBe("pass");
      },
      LIVE_TEST_TIMEOUT_MS,
    );

    it(
      "LIVE-D06 rejects contradictory reliance scope without performing any network I/O",
      async () => {
        const sample = await pinned();

        const wrong: Network =
          NETWORK === "mainnet"
            ? "testnet"
            : "mainnet";

        const forbiddenFetch: typeof fetch = async () => {
          throw new Error(
            "Network I/O must not occur before Dataset scope validation",
          );
        };

        const changed: VerificationPolicyV1 = {
          ...policy(),
          subject: {
            kind: "dataset",
            id: DATASET_KEY,
            hedera_network: wrong,
          },
        };

        await expect(
          triangulateDatasetWithPolicyV1(
            {
              explorer: {
                base_url: EXPLORER,
                fetch_impl: forbiddenFetch,
              },
              mirror: {
                base_urls: {
                  [NETWORK]: MIRRORS[NETWORK],
                },
                fetch_impl: forbiddenFetch,
              },
            },
            sample.input(),
            changed,
          ),
        ).rejects.toThrow(/policy intent/);
      },
    );
  },
);