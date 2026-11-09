import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

import {
  VERIFICATION_POLICY_SCHEMA_VERSION,
  resolveExplorerIngestV1,
  triangulateIngestV1,
  triangulateIngestWithPolicyV1,
  validatePortableVerificationReportV1,
  verifyIngestV1Bundle,
  verifyIngestV1Pair,
  verifyIngestV1Receipt,
  verifyIngestV1WithIntent,
  type IngestV1IntentInput,
  type VerificationPolicyV1,
} from "../../src/index.js";


/**
 * Pinned mainnet Ingest conformance.
 *
 * The fixture is a real Vera Anchor mainnet file Ingest produced through
 * Hash Factory and publicly resolvable through the Core Merkle anchor path.
 *
 * Source bytes are deterministically recomputed before any public resolution.
 */
const OBJECT_KEY = "hf.first-ingest.demo";

const NETWORK = "mainnet" as const;

/**
 * Core anchor request created for the Ingest receipt.
 *
 * This is intentionally distinct from:
 * - the Ingest object key
 * - the later Core root anchor row
 * - the Core root ID
 */
const ANCHOR_REQUEST_ID =
  "8c05a623-a217-44de-9f82-70b1190330e6";

const ROOT_ANCHOR_ID =
  "6d76e547-7803-4d6e-9b6c-7e8cf1692caf";

const ROOT_ID =
  "32acf859-0390-4a44-bd40-6798939be87a";

const SOURCE_PATH = "vera_anchor_ingest_example.txt";

const EXPECTED_SOURCE_BYTES = 71;

const EXPECTED_SOURCE_SHA3_512 =
  "5a296115fa8ef838797d9168ada7d96ed0c824441fa1efd5b330ea37bb0bfa9400ce60cc437ab7b47b4d91033acde41d2c4294cc7ae6195e7378fd4ba27778d7";

const EXPECTED_FINGERPRINT =
  "7b3eb268ac387fa604335f32834349b81c61468e740230025ee652ad65e4280b555f47f0d2db74556d95d48bbe26da16c7d8751b0e0f8b373ee33f170c5bb0f5";

const EXPECTED_BUNDLE_DIGEST =
  "a80892b2f77853074c8534146c95429a72ff96746e91a1daba73af5ee706f04bc7a4d93c27badeaf034bec1ccf19562dff0e1e10ee492cc8090c855d7649f542";

const EXPECTED_MERKLE_ROOT =
  "af689d911487c83afaa36cc16523790275b4664c94193d1e345e6fc68a57580704d278998a89dcfade2b93f3aa4f0f5b884f4e3380395e353b561823df17542c";

const EXPECTED_LEAF_HASH =
  "af689d911487c83afaa36cc16523790275b4664c94193d1e345e6fc68a57580704d278998a89dcfade2b93f3aa4f0f5b884f4e3380395e353b561823df17542c";

const EXPECTED_ROOT_HASH =
  "8ce748ed52a162826cfa16b09a94dfe3e5a51aab10764994d64cc9847193ef55493c77a70b34f25b6ba69a4d7ae876bcc86ec09bc30cdecd1ba71690158d1b64";

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
  "./fixtures/conformance/ingest/mainnet/2026-10-31/",
  import.meta.url,
);

const sourceFile = new URL(
  `./source/${SOURCE_PATH}`,
  fixtureDir,
);


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


async function pinned() {
  const [bundle, receipt, sourceBytes] = await Promise.all([
    jsonFixture("bundle"),
    jsonFixture("receipt"),
    readFile(sourceFile),
  ]);

  const intent = {
    subject: {
      kind: "ingest" as const,
      id: OBJECT_KEY,
      hedera_network: NETWORK,
    },
    expected: [],
  };

  const input = (): IngestV1IntentInput => ({
    bundle,
    receipt,
    material: {
      kind: "file",
      file: {
        path_rel: SOURCE_PATH,
        source: [Buffer.from(sourceBytes)],
      },
    },
    intent,
  });

  const publicInput = () => ({
    ...input(),
    anchor_request_id: ANCHOR_REQUEST_ID,
  });

  return {
    bundle,
    receipt,
    sourceBytes,
    input,
    publicInput,
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


function factValue(
  observation: {
    facts: readonly {
      key: string;
      state: string;
      value?: unknown;
    }[];
  } | null,
  key: string,
): unknown {
  const fact = observation?.facts.find(
    (entry) => entry.key === key,
  );

  return fact?.state === "available"
    ? fact.value
    : null;
}


function policy(): VerificationPolicyV1 {
  return {
    schema_version: VERIFICATION_POLICY_SCHEMA_VERSION,
    subject: {
      kind: "ingest",
      id: OBJECT_KEY,
      hedera_network: NETWORK,
    },
    report_kind: "public_triangulation",
    required_checks: [
      "ingest.source_binding",
      "ingest.bundle_consistency",
      "ingest.receipt_binding",
      "intent.subject",
      "intent.declared_network",
      "triangulation.public_record_hedera.message_sha3_512",
    ],
    required_assurance: [
      "mirror_corroboration",
    ],
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
  "Ingest mainnet conformance: pinned Vera Anchor verifier example",
  () => {
    it(
      "LIVE-I01 validates the pinned bundle, receipt, source bytes, and explicit mainnet identities",
      async () => {
        const sample = await pinned();

        const bundleResult =
          verifyIngestV1Bundle(sample.bundle);

        const receiptResult =
          verifyIngestV1Receipt(sample.receipt);

        const pairResult =
          verifyIngestV1Pair({
            bundle: sample.bundle,
            receipt: sample.receipt,
          });

        expect(
          bundleResult.ok,
          JSON.stringify(
            bundleResult.mismatches,
            null,
            2,
          ),
        ).toBe(true);

        expect(
          receiptResult.ok,
          JSON.stringify(
            receiptResult.mismatches,
            null,
            2,
          ),
        ).toBe(true);

        expect(
          pairResult.ok,
          JSON.stringify(
            pairResult.mismatches,
            null,
            2,
          ),
        ).toBe(true);

        expect(bundleResult.mismatches).toEqual([]);
        expect(receiptResult.mismatches).toEqual([]);
        expect(pairResult.mismatches).toEqual([]);

        const bundleIdentity = item(
          sample.bundle,
          "identity",
        );

        const receiptIdentity = item(
          sample.receipt,
          "identity",
        );

        const evidence = item(
          sample.receipt,
          "evidence",
        );

        const merkle = item(
          sample.bundle,
          "merkle",
        );

        expect(bundleIdentity.object_key).toBe(
          OBJECT_KEY,
        );

        expect(receiptIdentity.object_key).toBe(
          OBJECT_KEY,
        );

        expect(sample.receipt.hedera_network).toBe(
          NETWORK,
        );

        expect(sample.sourceBytes.byteLength).toBe(
          EXPECTED_SOURCE_BYTES,
        );

        expect(
          createHash("sha3-512")
            .update(sample.sourceBytes)
            .digest("hex"),
        ).toBe(EXPECTED_SOURCE_SHA3_512);

        expect(evidence.fingerprint).toBe(
          EXPECTED_FINGERPRINT,
        );

        expect(evidence.bundle_digest).toBe(
          EXPECTED_BUNDLE_DIGEST,
        );

        expect(evidence.merkle_root).toBe(
          EXPECTED_MERKLE_ROOT,
        );

        expect(evidence.item_count).toBe(1);
        expect(evidence.total_bytes).toBe(
          EXPECTED_SOURCE_BYTES,
        );

        expect(merkle.root).toBe(
          EXPECTED_MERKLE_ROOT,
        );

        expect(merkle.leaf_count).toBe(1);

        const items = sample.bundle.items;

        if (
          !Array.isArray(items) ||
          items.length !== 1
        ) {
          throw new TypeError(
            "Pinned Ingest bundle must contain exactly one item",
          );
        }

        const committed = object(
          items[0],
          "bundle.items[0]",
        );

        expect(committed.item_kind).toBe("file");
        expect(committed.path_rel).toBe(
          SOURCE_PATH,
        );
        expect(committed.bytes).toBe(
          EXPECTED_SOURCE_BYTES,
        );
        expect(committed.sha3_512).toBe(
          EXPECTED_SOURCE_SHA3_512,
        );
        expect(committed.leaf_hash).toBe(
          EXPECTED_LEAF_HASH,
        );

        const core = item(
          sample.receipt,
          "core",
        );

        const receiptAnchor = item(
          core,
          "receipt_anchor",
        );

        const rootAnchor = item(
          core,
          "root_anchor",
        );

        expect(receiptAnchor.id).toBe(
          ANCHOR_REQUEST_ID,
        );

        expect(receiptAnchor.anchor_kind).toBe(
          "custom",
        );

        expect(receiptAnchor.payload_type).toBe(
          "ingest_receipt_v1",
        );

        expect(receiptAnchor.hedera_network).toBe(
          NETWORK,
        );

        expect(rootAnchor.id).toBe(
          ROOT_ANCHOR_ID,
        );

        expect(rootAnchor.anchor_kind).toBe(
          "root",
        );

        expect(rootAnchor.root_id).toBe(
          ROOT_ID,
        );

        expect(rootAnchor.root_hash).toBe(
          EXPECTED_ROOT_HASH,
        );

        expect(rootAnchor.hedera_network).toBe(
          NETWORK,
        );
      },
    );

    it(
      "LIVE-I02 independently recomputes the pinned source, bundle, receipt, and declared network",
      async () => {
        const sample = await pinned();

        const report =
          await verifyIngestV1WithIntent(
            sample.input(),
          );

        for (const checkId of [
          "ingest.source_binding",
          "ingest.bundle_consistency",
          "ingest.receipt_binding",
          "intent.subject",
          "intent.declared_network",
        ]) {
          expect(
            finding(report, checkId)?.outcome,
            checkId,
          ).toBe("pass");
        }

        expect(
          failedFindings(report),
        ).toEqual([]);
      },
    );

    it(
      "LIVE-I03 resolves the exact public Core anchor and rejects anchor, object, or network substitution",
      async () => {
        const config = {
          base_url: EXPLORER,
          timeout_ms: LIVE_HTTP_TIMEOUT_MS,
        };

        const selected = {
          anchor_request_id: ANCHOR_REQUEST_ID,
          ingest_object_key: OBJECT_KEY,
          network: NETWORK,
        };

        const first =
          await resolveExplorerIngestV1(
            config,
            selected,
          );

        expect(
          first.status,
          first.reason_code ??
            "Explorer Ingest lookup",
        ).toBe("resolved");

        expect(first.publication).toMatchObject({
          hedera_network: NETWORK,
          entity_kind: "merkle_anchor",
          entity_id: ANCHOR_REQUEST_ID,
        });

        expect(
          factValue(
            first.observation,
            "ingest.object_key",
          ),
        ).toBe(OBJECT_KEY);

        expect(
          factValue(
            first.observation,
            "fingerprint",
          ),
        ).toBe(EXPECTED_FINGERPRINT);

        expect(
          factValue(
            first.observation,
            "bundle_digest",
          ),
        ).toBe(EXPECTED_BUNDLE_DIGEST);

        expect(
          factValue(
            first.observation,
            "ingest.merkle_root",
          ),
        ).toBe(EXPECTED_MERKLE_ROOT);

        expect(
          factValue(
            first.observation,
            "merkle.anchor_request_id",
          ),
        ).toBe(ANCHOR_REQUEST_ID);

        // This public record is the explicit custom receipt anchor.
        // Its root identity is intentionally absent; the later Core root anchor is a
        // separate evidence object pinned independently in LIVE-I01.
        expect(
        factValue(
            first.observation,
            "merkle.root_id",
        ),
        ).toBeNull();

        expect(
        factValue(
            first.observation,
            "merkle.root_hash",
        ),
        ).toBeNull();

        const unrelatedAnchor =
          await resolveExplorerIngestV1(
            config,
            {
              ...selected,
              anchor_request_id:
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            },
          );

        expect(
          unrelatedAnchor.status,
          "An unselected Core anchor must never fall back to another public anchor",
        ).not.toBe("resolved");

        const wrongObject =
          await resolveExplorerIngestV1(
            config,
            {
              ...selected,
              ingest_object_key:
                "hf.unrelated-ingest.demo",
            },
          );

        expect(
          wrongObject.status,
          "A Core anchor bound to another Ingest object must not resolve as the selected object",
        ).not.toBe("resolved");

        const other: Network =
          NETWORK === "mainnet"
            ? "testnet"
            : "mainnet";

        const crossed =
          await resolveExplorerIngestV1(
            config,
            {
              ...selected,
              network: other,
            },
          );

        expect(
          crossed.status,
          "An explicitly wrong-network Ingest lookup must not resolve",
        ).not.toBe("resolved");

        const again =
          await resolveExplorerIngestV1(
            config,
            selected,
          );

        expect(
          again.status,
          again.reason_code ??
            "repeat Ingest lookup",
        ).toBe("resolved");

        expect(again.publication).toEqual(
          first.publication,
        );
      },
      LIVE_TEST_TIMEOUT_MS,
    );

    it(
      "LIVE-I04 independently triangulates the selected Ingest publication against Hedera mainnet Mirror",
      async () => {
        const sample = await pinned();

        const result =
          await triangulateIngestV1(
            publicConfig(),
            sample.publicInput(),
          );

        expect(
          result.consistency,
          JSON.stringify(
            {
              resolution: result.resolution,
              relationships:
                result.relationships,
              non_pass:
                result.report.findings.filter(
                  (entry) =>
                    entry.outcome !== "pass",
                ),
            },
            null,
            2,
          ),
        ).toBe("consistent");

        expect(
          result.resolution,
        ).toMatchObject({
          public_record: "resolved",
          publication_disclosure: "resolved",
          hedera_mirror: "resolved",
        });

        expect(
          finding(
            result.report,
            "triangulation.provided_public_record.ingest_fingerprint",
          )?.outcome,
        ).toBe("pass");

        expect(
          finding(
            result.report,
            "triangulation.provided_public_record.ingest_bundle_digest",
          )?.outcome,
        ).toBe("pass");

        expect(
          finding(
            result.report,
            "triangulation.provided_public_record.publication_subject",
          )?.outcome,
        ).toBe("pass");

        expect(
          finding(
            result.report,
            "triangulation.provided_public_record.publication_fingerprint",
          )?.outcome,
        ).toBe("pass");

        expect(
          finding(
            result.report,
            "triangulation.provided_public_record.publication_bundle_digest",
          )?.outcome,
        ).toBe("pass");

        for (const checkId of [
          "triangulation.public_record_hedera.publication_topic",
          "triangulation.public_record_hedera.publication_sequence",
          "triangulation.public_record_hedera.message_sha3_512",
          "triangulation.public_record_hedera.message_bytes",
        ]) {
          expect(
            finding(
              result.report,
              checkId,
            )?.outcome,
            checkId,
          ).toBe("pass");
        }

        expect(
          failedFindings(result.report),
        ).toEqual([]);

        const unresolved =
          result.report.findings.filter(
            (entry) =>
              entry.outcome !== "pass",
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
      "LIVE-I05 evaluates the real public Ingest pathway through the SDK policy boundary",
      async () => {
        const sample = await pinned();

        const workflow =
          await triangulateIngestWithPolicyV1(
            publicConfig(),
            sample.publicInput(),
            policy(),
          );

        expect(
          workflow.report.kind,
        ).toBe(
          "public_triangulation",
        );

        expect(
          validatePortableVerificationReportV1(
            workflow.report,
          ).status,
        ).toBe("valid");

        expect(
          workflow.policy,
        ).toMatchObject({
          decision: "allow",
          authority: "sdk_verification",
        });

        expect(
          workflow.policy.requirements.find(
            (entry) =>
              entry.key ===
              "verification.public_evidence",
          )?.outcome,
        ).toBe("pass");

        expect(
          workflow.policy.requirements.find(
            (entry) =>
              entry.key ===
              "assurance.mirror_corroboration",
          )?.outcome,
        ).toBe("pass");

        expect(
          workflow.report.core.intent.subject,
        ).toEqual({
          kind: "ingest",
          id: OBJECT_KEY,
          hedera_network: NETWORK,
        });

        expect(
          workflow.report.context,
        ).toMatchObject({
          resolution: {
            public_record: "resolved",
            publication_disclosure:
              "resolved",
            hedera_mirror: "resolved",
          },
        });

        expect(
          workflow.report.context,
        ).not.toHaveProperty(
          "publication_payload_binding",
        );

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
      "LIVE-I06 rejects contradictory reliance scope without performing any network I/O",
      async () => {
        const sample = await pinned();

        const wrong: Network =
          NETWORK === "mainnet"
            ? "testnet"
            : "mainnet";

        const forbiddenFetch: typeof fetch =
          async () => {
            throw new Error(
              "Network I/O must not occur before Ingest scope validation",
            );
          };

        const changed: VerificationPolicyV1 = {
          ...policy(),
          subject: {
            kind: "ingest",
            id: OBJECT_KEY,
            hedera_network: wrong,
          },
        };

        await expect(
          triangulateIngestWithPolicyV1(
            {
              explorer: {
                base_url: EXPLORER,
                fetch_impl:
                  forbiddenFetch,
              },
              mirror: {
                base_urls: {
                  [NETWORK]:
                    MIRRORS[NETWORK],
                },
                fetch_impl:
                  forbiddenFetch,
              },
            },
            sample.publicInput(),
            changed,
          ),
        ).rejects.toThrow(
          /policy intent/,
        );
      },
    );
  },
);