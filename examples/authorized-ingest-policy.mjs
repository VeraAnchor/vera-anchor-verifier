import { readFile } from "node:fs/promises";

import {
  createStaticBearerAuthProviderV1,
  triangulateAuthorizedIngestWithPolicyV1,
} from "@veraanchor/verifier";

const [bundlePath, materialPath, intentPath, policyPath, messageId] =
  process.argv.slice(2);

const coreUrl = process.env.VERA_ANCHOR_CORE_URL;
const apiKey = process.env.VERA_ANCHOR_API_KEY;

if (
  !bundlePath ||
  !materialPath ||
  !intentPath ||
  !policyPath ||
  !messageId ||
  !coreUrl ||
  !apiKey
) {
  console.error(
    "Usage: VERA_ANCHOR_CORE_URL=<url> VERA_ANCHOR_API_KEY=<key> " +
      "node examples/authorized-ingest-policy.mjs " +
      "<bundle.json> <material.json> <intent.json> <policy.json> <message-id>",
  );
  process.exit(64);
}

async function readJson(path) {
  const text = (await readFile(path, "utf8")).replace(/^\uFEFF/, "");
  return JSON.parse(text);
}

const [bundle, material, intent, policy] = await Promise.all([
  readJson(bundlePath),
  readJson(materialPath),
  readJson(intentPath),
  readJson(policyPath),
]);

if (
  !material ||
  typeof material !== "object" ||
  (material.kind !== "json" && material.kind !== "text")
) {
  console.error(
    "This example supports JSON and text Ingest material. " +
      "Use the library API directly for file and file-set sources.",
  );
  process.exit(64);
}

const result = await triangulateAuthorizedIngestWithPolicyV1(
  {
    core: {
      base_url: coreUrl,
      auth_provider: createStaticBearerAuthProviderV1(apiKey),
    },
  },
  {
    bundle,
    material,
    intent,
    hcs_reference: {
      message_id: messageId,
    },
  },
  policy,
);

console.log(JSON.stringify(result, null, 2));

process.exitCode =
  result.policy.decision === "allow"
    ? 0
    : result.policy.decision === "review"
      ? 2
      : 1;