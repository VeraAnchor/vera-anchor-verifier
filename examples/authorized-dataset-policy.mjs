import { readFile } from "node:fs/promises";

import {
  createStaticBearerAuthProviderV1,
  triangulateAuthorizedDatasetWithPolicyV1,
} from "@veraanchor/verifier";

const [
  bundlePath,
  receiptPath,
  sourcePath,
  pathRel,
  intentPath,
  policyPath,
  messageId,
] = process.argv.slice(2);

const coreUrl = process.env.VERA_ANCHOR_CORE_URL;
const apiKey = process.env.VERA_ANCHOR_API_KEY;

if (
  !bundlePath ||
  !receiptPath ||
  !sourcePath ||
  !pathRel ||
  !intentPath ||
  !policyPath ||
  !messageId ||
  !coreUrl ||
  !apiKey
) {
  console.error(
    "Usage: VERA_ANCHOR_CORE_URL=<url> VERA_ANCHOR_API_KEY=<key> " +
      "node examples/authorized-dataset-policy.mjs " +
      "<bundle.json> <receipt.json> <source-file> <producer-relative-path> " +
      "<intent.json> <policy.json> <message-id>",
  );
  process.exit(64);
}

async function readJson(path) {
  const text = (await readFile(path, "utf8")).replace(/^\uFEFF/, "");
  return JSON.parse(text);
}

const [bundle, receipt, sourceBytes, intent, policy] = await Promise.all([
  readJson(bundlePath),
  readJson(receiptPath),
  readFile(sourcePath),
  readJson(intentPath),
  readJson(policyPath),
]);

const result = await triangulateAuthorizedDatasetWithPolicyV1(
  {
    core: {
      base_url: coreUrl,
      auth_provider: createStaticBearerAuthProviderV1(apiKey),
    },
  },
  {
    bundle,
    receipt,
    files: [
      {
        path_rel: pathRel,
        source: [sourceBytes],
      },
    ],
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