import { readFile } from "node:fs/promises";

import { verifyIngestWithPolicyV1 } from "@veraanchor/verifier";

const [bundlePath, receiptPath, materialPath, intentPath, policyPath] =
  process.argv.slice(2);

if (
  !bundlePath ||
  !receiptPath ||
  !materialPath ||
  !intentPath ||
  !policyPath
) {
  console.error(
    "Usage: node examples/ingest-policy.mjs " +
      "<bundle.json> <receipt.json> <material.json> " +
      "<intent.json> <policy.json>",
  );
  process.exit(64);
}

async function readJson(path) {
  const text = (await readFile(path, "utf8")).replace(/^\uFEFF/, "");
  return JSON.parse(text);
}

const [bundle, receipt, material, intent, policy] = await Promise.all([
  readJson(bundlePath),
  readJson(receiptPath),
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

const result = await verifyIngestWithPolicyV1(
  {
    bundle,
    receipt,
    material,
    intent,
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