import { readFile } from "node:fs/promises";

import { verifyDatasetWithPolicyV1 } from "@veraanchor/verifier";

const [bundlePath, receiptPath, sourcePath, pathRel, intentPath, policyPath] =
  process.argv.slice(2);

if (
  !bundlePath ||
  !receiptPath ||
  !sourcePath ||
  !pathRel ||
  !intentPath ||
  !policyPath
) {
  console.error(
    "Usage: node examples/dataset-policy.mjs " +
      "<bundle.json> <receipt.json> <source-file> <producer-relative-path> " +
      "<intent.json> <policy.json>",
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

const result = await verifyDatasetWithPolicyV1(
  {
    bundle,
    receipt,
    intent,
    files: [
      {
        path_rel: pathRel,
        source: [sourceBytes],
      },
    ],
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
