import { readFile } from "node:fs/promises";

import { verifyDatasetV1WithIntent } from "@veraanchor/verifier";

const [bundlePath, receiptPath, sourcePath, pathRel, datasetKey, network] =
  process.argv.slice(2);

if (
  !bundlePath ||
  !receiptPath ||
  !sourcePath ||
  !pathRel ||
  !datasetKey ||
  (network !== "mainnet" && network !== "testnet")
) {
  console.error(
    "Usage: node examples/dataset-offline.mjs " +
      "<bundle.json> <receipt.json> <source-file> <producer-relative-path> " +
      "<dataset-key> <mainnet|testnet>",
  );
  process.exit(64);
}

async function readJson(path) {
  const text = (await readFile(path, "utf8")).replace(/^\uFEFF/, "");
  return JSON.parse(text);
}

const [bundle, receipt, sourceBytes] = await Promise.all([
  readJson(bundlePath),
  readJson(receiptPath),
  readFile(sourcePath),
]);

const report = await verifyDatasetV1WithIntent({
  bundle,
  receipt,
  intent: {
    subject: {
      kind: "dataset",
      id: datasetKey,
      hedera_network: network,
    },
    expected: [],
  },
  files: [
    {
      path_rel: pathRel,
      source: [sourceBytes],
    },
  ],
});

console.log(JSON.stringify(report, null, 2));

if (report.findings.some((finding) => finding.outcome === "fail")) {
  process.exitCode = 1;
}
