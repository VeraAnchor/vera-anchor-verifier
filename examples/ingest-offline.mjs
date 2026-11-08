import { readFile } from "node:fs/promises";

import { verifyIngestV1WithIntent } from "@veraanchor/verifier";

const [bundlePath, receiptPath, materialPath, objectKey, network] =
  process.argv.slice(2);

if (
  !bundlePath ||
  !receiptPath ||
  !materialPath ||
  !objectKey ||
  (network !== "mainnet" && network !== "testnet")
) {
  console.error(
    "Usage: node examples/ingest-offline.mjs " +
      "<bundle.json> <receipt.json> <material.json> <object-key> " +
      "<mainnet|testnet>",
  );
  process.exit(64);
}

async function readJson(path) {
  const text = (await readFile(path, "utf8")).replace(/^\uFEFF/, "");
  return JSON.parse(text);
}

const [bundle, receipt, material] = await Promise.all([
  readJson(bundlePath),
  readJson(receiptPath),
  readJson(materialPath),
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

const report = await verifyIngestV1WithIntent({
  bundle,
  receipt,
  material,
  intent: {
    subject: {
      kind: "ingest",
      id: objectKey,
      hedera_network: network,
    },
    expected: [],
  },
});

console.log(JSON.stringify(report, null, 2));

if (report.findings.some((finding) => finding.outcome === "fail")) {
  process.exitCode = 1;
}