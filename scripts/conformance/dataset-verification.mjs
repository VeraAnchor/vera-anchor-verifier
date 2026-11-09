// Dataset v1 conformance example for @vera-anchor/verifier.
// Local verification is offline. --live explicitly enables public Explorer and
// Hedera Mirror requests; Explorer's decrypt/verify POST may create audit records.
// This repository tool is not a published SDK API or a stable CLI contract.
import { createReadStream } from 'node:fs';
import { readFile, readdir, lstat } from 'node:fs/promises';
import { basename, join, relative, resolve, sep } from 'node:path';

const DEFAULT_EXPLORER_URL = 'https://explorer.veraanchor.com';
const MAX_EVIDENCE_BYTES = 20 * 1024 * 1024;
const MAX_FILES = 5_000;
const REQUIRED_LOCAL = [
  'dataset.source_binding', 'dataset.bundle_consistency', 'dataset.receipt_binding',
  'intent.subject',
];
const EXPECTED_PLAINTEXT_LIMIT = 'EXPLORER_ASSISTED_DECRYPTION';
const EXIT = Object.freeze({ ok: 0, usage: 1, invalid: 2, source: 3, conflict: 4, incomplete: 5, error: 6 });

function usage() {
  return `Usage:
  node scripts/conformance/dataset-verification.mjs <bundle.json> <receipt.json> <source-dir> [options]

Options:
  --dataset-key <key>       Independent expected Dataset key (required with --live)
  --network <testnet|mainnet>  Independent expected network (required with --live)
  --live                    Query Explorer + Hedera Mirror (may create decrypt audit records)
  --explorer-url <origin>   Explorer HTTPS origin (default: ${DEFAULT_EXPLORER_URL})
  --timeout-ms <ms>        HTTP timeout (default: 15000; range: 1000–120000)
  --path-prefix <posix>    Explicit producer-relative path prefix, e.g. assets/icons
  --expect-fingerprint <hex>  Independently expected SHA3-512 Dataset fingerprint
  --expect-root <hex>      Independently expected SHA3-512 source Merkle root
  --expect-leaf-count <n> Independently expected leaf count (with --expect-root)
  --json                    Emit one sanitized JSON result for automation
  --help                    Show this help

Path mapping defaults to exactly two candidates: selected-directory-relative and
selected-directory-name-prefixed. Both are checked against ALL bundle commitments;
no path mapping is accepted on a partial or ambiguous match.

Exit codes: 0 verified; 1 usage; 2 invalid evidence; 3 source mismatch;
            4 conflict; 5 incomplete live evidence; 6 operational error.`;
}

function fail(message, code) {
  const e = new Error(message);
  e.exitCode = code;
  throw e;
}

function parseArgs(args) {
  const opts = { live: false, json: false, explorer_url: DEFAULT_EXPLORER_URL, timeout_ms: 30_000 };
  const positional = [];
  const values = new Map([
    ['--dataset-key', 'dataset_key'], ['--network', 'network'],
    ['--explorer-url', 'explorer_url'], ['--timeout-ms', 'timeout_ms'],
    ['--path-prefix', 'path_prefix'], ['--expect-fingerprint', 'expected_fingerprint'],
    ['--expect-root', 'expected_root'], ['--expect-leaf-count', 'expected_leaf_count'],
  ]);
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--help' || arg === '-h') return { help: true };
    if (arg === '--live' || arg === '--json') {
      opts[arg.slice(2)] = true;
    } else if (values.has(arg)) {
      if (i + 1 >= args.length || args[i + 1].startsWith('--')) fail(`Missing value for ${arg}`, EXIT.usage);
      const field = values.get(arg);
      if (Object.hasOwn(opts, field) && field !== 'explorer_url' && field !== 'timeout_ms') {
        fail(`Repeated option: ${arg}`, EXIT.usage);
      }
      opts[field] = args[++i];
    } else if (arg.startsWith('-')) {
      fail(`Unknown option: ${arg}`, EXIT.usage);
    } else {
      positional.push(arg);
    }
  }
  if (positional.length !== 3) fail('Exactly three positional paths are required', EXIT.usage);
  if (opts.network && !['testnet', 'mainnet'].includes(opts.network)) fail('Invalid --network', EXIT.usage);
  if (opts.live && (!opts.network || !opts.dataset_key)) {
    fail('--live requires --dataset-key and --network from the caller, not from the supplied receipt', EXIT.usage);
  }
  if (opts.dataset_key && !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/.test(opts.dataset_key)) {
    fail('Invalid --dataset-key', EXIT.usage);
  }
  const timeout = Number(opts.timeout_ms);
  if (!Number.isSafeInteger(timeout) || timeout < 1_000 || timeout > 120_000) {
    fail('--timeout-ms must be an integer between 1000 and 120000', EXIT.usage);
  }
  opts.timeout_ms = timeout;
  if (opts.path_prefix !== undefined) {
    if (!/^[A-Za-z0-9_. -]+(?:\/[A-Za-z0-9_. -]+)*$/.test(opts.path_prefix) ||
        opts.path_prefix.split('/').some((part) => part === '.' || part === '..')) {
      fail('--path-prefix must be a safe relative POSIX path without dot segments', EXIT.usage);
    }
  }
  const hex = /^[0-9a-fA-F]{128}$/;
  if (opts.expected_fingerprint && !hex.test(opts.expected_fingerprint)) fail('Invalid --expect-fingerprint', EXIT.usage);
  if (Boolean(opts.expected_root) !== Boolean(opts.expected_leaf_count)) {
    fail('--expect-root and --expect-leaf-count must be provided together', EXIT.usage);
  }
  if (opts.expected_root) {
    if (!hex.test(opts.expected_root) || !/^[1-9][0-9]*$/.test(opts.expected_leaf_count) ||
        !Number.isSafeInteger(Number(opts.expected_leaf_count))) {
      fail('Invalid --expect-root or --expect-leaf-count', EXIT.usage);
    }
    opts.expected_leaf_count = Number(opts.expected_leaf_count);
  }
  opts.paths = positional.map((path) => resolve(path));
  return opts;
}

async function readEvidence(path) {
  const meta = await lstat(path);
  if (!meta.isFile() || meta.isSymbolicLink() || meta.size > MAX_EVIDENCE_BYTES) {
    fail('Evidence JSON must be a regular file within the 20 MiB limit', EXIT.invalid);
  }
  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch {
    fail('Evidence JSON could not be parsed', EXIT.invalid);
  }
}

async function collectFiles(root) {
  const rootStat = await lstat(root);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    fail('Source root must be a real directory, not a symlink', EXIT.source);
  }
  const files = [];
  async function walk(dir) {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const absolute = join(dir, entry.name);
      if (entry.isSymbolicLink()) fail('Symlinks are not supported in source trees', EXIT.source);
      if (entry.isDirectory()) await walk(absolute);
      else if (entry.isFile()) {
        const path_rel = relative(root, absolute).split(sep).join('/');
        if (!path_rel || path_rel.startsWith('../') || path_rel.includes('/../')) {
          fail('Source path escapes the selected root', EXIT.source);
        }
        files.push({ path_rel, absolute });
        if (files.length > MAX_FILES) fail('Source tree exceeds 5000 files', EXIT.source);
      } else fail('Unsupported filesystem entry in source tree', EXIT.source);
    }
  }
  await walk(root);
  files.sort((a, b) => a.path_rel < b.path_rel ? -1 : a.path_rel > b.path_rel ? 1 : 0);
  return files;
}

function selectPaths(discovered, root, bundle, hashHfV1, explicitPrefix) {
  const committed = bundle.files;
  if (!Array.isArray(committed) || !committed.length) fail('Bundle has no file commitments', EXIT.invalid);
  const redacted = bundle.rules?.redact_paths === true;
  const field = redacted ? 'path_hash' : 'path_rel';
  const prefixes = explicitPrefix !== undefined
    ? [{ mode: 'explicit_prefix', prefix: `${explicitPrefix}/` }]
    : [{ mode: 'relative_to_directory', prefix: '' },
       { mode: 'includes_directory_name', prefix: `${basename(root)}/` }];
  const candidateScores = prefixes.map(({ mode, prefix }) => {
    const files = discovered.map((file) => ({ ...file, path_rel: prefix + file.path_rel }));
    const matches = files.reduce((n, file, i) => {
      const actual = redacted
        ? hashHfV1({ domain: 'va:dataset:path:v1', material: 'raw', bytes: Buffer.from(file.path_rel, 'utf8') })
        : file.path_rel;
      return n + Number(actual === committed[i]?.[field]);
    }, 0);
    return { mode, files, matches };
  });
  const exact = candidateScores.filter((c) => c.files.length === committed.length && c.matches === committed.length);
  if (exact.length !== 1) {
    return {
      files: null,
      candidates: candidateScores.map(({ mode, files, matches }) => ({ mode, file_count: files.length, matched_commitments: matches })),
      reason: exact.length ? 'AMBIGUOUS_SOURCE_PATH_LAYOUT' : 'SOURCE_PATH_LAYOUT_MISMATCH',
    };
  }
  return { files: exact[0].files, mode: exact[0].mode };
}

function findingsSummary(findings) {
  return findings.map(({ check_id, outcome, reason_code }) => ({ check_id, outcome, reason_code: reason_code ?? null }));
}

function requiredChecks(findings, expectedIds) {
  return expectedIds.map((id) => findings.find((f) => f.check_id === id) ??
    { check_id: id, outcome: 'missing', reason_code: 'REQUIRED_CHECK_MISSING' });
}

function expectedPublication(receipt, kind) {
  const hcs = receipt?.core?.published?.published?.[kind]?.publication_receipt?.hcs;
  const entityId = kind === 'dataset_version' ? receipt?.core?.version?.id : receipt?.core?.dataset?.id;
  if (!entityId || !hcs?.messageId || !hcs?.transactionId || !hcs?.topicId || !hcs?.sequenceNumber) return null;
  return { entity_kind: kind, entity_id: entityId, message_id: hcs.messageId,
    transaction_id: hcs.transactionId, topic_id: hcs.topicId, sequence_number: String(hcs.sequenceNumber) };
}

function publicationMatches(actual, expected, network) {
  return !!expected && actual?.hedera_network === network &&
    actual.entity_kind === expected.entity_kind && actual.entity_id === expected.entity_id &&
    actual.message_id === expected.message_id && actual.transaction_id === expected.transaction_id &&
    actual.topic_id === expected.topic_id && String(actual.sequence_number) === expected.sequence_number;
}

function liveOutcome(result) {
  const others = result.report.findings.filter((f) => !(
    f.check_id === 'triangulation.plaintext_ciphertext_binding' &&
    f.outcome === 'indeterminate' && f.reason_code === EXPECTED_PLAINTEXT_LIMIT
  ));
  if (result.consistency === 'conflict' || others.some((f) => f.outcome === 'fail')) return { status: 'conflict', exit: EXIT.conflict };
  if (result.consistency !== 'consistent' || others.some((f) => f.outcome !== 'pass')) {
    return { status: 'incomplete', exit: EXIT.incomplete };
  }
  return { status: 'verified_with_assurance_limit', exit: EXIT.ok };
}

async function execute(opts) {
  const sdk = await import(new URL('../../dist/index.js', import.meta.url).href);
  const [bundle, receipt] = await Promise.all([readEvidence(opts.paths[0]), readEvidence(opts.paths[1])]);
  const key = opts.dataset_key ?? bundle?.dataset_identity?.dataset_key;
  const network = opts.network ?? receipt?.hedera_network;
  const result = { tool: 'dataset-verification', mode: opts.live ? 'live' : 'offline',
    status: 'incomplete', dataset_key: key ?? null, network: network ?? null,
    intent_basis: opts.dataset_key && opts.network ? 'caller_supplied' : 'partially_derived_from_evidence',
    findings: [] };
  if (!key || (network != null && !['mainnet', 'testnet'].includes(network)) ||
    bundle?.dataset_identity?.dataset_key !== key || receipt?.dataset_identity?.dataset_key !== key ||
    (opts.network && receipt?.hedera_network !== opts.network)) {
    return { ...result, status: 'invalid_evidence', reason_code: 'DATASET_IDENTITY_OR_NETWORK_MISMATCH', exit: EXIT.invalid };
  }
  let bundleResult;
  let receiptResult;
  try {
    bundleResult = sdk.verifyDatasetV1Bundle(bundle);
    receiptResult = sdk.verifyDatasetV1Receipt(receipt);
  } catch {
    return { ...result, status: 'invalid_evidence', reason_code: 'STATIC_PROFILE_INVALID', exit: EXIT.invalid };
  }
  result.static = { bundle_ok: bundleResult.ok, receipt_ok: receiptResult.ok,
    bundle_mismatch_fields: bundleResult.mismatches.map((m) => m.field),
    receipt_mismatch_fields: receiptResult.mismatches.map((m) => m.field) };
  if (!bundleResult.ok || !receiptResult.ok) {
    return { ...result, status: 'invalid_evidence', reason_code: 'STATIC_PROFILE_MISMATCH', exit: EXIT.invalid };
  }
  const discovered = await collectFiles(opts.paths[2]);
  const selected = selectPaths(discovered, opts.paths[2], bundle, sdk.hashHfV1, opts.path_prefix);
  if (!selected.files) {
    return { ...result, status: 'source_mismatch', reason_code: selected.reason,
      source: { candidates: selected.candidates }, exit: EXIT.source };
  }
  result.source = { file_count: selected.files.length, path_layout: selected.mode };
  const expectations = [];
  if (opts.expected_fingerprint) expectations.push({
    kind: 'digest', key: 'dataset_fingerprint', contract: 'hf-contract-v1', material: 'json',
    domain: 'va:dataset:fingerprint:v1', digest: opts.expected_fingerprint.toLowerCase(),
  });
  if (opts.expected_root) expectations.push({
    kind: 'merkle-root', key: 'merkle_root', tree_alg: 'hf-dataset-v1',
    root_hash: opts.expected_root.toLowerCase(), leaf_count: opts.expected_leaf_count,
  });
  const intent = { subject: { kind: 'dataset', id: key, ...(network ? { hedera_network: network } : {}) },
    expected: expectations }; // Caller-only expectations; never copy them out of provided evidence.
  const input = () => ({ bundle, receipt, intent,
    files: selected.files.map(({ path_rel, absolute }) => ({ path_rel, source: createReadStream(absolute) })) });
  const offline = await sdk.verifyDatasetV1WithIntent(input());
  result.findings = findingsSummary(offline.findings);
  const requiredIds = [...REQUIRED_LOCAL, ...(network ? ['intent.declared_network'] : []),
    ...expectations.map(({ key: commitmentKey }) => `intent.commitment.${commitmentKey}`)];
  const unsatisfied = requiredChecks(offline.findings, requiredIds).filter((f) => f.outcome !== 'pass');
  const failed = offline.findings.filter((f) => f.outcome === 'fail' || f.outcome === 'unsupported');
  if (unsatisfied.length || failed.length) {
    if ([...unsatisfied, ...failed].some((f) => f.check_id.startsWith('intent.commitment.'))) {
      const isConflict = [...unsatisfied, ...failed].some((f) =>
        f.check_id.startsWith('intent.commitment.') && f.outcome === 'fail');
      return { ...result, status: isConflict ? 'conflict' : 'invalid_evidence',
        reason_code: isConflict ? 'EXPECTED_COMMITMENT_MISMATCH' : 'EXPECTED_COMMITMENT_NOT_VERIFIED',
        exit: isConflict ? EXIT.conflict : EXIT.invalid };
    }
    const details = await sdk.verifyDatasetV1Sources(input());
    result.source.mismatch_fields = details.mismatches.map((m) => m.field);
    return { ...result, status: 'source_mismatch', reason_code: 'OFFLINE_CHECKS_NOT_PASSED', exit: EXIT.source };
  }
  if (!opts.live) return { ...result, status: 'offline_verified', exit: EXIT.ok };

  const explorer = { base_url: opts.explorer_url, timeout_ms: opts.timeout_ms };
  const preflight = await sdk.resolveExplorerDatasetV1(explorer, { dataset_key: key, network });
  result.publication = { lookup_status: preflight.status, reason_code: preflight.reason_code ?? null,
    entity_kind: preflight.publication?.entity_kind ?? null,
    entity_id: preflight.publication?.entity_id ?? null,
    message_id: preflight.publication?.message_id ?? null };
  if (preflight.status !== 'resolved' || !preflight.publication) {
    return { ...result, status: preflight.status === 'conflict' ? 'conflict' : 'incomplete',
      reason_code: preflight.reason_code ?? 'PUBLIC_DATASET_UNAVAILABLE',
      exit: preflight.status === 'conflict' ? EXIT.conflict : EXIT.incomplete };
  }
  const kind = preflight.publication.entity_kind;
  const expected = kind === 'dataset_version' || kind === 'dataset' ? expectedPublication(receipt, kind) : null;
  if (!expected) {
    return { ...result, status: 'incomplete', reason_code: 'EXPECTED_PUBLICATION_RECEIPT_UNAVAILABLE', exit: EXIT.incomplete };
  }
  if (!publicationMatches(preflight.publication, expected, network)) {
    return { ...result, status: 'conflict', reason_code: 'PUBLICATION_RECEIPT_MISMATCH', exit: EXIT.conflict };
  }

  // This call sends an authenticated-by-Explorer proxy POST, not an authenticated SDK request.
  // The SDK must not receive or supply Core credentials.
  const triangulated = await sdk.triangulateDatasetV1(
    { explorer, mirror: { timeout_ms: opts.timeout_ms } }, input());
  const outcome = liveOutcome(triangulated);
  result.findings = findingsSummary(triangulated.report.findings);
  result.consistency = triangulated.consistency;
  result.relationships = triangulated.relationships;
  result.resolution = triangulated.resolution;
  result.assurance_note = 'Explorer-assisted decryption does not independently authenticate plaintext to HCS ciphertext';
  return { ...result, ...outcome };
}

function output(report, json) {
  if (json) {
    console.log(JSON.stringify(report, null, 2));
    return;
  }
  console.log(`DATASET VERIFICATION: ${report.status} (${report.mode})`);
  console.log(`Subject: ${report.dataset_key ?? 'unavailable'} · network: ${report.network ?? 'unavailable'}`);
  if (report.static) console.log('STATIC:', JSON.stringify(report.static));
  if (report.source) console.log('SOURCE:', JSON.stringify(report.source));
  if (report.publication) console.log('PUBLICATION:', JSON.stringify(report.publication));
  if (report.resolution) console.log('RESOLUTION:', JSON.stringify(report.resolution));
  if (report.consistency) console.log('CONSISTENCY:', report.consistency);
  if (report.relationships) console.log('RELATIONSHIPS:', JSON.stringify(report.relationships, null, 2));
  if (report.findings?.length) console.log('FINDINGS:', JSON.stringify(report.findings, null, 2));
  if (report.reason_code) console.log('REASON:', report.reason_code);
  if (report.assurance_note) console.log('ASSURANCE LIMIT:', report.assurance_note);
  console.log('EXIT CODE:', report.exit);
}

async function main() {
  let opts;
  try {
    opts = parseArgs(process.argv.slice(2));
    if (opts.help) {
      console.log(usage());
      return;
    }
    if (opts.live && !opts.json) {
      console.error('LIVE ENABLED: Explorer decrypt/verify POST may create audit/job records; no anchors are submitted.');
    }
    const result = await execute(opts);
    output(result, opts.json);
    process.exitCode = result.exit;
  } catch (err) {
    const code = err?.exitCode ?? EXIT.error;
    if (opts?.json) output({ tool: 'dataset-verification', status: 'error', reason_code: err?.message ?? 'unknown', exit: code }, true);
    else {
      console.error('DATASET VERIFICATION ERROR:', err?.message ?? String(err));
      if (code === EXIT.usage) console.error(usage());
    }
    process.exitCode = code;
  }
}

await main();
