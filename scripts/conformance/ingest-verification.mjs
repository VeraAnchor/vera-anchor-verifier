// Ingest v1 source -> HF bundle/receipt -> optional Explorer/Hedera conformance.
// Offline by default. --live explicitly authorizes public GET and Explorer's
// decrypt/verify POST, which may create audit/job records in Core.
// Repository conformance example, not a versioned @vera-anchor/verifier CLI API.
import { createReadStream } from 'node:fs';
import { lstat, readFile, readdir } from 'node:fs/promises';
import { basename, join, relative, resolve, sep } from 'node:path';

const EXPLORER_URL = 'https://explorer.veraanchor.com';
const MAX_DOCUMENT_BYTES = 20 * 1024 * 1024;
const MAX_SOURCE_FILES = 5_000;
const EXIT = Object.freeze({
  pass: 0,
  usage: 1,
  invalid: 2,
  source: 3,
  conflict: 4,
  incomplete: 5,
  operational: 6,
});
const LOCAL_CHECKS = [
  'ingest.source_binding',
  'ingest.bundle_consistency',
  'ingest.receipt_binding',
  'intent.subject',
];
const EXPECTED_ASSURANCE_LIMIT = 'EXPLORER_ASSISTED_DECRYPTION';

function help() {
  return `Usage (from @vera-anchor/verifier repo root after npm run build):
  node scripts/conformance/ingest-verification.mjs <bundle.json> <receipt.json> <source> [options]

Source is a JSON/text document, a single file, or a directory according to
bundle.identity.object_kind (json | text | file | file_set).

  --ingest-object-key <key>       Caller-expected Ingest key (required live)
  --network <testnet|mainnet>     Caller-expected Hedera network (required live)
  --anchor-request-id <uuid>     Explicit PUBLIC anchor ID (required live)
  --live                         Enable Explorer/Mirror network requests and
                                 an Explorer decrypt/verify POST (audit possible)
  --explorer-url <url>           Explorer HTTPS origin (default: ${EXPLORER_URL})
  --explorer-timeout-ms <n>      Explorer timeout (default 15000; max 60000)
  --mirror-timeout-ms <n>        Mirror timeout (default 12000; max 15000)
  --path-prefix <posix-path>     Explicit path prefix for file_set sources
  --media-type <type>            Caller-supplied media type for text sources
  --expect-fingerprint <hex>     Independently expected Ingest fingerprint
  --expect-root <hex>            Independently expected HF Merkle root
  --expect-leaf-count <n>        Required alongside --expect-root
  --json                         Print a sanitized JSON report
  --help                         Show help

Exit: 0 verified; 1 usage; 2 invalid evidence; 3 source mismatch;
      4 conflicting evidence; 5 incomplete live evidence; 6 operational error.

Original receipt/root HCS anchors are NOT public Explorer publication receipts.
The live anchor request ID must be chosen independently of the supplied receipt.`;
}

function fail(message, code = EXIT.usage) {
  const error = new Error(message);
  error.exitCode = code;
  throw error;
}

function parseArgs(argv) {
  const opts = {
    live: false,
    json: false,
    explorer_url: EXPLORER_URL,
    explorer_timeout_ms: 30_000,
    mirror_timeout_ms: 12_000,
  };

  const valued = new Map([
    ['--ingest-object-key', 'object_key'],
    ['--network', 'network'],
    ['--anchor-request-id', 'anchor_request_id'],
    ['--explorer-url', 'explorer_url'],
    ['--explorer-timeout-ms', 'explorer_timeout_ms'],
    ['--mirror-timeout-ms', 'mirror_timeout_ms'],
    ['--path-prefix', 'path_prefix'],
    ['--media-type', 'media_type'],
    ['--expect-fingerprint', 'expected_fingerprint'],
    ['--expect-root', 'expected_root'],
    ['--expect-leaf-count', 'expected_leaf_count'],
  ]);

  const positional = [];
  const supplied = new Set();

  for (let i = 0; i < argv.length; i++) {
    const option = argv[i];

    if (option === '--help' || option === '-h') {
      return { help: true };
    }

    if (option === '--live' || option === '--json') {
      if (supplied.has(option)) fail(`Repeated flag: ${option}`);
      supplied.add(option);
      opts[option.slice(2)] = true;
    } else if (valued.has(option)) {
      if (supplied.has(option)) fail(`Repeated option: ${option}`);
      supplied.add(option);

      const value = argv[++i];
      if (!value || value.startsWith('--')) {
        fail(`Missing value for ${option}`);
      }

      opts[valued.get(option)] = value;
    } else if (option.startsWith('-')) {
      fail(`Unknown option: ${option}`);
    } else {
      positional.push(option);
    }
  }

  if (positional.length !== 3) {
    fail('Expected bundle, receipt, and source paths');
  }

  if (
    opts.network !== undefined &&
    opts.network !== 'mainnet' &&
    opts.network !== 'testnet'
  ) {
    fail('Invalid network');
  }

  if (
    opts.object_key !== undefined &&
    !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/.test(opts.object_key)
  ) {
    fail('Invalid Ingest object key');
  }

  if (
    opts.anchor_request_id !== undefined &&
    !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(
      opts.anchor_request_id
    )
  ) {
    fail('Invalid anchor request ID');
  }

  if (
    opts.live &&
    (!opts.object_key || !opts.network || !opts.anchor_request_id)
  ) {
    fail(
      'Live verification requires caller-supplied --ingest-object-key, ' +
      '--network and --anchor-request-id'
    );
  }

  for (const [name, min, max] of [
    ['explorer_timeout_ms', 100, 60_000],
    ['mirror_timeout_ms', 250, 15_000],
  ]) {
    const n = Number(opts[name]);
    if (!Number.isSafeInteger(n) || n < min || n > max) {
      fail(`Invalid ${name} (expected integer ${min}–${max})`);
    }
    opts[name] = n;
  }

  if (
    opts.path_prefix !== undefined &&
    (
      !/^[A-Za-z0-9_. -]+(?:\/[A-Za-z0-9_. -]+)*$/.test(opts.path_prefix) ||
      opts.path_prefix.split('/').some((s) => s === '.' || s === '..')
    )
  ) {
    fail('Invalid POSIX --path-prefix');
  }

  if (
    opts.media_type !== undefined &&
    (
      !/^[\w.+-]+\/[\w.+-]+(?:;[\w=.+-]+)*$/.test(opts.media_type) ||
      opts.media_type.length > 128
    )
  ) {
    fail('Invalid --media-type');
  }

  const hash = /^[0-9a-f]{128}$/i;

  if (opts.expected_fingerprint && !hash.test(opts.expected_fingerprint)) {
    fail('Invalid --expect-fingerprint');
  }

  if (Boolean(opts.expected_root) !== Boolean(opts.expected_leaf_count)) {
    fail('--expect-root and --expect-leaf-count are a pair');
  }

  if (
    opts.expected_root &&
    (
      !hash.test(opts.expected_root) ||
      !/^[1-9][0-9]*$/.test(opts.expected_leaf_count) ||
      !Number.isSafeInteger(Number(opts.expected_leaf_count))
    )
  ) {
    fail('Invalid expected Merkle commitment');
  }

  if (opts.expected_leaf_count) {
    opts.expected_leaf_count = Number(opts.expected_leaf_count);
  }

  opts.paths = positional.map((name) => resolve(name));
  return opts;
}

async function regularFile(path, maxBytes = null) {
  const meta = await lstat(path);

  if (
    !meta.isFile() ||
    meta.isSymbolicLink() ||
    (maxBytes !== null && meta.size > maxBytes)
  ) {
    fail(
      'Expected a regular non-symlink file within supported limits',
      EXIT.invalid
    );
  }

  return meta;
}

async function document(path) {
  await regularFile(path, MAX_DOCUMENT_BYTES);

  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch {
    fail('Invalid JSON document', EXIT.invalid);
  }
}

async function sourceEntries(root) {
  const dir = await lstat(root);

  if (!dir.isDirectory() || dir.isSymbolicLink()) {
    fail('file_set source must be a real directory', EXIT.source);
  }

  const files = [];

  async function walk(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const absolute = join(directory, entry.name);

      if (entry.isSymbolicLink()) {
        fail('Symlinks are not supported', EXIT.source);
      }

      if (entry.isDirectory()) {
        await walk(absolute);
      } else if (entry.isFile()) {
        const path_rel = relative(root, absolute).split(sep).join('/');

        if (
          !path_rel ||
          path_rel.startsWith('../') ||
          path_rel.includes('/../')
        ) {
          fail('Source path escapes root', EXIT.source);
        }

        files.push({ path_rel, absolute });

        if (files.length > MAX_SOURCE_FILES) {
          fail('Source tree exceeds 5000 files', EXIT.source);
        }
      } else {
        fail('Unsupported filesystem entry in source tree', EXIT.source);
      }
    }
  }

  await walk(root);

  files.sort((a, b) =>
    a.path_rel < b.path_rel ? -1 : a.path_rel > b.path_rel ? 1 : 0
  );

  return files;
}

function selectFileSetPaths(
  discovered,
  root,
  bundle,
  hashHfV1,
  explicitPrefix
) {
  const declared = bundle.items;

  if (!Array.isArray(declared) || declared.length === 0) {
    fail('Missing Ingest item commitments', EXIT.invalid);
  }

  const redacted = bundle.rules?.redact_paths === true;
  const field = redacted ? 'path_hash' : 'path_rel';

  const candidates = explicitPrefix === undefined
    ? [
        { mode: 'directory_relative', prefix: '' },
        {
          mode: 'directory_name_prefixed',
          prefix: `${basename(root)}/`,
        },
      ]
    : [
        {
          mode: 'caller_supplied_prefix',
          prefix: `${explicitPrefix}/`,
        },
      ];

  const compared = candidates.map(({ mode, prefix }) => {
    const files = discovered.map((file) => {
      const path_rel = prefix + file.path_rel;

      const commitment = redacted
        ? hashHfV1({
            domain: 'va:ingest:path:v1',
            material: 'json',
            value: { path_rel },
          })
        : path_rel;

      return {
        absolute: file.absolute,
        path_rel,
        commitment,
      };
    });

    // SDK sorts file_set material by path_hash when redacted,
    // and by path_rel otherwise.
    files.sort((a, b) =>
      a.commitment < b.commitment
        ? -1
        : a.commitment > b.commitment
          ? 1
          : 0
    );

    const matched = files.reduce(
      (n, file, i) =>
        n + Number(file.commitment === declared[i]?.[field]),
      0
    );

    return { mode, files, matched };
  });

  const exact = compared.filter(
    (candidate) =>
      candidate.files.length === declared.length &&
      candidate.matched === declared.length
  );

  if (exact.length !== 1) {
    return {
      files: null,
      diagnostics: compared.map(({ mode, files, matched }) => ({
        mode,
        file_count: files.length,
        matched_commitments: matched,
      })),
      reason_code: exact.length
        ? 'AMBIGUOUS_SOURCE_PATH_LAYOUT'
        : 'SOURCE_PATH_LAYOUT_MISMATCH',
    };
  }

  return {
    files: exact[0].files,
    mode: exact[0].mode,
  };
}

async function materialFactory(opts, bundle, sdk) {
  const kind = bundle.identity?.object_kind;
  const sourcePath = opts.paths[2];

  if (kind === 'json') {
    if (opts.path_prefix || opts.media_type) {
      fail('JSON source does not accept path prefix or media type');
    }

    const value = await document(sourcePath);

    return {
      description: { kind },
      material: () => ({ kind, value }),
    };
  }

  if (kind === 'text') {
    if (opts.path_prefix) {
      fail('Text source does not accept path prefix');
    }

    await regularFile(sourcePath, MAX_DOCUMENT_BYTES);

    const text = new TextDecoder('utf-8', {
      fatal: true,
    }).decode(await readFile(sourcePath));

    const declaredType = bundle.items?.[0]?.media_type;
    const media_type = opts.media_type ?? declaredType;

    return {
      description: { kind },
      material: () => ({
        kind,
        text,
        ...(media_type ? { media_type } : {}),
      }),
    };
  }

  if (kind === 'file') {
    if (opts.path_prefix || opts.media_type) {
      fail('Single file source does not accept path prefix or media type');
    }

    await regularFile(sourcePath);

    const filePath = basename(sourcePath);

    return {
      description: { kind, file_count: 1 },
      material: () => ({
        kind,
        file: {
          path_rel: filePath,
          source: createReadStream(sourcePath),
        },
      }),
    };
  }

  if (kind === 'file_set') {
    if (opts.media_type) {
      fail('file_set source does not accept --media-type');
    }

    const discovered = await sourceEntries(sourcePath);
    const selected = selectFileSetPaths(
      discovered,
      sourcePath,
      bundle,
      sdk.hashHfV1,
      opts.path_prefix
    );

    if (!selected.files) {
      return { error: selected };
    }

    return {
      description: {
        kind,
        file_count: selected.files.length,
        path_layout: selected.mode,
      },
      material: () => ({
        kind,
        files: selected.files.map(({ path_rel, absolute }) => ({
          path_rel,
          source: createReadStream(absolute),
        })),
      }),
    };
  }

  fail('Unsupported Ingest object kind', EXIT.invalid);
}

function concise(findings) {
  return (findings ?? []).map(
    ({ check_id, outcome, reason_code }) => ({
      check_id,
      outcome,
      reason_code: reason_code ?? null,
    })
  );
}

function expectations(opts) {
  const out = [];

  if (opts.expected_fingerprint) {
    out.push({
      kind: 'digest',
      key: 'fingerprint',
      domain: 'va:ingest:fingerprint:v1',
      contract: 'hf-contract-v1',
      material: 'json',
      digest: opts.expected_fingerprint.toLowerCase(),
    });
  }

  if (opts.expected_root) {
    out.push({
      kind: 'merkle-root',
      key: 'merkle_root',
      tree_alg: 'hf-ingest-v1',
      root_hash: opts.expected_root.toLowerCase(),
      leaf_count: opts.expected_leaf_count,
    });
  }

  return out;
}

function classifyLive(value) {
  const findings = value.report.findings.filter(
    (finding) =>
      !(
        finding.check_id === 'triangulation.plaintext_ciphertext_binding' &&
        finding.outcome === 'indeterminate' &&
        finding.reason_code === EXPECTED_ASSURANCE_LIMIT
      )
  );

  if (
    value.consistency === 'conflict' ||
    findings.some((f) => f.outcome === 'fail')
  ) {
    return { status: 'conflict', exit: EXIT.conflict };
  }

  if (
    value.consistency !== 'consistent' ||
    findings.some((f) => f.outcome !== 'pass')
  ) {
    return { status: 'incomplete', exit: EXIT.incomplete };
  }

  return {
    status: 'verified_with_assurance_limit',
    exit: EXIT.pass,
  };
}

async function run(opts) {
  const sdk = await import(
    new URL('../../dist/index.js', import.meta.url).href
  );

  const [bundle, receipt] = await Promise.all([
    document(opts.paths[0]),
    document(opts.paths[1]),
  ]);

  const key = opts.object_key ?? bundle?.identity?.object_key;
  const network = opts.network ?? receipt?.hedera_network ?? null;

  const report = {
    tool: 'ingest-verification',
    mode: opts.live ? 'live' : 'offline',
    status: 'incomplete',
    ingest_object_key: key ?? null,
    network,
    identity_basis: opts.object_key && opts.network
      ? 'caller_supplied'
      : 'partially_derived_from_evidence',
    findings: [],
  };

  if (
    !key ||
    bundle?.identity?.object_key !== key ||
    receipt?.identity?.object_key !== key ||
    (network !== null && network !== 'mainnet' && network !== 'testnet') ||
    (opts.network && receipt?.hedera_network !== opts.network)
  ) {
    return {
      ...report,
      status: 'invalid_evidence',
      reason_code: 'INGEST_IDENTITY_OR_NETWORK_MISMATCH',
      exit: EXIT.invalid,
    };
  }

  let staticResult;

  try {
    staticResult = sdk.verifyIngestV1Pair({ bundle, receipt });
  } catch {
    return {
      ...report,
      status: 'invalid_evidence',
      reason_code: 'INGEST_PROFILE_INVALID',
      exit: EXIT.invalid,
    };
  }

  report.static = {
    pair_ok: staticResult.ok,
    mismatch_fields: staticResult.mismatches.map((m) => m.field),
  };

  if (!staticResult.ok) {
    return {
      ...report,
      status: 'invalid_evidence',
      reason_code: 'INGEST_PAIR_INVALID',
      exit: EXIT.invalid,
    };
  }

  const source = await materialFactory(opts, bundle, sdk);

  if (source.error) {
    return {
      ...report,
      status: 'source_mismatch',
      reason_code: source.error.reason_code,
      source: { candidates: source.error.diagnostics },
      exit: EXIT.source,
    };
  }

  report.source = source.description;

  const expected = expectations(opts);

  const intent = {
    subject: {
      kind: 'ingest',
      id: key,
      ...(network ? { hedera_network: network } : {}),
    },
    expected,
  };

  const input = () => ({
    bundle,
    receipt,
    intent,
    material: source.material(),
  });

  const offline = await sdk.verifyIngestV1WithIntent(input());
  report.findings = concise(offline.findings);

  const required = [
    ...LOCAL_CHECKS,
    ...(network ? ['intent.declared_network'] : []),
    ...expected.map(({ key: k }) => `intent.commitment.${k}`),
  ];

  const missing = required.filter(
    (id) =>
      !offline.findings.some(
        (finding) =>
          finding.check_id === id && finding.outcome === 'pass'
      )
  );

  const unexpected = offline.findings.filter(
    (finding) =>
      finding.outcome === 'fail' ||
      finding.outcome === 'unsupported'
  );

  if (missing.length || unexpected.length) {
    const expectedFailure = unexpected.some(
      (finding) => finding.check_id.startsWith('intent.commitment.')
    );

    const sourceResult = await sdk.verifyIngestV1Sources({
      bundle,
      receipt,
      material: source.material(),
    });

    report.source = {
      ...report.source,
      mismatch_fields: sourceResult.mismatches.map((m) => m.field),
    };

    return {
      ...report,
      status: expectedFailure ? 'conflict' : 'source_mismatch',
      reason_code: expectedFailure
        ? 'EXPECTED_COMMITMENT_MISMATCH'
        : 'OFFLINE_VERIFICATION_INCOMPLETE_OR_FAILED',
      missing_checks: missing,
      exit: expectedFailure ? EXIT.conflict : EXIT.source,
    };
  }

  if (!opts.live) {
    return {
      ...report,
      status: 'offline_verified',
      exit: EXIT.pass,
    };
  }

  const explorer = {
    base_url: opts.explorer_url,
    timeout_ms: opts.explorer_timeout_ms,
  };

  // Read-only preflight.
  // Resolver checks network, anchor ID and Ingest object key.
  const publicRecord = await sdk.resolveExplorerIngestV1(explorer, {
    ingest_object_key: key,
    anchor_request_id: opts.anchor_request_id,
    network,
  });

  report.publication = {
    lookup_status: publicRecord.status,
    reason_code: publicRecord.reason_code,
    anchor_request_id: opts.anchor_request_id,
    entity_kind: publicRecord.publication?.entity_kind ?? null,
    entity_id: publicRecord.publication?.entity_id ?? null,
    message_id: publicRecord.publication?.message_id ?? null,
  };

  if (publicRecord.status !== 'resolved') {
    return {
      ...report,
      status: publicRecord.status === 'conflict'
        ? 'conflict'
        : 'incomplete',
      reason_code:
        publicRecord.reason_code ?? 'PUBLIC_INGEST_ANCHOR_UNAVAILABLE',
      exit: publicRecord.status === 'conflict'
        ? EXIT.conflict
        : EXIT.incomplete,
    };
  }

  const pub = publicRecord.publication;

  if (
    !pub ||
    !pub.message_id ||
    !pub.transaction_id ||
    !pub.topic_id ||
    pub.sequence_number === null
  ) {
    return {
      ...report,
      status: 'incomplete',
      reason_code: 'PUBLICATION_LOCATOR_UNAVAILABLE',
      exit: EXIT.incomplete,
    };
  }

  if (
    pub.hedera_network !== network ||
    pub.entity_kind !== 'merkle_anchor' ||
    pub.entity_id !== opts.anchor_request_id
  ) {
    return {
      ...report,
      status: 'conflict',
      reason_code: 'PUBLICATION_IDENTITY_MISMATCH',
      exit: EXIT.conflict,
    };
  }

  // Explorer performs authorized disclosure internally.
  // The SDK supplies no Core authentication credentials.
  const triangulated = await sdk.triangulateIngestV1(
    {
      explorer,
      mirror: { timeout_ms: opts.mirror_timeout_ms },
    },
    {
      ...input(),
      anchor_request_id: opts.anchor_request_id,
    }
  );

  const outcome = classifyLive(triangulated);

  report.consistency = triangulated.consistency;
  report.resolution = triangulated.resolution;
  report.relationships = triangulated.relationships;
  report.findings = concise(triangulated.report.findings);
  report.assurance_note =
    'Explorer-assisted decryption does not independently authenticate plaintext to HCS ciphertext';

  return {
    ...report,
    ...outcome,
  };
}

function output(report, json) {
  if (json) {
    console.log(JSON.stringify(report, null, 2));
    return;
  }

  console.log(
    `INGEST VERIFICATION: ${report.status} (${report.mode})`
  );
  console.log(
    `Object: ${report.ingest_object_key ?? 'unknown'} · network: ${report.network ?? 'unknown'}`
  );

  if (report.static) {
    console.log('STATIC:', JSON.stringify(report.static));
  }

  if (report.source) {
    console.log('SOURCE:', JSON.stringify(report.source));
  }

  if (report.publication) {
    console.log('PUBLICATION:', JSON.stringify(report.publication));
  }

  if (report.resolution) {
    console.log('RESOLUTION:', JSON.stringify(report.resolution));
  }

  if (report.consistency) {
    console.log('CONSISTENCY:', report.consistency);
  }

  if (report.relationships) {
    console.log(
      'RELATIONSHIPS:',
      JSON.stringify(report.relationships, null, 2)
    );
  }

  if (report.findings?.length) {
    console.log(
      'FINDINGS:',
      JSON.stringify(report.findings, null, 2)
    );
  }

  if (report.reason_code) {
    console.log('REASON:', report.reason_code);
  }

  if (report.assurance_note) {
    console.log('ASSURANCE LIMIT:', report.assurance_note);
  }

  console.log('EXIT CODE:', report.exit);
}

let opts;

try {
  opts = parseArgs(process.argv.slice(2));

  if (opts.help) {
    console.log(help());
  } else {
    if (opts.live && !opts.json) {
      console.error(
        'LIVE ENABLED: Explorer decrypt/verify POST may create audit records. No anchors are submitted.'
      );
    }

    const report = await run(opts);
    output(report, opts.json);
    process.exitCode = report.exit;
  }
} catch (error) {
  const exitCode = error?.exitCode ?? EXIT.operational;

  if (opts?.json) {
    output({
      tool: 'ingest-verification',
      status: 'error',
      reason_code: error?.name ?? 'Error',
      exit: exitCode,
    }, true);
  } else {
    console.error(
      'INGEST VERIFICATION ERROR:',
      error?.message ?? String(error)
    );

    if (exitCode === EXIT.usage) {
      console.error(help());
    }
  }

  process.exitCode = exitCode;
}
