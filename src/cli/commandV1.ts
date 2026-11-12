import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { link, lstat, open, realpath, unlink } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import type { VerificationIntent } from "../contracts/verification.js";
import { sourceV1Path } from "../profiles/sourceV1Helpers.js";
import type { ExecutionV1Input } from "../profiles/execution/verificationV1.js";
import type { IngestV1SourceMaterial } from "../profiles/ingest/sourceV1.js";
import type { VerificationPolicyV1, VerificationPolicyWorkflowV1 } from "../policy/contractV1.js";
import { assessPortableVerificationPolicyV1, triangulateDatasetWithPolicyV1,
  triangulateIngestWithPolicyV1, verifyIngestWithPolicyV1,
  triangulateExecutionWithPolicyV1, verifyDatasetWithPolicyV1, verifyExecutionWithPolicyV1,
  verifyExecutionStandardsWithPolicyV1 } from "../policy/evaluateV1.js";
import type { PublicTriangulationV1Config } from "../triangulation/publicV1.js";
import { validatePortableVerificationReportV1 } from "../reports/validationV1.js";
import type { PortableVerificationReportV1 } from "../reports/portableV1.js";

const CLI_SCHEMA = "va.verifier-cli-result.v1";
const MAX_JSON_BYTES = 2 * 1024 * 1024;
const MAX_SOURCE_BYTES = 1024 * 1024 * 1024;
const MAX_FILES = 256;
const CLI_HELP = [
  "Usage: vera-anchor <command> [options]",
  "",
  "Commands:",
  "  verify dataset      Verify Dataset evidence",
  "  verify ingest       Verify Ingest evidence",
  "  verify execution    Verify execution evidence",
  "  verify standards    Verify supported HCS standards",
  "  report validate     Validate a portable verification report",
  "  policy assess       Assess a portable report under a policy",
  "",
  "Run with --help, -h, or help to display this message.",
  "See docs/cli.md for command options, inputs, and exit codes.",
].join("\n");
const COMMANDS = {
  "verify dataset": ["bundle", "sources", "source-root", "intent", "policy", "receipt",
    "mode", "explorer-url", "mirror-url", "report-out"],
  "verify execution": ["evidence", "intent", "policy", "verification-material",
    "mode", "explorer-url", "mirror-url", "report-out"],
  "verify ingest": ["bundle", "material", "source-root", "intent", "policy", "receipt",
    "anchor-request-id", "mode", "explorer-url", "mirror-url", "report-out"],
  "verify standards": ["evidence", "intent", "policy", "verification-material",
    "mirror-url", "report-out"],
  "report validate": ["report"],
  "policy assess": ["report", "policy"],
} as const;

type Command = keyof typeof COMMANDS;
type Emitter = (line: string) => void;
type Options = Readonly<Record<string, string>>;

class CliInputError extends Error {}

function plainObject(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === null || prototype === Object.prototype;
}

function parseArgs(argv: readonly string[]): { command: Command; options: Options } {
  const command = `${argv[0] ?? ""} ${argv[1] ?? ""}` as Command;
  if (!Object.hasOwn(COMMANDS, command)) throw new CliInputError("Unsupported command");
  const allowed: readonly string[] = COMMANDS[command];
  const options: Record<string, string> = Object.create(null) as Record<string, string>;
  for (let i = 2; i < argv.length; i += 2) {
    const flag = argv[i];
    const value = argv[i + 1];
    if (!flag?.startsWith("--") || !value || value.startsWith("--") || !allowed.includes(flag.slice(2))) {
      throw new CliInputError("Unexpected option or missing value");
    }
    const key = flag.slice(2);
    if (Object.hasOwn(options, key)) throw new CliInputError("Duplicate option");
    options[key] = value;
  }
  const required = command === "verify dataset" ? ["bundle", "sources", "source-root", "intent", "policy"] :
    command === "verify execution" ? ["evidence", "intent", "policy"] :
    command === "verify ingest" ? ["bundle", "material", "intent", "policy"] :
    command === "verify standards" ? ["evidence", "intent", "policy"] :
      command === "report validate" ? ["report"] : ["report", "policy"];
  if (required.some((key) => !Object.hasOwn(options, key))) throw new CliInputError("Missing required option");
  return { command, options };
}

function option(options: Options, name: string): string {
  const selected = options[name];
  if (!selected) throw new CliInputError("Missing required option");
  return selected;
}

/** Only bounded, regular local files may supply JSON metadata. */
async function readJson(path: string): Promise<unknown> {
  const filename = resolve(path);
  const stat = await lstat(filename);
  if (!stat.isFile() || stat.size > MAX_JSON_BYTES) throw new CliInputError("Invalid JSON input file");
  const handle = await open(filename, constants.O_RDONLY | (process.platform === "win32" ? 0 : constants.O_NOFOLLOW));
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.size > MAX_JSON_BYTES) throw new CliInputError("Invalid JSON input file");
    const bytes = await handle.readFile();
    if (bytes.byteLength > MAX_JSON_BYTES) throw new CliInputError("JSON input exceeds size limit");
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
  } finally {
    await handle.close();
  }
}

function checkIntent(value: unknown, kind: "dataset" | "execution" | "ingest"): VerificationIntent {
  if (!plainObject(value) || !plainObject(value.subject) || value.subject.kind !== kind ||
      typeof value.subject.id !== "string" || !Array.isArray(value.expected)) {
    throw new CliInputError("Invalid independent verification intent");
  }
  return value as unknown as VerificationIntent;
}

function checkPolicy(value: unknown): VerificationPolicyV1 {
  if (!plainObject(value) || !plainObject(value.subject) || !Array.isArray(value.required_checks)) {
    throw new CliInputError("Invalid independent verification policy");
  }
  return value as unknown as VerificationPolicyV1;
}

function sameSubject(intent: VerificationIntent, policy: VerificationPolicyV1): void {
  if (policy.subject.kind !== intent.subject.kind || policy.subject.id !== intent.subject.id ||
      policy.subject.hedera_network !== intent.subject.hedera_network) {
    throw new CliInputError("Independent intent does not match policy subject");
  }
}

/** No source path can escape the explicit root or traverse a symbolic link. */
async function sourceFile(root: string, relativePath: string): Promise<string> {
  const name = sourceV1Path(relativePath, 1024);
  const filename = join(root, ...name.split("/"));
  const pathRelative = relative(root, filename);
  if (isAbsolute(pathRelative) || pathRelative === ".." || pathRelative.startsWith(`..${sep}`)) {
    throw new CliInputError("Source escapes specified root");
  }
  let part = root;
  const segments = name.split("/");
  for (const [index, segment] of segments.entries()) {
    part = join(part, segment);
    const stat = await lstat(part);
    if (stat.isSymbolicLink() || (index < segments.length - 1 ? !stat.isDirectory() : !stat.isFile())) {
      throw new CliInputError("Source must be a regular file under the specified root");
    }
  }
  const actual = await realpath(filename);
  const inside = relative(root, actual);
  if (isAbsolute(inside) || inside === ".." || inside.startsWith(`..${sep}`)) {
    throw new CliInputError("Source escapes specified root");
  }
  return filename;
}

async function* sourceStream(root: string, relativePath: string, budget: { remaining: number }): AsyncGenerator<Uint8Array> {
  const filename = await sourceFile(root, relativePath);
  const handle = await open(filename, constants.O_RDONLY | (process.platform === "win32" ? 0 : constants.O_NOFOLLOW));
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > MAX_SOURCE_BYTES) throw new CliInputError("Source file exceeds limit");
    for await (const chunk of handle.createReadStream({ autoClose: false })) {
      if (chunk.byteLength > budget.remaining) throw new RangeError("Total source bytes exceed limit");
      budget.remaining -= chunk.byteLength;
      yield chunk;
    }
  } finally {
    await handle.close();
  }
}

/** Shared bounded local file loader for Dataset and Ingest source material. */
async function sourcePaths(sourceRoot: string, paths: unknown): Promise<Array<{ path_rel: string; source: AsyncIterable<Uint8Array> }>> {
  const rootArg = resolve(sourceRoot);
  const rootStat = await lstat(rootArg);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) throw new CliInputError("Invalid source root");
  const root = await realpath(rootArg);
  if (!Array.isArray(paths) || paths.length < 1 || paths.length > MAX_FILES) {
    throw new CliInputError("Source paths must be a nonempty bounded array");
  }
  const files: Array<{ path_rel: string; source: AsyncIterable<Uint8Array> }> = [];
  const unique = new Set<string>();
  const budget = { remaining: MAX_SOURCE_BYTES };
  let total = 0;
  for (const candidate of paths) {
    const path_rel = sourceV1Path(candidate, 1024);
    const identity = process.platform === "win32" ? path_rel.toLowerCase() : path_rel;
    if (unique.has(identity)) throw new CliInputError("Duplicate source path");
    unique.add(identity);
    const filename = await sourceFile(root, path_rel);
    const stat = await lstat(filename);
    if (stat.size > MAX_SOURCE_BYTES - total) throw new CliInputError("Total source bytes exceed limit");
    total += stat.size;
    files.push({ path_rel, source: sourceStream(root, path_rel, budget) });
  }
  return files;
}

async function datasetSources(options: Options): Promise<Array<{ path_rel: string; source: AsyncIterable<Uint8Array> }>> {
  const manifest = await readJson(option(options, "sources"));
  if (!plainObject(manifest) || Object.keys(manifest).length !== 1 || !Array.isArray(manifest.paths)) {
    throw new CliInputError("Sources manifest must contain a bounded paths array");
  }
  return sourcePaths(option(options, "source-root"), manifest.paths);
}

/** The CLI descriptor contains local paths, never source bytes, user URLs, or trusted commitments. */
async function ingestMaterial(options: Options): Promise<IngestV1SourceMaterial> {
  const descriptor = await readJson(option(options, "material"));
  if (!plainObject(descriptor)) throw new CliInputError("Invalid Ingest material descriptor");
  const exact = (keys: readonly string[]): void => {
    if (Object.keys(descriptor).some((key) => !keys.includes(key))) {
      throw new CliInputError("Unknown Ingest material field");
    }
  };
  if (descriptor.kind === "json") {
    exact(["kind", "value"]);
    if (!Object.hasOwn(descriptor, "value") || options["source-root"]) {
      throw new CliInputError("Inline JSON material requires a value and no source root");
    }
    return { kind: "json", value: descriptor.value };
  }
  if (descriptor.kind === "text") {
    exact(["kind", "text", "media_type"]);
    if (typeof descriptor.text !== "string" || options["source-root"] ||
        (descriptor.media_type !== undefined && descriptor.media_type !== null &&
        (typeof descriptor.media_type !== "string" || !descriptor.media_type.trim() ||
          descriptor.media_type.length > 256 || descriptor.media_type.trim() !== descriptor.media_type))) {
      throw new CliInputError("Invalid inline text material");
    }
    return { kind: "text", text: descriptor.text,
      ...(descriptor.media_type === undefined || descriptor.media_type === null ? {} : { media_type: descriptor.media_type }) };
  }
  if (descriptor.kind === "file") {
    exact(["kind", "path_rel"]);
    const path_rel = sourceV1Path(descriptor.path_rel, 1024);
    if (path_rel.includes("/")) throw new CliInputError("Single-file Ingest requires a basename");
    const files = await sourcePaths(option(options, "source-root"), [path_rel]);
    return { kind: "file", file: files[0]! };
  }
  if (descriptor.kind === "file_set") {
    exact(["kind", "paths"]);
    return { kind: "file_set", files: await sourcePaths(option(options, "source-root"), descriptor.paths) };
  }
  throw new CliInputError("Unsupported Ingest material kind");
}

/** Public Core anchor identity is separate from the independently selected Ingest source key. */
function ingestAnchor(options: Options, mode: "offline" | "public"): string | null {
  const id = options["anchor-request-id"];
  if (mode === "offline") {
    if (id !== undefined) throw new CliInputError("Offline Ingest cannot select a public anchor");
    return null;
  }
  if (!id || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)) {
    throw new CliInputError("Public Ingest requires an independently selected Core anchor request UUID");
  }
  return id.toLowerCase();
}

/** Resolver endpoints are operator-controlled arguments, never fields from evidence.
 * The resolvers independently enforce URL, transport and response bounds. */
function endpoint(value: string, kind: "explorer" | "mirror"): string {
  let url: URL;
  try { url = new URL(value); } catch { throw new CliInputError("Invalid resolver endpoint"); }
  const loopback = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
  const pathname = kind === "explorer" ? url.pathname.replace(/\/$/, "") : url.pathname;
  if ((url.protocol !== "https:" && !(loopback && url.protocol === "http:")) ||
      url.username || url.password || url.search || url.hash ||
      (kind === "explorer" ? pathname !== "" && pathname !== "/v1" : pathname !== "/api/v1")) {
    throw new CliInputError("Resolver endpoint requires HTTPS and a supported API root (HTTP loopback permitted)");
  }
  return value;
}

/** Offline is the default. A public run requires explicit operator-selected
 * endpoints and a network-scoped relying-party policy, never producer metadata. */
function verificationMode(options: Options, intent: VerificationIntent, policy: VerificationPolicyV1,
  reportKinds: Readonly<{ offline: "verification" | "execution"; public: "public_triangulation" | "execution_triangulation" }>):
  Readonly<{ mode: "offline" }> | Readonly<{ mode: "public"; config: PublicTriangulationV1Config }> {
  const mode = options.mode ?? "offline";
  if (mode !== "offline" && mode !== "public") throw new CliInputError("Unsupported verification mode");
  if (mode === "offline") {
    if (options["explorer-url"] || options["mirror-url"] || policy.report_kind !== reportKinds.offline) {
      throw new CliInputError("Offline verification does not accept public resolver options or policies");
    }
    return { mode };
  }
  const network = intent.subject.hedera_network;
  if (policy.report_kind !== reportKinds.public || (network !== "mainnet" && network !== "testnet") ||
      !options["explorer-url"]) {
    throw new CliInputError("Public verification requires explicit network, public policy and Explorer origin");
  }
  const explorer: PublicTriangulationV1Config["explorer"] = {
    base_url: endpoint(options["explorer-url"], "explorer"),
  };
  const config: PublicTriangulationV1Config = options["mirror-url"] ? {
    explorer, mirror: { base_urls: { [network]: endpoint(options["mirror-url"], "mirror") } },
  } : { explorer };
  return { mode, config };
}

function statusCode(decision: "allow" | "deny" | "review" | "valid" | "invalid"): number {
  return decision === "allow" || decision === "valid" ? 0 : decision === "review" ? 2 : 1;
}

/** Persist a complete standalone report with exclusive creation, not a CLI envelope.
 * Linking a fully flushed sibling file avoids partial or overwritten reports. */
async function saveReport(path: string, report: PortableVerificationReportV1): Promise<void> {
  if (validatePortableVerificationReportV1(report).status !== "valid") {
    throw new Error("Verifier produced an invalid portable report");
  }
  const serialized = `${JSON.stringify(report)}\n`;
  if (Buffer.byteLength(serialized, "utf8") > MAX_JSON_BYTES) {
    throw new Error("Verifier report exceeds output size limit");
  }
  const destination = resolve(path);
  const staging = join(dirname(destination), `.va-verifier-${randomUUID()}.tmp`);
  let created = false;
  try {
    const handle = await open(staging, "wx", 0o600);
    created = true;
    try {
      await handle.writeFile(serialized, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
    try {
      // link() rejects an existing destination, including an existing symlink.
      // Staging in the same directory guarantees a complete final file on success.
      await link(staging, destination);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") {
        throw new CliInputError("Report output already exists");
      }
      throw error;
    }
  } finally {
    if (created) await unlink(staging).catch(() => undefined);
  }
}

/** CLI adapter only. Never accepts a caller flag claiming a report was SDK-verified. */
export async function runVerifierCliV1(argv: readonly string[], emit: Emitter): Promise<number> {
  if (argv.length === 1 &&
      (argv[0] === "--help" || argv[0] === "-h" || argv[0] === "help")) {
    emit(CLI_HELP);
    return 0;
  }
  try {
    const { command, options } = parseArgs(argv);
    let result: unknown;
    let code: number;
    if (command === "report validate") {
      result = validatePortableVerificationReportV1(await readJson(option(options, "report")));
      code = statusCode(result && typeof result === "object" && "status" in result && result.status === "valid" ? "valid" : "invalid");
    } else if (command === "policy assess") {
      const policy = checkPolicy(await readJson(option(options, "policy")));
      const decision = assessPortableVerificationPolicyV1(await readJson(option(options, "report")), policy);
      result = decision;
      code = statusCode(decision.decision);
    } else if (command === "verify standards") {
      const intent = checkIntent(await readJson(option(options, "intent")), "execution");
      const policy = checkPolicy(await readJson(option(options, "policy")));
      sameSubject(intent, policy);
      const network = intent.subject.hedera_network;
      const scope = policy.execution_scope;
      if ((network !== "testnet" && network !== "mainnet") ||
          policy.report_kind !== "independent_standards" ||
          scope?.profile !== "sage-standards-v1" || scope.expected_program !== "sage" ||
          (scope.requested_result_id !== null && typeof scope.requested_result_id !== "string")) {
        throw new CliInputError("Independent SAGE standards require a network-scoped standards policy and exact SAGE execution scope");
      }
      // Only configured Mirror REST observations are used. HCS-1 decoding is
      // handled by the bounded native Zstd adapter in the existing SDK kernel.
      const config: Parameters<typeof verifyExecutionStandardsWithPolicyV1>[0] = options["mirror-url"] ? {
        base_urls: { [network]: endpoint(options["mirror-url"], "mirror") },
      } : {};
      const input: ExecutionV1Input = {
        intent, evidence: await readJson(option(options, "evidence")),
        profile: "sage-standards-v1", expected_program: "sage",
        ...(scope.requested_result_id === null ? {} : { result_id: scope.requested_result_id }),
        ...(options["verification-material"] ? {
          verification_material: await readJson(options["verification-material"]) as Exclude<ExecutionV1Input["verification_material"], undefined>,
        } : {}),
      };
      const workflow = await verifyExecutionStandardsWithPolicyV1(config, input, {}, policy);
      result = workflow;
      code = statusCode(workflow.policy.decision);
    } else if (command === "verify execution") {
      const intent = checkIntent(await readJson(option(options, "intent")), "execution");
      const policy = checkPolicy(await readJson(option(options, "policy")));
      sameSubject(intent, policy);
      if (!policy.execution_scope) throw new CliInputError("Execution policy scope required");
      const selected = verificationMode(options, intent, policy,
        { offline: "execution", public: "execution_triangulation" });
      const scope = policy.execution_scope;
      const input: ExecutionV1Input = {
        intent, evidence: await readJson(option(options, "evidence")), profile: scope.profile,
        ...(scope.expected_program === null ? {} : { expected_program: scope.expected_program }),
        ...(scope.requested_result_id === null ? {} : { result_id: scope.requested_result_id }),
        ...(options["verification-material"] ? { verification_material: await readJson(options["verification-material"]) as Exclude<ExecutionV1Input["verification_material"], undefined> } : {}),
      };
      const workflow = selected.mode === "public"
        ? await triangulateExecutionWithPolicyV1(selected.config, input, policy)
        : verifyExecutionWithPolicyV1(input, policy);
      result = workflow;
      code = statusCode(workflow.policy.decision);
    } else if (command === "verify ingest") {
      const intent = checkIntent(await readJson(option(options, "intent")), "ingest");
      const policy = checkPolicy(await readJson(option(options, "policy")));
      sameSubject(intent, policy);
      const selected = verificationMode(options, intent, policy,
        { offline: "verification", public: "public_triangulation" });
      const anchor_request_id = ingestAnchor(options, selected.mode);
      const bundle = await readJson(option(options, "bundle"));
      const material = await ingestMaterial(options);
      const input = { bundle, material, intent,
        ...(options.receipt ? { receipt: await readJson(options.receipt) } : {}) };
      if (selected.mode === "public") {
        if (anchor_request_id === null) throw new CliInputError("Missing Core anchor request ID");
        const workflow = await triangulateIngestWithPolicyV1(selected.config, { ...input, anchor_request_id }, policy);
        result = workflow;
        code = statusCode(workflow.policy.decision);
      } else {
        const workflow = await verifyIngestWithPolicyV1(input, policy);
        result = workflow;
        code = statusCode(workflow.policy.decision);
      }
    } else {
      const intent = checkIntent(await readJson(option(options, "intent")), "dataset");
      const policy = checkPolicy(await readJson(option(options, "policy")));
      sameSubject(intent, policy);
      const selected = verificationMode(options, intent, policy,
        { offline: "verification", public: "public_triangulation" });
      const bundle = await readJson(option(options, "bundle"));
      const files = await datasetSources(options);
      const input = { bundle, files, intent,
        ...(options.receipt ? { receipt: await readJson(options.receipt) } : {}) };
      const workflow = selected.mode === "public"
        ? await triangulateDatasetWithPolicyV1(selected.config, input, policy)
        : await verifyDatasetWithPolicyV1(input, policy);
      result = workflow;
      code = statusCode(workflow.policy.decision);
    }
    if (options["report-out"] !== undefined) {
      // Only verification commands allow this option; imported reports never acquire authority.
      await saveReport(options["report-out"], (result as VerificationPolicyWorkflowV1).report);
    }
    emit(JSON.stringify({ schema_version: CLI_SCHEMA, command, result }));
    return code;
  } catch (error) {
    // Never echo attacker-controlled filenames, response bodies, source text or credentials.
    const badInput = error instanceof CliInputError || error instanceof TypeError || error instanceof SyntaxError || error instanceof RangeError;
    emit(JSON.stringify({ schema_version: CLI_SCHEMA, error: { code: badInput ? "CLI_INPUT_INVALID" : "CLI_OPERATION_FAILED" } }));
    return badInput ? 64 : 70;
  }
}
