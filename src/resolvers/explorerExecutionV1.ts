import type { HederaNetwork } from "../contracts/verification.js";
import type { PublicExecutionStandardsEvidence } from "../profiles/execution/contractV1.js";
import { readExplorerPublicV1, type ExplorerPublicTransportV1 } from "./explorerTransportV1.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

type Status = "resolved" | "not_found" | "unavailable" | "invalid" | "conflict" | "verification_material_unavailable";
export type ExplorerExecutionV1Request = Readonly<{
  job_id: string;
  result_id?: string | null;
  network: HederaNetwork;
}>;
export type ExplorerExecutionV1Result = Readonly<{
  status: Status;
  reason_code: string | null;
  evidence: PublicExecutionStandardsEvidence | null;
}>;

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}
function identity(value: unknown): string | null {
  return typeof value === "string" && UUID.test(value.trim()) ? value.trim().toLowerCase() : null;
}
function result(status: Status, reason_code: string, evidence: PublicExecutionStandardsEvidence | null = null): ExplorerExecutionV1Result {
  return Object.freeze({ status, reason_code, evidence });
}

export async function resolveExplorerExecutionV1(
  config: ExplorerPublicTransportV1,
  request: ExplorerExecutionV1Request,
): Promise<ExplorerExecutionV1Result> {
  const job = identity(request.job_id);
  const selected = request.result_id == null ? null : identity(request.result_id);
  if (!job || (request.result_id != null && !selected) ||
      (request.network !== "mainnet" && request.network !== "testnet")) {
    throw new TypeError("Execution lookup requires a valid job, result and network scope");
  }
  if (selected) {
    const scoped = await readExplorerPublicV1(config, `/v1/sage/results/${selected}`, request.network);
    if (scoped.status !== "ok") return result(scoped.status, scoped.reason_code ?? "EXPLORER_RESULT_UNAVAILABLE");
    const row = record(scoped.body);
    if (!row) return result("invalid", "EXPLORER_RESULT_INVALID");
    const resultId = identity(row.result_id ?? row.id);
    const jobId = identity(row.job_id);
    if (!resultId || !jobId) return result("invalid", "EXPLORER_RESULT_SCOPE_MISSING");
    if (resultId !== selected || jobId !== job ||
        (row.hedera_network != null && row.hedera_network !== request.network)) {
      return result("conflict", "EXPLORER_RESULT_SCOPE_MISMATCH");
    }
  }
  const response = await readExplorerPublicV1(config, `/v1/sage/jobs/${job}/standards`, request.network,
    undefined, selected ? { resultId: selected } : undefined);
  if (response.status !== "ok") return result(response.status, response.reason_code ?? "EXPLORER_EXECUTION_UNAVAILABLE");
  const body = record(response.body);
  if (!body) return result("invalid", "EXPLORER_EXECUTION_INVALID");
  const execution = record(body.execution);
  if (!execution || identity(execution.job_id) !== job || execution.hedera_network !== request.network) {
    return result("conflict", "EXPLORER_EXECUTION_SCOPE_MISMATCH");
  }
  if (body.available === false) return result("verification_material_unavailable", "EXPLORER_STANDARDS_UNAVAILABLE");
  if (body.available !== true || body.contract_version !== "1.0.0") {
    return result("invalid", "EXPLORER_EXECUTION_CONTRACT_UNSUPPORTED");
  }
  if (selected) {
    const resultEvidence = record(body.result_evidence);
    const actual = identity(resultEvidence?.result_id);
    if (!resultEvidence || !actual) return result("verification_material_unavailable", "EXPLORER_RESULT_EVIDENCE_UNAVAILABLE");
    if (actual !== selected || (execution.result_id != null && identity(execution.result_id) !== selected)) {
      return result("conflict", "EXPLORER_RESULT_EVIDENCE_SCOPE_MISMATCH");
    }
  }
  return Object.freeze({ status: "resolved" as const, reason_code: null, evidence: body as PublicExecutionStandardsEvidence });
}
