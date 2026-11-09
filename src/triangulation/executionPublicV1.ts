import type { ExecutionV1Input } from "../profiles/execution/verificationV1.js";
import { verifyExecutionV1WithIntent } from "../profiles/execution/verificationV1.js";
import { resolveExplorerExecutionV1, type ExplorerExecutionV1Result } from "../resolvers/explorerExecutionV1.js";
import { resolveExecutionHederaV1, type ExecutionMirrorV1Result } from "../resolvers/executionMirrorV1.js";
import type { ExplorerPublicTransportV1 } from "../resolvers/explorerTransportV1.js";
import type { HederaMirrorV1Config } from "../resolvers/hederaMirrorV1.js";
import { compareEvidenceTriangulationV1, type TriangulationV1Result } from "./compareV1.js";
import { prepareExecutionTriangulationV1, type ExecutionTriangulationPlanV1 } from "./executionPlanV1.js";

export type PublicExecutionTriangulationV1Config = Readonly<{
  explorer: ExplorerPublicTransportV1;
  mirror?: HederaMirrorV1Config;
}>;
export type PublicExecutionTriangulationV1Result = Readonly<{
  status: "resolved" | "not_found" | "unavailable" | "invalid" | "conflict" | "verification_material_unavailable";
  reason_code: string | null;
  public_record_acquisition: ExplorerExecutionV1Result["status"];
  hedera_resolution: ExecutionMirrorV1Result["status"] | "not_checked";
  plan: ExecutionTriangulationPlanV1 | null;
  mirror: ExecutionMirrorV1Result | null;
  comparison: TriangulationV1Result | null;
}>;

export async function triangulatePublicExecutionV1(
  config: PublicExecutionTriangulationV1Config,
  execution: ExecutionV1Input,
): Promise<PublicExecutionTriangulationV1Result> {
  const initial = verifyExecutionV1WithIntent(execution);
  if (initial.findings.find((item) => item.check_id === "input.bounds")?.outcome !== "pass") {
    throw new TypeError("Invalid execution verification input");
  }
  const subject = initial.intent.subject;
  if (subject.kind !== "execution" || !subject.hedera_network) throw new TypeError("Execution verification subject is required");
  const publicRecord = await resolveExplorerExecutionV1(config.explorer, {
    job_id: subject.id, network: subject.hedera_network,
    result_id: initial.verification_scope.requested_result_id,
  });
  if (publicRecord.status !== "resolved" || !publicRecord.evidence) {
    return Object.freeze({ status: publicRecord.status, reason_code: publicRecord.reason_code,
      public_record_acquisition: publicRecord.status, hedera_resolution: "not_checked" as const,
      plan: null, mirror: null, comparison: null });
  }
  const plan = prepareExecutionTriangulationV1({ execution, public_evidence: publicRecord.evidence });
  const mirror = await resolveExecutionHederaV1(config.mirror ?? {}, {
    subject: plan.source_report.intent.subject, targets: plan.hedera_targets,
  });
  const comparison = compareEvidenceTriangulationV1({
    ...plan.triangulation,
    observations: Object.freeze([...plan.triangulation.observations, mirror.observation]),
  });
  const status = mirror.status === "conflict" || comparison.consistency === "conflict"
    ? "conflict" : mirror.status;
  const reason_code = comparison.consistency === "conflict" && mirror.status !== "conflict"
    ? "EXECUTION_SOURCE_OR_COMPARISON_CONFLICT" : mirror.reason_code;
  return Object.freeze({ status, reason_code,
    public_record_acquisition: "resolved" as const, hedera_resolution: mirror.status,
    plan, mirror, comparison });
}
