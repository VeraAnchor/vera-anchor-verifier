// Exact local port of Explorer's deterministic standards resolution reference plan.
import type { PublicExecutionStandardsEvidence } from "./contractV1.js";
export type StandardsResolutionPlanTarget =
  | Readonly<{ kind: "agent"; role: "requester" | "executor" }>
  | Readonly<{ kind: "capability" }>
  | Readonly<{ kind: "schema"; index: number }>;
export type StandardsResolutionPlanItem = Readonly<{
  key: string; standard: string; reference: string; target: StandardsResolutionPlanTarget;
}>;
function text(value: unknown): string {
  return typeof value === "string" ? value.trim() : String(value ?? "").trim();
}
export function buildStandardsResolutionPlan(evidence: PublicExecutionStandardsEvidence): readonly StandardsResolutionPlanItem[] {
  const items: StandardsResolutionPlanItem[] = [
    Object.freeze({ key: "agent:requester", standard: "HCS-11/HCS-14", reference: text(evidence.agents?.requester?.hcs11?.profile_hcs1_ref), target: Object.freeze({ kind: "agent", role: "requester" as const }) }),
    Object.freeze({ key: "agent:executor", standard: "HCS-11/HCS-14", reference: text(evidence.agents?.executor?.hcs11?.profile_hcs1_ref), target: Object.freeze({ kind: "agent", role: "executor" as const }) }),
    Object.freeze({ key: "capability:hcs26", standard: "HCS-26", reference: text(evidence.capability?.manifest_hcs1_ref), target: Object.freeze({ kind: "capability" as const }) }),
  ];
  const schemas = Array.isArray(evidence.standards?.schemas) ? evidence.standards.schemas : [];
  schemas.forEach((schema, index) => {
    items.push(Object.freeze({ key: `schema:${text(schema?.role).toLowerCase()}:${Number(schema?.ordinal ?? index)}`, standard: "HCS-13", reference: text(schema?.hcs13_ref), target: Object.freeze({ kind: "schema" as const, index }) }));
  });
  return Object.freeze(items);
}
