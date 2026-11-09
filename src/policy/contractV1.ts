import type { VerificationSubject } from "../contracts/verification.js";
import type { PortableVerificationReportV1 } from "../reports/portableV1.js";

export const VERIFICATION_POLICY_SCHEMA_VERSION = "va.verification-policy.v1";

/** Assurance dimensions are independent; they are not a numeric trust score. */
export type VerificationPolicyAssuranceV1 =
  | "mirror_corroboration";

export type VerificationPolicyV1 = Readonly<{
  schema_version: typeof VERIFICATION_POLICY_SCHEMA_VERSION;
  /** Relying-party expectation, NOT copied from supplied evidence. */
  subject: VerificationSubject;
  report_kind: PortableVerificationReportV1["kind"];
  required_checks: readonly string[];
  required_assurance?: readonly VerificationPolicyAssuranceV1[];
  /** Exact caller-selected scope, required when report_kind is an execution profile. */
  execution_scope?: Readonly<{
    profile: "execution-v1" | "sage-standards-v1";
    expected_program: string | null;
    requested_result_id: string | null;
  }>;
  on_unresolved?: "review" | "deny";
}>;

export type VerificationPolicyRequirementV1 = Readonly<{
  key: string;
  outcome: "pass" | "fail" | "unresolved";
  reason_code: string | null;
}>;

export type VerificationPolicyDecisionV1 = Readonly<{
  decision: "allow" | "deny" | "review";
  report_sha3_512: string | null;
  authority: "sdk_verification" | "unauthenticated_report";
  requirements: readonly VerificationPolicyRequirementV1[];
  reason_codes: readonly string[];
}>;

export type VerificationPolicyWorkflowV1 = Readonly<{
  report: PortableVerificationReportV1;
  policy: VerificationPolicyDecisionV1;
}>;
