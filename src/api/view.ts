import { createHash } from "node:crypto";

export const assessmentStates = [
  "POTENTIALLY_AFFECTED",
  "OBSERVED_BY_CHECK",
  "REMEDIATION_RETESTED",
  "UNKNOWN",
  "EVIDENCE_STALE_FOR_CURRENT_HEAD",
] as const;

export type AssessmentState = (typeof assessmentStates)[number];

export type MatrixStatus = "pending" | "effect_observed" | "effect_absent" | "inconclusive";

export type AftershockView = {
  meta: {
    mode: "demo-fixture" | "live";
    syntheticCanary: true;
    frame: number;
    frameCount: number;
  };
  incident: {
    id: string;
    title: string;
    severity: string;
    sourceUrl: string;
    revision: string;
  };
  repository: { fullName: string; branch: string; headSha: string };
  capsule: { id: string; revision: string; digest: string };
  assessment: {
    id: string;
    state: AssessmentState;
    summary: string;
    supersedes?: string;
  };
  capabilities: {
    executor: string;
    runtime: string;
    network: string;
    credentials: string;
    filesystem: string;
    timeoutMs: number;
  };
  matrix: Array<{
    id: string;
    label: string;
    status: MatrixStatus;
    effect: string;
    beforeHash: string;
    afterHash: string;
    durationMs: number;
  }>;
  events: Array<{
    id: string;
    at: string;
    type: string;
    title: string;
    detail: string;
  }>;
  artifacts: Array<{ kind: string; label: string; url: string }>;
};

export function shortHash(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 12);
}
