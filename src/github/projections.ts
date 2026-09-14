import { createHash } from "node:crypto";
import type { AftershockView, AssessmentState } from "../api/view.js";

export type CheckConclusion = "neutral" | "failure" | "success";

export type GitHubCheckProjection = {
  name: string;
  head_sha: string;
  status: "completed";
  conclusion: CheckConclusion;
  output: { title: string; summary: string; text: string };
  external_id: string;
};

export type GitHubIssueProjection = {
  title: string;
  body: string;
  labels: string[];
  dedupeKey: string;
  shouldBeOpen: boolean;
};

function conclusionFor(state: AssessmentState): CheckConclusion {
  if (state === "OBSERVED_BY_CHECK") return "failure";
  if (state === "REMEDIATION_RETESTED") return "success";
  return "neutral";
}

function matrixMarkdown(view: AftershockView): string {
  const rows = view.matrix.map((row) =>
    `| ${row.label} | ${row.status} | ${row.effect} | \`${row.beforeHash}\` | \`${row.afterHash}\` |`,
  );
  return [
    "| Run | Status | Deterministic fixture effect | Before | After |",
    "|---|---|---|---|---|",
    ...rows,
  ].join("\n");
}

function evidenceJson(view: AftershockView): string {
  return JSON.stringify({
    assessment_id: view.assessment.id,
    state: view.assessment.state,
    repository: view.repository,
    source: { id: view.incident.id, revision: view.incident.revision, url: view.incident.sourceUrl },
    capsule: view.capsule,
    provenance: view.provenance,
    capabilities: view.capabilities,
    matrix: view.matrix,
  }, null, 2);
}

export function projectCheck(view: AftershockView): GitHubCheckProjection {
  const title = `Aftershock — ${view.assessment.state.replaceAll("_", " ")}`;
  const summary = [
    "**Provenance: deterministic fixture replay.**",
    "No fresh execution occurred, the repository SHA was not freshly tested, and the separate saved experimental receipt is not bound to this assessment.",
    "",
    view.assessment.summary,
    "",
    `Repository: \`${view.repository.fullName}@${view.repository.headSha}\``,
    `Capsule: \`${view.capsule.id}:${view.capsule.revision}\` (\`${view.capsule.digest}\`)`,
    "",
    "Synthetic canary only — no real secret accessed.",
  ].join("\n");
  const text = [
    matrixMarkdown(view),
    "",
    "<details><summary>Machine-readable evidence</summary>",
    "",
    "```json",
    evidenceJson(view),
    "```",
    "</details>",
  ].join("\n");
  return {
    name: `Aftershock / ${view.incident.id}`,
    head_sha: view.repository.headSha,
    status: "completed",
    conclusion: conclusionFor(view.assessment.state),
    output: { title, summary, text },
    external_id: view.assessment.id,
  };
}

export function projectIssue(view: AftershockView): GitHubIssueProjection {
  const dedupeKey = createHash("sha256")
    .update(`${view.repository.fullName}\0${view.incident.id}\0${view.capsule.revision}`)
    .digest("hex")
    .slice(0, 20);
  const shouldBeOpen = view.assessment.state === "OBSERVED_BY_CHECK" ||
    view.assessment.state === "POTENTIALLY_AFFECTED" ||
    view.assessment.state === "UNKNOWN" ||
    view.assessment.state === "EVIDENCE_STALE_FOR_CURRENT_HEAD";
  const body = [
    `<!-- aftershock-dedupe:${dedupeKey} -->`,
    `# ${view.incident.title}`,
    "",
    "> **Deterministic fixture replay:** no fresh execution occurred, this repository SHA was not freshly tested, and the separate saved experimental receipt is not bound to this assessment.",
    "",
    view.assessment.summary,
    "",
    `- State: **${view.assessment.state}**`,
    `- Repository revision: \`${view.repository.headSha}\``,
    `- Capsule: \`${view.capsule.id}:${view.capsule.revision}\``,
    `- Capsule digest: \`${view.capsule.digest}\``,
    `- Source: [${view.incident.id}](${view.incident.sourceUrl})`,
    "- Fixture: **synthetic canary; no real secret accessed**",
    "",
    matrixMarkdown(view),
    "",
    "## Context for the coding agent",
    "",
    "The affected-version match is not a universal safety conclusion. These are deterministic presentation-fixture observations, not fresh measurements. Run a separately admitted capsule before making a repository-specific conclusion, and never reuse evidence across another SHA or capsule revision.",
    "",
    "```json",
    evidenceJson(view),
    "```",
  ].join("\n");
  return {
    title: `[Aftershock] ${view.incident.id} — ${view.assessment.state.replaceAll("_", " ")}`,
    body,
    labels: ["aftershock", "security", view.assessment.state.toLowerCase()],
    dedupeKey,
    shouldBeOpen,
  };
}
