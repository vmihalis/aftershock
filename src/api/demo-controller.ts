import { EventEmitter } from "node:events";
import { randomUUID } from "node:crypto";
import type { AftershockView, AssessmentState, MatrixStatus } from "./view.js";
import { shortHash } from "./view.js";

const SYNTHETIC_CANARY = "AFTERSHOCK_SYNTHETIC_CANARY_V1\n";
const CANARY_HASH = shortHash(SYNTHETIC_CANARY);
const EMPTY_HASH = shortHash("");
const LIFECYCLE_ISSUE_URL = "https://github.com/vmihalis/aftershock-apm-fixture/issues/1";

const checkArtifactByFrame: Partial<Record<number, { label: string; url: string }>> = {
  3: {
    label: "Live failing Check · observed effect",
    url: "https://github.com/vmihalis/aftershock-apm-fixture/runs/103819046282",
  },
  4: {
    label: "Live failing Check · observed effect",
    url: "https://github.com/vmihalis/aftershock-apm-fixture/runs/103819046282",
  },
  5: {
    label: "Live passing Check · remediation retested",
    url: "https://github.com/vmihalis/aftershock-apm-fixture/runs/103819189475",
  },
  6: {
    label: "Live neutral Check · evidence stale",
    url: "https://github.com/vmihalis/aftershock-apm-fixture/runs/103819288142",
  },
};

type Frame = {
  state: AssessmentState;
  summary: string;
  headSha: string;
  eventTitle: string;
  eventDetail: string;
  eventType: string;
  matrix: Record<string, { status: MatrixStatus; effect: string; before: string; after: string; durationMs: number }>;
};

const pending = { status: "pending" as const, effect: "Not executed", before: EMPTY_HASH, after: EMPTY_HASH, durationMs: 0 };
const observed = {
  status: "effect_observed" as const,
  effect: "Exact 31-byte synthetic canary copied across the plugin boundary",
  before: EMPTY_HASH,
  after: CANARY_HASH,
  durationMs: 428,
};
const absent = {
  status: "effect_absent" as const,
  effect: "Escaping source rejected; effect path remained absent",
  before: EMPTY_HASH,
  after: EMPTY_HASH,
  durationMs: 391,
};

const frames: Frame[] = [
  {
    state: "POTENTIALLY_AFFECTED",
    summary: "apm-cli 0.8.11 matches the affected range; no runtime effect has been claimed.",
    headSha: "805de8f439f2e01c0f6c52d744a8fc3af640a931",
    eventTitle: "Project matched",
    eventDetail: "requirements.txt pins apm-cli==0.8.11.",
    eventType: "project.matched",
    matrix: { before: pending, fixed: pending, positive: pending, after: pending },
  },
  {
    state: "POTENTIALLY_AFFECTED",
    summary: "A restricted verification job started; the assessment remains a version match until controls finish.",
    headSha: "805de8f439f2e01c0f6c52d744a8fc3af640a931",
    eventTitle: "Wasmer job started",
    eventDetail: "Network disabled; no credentials or live host mount granted.",
    eventType: "verification.started",
    matrix: { before: pending, fixed: pending, positive: pending, after: pending },
  },
  {
    state: "OBSERVED_BY_CHECK",
    summary: "The target copied exact synthetic canary bytes across the plugin boundary; fixed and positive controls behaved as required.",
    headSha: "805de8f439f2e01c0f6c52d744a8fc3af640a931",
    eventTitle: "Effect observed",
    eventDetail: "Trusted host observation changed from the safe canary hash to the copied canary hash.",
    eventType: "verification.observed",
    matrix: { before: observed, fixed: absent, positive: observed, after: pending },
  },
  {
    state: "OBSERVED_BY_CHECK",
    summary: "An evidence-backed GitHub task is ready for the connected coding agent.",
    headSha: "805de8f439f2e01c0f6c52d744a8fc3af640a931",
    eventTitle: "Check and Issue created",
    eventDetail: "The issue is deduplicated by repository, commit and capsule revision.",
    eventType: "github.task_created",
    matrix: { before: observed, fixed: absent, positive: observed, after: pending },
  },
  {
    state: "REMEDIATION_RETESTED",
    summary: "The 0.8.12 remediation stopped the exact effect while the vulnerable positive control remained live.",
    headSha: "e4d7a28fa5dc5cf027fe421576f3ddb5c0dad46c",
    eventTitle: "Remediation retested",
    eventDetail: "Project head passed the scoped check; the prior vulnerable receipt remains attached to its original SHA.",
    eventType: "verification.remediated",
    matrix: { before: observed, fixed: absent, positive: observed, after: absent },
  },
  {
    state: "EVIDENCE_STALE_FOR_CURRENT_HEAD",
    summary: "The current head differs from the retested commit; the older green receipt is not evidence for this revision.",
    headSha: "5c29dc5fca31d077d6f23d73e648f3bc8a61924a",
    eventTitle: "Evidence invalidated for current head",
    eventDetail: "Automatic reassessment queued for the new repository SHA.",
    eventType: "assessment.superseded",
    matrix: { before: observed, fixed: absent, positive: observed, after: pending },
  },
];

export class DemoController extends EventEmitter {
  #index = 0;
  #runId = randomUUID();
  #startedAt = new Date("2026-09-13T18:00:00.000Z");
  #headOverride: string | null = null;

  reset(): AftershockView {
    this.#index = 0;
    this.#runId = randomUUID();
    this.#startedAt = new Date();
    this.#headOverride = null;
    const view = this.view();
    this.emit("view", view);
    return view;
  }

  advance(): AftershockView {
    this.#index = Math.min(this.#index + 1, frames.length - 1);
    const view = this.view();
    this.emit("view", view);
    return view;
  }

  invalidateForHead(headSha: string): AftershockView {
    if (!/^[0-9a-f]{40}$/i.test(headSha)) {
      throw new TypeError("headSha must be a full 40-character Git SHA");
    }
    this.#index = frames.length - 1;
    this.#headOverride = headSha.toLowerCase();
    const view = this.view();
    this.emit("view", view);
    return view;
  }

  view(): AftershockView {
    const current = frames[this.#index];
    const events = frames.slice(0, this.#index + 1).map((frame, index) => ({
      id: `${this.#runId}:${index}`,
      at: new Date(this.#startedAt.getTime() + index * 15_000).toISOString(),
      type: frame.eventType,
      title: frame.eventTitle,
      detail: frame.eventDetail,
    }));
    const row = (id: string, label: string) => {
      const item = current.matrix[id];
      return {
        id,
        label,
        status: item.status,
        effect: item.effect,
        beforeHash: item.before,
        afterHash: item.after,
        durationMs: item.durationMs,
      };
    };
    const capsuleDigest = shortHash("GHSA-xhrw-5qxx-jpwr:r1:apm-path-boundary-v1");
    const frameNumber = this.#index + 1;
    const artifacts: AftershockView["artifacts"] = [
      { kind: "source", label: "Official Microsoft advisory", url: "https://github.com/microsoft/apm/security/advisories/GHSA-xhrw-5qxx-jpwr" },
      { kind: "fixture", label: "Authorized public fixture", url: "https://github.com/vmihalis/aftershock-apm-fixture" },
      { kind: "receipt", label: "Recorded Wasmer receipt", url: "/api/feasibility/receipt" },
    ];
    const checkArtifact = checkArtifactByFrame[frameNumber];
    if (checkArtifact) artifacts.push({ kind: "github_check", ...checkArtifact });
    if (frameNumber >= 4) {
      artifacts.push({ kind: "github_issue", label: "Live lifecycle Issue · full state history", url: LIFECYCLE_ISSUE_URL });
    }
    return {
      meta: { mode: "demo-fixture", syntheticCanary: true, frame: frameNumber, frameCount: frames.length },
      incident: {
        id: "GHSA-xhrw-5qxx-jpwr",
        title: "Microsoft APM plugin path escape",
        severity: "HIGH",
        sourceUrl: "https://github.com/microsoft/apm/security/advisories/GHSA-xhrw-5qxx-jpwr",
        revision: "2026-05-15",
      },
      repository: {
        fullName: "vmihalis/aftershock-apm-fixture",
        branch: "main",
        headSha: this.#index === frames.length - 1 && this.#headOverride ? this.#headOverride : current.headSha,
      },
      capsule: { id: "GHSA-xhrw-5qxx-jpwr", revision: "r1", digest: capsuleDigest },
      assessment: {
        id: `${this.#runId}:${this.#index}`,
        state: current.state,
        summary: current.summary,
        ...(this.#index === frames.length - 1 ? { supersedes: `${this.#runId}:${this.#index - 1}` } : {}),
      },
      capabilities: {
        executor: "local",
        runtime: "@wasmer/sdk 0.13.0 · python/python@=3.13.18",
        network: "disabled",
        credentials: "none",
        filesystem: "fresh guest · synthetic files · no host mounts",
        timeoutMs: 10_000,
      },
      matrix: [
        row("before", "Project before patch"),
        row("fixed", "Fixed control"),
        row("positive", "Vulnerable positive control"),
        row("after", "Project after patch"),
      ],
      events,
      artifacts,
    };
  }
}
