import { EventEmitter } from "node:events";
import { randomUUID } from "node:crypto";
import type { AftershockView, AssessmentState, MatrixStatus } from "./view.js";
import { APM_PATH_ESCAPE_CAPSULE } from "../core/apm-capsule.js";
import { digestThreatCapsule } from "../core/capsule.js";
import { sha256Text } from "../core/hash.js";

const CAPSULE_IDENTITY = digestThreatCapsule(APM_PATH_ESCAPE_CAPSULE);
const CANARY_HASH = APM_PATH_ESCAPE_CAPSULE.effect.expectedSha256;
const EMPTY_HASH = sha256Text("");
const LIFECYCLE_ISSUE_URL = "https://github.com/vmihalis/aftershock-apm-fixture/issues/1";

const checkArtifactByFrame: Partial<Record<number, { label: string; url: string }>> = {
  3: {
    label: "Historical failing Check · fixture effect",
    url: "https://github.com/vmihalis/aftershock-apm-fixture/runs/103819046282",
  },
  4: {
    label: "Historical failing Check · fixture effect",
    url: "https://github.com/vmihalis/aftershock-apm-fixture/runs/103819046282",
  },
  5: {
    label: "Historical passing Check · fixture remediation",
    url: "https://github.com/vmihalis/aftershock-apm-fixture/runs/103819189475",
  },
  6: {
    label: "Historical neutral Check · evidence stale",
    url: "https://github.com/vmihalis/aftershock-apm-fixture/runs/103819288142",
  },
};

type MatrixItem = {
  status: MatrixStatus;
  effect: string;
  before: string;
  after: string;
  durationMs: number | null;
};

type Frame = {
  state: AssessmentState;
  summary: string;
  headSha: string;
  eventTitle: string;
  eventDetail: string;
  eventType: string;
  matrix: Record<string, MatrixItem>;
};

const pending: MatrixItem = {
  status: "pending",
  effect: "Not executed in this deterministic replay",
  before: EMPTY_HASH,
  after: EMPTY_HASH,
  durationMs: null,
};
const observed = {
  status: "effect_observed" as const,
  effect: "Canonical synthetic canary copied in the deterministic fixture",
  before: EMPTY_HASH,
  after: CANARY_HASH,
  durationMs: null,
};
const absent = {
  status: "effect_absent" as const,
  effect: "Fixture records the escaping source rejected and effect path absent",
  before: EMPTY_HASH,
  after: EMPTY_HASH,
  durationMs: null,
};

const frames: Frame[] = [
  {
    state: "POTENTIALLY_AFFECTED",
    summary: "The deterministic fixture records apm-cli 0.8.11 in the affected range; no fresh runtime effect is claimed.",
    headSha: "805de8f439f2e01c0f6c52d744a8fc3af640a931",
    eventTitle: "Project matched",
    eventDetail: "Fixture snapshot references requirements.txt with apm-cli==0.8.11.",
    eventType: "project.matched",
    matrix: { before: pending, fixed: pending, positive: pending, after: pending },
  },
  {
    state: "POTENTIALLY_AFFECTED",
    summary: "The replay enters the restricted-verification step; no fresh job runs and the state remains a version match.",
    headSha: "805de8f439f2e01c0f6c52d744a8fc3af640a931",
    eventTitle: "Verification step replayed",
    eventDetail: "Fixture capability contract declares no network, credentials, or live host mount.",
    eventType: "verification.started",
    matrix: { before: pending, fixed: pending, positive: pending, after: pending },
  },
  {
    state: "OBSERVED_BY_CHECK",
    summary: "The deterministic fixture records the canonical canary effect with fixed and positive controls behaving as required.",
    headSha: "805de8f439f2e01c0f6c52d744a8fc3af640a931",
    eventTitle: "Fixture effect replayed",
    eventDetail: "The replay exposes canonical fixture hashes; it is not a fresh host observation.",
    eventType: "verification.observed",
    matrix: { before: observed, fixed: absent, positive: observed, after: pending },
  },
  {
    state: "OBSERVED_BY_CHECK",
    summary: "Historical GitHub artifacts show how the deterministic fixture was delivered to a coding agent.",
    headSha: "805de8f439f2e01c0f6c52d744a8fc3af640a931",
    eventTitle: "Historical Check and Issue linked",
    eventDetail: "These public artifacts were published from the deterministic replay, not a fresh execution.",
    eventType: "github.task_created",
    matrix: { before: observed, fixed: absent, positive: observed, after: pending },
  },
  {
    state: "REMEDIATION_RETESTED",
    summary: "The fixture records 0.8.12 stopping the canonical effect while its vulnerable positive control remains sensitive.",
    headSha: "e4d7a28fa5dc5cf027fe421576f3ddb5c0dad46c",
    eventTitle: "Fixture remediation replayed",
    eventDetail: "The fixture references the remediated SHA; this replay does not freshly test that repository revision.",
    eventType: "verification.remediated",
    matrix: { before: observed, fixed: absent, positive: observed, after: absent },
  },
  {
    state: "EVIDENCE_STALE_FOR_CURRENT_HEAD",
    summary: "The current fixture SHA differs from the replayed remediation reference; no prior result is current-head evidence.",
    headSha: "5c29dc5fca31d077d6f23d73e648f3bc8a61924a",
    eventTitle: "Evidence invalidated for current head",
    eventDetail: "The current-head matrix is cleared and reassessment is required.",
    eventType: "assessment.superseded",
    matrix: { before: pending, fixed: pending, positive: pending, after: pending },
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
    const frameNumber = this.#index + 1;
    const knownHistoricalFrame = this.#headOverride === null;
    const artifacts: AftershockView["artifacts"] = [
      { kind: "source", label: "Official Microsoft advisory", url: "https://github.com/microsoft/apm/security/advisories/GHSA-xhrw-5qxx-jpwr" },
      { kind: "fixture", label: "Authorized public fixture · replay reference", url: "https://github.com/vmihalis/aftershock-apm-fixture" },
      { kind: "receipt", label: "Separate experimental receipt · not bound to replay", url: "/api/feasibility/receipt" },
    ];
    const checkArtifact = checkArtifactByFrame[frameNumber];
    if (knownHistoricalFrame && checkArtifact) artifacts.push({ kind: "github_check", ...checkArtifact });
    if (knownHistoricalFrame && frameNumber >= 4) {
      artifacts.push({ kind: "github_issue", label: "Historical replay Issue · full state history", url: LIFECYCLE_ISSUE_URL });
    }
    return {
      meta: { mode: "demo-fixture", syntheticCanary: true, frame: frameNumber, frameCount: frames.length },
      provenance: {
        kind: "deterministic_fixture_replay",
        observationSource: "deterministic_presentation_fixture",
        freshExecution: false,
        repositoryShaFreshlyTested: false,
        savedExperimentalReceiptBound: false,
      },
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
      capsule: CAPSULE_IDENTITY,
      assessment: {
        id: `${this.#runId}:${this.#index}`,
        state: current.state,
        summary: current.summary,
        ...(this.#index === frames.length - 1 ? { supersedes: `${this.#runId}:${this.#index - 1}` } : {}),
      },
      capabilities: {
        executor: "deterministic fixture replay",
        runtime: "fixture contract · @wasmer/sdk 0.13.0 · python/python@=3.13.18",
        network: "fixture contract · disabled",
        credentials: "fixture contract · none",
        filesystem: "fixture contract · fresh guest · synthetic files · no host mounts",
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
