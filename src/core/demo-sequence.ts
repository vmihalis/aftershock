import {
  appendAssessment,
  createAdjudicatedAssessment,
  createAssessmentEvent,
  createPotentiallyAffectedAssessment,
  createStaleAssessment,
} from "./assessment.js";
import { APM_PATH_ESCAPE_CAPSULE, SYNTHETIC_CANARY_TEXT } from "./apm-capsule.js";
import { matchApmApplicability, parseProjectSnapshot } from "./applicability.js";
import { digestThreatCapsule } from "./capsule.js";
import { deepFreeze, sha256Text } from "./hash.js";
import {
  adjudicateInitialMatrix,
  adjudicateRemediationMatrix,
  capturedFile,
  missingFile,
} from "./observation.js";
import {
  asIsoTimestamp,
  type AssessmentRecord,
  type DemoSequence,
  type ObservationMatrix,
  type ObservationRole,
  type ProjectSnapshot,
  type RawHostObservation,
} from "./types.js";

const REPOSITORY = "aftershock-demo/apm-agent-fixture";
const VULNERABLE_SHA = "1d445c29136bf8008cd6df6cb0cf0133f3275d8f";
const PATCHED_SHA = "f6fc7e66afd3bf6ec6f7ee454264f4cec20e3cec";
const CURRENT_SHA = "587c569b7d313bbba9d75b31bf84a280c18262af";

function snapshot(headSha: string, version: string, observedAt: string): ProjectSnapshot {
  return parseProjectSnapshot({
    schemaVersion: 1,
    repository: { fullName: REPOSITORY, branch: "main", headSha },
    observedAt,
    inventory: {
      status: "COMPLETE",
      checkedPaths: ["requirements.txt"],
      detail: "Team-owned fixture dependency inventory.",
    },
    dependencies: [
      {
        id: `requirements.txt:apm-cli:${version}`,
        ecosystem: "PyPI",
        packageName: "apm-cli",
        version,
        manifestPath: "requirements.txt",
        observedAt,
      },
    ],
  });
}

function observation(input: Readonly<{
  id: string;
  role: ObservationRole;
  inputLabel: string;
  effectObserved: boolean;
  startedAt: string;
  durationMs: number;
  claimedResult?: string;
}>): RawHostObservation {
  const capsuleIdentity = digestThreatCapsule(APM_PATH_ESCAPE_CAPSULE);
  const startedAt = asIsoTimestamp(input.startedAt);
  const finishedAt = asIsoTimestamp(new Date(Date.parse(startedAt) + input.durationMs).toISOString());
  return deepFreeze({
    id: input.id,
    role: input.role,
    inputLabel: input.inputLabel,
    inputDigest: sha256Text(input.inputLabel),
    capsuleDigest: capsuleIdentity.digest,
    effectPath: APM_PATH_ESCAPE_CAPSULE.effect.path,
    runStatus: "COMPLETED",
    evidenceComplete: true,
    before: missingFile(),
    after: input.effectObserved ? capturedFile(Buffer.from(SYNTHETIC_CANARY_TEXT, "utf8")) : missingFile(),
    startedAt,
    finishedAt,
    durationMs: input.durationMs,
    guest: {
      exitCode: 0,
      stdoutSha256: sha256Text(input.claimedResult ?? ""),
      stderrSha256: sha256Text(""),
      ...(input.claimedResult ? { claimedResult: input.claimedResult } : {}),
    },
  }) as RawHostObservation;
}

function initialMatrix(): ObservationMatrix {
  return deepFreeze({
    target: observation({
      id: "run-vulnerable-target",
      role: "TARGET",
      inputLabel: `${REPOSITORY}@${VULNERABLE_SHA}`,
      effectObserved: true,
      startedAt: "2026-09-13T18:00:10.000Z",
      durationMs: 428,
      claimedResult: "safe",
    }),
    fixedControl: observation({
      id: "run-fixed-control",
      role: "FIXED_CONTROL",
      inputLabel: "apm-cli-0.8.12-fixed-control",
      effectObserved: false,
      startedAt: "2026-09-13T18:00:11.000Z",
      durationMs: 391,
    }),
    positiveControl: observation({
      id: "run-positive-control-initial",
      role: "POSITIVE_CONTROL",
      inputLabel: "apm-cli-0.8.11-positive-control-r1",
      effectObserved: true,
      startedAt: "2026-09-13T18:00:12.000Z",
      durationMs: 407,
    }),
  }) as ObservationMatrix;
}

function remediationMatrix(): ObservationMatrix {
  return deepFreeze({
    target: observation({
      id: "run-patched-target",
      role: "TARGET",
      inputLabel: `${REPOSITORY}@${PATCHED_SHA}`,
      effectObserved: false,
      startedAt: "2026-09-13T18:01:10.000Z",
      durationMs: 376,
    }),
    fixedControl: observation({
      id: "run-fixed-control-retest",
      role: "FIXED_CONTROL",
      inputLabel: "apm-cli-0.8.12-fixed-control",
      effectObserved: false,
      startedAt: "2026-09-13T18:01:11.000Z",
      durationMs: 384,
    }),
    positiveControl: observation({
      id: "run-positive-control-retest",
      role: "POSITIVE_CONTROL",
      inputLabel: "apm-cli-0.8.11-positive-control-r1",
      effectObserved: true,
      startedAt: "2026-09-13T18:01:12.000Z",
      durationMs: 401,
    }),
  }) as ObservationMatrix;
}

export function buildDeterministicDemoSequence(): DemoSequence {
  const capsule = APM_PATH_ESCAPE_CAPSULE;
  const capsuleIdentity = digestThreatCapsule(capsule);
  const vulnerable = snapshot(VULNERABLE_SHA, "0.8.11", "2026-09-13T18:00:00.000Z");
  const patched = snapshot(PATCHED_SHA, "0.8.12", "2026-09-13T18:01:00.000Z");
  const current = snapshot(CURRENT_SHA, "0.8.12", "2026-09-13T18:02:00.000Z");
  const vulnerableApplicability = matchApmApplicability(capsule, vulnerable);
  const patchedApplicability = matchApmApplicability(capsule, patched);

  const potential = createPotentiallyAffectedAssessment({
    repository: vulnerable.repository,
    source: capsule.source,
    capsule: capsuleIdentity,
    applicability: vulnerableApplicability,
    createdAt: asIsoTimestamp("2026-09-13T18:00:01.000Z"),
  });

  const beforeMatrix = initialMatrix();
  const observedAdjudication = adjudicateInitialMatrix(
    vulnerableApplicability,
    capsule.effect,
    capsuleIdentity,
    beforeMatrix,
  );
  const observed = createAdjudicatedAssessment({
    repository: vulnerable.repository,
    source: capsule.source,
    capsule: capsuleIdentity,
    applicability: vulnerableApplicability,
    adjudication: observedAdjudication,
    matrix: beforeMatrix,
    createdAt: asIsoTimestamp("2026-09-13T18:00:30.000Z"),
    supersedes: potential.id,
  });

  const afterMatrix = remediationMatrix();
  const remediationAdjudication = adjudicateRemediationMatrix(
    observed,
    patched.repository,
    patchedApplicability,
    capsule.effect,
    capsuleIdentity,
    afterMatrix,
  );
  const remediated = createAdjudicatedAssessment({
    repository: patched.repository,
    source: capsule.source,
    capsule: capsuleIdentity,
    applicability: patchedApplicability,
    adjudication: remediationAdjudication,
    matrix: afterMatrix,
    createdAt: asIsoTimestamp("2026-09-13T18:01:30.000Z"),
    supersedes: observed.id,
  });

  const stale = createStaleAssessment({
    previous: remediated,
    repository: current.repository,
    source: capsule.source,
    capsule: capsuleIdentity,
    applicability: matchApmApplicability(capsule, current),
    createdAt: asIsoTimestamp("2026-09-13T18:02:01.000Z"),
  });

  let assessments: readonly AssessmentRecord[] = appendAssessment([], potential);
  assessments = appendAssessment(assessments, observed);
  assessments = appendAssessment(assessments, remediated);
  assessments = appendAssessment(assessments, stale);

  const events = [
    createAssessmentEvent({
      sequence: 1,
      at: potential.createdAt,
      type: "PROJECT_MATCHED",
      assessment: potential,
      title: "Project matched",
      detail: "requirements.txt pins apm-cli==0.8.11; runtime exploitation is not yet claimed.",
    }),
    createAssessmentEvent({
      sequence: 2,
      at: observed.createdAt,
      type: "EFFECT_OBSERVED",
      assessment: observed,
      title: "Exact effect observed",
      detail: "Host-captured canary bytes appeared only on the target and frozen vulnerable positive control.",
    }),
    createAssessmentEvent({
      sequence: 3,
      at: remediated.createdAt,
      type: "REMEDIATION_RETESTED",
      assessment: remediated,
      title: "Remediation retested",
      detail: "apm-cli 0.8.12 stopped the exact effect while the positive control remained sensitive.",
    }),
    createAssessmentEvent({
      sequence: 4,
      at: stale.createdAt,
      type: "EVIDENCE_STALE",
      assessment: stale,
      title: "Evidence stale for current head",
      detail: "A later repository SHA cannot inherit the green receipt; reassessment is required.",
    }),
  ];

  return deepFreeze({ capsule, capsuleIdentity, assessments, events }) as DemoSequence;
}
