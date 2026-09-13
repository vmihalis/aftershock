import assert from "node:assert/strict";
import test from "node:test";
import {
  APM_PATH_ESCAPE_CAPSULE,
  SYNTHETIC_CANARY_TEXT,
  adjudicateInitialMatrix,
  asIsoTimestamp,
  capturedFile,
  digestThreatCapsule,
  failedFileCapture,
  missingFile,
  sha256Text,
  type ApplicabilityResult,
  type FileCapture,
  type HostRunStatus,
  type ObservationMatrix,
  type ObservationRole,
  type RawHostObservation,
} from "../../src/core/index.js";

const capsule = digestThreatCapsule(APM_PATH_ESCAPE_CAPSULE);
const affected: ApplicabilityResult = {
  status: "MATCHED_AFFECTED",
  packageName: "apm-cli",
  affectedRange: "<=0.8.11",
  installedVersion: "0.8.11",
  evidenceIds: ["requirements.txt:apm-cli:0.8.11"],
  explanation: "direct fixture match",
};

function observation(input: Readonly<{
  id: string;
  role: ObservationRole;
  before?: FileCapture;
  after?: FileCapture;
  runStatus?: HostRunStatus;
  evidenceComplete?: boolean;
  claimedResult?: string;
  effectPath?: string;
}>): RawHostObservation {
  return {
    id: input.id,
    role: input.role,
    inputLabel: input.id,
    inputDigest: sha256Text(input.id),
    capsuleDigest: capsule.digest,
    effectPath: input.effectPath ?? APM_PATH_ESCAPE_CAPSULE.effect.path,
    runStatus: input.runStatus ?? "COMPLETED",
    evidenceComplete: input.evidenceComplete ?? true,
    before: input.before ?? missingFile(),
    after: input.after ?? missingFile(),
    startedAt: asIsoTimestamp("2026-09-13T18:00:00.000Z"),
    finishedAt: asIsoTimestamp("2026-09-13T18:00:00.100Z"),
    durationMs: 100,
    guest: {
      exitCode: 0,
      stdoutSha256: sha256Text(input.claimedResult ?? ""),
      stderrSha256: sha256Text(""),
      ...(input.claimedResult ? { claimedResult: input.claimedResult } : {}),
    },
  };
}

function validMatrix(target: RawHostObservation): ObservationMatrix {
  return {
    target,
    fixedControl: observation({ id: "fixed", role: "FIXED_CONTROL" }),
    positiveControl: observation({
      id: "positive",
      role: "POSITIVE_CONTROL",
      after: capturedFile(Buffer.from(SYNTHETIC_CANARY_TEXT)),
    }),
  };
}

test("host bytes override a guest claim of safety", () => {
  const target = observation({
    id: "target",
    role: "TARGET",
    after: capturedFile(Buffer.from(SYNTHETIC_CANARY_TEXT)),
    claimedResult: "safe",
  });
  const result = adjudicateInitialMatrix(affected, APM_PATH_ESCAPE_CAPSULE.effect, capsule, validMatrix(target));
  assert.equal(result.state, "OBSERVED_BY_CHECK");
  assert.equal(result.effects.target.status, "OBSERVED");
});

test("failed positive control, contaminated fixed control, and incomplete capture cannot pass", () => {
  const target = observation({
    id: "target",
    role: "TARGET",
    after: capturedFile(Buffer.from(SYNTHETIC_CANARY_TEXT)),
  });
  const badPositive: ObservationMatrix = {
    ...validMatrix(target),
    positiveControl: observation({
      id: "positive-timeout",
      role: "POSITIVE_CONTROL",
      runStatus: "TIMED_OUT",
    }),
  };
  assert.equal(
    adjudicateInitialMatrix(affected, APM_PATH_ESCAPE_CAPSULE.effect, capsule, badPositive).state,
    "UNKNOWN",
  );

  const badFixed: ObservationMatrix = {
    ...validMatrix(target),
    fixedControl: observation({
      id: "fixed-observed",
      role: "FIXED_CONTROL",
      after: capturedFile(Buffer.from(SYNTHETIC_CANARY_TEXT)),
    }),
  };
  assert.equal(adjudicateInitialMatrix(affected, APM_PATH_ESCAPE_CAPSULE.effect, capsule, badFixed).state, "UNKNOWN");

  const failedCapture: ObservationMatrix = {
    ...validMatrix(target),
    fixedControl: observation({
      id: "fixed-capture",
      role: "FIXED_CONTROL",
      after: failedFileCapture("read failed"),
    }),
  };
  assert.equal(
    adjudicateInitialMatrix(affected, APM_PATH_ESCAPE_CAPSULE.effect, capsule, failedCapture).state,
    "UNKNOWN",
  );
});

test("preexisting expected bytes and unexpected mutations remain unknown", () => {
  const canary = capturedFile(Buffer.from(SYNTHETIC_CANARY_TEXT));
  const preexisting = observation({ id: "preexisting", role: "TARGET", before: canary, after: canary });
  const first = adjudicateInitialMatrix(affected, APM_PATH_ESCAPE_CAPSULE.effect, capsule, validMatrix(preexisting));
  assert.equal(first.effects.target.status, "UNKNOWN");
  assert.match(first.effects.target.explanation, /before execution/u);

  const unexpected = observation({ id: "unexpected", role: "TARGET", after: capturedFile(Buffer.from("different")) });
  const second = adjudicateInitialMatrix(affected, APM_PATH_ESCAPE_CAPSULE.effect, capsule, validMatrix(unexpected));
  assert.equal(second.effects.target.status, "UNKNOWN");
  assert.match(second.effects.target.explanation, /not to the exact/u);
});

test("capturing the wrong effect path cannot satisfy the capsule", () => {
  const target = observation({
    id: "wrong-path",
    role: "TARGET",
    after: capturedFile(Buffer.from(SYNTHETIC_CANARY_TEXT)),
    effectPath: ".github/prompts/other.prompt.md",
  });
  const result = adjudicateInitialMatrix(affected, APM_PATH_ESCAPE_CAPSULE.effect, capsule, validMatrix(target));
  assert.equal(result.state, "UNKNOWN");
  assert.match(result.effects.target.explanation, /different path/u);
});
