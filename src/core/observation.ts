import { deepFreeze, sha256Bytes } from "./hash.js";
import type {
  ApplicabilityResult,
  AssessmentRecord,
  CapsuleIdentity,
  DerivedEffect,
  EffectContract,
  FileCapture,
  MatrixAdjudication,
  ObservationMatrix,
  RawHostObservation,
  RepositoryRevision,
} from "./types.js";

export function capturedFile(bytes: Uint8Array): FileCapture {
  return deepFreeze({
    status: "CAPTURED",
    exists: true,
    sha256: sha256Bytes(bytes),
    byteLength: bytes.byteLength,
  }) as FileCapture;
}

export function missingFile(): FileCapture {
  return deepFreeze({ status: "CAPTURED", exists: false, sha256: null, byteLength: 0 }) as FileCapture;
}

export function failedFileCapture(error: string): FileCapture {
  if (error.trim() === "") throw new TypeError("A failed capture requires an explanation");
  return deepFreeze({ status: "FAILED", exists: null, sha256: null, byteLength: null, error }) as FileCapture;
}

function fileCapturesEqual(before: FileCapture, after: FileCapture): boolean {
  if (before.status !== "CAPTURED" || after.status !== "CAPTURED") return false;
  if (before.exists !== after.exists) return false;
  if (!before.exists || !after.exists) return true;
  return before.sha256 === after.sha256 && before.byteLength === after.byteLength;
}

function unknown(observation: RawHostObservation, explanation: string): DerivedEffect {
  return deepFreeze({
    observationId: observation.id,
    role: observation.role,
    status: "UNKNOWN",
    beforeSha256: observation.before.status === "CAPTURED" ? observation.before.sha256 : null,
    afterSha256: observation.after.status === "CAPTURED" ? observation.after.sha256 : null,
    explanation,
  }) as DerivedEffect;
}

export function deriveEffectResult(
  contract: EffectContract,
  capsule: CapsuleIdentity,
  observation: RawHostObservation,
): DerivedEffect {
  if (observation.capsuleDigest !== capsule.digest) {
    return unknown(observation, "Observation capsule digest does not match the admitted capsule.");
  }
  if (observation.effectPath !== contract.path) {
    return unknown(observation, "Observation captured a different path from the admitted effect contract.");
  }
  if (observation.runStatus !== "COMPLETED") {
    return unknown(observation, `Host run ended as ${observation.runStatus.toLowerCase()}.`);
  }
  if (!observation.evidenceComplete) {
    return unknown(observation, "Host marked the run evidence incomplete.");
  }
  if (observation.before.status !== "CAPTURED" || observation.after.status !== "CAPTURED") {
    return unknown(observation, "Host could not capture both filesystem states.");
  }
  if (observation.before.exists && observation.before.sha256 === contract.expectedSha256) {
    return unknown(observation, "Expected canary bytes existed before execution, so causation cannot be established.");
  }
  if (observation.after.exists && observation.after.sha256 === contract.expectedSha256) {
    return deepFreeze({
      observationId: observation.id,
      role: observation.role,
      status: "OBSERVED",
      beforeSha256: observation.before.sha256,
      afterSha256: observation.after.sha256,
      explanation: `Trusted host capture observed the exact admitted bytes at ${contract.path}.`,
    }) as DerivedEffect;
  }
  if (fileCapturesEqual(observation.before, observation.after)) {
    return deepFreeze({
      observationId: observation.id,
      role: observation.role,
      status: "NOT_OBSERVED",
      beforeSha256: observation.before.sha256,
      afterSha256: observation.after.sha256,
      explanation: `Trusted host capture found no change to the exact admitted effect at ${contract.path}.`,
    }) as DerivedEffect;
  }
  return unknown(observation, "The filesystem changed, but not to the exact admitted canary bytes.");
}

function deriveMatrix(
  contract: EffectContract,
  capsule: CapsuleIdentity,
  matrix: ObservationMatrix,
): MatrixAdjudication["effects"] {
  if (
    matrix.target.role !== "TARGET" ||
    matrix.fixedControl.role !== "FIXED_CONTROL" ||
    matrix.positiveControl.role !== "POSITIVE_CONTROL"
  ) {
    throw new TypeError("Observation matrix roles do not match their slots");
  }
  return deepFreeze({
    target: deriveEffectResult(contract, capsule, matrix.target),
    fixedControl: deriveEffectResult(contract, capsule, matrix.fixedControl),
    positiveControl: deriveEffectResult(contract, capsule, matrix.positiveControl),
  }) as MatrixAdjudication["effects"];
}

function controlsAreValid(effects: MatrixAdjudication["effects"]): boolean {
  return effects.fixedControl.status === "NOT_OBSERVED" && effects.positiveControl.status === "OBSERVED";
}

export function adjudicateInitialMatrix(
  applicability: ApplicabilityResult,
  contract: EffectContract,
  capsule: CapsuleIdentity,
  matrix: ObservationMatrix,
): MatrixAdjudication {
  const effects = deriveMatrix(contract, capsule, matrix);
  if (applicability.status !== "MATCHED_AFFECTED") {
    return deepFreeze({
      state: "UNKNOWN",
      summary: "Runtime evidence cannot establish an affected observation without a current affected-version match.",
      effects,
    }) as MatrixAdjudication;
  }
  if (!controlsAreValid(effects)) {
    return deepFreeze({
      state: "UNKNOWN",
      summary: "The fixed differential or vulnerable positive control did not establish a valid comparison.",
      effects,
    }) as MatrixAdjudication;
  }
  if (effects.target.status === "OBSERVED") {
    return deepFreeze({
      state: "OBSERVED_BY_CHECK",
      summary: "The target produced the exact host-observed canary effect; the fixed control was clean and the vulnerable positive control fired.",
      effects,
    }) as MatrixAdjudication;
  }
  return deepFreeze({
    state: "UNKNOWN",
    summary:
      effects.target.status === "NOT_OBSERVED"
        ? "The exact effect was not observed on this affected-version snapshot; that scoped absence is not a universal safety conclusion."
        : "Target execution did not produce complete evidence for the admitted effect.",
    effects,
  }) as MatrixAdjudication;
}

export function adjudicateRemediationMatrix(
  priorObserved: AssessmentRecord,
  currentRepository: RepositoryRevision,
  applicability: ApplicabilityResult,
  contract: EffectContract,
  capsule: CapsuleIdentity,
  matrix: ObservationMatrix,
): MatrixAdjudication {
  if (priorObserved.state !== "OBSERVED_BY_CHECK") {
    throw new TypeError("Remediation retest requires a prior OBSERVED_BY_CHECK assessment");
  }
  if (priorObserved.repository.headSha === currentRepository.headSha) {
    throw new TypeError("Remediation retest must bind a new repository SHA");
  }
  if (
    priorObserved.capsule.id !== capsule.id ||
    priorObserved.capsule.revision !== capsule.revision ||
    priorObserved.capsule.digest !== capsule.digest
  ) {
    throw new TypeError("Remediation retest must use the identical admitted capsule");
  }

  const effects = deriveMatrix(contract, capsule, matrix);
  if (!controlsAreValid(effects)) {
    return deepFreeze({
      state: "UNKNOWN",
      summary: "Remediation cannot be credited because the differential or positive control was invalid.",
      effects,
    }) as MatrixAdjudication;
  }
  if (effects.target.status === "OBSERVED") {
    return deepFreeze({
      state: "OBSERVED_BY_CHECK",
      summary: "The exact effect remained observable on the proposed remediation revision.",
      effects,
    }) as MatrixAdjudication;
  }
  if (effects.target.status === "NOT_OBSERVED" && applicability.status === "MATCHED_UNAFFECTED") {
    return deepFreeze({
      state: "REMEDIATION_RETESTED",
      summary: "The fixed dependency revision stopped the exact target effect while the frozen vulnerable positive control still fired.",
      effects,
    }) as MatrixAdjudication;
  }
  return deepFreeze({
    state: "UNKNOWN",
    summary: "The remediation run lacks either complete target evidence or fixed-version applicability evidence.",
    effects,
  }) as MatrixAdjudication;
}
