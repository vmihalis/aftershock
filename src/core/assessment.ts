import { deepFreeze, sha256CanonicalJson } from "./hash.js";
import {
  asAssessmentId,
  asEventId,
  type ApplicabilityResult,
  type AssessmentEvent,
  type AssessmentEventType,
  type AssessmentId,
  type AssessmentRecord,
  type AssessmentState,
  type CapsuleIdentity,
  type IsoTimestamp,
  type MatrixAdjudication,
  type ObservationMatrix,
  type RawHostObservation,
  type RepositoryRevision,
  type SourceRevision,
} from "./types.js";

export type CreateAssessmentInput = Readonly<{
  repository: RepositoryRevision;
  source: SourceRevision;
  capsule: CapsuleIdentity;
  state: AssessmentState;
  summary: string;
  createdAt: IsoTimestamp;
  applicability: ApplicabilityResult;
  observations?: readonly RawHostObservation[];
  staleAxes?: AssessmentRecord["evidence"]["staleAxes"];
  supersedes?: AssessmentId;
}>;

function validateAssessmentInput(input: CreateAssessmentInput): void {
  if (input.summary.trim() === "") throw new TypeError("Assessment summary cannot be empty");
  if (input.source.id !== input.capsule.id) throw new TypeError("Assessment source and capsule ids must match");
  const observations = input.observations ?? [];
  const staleAxes = input.staleAxes ?? [];

  if (input.state === "POTENTIALLY_AFFECTED") {
    if (input.applicability.status !== "MATCHED_AFFECTED") {
      throw new TypeError("POTENTIALLY_AFFECTED requires an affected-version match");
    }
    if (observations.length !== 0) throw new TypeError("POTENTIALLY_AFFECTED cannot claim runtime observations");
  }
  if (input.state === "OBSERVED_BY_CHECK" || input.state === "REMEDIATION_RETESTED") {
    const roles = new Set(observations.map((observation) => observation.role));
    if (
      observations.length !== 3 ||
      !roles.has("TARGET") ||
      !roles.has("FIXED_CONTROL") ||
      !roles.has("POSITIVE_CONTROL")
    ) {
      throw new TypeError(`${input.state} requires exactly one target, fixed-control, and positive-control observation`);
    }
  }
  if (input.state === "EVIDENCE_STALE_FOR_CURRENT_HEAD") {
    if (!input.supersedes || staleAxes.length === 0) {
      throw new TypeError("A stale assessment must supersede prior evidence and identify a changed axis");
    }
    if (observations.length !== 0) throw new TypeError("A stale marker cannot inherit prior runtime observations");
  } else if (staleAxes.length !== 0) {
    throw new TypeError("Only a stale assessment can identify stale axes");
  }
}

export function createAssessment(input: CreateAssessmentInput): AssessmentRecord {
  validateAssessmentInput(input);
  const observations = [...(input.observations ?? [])];
  const body = {
    repository: input.repository,
    source: input.source,
    capsule: input.capsule,
    state: input.state,
    summary: input.summary,
    createdAt: input.createdAt,
    evidence: {
      applicability: input.applicability,
      observationIds: observations.map((observation) => observation.id),
      staleAxes: [...(input.staleAxes ?? [])],
    },
    observations,
    ...(input.supersedes ? { supersedes: input.supersedes } : {}),
  };
  const digest = sha256CanonicalJson(body);
  const id = asAssessmentId(
    `assessment:${digest.slice("sha256:".length, "sha256:".length + 24)}`,
  );
  return deepFreeze({ id, ...body }) as AssessmentRecord;
}

export function createPotentiallyAffectedAssessment(input: Readonly<{
  repository: RepositoryRevision;
  source: SourceRevision;
  capsule: CapsuleIdentity;
  applicability: ApplicabilityResult;
  createdAt: IsoTimestamp;
}>): AssessmentRecord {
  return createAssessment({
    ...input,
    state: "POTENTIALLY_AFFECTED",
    summary: input.applicability.explanation,
  });
}

export function createAdjudicatedAssessment(input: Readonly<{
  repository: RepositoryRevision;
  source: SourceRevision;
  capsule: CapsuleIdentity;
  applicability: ApplicabilityResult;
  adjudication: MatrixAdjudication;
  matrix: ObservationMatrix;
  createdAt: IsoTimestamp;
  supersedes: AssessmentId;
}>): AssessmentRecord {
  return createAssessment({
    repository: input.repository,
    source: input.source,
    capsule: input.capsule,
    state: input.adjudication.state,
    summary: input.adjudication.summary,
    createdAt: input.createdAt,
    applicability: input.applicability,
    observations: [input.matrix.target, input.matrix.fixedControl, input.matrix.positiveControl],
    supersedes: input.supersedes,
  });
}

export function createStaleAssessment(input: Readonly<{
  previous: AssessmentRecord;
  repository: RepositoryRevision;
  source: SourceRevision;
  capsule: CapsuleIdentity;
  applicability: ApplicabilityResult;
  createdAt: IsoTimestamp;
}>): AssessmentRecord {
  const { previous } = input;
  if (previous.repository.fullName !== input.repository.fullName) {
    throw new TypeError("Stale evidence must remain within one repository");
  }
  if (previous.source.id !== input.source.id || previous.capsule.id !== input.capsule.id) {
    throw new TypeError("A different source or capsule id starts a separate assessment chain");
  }
  const staleAxes: AssessmentRecord["evidence"]["staleAxes"][number][] = [];
  if (previous.repository.headSha !== input.repository.headSha) staleAxes.push("REPOSITORY_SHA");
  if (previous.source.revision !== input.source.revision) staleAxes.push("SOURCE_REVISION");
  if (previous.capsule.revision !== input.capsule.revision) staleAxes.push("CAPSULE_REVISION");
  if (previous.capsule.digest !== input.capsule.digest) staleAxes.push("CAPSULE_DIGEST");
  if (staleAxes.length === 0) throw new TypeError("Evidence is still current for all immutable axes");

  return createAssessment({
    repository: input.repository,
    source: input.source,
    capsule: input.capsule,
    state: "EVIDENCE_STALE_FOR_CURRENT_HEAD",
    summary:
      staleAxes.length === 1 && staleAxes[0] === "REPOSITORY_SHA"
        ? "The current repository head differs from the retested commit; the older receipt cannot be reused for this revision."
        : `Prior evidence is stale because these immutable axes changed: ${staleAxes.join(", ")}.`,
    createdAt: input.createdAt,
    applicability: input.applicability,
    staleAxes,
    supersedes: previous.id,
  });
}

export function appendAssessment(
  history: readonly AssessmentRecord[],
  next: AssessmentRecord,
): readonly AssessmentRecord[] {
  if (history.some((record) => record.id === next.id)) throw new TypeError(`Assessment ${next.id} already exists`);
  if (history.length === 0) {
    if (next.supersedes) throw new TypeError("The first assessment cannot supersede an absent record");
    return deepFreeze([next]);
  }
  if (!next.supersedes) throw new TypeError("A subsequent assessment must explicitly supersede prior evidence");
  const previous = history.find((record) => record.id === next.supersedes);
  if (!previous) throw new TypeError(`Superseded assessment ${next.supersedes} is not in the ledger`);
  if (history.some((record) => record.supersedes === previous.id)) {
    throw new TypeError(`Assessment ${previous.id} already has a superseding record`);
  }
  if (previous.repository.fullName !== next.repository.fullName) throw new TypeError("Assessment chain changed repository");
  if (previous.source.id !== next.source.id || previous.capsule.id !== next.capsule.id) {
    throw new TypeError("Assessment chain changed source or capsule identity");
  }
  if (Date.parse(next.createdAt) <= Date.parse(previous.createdAt)) {
    throw new TypeError("A superseding assessment must be created after its predecessor");
  }
  return deepFreeze([...history, next]);
}

export function supersededBy(
  history: readonly AssessmentRecord[],
  assessmentId: AssessmentId,
): AssessmentId | null {
  return history.find((record) => record.supersedes === assessmentId)?.id ?? null;
}

export function createAssessmentEvent(input: Readonly<{
  sequence: number;
  at: IsoTimestamp;
  type: AssessmentEventType;
  assessment: AssessmentRecord;
  title: string;
  detail: string;
}>): AssessmentEvent {
  if (!Number.isSafeInteger(input.sequence) || input.sequence < 1) {
    throw new TypeError("Event sequence must be a positive safe integer");
  }
  if (input.title.trim() === "" || input.detail.trim() === "") throw new TypeError("Event title and detail are required");
  const body = {
    sequence: input.sequence,
    at: input.at,
    type: input.type,
    assessmentId: input.assessment.id,
    state: input.assessment.state,
    title: input.title,
    detail: input.detail,
  };
  const digest = sha256CanonicalJson(body);
  const id = asEventId(`event:${digest.slice("sha256:".length, "sha256:".length + 24)}`);
  return deepFreeze({ id, ...body }) as AssessmentEvent;
}
