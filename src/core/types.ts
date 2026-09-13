declare const brand: unique symbol;

export type Branded<T, Name extends string> = T & { readonly [brand]: Name };

export type Sha256Digest = Branded<string, "Sha256Digest">;
export type RepositorySha = Branded<string, "RepositorySha">;
export type IsoTimestamp = Branded<string, "IsoTimestamp">;
export type AssessmentId = Branded<string, "AssessmentId">;
export type EventId = Branded<string, "EventId">;

export const assessmentStates = [
  "POTENTIALLY_AFFECTED",
  "OBSERVED_BY_CHECK",
  "REMEDIATION_RETESTED",
  "UNKNOWN",
  "EVIDENCE_STALE_FOR_CURRENT_HEAD",
] as const;

export type AssessmentState = (typeof assessmentStates)[number];

export type PackageEcosystem = "PyPI" | "npm";

export type SourceRevision = Readonly<{
  id: string;
  revision: string;
  kind: "DEPENDENCY_ADVISORY";
  aliases: readonly string[];
  url: string;
  publishedAt: IsoTimestamp;
  modifiedAt: IsoTimestamp;
}>;

export type DependencyApplicability = Readonly<{
  ecosystem: PackageEcosystem;
  packageName: string;
  affectedRange: string;
  fixedVersion: string;
}>;

export type EffectContract = Readonly<{
  id: string;
  path: string;
  expectedSha256: Sha256Digest;
  dataClassification: "SYNTHETIC_CANARY_NO_SECRET";
  notice: string;
}>;

export type CapsuleControls = Readonly<{
  fixed: Readonly<{
    id: string;
    packageVersion: string;
  }>;
  positive: Readonly<{
    id: string;
    packageVersion: string;
    fixtureRevision: string;
  }>;
}>;

export type CapsuleCapabilities = Readonly<{
  network: "NONE";
  credentials: "NONE";
  readOnlyPaths: readonly string[];
  writablePaths: readonly string[];
  timeoutMs: number;
}>;

export type ThreatCapsule = Readonly<{
  schemaVersion: 1;
  id: string;
  revision: string;
  source: SourceRevision;
  applicability: DependencyApplicability;
  effect: EffectContract;
  controls: CapsuleControls;
  capabilities: CapsuleCapabilities;
}>;

export type CapsuleIdentity = Readonly<{
  id: string;
  revision: string;
  digest: Sha256Digest;
}>;

export type RepositoryRevision = Readonly<{
  fullName: string;
  branch: string;
  headSha: RepositorySha;
}>;

export type InventoryCoverage = Readonly<{
  status: "COMPLETE" | "PARTIAL" | "FAILED";
  checkedPaths: readonly string[];
  detail: string;
}>;

export type DependencyEvidence = Readonly<{
  id: string;
  ecosystem: PackageEcosystem;
  packageName: string;
  version: string;
  manifestPath: string;
  observedAt: IsoTimestamp;
}>;

export type ProjectSnapshot = Readonly<{
  schemaVersion: 1;
  repository: RepositoryRevision;
  observedAt: IsoTimestamp;
  inventory: InventoryCoverage;
  dependencies: readonly DependencyEvidence[];
}>;

export type ApplicabilityStatus =
  | "MATCHED_AFFECTED"
  | "MATCHED_UNAFFECTED"
  | "NOT_PRESENT"
  | "UNKNOWN";

export type ApplicabilityResult = Readonly<{
  status: ApplicabilityStatus;
  packageName: string;
  affectedRange: string;
  installedVersion: string | null;
  evidenceIds: readonly string[];
  explanation: string;
}>;

export type ObservationRole = "TARGET" | "FIXED_CONTROL" | "POSITIVE_CONTROL";
export type HostRunStatus = "COMPLETED" | "FAILED" | "TIMED_OUT";

export type FileCapture =
  | Readonly<{
      status: "CAPTURED";
      exists: false;
      sha256: null;
      byteLength: 0;
    }>
  | Readonly<{
      status: "CAPTURED";
      exists: true;
      sha256: Sha256Digest;
      byteLength: number;
    }>
  | Readonly<{
      status: "FAILED";
      exists: null;
      sha256: null;
      byteLength: null;
      error: string;
    }>;

export type RawHostObservation = Readonly<{
  id: string;
  role: ObservationRole;
  inputLabel: string;
  inputDigest: Sha256Digest;
  capsuleDigest: Sha256Digest;
  effectPath: string;
  runStatus: HostRunStatus;
  evidenceComplete: boolean;
  before: FileCapture;
  after: FileCapture;
  startedAt: IsoTimestamp;
  finishedAt: IsoTimestamp;
  durationMs: number;
  guest: Readonly<{
    exitCode: number | null;
    stdoutSha256: Sha256Digest;
    stderrSha256: Sha256Digest;
    claimedResult?: string;
  }>;
}>;

export type EffectStatus = "OBSERVED" | "NOT_OBSERVED" | "UNKNOWN";

export type DerivedEffect = Readonly<{
  observationId: string;
  role: ObservationRole;
  status: EffectStatus;
  beforeSha256: Sha256Digest | null;
  afterSha256: Sha256Digest | null;
  explanation: string;
}>;

export type ObservationMatrix = Readonly<{
  target: RawHostObservation;
  fixedControl: RawHostObservation;
  positiveControl: RawHostObservation;
}>;

export type MatrixAdjudication = Readonly<{
  state: "OBSERVED_BY_CHECK" | "REMEDIATION_RETESTED" | "UNKNOWN";
  summary: string;
  effects: Readonly<{
    target: DerivedEffect;
    fixedControl: DerivedEffect;
    positiveControl: DerivedEffect;
  }>;
}>;

export type AssessmentEvidence = Readonly<{
  applicability: ApplicabilityResult;
  observationIds: readonly string[];
  staleAxes: readonly ("REPOSITORY_SHA" | "SOURCE_REVISION" | "CAPSULE_REVISION" | "CAPSULE_DIGEST")[];
}>;

export type AssessmentRecord = Readonly<{
  id: AssessmentId;
  repository: RepositoryRevision;
  source: SourceRevision;
  capsule: CapsuleIdentity;
  state: AssessmentState;
  summary: string;
  createdAt: IsoTimestamp;
  evidence: AssessmentEvidence;
  observations: readonly RawHostObservation[];
  supersedes?: AssessmentId;
}>;

export type AssessmentEventType =
  | "PROJECT_MATCHED"
  | "EFFECT_OBSERVED"
  | "REMEDIATION_RETESTED"
  | "EVIDENCE_STALE";

export type AssessmentEvent = Readonly<{
  id: EventId;
  sequence: number;
  at: IsoTimestamp;
  type: AssessmentEventType;
  assessmentId: AssessmentId;
  state: AssessmentState;
  title: string;
  detail: string;
}>;

export type DemoSequence = Readonly<{
  capsule: ThreatCapsule;
  capsuleIdentity: CapsuleIdentity;
  assessments: readonly AssessmentRecord[];
  events: readonly AssessmentEvent[];
}>;

export function asSha256Digest(value: string): Sha256Digest {
  if (!/^sha256:[0-9a-f]{64}$/.test(value)) {
    throw new TypeError(`Invalid SHA-256 digest: ${value}`);
  }
  return value as Sha256Digest;
}

export function asRepositorySha(value: string): RepositorySha {
  if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(value)) {
    throw new TypeError(`Invalid full repository SHA: ${value}`);
  }
  return value as RepositorySha;
}

export function asIsoTimestamp(value: string): IsoTimestamp {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value) || Number.isNaN(Date.parse(value))) {
    throw new TypeError(`Invalid UTC timestamp: ${value}`);
  }
  return value as IsoTimestamp;
}

export function asAssessmentId(value: string): AssessmentId {
  if (!/^assessment:[0-9a-f]{24}$/.test(value)) {
    throw new TypeError(`Invalid assessment id: ${value}`);
  }
  return value as AssessmentId;
}

export function asEventId(value: string): EventId {
  if (!/^event:[0-9a-f]{24}$/.test(value)) {
    throw new TypeError(`Invalid event id: ${value}`);
  }
  return value as EventId;
}
