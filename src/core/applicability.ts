import semver from "semver";
import { deepFreeze } from "./hash.js";
import {
  asIsoTimestamp,
  asRepositorySha,
  type ApplicabilityResult,
  type DependencyApplicability,
  type DependencyEvidence,
  type InventoryCoverage,
  type PackageEcosystem,
  type ProjectSnapshot,
  type RepositoryRevision,
  type ThreatCapsule,
} from "./types.js";

type UnknownRecord = Record<string, unknown>;

function record(value: unknown, location: string): UnknownRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${location} must be an object`);
  }
  return value as UnknownRecord;
}

function exactKeys(value: UnknownRecord, location: string, keys: readonly string[]): void {
  const expected = [...keys].sort();
  const actual = Object.keys(value).sort();
  if (expected.length !== actual.length || expected.some((key, index) => key !== actual[index])) {
    throw new TypeError(`${location} must contain exactly: ${expected.join(", ")}`);
  }
}

function nonEmpty(value: unknown, location: string): string {
  if (typeof value !== "string" || value.trim() === "") throw new TypeError(`${location} must be a non-empty string`);
  return value;
}

function ecosystem(value: unknown, location: string): PackageEcosystem {
  if (value !== "PyPI" && value !== "npm") throw new TypeError(`${location} must be PyPI or npm`);
  return value;
}

function parseRepository(value: unknown): RepositoryRevision {
  const repository = record(value, "snapshot.repository");
  exactKeys(repository, "snapshot.repository", ["branch", "fullName", "headSha"]);
  return {
    fullName: nonEmpty(repository.fullName, "snapshot.repository.fullName"),
    branch: nonEmpty(repository.branch, "snapshot.repository.branch"),
    headSha: asRepositorySha(nonEmpty(repository.headSha, "snapshot.repository.headSha")),
  };
}

function parseInventory(value: unknown): InventoryCoverage {
  const inventory = record(value, "snapshot.inventory");
  exactKeys(inventory, "snapshot.inventory", ["checkedPaths", "detail", "status"]);
  if (inventory.status !== "COMPLETE" && inventory.status !== "PARTIAL" && inventory.status !== "FAILED") {
    throw new TypeError("snapshot.inventory.status must be COMPLETE, PARTIAL, or FAILED");
  }
  if (!Array.isArray(inventory.checkedPaths)) throw new TypeError("snapshot.inventory.checkedPaths must be an array");
  return {
    status: inventory.status,
    checkedPaths: inventory.checkedPaths.map((path, index) =>
      nonEmpty(path, `snapshot.inventory.checkedPaths[${index}]`),
    ),
    detail: nonEmpty(inventory.detail, "snapshot.inventory.detail"),
  };
}

function parseDependency(value: unknown, index: number): DependencyEvidence {
  const location = `snapshot.dependencies[${index}]`;
  const dependency = record(value, location);
  exactKeys(dependency, location, ["ecosystem", "id", "manifestPath", "observedAt", "packageName", "version"]);
  return {
    id: nonEmpty(dependency.id, `${location}.id`),
    ecosystem: ecosystem(dependency.ecosystem, `${location}.ecosystem`),
    packageName: nonEmpty(dependency.packageName, `${location}.packageName`),
    version: nonEmpty(dependency.version, `${location}.version`),
    manifestPath: nonEmpty(dependency.manifestPath, `${location}.manifestPath`),
    observedAt: asIsoTimestamp(nonEmpty(dependency.observedAt, `${location}.observedAt`)),
  };
}

export function parseProjectSnapshot(value: unknown): ProjectSnapshot {
  const snapshot = record(value, "snapshot");
  exactKeys(snapshot, "snapshot", ["dependencies", "inventory", "observedAt", "repository", "schemaVersion"]);
  if (snapshot.schemaVersion !== 1) throw new TypeError("snapshot.schemaVersion must be 1");
  if (!Array.isArray(snapshot.dependencies)) throw new TypeError("snapshot.dependencies must be an array");
  return deepFreeze({
    schemaVersion: 1,
    repository: parseRepository(snapshot.repository),
    observedAt: asIsoTimestamp(nonEmpty(snapshot.observedAt, "snapshot.observedAt")),
    inventory: parseInventory(snapshot.inventory),
    dependencies: snapshot.dependencies.map(parseDependency),
  }) as ProjectSnapshot;
}

export function normalizePackageName(name: string, packageEcosystem: PackageEcosystem): string {
  const lowered = name.trim().toLowerCase();
  return packageEcosystem === "PyPI" ? lowered.replace(/[-_.]+/gu, "-") : lowered;
}

function unknown(
  applicability: DependencyApplicability,
  installedVersion: string | null,
  evidenceIds: readonly string[],
  explanation: string,
): ApplicabilityResult {
  return deepFreeze({
    status: "UNKNOWN",
    packageName: applicability.packageName,
    affectedRange: applicability.affectedRange,
    installedVersion,
    evidenceIds,
    explanation,
  }) as ApplicabilityResult;
}

export function matchDependencyApplicability(
  applicability: DependencyApplicability,
  snapshot: ProjectSnapshot,
): ApplicabilityResult {
  const wantedName = normalizePackageName(applicability.packageName, applicability.ecosystem);
  const matches = snapshot.dependencies.filter(
    (dependency) =>
      dependency.ecosystem === applicability.ecosystem &&
      normalizePackageName(dependency.packageName, dependency.ecosystem) === wantedName,
  );

  if (matches.length === 0) {
    if (snapshot.inventory.status !== "COMPLETE") {
      return unknown(
        applicability,
        null,
        [],
        `Inventory coverage is ${snapshot.inventory.status.toLowerCase()}; absence of ${applicability.packageName} is inconclusive.`,
      );
    }
    return deepFreeze({
      status: "NOT_PRESENT",
      packageName: applicability.packageName,
      affectedRange: applicability.affectedRange,
      installedVersion: null,
      evidenceIds: [],
      explanation: `${applicability.packageName} was not present in the completely checked dependency inventory.`,
    }) as ApplicabilityResult;
  }

  const versions = [...new Set(matches.map((match) => match.version))];
  const evidenceIds = matches.map((match) => match.id);
  if (versions.length !== 1) {
    return unknown(applicability, null, evidenceIds, `Conflicting installed versions were observed: ${versions.join(", ")}.`);
  }

  const [installedVersion] = versions;
  if (!/^\d+\.\d+\.\d+$/u.test(installedVersion) || semver.valid(installedVersion) === null) {
    return unknown(
      applicability,
      installedVersion,
      evidenceIds,
      `Version ${installedVersion} is outside the stable three-component version syntax supported by this matcher.`,
    );
  }
  if (semver.validRange(applicability.affectedRange) === null || semver.valid(applicability.fixedVersion) === null) {
    return unknown(applicability, installedVersion, evidenceIds, "The capsule contains an unsupported version range.");
  }

  if (semver.satisfies(installedVersion, applicability.affectedRange)) {
    return deepFreeze({
      status: "MATCHED_AFFECTED",
      packageName: applicability.packageName,
      affectedRange: applicability.affectedRange,
      installedVersion,
      evidenceIds,
      explanation: `${applicability.packageName} ${installedVersion} matches advisory range ${applicability.affectedRange}; this establishes potential applicability, not exploitation.`,
    }) as ApplicabilityResult;
  }

  if (semver.gte(installedVersion, applicability.fixedVersion)) {
    return deepFreeze({
      status: "MATCHED_UNAFFECTED",
      packageName: applicability.packageName,
      affectedRange: applicability.affectedRange,
      installedVersion,
      evidenceIds,
      explanation: `${applicability.packageName} ${installedVersion} is at or above the advisory's fixed version ${applicability.fixedVersion}; this conclusion is scoped to the checked dependency evidence.`,
    }) as ApplicabilityResult;
  }

  return unknown(
    applicability,
    installedVersion,
    evidenceIds,
    `Version ${installedVersion} is neither in the affected range nor at or above the fixed version.`,
  );
}

export function matchApmApplicability(capsule: ThreatCapsule, snapshot: ProjectSnapshot): ApplicabilityResult {
  if (
    capsule.applicability.ecosystem !== "PyPI" ||
    normalizePackageName(capsule.applicability.packageName, "PyPI") !== "apm-cli"
  ) {
    throw new TypeError("matchApmApplicability requires an apm-cli PyPI capsule");
  }
  return matchDependencyApplicability(capsule.applicability, snapshot);
}
