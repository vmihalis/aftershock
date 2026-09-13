import { deepFreeze, sha256CanonicalJson } from "./hash.js";
import {
  asIsoTimestamp,
  asSha256Digest,
  type CapsuleCapabilities,
  type CapsuleControls,
  type CapsuleIdentity,
  type DependencyApplicability,
  type EffectContract,
  type PackageEcosystem,
  type SourceRevision,
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

function string(value: unknown, location: string): string {
  if (typeof value !== "string" || value.trim() === "") throw new TypeError(`${location} must be a non-empty string`);
  return value;
}

function stringArray(value: unknown, location: string): readonly string[] {
  if (!Array.isArray(value)) throw new TypeError(`${location} must be an array`);
  return value.map((item, index) => string(item, `${location}[${index}]`));
}

function packageEcosystem(value: unknown, location: string): PackageEcosystem {
  if (value !== "PyPI" && value !== "npm") throw new TypeError(`${location} must be PyPI or npm`);
  return value;
}

function parseSource(value: unknown): SourceRevision {
  const source = record(value, "source");
  exactKeys(source, "source", ["aliases", "id", "kind", "modifiedAt", "publishedAt", "revision", "url"]);
  if (source.kind !== "DEPENDENCY_ADVISORY") throw new TypeError("source.kind must be DEPENDENCY_ADVISORY");
  const url = string(source.url, "source.url");
  if (!url.startsWith("https://")) throw new TypeError("source.url must use https");
  return {
    id: string(source.id, "source.id"),
    revision: string(source.revision, "source.revision"),
    kind: source.kind,
    aliases: stringArray(source.aliases, "source.aliases"),
    url,
    publishedAt: asIsoTimestamp(string(source.publishedAt, "source.publishedAt")),
    modifiedAt: asIsoTimestamp(string(source.modifiedAt, "source.modifiedAt")),
  };
}

function parseApplicability(value: unknown): DependencyApplicability {
  const applicability = record(value, "applicability");
  exactKeys(applicability, "applicability", ["affectedRange", "ecosystem", "fixedVersion", "packageName"]);
  return {
    ecosystem: packageEcosystem(applicability.ecosystem, "applicability.ecosystem"),
    packageName: string(applicability.packageName, "applicability.packageName"),
    affectedRange: string(applicability.affectedRange, "applicability.affectedRange"),
    fixedVersion: string(applicability.fixedVersion, "applicability.fixedVersion"),
  };
}

function parseEffect(value: unknown): EffectContract {
  const effect = record(value, "effect");
  exactKeys(effect, "effect", ["dataClassification", "expectedSha256", "id", "notice", "path"]);
  if (effect.dataClassification !== "SYNTHETIC_CANARY_NO_SECRET") {
    throw new TypeError("effect.dataClassification must be SYNTHETIC_CANARY_NO_SECRET");
  }
  const path = string(effect.path, "effect.path");
  const pathParts = path.split(/[\\/]/u);
  if (path.startsWith("/") || pathParts.includes("..") || pathParts.includes(".")) {
    throw new TypeError("effect.path must be a normalized repository-relative path");
  }
  return {
    id: string(effect.id, "effect.id"),
    path,
    expectedSha256: asSha256Digest(string(effect.expectedSha256, "effect.expectedSha256")),
    dataClassification: effect.dataClassification,
    notice: string(effect.notice, "effect.notice"),
  };
}

function parseControls(value: unknown): CapsuleControls {
  const controls = record(value, "controls");
  exactKeys(controls, "controls", ["fixed", "positive"]);
  const fixed = record(controls.fixed, "controls.fixed");
  const positive = record(controls.positive, "controls.positive");
  exactKeys(fixed, "controls.fixed", ["id", "packageVersion"]);
  exactKeys(positive, "controls.positive", ["fixtureRevision", "id", "packageVersion"]);
  return {
    fixed: {
      id: string(fixed.id, "controls.fixed.id"),
      packageVersion: string(fixed.packageVersion, "controls.fixed.packageVersion"),
    },
    positive: {
      id: string(positive.id, "controls.positive.id"),
      packageVersion: string(positive.packageVersion, "controls.positive.packageVersion"),
      fixtureRevision: string(positive.fixtureRevision, "controls.positive.fixtureRevision"),
    },
  };
}

function parseCapabilities(value: unknown): CapsuleCapabilities {
  const capabilities = record(value, "capabilities");
  exactKeys(capabilities, "capabilities", [
    "credentials",
    "network",
    "readOnlyPaths",
    "timeoutMs",
    "writablePaths",
  ]);
  if (capabilities.network !== "NONE") throw new TypeError("capabilities.network must be NONE");
  if (capabilities.credentials !== "NONE") throw new TypeError("capabilities.credentials must be NONE");
  if (!Number.isSafeInteger(capabilities.timeoutMs) || (capabilities.timeoutMs as number) <= 0) {
    throw new TypeError("capabilities.timeoutMs must be a positive safe integer");
  }
  return {
    network: capabilities.network,
    credentials: capabilities.credentials,
    readOnlyPaths: stringArray(capabilities.readOnlyPaths, "capabilities.readOnlyPaths"),
    writablePaths: stringArray(capabilities.writablePaths, "capabilities.writablePaths"),
    timeoutMs: capabilities.timeoutMs as number,
  };
}

export function parseThreatCapsule(value: unknown): ThreatCapsule {
  const capsule = record(value, "capsule");
  exactKeys(capsule, "capsule", [
    "applicability",
    "capabilities",
    "controls",
    "effect",
    "id",
    "revision",
    "schemaVersion",
    "source",
  ]);
  if (capsule.schemaVersion !== 1) throw new TypeError("capsule.schemaVersion must be 1");
  const source = parseSource(capsule.source);
  const id = string(capsule.id, "capsule.id");
  if (id !== source.id) throw new TypeError("capsule.id must equal source.id");

  return deepFreeze({
    schemaVersion: 1,
    id,
    revision: string(capsule.revision, "capsule.revision"),
    source,
    applicability: parseApplicability(capsule.applicability),
    effect: parseEffect(capsule.effect),
    controls: parseControls(capsule.controls),
    capabilities: parseCapabilities(capsule.capabilities),
  }) as ThreatCapsule;
}

export function digestThreatCapsule(capsule: ThreatCapsule): CapsuleIdentity {
  return deepFreeze({
    id: capsule.id,
    revision: capsule.revision,
    digest: sha256CanonicalJson(capsule),
  }) as CapsuleIdentity;
}
