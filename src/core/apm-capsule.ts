import { parseThreatCapsule } from "./capsule.js";

export const SYNTHETIC_CANARY_TEXT = [
  "# AFTERSHOCK SYNTHETIC CANARY",
  "",
  "This is team-owned test data. It contains no personal, credential, or production information.",
  "",
].join("\n");

export const APM_PATH_ESCAPE_CAPSULE = parseThreatCapsule({
  schemaVersion: 1,
  id: "GHSA-xhrw-5qxx-jpwr",
  revision: "r1",
  source: {
    id: "GHSA-xhrw-5qxx-jpwr",
    revision: "2026-05-15",
    kind: "DEPENDENCY_ADVISORY",
    aliases: ["CVE-2026-44641"],
    url: "https://github.com/microsoft/apm/security/advisories/GHSA-xhrw-5qxx-jpwr",
    publishedAt: "2026-05-03T00:00:00.000Z",
    modifiedAt: "2026-05-15T00:00:00.000Z",
  },
  applicability: {
    ecosystem: "PyPI",
    packageName: "apm-cli",
    affectedRange: "<=0.8.11",
    fixedVersion: "0.8.12",
  },
  effect: {
    id: "apm-prompt-canary-copy",
    path: ".github/prompts/aftershock-synthetic-canary.prompt.md",
    expectedSha256: "sha256:6976c63e82496144356b60c25de1f22d85cae76aaebe7c146273b51af34290b6",
    dataClassification: "SYNTHETIC_CANARY_NO_SECRET",
    notice: "Synthetic canary — no real secret accessed",
  },
  controls: {
    fixed: {
      id: "apm-cli-0.8.12-fixed",
      packageVersion: "0.8.12",
    },
    positive: {
      id: "apm-cli-0.8.11-frozen-positive",
      packageVersion: "0.8.11",
      fixtureRevision: "apm-positive-control-r1",
    },
  },
  capabilities: {
    network: "NONE",
    credentials: "NONE",
    readOnlyPaths: ["/input"],
    writablePaths: ["/workspace"],
    timeoutMs: 10_000,
  },
});
