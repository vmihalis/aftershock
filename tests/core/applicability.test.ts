import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  APM_PATH_ESCAPE_CAPSULE,
  matchApmApplicability,
  parseProjectSnapshot,
} from "../../src/core/index.js";

const vulnerableUrl = new URL("../../fixtures/core/apm-vulnerable-snapshot.json", import.meta.url);
const patchedUrl = new URL("../../fixtures/core/apm-patched-snapshot.json", import.meta.url);

async function fixture(url: URL) {
  return parseProjectSnapshot(JSON.parse(await readFile(url, "utf8")));
}

test("apm-cli 0.8.11 is potentially affected and 0.8.12 is scoped fixed evidence", async () => {
  const vulnerable = matchApmApplicability(APM_PATH_ESCAPE_CAPSULE, await fixture(vulnerableUrl));
  const patched = matchApmApplicability(APM_PATH_ESCAPE_CAPSULE, await fixture(patchedUrl));

  assert.equal(vulnerable.status, "MATCHED_AFFECTED");
  assert.equal(vulnerable.installedVersion, "0.8.11");
  assert.match(vulnerable.explanation, /not exploitation/u);
  assert.equal(patched.status, "MATCHED_UNAFFECTED");
  assert.equal(patched.installedVersion, "0.8.12");
  assert.match(patched.explanation, /scoped/u);
});

test("PyPI name normalization accepts equivalent apm_cli spelling", async () => {
  const source = JSON.parse(await readFile(vulnerableUrl, "utf8")) as {
    dependencies: Array<Record<string, unknown>>;
  };
  source.dependencies[0]!.packageName = "APM_CLI";
  assert.equal(matchApmApplicability(APM_PATH_ESCAPE_CAPSULE, parseProjectSnapshot(source)).status, "MATCHED_AFFECTED");
});

test("missing partial inventory and conflicting versions stay unknown", async () => {
  const source = JSON.parse(await readFile(vulnerableUrl, "utf8")) as {
    inventory: Record<string, unknown>;
    dependencies: Array<Record<string, unknown>>;
  };
  source.inventory.status = "PARTIAL";
  source.dependencies = [];
  assert.equal(matchApmApplicability(APM_PATH_ESCAPE_CAPSULE, parseProjectSnapshot(source)).status, "UNKNOWN");

  const conflict = JSON.parse(await readFile(vulnerableUrl, "utf8")) as {
    dependencies: Array<Record<string, unknown>>;
  };
  conflict.dependencies.push({
    ...conflict.dependencies[0],
    id: "constraints.txt:apm-cli:0.8.12",
    version: "0.8.12",
    manifestPath: "constraints.txt",
  });
  const result = matchApmApplicability(APM_PATH_ESCAPE_CAPSULE, parseProjectSnapshot(conflict));
  assert.equal(result.status, "UNKNOWN");
  assert.match(result.explanation, /Conflicting/u);
});

test("unsupported Python version syntax does not become affected or safe", async () => {
  const source = JSON.parse(await readFile(vulnerableUrl, "utf8")) as {
    dependencies: Array<Record<string, unknown>>;
  };
  source.dependencies[0]!.version = "0.8.11rc1";
  const result = matchApmApplicability(APM_PATH_ESCAPE_CAPSULE, parseProjectSnapshot(source));
  assert.equal(result.status, "UNKNOWN");
  assert.match(result.explanation, /supported by this matcher/u);
});
