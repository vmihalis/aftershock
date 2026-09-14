import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, access } from "node:fs/promises";
import test from "node:test";
import { APM_PATH_ESCAPE_CAPSULE, digestThreatCapsule } from "../../src/core/index.js";

const root = new URL("../../", import.meta.url);

test("evaluation map resolves its evidence and preserves the original artifact identities", async () => {
  const map = JSON.parse(await readFile(new URL("EVALUATION.json", root), "utf8"));
  for (const artifact of map.artifact_identities) {
    const bytes = await readFile(new URL(artifact.path, root));
    assert.equal(createHash("sha256").update(bytes).digest("hex"), artifact.sha256, artifact.path);
  }
  for (const claim of map.claims) {
    await access(new URL(claim.implementation, root));
    await access(new URL(claim.tests, root));
  }
  assert.equal(map.canonical_model.canonical_digest, digestThreatCapsule(APM_PATH_ESCAPE_CAPSULE).digest);
  assert.equal(map.recorded_experiment.canonical_r1_binding, "NOT_ESTABLISHED");
  assert.notEqual(map.recorded_experiment.canary_sha256, map.canonical_model.canary_sha256);
});
