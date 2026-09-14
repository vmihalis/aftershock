import assert from "node:assert/strict";
import test from "node:test";
import { DemoController } from "../../src/api/demo-controller.js";

test("demo reaches the video-critical states in order", () => {
  const controller = new DemoController();
  const states = [controller.view().assessment.state];
  while (controller.view().meta.frame < controller.view().meta.frameCount) {
    states.push(controller.advance().assessment.state);
  }
  assert.deepEqual(states, [
    "POTENTIALLY_AFFECTED",
    "POTENTIALLY_AFFECTED",
    "OBSERVED_BY_CHECK",
    "OBSERVED_BY_CHECK",
    "REMEDIATION_RETESTED",
    "EVIDENCE_STALE_FOR_CURRENT_HEAD",
  ]);
});

test("observed result is supported by target, fixed, and positive-control effects", () => {
  const controller = new DemoController();
  controller.advance();
  const view = controller.advance();
  assert.equal(view.assessment.state, "OBSERVED_BY_CHECK");
  const results = Object.fromEntries(view.matrix.map((row) => [row.id, row.status]));
  assert.equal(results.before, "effect_observed");
  assert.equal(results.fixed, "effect_absent");
  assert.equal(results.positive, "effect_observed");
  assert.equal(results.after, "pending");
});

test("stale frame binds the old evidence to a different SHA", () => {
  const controller = new DemoController();
  const originalSha = controller.view().repository.headSha;
  let view = controller.view();
  while (view.meta.frame < view.meta.frameCount) view = controller.advance();
  assert.equal(view.assessment.state, "EVIDENCE_STALE_FOR_CURRENT_HEAD");
  assert.notEqual(view.repository.headSha, originalSha);
  assert.ok(view.assessment.supersedes);
});

test("a signed push adapter can invalidate evidence for its exact new head", () => {
  const controller = new DemoController();
  const headSha = "b".repeat(40);
  const view = controller.invalidateForHead(headSha);
  assert.equal(view.assessment.state, "EVIDENCE_STALE_FOR_CURRENT_HEAD");
  assert.equal(view.repository.headSha, headSha);
  assert.throws(() => controller.invalidateForHead("short"), /full 40-character Git SHA/);
});

test("demo frames expose their real public GitHub evidence", () => {
  const controller = new DemoController();
  controller.advance();
  let view = controller.advance();
  assert.equal(
    view.artifacts.find((artifact) => artifact.kind === "github_check")?.url,
    "https://github.com/vmihalis/aftershock-apm-fixture/runs/103819046282",
  );
  assert.equal(view.artifacts.some((artifact) => artifact.kind === "github_issue"), false);

  view = controller.advance();
  assert.equal(
    view.artifacts.find((artifact) => artifact.kind === "github_issue")?.url,
    "https://github.com/vmihalis/aftershock-apm-fixture/issues/1",
  );

  view = controller.advance();
  assert.equal(
    view.artifacts.find((artifact) => artifact.kind === "github_check")?.url,
    "https://github.com/vmihalis/aftershock-apm-fixture/runs/103819189475",
  );

  view = controller.advance();
  assert.equal(
    view.artifacts.find((artifact) => artifact.kind === "github_check")?.url,
    "https://github.com/vmihalis/aftershock-apm-fixture/runs/103819288142",
  );
});
