import assert from "node:assert/strict";
import test from "node:test";
import { DemoController } from "../../src/api/demo-controller.js";
import { projectCheck, projectIssue } from "../../src/github/projections.js";
import { triggerFromPush, verifyWebhookSignature } from "../../src/github/webhook.js";
import { createHmac } from "node:crypto";

test("observed effect becomes a failing Check and an open Issue", () => {
  const controller = new DemoController();
  controller.advance();
  const view = controller.advance();
  const check = projectCheck(view);
  const issue = projectIssue(view);
  assert.equal(check.conclusion, "failure");
  assert.equal(check.head_sha, view.repository.headSha);
  assert.equal(issue.shouldBeOpen, true);
  assert.match(issue.body, /synthetic canary/i);
  assert.match(issue.body, new RegExp(view.capsule.digest));
});

test("retested remediation becomes success and closes the task", () => {
  const controller = new DemoController();
  let view = controller.view();
  while (view.assessment.state !== "REMEDIATION_RETESTED") view = controller.advance();
  assert.equal(projectCheck(view).conclusion, "success");
  assert.equal(projectIssue(view).shouldBeOpen, false);
});

test("stale evidence is neutral and reopens the task", () => {
  const controller = new DemoController();
  let view = controller.view();
  while (view.meta.frame < view.meta.frameCount) view = controller.advance();
  assert.equal(projectCheck(view).conclusion, "neutral");
  assert.equal(projectIssue(view).shouldBeOpen, true);
});

test("webhook signature and push trigger are fail closed", () => {
  const body = Buffer.from('{"after":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ref":"refs/heads/main","repository":{"full_name":"a/b"}}');
  const secret = "demo-secret";
  const signature = `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`;
  assert.equal(verifyWebhookSignature(body, signature, secret), true);
  assert.equal(verifyWebhookSignature(body, "sha256=bad", secret), false);
  assert.deepEqual(triggerFromPush(JSON.parse(body.toString())), {
    kind: "repository_changed",
    repositoryFullName: "a/b",
    headSha: "a".repeat(40),
    ref: "refs/heads/main",
  });
  assert.equal(triggerFromPush({}), null);
});
