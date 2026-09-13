import assert from "node:assert/strict";
import test from "node:test";
import { DemoController } from "../../src/api/demo-controller.js";
import { publishAssessment, type GitHubRequestClient } from "../../src/github/publisher.js";

class FakeClient implements GitHubRequestClient {
  readonly calls: Array<{ route: string; parameters: Record<string, unknown> }> = [];
  constructor(private readonly issues: unknown[] = []) {}

  async request(route: string, parameters: Record<string, unknown>): Promise<{ data: unknown }> {
    this.calls.push({ route, parameters });
    if (route.startsWith("GET ")) return { data: this.issues };
    if (route.includes("check-runs")) return { data: { html_url: "https://example.test/check/1" } };
    return { data: { html_url: "https://example.test/issue/1" } };
  }
}

test("publishes one check and creates a deduplicated agent issue", async () => {
  const controller = new DemoController();
  controller.advance();
  controller.advance();
  const client = new FakeClient();

  const result = await publishAssessment(client, controller.view());

  assert.equal(result.issueAction, "created");
  assert.deepEqual(client.calls.map((call) => call.route), [
    "POST /repos/{owner}/{repo}/check-runs",
    "GET /repos/{owner}/{repo}/issues",
    "POST /repos/{owner}/{repo}/issues",
  ]);
  assert.equal(client.calls[0].parameters.head_sha, controller.view().repository.headSha);
});

test("updates an existing issue with the same evidence key", async () => {
  const controller = new DemoController();
  const projection = (await import("../../src/github/projections.js")).projectIssue(controller.view());
  const client = new FakeClient([{
    number: 7,
    state: "open",
    body: `<!-- aftershock-dedupe:${projection.dedupeKey} -->`,
    html_url: "https://example.test/issue/7",
  }]);

  const result = await publishAssessment(client, controller.view());

  assert.equal(result.issueAction, "updated");
  assert.equal(client.calls.at(-1)?.route, "PATCH /repos/{owner}/{repo}/issues/{issue_number}");
  assert.equal(client.calls.at(-1)?.parameters.issue_number, 7);
});

test("closes the matching issue after a retested remediation", async () => {
  const controller = new DemoController();
  for (let index = 0; index < 4; index += 1) controller.advance();
  const projection = (await import("../../src/github/projections.js")).projectIssue(controller.view());
  const client = new FakeClient([{
    number: 7,
    state: "open",
    body: `<!-- aftershock-dedupe:${projection.dedupeKey} -->`,
  }]);

  const result = await publishAssessment(client, controller.view());

  assert.equal(result.issueAction, "closed");
  assert.equal(client.calls.at(-1)?.parameters.state, "closed");
});
