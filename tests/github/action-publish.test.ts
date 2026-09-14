import assert from "node:assert/strict";
import test from "node:test";
import {
  AUTHORIZED_DEMO_REPOSITORY,
  publishActionFrame,
  selectDemoFrame,
} from "../../src/github/action-publish.js";

const repositoryEnvironment = {
  GITHUB_REPOSITORY: AUTHORIZED_DEMO_REPOSITORY,
  GITHUB_TOKEN: "actions-test-token",
};

test("selects each of the six DemoController frames with its deterministic fixture reference revision", () => {
  const expectedShas = [
    "805de8f439f2e01c0f6c52d744a8fc3af640a931",
    "805de8f439f2e01c0f6c52d744a8fc3af640a931",
    "805de8f439f2e01c0f6c52d744a8fc3af640a931",
    "805de8f439f2e01c0f6c52d744a8fc3af640a931",
    "e4d7a28fa5dc5cf027fe421576f3ddb5c0dad46c",
    "5c29dc5fca31d077d6f23d73e648f3bc8a61924a",
  ];
  expectedShas.forEach((sha, index) => {
    const view = selectDemoFrame(index + 1);
    assert.equal(view.meta.frame, index + 1);
    assert.equal(view.repository.fullName, AUTHORIZED_DEMO_REPOSITORY);
    assert.equal(view.repository.headSha, sha);
  });
});

test("publishes selected frame Check and deduplicated Issue using GITHUB_TOKEN", async () => {
  const requests: Array<{ url: URL; init: RequestInit }> = [];
  const fetchImpl: typeof fetch = async (input, init = {}) => {
    const url = new URL(String(input));
    requests.push({ url, init });
    if (url.pathname.endsWith("/check-runs")) {
      return new Response(JSON.stringify({ html_url: "https://github.test/check/3" }), { status: 201 });
    }
    if (init.method === "GET") return new Response("[]", { status: 200 });
    return new Response(JSON.stringify({ html_url: "https://github.test/issues/1" }), { status: 201 });
  };

  const result = await publishActionFrame(repositoryEnvironment, ["--frame", "3"], fetchImpl);

  assert.equal(result.frame, 3);
  assert.equal(result.state, "OBSERVED_BY_CHECK");
  assert.equal(result.headSha, "805de8f439f2e01c0f6c52d744a8fc3af640a931");
  assert.equal(result.publication.issueAction, "created");
  assert.deepEqual(requests.map(({ init }) => init.method), ["POST", "GET", "POST"]);
  assert.ok(requests.every(({ init }) =>
    (init.headers as Record<string, string>).authorization === "Bearer actions-test-token"
  ));
  const checkBody = JSON.parse(String(requests[0].init.body));
  assert.equal(checkBody.head_sha, result.headSha);
  assert.match(checkBody.output.summary, /deterministic fixture replay/i);
  assert.match(checkBody.output.text, /"freshExecution": false/);
  const issueBody = JSON.parse(String(requests[2].init.body));
  assert.match(issueBody.body, /aftershock-dedupe:/);
  assert.match(issueBody.body, new RegExp(result.headSha));
  assert.match(issueBody.body, /deterministic fixture replay/i);
  assert.match(issueBody.body, /"savedExperimentalReceiptBound": false/);
});

test("accepts AFTERSHOCK_FRAME when no CLI frame is supplied", async () => {
  const fetchImpl: typeof fetch = async (input, init = {}) => {
    const url = new URL(String(input));
    if (url.pathname.endsWith("/check-runs")) return new Response("{}", { status: 201 });
    if (init.method === "GET") return new Response("[]", { status: 200 });
    return new Response("{}", { status: 201 });
  };
  const result = await publishActionFrame({ ...repositoryEnvironment, AFTERSHOCK_FRAME: "5" }, [], fetchImpl);
  assert.equal(result.frame, 5);
  assert.equal(result.state, "REMEDIATION_RETESTED");
  assert.equal(result.headSha, "e4d7a28fa5dc5cf027fe421576f3ddb5c0dad46c");
  assert.equal(result.publication.issueAction, "none");
});

test("fails closed before HTTP on repository mismatch, invalid frame or absent token", async () => {
  let requests = 0;
  const fetchImpl: typeof fetch = async () => {
    requests += 1;
    return new Response("{}", { status: 200 });
  };

  await assert.rejects(
    publishActionFrame({ ...repositoryEnvironment, GITHUB_REPOSITORY: "someone/else" }, ["--frame", "3"], fetchImpl),
    /Refusing publication outside/,
  );
  await assert.rejects(
    publishActionFrame(repositoryEnvironment, ["--frame", "7"], fetchImpl),
    /frame must be one integer from 1 through 6/,
  );
  await assert.rejects(
    publishActionFrame({ GITHUB_REPOSITORY: AUTHORIZED_DEMO_REPOSITORY }, ["--frame", "3"], fetchImpl),
    /GITHUB_TOKEN is required/,
  );
  await assert.rejects(
    publishActionFrame(repositoryEnvironment, ["--unknown"], fetchImpl),
    /Unsupported action publisher argument/,
  );
  assert.equal(requests, 0);
});
