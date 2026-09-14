import assert from "node:assert/strict";
import { createVerify, generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { DemoController } from "../../src/api/demo-controller.js";
import {
  createGitHubAppJwt,
  githubTokenClient,
  publishAssessment,
  type GitHubRequestClient,
} from "../../src/github/publisher.js";

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

test("token client sends route parameters, JSON body and bearer auth over HTTP", async () => {
  const requests: Array<{ url: string; init: RequestInit }> = [];
  const fetchImpl: typeof fetch = async (input, init = {}) => {
    requests.push({ url: String(input), init });
    return new Response(JSON.stringify({ html_url: "https://example.test/check/9" }), {
      status: 201,
      headers: { "content-type": "application/json" },
    });
  };
  const client = githubTokenClient("github-actions-token", fetchImpl);

  await client.request("POST /repos/{owner}/{repo}/check-runs", {
    owner: "vmihalis",
    repo: "aftershock-apm-fixture",
    head_sha: "805de8f439f2e01c0f6c52d744a8fc3af640a931",
    status: "completed",
  });

  assert.equal(requests[0].url, "https://api.github.com/repos/vmihalis/aftershock-apm-fixture/check-runs");
  assert.equal((requests[0].init.headers as Record<string, string>).authorization, "Bearer github-actions-token");
  assert.deepEqual(JSON.parse(String(requests[0].init.body)), {
    head_sha: "805de8f439f2e01c0f6c52d744a8fc3af640a931",
    status: "completed",
  });
});

test("token client encodes GET query parameters", async () => {
  let requestedUrl = "";
  const fetchImpl: typeof fetch = async (input) => {
    requestedUrl = String(input);
    return new Response("[]", { status: 200 });
  };
  const client = githubTokenClient("token", fetchImpl);

  await client.request("GET /repos/{owner}/{repo}/issues", {
    owner: "vmihalis",
    repo: "aftershock-apm-fixture",
    state: "all",
    labels: "aftershock security",
  });

  const url = new URL(requestedUrl);
  assert.equal(url.pathname, "/repos/vmihalis/aftershock-apm-fixture/issues");
  assert.equal(url.searchParams.get("state"), "all");
  assert.equal(url.searchParams.get("labels"), "aftershock security");
});

test("token client errors never include bearer token or untrusted response text", async () => {
  const secret = "do-not-print-this-token";
  const fetchImpl: typeof fetch = async () => new Response(`reflected ${secret}`, { status: 403 });
  const client = githubTokenClient(secret, fetchImpl);

  await assert.rejects(
    client.request("GET /repos/{owner}/{repo}/issues", { owner: "o", repo: "r" }),
    (error: Error) => {
      assert.match(error.message, /status 403/);
      assert.doesNotMatch(error.message, new RegExp(secret));
      assert.doesNotMatch(error.message, /reflected/);
      return true;
    },
  );
});

test("GitHub App JWT carries bounded claims and verifies with its public key", () => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const jwt = createGitHubAppJwt("12345", pem, 2_000_000_000);
  const [encodedHeader, encodedPayload, encodedSignature] = jwt.split(".");

  assert.deepEqual(JSON.parse(Buffer.from(encodedHeader, "base64url").toString()), { alg: "RS256", typ: "JWT" });
  assert.deepEqual(JSON.parse(Buffer.from(encodedPayload, "base64url").toString()), {
    iat: 1_999_999_940,
    exp: 2_000_000_540,
    iss: "12345",
  });
  const verifier = createVerify("RSA-SHA256").update(`${encodedHeader}.${encodedPayload}`).end();
  assert.equal(verifier.verify(publicKey, Buffer.from(encodedSignature, "base64url")), true);
});
