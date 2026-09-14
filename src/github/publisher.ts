import { createSign } from "node:crypto";
import type { AftershockView } from "../api/view.js";
import { projectCheck, projectIssue } from "./projections.js";

export type GitHubRequestClient = {
  request(route: string, parameters: Record<string, unknown>): Promise<{ data: unknown }>;
};

type FetchLike = typeof fetch;

export type PublishedAssessment = Readonly<{
  checkUrl: string | null;
  issueUrl: string | null;
  issueAction: "created" | "updated" | "closed" | "none";
}>;

type ExistingIssue = {
  number: number;
  state: "open" | "closed";
  body?: string | null;
  html_url?: string;
  pull_request?: unknown;
};

function repositoryParts(fullName: string): { owner: string; repo: string } {
  const [owner, repo, ...extra] = fullName.split("/");
  if (!owner || !repo || extra.length > 0) {
    throw new TypeError(`Expected owner/repository, received ${fullName}`);
  }
  return { owner, repo };
}

function listData(value: unknown): ExistingIssue[] {
  return Array.isArray(value) ? value as ExistingIssue[] : [];
}

function objectData(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" ? value as Record<string, unknown> : {};
}

export async function publishAssessment(
  client: GitHubRequestClient,
  view: AftershockView,
): Promise<PublishedAssessment> {
  const { owner, repo } = repositoryParts(view.repository.fullName);
  const check = projectCheck(view);
  const issue = projectIssue(view);

  const checkResponse = await client.request("POST /repos/{owner}/{repo}/check-runs", {
    owner,
    repo,
    ...check,
  });
  const checkUrl = objectData(checkResponse.data).html_url;

  const listed = await client.request("GET /repos/{owner}/{repo}/issues", {
    owner,
    repo,
    state: "all",
    labels: "aftershock",
    per_page: 100,
  });
  const marker = `<!-- aftershock-dedupe:${issue.dedupeKey} -->`;
  const existing = listData(listed.data).find((candidate) =>
    candidate.pull_request === undefined && candidate.body?.includes(marker),
  );

  if (!issue.shouldBeOpen && !existing) {
    return {
      checkUrl: typeof checkUrl === "string" ? checkUrl : null,
      issueUrl: null,
      issueAction: "none",
    };
  }

  if (existing) {
    const closing = !issue.shouldBeOpen;
    const response = await client.request("PATCH /repos/{owner}/{repo}/issues/{issue_number}", {
      owner,
      repo,
      issue_number: existing.number,
      title: issue.title,
      body: issue.body,
      labels: issue.labels,
      state: closing ? "closed" : "open",
    });
    const url = objectData(response.data).html_url ?? existing.html_url;
    return {
      checkUrl: typeof checkUrl === "string" ? checkUrl : null,
      issueUrl: typeof url === "string" ? url : null,
      issueAction: closing ? "closed" : "updated",
    };
  }

  const response = await client.request("POST /repos/{owner}/{repo}/issues", {
    owner,
    repo,
    title: issue.title,
    body: issue.body,
    labels: issue.labels,
  });
  const url = objectData(response.data).html_url;
  return {
    checkUrl: typeof checkUrl === "string" ? checkUrl : null,
    issueUrl: typeof url === "string" ? url : null,
    issueAction: "created",
  };
}

function appCredentials(environment: NodeJS.ProcessEnv): { appId: string; privateKey: string } {
  const appId = environment.GITHUB_APP_ID;
  const privateKey = environment.GITHUB_PRIVATE_KEY?.replaceAll("\\n", "\n");
  if (!appId || !privateKey) {
    throw new Error("GITHUB_APP_ID and GITHUB_PRIVATE_KEY are required for live publication");
  }
  return { appId, privateKey };
}

function base64Url(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

export function createGitHubAppJwt(
  appId: string,
  privateKey: string,
  nowSeconds = Math.floor(Date.now() / 1000),
): string {
  const header = base64Url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = base64Url(JSON.stringify({
    iat: nowSeconds - 60,
    exp: nowSeconds + 540,
    iss: appId,
  }));
  const signingInput = `${header}.${payload}`;
  const signature = createSign("RSA-SHA256").update(signingInput).end().sign(privateKey, "base64url");
  return `${signingInput}.${signature}`;
}

export function githubTokenClient(
  token: string,
  fetchImpl: FetchLike = fetch,
): GitHubRequestClient {
  if (token.trim().length === 0) {
    throw new TypeError("A non-empty GitHub token is required");
  }
  return {
    async request(route, parameters) {
      const match = /^(GET|POST|PATCH) (\/.+)$/.exec(route);
      if (!match) throw new TypeError(`Unsupported GitHub route: ${route}`);
      const [, method, template] = match;
      const consumed = new Set<string>();
      const path = template.replaceAll(/\{([^}]+)\}/g, (_whole, key: string) => {
        const value = parameters[key];
        if (value === undefined || value === null) throw new TypeError(`Missing GitHub route parameter: ${key}`);
        consumed.add(key);
        return encodeURIComponent(String(value));
      });
      const remaining = Object.fromEntries(Object.entries(parameters).filter(([key]) => !consumed.has(key)));
      const url = new URL(`https://api.github.com${path}`);
      const init: RequestInit = {
        method,
        headers: {
          accept: "application/vnd.github+json",
          authorization: `Bearer ${token}`,
          "x-github-api-version": "2022-11-28",
        },
      };
      if (method === "GET") {
        for (const [key, value] of Object.entries(remaining)) {
          if (value !== undefined && value !== null) url.searchParams.set(key, String(value));
        }
      } else {
        (init.headers as Record<string, string>)["content-type"] = "application/json";
        init.body = JSON.stringify(remaining);
      }
      const response = await fetchImpl(url, init);
      const text = await response.text();
      if (!response.ok) {
        // GitHub error bodies are not included because they are outside our trust
        // boundary and can reflect request data. In particular, never put the
        // bearer token or response text into an Actions log.
        throw new Error(`GitHub API ${method} ${path} failed with status ${response.status}`);
      }
      return { data: text ? JSON.parse(text) as unknown : null };
    },
  };
}

export async function installationClientFromEnvironment(
  installationId: number,
  environment: NodeJS.ProcessEnv = process.env,
  fetchImpl: FetchLike = fetch,
): Promise<GitHubRequestClient> {
  const { appId, privateKey } = appCredentials(environment);
  const jwt = createGitHubAppJwt(appId, privateKey);
  const response = await fetchImpl(`https://api.github.com/app/installations/${installationId}/access_tokens`, {
    method: "POST",
    headers: {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${jwt}`,
      "x-github-api-version": "2022-11-28",
    },
  });
  const text = await response.text();
  if (!response.ok) throw new Error(`GitHub installation authentication failed with status ${response.status}`);
  const token = objectData(text ? JSON.parse(text) as unknown : null).token;
  if (typeof token !== "string" || token.length === 0) throw new Error("GitHub installation response omitted its token");
  return githubTokenClient(token, fetchImpl);
}

export async function publishWithInstallation(
  installationId: number,
  view: AftershockView,
  environment: NodeJS.ProcessEnv = process.env,
): Promise<PublishedAssessment> {
  if (!Number.isSafeInteger(installationId) || installationId <= 0) {
    throw new TypeError("installationId must be a positive integer");
  }
  const client = await installationClientFromEnvironment(installationId, environment);
  return publishAssessment(client, view);
}
