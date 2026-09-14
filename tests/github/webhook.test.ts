import assert from "node:assert/strict";
import test from "node:test";
import { scopePushTrigger } from "../../src/github/webhook.js";

const repositoryFullName = "vmihalis/aftershock-apm-fixture";
const monitoredRef = "refs/heads/main";
const headSha = "a".repeat(40);

function pushPayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    after: headSha,
    ref: monitoredRef,
    repository: { full_name: repositoryFullName },
    ...overrides,
  };
}

test("accepts only the configured repository, branch, and nonzero head", () => {
  assert.deepEqual(scopePushTrigger(pushPayload(), repositoryFullName, monitoredRef), {
    status: "accepted",
    trigger: {
      kind: "repository_changed",
      repositoryFullName,
      headSha,
      ref: monitoredRef,
    },
  });
});

test("ignores signed pushes outside the monitored repository scope", () => {
  assert.deepEqual(
    scopePushTrigger(
      pushPayload({ repository: { full_name: "vmihalis/unrelated-repository" } }),
      repositoryFullName,
      monitoredRef,
    ),
    { status: "ignored", reason: "repository_not_monitored" },
  );
  assert.deepEqual(
    scopePushTrigger(pushPayload({ ref: "refs/heads/feature" }), repositoryFullName, monitoredRef),
    { status: "ignored", reason: "ref_not_monitored" },
  );
  assert.deepEqual(
    scopePushTrigger(pushPayload({ after: "0".repeat(40) }), repositoryFullName, monitoredRef),
    { status: "ignored", reason: "ref_deleted" },
  );
});

test("rejects malformed push payloads before scope evaluation", () => {
  const malformedPayloads: unknown[] = [
    null,
    [],
    {},
    pushPayload({ after: "short" }),
    pushPayload({ ref: 7 }),
    pushPayload({ repository: null }),
    pushPayload({ repository: { full_name: "missing-slash" } }),
  ];

  for (const payload of malformedPayloads) {
    assert.deepEqual(scopePushTrigger(payload, repositoryFullName, monitoredRef), {
      status: "invalid",
      reason: "malformed_push_payload",
    });
  }
});
