import { createHmac, timingSafeEqual } from "node:crypto";

export type RepositoryTrigger = {
  kind: "repository_changed";
  repositoryFullName: string;
  headSha: string;
  ref: string;
};

export type ScopedPushTrigger =
  | Readonly<{ status: "accepted"; trigger: RepositoryTrigger }>
  | Readonly<{
      status: "ignored";
      reason: "repository_not_monitored" | "ref_not_monitored" | "ref_deleted";
    }>
  | Readonly<{ status: "invalid"; reason: "malformed_push_payload" }>;

export function verifyWebhookSignature(rawBody: Buffer, signature: string | undefined, secret: string): boolean {
  if (!signature?.startsWith("sha256=") || secret.length === 0) return false;
  const expected = Buffer.from(`sha256=${createHmac("sha256", secret).update(rawBody).digest("hex")}`);
  const received = Buffer.from(signature);
  return received.length === expected.length && timingSafeEqual(received, expected);
}

export function triggerFromPush(payload: unknown): RepositoryTrigger | null {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return null;
  const value = payload as Record<string, unknown>;
  const repository = value.repository;
  if (!repository || typeof repository !== "object" || Array.isArray(repository)) return null;
  const fullName = (repository as Record<string, unknown>).full_name;
  if (
    typeof value.after !== "string" ||
    typeof value.ref !== "string" ||
    typeof fullName !== "string" ||
    !/^[^/\s]+\/[^/\s]+$/.test(fullName)
  ) {
    return null;
  }
  if (!/^[0-9a-f]{40}$/i.test(value.after)) return null;
  return {
    kind: "repository_changed",
    repositoryFullName: fullName,
    headSha: value.after.toLowerCase(),
    ref: value.ref,
  };
}

export function scopePushTrigger(
  payload: unknown,
  expectedRepositoryFullName: string,
  expectedRef: string,
): ScopedPushTrigger {
  const trigger = triggerFromPush(payload);
  if (!trigger) return { status: "invalid", reason: "malformed_push_payload" };
  if (trigger.repositoryFullName !== expectedRepositoryFullName) {
    return { status: "ignored", reason: "repository_not_monitored" };
  }
  if (trigger.ref !== expectedRef) {
    return { status: "ignored", reason: "ref_not_monitored" };
  }
  if (/^0{40}$/.test(trigger.headSha)) {
    return { status: "ignored", reason: "ref_deleted" };
  }
  return { status: "accepted", trigger };
}
