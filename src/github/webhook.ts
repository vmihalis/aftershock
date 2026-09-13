import { createHmac, timingSafeEqual } from "node:crypto";

export type RepositoryTrigger = {
  kind: "repository_changed";
  repositoryFullName: string;
  headSha: string;
  ref: string;
};

export function verifyWebhookSignature(rawBody: Buffer, signature: string | undefined, secret: string): boolean {
  if (!signature?.startsWith("sha256=") || secret.length === 0) return false;
  const expected = Buffer.from(`sha256=${createHmac("sha256", secret).update(rawBody).digest("hex")}`);
  const received = Buffer.from(signature);
  return received.length === expected.length && timingSafeEqual(received, expected);
}

export function triggerFromPush(payload: unknown): RepositoryTrigger | null {
  if (!payload || typeof payload !== "object") return null;
  const value = payload as Record<string, unknown>;
  const repository = value.repository as Record<string, unknown> | undefined;
  if (typeof value.after !== "string" || typeof value.ref !== "string" || typeof repository?.full_name !== "string") {
    return null;
  }
  if (!/^[0-9a-f]{40}$/i.test(value.after)) return null;
  return {
    kind: "repository_changed",
    repositoryFullName: repository.full_name,
    headSha: value.after,
    ref: value.ref,
  };
}
