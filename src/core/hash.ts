import { createHash } from "node:crypto";
import { asSha256Digest, type Sha256Digest } from "./types.js";

function serializeCanonical(value: unknown, ancestors: WeakSet<object>): string {
  if (value === null) return "null";

  if (typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Canonical JSON does not allow non-finite numbers");
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    if (ancestors.has(value)) throw new TypeError("Canonical JSON does not allow cycles");
    ancestors.add(value);
    const items: string[] = [];
    for (let index = 0; index < value.length; index += 1) {
      if (!(index in value)) throw new TypeError("Canonical JSON does not allow sparse arrays");
      items.push(serializeCanonical(value[index], ancestors));
    }
    ancestors.delete(value);
    return `[${items.join(",")}]`;
  }

  if (typeof value === "object") {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError("Canonical JSON accepts only plain objects");
    }
    if (ancestors.has(value)) throw new TypeError("Canonical JSON does not allow cycles");
    ancestors.add(value);
    const record = value as Record<string, unknown>;
    const entries = Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${serializeCanonical(record[key], ancestors)}`);
    ancestors.delete(value);
    return `{${entries.join(",")}}`;
  }

  throw new TypeError(`Canonical JSON does not allow ${typeof value}`);
}

export function canonicalJson(value: unknown): string {
  return serializeCanonical(value, new WeakSet<object>());
}

export function sha256Bytes(value: Uint8Array): Sha256Digest {
  return asSha256Digest(`sha256:${createHash("sha256").update(value).digest("hex")}`);
}

export function sha256Text(value: string): Sha256Digest {
  return sha256Bytes(Buffer.from(value, "utf8"));
}

export function sha256CanonicalJson(value: unknown): Sha256Digest {
  return sha256Text(canonicalJson(value));
}

export function deepFreeze<T>(value: T): Readonly<T> {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}
