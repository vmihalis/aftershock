import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  APM_PATH_ESCAPE_CAPSULE,
  SYNTHETIC_CANARY_TEXT,
  canonicalJson,
  digestThreatCapsule,
  parseThreatCapsule,
  sha256Text,
} from "../../src/core/index.js";

const capsuleUrl = new URL("../../capsules/GHSA-xhrw-5qxx-jpwr/r1.json", import.meta.url);
const canaryUrl = new URL("../../fixtures/core/synthetic-canary.md", import.meta.url);

test("checked-in capsule and TypeScript capsule have one canonical digest", async () => {
  const fromDisk = parseThreatCapsule(JSON.parse(await readFile(capsuleUrl, "utf8")));
  assert.equal(digestThreatCapsule(fromDisk).digest, digestThreatCapsule(APM_PATH_ESCAPE_CAPSULE).digest);
  assert.equal(canonicalJson(fromDisk), canonicalJson(APM_PATH_ESCAPE_CAPSULE));
  assert.equal(Object.isFrozen(fromDisk), true);
  assert.equal(Object.isFrozen(fromDisk.controls.positive), true);
});

test("capsule effect hash binds the visibly labelled synthetic canary bytes", async () => {
  const fileBytes = await readFile(canaryUrl, "utf8");
  assert.equal(fileBytes, SYNTHETIC_CANARY_TEXT);
  assert.equal(sha256Text(fileBytes), APM_PATH_ESCAPE_CAPSULE.effect.expectedSha256);
  assert.match(fileBytes, /SYNTHETIC CANARY/u);
  assert.match(APM_PATH_ESCAPE_CAPSULE.effect.notice, /no real secret accessed/u);
});

test("canonical digest is independent of object key insertion order and sensitive to content", () => {
  const first = { z: 1, nested: { b: true, a: "value" }, list: [3, 2, 1] };
  const reordered = { list: [3, 2, 1], nested: { a: "value", b: true }, z: 1 };
  const changed = { list: [3, 2, 1], nested: { a: "changed", b: true }, z: 1 };
  assert.equal(sha256Text(canonicalJson(first)), sha256Text(canonicalJson(reordered)));
  assert.notEqual(sha256Text(canonicalJson(first)), sha256Text(canonicalJson(changed)));
});

test("capsule parser rejects unknown fields and unsafe effect paths", () => {
  const base = JSON.parse(JSON.stringify(APM_PATH_ESCAPE_CAPSULE)) as Record<string, unknown>;
  assert.throws(() => parseThreatCapsule({ ...base, guestVerdict: "pass" }), /contain exactly/u);

  const unsafe = JSON.parse(JSON.stringify(APM_PATH_ESCAPE_CAPSULE)) as {
    effect: Record<string, unknown>;
  };
  unsafe.effect.path = "../outside.md";
  assert.throws(() => parseThreatCapsule(unsafe), /normalized repository-relative path/u);
});

test("canonical JSON rejects values whose digest would be ambiguous", () => {
  assert.throws(() => canonicalJson({ missing: undefined }), /does not allow undefined/u);
  assert.throws(() => canonicalJson([, "sparse"]), /sparse arrays/u);
  assert.throws(() => canonicalJson({ invalid: Number.NaN }), /non-finite/u);
});
