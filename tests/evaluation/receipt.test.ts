import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const verifier = join(root, "experiments/apm-wasmer/verify-receipt.mjs");
const original = JSON.parse(readFileSync(join(root, "artifacts/feasibility/apm-wasmer-receipt.json"), "utf8"));

function checkReceipt(receipt: typeof original) {
  const directory = mkdtempSync(join(tmpdir(), "aftershock-receipt-test-"));
  const path = join(directory, "receipt.json");
  try {
    writeFileSync(path, JSON.stringify(receipt));
    return spawnSync(process.execPath, [verifier, "--bundled-only", "--receipt", path], {
      cwd: directory, encoding: "utf8", timeout: 20_000,
    });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test("bundled verification works without the local runtime cache and limits its claim", () => {
  const result = checkReceipt(original);
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.status, "bundled-receipt-consistent");
  assert.equal(report.runtimeArtifact.status, "NOT_CHECKED");
  assert.equal(report.executionPerformed, false);
  assert.equal(report.independentlyAuthenticated, false);
  assert.equal(report.harnessSha256, original.capsule.sha256);
  assert.match(report.threatCapsuleBinding, /not-established/);
});

test("recorded output edits and false positive-control hashes cannot pass integrity checks", () => {
  const output = structuredClone(original);
  output.cases[0].narrowExecution.result.stdout += "altered";
  const changedOutput = checkReceipt(output);
  assert.notEqual(changedOutput.status, 0);
  assert.match(changedOutput.stderr, /stdout digest mismatch/);

  const positive = structuredClone(original);
  positive.cases[2].hostObservation.effect.sha256 = "0".repeat(64);
  const changedDigest = checkReceipt(positive);
  assert.notEqual(changedDigest.status, 0);
  assert.match(changedDigest.stderr, /effect bytes mismatch/);
});

test("duplicate roles and truncated captures do not become verified records", () => {
  const duplicate = structuredClone(original);
  duplicate.cases[2] = duplicate.cases[0];
  const duplicateResult = checkReceipt(duplicate);
  assert.notEqual(duplicateResult.status, 0);
  assert.match(duplicateResult.stderr, /duplicate case ID/);

  const truncated = structuredClone(original);
  truncated.cases[0].narrowExecution.result.stdoutTruncated = true;
  const truncatedResult = checkReceipt(truncated);
  assert.notEqual(truncatedResult.status, 0);
  assert.match(truncatedResult.stderr, /truncated recorded output/);
});

test("missing runtime bytes still fail strict receipt verification", () => {
  const directory = mkdtempSync(join(tmpdir(), "aftershock-runtime-test-"));
  try {
    const receipt = structuredClone(original);
    receipt.runtime.packageArtifact.path = join(directory, "absent-runtime.bin");
    const path = join(directory, "receipt.json");
    writeFileSync(path, JSON.stringify(receipt));
    const result = spawnSync(process.execPath, [verifier, "--receipt", path], {
      encoding: "utf8", timeout: 20_000,
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /ENOENT/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("a permission failure cannot be accepted as evidence of absence", () => {
  const denied = structuredClone(original);
  denied.cases[3].hostObservation.effect.readError = "permission denied";
  const result = checkReceipt(denied);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /absence requires a recorded missing-file result/);
});

test("a package version label cannot be paired with the other admitted wheel", () => {
  const mismatched = structuredClone(original);
  const otherPackage = mismatched.cases[1].package;
  Object.assign(mismatched.cases[0].package, {
    wheel: otherPackage.wheel,
    wheelSha256: otherPackage.wheelSha256,
    wheelByteLength: otherPackage.wheelByteLength,
  });
  const result = checkReceipt(mismatched);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /package version does not match its admitted wheel identity/);
});
