import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const aftershockRoot = resolve(here, "../..");
const args = process.argv.slice(2);
const bundledOnly = args.includes("--bundled-only");
const receiptArgument = args.indexOf("--receipt");
const receiptPath = receiptArgument === -1
  ? resolve(aftershockRoot, "artifacts/feasibility/apm-wasmer-receipt.json")
  : resolve(args[receiptArgument + 1] ?? "");
const allowedArgs = args.filter((_, index) => index !== receiptArgument && index !== receiptArgument + 1);
if ((receiptArgument !== -1 && !args[receiptArgument + 1]) ||
    (receiptArgument === -1 ? args : allowedArgs).some((arg) => arg !== "--bundled-only")) {
  throw new Error("Usage: verify-receipt.mjs [--bundled-only] [--receipt path]");
}
const receipt = JSON.parse(
  await readFile(receiptPath, "utf8"),
);
const expectedCanary = Buffer.from("AFTERSHOCK_SYNTHETIC_CANARY_V1\n", "utf8");

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

assert(receipt.advisory.id === "GHSA-xhrw-5qxx-jpwr", "wrong advisory");
assert(receipt.cases.length === 4, "expected exactly four cases");
assert(receipt.schemaVersion === 1, "unsupported receipt schema");
const expectedRoles = {
  "vulnerable-target": "target_before",
  "fixed-control": "fixed_control",
  "vulnerable-positive-control": "positive_control",
  "remediated-target": "target_after",
};
const admittedWheels = {
  "0.8.11": {
    file: "apm_cli-0.8.11-py3-none-any.whl",
    sha256: "268a3832035d15568d9a395f40ac36fc1e66e98f116e2ba961662420a142b723",
  },
  "0.8.12": {
    file: "apm_cli-0.8.12-py3-none-any.whl",
    sha256: "d252a1364b52cf14dde7ca3a25dbd3af949e0d573d3f163fa3ac76757aec5961",
  },
};
assert(new Set(receipt.cases.map((entry) => entry.id)).size === 4, "duplicate case ID");
assert(
  receipt.syntheticCanary.containsCredentialOrPersonalData === false,
  "canary data classification changed",
);
assert(receipt.syntheticCanary.byteLength === expectedCanary.byteLength, "wrong canary length");
assert(receipt.syntheticCanary.sha256 === sha256(expectedCanary), "wrong canary digest");

const capsule = await readFile(resolve(aftershockRoot, receipt.capsule.path));
assert(sha256(capsule) === receipt.capsule.sha256, "capsule digest mismatch");
const runtimeArtifact = receipt.runtime.packageArtifact;
assert(runtimeArtifact && /^[a-f0-9]{64}$/.test(runtimeArtifact.sha256), "invalid runtime digest metadata");
assert(Number.isSafeInteger(runtimeArtifact.byteLength) && runtimeArtifact.byteLength > 0, "invalid runtime size metadata");
if (!bundledOnly) {
  const runtimePackage = await readFile(
    resolve(aftershockRoot, receipt.runtime.packageArtifact.path),
  );
  assert(
    runtimePackage.byteLength === receipt.runtime.packageArtifact.byteLength,
    "runtime package size mismatch",
  );
  assert(
    sha256(runtimePackage) === receipt.runtime.packageArtifact.sha256,
    "runtime package digest mismatch",
  );
}

for (const testCase of receipt.cases) {
  assert(Object.hasOwn(expectedRoles, testCase.id) && testCase.role === expectedRoles[testCase.id], "unexpected case ID or role");
  assert(testCase.package.name === "apm-cli", "wrong package identity");
  const admittedWheel = admittedWheels[testCase.package.version];
  assert(admittedWheel && testCase.package.wheel === admittedWheel.file &&
    testCase.package.wheelSha256 === admittedWheel.sha256, "package version does not match its admitted wheel identity");
  const wheel = await readFile(resolve(here, "vendor", testCase.package.wheel));
  assert(wheel.byteLength === testCase.package.wheelByteLength, "wheel size mismatch");
  assert(sha256(wheel) === testCase.package.wheelSha256, "wheel digest mismatch");
  assert(testCase.networkCapability === "disabled", "guest network was enabled");
  assert(testCase.hostFilesystemMounts.length === 0, "host filesystem was mounted");
  assert(testCase.runtimeVersion.ok === true, "Wasmer Python did not run");
  assert(
    testCase.compatibilityAttempts.fullOfflineDependencyInstall.ok === false,
    "receipt no longer matches the recorded full dependency limitation",
  );
  assert(
    testCase.compatibilityAttempts.wheelOnlyInstall.ok === true,
    "wheel-only install failed",
  );
  assert(testCase.narrowExecution.result.ok === true, "narrow execution failed");
  for (const result of [testCase.runtimeVersion, testCase.narrowExecution.result]) {
    assert(result.exitCode === 0 && result.reason === "exited", "incomplete process result");
    assert(result.stdoutTruncated === false && result.stderrTruncated === false, "truncated recorded output");
    assert(sha256(Buffer.from(result.stdout, "utf8")) === result.stdoutSha256, "recorded stdout digest mismatch");
    assert(sha256(Buffer.from(result.stderr, "utf8")) === result.stderrSha256, "recorded stderr digest mismatch");
  }
  const source = testCase.hostObservation.source;
  const effect = testCase.hostObservation.effect;
  assert(source.present === true && source.byteLength === expectedCanary.byteLength, "invalid source capture");
  assert(effect.path === "/workspace/project/untrusted-plugin/.apm/prompts/synthetic-canary.prompt.md", "wrong recorded effect path");
  if (effect.present) {
    assert(effect.sha256 === sha256(expectedCanary) && effect.byteLength === expectedCanary.byteLength, "recorded effect bytes mismatch");
    assert(effect.exactSyntheticCanaryMatch === true && effect.readError === null, "inconsistent present effect");
  } else {
    assert(effect.sha256 === null && effect.byteLength === null && effect.exactSyntheticCanaryMatch === false, "inconsistent absent effect");
    const missingFileError = `filesystem operation \`open\` failed for \`${effect.path}\`: entry not found`;
    assert(effect.readError === missingFileError, "absence requires a recorded missing-file result, not a capture failure");
  }
  assert(
    testCase.hostObservation.source.exactSyntheticCanaryMatch === true,
    "source canary mismatch",
  );
  assert(
    testCase.hostObservation.source.sha256 === sha256(expectedCanary),
    "source canary digest mismatch",
  );
}

const targetBefore = receipt.cases.find(
  (testCase) => testCase.id === "vulnerable-target",
);
const fixed = receipt.cases.find((testCase) => testCase.id === "fixed-control");
const positive = receipt.cases.find(
  (testCase) => testCase.id === "vulnerable-positive-control",
);
const targetAfter = receipt.cases.find(
  (testCase) => testCase.id === "remediated-target",
);
assert(targetBefore?.package.version === "0.8.11", "wrong target version");
assert(fixed?.package.version === "0.8.12", "wrong fixed version");
assert(positive?.package.version === "0.8.11", "wrong positive control version");
assert(targetAfter?.package.version === "0.8.12", "wrong remediated version");
assert(targetBefore.hostObservation.assessment === "effect_observed", "initial target failed");
assert(targetBefore.hostObservation.effect.present === true, "initial target effect absent");
assert(
  targetBefore.hostObservation.effect.exactSyntheticCanaryMatch === true,
  "initial target effect bytes mismatch",
);
assert(
  targetBefore.hostObservation.effect.sha256 === sha256(expectedCanary),
  "initial target effect digest mismatch",
);
assert(fixed.hostObservation.assessment === "effect_not_observed", "fixed control failed");
assert(fixed.hostObservation.effect.present === false, "fixed control created effect");
assert(
  fixed.narrowExecution.result.stderr.includes("path escapes plugin root"),
  "fixed control did not report the escape rejection",
);
assert(positive.hostObservation.assessment === "effect_observed", "positive control failed");
assert(positive.hostObservation.effect.present === true, "positive control effect absent");
assert(
  positive.hostObservation.effect.exactSyntheticCanaryMatch === true,
  "positive control effect bytes mismatch",
);
assert(
  targetAfter.hostObservation.assessment === "effect_not_observed",
  "remediated target failed",
);
assert(targetAfter.hostObservation.effect.present === false, "remediated target created effect");
assert(receipt.gate.fullPackageCompatible === false, "full package claim changed");
assert(receipt.gate.narrowExactPathPassed === true, "narrow gate did not pass");
assert(receipt.gate.initial.assessment === "OBSERVED", "initial gate is not OBSERVED");
assert(receipt.gate.initial.passed === true, "initial control gate failed");
assert(receipt.gate.remediation.assessment === "REMEDIATED", "remediation gate failed");
assert(receipt.gate.remediation.passed === true, "remediation controls failed");
assert(
  receipt.gate.verdict ===
    "pass_narrow_exact_affected_path_with_independent_controls",
  "unexpected verdict",
);
assert(receipt.gate.guestOutputCanSelectVerdict === false, "guest can select verdict");
assert(
  receipt.repository.sha === null || receipt.repository.dirty === false,
  "dirty repository must not claim a bound assessment SHA",
);
assert(
  receipt.repository.sha === null || receipt.repository.sha === receipt.repository.headSha,
  "bound repository SHA does not match HEAD",
);

process.stdout.write(
  `${JSON.stringify({
    status: bundledOnly ? "bundled-receipt-consistent" : "receipt-verification-ok",
    scope: "recorded-claims-and-artifact-integrity",
    executionPerformed: false,
    independentlyAuthenticated: false,
    harnessSha256: receipt.capsule.sha256,
    threatCapsuleBinding: "not-established; receipt.capsule identifies the experiment harness",
    runtimeArtifact: {
      status: bundledOnly ? "NOT_CHECKED" : "HASH_VERIFIED",
      reason: bundledOnly ? "runtime cache is not included in the repository" : "local bytes match recorded metadata",
      declaredSha256: runtimeArtifact.sha256,
    },
    runtimeRequested: receipt.runtime.packageRequested,
    recordedRuntimeVersion: targetBefore.runtimeVersion.stdout.trim(),
    repository: receipt.repository,
    targetBefore: targetBefore.hostObservation.assessment,
    fixedEffect: fixed.hostObservation.assessment,
    positiveControl: positive.hostObservation.assessment,
    targetAfter: targetAfter.hostObservation.assessment,
    initialAssessment: receipt.gate.initial.assessment,
    remediationAssessment: receipt.gate.remediation.assessment,
    fullPackageCompatible: receipt.gate.fullPackageCompatible,
    narrowExactPathPassed: receipt.gate.narrowExactPathPassed,
  })}\n`,
);
