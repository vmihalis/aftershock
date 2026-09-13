import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const aftershockRoot = resolve(here, "../..");
const receipt = JSON.parse(
  await readFile(
    resolve(aftershockRoot, "artifacts/feasibility/apm-wasmer-receipt.json"),
    "utf8",
  ),
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
assert(
  receipt.syntheticCanary.containsCredentialOrPersonalData === false,
  "canary data classification changed",
);
assert(receipt.syntheticCanary.byteLength === expectedCanary.byteLength, "wrong canary length");
assert(receipt.syntheticCanary.sha256 === sha256(expectedCanary), "wrong canary digest");

const capsule = await readFile(resolve(aftershockRoot, receipt.capsule.path));
assert(sha256(capsule) === receipt.capsule.sha256, "capsule digest mismatch");
if (receipt.runtime.packageArtifact !== null) {
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
    status: "receipt-verification-ok",
    capsuleSha256: receipt.capsule.sha256,
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
