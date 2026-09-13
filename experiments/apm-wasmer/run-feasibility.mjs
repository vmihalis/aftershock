import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { basename, dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { Wasmer } from "@wasmer/sdk/node";

import {
  pythonPackageReference,
  selectPythonPackage,
} from "./python-package.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const aftershockRoot = resolve(here, "../..");
const artifactPath = resolve(
  aftershockRoot,
  "artifacts/feasibility/apm-wasmer-receipt.json",
);
const cacheDirectory = resolve(here, ".cache/wasmer");
const canary = Buffer.from("AFTERSHOCK_SYNTHETIC_CANARY_V1\n", "utf8");
const effectPath =
  "project/untrusted-plugin/.apm/prompts/synthetic-canary.prompt.md";

const cases = [
  {
    id: "vulnerable-target",
    role: "target_before",
    version: "0.8.11",
    wheel: "apm_cli-0.8.11-py3-none-any.whl",
    expectedEffect: "present_exact",
  },
  {
    id: "fixed-control",
    role: "fixed_control",
    version: "0.8.12",
    wheel: "apm_cli-0.8.12-py3-none-any.whl",
    expectedEffect: "absent",
  },
  {
    id: "vulnerable-positive-control",
    role: "positive_control",
    version: "0.8.11",
    wheel: "apm_cli-0.8.11-py3-none-any.whl",
    expectedEffect: "present_exact",
  },
  {
    id: "remediated-target",
    role: "target_after",
    version: "0.8.12",
    wheel: "apm_cli-0.8.12-py3-none-any.whl",
    expectedEffect: "absent",
  },
];
const execFileAsync = promisify(execFile);

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function captured(output) {
  return {
    exitCode: output.exitCode,
    reason: output.reason,
    ok: output.ok,
    stdout: output.stdout.text(),
    stderr: output.stderr.text(),
    stdoutSha256: sha256(output.stdout.bytes),
    stderrSha256: sha256(output.stderr.bytes),
    stdoutTruncated: output.stdout.truncated,
    stderrTruncated: output.stderr.truncated,
  };
}

async function readGuestFile(sandbox, path) {
  try {
    const bytes = await sandbox.fs.readFile(path);
    return {
      present: true,
      bytes,
      byteLength: bytes.byteLength,
      sha256: sha256(bytes),
    };
  } catch (error) {
    return {
      present: false,
      bytes: null,
      byteLength: null,
      sha256: null,
      readError: error instanceof Error ? error.message : String(error),
    };
  }
}

function exactBytes(actual, expected) {
  if (actual === null || actual.byteLength !== expected.byteLength) return false;
  return actual.every((byte, index) => byte === expected[index]);
}

async function inspectRepository() {
  let headSha = null;
  try {
    const result = await execFileAsync("git", ["rev-parse", "HEAD"], {
      cwd: aftershockRoot,
      encoding: "utf8",
    });
    headSha = result.stdout.trim() || null;
  } catch {
    // An initial repository has no commit to bind. The state below says so.
  }

  const status = await execFileAsync(
    "git",
    ["status", "--porcelain=v1", "--untracked-files=all"],
    { cwd: aftershockRoot, encoding: "utf8" },
  );
  const dirty = status.stdout.length > 0;

  if (headSha === null) {
    return {
      sha: null,
      headSha: null,
      state: "uncommitted initial working tree",
      dirty: true,
    };
  }
  if (dirty) {
    return {
      sha: null,
      headSha,
      state: "dirty working tree",
      dirty: true,
    };
  }
  return {
    sha: headSha,
    headSha,
    state: "clean",
    dirty: false,
  };
}

const runnerSource = `
import json
import importlib.util
import sys
import types
from pathlib import Path

# The affected mapper imports PyYAML at module load, but the exercised copy
# path does not call it. This tiny serializer shim lets normalize_plugin_directory
# finish writing its unrelated generated apm.yml without replacing any APM code.
yaml_stub = types.ModuleType("yaml")
yaml_stub.YAMLError = Exception
yaml_stub.safe_dump = lambda data, **kwargs: "name: aftershock-untrusted-plugin\\n"
yaml_stub.safe_load = lambda value: {}
sys.modules["yaml"] = yaml_stub

# Load the exact module file from the installed public wheel without executing
# apm_cli.deps.__init__, which imports unrelated CLI dependencies such as click.
# Real package paths are retained so the fixed module's relative import of
# apm_cli.utils.path_security resolves to the wheel's own source file.
package_paths = {
    "apm_cli": "/workspace/site/apm_cli",
    "apm_cli.deps": "/workspace/site/apm_cli/deps",
    "apm_cli.utils": "/workspace/site/apm_cli/utils",
}
for package_name, package_path in package_paths.items():
    package = types.ModuleType(package_name)
    package.__package__ = package_name
    package.__path__ = [package_path]
    sys.modules[package_name] = package

module_name = "apm_cli.deps.plugin_parser"
module_path = "/workspace/site/apm_cli/deps/plugin_parser.py"
spec = importlib.util.spec_from_file_location(module_name, module_path)
if spec is None or spec.loader is None:
    raise RuntimeError("could not load public wheel plugin_parser.py")
plugin_parser = importlib.util.module_from_spec(spec)
sys.modules[module_name] = plugin_parser
spec.loader.exec_module(plugin_parser)

plugin = Path("/workspace/project/untrusted-plugin")
generated = plugin_parser.normalize_plugin_directory(plugin, plugin / "plugin.json")
print(json.dumps({
    "called": "apm_cli.deps.plugin_parser.normalize_plugin_directory",
    "generated": str(generated),
    "effect_path": "/workspace/${effectPath}",
}, sort_keys=True))
`;

const pluginManifest = JSON.stringify(
  {
    name: "aftershock-untrusted-plugin",
    commands: "../../control/synthetic-canary.md",
  },
  null,
  2,
);

const sdkPackage = JSON.parse(
  await readFile(resolve(aftershockRoot, "node_modules/@wasmer/sdk/package.json"), "utf8"),
);
const capsuleBytes = await readFile(fileURLToPath(import.meta.url));
const repository = await inspectRepository();
const packageInput = await selectPythonPackage(cacheDirectory);

const wasmer = new Wasmer({
  cache: { directory: cacheDirectory },
  outputBytes: 256 * 1024,
});
const pythonPackage = await wasmer.packages.load(packageInput.source);

async function runCase(testCase) {
  const wheelPath = resolve(here, "vendor", testCase.wheel);
  const wheelBytes = await readFile(wheelPath);
  const sandbox = await wasmer.sandboxes.create({
    packages: [pythonPackage],
    files: {
      [`wheels/${testCase.wheel}`]: wheelBytes,
      "runner.py": runnerSource,
      "control/synthetic-canary.md": canary,
      "project/untrusted-plugin/plugin.json": pluginManifest,
    },
    network: { mode: "disabled" },
  });

  try {
    const runtimeVersion = await sandbox
      .command("python", ["--version"])
      .run({ timeoutMs: 30_000, outputBytes: 64 * 1024, check: false });

    const fullDependencyInstall = await sandbox
      .command("python", [
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-index",
        "--find-links=/workspace/wheels",
        "--target=/workspace/full-site",
        `/workspace/wheels/${testCase.wheel}`,
      ])
      .run({ timeoutMs: 60_000, outputBytes: 256 * 1024, check: false });

    const narrowWheelInstall = await sandbox
      .command("python", [
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-index",
        "--no-deps",
        "--target=/workspace/site",
        `/workspace/wheels/${testCase.wheel}`,
      ])
      .run({ timeoutMs: 60_000, outputBytes: 256 * 1024, check: false });

    const fullCliImport = await sandbox
      .command(
        "python",
        ["-m", "apm_cli.cli", "--version"],
        {
          cwd: "/workspace/project",
          env: { PYTHONPATH: "/workspace/site" },
        },
      )
      .run({ timeoutMs: 30_000, outputBytes: 256 * 1024, check: false });

    const narrowExecution = await sandbox
      .command("python", ["/workspace/runner.py"], {
        cwd: "/workspace/project",
      })
      .run({ timeoutMs: 30_000, outputBytes: 256 * 1024, check: false });

    const source = await readGuestFile(
      sandbox,
      "control/synthetic-canary.md",
    );
    const effect = await readGuestFile(sandbox, effectPath);
    const sourceExact = exactBytes(source.bytes, canary);
    const effectExact = exactBytes(effect.bytes, canary);

    let hostAssessment = "inconclusive";
    if (narrowWheelInstall.ok && narrowExecution.ok && sourceExact) {
      if (testCase.expectedEffect === "present_exact" && effectExact) {
        hostAssessment = "effect_observed";
      } else if (testCase.expectedEffect === "absent" && !effect.present) {
        hostAssessment = "effect_not_observed";
      } else {
        hostAssessment = "unexpected_effect_state";
      }
    }

    return {
      id: testCase.id,
      role: testCase.role,
      package: {
        name: "apm-cli",
        version: testCase.version,
        source: `https://pypi.org/project/apm-cli/${testCase.version}/`,
        wheel: testCase.wheel,
        wheelByteLength: wheelBytes.byteLength,
        wheelSha256: sha256(wheelBytes),
      },
      expectedEffect: testCase.expectedEffect,
      networkCapability: "disabled",
      hostFilesystemMounts: [],
      runtimeVersion: captured(runtimeVersion),
      compatibilityAttempts: {
        fullOfflineDependencyInstall: captured(fullDependencyInstall),
        wheelOnlyInstall: captured(narrowWheelInstall),
        fullCliImportAfterWheelOnlyInstall: captured(fullCliImport),
      },
      narrowExecution: {
        classification:
          "public wheel, exact normalize_plugin_directory path, YAML serialization shim only",
        command: "python /workspace/runner.py",
        result: captured(narrowExecution),
      },
      hostObservation: {
        source: {
          path: "/workspace/control/synthetic-canary.md",
          present: source.present,
          byteLength: source.byteLength,
          sha256: source.sha256,
          exactSyntheticCanaryMatch: sourceExact,
        },
        effect: {
          path: `/workspace/${effectPath}`,
          present: effect.present,
          byteLength: effect.byteLength,
          sha256: effect.sha256,
          exactSyntheticCanaryMatch: effectExact,
          readError: effect.readError ?? null,
        },
        assessment: hostAssessment,
      },
    };
  } finally {
    await sandbox.close();
  }
}

try {
  const caseResults = [];
  for (const testCase of cases) caseResults.push(await runCase(testCase));

  const targetBefore = caseResults.find(
    (entry) => entry.id === "vulnerable-target",
  );
  const fixedControl = caseResults.find(
    (entry) => entry.id === "fixed-control",
  );
  const positiveControl = caseResults.find(
    (entry) => entry.id === "vulnerable-positive-control",
  );
  const targetAfter = caseResults.find(
    (entry) => entry.id === "remediated-target",
  );
  const initialGatePassed =
    targetBefore?.hostObservation.assessment === "effect_observed" &&
    fixedControl?.hostObservation.assessment === "effect_not_observed" &&
    positiveControl?.hostObservation.assessment === "effect_observed";
  const remediationGatePassed =
    targetAfter?.hostObservation.assessment === "effect_not_observed" &&
    positiveControl?.hostObservation.assessment === "effect_observed";
  const narrowGatePassed = initialGatePassed && remediationGatePassed;
  const fullPackageCompatible = caseResults.every(
    (entry) => entry.compatibilityAttempts.fullOfflineDependencyInstall.ok,
  );

  const receipt = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    advisory: {
      id: "GHSA-xhrw-5qxx-jpwr",
      cve: "CVE-2026-44641",
      url: "https://github.com/microsoft/apm/security/advisories/GHSA-xhrw-5qxx-jpwr",
    },
    repository,
    capsule: {
      path: "experiments/apm-wasmer/run-feasibility.mjs",
      sha256: sha256(capsuleBytes),
    },
    runtime: {
      sdk: `@wasmer/sdk@${sdkPackage.version}`,
      packageRequested: pythonPackageReference,
      packageAcquisition: packageInput.acquisition,
      packageArtifact:
        packageInput.artifactPath === null
          ? null
          : {
              path: relative(aftershockRoot, packageInput.artifactPath),
              byteLength: packageInput.source.byteLength,
              sha256: sha256(packageInput.source),
            },
      cache: "experiment-local cache; direct WEBC byte load when present",
      networkCapability: "disabled in every guest sandbox",
      hostFilesystemMounts: [],
    },
    syntheticCanary: {
      label: canary.toString("utf8").trim(),
      byteLength: canary.byteLength,
      sha256: sha256(canary),
      containsCredentialOrPersonalData: false,
    },
    cases: caseResults,
    gate: {
      fullPackageCompatible,
      fullPackageStatus: fullPackageCompatible
        ? "demonstrated"
        : "not_demonstrated_missing_offline_dependencies",
      narrowExactPathPassed: narrowGatePassed,
      initial: {
        assessment: initialGatePassed ? "OBSERVED" : "INCONCLUSIVE",
        passed: initialGatePassed,
        targetCaseId: "vulnerable-target",
        fixedControlCaseId: "fixed-control",
        positiveControlCaseId: "vulnerable-positive-control",
        rule: "target present AND fixed control absent AND positive control present",
      },
      remediation: {
        assessment: remediationGatePassed ? "REMEDIATED" : "INCONCLUSIVE",
        passed: remediationGatePassed,
        targetCaseId: "remediated-target",
        positiveControlCaseId: "vulnerable-positive-control",
        rule: "remediated target absent AND independent positive control present",
      },
      verdict: narrowGatePassed
        ? "pass_narrow_exact_affected_path_with_independent_controls"
        : "inconclusive_or_failed",
      trustedDecisionSource: "host-read guest filesystem bytes",
      guestOutputCanSelectVerdict: false,
    },
    limitations: [
      "The full apm CLI dependency graph was not vendored into the guest wheelhouse.",
      "The narrowed run imports the exact affected function from each public wheel; it does not execute the complete apm install command.",
      "A minimal YAML serialization shim is used only because the affected copy path does not call PyYAML.",
      "The requested python/python package version reports its own interpreter build in each case result.",
      "Target, fixed control, independent positive control, and remediated target each run in a fresh sandbox.",
    ],
  };

  await mkdir(dirname(artifactPath), { recursive: true });
  await writeFile(artifactPath, `${JSON.stringify(receipt, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify(receipt.gate)}\n`);
  if (!narrowGatePassed) process.exitCode = 1;
} finally {
  await wasmer.close();
}
