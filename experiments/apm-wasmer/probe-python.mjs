import { Wasmer } from "@wasmer/sdk/node";

import {
  pythonPackageReference,
  selectPythonPackage,
} from "./python-package.mjs";

const encoder = new TextEncoder();
const expected = encoder.encode("AFTERSHOCK_SYNTHETIC_CANARY_V1\n");
const cacheDirectory = "experiments/apm-wasmer/.cache/wasmer";
const packageInput = await selectPythonPackage(cacheDirectory);
const wasmer = new Wasmer({
  cache: { directory: cacheDirectory },
  outputBytes: 64 * 1024,
});

try {
  const pythonPackage = await wasmer.packages.load(packageInput.source);
  const sandbox = await wasmer.sandboxes.create({
    packages: [pythonPackage],
    files: {
      "probe.py": [
        "from pathlib import Path",
        "Path('/workspace/effect.bin').write_bytes(b'AFTERSHOCK_SYNTHETIC_CANARY_V1\\n')",
        "print('python-wasix-ok')",
      ].join("\n"),
    },
    network: { mode: "disabled" },
  });

  try {
    const output = await sandbox
      .command("python", ["/workspace/probe.py"])
      .run({ timeoutMs: 30_000, outputBytes: 64 * 1024, check: false });
    const observed = await sandbox.fs.readFile("effect.bin");
    const matches =
      observed.byteLength === expected.byteLength &&
      observed.every((byte, index) => byte === expected[index]);

    process.stdout.write(
      `${JSON.stringify({
        runtime: pythonPackageReference,
        packageAcquisition: packageInput.acquisition,
        network: "disabled",
        exitCode: output.exitCode,
        exitReason: output.reason,
        stdout: output.stdout.text(),
        stderr: output.stderr.text(),
        hostObservedByteLength: observed.byteLength,
        hostObservedExactMatch: matches,
      })}\n`,
    );

    if (!output.ok || !matches) process.exitCode = 1;
  } finally {
    await sandbox.close();
  }
} finally {
  await wasmer.close();
}
