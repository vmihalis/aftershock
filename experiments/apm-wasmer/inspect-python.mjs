import { Wasmer } from "@wasmer/sdk/node";

import { selectPythonPackage } from "./python-package.mjs";

const cacheDirectory = "experiments/apm-wasmer/.cache/wasmer";
const packageInput = await selectPythonPackage(cacheDirectory);
const wasmer = new Wasmer({
  cache: { directory: cacheDirectory },
  outputBytes: 256 * 1024,
});

try {
  const pythonPackage = await wasmer.packages.load(packageInput.source);
  const sandbox = await wasmer.sandboxes.create({
    packages: [pythonPackage],
    network: { mode: "disabled" },
  });
  try {
    const output = await sandbox
      .command("python", [
        "-c",
        [
          "import importlib.util, json, sys",
          "names=['pip','yaml','click','requests','frontmatter','llm','toml','rich','rich_click','watchdog','git']",
          "print(json.dumps({'version':sys.version,'modules':{n:bool(importlib.util.find_spec(n)) for n in names}}, sort_keys=True))",
        ].join(";"),
      ])
      .run({ timeoutMs: 30_000, outputBytes: 256 * 1024, check: false });
    process.stdout.write(output.stdout.text());
    process.stderr.write(output.stderr.text());
    if (!output.ok) process.exitCode = 1;
  } finally {
    await sandbox.close();
  }
} finally {
  await wasmer.close();
}
