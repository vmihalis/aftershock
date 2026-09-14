import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
if (args.some((arg) => arg !== "--json")) {
  process.stderr.write("Usage: npm run evaluate -- [--json]\n");
  process.exit(2);
}
const json = args.includes("--json");
if (Number(process.versions.node.split(".")[0]) < 24) {
  process.stderr.write("Evaluation requires Node.js 24 or newer.\n");
  process.exit(2);
}
const git = spawnSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" });
const status = spawnSync("git", ["status", "--porcelain"], { cwd: root, encoding: "utf8" });
const report = {
  schemaVersion: 1,
  kind: "aftershock-local-evaluation",
  generatedAt: new Date().toISOString(),
  revision: git.status === 0 ? git.stdout.trim() : null,
  workingTreeDirty: status.status === 0 ? status.stdout.trim().length > 0 : null,
  nodeVersion: process.version,
  scope: "unit-tests-types-build-and-bundled-record-integrity",
  runtimeExecutionPerformed: false,
  githubPublicationPerformed: false,
  checks: [],
  passed: false,
};

// All entries are fixed local npm scripts. No package installation, server startup,
// target check, guest execution, credential lookup, or GitHub publication occurs.
for (const script of ["verify:bundled", "test", "lint", "build"]) {
  const startedAt = Date.now();
  const npmCli = process.env.npm_execpath;
  const child = npmCli
    ? spawnSync(process.execPath, [npmCli, "run", "--silent", script], {
      cwd: root, encoding: "utf8", timeout: 120_000, maxBuffer: 4 * 1024 * 1024,
    })
    : spawnSync("npm", ["run", "--silent", script], {
      cwd: root, encoding: "utf8", timeout: 120_000, maxBuffer: 4 * 1024 * 1024,
    });
  const check = {
    name: script,
    passed: child.status === 0 && !child.error,
    exitCode: child.status,
    signal: child.signal,
    durationMs: Date.now() - startedAt,
    stdout: child.stdout ?? "",
    stderr: child.stderr ?? "",
    error: child.error?.code ?? null,
  };
  report.checks.push(check);
  if (!json) {
    process.stdout.write(`${check.passed ? "PASS" : "FAIL"} ${script} (${check.durationMs} ms)\n`);
    if (!check.passed) process.stderr.write(check.stdout + check.stderr + (check.error ?? ""));
  }
}
report.passed = report.checks.every((check) => check.passed);
if (json) process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
else {
  process.stdout.write(`Revision: ${report.revision ?? "unavailable (source archive)"}; dirty: ${report.workingTreeDirty ?? "unknown"}\n`);
  process.stdout.write("Recorded evidence only. No fresh Wasmer run or external publication.\n");
  process.stdout.write("Runtime cache hash is NOT_CHECKED; see EVALUATION.md for evidence limits.\n");
}
process.exitCode = report.passed ? 0 : 1;
