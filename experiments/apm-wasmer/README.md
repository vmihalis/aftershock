# APM / Wasmer feasibility gate

This experiment determines whether public `apm-cli` 0.8.11 and 0.8.12 wheels
can produce a controlled vulnerable-to-remediated sequence in Wasmer. Four
fresh guests keep the target, fixed control, independent positive control, and
remediated target separate. Each guest receives no network capability or host
filesystem mount. Trusted host JavaScript reads effect bytes from each guest
filesystem and derives the result; guest prose is never treated as a verdict.

The staged order is:

1. Prove the pinned Wasmer Python package runs with networking disabled and
   that the host can read exact guest effect bytes.
2. Run the published `apm-cli` wheels through their real CLI entry point with
   an entirely local plugin fixture.
3. If the full dependency graph is incompatible, record the failure and run
   only the narrowest source-identical vulnerable/fixed path, clearly labelled
   as a fallback rather than a full-package result.

Public package artifacts and generated receipts remain inside this experiment
or `artifacts/feasibility/`.

## Reproduce

The two public wheels are already vendored and pinned by SHA-256. The Wasmer
Python package cache must be prewarmed once. On a cold checkout, the first
command resolves that package through the host SDK; its guest sandbox still has
networking disabled. Later processes load the cached WEBC artifact directly by
bytes and SHA-256, without a registry lookup. Every sandbox receives disabled
guest networking and no host filesystem mount.

```sh
node experiments/apm-wasmer/probe-python.mjs
node experiments/apm-wasmer/run-feasibility.mjs
node experiments/apm-wasmer/verify-receipt.mjs
```

The recorded run produced:

```text
probe: packageAcquisition=cached_webc_bytes, hostObservedExactMatch=true
gate:  fullPackageCompatible=false
gate:  narrowExactPathPassed=true
gate:  initial.assessment=OBSERVED
gate:  remediation.assessment=REMEDIATED
gate:  verdict=pass_narrow_exact_affected_path_with_independent_controls
verify: receipt-verification-ok
```

The four fresh sandboxes contain a vulnerable 0.8.11 target, a fixed 0.8.12
control, a separate vulnerable 0.8.11 positive control, and a remediated 0.8.12
target. Both public wheels install without dependencies inside Wasmer. Their
complete CLI imports fail on the first unavailable dependency, `click`; that
failure is captured rather than converted into a pass. The narrow fallback
imports the real `apm_cli/deps/plugin_parser.py` file from each installed wheel
and calls its `normalize_plugin_directory` function. A minimal `yaml`
serialization shim only permits the function to write its unrelated generated
`apm.yml`; the affected copy branch does not call PyYAML.

Trusted host JavaScript reads both the source canary and the expected effect
path from each guest filesystem. Both independent 0.8.11 runs contain the exact
31 canary bytes at the effect path. Both independent 0.8.12 runs leave that
path absent and emit the path-escape rejection. The initial assessment becomes
`OBSERVED` only when the target is present, the fixed control is absent, and
the positive control is present. The later assessment becomes `REMEDIATED`
only when the remediated target is absent while the independent positive
control remains present.

See `artifacts/feasibility/apm-wasmer-report.md` for the recorded commands and
`artifacts/feasibility/apm-wasmer-receipt.json` for the machine-readable
evidence.
