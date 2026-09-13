# APM / Wasmer feasibility result

## Decision

The initial and remediation gates pass for the narrow exact affected path. They
do not establish that the complete `apm` CLI runs in Wasmer.

- Vulnerable target, `apm-cli` 0.8.11: exact synthetic canary bytes observed at
  the guest effect path.
- Fixed control, `apm-cli` 0.8.12: effect path absent; the package reports that
  the commands entry escapes the plugin root.
- Independent positive control, `apm-cli` 0.8.11: exact synthetic canary bytes
  observed in a separate guest.
- Remediated target, `apm-cli` 0.8.12: effect absent in a fourth guest.
- Initial decision: `OBSERVED` from target present, fixed control absent, and
  positive control present.
- Remediation decision: `REMEDIATED` from remediated target absent while the
  independent positive control remains present.
- Trusted decision source: Wasmer SDK host reads of guest filesystem bytes.
- Guest network: explicitly disabled in all four fresh sandboxes.
- Host filesystem mounts: none.

## Recorded commands

Public wheels were fetched once from PyPI:

```sh
python3 -m pip download --no-deps --only-binary=:all: \
  --dest experiments/apm-wasmer/vendor apm-cli==0.8.11
python3 -m pip download --no-deps --only-binary=:all: \
  --dest experiments/apm-wasmer/vendor apm-cli==0.8.12
```

An attempt to assemble a platform-independent Python 3.13 dependency
wheelhouse was also made:

```sh
python3 -m pip download --only-binary=:all: --platform any \
  --implementation py --python-version 3.13 --abi none \
  --dest /private/tmp/aftershock-apm-wheelhouse.ddsqxw apm-cli==0.8.11
```

It stopped at `pyyaml>=6.0.0` because no matching `py3-none-any` distribution
was available. A separate unconstrained host download resolved native macOS
wheels and a source distribution; those are not a WASIX wheelhouse and were
not copied into this experiment.

The prewarmed Wasmer package was then loaded directly from cached WEBC bytes:

```sh
node experiments/apm-wasmer/probe-python.mjs
node experiments/apm-wasmer/run-feasibility.mjs
node experiments/apm-wasmer/verify-receipt.mjs
```

Stable result fields from the recorded summaries:

```json
{"runtime":"python/python@=3.13.18","packageAcquisition":"cached_webc_bytes","network":"disabled","exitCode":0,"hostObservedByteLength":31,"hostObservedExactMatch":true}
{"fullPackageCompatible":false,"narrowExactPathPassed":true,"initial":{"assessment":"OBSERVED","passed":true},"remediation":{"assessment":"REMEDIATED","passed":true},"verdict":"pass_narrow_exact_affected_path_with_independent_controls","trustedDecisionSource":"host-read guest filesystem bytes","guestOutputCanSelectVerdict":false}
{"status":"receipt-verification-ok","targetBefore":"effect_observed","fixedEffect":"effect_not_observed","positiveControl":"effect_observed","targetAfter":"effect_not_observed","initialAssessment":"OBSERVED","remediationAssessment":"REMEDIATED","fullPackageCompatible":false,"narrowExactPathPassed":true}
```

The receipt also records whether the repository was clean at run start. A
clean run binds `repository.sha` to the actual `git rev-parse HEAD`. A dirty
working tree records the real HEAD separately and leaves the assessment SHA
null. An initial repository with no commit records both values as null rather
than inventing a revision.

## Compatibility boundary

The published wheels themselves are pure Python and install in Wasmer without
dependencies. A full offline install stops at unavailable `click`, and the
complete CLI import consequently fails with `ModuleNotFoundError: click`.
Resolving the entire dependency graph would also require preparing packages
for WASIX when they are not distributed as platform-independent wheels.

The fallback imports the exact `apm_cli/deps/plugin_parser.py` installed from
each public wheel and calls `normalize_plugin_directory`. It avoids executing
the package initializer, which imports unrelated CLI dependencies. A minimal
`yaml` shim is present only for serialization after the affected copy branch;
that branch does not call PyYAML. The machine-readable receipt captures all
commands, outputs, wheel hashes, capsule hash, source bytes and effect bytes.
