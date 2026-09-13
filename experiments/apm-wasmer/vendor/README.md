# Public artifacts

This directory contains public package artifacts used by the feasibility run.
Each downloaded artifact is recorded with its source URL and SHA-256 digest in
the generated feasibility receipt. No package in this directory is executed on
the host.

They were downloaded from the public Python package index without dependencies:

```sh
python3 -m pip download --no-deps --only-binary=:all: \
  --dest experiments/apm-wasmer/vendor apm-cli==0.8.11
python3 -m pip download --no-deps --only-binary=:all: \
  --dest experiments/apm-wasmer/vendor apm-cli==0.8.12
```

Pinned artifacts:

```text
268a3832035d15568d9a395f40ac36fc1e66e98f116e2ba961662420a142b723  apm_cli-0.8.11-py3-none-any.whl
d252a1364b52cf14dde7ca3a25dbd3af949e0d573d3f163fa3ac76757aec5961  apm_cli-0.8.12-py3-none-any.whl
```
