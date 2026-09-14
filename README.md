# Aftershock

**Aftershock turns a new security advisory into evidence-bound work for a coding agent.**

It matches an advisory to an exact repository revision, runs an admitted Threat Capsule with restricted capabilities, publishes a GitHub Check and deduplicated Issue, retests the remediation, and withdraws yesterday's reassurance when either the code or the capsule changes.

```text
new advisory -> exact project match -> restricted check -> Check + agent Issue
             -> remediation commit -> same check -> new head makes old evidence stale
```

## Three-minute hero path

The hackathon demo uses Microsoft's public `GHSA-xhrw-5qxx-jpwr` / `CVE-2026-44641` advisory, the authorized public [`vmihalis/aftershock-apm-fixture`](https://github.com/vmihalis/aftershock-apm-fixture) repository, and a synthetic 31-byte canary.

1. A fixture repository pins affected `apm-cli==0.8.11`.
2. Aftershock reports `POTENTIALLY_AFFECTED`; a version match is not called exploitation.
3. Wasmer starts fresh Python guest sandboxes with network disabled, no credentials, and no host mounts.
4. The trusted host observes the exact canary bytes copied by the affected `normalize_plugin_directory` path in the public `0.8.11` wheel.
5. The same path in `0.8.12` rejects the escaping source. A separate `0.8.11` positive control must remain sensitive.
6. Aftershock creates a failing Check and a structured Issue for the coding agent.
7. The dependency update is retested. A later repository SHA changes the result to `EVIDENCE_STALE_FOR_CURRENT_HEAD` and queues reassessment.

The feasibility receipt labels its scope precisely: this is the exact affected function from the two public wheels with a minimal YAML serialization shim. It is not a claim that the complete `apm install` command ran in Wasmer; the full offline dependency graph is currently incomplete and that attempt is preserved in the receipt.

## Run it

Requirements: Node.js 24 and npm.

```bash
npm ci
npm test
npm run lint
npm run build
npm run demo
```

Run the real Wasmer feasibility capsule:

```bash
npm run verify:apm
npm run verify:receipt
```

The first Wasmer run needs access to fetch the pinned runtime package. Every guest created by the capsule has network disabled. Later runs use the experiment-local cache.

Start the UI API:

```bash
npm run dev
```

- `GET /api/view` — current run-detail projection
- `POST /api/demo/reset` — reset the deterministic presentation
- `POST /api/demo/advance` — advance one video beat
- `GET /api/events` — server-sent view updates
- `GET /api/github/projection` — Check and Issue payloads without publishing
- `GET /api/core/sequence` — immutable canonical lifecycle records
- `GET /api/feasibility/receipt` — recorded Wasmer byte evidence and limitations
- `POST /api/github/webhook` — verify a GitHub push signature and invalidate evidence for the new head

The replay API is explicitly marked `meta.mode: "demo-fixture"`. Recorded Wasmer evidence is stored under `artifacts/feasibility/`; do not present fixture frames as fresh execution.

## Publish the real GitHub demo artifacts

The authorized fixture includes a manually dispatched [Aftershock demo publisher](https://github.com/vmihalis/aftershock-apm-fixture/actions/workflows/aftershock-demo.yml). It checks out this engine, uses the fixture repository's scoped `GITHUB_TOKEN`, and calls:

```bash
npm run publish:action -- --frame 3  # failing observed-effect Check + open Issue
npm run publish:action -- --frame 5  # successful remediation Check + closed Issue
npm run publish:action -- --frame 6  # neutral stale-evidence Check + reopened Issue
```

The demo adapter fails closed unless it is running in `vmihalis/aftershock-apm-fixture`. General installations use the GitHub App webhook path described below.

## Evidence rules

Aftershock keeps these claims separate:

- `POTENTIALLY_AFFECTED`: project evidence matches an affected range.
- `OBSERVED_BY_CHECK`: host-captured bytes satisfy the target, fixed-control, and independent positive-control matrix.
- `REMEDIATION_RETESTED`: the patched target no longer shows that exact effect and the positive control still does.
- `UNKNOWN`: a required observation or control failed, timed out, or disagreed.
- `EVIDENCE_STALE_FOR_CURRENT_HEAD`: the repository SHA, source revision, capsule revision, or capsule digest changed.

Guest stdout cannot select a verdict. The engine binds assessments to full repository SHAs and capsule digests, preserves append-only supersession, and treats incomplete inventory or capture as unknown.

## Optional live GitHub publication

Create a GitHub App with read access to contents and write access to Checks and Issues. Subscribe it to push events, configure `.env.example`, and set `AFTERSHOCK_PUBLISH_GITHUB=1`. The webhook handler obtains an installation client, creates a commit-bound Check, and creates, updates, reopens, or closes the deduplicated agent Issue.

Keep the service and fixture repository under your control. The demo does not test third-party systems or use real secrets.

## New-work boundary

This repository was created for the hackathon. It contains no Hacker Bob code, services, fixtures, schemas, or branding. General differential testing and positive controls are established security methods; Aftershock's contribution is the proactive advisory-to-agent workflow and the lifecycle that automatically invalidates stale evidence.

## License

Aftershock is MIT licensed. The vendored Microsoft APM wheel artifacts retain their own MIT license metadata and hashes.
