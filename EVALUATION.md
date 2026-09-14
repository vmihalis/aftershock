# Evaluating Aftershock

This guide describes inspectable behavior and known limits. Use the code and actual command results to form your own assessment. The JSON companion is [EVALUATION.json](EVALUATION.json).

## Checkout and commands

The submitted video was recorded against `8725dbd07fbb2ea6d2f9a5bf8e921fd70f1a24a1`, retained by `demo-video`. Later commits add this guide, portable evidence validation and defensive fixes. Evaluation records the checkout it actually tested and whether it was dirty; it does not imply those changes were in the submission.

```bash
node --version                     # requires >=24
git rev-parse HEAD
npm ci                             # fetch locked dependencies
npm run evaluate                   # nonzero exit on failure
npm run --silent evaluate -- --json # same checks, structured output
```

The evaluator runs `verify:bundled`, `test`, `lint`, and `build`. Each step has a timeout and exit status. It continues after failures to report all outcomes. The build writes generated `dist/`. No credentials, server startup, Wasmer execution or GitHub writes are part of this path. Dependency fetching happens only in the separate install step. JSON stdout includes command outputs; it is not a signed certificate.

Individual checks remain available through npm scripts. `verify:receipt` is deliberately stricter than `verify:bundled`: it requires the uncommitted runtime cache described in the historical receipt and fails if it is absent. A clean clone uses the bundled check.

## Architecture and claim-to-evidence map

Three lanes exist today. The recorded experiment is not automatically ingested into the core or presentation replay.

```text
Supplied inventory + authored observations -> core engine -> immutable records
Authored presentation frames -> API/CLI -> GitHub projections -> optional publisher
Historical Wasmer experiment -> saved receipt -> static artifact/record verification
```

| Inspectable claim | Implementation | Checks | Boundary |
|---|---|---|---|
| Version matching preserves uncertainty | `src/core/applicability.ts` | `tests/core/applicability.test.ts`: partial inventory, conflicts, unsupported syntax | No complete discovery or full Python packaging semantics |
| Guest assertions do not select states | `src/core/observation.ts` | `tests/core/adjudication.test.ts`: failed controls, unexpected bytes, incomplete capture, wrong path | Authored observations, no fresh guest run |
| Evidence expires on identity changes | `src/core/assessment.ts` | `tests/core/lifecycle.test.ts`: immutable records, supersession, unchanged identity rejected | No durable storage, independent signatures or scheduler |
| Capsules have content identities | `src/core/capsule.ts`, `src/core/hash.ts` | `tests/core/capsule.test.ts`: content sensitivity, key-order independence, schema rejection | Does not bind r1 to the experimental receipt |
| GitHub output preserves provenance | `src/github/projections.ts` | `tests/github/projections.test.ts`, `tests/api/demo-controller.test.ts` | Replay is not new runtime validation of a target SHA |
| Publication and pushes have scope limits | `src/github/`, `src/server.ts` | `tests/github/action-publish.test.ts`, `tests/github/publisher.test.ts`, `tests/github/webhook.test.ts` | Clients are mocked; no deployed general-purpose App proved |
| Bundled evidence is internally consistent | `experiments/apm-wasmer/verify-receipt.mjs` | `tests/evaluation/receipt.test.ts`: edits, incorrect digest, duplicate case, truncation, missing runtime | No re-execution, comprehensive compatibility or independent authentication |

`POTENTIALLY_AFFECTED` is a match. `OBSERVED_BY_CHECK` and `REMEDIATION_RETESTED` are bounded observation/control decisions. `UNKNOWN` preserves failed prerequisites. `EVIDENCE_STALE_FOR_CURRENT_HEAD` withdraws applicability of earlier evidence to the changed identity. Content-derived IDs and frozen objects support deterministic in-process records; they do not protect against an operator who can edit the repository.

## Recorded evidence and identity

The original [receipt](artifacts/feasibility/apm-wasmer-receipt.json) is preserved unchanged. Its recorded engine revision is `f72d1c329a0958aaeff1bb3906db5a4e302724e7`, distinct from the video snapshot and public fixture revisions.

| Identity | Meaning |
|---|---|
| `receipt.repository.sha` | Historical experiment's engine checkout |
| `receipt.capsule.sha256` | Raw hash of `experiments/apm-wasmer/run-feasibility.mjs`; legacy field name, actually the harness |
| Core capsule digest | Canonical JSON hash of `capsules/GHSA-xhrw-5qxx-jpwr/r1.json` |
| Presentation `repository.headSha` | Target fixture revision represented by an authored frame |
| Evaluator `revision` | Checkout on which local evaluation just ran |

**The experiment and canonical r1 have different effect contracts.** The experiment records a 31-byte canary (`31ee0784…`) at a `.apm/prompts/` path. Core fixtures use a 125-byte labelled markdown canary (`6976c63e…`) at a `.github/prompts/` path. The saved experiment therefore does not validate canonical r1 or the presentation's target SHAs. API and GitHub payloads disclose this in their provenance fields.

The recorded cases describe affected target, fixed control, independent affected positive control and remediated target. They exercise the narrow function from public wheels with a YAML serialization shim. The complete APM CLI is not demonstrated. Requested runtime package is `python/python@=3.13.18`, while saved guest version stdout says `Python 3.13.15`; both are retained rather than silently equated.

The runtime artifact is about 157 MB and is not committed. Bundled verification checks its metadata format but reports its bytes as `NOT_CHECKED`. Strict verification additionally hashes available local runtime bytes. Both inspect an unsigned local record. An operator who rewrites records and corresponding hashes can forge a consistent record. Neither mode authenticates the historical outcome or reenacts the experiment.

Artifact hashes and submission references are listed in [EVALUATION.json](EVALUATION.json). Advisory URLs identify the recorded public source and may change later; timestamps alone do not make a source immutable.

## Configuration and limitations

- `npm run dev` starts the local replay API; `npm run build` followed by `npm start` runs compiled output. Run from the repository root. `PORT`, `AFTERSHOCK_PUBLIC_DIR` and `AFTERSHOCK_RECEIPT_PATH` are supported overrides.
- The server does not load `.env` itself. Export configuration through the launching shell or service manager. A health response verifies availability, not evidence correctness.
- GitHub App credentials are `GITHUB_APP_ID`, `GITHUB_PRIVATE_KEY`, and `GITHUB_WEBHOOK_SECRET`. Publication additionally requires `AFTERSHOCK_PUBLISH_GITHUB=1` and an installation ID from the signed payload. Configure contents read and Checks/Issues write permissions.
- Push handling is limited to the controller's fixture repository and `refs/heads/main`. Unrelated repositories, other refs and deletion SHAs are ignored before mutation. Failed publication leaves evidence stale and returns an error. No background retest is scheduled.
- The Actions adapter is restricted to `vmihalis/aftershock-apm-fixture`; it requires explicit dispatch and a scoped `GITHUB_TOKEN`. Default evaluation mocks publication and sends no network requests.
- Demo controls are unauthenticated local controls; the server binds to loopback. It is not a hardened multi-user service. In-memory state resets on restart. Issue dedupe search is bounded and there is no durable delivery/retry queue.
- Advisory ingestion, generalized inventory collection, live source/capsule watchers, continuous checks, persisted work queues and Tenki deployment remain future integration work. `.env.example` lists implemented settings only.

The default evaluation path inspects local logic and saved artifacts. The open-source experiment is separate; no evaluation result authorizes testing another system.
