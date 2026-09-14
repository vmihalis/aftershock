# Aftershock

**Security context for coding agents, with evidence that expires when the code changes.**

Aftershock explores: “That vulnerability was in the news. What does my coding agent need to know about my project?” The prototype separates a dependency match, an observed effect, a retested remediation and stale evidence, and turns those states into structured GitHub work.

This repository contains a tested assessment engine, a deterministic API/presentation replay, GitHub publication adapters, and a separate recorded Wasmer experiment. They demonstrate the intended workflow; they are not yet a fully connected continuous monitoring service.

## Review with a coding agent

Start with [EVALUATION.md](EVALUATION.md) for the architecture, claim-to-test map and evidence limits. [EVALUATION.json](EVALUATION.json) supplies structured entry points and artifact identities.

With Node.js 24 or newer:

```bash
npm ci
npm run evaluate
```

Evaluation checks bundled receipt integrity, unit tests, TypeScript and the build. It requires no credentials, performs no GitHub publication and does not start Wasmer or execute a target. Dependency installation needs registry access; evaluation after installation uses local files. For machine-readable results:

```bash
npm run --silent evaluate -- --json
```

The video/submission snapshot is [`8725dbd`](https://github.com/vmihalis/aftershock/tree/8725dbd07fbb2ea6d2f9a5bf8e921fd70f1a24a1), retained by the [`demo-video` release](https://github.com/vmihalis/aftershock/releases/tag/demo-video). Later commits improve evaluation, documentation and defensive correctness; they are not represented as part of that snapshot.

## What is implemented

| Component | Behavior | Boundary |
|---|---|---|
| Applicability | Match an advisory against supplied inventory at an exact SHA | No inventory collector or news feed |
| Adjudication | Evaluate captured-file observations and target/fixed/positive controls | Tests supply synthetic observations |
| Evidence lifecycle | Immutable records, supersession and invalidation on SHA/source/capsule changes | In-memory records; no persistent scheduler or ledger |
| GitHub adapters | Generate Checks and deduplicated Issues; publish with configuration | Public fixture workflow is manually dispatched |
| API and CLI | Six-frame fixture replay with provenance and historical links | No fresh verification or receipt-derived states |
| Wasmer experiment | Saved four-guest record for a narrow path in two public APM wheels | Separate contract from canonical r1; full APM CLI not demonstrated |

## Inspect the lifecycle

```bash
npm run demo
npm run dev
```

The CLI prints fixture frames. The server binds to [127.0.0.1:4317](http://127.0.0.1:4317) and serves:

- `GET /api/view`: presentation frame labelled as replay.
- `GET /api/core/sequence`: canonical records from authored observations.
- `GET /api/github/projection`: Check/Issue payloads without publishing.
- `GET /api/feasibility/receipt`: original experiment record.
- `GET /api/events`: presentation updates over SSE.
- `POST /api/demo/reset` and `/api/demo/advance`: local presentation controls.
- `POST /api/github/webhook`: signed, scoped push handling; invalidates evidence and optionally publishes, without scheduling a retest.

## Recorded evidence

The experiment concerns Microsoft's public [APM advisory](https://github.com/microsoft/apm/security/advisories/GHSA-xhrw-5qxx-jpwr), affected `apm-cli` 0.8.11 and fixed 0.8.12. Its four recorded cases use synthetic canary bytes, no host mounts and disabled guest networking. The [receipt](artifacts/feasibility/apm-wasmer-receipt.json) preserves both the incomplete full dependency install and the successful narrower function-level run with a YAML shim.

`npm run verify:bundled` checks committed harness/wheel hashes and consistency of recorded observations. It explicitly reports the unbundled runtime as `NOT_CHECKED`. `npm run verify:receipt` also requires the original local runtime artifact and checks its hash. Neither command executes the experiment or independently authenticates its historical outcome.

The receipt's harness hash and canary contract differ from the core Threat Capsule. [EVALUATION.md](EVALUATION.md#recorded-evidence-and-identity) explains this boundary. Passing verification is not a fresh vulnerability assessment of this checkout or any fixture SHA.

Historical publication artifacts: [agent Issue](https://github.com/vmihalis/aftershock-apm-fixture/issues/1), [observed-state Check](https://github.com/vmihalis/aftershock-apm-fixture/runs/103819046282), [remediation-state Check](https://github.com/vmihalis/aftershock-apm-fixture/runs/103819189475), [stale-state Check](https://github.com/vmihalis/aftershock-apm-fixture/runs/103819288142). They demonstrate publication of fixture state, not independent runtime attestation.

## Self-hosting scope

The source is MIT licensed. The server runs locally; GitHub publication requires an App or scoped Actions token. [EVALUATION.md](EVALUATION.md#configuration-and-limitations) documents the configuration and missing production pieces. Wasmer supplies the experiment's guest execution substrate. No Tenki integration is implemented.

This repository contains no Hacker Bob code, services, fixtures, schemas or branding. Differential testing and positive controls are established methods. Aftershock's proposed contribution is connecting advisory context, agent work and evidence invalidation. Vendored Microsoft APM wheels retain their MIT license metadata and recorded hashes.
