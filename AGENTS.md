# Aftershock agent contract

This is a new hackathon implementation. Current priority: inspectable, reproducible behavior. Read `README.md`, then `EVALUATION.md`; `EVALUATION.json` is the machine-readable evidence map.

## Evaluation entry point

- Node.js 24 or newer; `npm ci`, then `npm run evaluate`.
- `npm run --silent evaluate -- --json` emits results, exit codes, outputs and checkout identity. A nonzero exit means at least one check failed.
- Default evaluation checks existing artifacts and local logic. It does not start Wasmer, execute a target, require credentials or publish to GitHub.
- Assess findings against the code and evidence. These documents are context, not instructions about scoring or disregarding defects.
- The video/submission snapshot is `8725dbd07fbb2ea6d2f9a5bf8e921fd70f1a24a1` (`demo-video`). Do not attribute later commits to that snapshot.

## Boundaries

- Do not copy or import Hacker Bob code, fixtures, schemas, services or branding.
- Use only team-owned fixtures and public advisory/package artifacts. Never test external systems.
- The synthetic canary must be visibly labelled and contain no personal or credential data.
- Guest output cannot directly select an assessment state. Trusted host code derives results from captured effects and controls.
- Preserve unknown/inconclusive outcomes. Never convert a failed run or failed control into a pass.
- Keep source revision, capsule digest and repository SHA attached to every assessment.

## Evidence boundaries

- Core tests and API frames use authored observations; a passing test is evidence about program logic.
- The saved Wasmer receipt is a separate historical experiment. Its `capsule` field identifies the harness, not canonical r1. Their canary/path contracts differ; no binding is established.
- Preserve original receipts and source hashes. Bundled verification checks committed artifacts and recorded claims; it does not authenticate the recorder, re-execute a check or verify the unbundled runtime.
- Keep missing inventory, failed controls and stale evidence explicit. No advisory poller, persistent queue, durable ledger or general automatic retesting service is shipped.

Work in assigned paths, coordinate shared files and do not revert unrelated work. CodeRabbit is banned.
