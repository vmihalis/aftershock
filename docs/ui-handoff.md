# UI handoff

Build one dark run-detail page against `GET /api/view`. Do not build a dashboard or settings product for the demo.

The page needs, in order:

1. A top incident strip with `GHSA-xhrw-5qxx-jpwr`, severity, source revision, and a link to the Microsoft advisory.
2. Repository, full commit SHA, capsule revision, and capsule digest directly below it.
3. One large assessment-state pill and one sentence explaining exactly what has or has not been established.
4. A four-row verification matrix: vulnerable target, fixed control, independent vulnerable positive control, remediated target. Show pending, exact effect observed, effect absent, or unknown.
5. A capability card: Wasmer runtime, network disabled, no credentials, synthetic snapshot only, timeout.
6. A vertical event timeline ending in `EVIDENCE_STALE_FOR_CURRENT_HEAD`.
7. Links to the Check, Issue, capsule, and receipt when present.

Use `POST /api/demo/reset` and `POST /api/demo/advance` for the recorded video. Subscribe to `GET /api/events` for immediate updates. Keep `meta.mode` visible during development so a fixture frame cannot be mistaken for a fresh Wasmer execution.

The visual climax is the green remediation receipt becoming amber and stale when a new head SHA arrives. That transition should dominate the last screen.
