# Threat Capsules

`GHSA-xhrw-5qxx-jpwr/r1.json` is the canonical data contract for the demo capsule. Its digest covers the complete JSON value using recursively sorted object keys and SHA-256. The digest is computed by trusted host code; it is intentionally not embedded in the capsule itself.

The synthetic canary is team-owned test data. It contains no personal, credential, or production information.
