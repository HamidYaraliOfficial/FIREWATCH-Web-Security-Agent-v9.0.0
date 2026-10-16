# FIREWATCH Web Security Agent v9.0.0

FIREWATCH v9 is a release-readiness and operational-hardening release built on the v8 security and regression baseline. It strengthens startup configuration validation, adds integrity manifests for report bundles, documents operational boundaries, and makes the test/dependency inventories repeatable and machine-readable.

## Highlights

- Validate effective runtime configuration before startup; production mode fails closed on weak/missing API keys, SQLite, private-target override, inline worker mode, malformed limits, CORS origins, and ZAP URL configuration.
- Report ZIP bundles include a JSON integrity manifest with SHA-256 and byte lengths; a standalone verifier checks archive paths, duplicates, sizes and digests. Hash manifests detect accidental modification relative to the manifest but are not publisher signatures.
- Add regression tests for production settings, report bundle manifest integrity, dependency inventory generation, CLI verifier behavior, and coverage-shard inventory consistency.
- Generate a declared dependency inventory in JSON and Markdown without misrepresenting it as a resolved SBOM or vulnerability scan.
- Add a threat model and production-readiness checklist; refresh version branding, assessment catalog, test manifest, CI references and GitHub publish guide to v9.0.0.
- Clean source release excludes Python bytecode, test caches, coverage artifacts and local database files.

## Verification summary

- **5,869 / 5,869 pytest cases passed**, across **57 modules**, with the complete local regression run reaching 100% and no reported failures/errors/skips.
- **85.70% combined statement coverage** for `backend/app`, above the 80% minimum, measured across eight deterministic test shards using the same collected test inventory. All shards passed.
- Source compilation, JavaScript syntax, publisher shell syntax, Docker Compose YAML parsing, repository hygiene, generated assessment/test/dependency inventories, and the sample report-bundle manifest were checked locally.

These are software quality metrics, not vulnerability-detection rates. Bandit, `pip-audit`, Docker image builds and hosted GitHub/CodeQL execution were unavailable in the build environment and remain unverified. See [`VERIFICATION.md`](VERIFICATION.md) for details.
