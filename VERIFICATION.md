# FIREWATCH v9.0.0 Verification Record

Release target: `FIREWATCH-WebSec-Agent-v9.0.0`

## Test results (local environment)

- Pytest collection: **5,869 test cases across 57 modules** (`docs/TEST_MANIFEST_V9.json`).
- Full regression suite without coverage instrumentation: **passed**, reached 100%, zero failures/errors/skips reported; command exited successfully.
- Combined statement coverage: **85.70%**, collected test inventory 5,869 cases across 57 modules, 8 deterministic shards, zero shard failures; minimum gate 80% passed.
- Local demo scan: completed against the bundled loopback-only demo target; sample report contains 41 findings and uses FIREWATCH v9 metadata. It is test-fixture output, not a result for an external website.
- Report bundle integrity: verified `manifest.json` paths, file sizes and SHA-256 digests with `scripts/verify_report_bundle.py`. Included hashes detect accidental modification relative to the manifest; they do not establish publisher authenticity.
- Python compilation, dashboard JavaScript syntax, publisher shell syntax, Docker Compose YAML parsing, repository hygiene, assessment-plan export, test-manifest generation, dependency inventory export and required release checks were run locally and passed.

## Not verified in this build environment

Bandit, `pip-audit`, and Docker CLI/image build were unavailable, so those checks were **not run**. GitHub Actions and CodeQL have not run on the user's GitHub account because this package has not been pushed to a remote repository. A resolved SBOM/package vulnerability audit is not claimed; the dependency inventory documents declared constraints. Browser-mode checks that require an installed Chromium binary may need a configured Playwright browser in the deployment environment.

## Release checks

- Python compilation for application, tests, demo target and scripts.
- Complete pytest regression suite, including local demo end-to-end, API contracts, property/matrix tests and v9 config/report-integrity checks.
- Combined statement coverage across deterministic shards with an 80% floor.
- Dashboard JavaScript syntax, publisher shell syntax, Docker Compose YAML parse, repository hygiene, assessment-plan export, test manifest regeneration, dependency inventory generation and report ZIP integrity.

## Security limitations

Automated web checks do not prove the absence of vulnerabilities. Authorization/business-logic cases and exploit-required cases may need dedicated test accounts, staged data, a written test plan and human validation. Do not scan systems without explicit authorization. Production readiness still requires deployment-specific review of secrets, TLS, network boundaries, backups, monitoring and database permissions.
