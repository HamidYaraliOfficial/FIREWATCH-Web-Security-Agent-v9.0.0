# Changelog

## 9.0.0 — 2026-10-14

- Validate effective runtime configuration before startup; production mode fails closed on weak/missing API keys, SQLite, private-target override, inline worker mode, malformed resource limits, CORS origins and ZAP URL configuration.
- Report ZIP bundles now include a JSON integrity manifest with per-file SHA-256 and byte lengths; the text manifest carries the same digests and clearly states that it is not digitally signed.
- Add regression matrices for production settings and bundle-manifest integrity.
- Add declared dependency inventory generation for JSON/Markdown without claiming dependency resolution or SBOM completeness.
- Add threat-model and production-readiness documentation; update version branding, test catalogs, CI checks and publish scripts to v9.0.0.
- Build from a cleaned source tree, excluding Python bytecode, caches and local database artifacts.


All notable release changes are recorded here.

## 8.0.0 — 2026-10-13

### Security and scope hardening
- Enforce RFC-style header-token syntax, reject case-insensitive duplicate custom headers, and reject forbidden control characters before requests are queued.
- Reject embedded URL user-info and credential-like query parameters directly in the scan request schema.
- Bind configured additional-host scope declarations to their configured scheme as well as allowed port.
- Make path exclusions conservative across case variants and explicitly block multicast/reserved address classes; reject unescaped URL whitespace.
- Extend bounded recursive redaction to handle more layers of nested encoded return/redirect URLs.

### Expanded verification
- Added 11 v8 test modules for header protocol rules, adversarial URL/scope matrices, risk/status invariants, redaction properties, output sinks, schema limits, crawler parser robustness, API discovery, encrypted credential storage, origin isolation and transport boundaries.
- Updated release version metadata, test inventory generation and CI freshness checks to v8.0.0.
- The automated test total and coverage are published only after a full run; optional tools unavailable in the local build environment are explicitly listed as unverified.

### Safety boundary
- The default assessment remains bounded and non-destructive. A clean software test suite does not imply that every target vulnerability will be detected or that an assessed target is secure.

## 7.0.0 — 2026-10-13

### Security and correctness
- Tightened wildcard exclusion semantics: `/internal/*` covers the intended path and descendants without matching siblings such as `/internal-public`.
- Improved redaction of nested redirect/return URLs that are percent-encoded multiple times.
- Escaped target-derived content in Markdown reports to reduce raw HTML and Markdown-link injection; retained spreadsheet formula neutralization in CSV reports.
- API classification now matches `graphql` as a path segment, reducing substring false positives. Expanded inventory review for URL-like OpenAPI parameters.
- Reject whitespace-padded prohibited request header names and zero as an optional ZAP service port.
- Improved case-insensitive fingerprinting of PHP and Next.js markers.

### Test and release quality
- Added deterministic adversarial matrices for scope paths/ports, sensitive-field and nested-URL redaction, OpenAPI effective authentication, report sinks, origin credential isolation, crawling, schema boundaries, ZAP serialization, role-comparison boundaries, and safe GET canary behavior.
- Version metadata now uses a single application constant and v7 release manifests/catalog exports are generated from the live test collection.
- Raised the release coverage gate to 80%; local measurements are recorded only after the full suite completes.

### Safety boundary
- Default assessment remains bounded and non-destructive. Review candidates/manual cases are explicitly distinguished from validated vulnerabilities; the assessment catalog is not a count of tests automatically performed against arbitrary targets.

## 6.0.0 — 2026-10-12

### Origin and scope security
- Bind HTTP and browser authentication headers to the exact root origin (scheme, hostname, and effective port), preventing credentials from being sent to a different service on the same hostname.
- Reject URL user-information in the shared credential-origin guard.
- Normalize encoded path traversal multiple times for exclusion-policy comparison without mutating the actual request URL.
- Recursively redact credentials nested in redirect/return/next URL query values, with a recursion cap.
- Align the scan schema's restricted transport-header list with the HTTP client (`TE` and `Trailer` included).

### Test and release quality
- Added broad deterministic matrices for adversarial URL scope, nested redaction, Pydantic scan/header bounds, risk scoring, HTTP methods/redirect behavior, catalog/report contracts and API routes.
- Added an executable release verification script plus machine-generated test inventory and JUnit/coverage output options.
- CI coverage floor raised to 78% and release metadata/docs/dashboard updated to v6.0.0.
- Maintained a clear boundary between software-regression test counts and the separate security-assessment catalog.

### Safety boundary
- The scanner remains scope-controlled and non-destructive by default. Test-account, business-logic and specialist-tool cases are explicitly identified rather than reported as fully automated.

## 5.0.0 — 2026-10-09

### Assessment coverage and transparency
- Added a 79-case assessment plan mapped to OWASP Top 10:2025, OWASP ASVS 5.0.0, WSTG v4.2 stable and OWASP API Security Top 10:2023.
- Added `/api/v1/assessment-plan` and export formats JSON, CSV, and Markdown.
- Clearly separated built-in passive observations, automated review candidates, manual/test-account workflows, and specialist-tool-only tests.

### Security and correctness
- Expanded secret redaction for URLs, structured evidence, Authorization, cookies and credential-like values.
- Corrected URL rejection for control characters/backslashes and invalid port values.
- Corrected OpenAPI operation-level `security: []` review behavior.
- Added precise cookie attribute, SameSite=None/Secure, `__Host-` and `__Secure-` policy checks.
- Added CSP `object-src`/`base-uri`, cross-origin isolation and header-value review checks.
- Enabled Jinja HTML autoescaping for generated findings reports.
- Neutralized spreadsheet formula injection in CSV findings exports.
- Safely serialized optional ZAP automation YAML and validated ZAP base URLs.
- Fixed same-transaction asset de-duplication with SQLAlchemy sessions configured with `autoflush=False`.
- Hardened risk score handling for NaN, infinity and malformed confidence values.

### Test quality and GitHub automation
- Expanded the automated suite to 400 unit, matrix, regression and local end-to-end tests.
- Measured 80.39% statement coverage in the local build environment and added a 65% CI coverage threshold.
- Added Python 3.11/3.12/3.13 CI matrix, high-severity/high-confidence Bandit checks and `pip-audit` dependency review.
- Added test inventory, generated assessment catalog, v5 verification record and release notes.
- Updated publishing helpers and package metadata to v6.0.0.

### Boundaries
- Manual and specialist tests are not represented as automatically executed. FIREWATCH does not perform brute-force login attempts, destructive workflows, exploit chains, or arbitrary write/delete operations by default.

## 4.0.0 — 2026-10-09
- Isolated credentials to the root hostname and scheme; refused credential-like query strings.
- Added cancellation checkpoints, strict scope behavior, report bundle APIs and GitHub publishing helpers.

## 3.0.0
- Improved scope validation, credential encryption/redaction, API discovery, coverage catalog, multiple report outputs, and security tests.

## 2.0.0
- Added browser/API discovery and a broader low-impact rule catalog.

## 1.0.0
- Initial working assessment pipeline, queue, dashboard, findings, and HTML/JSON reports.
