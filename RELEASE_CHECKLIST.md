# FIREWATCH v9 Release Checklist

- [ ] `VERSION`, `backend/app/version.py`, `backend/pyproject.toml`, assessment catalog and UI branding agree on `9.0.0`.
- [ ] `python scripts/export_assessment_plan.py` generates the v9 assessment JSON/CSV and catalog.
- [ ] `python scripts/build_test_manifest.py` regenerates the v9 test manifest/matrix from pytest collection.
- [ ] `python scripts/export_dependency_inventory.py` regenerates the v9 declared dependency inventory.
- [ ] `python scripts/verify_release.py` completes successfully; optional skipped tools are handled explicitly.
- [ ] `python -m pytest backend/tests -q` passes all collected tests.
- [ ] `bandit -q -r backend/app -lll -iii` passes in a tool-enabled environment.
- [ ] `pip-audit -r backend/requirements.txt` passes with dependency index access.
- [ ] Docker Compose config validates and the images build.
- [ ] Demo Target e2e scan writes all expected formats and can be canceled safely.
- [ ] A report ZIP verifies with `scripts/verify_report_bundle.py`.
- [ ] Run a staged coverage sequence only with the same collected test inventory; the runner checks a collection fingerprint before finalizing.
- [ ] GitHub Actions, CodeQL and Dependabot status are reviewed before a public release.
- [ ] Source archive excludes databases, secrets, keys, bytecode, caches, local reports and coverage scratch files.
- [ ] Changelog, known limitations, dependency inventory and checksum are included in the release.

Checks not executed in a local environment must be listed as **unverified**, not marked passed.
