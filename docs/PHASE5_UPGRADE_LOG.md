# Phase 5 upgrade log — institution registry and authenticated submission API

## Objective

Build the institutional trust and integration foundation identified in the SIH26263 objective review while preserving Phase 4 central submissions and oversight. This is an additive prototype milestone, not an official AICTE or APAAR integration.

## Implemented

- Added `institution_registry` with unique institution code/name and `active`/`suspended` status.
- Added platform-admin UI at `/central-institutions` to register institutions, suspend/reactivate them, issue credentials and revoke credentials.
- Added `institution_api_credentials`; only a SHA-256 digest and short display prefix are stored. The raw token is rendered once at issuance.
- Added `POST /api/v1/institution-submissions`, authenticated using a bearer credential tied to one active registry institution.
- Added a fixed JSON contract and field/length validation; payloads cannot select their own institution.
- Added idempotency keys with same-payload replay, conflicting-payload rejection, and identical-content duplicate protection.
- Added submission batches/events/audit log records using the existing central workflow and reviewer state transitions.
- Kept browser-session CSRF protection intact; only the exact service API route is exempt because it uses bearer authentication instead.
- Added regression tests for missing credentials, valid submissions, idempotent replay, conflicting key reuse, suspended institutions, revoked credentials and duplicate record IDs.
- Updated the README and navigation.

## Data model and security choices

- API submissions contain only institutional enrolment ID, institutional student reference, student name, programme code/name, enrolment status and academic year.
- The API does not accept APAAR IDs, email addresses, Aadhaar numbers, birth dates or raw identity documents.
- The service token is generated with a cryptographically secure random source and stored as a SHA-256 digest; tokens are not displayed again after issuance.
- Institution name/code association comes from the credential, not from request data.
- Idempotency is scoped to institution; content hashes detect identical payloads within that institution.
- Suspended institutions and revoked credentials cannot submit.
- Existing Phase 4 reviewer transitions remain the control for accepting or returning batches.

## Validation performed for this package

- Python syntax compilation: passed for all Python files (UTF-8 BOM-aware).
- SQLite schema smoke test: passed; the complete `init_db()` schema script executed in an in-memory SQLite database and `PRAGMA integrity_check` returned `ok`; all three new tables were present.
- Flask runtime test suite: not executable in this build environment because Flask and Werkzeug are not installed. Attempting to collect the new tests stopped at `ModuleNotFoundError: No module named 'werkzeug'`.
- End-to-end browser and service API tests: regression cases are defined in `tests/test_institution_registry_api.py`, but have not been executed due to the missing runtime dependencies.
- ZIP integrity: passed; the packaged archive contains 94 files, `ZipFile.testzip()` found no corruption, and no `.env` file or `instance/` database was included.

## Not implemented / must not be claimed

- No authoritative institutional registry or accreditation validation.
- No official APAAR/AICTE/ABC/DigiLocker integration.
- No authoritative APAAR identifier validation or official identity proof.
- No approved-intake/sanctioned-seat/supernumerary/NRI/OCI/foreign-national rules engine yet.
- No HMAC identifier matching service, institution-specific cryptographic key management, external secret manager, rate limiter, asynchronous queue, mTLS, signed request bodies or production-grade key rotation workflow.
- No proof that the application is production-ready; this requires runtime tests, security review, deployment hardening, privacy review, backup/restore testing and load testing.

## Next recommended milestone

1. Establish a versioned approved-intake model and category-aware seat allocation rules from the official problem statement and verified authoritative requirements.
2. Add a synthetic cross-institution matching job that runs only within an authorized central boundary and generates explainable human-review cases.
3. Add full integration tests and evidence tied to a specific Git commit before any live demonstration.
