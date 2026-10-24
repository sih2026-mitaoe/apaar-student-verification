# Phase 4 Upgrade Log — Central Submission Workflow

Date: 2026-10-24
Base: `apaar-student-verification-phase3-reviewed.zip`
Scope: additive institution-to-central demo submission and review workflow.

## Delivered in this checkpoint

### 4.1 Versioned central batch submission
- Added `central_submission_batches` and `central_submission_events` tables.
- An institution administrator or operator can create a batch from the latest `submitted` enrolment-submission version for a selected academic year.
- Batch versioning is per institution. Each batch links to the previous batch for that institution.
- A content digest prevents an identical batch payload from being processed twice.
- Submission event history records the creation and central review state transitions.

### 4.2 Data minimization and integrity checks
- The central payload is built from frozen admissions submission snapshots.
- The payload excludes APAAR-like identifiers, email addresses, notes and local database primary keys.
- The snapshot includes institutional references, student name, programme, academic year, local submission version and source snapshot digest.
- SHA-256 digest verification detects accidental payload changes. It is not a signature, identity proof or guarantee that source data is true.
- A digest mismatch makes the central batch read-only for status transitions.

### 4.3 Central oversight and review
- Added `/central-submissions` for institution-scoped batch creation and history.
- Added `/central-oversight` for the dedicated `platform_admin` role.
- Added `/central-oversight/<batch_id>` for central review, minimal record inspection, event history and controlled status transitions.
- Review/correction transitions require a note; transitions cannot skip directly from `submitted` to `accepted`.
- The platform admin role is not assignable through the existing institution user-management interface.
- Added `bootstrap_platform_admin.py`, a separate one-time account provisioning script that refuses to modify an existing account and requires a long password.

### 4.4 Preliminary capacity signal
- The batch records a preliminary signal when submitted record counts exceed the configured capacity copied into the frozen enrolment snapshots.
- The UI explicitly labels this as an institution-configured capacity signal, not an approved-intake or regulatory verdict.
- Category-specific/supernumerary rules and a verified approved-intake registry remain unimplemented.

### 4.5 Configuration consistency
- Replaced remaining authentication delivery and login-page environment checks based only on `FLASK_ENV` with the resolved `production_mode`.
- OTP-authenticated `platform_admin` accounts are directed to the central oversight dashboard after successful OTP verification.

## Files changed

- `app.py`
- `templates/base.html`
- `templates/central_submissions.html` (new)
- `templates/central_oversight.html` (new)
- `templates/central_batch_detail.html` (new)
- `static/style.css`
- `static/design-system.css`
- `bootstrap_platform_admin.py` (new)
- `tests/test_central_submission_workflow.py` (new)
- `README.md`

## Validation evidence

- Python syntax compilation: passed for all Python files.
- Application schema DDL: extracted and executed against an in-memory SQLite database successfully.
- ZIP packaging integrity: to be checked after packaging.
- Full Flask runtime suite: not run in this build environment because Flask and Werkzeug are not installed and package installation is unavailable. New tests are present but not runtime-verified.
- End-to-end central submission flow: not runtime-verified here.

## Known limitations (do not present as completed)

- This is a local demo workflow, not an official AICTE submission endpoint or live central repository.
- There is no institution onboarding/registry workflow yet. Batch institution names derive from the authenticated institution account.
- No service-to-service API authentication, public institutional API, retry queue or background processing job is implemented in this phase.
- Central snapshots contain limited student-identifying data for authorized review; production deployment needs a formal access policy, retention schedule, encryption/key management and data protection review.
- Configured-capacity flags are not a substitute for sanctioned intake approvals and category-specific seat-allocation rules.
- Cross-institution identity matching remains the separate demo-only shared-database feature from Phase 2 and is not invoked as part of this batch workflow.
- Official APAAR/ABC/DigiLocker or AICTE integrations remain unavailable and unimplemented.
- SHA-256 digest checks are not a digital signature, tamper-proof audit system or proof of data truth.

## Next phase recommendation

1. Run the complete test suite in the project's normal Python environment.
2. Add institution registry/onboarding and explicit active/suspended institution state.
3. Add authenticated, idempotent institution submission API and request audit.
4. Build approved-intake records and versioned category-aware seat rules before presenting compliance findings.
5. Add cross-institution identity matching to the central processing workflow only after designing and testing the authorization boundary.
