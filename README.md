# APAAR Student Data Management & Verification Platform

SIH 2026 · Problem Statement SIH26263 · Local synthetic-data prototype

The primary application is Flask with server-rendered Jinja pages and a versioned Flask API. Both use the existing SQLite database at `instance/apaar_demo.db`. It supports student record management, local validation, CSV operations, duplicate decisions, consolidated verification cases and timelines, synthetic evidence metadata, institution-scoped account management, and archive restoration.

This application does not issue APAAR identifiers or connect to APAAR, ABC, DigiLocker, or another government database. Local checks and demo statuses are not official verification. Use synthetic records only. Verification runs persist versioned local-rule outcomes. With `APAAR_PROVIDER=mock`, deterministic scenarios are explicitly simulated and always non-authoritative; with no provider configured, the UI shows `NOT_CONFIGURED` and the attempt remains review-needed rather than a failed identity result. The reserved `Verified against source` status cannot be set by clients and is not currently produced because no approved authoritative adapter is configured. APAAR identifiers are masked in the profile and omitted from APIs and exports; this is not encryption at rest.

## Windows setup

Install Python 3.11 or newer, then run these commands in PowerShell from the repository root:

```powershell
$python311 = Join-Path $env:LOCALAPPDATA 'Programs\Python\Python311\python.exe'
& $python311 -m venv --clear .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
python -m pytest -q
python app.py
```

Before the first launch, edit `.env` and replace the `SECRET_KEY` and `DEMO_ADMIN_PASSWORD` placeholders with private values. The app now treats every `replace-with-` secret as a placeholder; never keep one in production. Set `APP_ENV=production` for production-mode secret validation. Use a unique password of at least 16 characters. The first database initialization creates the `admin` account using that password; later launches do not reset an existing account. If the account needs to be created or reset explicitly, use `bootstrap_admin.py`, which prompts for credentials without echoing the password and requires `--update-existing` before resetting a matching account.

Open <http://127.0.0.1:5000>. Production mode forces secure session cookies; set `COOKIE_SECURE=1` when serving a non-production instance through HTTPS. `run.cmd` is also available for setup and launch. Do not expose Flask's development server to the public internet.

See [Phase 1 security and correctness changes](docs/PHASE1_SECURITY_FIXES.md) for the latest implementation log and validation status.

See [Phase 2 upgrade log](docs/PHASE2_UPGRADE_LOG.md) for cross-institution identity candidate review, intake utilization visibility, limitations, and validation status. The new reconciliation view is a local synthetic-data feature and is not official APAAR verification.

See [Phase 3 completion audit](docs/PHASE3_COMPLETION_AUDIT.md) for the feature-by-feature gap assessment against the agreed SIH requirements. It records what is implemented, what remains partial or missing, and which checks are still unverified.

See [Phase 4 upgrade log](docs/PHASE4_UPGRADE_LOG.md) for the additive central submission workflow, platform oversight role, snapshot integrity checks, limitations, and validation status.

### Central demo workflow

Institution administrators/operators can open **Central submissions** after at least one admissions enrolment has been submitted for review. They can create a versioned synthetic batch from eligible records for an academic year. A dedicated `platform_admin` account can inspect batches and record controlled review transitions in **Central oversight**.

To provision a separate central demo reviewer, first initialize the database and configure SMTP/email delivery for OTP sign-in, then run:

```powershell
python bootstrap_platform_admin.py
```

The script prompts for a unique username, email and password (minimum 16 characters). It does not modify an existing account. This role is for local synthetic prototype oversight only; it does not grant official AICTE authority.

The central batch is an internal demo snapshot, not an external submission. It excludes APAAR-like identifiers and email, and its SHA-256 digest is an integrity check only—not a signature. Institution-configured capacity flags are preliminary and are not approved-intake findings. Use synthetic data only.


## Database and backup

SQLite is the implemented local database. `APAAR_DB_PATH` selects the database file and defaults to `instance/apaar_demo.db`. The API uses this same file. The prior API-only database at `instance/apaar_backend.db` is left untouched and is not read by the current shared API; its records have not been merged.

At startup, the application checks for additive user, audit, student archive, duplicate-decision timestamp, import-history, case-history, and evidence metadata schema changes. Before changing an existing database, it creates and verifies a SQLite-consistent snapshot named `<database>.pre-upgrade-<UTC timestamp>.db`. Website local-validation rows migrate to canonical workflow cases through a documented deterministic ID map; source rows remain preserved. This migration was tested on a separate staging clone before the primary database was upgraded. See [the case migration map](docs/CASE_MIGRATION_MAPPING.md). You can create a manual backup while the app is stopped:

```powershell
python -c "import sqlite3; src=sqlite3.connect('instance/apaar_demo.db'); dst=sqlite3.connect('instance/apaar_demo.backup.db'); src.backup(dst); dst.close(); src.close()"
```

To rehearse recovery without replacing the current database, stop the app and copy one verified snapshot to a new file, then point a separate run at that copy:

```powershell
$recoveryPath = Join-Path (Resolve-Path 'instance').Path 'apaar_demo.recovery.db'
Copy-Item -LiteralPath 'instance\apaar_demo.pre-upgrade-<timestamp>.db' -Destination $recoveryPath
$env:APAAR_DB_PATH = $recoveryPath
python -c "import sqlite3,os; c=sqlite3.connect(os.environ['APAAR_DB_PATH']); print(c.execute('PRAGMA integrity_check').fetchone()[0]); c.close()"
python app.py
```

Replace `<timestamp>` with the exact backup filename. Verify the copied database before switching any live configuration; keep the original database and snapshot unchanged during recovery review.

The old API-only `instance/apaar_backend.db` has a different schema and contains legacy API data. It has not been merged or modified; keep it as an offline recovery source until its records can be mapped and reviewed. The canonical application uses `instance/apaar_demo.db`; its additive migration was run after a verified backup and staging-copy test. The earlier pre-upgrade snapshot remains intact.

## CSV format

The website importer requires `institution_student_id,full_name`; optional columns are `course,semester,apaar_id,email,notes`. It stores an institution-scoped preview, validates rows, warns about likely duplicate matches, exports row errors, and requires explicit confirmation. Confirmation inserts all valid rows in one transaction; invalid rows are reported and skipped. Exact file content is hashed to prevent repeated imports. Any CSV institution value is ignored in favor of the signed-in institution. Upload limit: 2 MB. API CSV dry-run does not write records.

The Review workspace is the central action list for open cases, pending duplicate decisions, records with quality findings, and import previews; each task links to its existing authorized page. The work-type filter and counts are institution-scoped. Student detail pages summarize the internal record label, quality findings, duplicate state, and related cases, with links to the next permitted action. Import previews link to the directory and review queue, and confirmed imports show a success message. The Review workspace also filters cases by active/status, priority, age, and reason/type. Its timeline shows recorded workflow events and separately labels audit records linked to that case or its evidence. Historical fields that are absent are identified as unavailable. Open-case age bands use `CASE_AGE_THRESHOLDS_DAYS` (default `(7, 30)`) and are internal review guidance, not official deadlines. The filtered report at `/api/v1/reports/cases.csv` is available to signed-in institution roles, uses the queue filters, excludes student names, contact details, codes, and free-text reasons, neutralizes spreadsheet formulas, and logs the export. Case type is used as the reason category; resolution outcome is represented by its internal terminal status. Institution administrators can assign active cases to active verifiers in their own institution; assignment, reassignment, and unassignment are recorded in the case timeline and audit events. Reviewer workload counts are limited to active institution-scoped cases. Case creation, assignment, and state changes use the existing authorized workflow and audit trail. Duplicate candidates show matching signals and whether course, semester, and email match, differ, or are missing. Email values are not displayed, and scores never decide identity. A reusable non-mutating data-quality check reports stable issue codes, severity, explanations, and suggested actions on student details and CSV previews. Checks cover required fields, the existing field-length limits, email syntax, incomplete course/semester values, and duplicate signals. The student schema has no date-of-birth field, so no date plausibility check is performed.

### Institution source database import and comparison

Institution administrators and data entry operators can register and import a CSV reference dataset at `/source-datasets`. Uploads are limited to UTF-8 CSV, 2 MB and 10,000 rows; the required columns are `institution_student_id` and `full_name`, with optional `course`, `semester`, and `email`. APAAR identifiers and notes are not accepted in institutional reference imports. The upload is validated and previewed before explicit confirmation. Confirmed source rows are stored in separate `institution_source_*` tables, with institution, dataset name, version, upload time, and importing user. Repeated file content is rejected for that institution. Invalid rows are excluded and duplicate institutional identifiers are rejected. New versions show added, removed, changed, and unchanged counts; changed rows list field names without storing old/new values in the summary. The original upload is not written to disk or modified.

Authorized operators, verifiers, and institution administrators can compare a student from the student detail page with the latest confirmed dataset. Institutional student ID is the only lookup key; name-only matching is never used. The result reports `MATCH`, `MISMATCH`, `NOT_FOUND`, or `REVIEW_REQUIRED`, per-field matched/differed/missing indicators, an explanation, and a manual-review flag. Missing data, duplicate source identifiers, and a pending operational duplicate candidate trigger human review. A review case and audit event are recorded for uncertain or differing outcomes. Comparisons never merge or alter student records. This is explicitly a comparison against institution-provided data and is not official APAAR/ABC/DigiLocker verification.

SQLite source database files and arbitrary server paths are not accepted. The application has no safe general-purpose schema mapping for arbitrary uploaded SQLite databases; CSV is the supported interchange format. Source rows are protected by institution-scoped queries and role checks, but share the application's SQLite file and are not encrypted at rest.

The dashboard includes institution-scoped student status distribution, open-case age bands, recent saved import outcomes, and links to existing pending work. Import and dashboard warning counts refer to rows with one or more warnings. Failed upload attempts are not persisted as import jobs. These task links are derived from current database state; persistent read/unread notifications are not implemented.

## Tests

```powershell
python -m pytest -q
```

The test suite runs with `python -m pytest -q` and covers Flask login, CSRF, login throttling, production first-admin safeguards, student archive/restoration, account administration, case migration and rollback, reviewer separation, evidence metadata, backup-before-migration, API/website shared IDs and updates, tenant isolation, rejected identity headers, API rollback, CSV preview/confirmation/idempotency/rollback, filtering/pagination, duplicate review, audit hash-chain tampering, audit metadata minimization, case timeline ordering, age categories, and case report authorization/privacy. Verification tests cover direct status tampering, legacy status normalization, identifier redaction, provider configuration and synthetic outcomes. Source dataset tests cover CSV import limits, tenant scope, rollback, version diffs, comparison outcomes, provenance, and audit behavior. A previous development run recorded 90 passing tests, but that result was not reproducible in the current packaging environment and does not include all later tests. The current full-suite result is **unverified** until `python -m pytest -q` succeeds in a configured virtual environment.

## Current security and workflow limits

- API identity headers are ignored; API calls require a signed-in Flask session. Page/API access is scoped to the institution stored on the user account. Opening Review and listing duplicate candidates are read-only; authorized operators/admins explicitly run a CSRF-protected duplicate scan.
- Institution administrators can create/deactivate accounts and assign operator, verifier, or auditor roles in their own institution. They cannot promote accounts to administrator or move users across institutions. Login throttling is process-local and resets on restart; sessions expire after eight hours. CSRF tokens are required for browser form posts and API state-changing requests (`X-CSRF-Token` header for JSON clients).
- The implemented role matrix is institution-scoped: institution administrators manage same-institution accounts and all scoped workflows; operators create/update records, import data, and open review work; verifiers review cases and make decisions; auditors have read-only pages and explicitly role-authorized, audited exports. Unknown roles are denied. A platform administrator and institution registry do not exist, so platform-wide administration is not implemented. Password reset/invitation workflows are not implemented; local account creation sets an initial password.
- Route-level permissions and institution scope are summarized in [the role permission matrix](docs/ROLE_PERMISSION_MATRIX.md). Case transitions use an optional `expected_updated_at` version token in the UI/API and an atomic status/version compare-and-update; stale edits return a conflict and do not emit a success audit event.
- Website validation history and API cases now use canonical `workflow_cases`, a shared transition service, case timeline, and API/UI. Legacy validation outcomes are preserved as `legacy-web:<id>` and mapped to `open` or informational `recorded` states; migration details are in `docs/CASE_MIGRATION_MAPPING.md`.
- Import preview, row validation, error reports, history, repeated-file protection, and an atomic confirmation transaction are implemented. Import retention/deletion and richer column mapping are not.
- Student archive is soft-delete. Institution administrators can restore records; conflicting institutional IDs require a replacement value, while the internal student ID and history are retained. There is no automated purge or retention schedule; archived rows remain in SQLite unless an authorized, separately planned retention process is introduced.
- This Phase 6 distribution contains the canonical Flask/Jinja application and does not include a separate React/Express prototype workspace. Run the app with `python app.py` from the repository root; the Flask application and SQLite database described above are the supported local demonstration path.
- Duplicate detection uses exact or thresholded normalized-name similarity plus email/course signals, records explanations, and requires a reviewer decision and reason. Tune `DUPLICATE_NAME_SIMILARITY` (default `0.88`). The schema has no date-of-birth field and there is no automatic merge. Evidence metadata is synthetic and non-file based; evidence file uploads are not implemented.
- The student directory has search, status filtering, and 50-row pagination. Dashboard metrics use institution-scoped database counts; import failures are not counted because failed import jobs are not persisted as a distinct status.
- SQLite is suitable for the local synthetic demo, not a multi-worker production deployment. The demo has no official provider integration and is not production-ready.
- No external identity provider is connected. Do not use real student data or describe this as production-ready or legally compliant.

See [the current state audit](docs/CURRENT_STATE_AUDIT.md) for verified architecture findings and remaining work.

## End-to-end demonstration

For a repeatable, isolated synthetic-data rehearsal, follow [the verification workbench walkthrough](docs/DEMO_WORKBENCH.md). It refuses to reuse an existing demo database path and keeps the primary and legacy databases separate.

## Database migration note

On first startup after this update, the app creates a verified SQLite backup before migrating student identifiers from globally unique to institution-scoped unique. Student IDs can then repeat across institutions but remain unique (case-insensitively) within each institution. If existing records already conflict within one institution, startup stops safely and asks you to resolve the duplicates first. Backups are written beside the database and should be retained until validation is complete.

### Admissions workflow hardening (Phase 4)

Capacity checks and enrolment creation are serialized in SQLite transactions; submission versioning rechecks the live workflow state under a write lock. Enrolment IDs are checked case-insensitively within the institution, and rejection/return decisions require a reason. See [Phase 4 implementation notes](docs/PHASE4_ADMISSIONS_HARDENING.md). The new regression tests are included, but the full suite must be rerun in the configured project virtual environment before relying on this build; Flask was not available in the packaging environment.
### Phase 5: data-use authorization register

The student profile now includes a purpose-limited internal authorization register. Admissions submission requires an unexpired authorization covering identity, academic records, and admissions records, and each submission version records the authorization used. This register is not a legal determination or proof that consent was validly obtained. See `docs/PHASE5_DATA_USE_AUTHORIZATION.md` for limitations and validation status.


### Current audit caveat

The current source has passed Python syntax compilation, but this environment does not have Flask/Werkzeug and cannot reach the package index. Consequently, no claim is made that the full Flask integration suite passes in this build. See `docs/ENGINEERING_STATUS.md` for the precise validation boundary and outstanding work.


See [Phase 2 upgrade log](docs/PHASE2_UPGRADE_LOG.md) for implemented changes, validation status, and limitations.



## Phase 5 — institution registry and service submission API

Phase 5 adds a platform-admin-managed **prototype institution registry** at `/central-institutions`. A platform administrator can register institutions, suspend/reactivate them, issue service credentials, and revoke credentials. Raw service tokens are shown only at issuance and are stored only as SHA-256 digests; store issued tokens in a secret manager and never commit them to source control.

The versioned service endpoint is `POST /api/v1/institution-submissions`. It requires:
- `Authorization: Bearer <service-token>`
- `Idempotency-Key: <unique key>` (8–128 characters)
- JSON containing `academic_year` and `records` (1–5,000 records)

Each record must include `institutional_enrolment_id`, `institution_student_id`, `student_name`, `programme_code`, `programme_name`, and `enrolment_status`. Optional `student_category` (`domestic`, `nri`, `oci`, `foreign_national`, `unknown`) and `seat_type` (`regular`, `supernumerary`) fields are available for monitoring; omitted values default to `unknown` and `regular`. These fields do not determine eligibility or encode category-specific seat-allocation rules. The API binds the batch to the institution associated with the credential; clients cannot choose another institution. Reusing an idempotency key with the same payload returns the original batch, while a different payload with that key returns HTTP 409. Identical content submitted with a new key is also rejected. Suspended institutions and revoked credentials cannot submit.

Example request body:

```json
{
  "academic_year": 2026,
  "records": [
    {
      "institutional_enrolment_id": "ENR-001",
      "institution_student_id": "STU-001",
      "student_name": "Synthetic Student",
      "programme_code": "CSE",
      "programme_name": "Computer Science",
      "enrolment_status": "submitted"
    }
  ]
}
```

Use the actual credential in the Authorization header and a fresh Idempotency-Key for each distinct submission. The payload deliberately excludes APAAR IDs, email addresses, dates of birth, Aadhaar numbers and raw identity documents.

**Important limitations:** the registry is not connected to an official institution directory and does not establish accreditation. The API is a prototype and has not been independently penetration-tested or load-tested. It has no external credential vault, rate limiter, background job queue, signed request payload, or official AICTE/APAAR/ABC/DigiLocker connection. The current SQLite storage and demo deployment are not a production hosting recommendation. Deploy behind HTTPS, keep credentials in managed secrets, rotate/revoke exposed tokens, and complete privacy/security review before using real student data. Official validation of intake references, authoritative supernumerary/category allocation rules, and external verification remain future work. Phase 6 provides only a transparent, institution-entered monitoring foundation.

See `docs/PHASE5_UPGRADE_LOG.md` for changes and validation status.

## Phase 6 — explainable admissions monitoring

Phase 6 adds versioned institution-entered approved-intake references, explicit student-category and seat-type classifications, and an institution-scoped **Admissions monitoring** page. The view separates approved counts from pending workflow records and flags missing intake references, intake excess, supernumerary-limit excess and missing category information. NRI, OCI and foreign-national counts are reported separately; the app does not invent category-specific seat-allocation rules. All reference values remain unverified until checked against the underlying authoritative source. These are operational review signals, not regulatory findings. See [Phase 6 admissions monitoring notes](docs/PHASE6_ADMISSIONS_MONITORING.md).

