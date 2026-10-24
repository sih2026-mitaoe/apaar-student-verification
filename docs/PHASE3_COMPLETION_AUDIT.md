# Phase 3 Completion Audit — SIH26263

Date: 2026-10-24
Reviewed artifact: `apaar-student-verification-phase3.zip`

## Executive finding

**The application is a useful local prototype, but Phases 1–3 are not yet complete against the agreed SIH-oriented target.** The archive contains several useful follow-on hardening changes documented as Phases 4 and 5, but the presence of those files is not evidence that their runtime behavior has passed the test suite. The next large feature phase should not be represented as complete or production-ready until the regression suite can run in the project's actual environment.

## Evidence-based feature matrix

| Requirement from the agreed plan | What is present in this archive | Audit status |
|---|---|---|
| Institution-scoped student records and local CRUD/import/export | Existing Flask/Jinja routes, tenant-scoped queries and CSV workflows | Present; full regression run unavailable |
| Exact cross-institution identity candidate review | `backend/identity_reconciliation.py`, `/identity-reconciliation`, template and focused tests | Implemented as a **demo-only shared-local-database feature**; not a secure central service |
| Mask foreign student identifier and avoid returning foreign PII | Reconciliation output masks the other institution's institutional ID and does not return foreign names/email | Present in the current helper; must be regression-tested |
| Probabilistic identity candidate matching | No calibrated multi-field probabilistic matcher or measured precision/recall is present | Missing |
| Verification provider boundary and authoritative result distinction | Existing verification module and UI distinguish synthetic/non-authoritative results in some workflows | Partial; no official APAAR/ABC/DigiLocker adapter |
| Approved intake registry with approval reference, effective dates and source provenance | `intake_allocations` has institution/programme/year/capacity/status; UI states capacity is institution-configured | Partial; no authoritative approval record or versioned category-specific seat rules |
| Basic admissions workflow | Programmes, intake allocations, enrolments, per-enrolment submission versions, review and capacity guard | Present as local prototype |
| Category-aware admissions rules (NRI/OCI/foreign-national and applicable supernumerary rules) | No complete configurable rules engine or evidence-backed category-specific calculation | Missing |
| Submission snapshot and digest | New submission snapshot JSON/hash and institution-scoped register | Present; hash is a change-detection digest, not a signature or proof of truth |
| Purpose-limited data-use authorization | Authorization records gate admissions submission and are audited | Present as an internal register; not legal validation or verified consent |
| Institution registry and central oversight role/dashboard | No institution registry or distinct platform-wide oversight dashboard/role is wired into the application | Missing |
| Institution-to-central batch submission API | No `/api/v1` submission/status/report endpoints are implemented in `app.py` or `backend/routes.py` | Missing |
| Centralized review queue connecting identity, intake and submission cases | Existing local review/case functions exist, but no complete central end-to-end workflow joins the three domains | Partial/missing |
| Production configuration | Production mode rejects placeholder secret and disables shared-database reconciliation; prior code did not force secure cookies when `APP_ENV=production` and only checked `FLASK_ENV` for the first admin password length | One concrete configuration defect fixed in this reviewed copy; new regression tests added, runtime test pending |
| Test suite | Python compilation succeeds; `pytest` collection fails here because Flask/Werkzeug are unavailable and package-index network access is unavailable | **Not verified** |

## Corrections made during this review

1. `SESSION_COOKIE_SECURE` is now forced on whenever the resolved application environment is production, even if `COOKIE_SECURE=0` or unset.
2. First-admin password-length enforcement now uses the same resolved production-mode decision as the rest of the app, including `APP_ENV=production`.
3. Added `tests/test_production_config.py` with isolated subprocess regressions for secure-cookie enforcement, demo reconciliation remaining disabled in production, and short first-admin password rejection under `APP_ENV=production`.
4. Preserved the existing workflows and database model; these are narrow hardening changes, not a schema rewrite.

## Validation performed for this review

- ZIP integrity: passed (`ZipFile.testzip()` returned no corrupt member).
- Python syntax compilation: passed for `app.py`, `backend/`, `tests/` and `bootstrap_admin.py`.
- Runtime test suite: blocked. This environment does not have Flask/Werkzeug installed; `python -m pytest -q tests/test_migrations.py` fails during collection with `ModuleNotFoundError: No module named 'flask'`. Installing requirements is not possible here because package-index network access is unavailable.
- The new subprocess tests are added but **not executed successfully in this environment** for the same dependency reason.

## Required before claiming the agreed plan is complete

1. Run `python -m pip install -r requirements.txt` in the project virtual environment, then `python -m pytest -q`; fix every failure before adding another feature phase.
2. Add institution isolation tests for every student, authorization, admissions, submission, export, and API path.
3. Add approved intake records with approval reference, source, effective dates and version history; keep institution-reported capacity separate from independently approved capacity.
4. Define explicit counting semantics for draft, submitted, under-review, approved, returned, rejected and withdrawn admissions; test category-specific rules rather than assuming every capacity allocation is interchangeable.
5. Implement a separate institution registry, a narrowly privileged central oversight role, and a central submission/report workflow. Ordinary institution users must not gain access to other institutions' personal data.
6. Implement explainable reconciliation case management and evaluate matching precision/recall against a labelled synthetic ground-truth dataset.
7. Keep official APAAR/ABC/DigiLocker verification clearly marked as unavailable until authorized interfaces, credentials and policy permissions exist.

## Safety boundary

Use synthetic records only for cross-institution demonstration in the current shared-database design. Do not expose the shared-database reconciliation route to real institutional records. Do not label a local format check, synthetic reference match, or reviewer workflow state as official identity verification.
