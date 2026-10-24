# Phase 6 — Explainable admissions monitoring

## Objective

Move closer to SIH26263's admissions-monitoring requirements without inventing regulatory allocation rules or claiming that institution-entered values are official/verified.

## Added

- `approved_intake_records`: versioned, institution-scoped intake reference records with sanctioned intake, a supernumerary limit, approval/order reference, source/evidence reference, optional approval date, recorder and timestamp.
- Recording a new intake reference supersedes the previous current version; previous versions remain visible in history.
- `enrolments.student_category`: `domestic`, `nri`, `oci`, `foreign_national`, or `unknown`.
- `enrolments.seat_type`: `regular` or `supernumerary`.
- Existing records migrate safely with `unknown` category and `regular` seat type defaults. The existing startup backup-before-schema-upgrade path now recognizes the added table/columns.
- An institution-scoped **Admissions monitoring** view compares active workflow counts with the latest recorded intake reference and shows approved counts separately from pending counts.
- Explainable signals include missing intake reference, approved intake exceeded, potential excess including pending submissions, supernumerary limit exceeded/potential excess, and missing category information.
- Separate NRI, OCI, foreign-national and domestic counts; no category-to-seat consumption assumptions are hard-coded.
- Classification can be corrected while an enrolment is draft or returned for correction. The classification and seat type are included in the frozen local submission snapshot.
- The institution API accepts optional `student_category` and `seat_type` fields with backwards-compatible defaults. Central batch snapshots display those fields where available. API payload types are validated, duplicate enrolment IDs are checked case-insensitively, and the idempotency/content check plus batch creation now run under a SQLite immediate write transaction to prevent concurrent duplicate creation.
- Added regression tests for schema, version history, monitoring flags, and institution isolation.

## Counting semantics

- Active workflow count includes `submitted`, `under_review`, `approved`, and `returned_for_correction`.
- Approved count includes only `approved` enrolments.
- Pending count includes `submitted`, `under_review`, and `returned_for_correction`.
- Draft, rejected and withdrawn records are excluded from these monitoring counts.
- A confirmed intake-exceeded signal is raised when approved enrolments exceed the recorded sanctioned intake. A potential excess signal is raised when active workflow records exceed it but approved records do not.
- Supernumerary counts are compared only with the institution-recorded supernumerary limit.

## Explicit limitations

- Approved-intake and supernumerary figures are entered by an institution user and are **not independently verified** against an official order or AICTE system. A source reference is recorded, but the application does not upload or authenticate the source document.
- These signals are operational review prompts, not findings of regulatory non-compliance.
- NRI/OCI/foreign-national categories are reported separately. The app does not determine eligibility, infer seat allocation, or encode legal rules for category-specific treatment.
- The current central batch process still has its own preliminary configured-capacity signal; this phase does not claim to provide a complete central AICTE-approved-intake rules engine.
- Existing historical enrolments default to `unknown` category and `regular` seat type. Users must review and correct synthetic records as appropriate.
- Official APAAR/ABC/DigiLocker/AICTE verification and production deployment remain out of scope.

## Validation status for this package

- Python syntax compilation: passed for all Python files.
- Jinja template parsing: passed for all templates.
- SQLite DDL/schema smoke test: passed; `PRAGMA integrity_check` returned `ok`; new columns and table are present.
- ZIP integrity: checked after packaging.
- Flask integration tests: not executed in this build environment because Flask/Werkzeug are not installed and package-index access is unavailable. The added tests are included but remain unverified until run in the project virtual environment.
