# Phase 2 Upgrade Log

Project: APAAR Student Data Management & Verification Platform (SIH26263)

## Baseline and guardrails
- Phase 1 stabilization is treated as completed by the project owner.
- Existing Flask/Jinja application, SQLite database, role checks, audit logs, admissions workflow, source-dataset comparison, imports, and case workflow are retained.
- Synthetic/demo data only. Local matching is not official APAAR, ABC, DigiLocker, or government verification.
- No automatic identity merge, fraud verdict, or record mutation is performed by reconciliation.

## Entry 2.1 — Cross-institution identity reconciliation candidate view
**Status:** Implemented in this change set; test status recorded below.

Files changed:
- `backend/identity_reconciliation.py` — new deterministic reconciliation rules.
- `app.py` — added `/identity-reconciliation`, role-gated to existing signed-in institution roles; records view in the audit log without writing identifier values into audit details.
- `templates/identity_reconciliation.html` — new review surface.
- `templates/base.html` — added navigation entry.
- `tests/test_identity_reconciliation.py` — tests exact identifier matching, conflicting names, masked identifiers, and archived-record exclusion.

Behavior:
- Uses exact normalized APAAR-like identifier matches across institutions as a candidate key. It does not use name-only matches.
- Compares names only to distinguish a matching name from a name conflict.
- Shows the current institution's student name and local ID, other institution name, and a masked other-institution student ID. It does not return foreign names, emails, notes, or full identifiers.
- A match is a review signal only; no identity status is changed and no records are merged.
- Each result carries a ruleset version for explainability.

Limitations / next step:
- This prototype currently computes candidates from the local shared SQLite dataset. It is not a secure central multi-tenant matching service and must not be exposed with real student data. A production design needs a separately authorized central matching service, minimal-disclosure controls, formal access policy, and appropriate protection for identifiers at rest/in transit.
- Records with missing identifiers cannot be cross-matched by this exact-key rule.

## Entry 2.2 — Intake utilization visibility
**Status:** Implemented in this change set; test status recorded below.

Files changed:
- `app.py` — calculates utilization percentage, remaining capacity, and an over-capacity flag from existing enrolment counts.
- `templates/admissions.html` — displays utilization and remaining capacity and warns if counts exceed configured capacity.
- `static/design-system.css` — adds a compact utilization indicator and responsive table sizing.

Behavior:
- Counts continue to exclude withdrawn and rejected enrolments, consistent with the existing query.
- Capacity is explicitly labelled as institution-configured, not independently confirmed against an official approval record.
- This is an exception-reporting view; it does not change intake capacity or enrolment decisions.

## Validation
- Python syntax compilation: **passed** (`python -m compileall -q app.py backend tests`).
- Identity reconciliation logic smoke test: **passed** using a standalone loader.
- Targeted pytest collection: **blocked in this packaging environment** because Flask is not installed (`ModuleNotFoundError: No module named 'flask'`).
- Full pytest suite: **not run / unverified** until run in the project's configured virtual environment.

## Next planned entries
1. Add a central submission register with versioned snapshots and explicit validation/return/acceptance states, without pretending it submits to AICTE.
2. Add a central oversight role and institution registry only after defining tenant access rules; do not grant ordinary institution users broad access to other institutions' student data.
3. Expand regression coverage for institution isolation, intake calculations, and the new UI.


## Entry 2.3 — Versioned admissions submission register
**Status:** Implemented in this change set; runtime tests remain unverified in the packaging environment.

Files changed:
- `app.py` — additive SQLite columns for immutable submission snapshot JSON and SHA-256 digest; snapshot creation during authorized submission; institution-scoped submission register route.
- `templates/admissions_submissions.html` — new filtered register with submission version, status, timestamps, reviewer, and abbreviated snapshot digest.
- `templates/admissions.html` and `templates/base.html` — navigation from admissions workspace.
- `tests/test_admissions_workflow.py` — asserts snapshot contents, omission of APAAR ID/email, digest correctness, and register visibility.

Behavior:
- Every newly submitted version captures a minimal snapshot of the enrolment, local student ID/name, course/semester, programme, intake year, and configured capacity. Full APAAR-like identifiers and email are excluded.
- The snapshot is serialized deterministically and its SHA-256 digest is stored alongside it. The digest is an integrity aid, not a digital signature or tamper-proof guarantee.
- The register is filtered by the signed-in user's institution and uses join conditions that keep related records institution-scoped.
- Existing submissions remain readable; legacy versions have empty snapshots and are labelled as legacy.
- No external or government submission is claimed.

Validation:
- `python -m compileall -q app.py backend tests`: passed after this change.
- Full Flask tests: not run because Flask could not be installed in this network-isolated environment.

Next: continue with focused tenant-isolation tests and review of reconciliation disclosure boundaries before introducing any central oversight role or shared registry.


## Security hardening — shared-database reconciliation opt-in
The identity reconciliation page reads records from the shared local SQLite database. To reduce accidental disclosure, the route is now disabled by default and is not enabled in production mode. To demonstrate it, set `ENABLE_SHARED_DEMO_RECONCILIATION=1` only in an isolated environment populated exclusively with synthetic data. The navigation entry appears only when this opt-in is active. This does not make shared-database matching production-safe; a separately authorized central matching service and access policy are still required.

## Validation after submission-register and disclosure-guard changes
- `python -m compileall -q app.py backend tests`: passed.
- Runtime pytest suite: still blocked because Flask is not installed and this environment cannot reach the package index.
- No production database was opened or modified during this work; all changes were made in an extracted working copy of the uploaded ZIP.
