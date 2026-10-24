import csv
import hashlib
import io
import json
import os
import re
import hmac
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, Response, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from backend.audit import verify_chain
from backend.audit import record_event
from backend.cases import create_case
from backend.data_quality import validate_student_record
from backend.readiness import score_student_readiness
from backend.source_data import (parse_source_csv, compare_student, encode_preview,
                                 version_diff, MAX_SOURCE_BYTES,
                                 SOURCE_COMPARISON_RULESET_VERSION)
from backend.verification import provider_configuration
from backend.identity_reconciliation import reconcile_records, RULESET_VERSION as IDENTITY_RECONCILIATION_RULESET_VERSION

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
except ImportError:
    pass

# ---------------------------------------------------------
# Application configuration
# ---------------------------------------------------------

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get(
    "APAAR_DB_PATH",
    os.path.join(APP_DIR, "instance", "apaar_demo.db")
)

os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

app = Flask(__name__)
def resolve_secret_key(value, production=False):
    """Reject documented placeholders and generate only a local-dev fallback."""
    candidate = (value or "").strip()
    is_placeholder = (
        not candidate
        or candidate.lower().startswith("replace-with-")
        or candidate == "development-only-change-me"
    )
    if is_placeholder:
        if production:
            raise RuntimeError("Set a private SECRET_KEY before starting in production mode")
        return secrets.token_hex(32)
    return candidate


production_mode = (
    os.environ.get("APP_ENV", "").strip().lower() == "production"
    or os.environ.get("FLASK_ENV", "").strip().lower() == "production"
)
app.secret_key = resolve_secret_key(os.environ.get("SECRET_KEY", ""), production=production_mode)
app.config["APAAR_DB_PATH"] = DB_PATH
# Shared-database cross-institution matching is a demo-only capability. It is
# opt-in and never enabled in production mode.
app.config["ENABLE_SHARED_DEMO_RECONCILIATION"] = (
    not production_mode and os.environ.get("ENABLE_SHARED_DEMO_RECONCILIATION", "0").strip() == "1"
)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Secure cookies are mandatory in production regardless of a stale or
    # accidentally unset COOKIE_SECURE environment variable.
    SESSION_COOKIE_SECURE=(
        production_mode or os.environ.get("COOKIE_SECURE", "0").strip() == "1"
    ),
    PERMANENT_SESSION_LIFETIME=8 * 60 * 60,
)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
app.config["CASE_AGE_THRESHOLDS_DAYS"] = (7, 30)
LOGIN_FAILURE_LIMIT = 5
LOGIN_FAILURE_WINDOW = 15 * 60
login_failures = {}


@app.before_request
def protect_cookie_authenticated_posts():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return None
    # Machine API requests are authenticated independently with scoped bearer
    # credentials; browser/session routes remain protected by CSRF.
    if request.path == "/api/v1/institution-submissions":
        return None
    supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
    expected = session.get("_csrf_token", "")
    if not expected or not hmac.compare_digest(expected, supplied):
        abort(400, description="The request security token is missing or invalid.")


def backup_before_schema_upgrade():
    """Create a consistent SQLite snapshot before additive startup migrations."""
    if not os.path.isfile(DB_PATH) or os.path.getsize(DB_PATH) == 0:
        return
    source = sqlite3.connect(DB_PATH)
    try:
        tables = {row[0] for row in source.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        if not tables:
            return
        required_tables = {"users", "audit_logs", "workflow_cases", "duplicate_candidates", "audit_events", "import_jobs", "import_job_rows", "case_events", "case_evidence", "verification_runs", "verification_rule_results", "app_migrations", "institution_source_datasets", "institution_source_uploads", "institution_source_records", "institution_source_comparisons", "programmes", "intake_allocations", "enrolments", "enrolment_submissions", "data_use_authorizations", "central_submission_batches", "central_submission_events", "institution_registry", "institution_api_credentials", "institution_api_idempotency", "approved_intake_records"}
        missing_tables = required_tables - tables
        needs_upgrade = bool(missing_tables)
        triggers = {row[0] for row in source.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger'"
        )}
        required_triggers = {
            "trg_case_events_scope_insert", "trg_case_evidence_scope_insert",
            "trg_workflow_case_student_insert", "trg_workflow_case_student_update",
        }
        needs_upgrade = needs_upgrade or bool(required_triggers - triggers)
        for table, column in (("users", "institution"), ("audit_logs", "institution")):
            if table in tables:
                columns = {row[1] for row in source.execute(f"PRAGMA table_info({table})")}
                needs_upgrade = needs_upgrade or column not in columns
        if "students" in tables:
            student_columns = {row[1] for row in source.execute("PRAGMA table_info(students)")}
            needs_upgrade = needs_upgrade or "archived_at" not in student_columns
        if "enrolments" in tables:
            enrolment_columns = {row[1] for row in source.execute("PRAGMA table_info(enrolments)")}
            needs_upgrade = needs_upgrade or not {"student_category", "seat_type"}.issubset(enrolment_columns)
        if "enrolment_submissions" in tables:
            submission_columns = {row[1] for row in source.execute("PRAGMA table_info(enrolment_submissions)")}
            needs_upgrade = needs_upgrade or not {"authorization_id", "snapshot_json", "snapshot_hash"}.issubset(submission_columns)
        if "institution_source_uploads" in tables:
            source_columns = {row[1] for row in source.execute("PRAGMA table_info(institution_source_uploads)")}
            needs_upgrade = needs_upgrade or "change_summary_json" not in source_columns
        if "duplicate_candidates" in tables:
            candidate_columns = {row[1] for row in source.execute("PRAGMA table_info(duplicate_candidates)")}
            needs_upgrade = needs_upgrade or "decided_at" not in candidate_columns
        if "workflow_cases" in tables:
            case_columns = {row[1] for row in source.execute("PRAGMA table_info(workflow_cases)")}
            needs_upgrade = needs_upgrade or not {"legacy_source", "legacy_id", "legacy_status", "reviewer_id", "decision_at"}.issubset(case_columns)
        if "users" in tables:
            user_columns = {row[1] for row in source.execute("PRAGMA table_info(users)")}
            needs_upgrade = needs_upgrade or not {"is_active", "created_at", "updated_at"}.issubset(user_columns)
        if not needs_upgrade:
            return
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        database_name = os.path.splitext(os.path.basename(DB_PATH))[0]
        backup_path = os.path.join(os.path.dirname(DB_PATH), f"{database_name}.pre-upgrade-{stamp}.db")
        destination = sqlite3.connect(backup_path)
        try:
            source.backup(destination)
        finally:
            destination.close()
        verification = sqlite3.connect(backup_path)
        try:
            if verification.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise RuntimeError("Pre-upgrade database backup failed its integrity check")
            original_tables = {row[0] for row in source.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            copied_tables = {row[0] for row in verification.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if original_tables != copied_tables:
                raise RuntimeError("Pre-upgrade database backup has a different table set")
            for table_name in original_tables:
                quoted = '"' + table_name.replace('"', '""') + '"'
                source_count = source.execute(f"SELECT COUNT(*) FROM {quoted}").fetchone()[0]
                backup_count = verification.execute(f"SELECT COUNT(*) FROM {quoted}").fetchone()[0]
                if source_count != backup_count:
                    raise RuntimeError(f"Pre-upgrade database backup row count differs for {table_name}")
        finally:
            verification.close()
    finally:
        source.close()


backup_before_schema_upgrade()

# Register the additional backend API.
# This does not replace any existing Flask pages or routes.
from backend import register_backend
register_backend(app)


# ---------------------------------------------------------
# Database and utility functions
# ---------------------------------------------------------

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def spreadsheet_safe(value):
    text = str(value or "")
    if text.lstrip(" \t\r\n").startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + text
    return text


class ClosingSQLiteConnection(sqlite3.Connection):
    """Commit/rollback on context exit and always release the SQLite handle.

    sqlite3's built-in connection context manager does not close the connection.
    Most routes use ``with connect_db()``; closing here avoids accumulating open
    handles and reduces file-lock surprises on Windows. Explicitly managed
    connections continue to work and can still call ``close()`` themselves.
    """

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


def connect_db():
    db = sqlite3.connect(DB_PATH, factory=ClosingSQLiteConnection, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA busy_timeout=15000")
    return db


def init_db():
    app.config["APAAR_DB_PATH"] = DB_PATH
    with connect_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'admin',
            institution TEXT NOT NULL DEFAULT 'MITAOE Demo Campus',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT,
            updated_at TEXT
        );

        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            institution_student_id TEXT NOT NULL UNIQUE,
            full_name TEXT NOT NULL,
            institution TEXT NOT NULL DEFAULT 'Demo Institution',
            course TEXT NOT NULL DEFAULT '',
            semester TEXT NOT NULL DEFAULT '',
            apaar_id TEXT NOT NULL DEFAULT '',
            email TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'Pending verification',
            notes TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            archived_at TEXT
        );

        CREATE TABLE IF NOT EXISTS verification_cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            summary TEXT NOT NULL,
            findings TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT 'Local rule engine',
            created_at TEXT NOT NULL,
            FOREIGN KEY(student_id)
                REFERENCES students(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            institution TEXT NOT NULL DEFAULT 'MITAOE Demo Campus',
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            entity TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            details TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS app_migrations (
            name TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS import_jobs (
            id TEXT PRIMARY KEY,
            institution TEXT NOT NULL,
            created_by TEXT NOT NULL,
            file_name TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'preview',
            accepted_count INTEGER NOT NULL DEFAULT 0,
            rejected_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            confirmed_at TEXT,
            UNIQUE(institution, content_hash)
        );

        CREATE TABLE IF NOT EXISTS import_job_rows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id TEXT NOT NULL,
            row_number INTEGER NOT NULL,
            student_code TEXT NOT NULL DEFAULT '',
            full_name TEXT NOT NULL DEFAULT '',
            course TEXT NOT NULL DEFAULT '',
            semester TEXT NOT NULL DEFAULT '',
            apaar_id TEXT NOT NULL DEFAULT '',
            email TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            errors_json TEXT NOT NULL DEFAULT '[]',
            warnings_json TEXT NOT NULL DEFAULT '[]',
            is_valid INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(job_id) REFERENCES import_jobs(id) ON DELETE CASCADE,
            UNIQUE(job_id, row_number)
        );

        CREATE TABLE IF NOT EXISTS programmes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            institution TEXT NOT NULL,
            code TEXT NOT NULL,
            name TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(institution, code)
        );

        CREATE TABLE IF NOT EXISTS intake_allocations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            institution TEXT NOT NULL,
            programme_id INTEGER NOT NULL,
            intake_year INTEGER NOT NULL,
            capacity INTEGER NOT NULL CHECK(capacity > 0),
            status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('draft','open','closed')),
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(institution, programme_id, intake_year),
            FOREIGN KEY(programme_id) REFERENCES programmes(id) ON DELETE RESTRICT
        );

        CREATE TABLE IF NOT EXISTS approved_intake_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            institution TEXT NOT NULL,
            programme_id INTEGER NOT NULL,
            intake_year INTEGER NOT NULL,
            version INTEGER NOT NULL CHECK(version > 0),
            sanctioned_intake INTEGER NOT NULL CHECK(sanctioned_intake > 0),
            supernumerary_limit INTEGER NOT NULL DEFAULT 0 CHECK(supernumerary_limit >= 0),
            approval_reference TEXT NOT NULL,
            source_reference TEXT NOT NULL,
            approval_date TEXT,
            status TEXT NOT NULL DEFAULT 'current' CHECK(status IN ('current','superseded')),
            recorded_by TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            superseded_at TEXT,
            UNIQUE(institution,programme_id,intake_year,version),
            FOREIGN KEY(programme_id) REFERENCES programmes(id) ON DELETE RESTRICT
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_approved_intake_current
            ON approved_intake_records(institution,programme_id,intake_year) WHERE status='current';

        CREATE TABLE IF NOT EXISTS enrolments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            institution TEXT NOT NULL,
            student_id INTEGER NOT NULL,
            allocation_id INTEGER NOT NULL,
            institutional_enrolment_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','submitted','under_review','approved','rejected','withdrawn','returned_for_correction')),
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(institution, institutional_enrolment_id),
            UNIQUE(student_id, allocation_id),
            FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE RESTRICT,
            FOREIGN KEY(allocation_id) REFERENCES intake_allocations(id) ON DELETE RESTRICT
        );
        CREATE INDEX IF NOT EXISTS idx_enrolments_institution_status ON enrolments(institution,status,updated_at);

        CREATE TABLE IF NOT EXISTS enrolment_submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            institution TEXT NOT NULL,
            enrolment_id INTEGER NOT NULL,
            version INTEGER NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('submitted','under_review','approved','rejected','returned_for_correction')),
            submitted_by TEXT NOT NULL,
            submitted_at TEXT NOT NULL,
            reviewed_by TEXT,
            reviewed_at TEXT,
            review_note TEXT NOT NULL DEFAULT '',
            authorization_id INTEGER REFERENCES data_use_authorizations(id) ON DELETE RESTRICT,
            UNIQUE(enrolment_id, version),
            FOREIGN KEY(enrolment_id) REFERENCES enrolments(id) ON DELETE RESTRICT
        );

        CREATE TABLE IF NOT EXISTS data_use_authorizations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            institution TEXT NOT NULL,
            student_id INTEGER NOT NULL,
            purpose TEXT NOT NULL CHECK(purpose IN ('admissions_submission','verification_review','source_comparison')),
            authority_basis TEXT NOT NULL CHECK(authority_basis IN ('consent','guardian_authorization','statutory_authority','institutional_policy','other_authority')),
            data_categories_json TEXT NOT NULL,
            evidence_reference TEXT NOT NULL DEFAULT '',
            note TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','withdrawn')),
            valid_until TEXT,
            recorded_by TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            withdrawn_by TEXT,
            withdrawn_at TEXT,
            FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE RESTRICT
        );
        CREATE INDEX IF NOT EXISTS idx_data_use_authorizations_student
            ON data_use_authorizations(institution, student_id, purpose, recorded_at DESC);

        CREATE TABLE IF NOT EXISTS institution_source_datasets (
            id TEXT PRIMARY KEY,
            institution TEXT NOT NULL,
            name TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(institution,name)
        );
        CREATE TABLE IF NOT EXISTS institution_source_uploads (
            id TEXT PRIMARY KEY,
            institution TEXT NOT NULL,
            dataset_id TEXT,
            dataset_name TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 0,
            created_by TEXT NOT NULL,
            file_name TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'preview',
            preview_json TEXT NOT NULL,
            accepted_count INTEGER NOT NULL,
            rejected_count INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            confirmed_at TEXT,
            change_summary_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(institution,content_hash),
            FOREIGN KEY(dataset_id) REFERENCES institution_source_datasets(id) ON DELETE RESTRICT
        );
        CREATE TABLE IF NOT EXISTS institution_source_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            institution TEXT NOT NULL,
            dataset_id TEXT NOT NULL,
            upload_id TEXT NOT NULL,
            dataset_version INTEGER NOT NULL,
            row_number INTEGER NOT NULL,
            institution_student_id TEXT NOT NULL,
            full_name TEXT NOT NULL,
            course TEXT NOT NULL DEFAULT '',
            semester TEXT NOT NULL DEFAULT '',
            email TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(dataset_id) REFERENCES institution_source_datasets(id) ON DELETE RESTRICT,
            FOREIGN KEY(upload_id) REFERENCES institution_source_uploads(id) ON DELETE RESTRICT
        );
        CREATE INDEX IF NOT EXISTS idx_source_records_lookup
            ON institution_source_records(institution,dataset_id,dataset_version,institution_student_id);
        CREATE TABLE IF NOT EXISTS institution_source_comparisons (
            id TEXT PRIMARY KEY,
            institution TEXT NOT NULL,
            dataset_id TEXT NOT NULL,
            dataset_version INTEGER NOT NULL,
            student_id INTEGER NOT NULL,
            actor TEXT NOT NULL,
            outcome TEXT NOT NULL,
            explanation TEXT NOT NULL,
            fields_json TEXT NOT NULL,
            run_status TEXT NOT NULL DEFAULT 'completed',
            ruleset_version TEXT NOT NULL DEFAULT 'institution-source-comparison-v1',
            input_digest TEXT NOT NULL DEFAULT '',
            result_digest TEXT NOT NULL DEFAULT '',
            student_updated_at_snapshot TEXT NOT NULL DEFAULT '',
            outcome_counts_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE RESTRICT,
            FOREIGN KEY(dataset_id) REFERENCES institution_source_datasets(id) ON DELETE RESTRICT
        );

        CREATE TABLE IF NOT EXISTS central_submission_batches (
            id TEXT PRIMARY KEY,
            institution TEXT NOT NULL,
            version INTEGER NOT NULL,
            academic_year INTEGER NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('submitted','processing','requires_review','accepted','returned_for_correction','superseded')),
            submitted_by TEXT NOT NULL,
            submitted_at TEXT NOT NULL,
            reviewed_by TEXT,
            reviewed_at TEXT,
            review_note TEXT NOT NULL DEFAULT '',
            record_count INTEGER NOT NULL CHECK(record_count >= 0),
            flagged_count INTEGER NOT NULL DEFAULT 0 CHECK(flagged_count >= 0),
            previous_batch_id TEXT,
            content_hash TEXT NOT NULL,
            snapshot_json TEXT NOT NULL,
            UNIQUE(institution, version),
            UNIQUE(institution, content_hash),
            FOREIGN KEY(previous_batch_id) REFERENCES central_submission_batches(id) ON DELETE RESTRICT
        );
        CREATE INDEX IF NOT EXISTS idx_central_batches_status_date
            ON central_submission_batches(status, submitted_at DESC);
        CREATE INDEX IF NOT EXISTS idx_central_batches_institution
            ON central_submission_batches(institution, submitted_at DESC);

        CREATE TABLE IF NOT EXISTS central_submission_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id TEXT NOT NULL,
            institution TEXT NOT NULL,
            actor TEXT NOT NULL,
            event_type TEXT NOT NULL,
            from_status TEXT,
            to_status TEXT,
            note TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY(batch_id) REFERENCES central_submission_batches(id) ON DELETE RESTRICT
        );
        CREATE INDEX IF NOT EXISTS idx_central_submission_events_batch
            ON central_submission_events(batch_id, id);

        CREATE TABLE IF NOT EXISTS institution_registry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            institution_code TEXT NOT NULL UNIQUE,
            institution_name TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','suspended')),
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS institution_api_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            institution_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            token_prefix TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_used_at TEXT,
            revoked_at TEXT,
            FOREIGN KEY(institution_id) REFERENCES institution_registry(id) ON DELETE RESTRICT
        );
        CREATE INDEX IF NOT EXISTS idx_institution_api_credentials_active
            ON institution_api_credentials(institution_id, revoked_at);
        CREATE TABLE IF NOT EXISTS institution_api_idempotency (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            institution_id INTEGER NOT NULL,
            idempotency_key TEXT NOT NULL,
            request_hash TEXT NOT NULL,
            batch_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(institution_id, idempotency_key),
            FOREIGN KEY(institution_id) REFERENCES institution_registry(id) ON DELETE RESTRICT,
            FOREIGN KEY(batch_id) REFERENCES central_submission_batches(id) ON DELETE RESTRICT
        );

        CREATE INDEX IF NOT EXISTS idx_students_name
            ON students(full_name);

        CREATE INDEX IF NOT EXISTS idx_students_status
            ON students(status);
        """)

        enrolment_columns = {row[1] for row in db.execute("PRAGMA table_info(enrolments)")}
        if "student_category" not in enrolment_columns:
            db.execute("ALTER TABLE enrolments ADD COLUMN student_category TEXT NOT NULL DEFAULT 'unknown'")
        if "seat_type" not in enrolment_columns:
            db.execute("ALTER TABLE enrolments ADD COLUMN seat_type TEXT NOT NULL DEFAULT 'regular'")
        user_columns = {row[1] for row in db.execute("PRAGMA table_info(users)")}
        if "institution" not in user_columns:
            db.execute("ALTER TABLE users ADD COLUMN institution TEXT NOT NULL DEFAULT 'MITAOE Demo Campus'")
        if "is_active" not in user_columns:
            db.execute("ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")
        if "created_at" not in user_columns:
            db.execute("ALTER TABLE users ADD COLUMN created_at TEXT")
        if "updated_at" not in user_columns:
            db.execute("ALTER TABLE users ADD COLUMN updated_at TEXT")
        if "email" not in user_columns:
            db.execute("ALTER TABLE users ADD COLUMN email TEXT")
        if "email_verified_at" not in user_columns:
            db.execute("ALTER TABLE users ADD COLUMN email_verified_at TEXT")
        if "session_version" not in user_columns:
            db.execute("ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0")
        db.execute("""
            CREATE TABLE IF NOT EXISTS auth_challenges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                purpose TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                consumed_at REAL,
                request_ip TEXT
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_auth_challenges_user ON auth_challenges(username,purpose,created_at)")
        db.execute("UPDATE users SET created_at=COALESCE(created_at,?), updated_at=COALESCE(updated_at,?)",
                   (now(), now()))
        audit_columns = {row[1] for row in db.execute("PRAGMA table_info(audit_logs)")}
        if "institution" not in audit_columns:
            db.execute("ALTER TABLE audit_logs ADD COLUMN institution TEXT NOT NULL DEFAULT 'MITAOE Demo Campus'")
        student_columns = {row[1] for row in db.execute("PRAGMA table_info(students)")}
        if "archived_at" not in student_columns:
            db.execute("ALTER TABLE students ADD COLUMN archived_at TEXT")
        source_upload_columns = {row[1] for row in db.execute("PRAGMA table_info(institution_source_uploads)")}
        if "change_summary_json" not in source_upload_columns:
            db.execute("ALTER TABLE institution_source_uploads ADD COLUMN change_summary_json TEXT NOT NULL DEFAULT '{}'")
        comparison_columns = {row[1] for row in db.execute("PRAGMA table_info(institution_source_comparisons)")}
        comparison_additions = {
            "run_status": "TEXT NOT NULL DEFAULT 'completed'",
            "ruleset_version": "TEXT NOT NULL DEFAULT 'institution-source-comparison-v1'",
            "input_digest": "TEXT NOT NULL DEFAULT ''",
            "result_digest": "TEXT NOT NULL DEFAULT ''",
            "student_updated_at_snapshot": "TEXT NOT NULL DEFAULT ''",
            "outcome_counts_json": "TEXT NOT NULL DEFAULT '{}'",
        }
        for column, declaration in comparison_additions.items():
            if column not in comparison_columns:
                db.execute(f"ALTER TABLE institution_source_comparisons ADD COLUMN {column} {declaration}")
        submission_columns = {row[1] for row in db.execute("PRAGMA table_info(enrolment_submissions)")}
        if "authorization_id" not in submission_columns:
            db.execute("ALTER TABLE enrolment_submissions ADD COLUMN authorization_id INTEGER REFERENCES data_use_authorizations(id) ON DELETE RESTRICT")
        if "snapshot_json" not in submission_columns:
            db.execute("ALTER TABLE enrolment_submissions ADD COLUMN snapshot_json TEXT NOT NULL DEFAULT '{}'")
        if "snapshot_hash" not in submission_columns:
            db.execute("ALTER TABLE enrolment_submissions ADD COLUMN snapshot_hash TEXT NOT NULL DEFAULT ''")

        admin_exists = db.execute(
            "SELECT id FROM users WHERE username='admin'"
        ).fetchone()
        if not admin_exists:
            admin_password = os.environ.get("DEMO_ADMIN_PASSWORD", "")
            if (not admin_password
                    or admin_password.startswith("replace-with-")):
                raise RuntimeError(
                    "Set DEMO_ADMIN_PASSWORD in your private .env before initializing the first admin"
                )
            if production_mode and len(admin_password) < 16:
                raise RuntimeError(
                    "Set a private DEMO_ADMIN_PASSWORD of at least 16 characters before initializing the production admin"
                )
            db.execute(
                "INSERT INTO users(username,password_hash,role,institution,is_active,created_at,updated_at,email) VALUES(?,?,?,?,1,?,?,?)",
                (
                    "admin",
                    generate_password_hash(admin_password),
                    "admin",
                    "MITAOE Demo Campus",
                    now(),
                    now(),
                    os.environ.get("DEMO_ADMIN_EMAIL", "").strip().lower() or None,
                ),
            )

        if db.execute(
            "SELECT COUNT(*) FROM students"
        ).fetchone()[0] == 0:
            sample = [
                (
                    "DEMO-1001", "Aarav Sharma", "MITAOE Demo Campus",
                    "Computer Engineering", "4", "DEMO-APAAR-0001",
                    "aarav@example.test", "Pending verification",
                    "Synthetic demo record",
                ),
                (
                    "DEMO-1002", "Ananya Patil", "MITAOE Demo Campus",
                    "Information Technology", "3", "DEMO-APAAR-0002",
                    "ananya@example.test", "Pending verification",
                    "Synthetic demo record",
                ),
                (
                    "DEMO-1003", "Rohan Kulkarni", "MITAOE Demo Campus",
                    "Computer Engineering", "4", "DEMO-APAAR-0003",
                    "rohan@example.test", "Needs review",
                    "Synthetic demo record",
                ),
                (
                    "DEMO-1004", "Ananya Patil", "MITAOE Demo Campus",
                    "Information Technology", "3", "DEMO-APAAR-0004",
                    "ananya2@example.test", "Pending verification",
                    "Synthetic duplicate candidate for demonstration",
                ),
            ]

            for row in sample:
                db.execute("""
                    INSERT INTO students(
                        institution_student_id, full_name, institution,
                        course, semester, apaar_id, email, status,
                        notes, created_at, updated_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                """, (*row, now(), now()))

            db.execute("""
                INSERT INTO audit_logs(
                    actor, action, entity, entity_id, details, created_at
                ) VALUES(?,?,?,?,?,?)
            """, (
                "system", "seed_demo_data", "students", "4",
                "Inserted synthetic sample records", now()
            ))

        legacy_counts = db.execute("""SELECT institution,COUNT(*) AS count FROM students
            WHERE lower(trim(status)) IN ('verified','pending','failed') GROUP BY institution""").fetchall()
        db.execute("UPDATE students SET status='Needs review' WHERE lower(trim(status))='verified'")
        db.execute("UPDATE students SET status='Pending verification' WHERE lower(trim(status))='pending'")
        db.execute("UPDATE students SET status='Failed to verify' WHERE lower(trim(status))='failed'")
        for legacy in legacy_counts:
            db.execute("""INSERT INTO audit_logs(institution,actor,action,entity,entity_id,details,created_at)
                VALUES(?, 'system','legacy_status_migration','students','status-labels',?,?)""",
                (legacy["institution"], f"Normalized {legacy['count']} legacy status labels; ambiguous Verified mapped to Needs review.", now()))

        db.commit()

    # Migrate the legacy global student-code constraint to institution scope.
    from backend.migrations import migrate_student_identifier_scope, migrate_admissions_workflow_schema
    migrate_student_identifier_scope(DB_PATH)
    migrate_admissions_workflow_schema(DB_PATH)

    # The website verification table is created above. Run the idempotent
    # bridge after both schemas exist so website-only startup also completes it.
    from backend.db import init_db as init_backend_schema
    with app.app_context():
        init_backend_schema()
    # Status claims require a current structured result; preserve legacy rows as review work.
    with connect_db() as db:
        migration = "verification_status_provenance_v1"
        applied = db.execute("SELECT 1 FROM app_migrations WHERE name=?", (migration,)).fetchone()
        if not applied:
            candidates = db.execute("""SELECT s.id,s.institution,s.status,v.overall_json,v.provider_name,v.provider_outcome,v.status AS run_status
                FROM students s LEFT JOIN verification_runs v ON v.id=(SELECT id FROM verification_runs
                    WHERE student_id=s.id AND institution_id=s.institution ORDER BY created_at DESC,id DESC LIMIT 1)
                WHERE s.status IN ('Demo-validated','Verified against source')""").fetchall()
            invalid_by_institution = {}
            for row in candidates:
                valid = False
                if row["run_status"] == row["status"] and row["overall_json"]:
                    try:
                        provider = json.loads(row["overall_json"]).get("provider", {})
                        if row["status"] == "Demo-validated":
                            valid = row["provider_name"] == "synthetic_mock" and row["provider_outcome"] == "match" and provider.get("authoritative") is False
                        else:
                            valid = row["provider_name"] not in {"synthetic_mock", "disabled"} and row["provider_outcome"] == "match" and provider.get("authoritative") is True
                    except (TypeError, ValueError):
                        valid = False
                if not valid:
                    db.execute("UPDATE students SET status='Needs review' WHERE id=? AND institution=?", (row["id"], row["institution"]))
                    invalid_by_institution[row["institution"]] = invalid_by_institution.get(row["institution"], 0) + 1
            for institution, count in invalid_by_institution.items():
                db.execute("""INSERT INTO audit_logs(institution,actor,action,entity,entity_id,details,created_at)
                    VALUES(?, 'system','verification_provenance_migration','students','status-labels',?,?)""",
                    (institution, f"Moved {count} status label(s) without matching structured provider evidence to Needs review.", now()))
            db.execute("INSERT INTO app_migrations(name,applied_at) VALUES(?,?)", (migration, now()))
            db.commit()


def audit(action, entity, entity_id, details):
    with connect_db() as db:
        db.execute("""
            INSERT INTO audit_logs(
                institution, actor, action, entity, entity_id, details, created_at
            ) VALUES(?,?,?,?,?,?,?)
        """, (
            session.get("institution", "MITAOE Demo Campus"),
            session.get("username", "system"),
            action,
            entity,
            str(entity_id),
            details[:500],
            now(),
        ))
        db.commit()


# ---------------------------------------------------------
# Authentication
# ---------------------------------------------------------

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("username"):
            return redirect(url_for("login", next=request.path))
        with connect_db() as db:
            user = db.execute(
                "SELECT role, institution, is_active, session_version FROM users WHERE username=?",
                (session["username"],),
            ).fetchone()
        if (not user or not user["is_active"]
                or int(session.get("session_version", 0)) != int(user["session_version"] or 0)):
            session.clear()
            return redirect(url_for("login", next=request.path))
        session["role"] = user["role"]
        session["institution"] = user["institution"]
        return fn(*args, **kwargs)
    return wrapper


def role_required(*allowed_roles):
    def decorate(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            with connect_db() as db:
                user = db.execute(
                    "SELECT role,is_active FROM users WHERE username=?",
                    (session.get("username"),),
                ).fetchone()
            role = ({"admin": "institution_admin"}.get(user["role"], user["role"])
                    if user else "")
            if not user or not user["is_active"] or role not in allowed_roles:
                if request.path.startswith("/api/"):
                    return {"error": "forbidden", "message": "Role is not authorized"}, 403
                flash("Your account cannot perform that action.", "error")
                return redirect(url_for("dashboard"))
            return fn(*args, **kwargs)
        return wrapper
    return decorate


def write_role_required(*allowed_roles):
    def decorate(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if request.method == "POST":
                with connect_db() as db:
                    user = db.execute(
                        "SELECT role,is_active FROM users WHERE username=?",
                        (session.get("username"),),
                    ).fetchone()
                role = ({"admin": "institution_admin"}.get(user["role"], user["role"])
                        if user else "")
                if not user or not user["is_active"] or role not in allowed_roles:
                    return {"error": "forbidden", "message": "Role is not authorized"}, 403
            return fn(*args, **kwargs)
        return wrapper
    return decorate


def _send_auth_code(email, code, subject, body):
    """Deliver auth codes via SMTP; expose codes only to Flask's isolated test client."""
    if app.testing:
        # Test-only capture lets automated tests complete the real OTP flow without SMTP.
        # This branch is disabled unless Flask TESTING is explicitly enabled.
        app.extensions.setdefault("test_auth_codes", {})[(email.lower(), subject)] = code
        return
    host = os.environ.get("SMTP_HOST", "").strip()
    if not host:
        if production_mode:
            raise RuntimeError("Email delivery is not configured.")
        app.logger.warning("LOCAL DEVELOPMENT AUTH MESSAGE for %s: %s | %s", email or "(no email)", subject, body.format(code=code))
        return
    import smtplib
    from email.message import EmailMessage
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = os.environ.get("SMTP_FROM", os.environ.get("SMTP_USERNAME", "noreply@localhost"))
    message["To"] = email
    message.set_content(body.format(code=code))
    with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", "587")), timeout=10) as smtp:
        if os.environ.get("SMTP_STARTTLS", "1") == "1":
            smtp.starttls()
        username = os.environ.get("SMTP_USERNAME", "")
        password = os.environ.get("SMTP_PASSWORD", "")
        if username:
            smtp.login(username, password)
        smtp.send_message(message)


def _create_auth_challenge(username, purpose, email):
    code = f"{secrets.randbelow(1_000_000):06d}"
    stamp = time.time()
    with connect_db() as db:
        db.execute("UPDATE auth_challenges SET consumed_at=? WHERE username=? AND purpose=? AND consumed_at IS NULL",
                   (stamp, username, purpose))
        db.execute("""INSERT INTO auth_challenges(username,purpose,token_hash,created_at,expires_at,request_ip)
                      VALUES(?,?,?,?,?,?)""",
                   (username, purpose, hashlib.sha256(code.encode()).hexdigest(),
                    stamp, stamp + int(os.environ.get("AUTH_CODE_TTL_SECONDS", "600")),
                    request.remote_addr or "unknown"))
    _send_auth_code(email, code, "APAAR Verify security code",
                    "Your APAAR Verify security code is {code}. It expires in 10 minutes. If you did not request it, ignore this message.")
    return code


def _consume_auth_challenge(username, purpose, code):
    stamp = time.time()
    with connect_db() as db:
        row = db.execute("""SELECT * FROM auth_challenges WHERE username=? AND purpose=?
                            AND consumed_at IS NULL ORDER BY id DESC LIMIT 1""",
                         (username, purpose)).fetchone()
        if not row or row["expires_at"] < stamp or row["attempts"] >= 5:
            return False
        digest = hashlib.sha256(code.strip().encode()).hexdigest()
        if not hmac.compare_digest(row["token_hash"], digest):
            db.execute("UPDATE auth_challenges SET attempts=attempts+1 WHERE id=?", (row["id"],))
            return False
        db.execute("UPDATE auth_challenges SET consumed_at=? WHERE id=?", (stamp, row["id"]))
        return True


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    username = session.get("pending_otp_username")
    if not username:
        return redirect(url_for("login"))
    if request.method == "POST":
        if _consume_auth_challenge(username, "login", request.form.get("code", "")):
            with connect_db() as db:
                user = db.execute("SELECT * FROM users WHERE username=? AND is_active=1", (username,)).fetchone()
            if not user:
                session.clear()
                return redirect(url_for("login"))
            session.clear()
            session["_csrf_token"] = secrets.token_urlsafe(32)
            session["username"] = user["username"]
            session["role"] = {"admin": "institution_admin"}.get(user["role"], user["role"])
            session["institution"] = user["institution"]
            session["session_version"] = user["session_version"] if "session_version" in user.keys() else 0
            if not user["email_verified_at"]:
                with connect_db() as db:
                    db.execute("UPDATE users SET email_verified_at=?,updated_at=? WHERE username=?",
                               (now(), now(), username))
                    db.commit()
            session.permanent = True
            audit("login_otp_verified", "user", username, "Password and email OTP verified")
            return redirect(url_for("central_oversight_dashboard") if user["role"] == "platform_admin" else url_for("dashboard"))
        flash("The code is invalid, expired, or has reached its attempt limit.", "error")
    return render_template("verify_otp.html")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        with connect_db() as db:
            user = db.execute("SELECT username,email FROM users WHERE lower(email)=? AND is_active=1 AND email_verified_at IS NOT NULL", (email,)).fetchone()
        # Same response for known and unknown addresses to reduce account enumeration.
        if user:
            try:
                token = secrets.token_urlsafe(32)
                stamp = time.time()
                with connect_db() as db:
                    db.execute("UPDATE auth_challenges SET consumed_at=? WHERE username=? AND purpose='reset' AND consumed_at IS NULL", (stamp, user["username"]))
                    db.execute("INSERT INTO auth_challenges(username,purpose,token_hash,created_at,expires_at,request_ip) VALUES(?,?,?,?,?,?)",
                               (user["username"], "reset", hashlib.sha256(token.encode()).hexdigest(), stamp, stamp+1800, request.remote_addr or "unknown"))
                host = os.environ.get("PUBLIC_BASE_URL", request.url_root.rstrip("/"))
                _send_auth_code(email, token, "Reset your APAAR Verify password",
                                "Use this one-time password reset link within 30 minutes: " + host + "/reset-password/" + "{code}")
            except (RuntimeError, OSError):
                app.logger.exception("Password reset delivery failed")
        flash("If the address belongs to a verified account, password reset instructions have been sent.", "info")
        return redirect(url_for("login"))
    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    digest = hashlib.sha256(token.encode()).hexdigest()
    with connect_db() as db:
        challenge = db.execute("""SELECT * FROM auth_challenges WHERE purpose='reset' AND token_hash=?
                                  AND consumed_at IS NULL ORDER BY id DESC LIMIT 1""", (digest,)).fetchone()
    if not challenge or challenge["expires_at"] < time.time() or challenge["attempts"] >= 5:
        flash("This reset link is invalid or expired. Request a new one.", "error")
        return redirect(url_for("forgot_password"))
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if len(password) < 12 or len(password) > 256:
            flash("Choose a password between 12 and 256 characters.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        else:
            with connect_db() as db:
                db.execute("UPDATE users SET password_hash=?,session_version=session_version+1,updated_at=? WHERE username=?",
                           (generate_password_hash(password), now(), challenge["username"]))
                db.execute("UPDATE auth_challenges SET consumed_at=? WHERE username=? AND purpose='reset' AND consumed_at IS NULL",
                           (time.time(), challenge["username"]))
                db.commit()
            flash("Password updated. Sign in with your new password.", "success")
            return redirect(url_for("login"))
    return render_template("reset_password.html")


@app.route("/help")
def help_page():
    return render_template("help.html")


@app.route("/account/security", methods=["GET", "POST"])
@login_required
def account_security():
    with connect_db() as db:
        user = db.execute("SELECT id,username,email,email_verified_at FROM users WHERE username=?",
                          (session.get("username"),)).fetchone()
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(email) > 254:
            flash("Enter a valid email address.", "error")
            return redirect(url_for("account_security"))
        try:
            code = f"{secrets.randbelow(1_000_000):06d}"
            stamp = time.time()
            with connect_db() as db:
                db.execute("UPDATE auth_challenges SET consumed_at=? WHERE username=? AND purpose='email_verify' AND consumed_at IS NULL",
                           (stamp, session.get("username")))
                db.execute("INSERT INTO auth_challenges(username,purpose,token_hash,created_at,expires_at,request_ip) VALUES(?,?,?,?,?,?)",
                           (session.get("username"), "email_verify", hashlib.sha256(code.encode()).hexdigest(),
                            stamp, stamp+600, request.remote_addr or "unknown"))
            _send_auth_code(email, code, "Verify your APAAR Verify email",
                            "Your email verification code is {code}. It expires in 10 minutes.")
            session["pending_email"] = email
            flash("Verification code sent. Enter it to confirm the email.", "info")
            return redirect(url_for("verify_email"))
        except (RuntimeError, OSError):
            flash("Email delivery is not configured or failed. Configure SMTP and try again.", "error")
    return render_template("account_security.html", user=user)


@app.route("/verify-email", methods=["GET", "POST"])
@login_required
def verify_email():
    email = session.get("pending_email")
    if not email:
        return redirect(url_for("account_security"))
    if request.method == "POST":
        if _consume_auth_challenge(session.get("username"), "email_verify", request.form.get("code", "")):
            with connect_db() as db:
                db.execute("UPDATE users SET email=?,email_verified_at=?,updated_at=? WHERE username=?",
                           (email, now(), now(), session.get("username")))
                db.commit()
            session.pop("pending_email", None)
            flash("Email address verified.", "success")
            return redirect(url_for("account_security"))
        flash("Invalid or expired verification code.", "error")
    return render_template("verify_otp.html", page_title="Verify email address")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        client_ip = request.remote_addr or "unknown"
        cutoff = time.time() - LOGIN_FAILURE_WINDOW
        recent_failures = [stamp for stamp in login_failures.get(client_ip, []) if stamp > cutoff]
        if len(recent_failures) >= LOGIN_FAILURE_LIMIT:
            login_failures[client_ip] = recent_failures
            flash("Too many sign-in attempts. Try again in 15 minutes.", "error")
            return render_template("login.html", show_demo_credentials=not production_mode), 429

        with connect_db() as db:
            user = db.execute(
                "SELECT * FROM users WHERE username=? AND is_active=1",
                (username,)
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            login_failures.pop(client_ip, None)
            email = (user["email"] or "").strip() if "email" in user.keys() else ""
            if not email:
                # First-run bootstrap only: permit the seeded local administrator to enroll an email.
                # Every subsequent sign-in requires OTP once an address is present.
                if production_mode:
                    flash("This account has no email address. Ask the system administrator to configure it securely.", "error")
                    return render_template("login.html", show_demo_credentials=False), 403
                session.clear()
                session["_csrf_token"] = secrets.token_urlsafe(32)
                session["username"] = user["username"]
                session["role"] = {"admin": "institution_admin"}.get(user["role"], user["role"])
                session["institution"] = user["institution"]
                session["session_version"] = user["session_version"] if "session_version" in user.keys() else 0
                session.permanent = True
                flash("Set and verify your email in Account security to enable OTP sign-in and password recovery.", "warning")
                return redirect(url_for("account_security"))
            try:
                _create_auth_challenge(user["username"], "login", email)
            except (RuntimeError, OSError):
                app.logger.exception("Login OTP delivery failed")
                flash("We could not send a security code. Please try later or contact your administrator.", "error")
                return render_template("login.html", show_demo_credentials=not production_mode), 503
            session.clear()
            session["_csrf_token"] = secrets.token_urlsafe(32)
            session["pending_otp_username"] = user["username"]
            flash("A sign-in code was sent to your verified email address.", "info")
            return redirect(url_for("verify_otp"))

        recent_failures.append(time.time())
        login_failures[client_ip] = recent_failures
        flash("Invalid username or password.", "error")

    return render_template("login.html", show_demo_credentials=not production_mode)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    audit(
        "logout", "user", session.get("username", ""),
        "Session ended"
    )
    session.clear()
    return redirect(url_for("login"))


@app.get("/admin/users")
@login_required
@role_required("institution_admin")
def admin_users():
    with connect_db() as db:
        users = db.execute("""
            SELECT id,username,email,email_verified_at,role,institution,is_active,created_at
            FROM users WHERE institution=? ORDER BY username
        """, (session.get("institution"),)).fetchall()
    return render_template("admin_users.html", users=users,
                           assignable_roles=("operator", "verifier", "auditor"))


@app.post("/admin/users")
@login_required
@role_required("institution_admin")
def admin_user_create():
    from backend.db import get_db
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    email = request.form.get("email", "").strip().lower()
    role = request.form.get("role", "")
    if (not username or len(username) > 40
            or not all(ch.isalnum() or ch in "._-" for ch in username)
            or len(username) < 3):
        flash("Username must be 3â€“40 letters, numbers, dots, underscores, or hyphens.", "error")
        return redirect(url_for("admin_users"))
    if len(password) < 12 or len(password) > 256:
        flash("Set a password between 12 and 256 characters.", "error")
        return redirect(url_for("admin_users"))
    # Reject privileged/unknown roles before validating other fields. This ensures
    # institution admins receive the correct permission error for attempted escalation.
    if role not in {"operator", "verifier", "auditor"}:
        flash("Select an approved non-administrator role.", "error")
        return redirect(url_for("admin_users"))
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(email) > 254:
        flash("Enter a valid email address for OTP and password recovery.", "error")
        return redirect(url_for("admin_users"))
    db = get_db()
    timestamp = now()
    try:
        cursor = db.execute("""
            INSERT INTO users(username,password_hash,role,institution,is_active,created_at,updated_at,email)
            VALUES(?,?,?,?,1,?,?,?)
        """, (username, generate_password_hash(password), role,
              session.get("institution"), timestamp, timestamp, email))
        record_event(session.get("institution"), session.get("username"),
                     "account.created", "user", str(cursor.lastrowid),
                     {"username": username, "role": role})
        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
        flash("That username is already in use.", "error")
        return redirect(url_for("admin_users"))
    flash("User account created for this institution.", "success")
    return redirect(url_for("admin_users"))


@app.post("/admin/users/<int:user_id>/role")
@login_required
@role_required("institution_admin")
def admin_user_role(user_id):
    from backend.db import get_db
    role = request.form.get("role", "")
    if role not in {"operator", "verifier", "auditor"}:
        flash("Only operator, verifier, and auditor roles can be assigned here.", "error")
        return redirect(url_for("admin_users"))
    db = get_db()
    user = db.execute("SELECT username,role FROM users WHERE id=? AND institution=?",
                      (user_id, session.get("institution"))).fetchone()
    if not user:
        abort(404)
    if user["username"] == session.get("username"):
        flash("You cannot change your own role.", "error")
        return redirect(url_for("admin_users"))
    old_role = user["role"]
    db.execute("UPDATE users SET role=?,updated_at=? WHERE id=? AND institution=?",
               (role, now(), user_id, session.get("institution")))
    record_event(session.get("institution"), session.get("username"),
                 "account.role_changed", "user", str(user_id),
                 {"from": old_role, "to": role})
    db.commit()
    flash("Account role updated.", "success")
    return redirect(url_for("admin_users"))


@app.post("/admin/users/<int:user_id>/active")
@login_required
@role_required("institution_admin")
def admin_user_active(user_id):
    from backend.db import get_db
    db = get_db()
    user = db.execute("SELECT username,role,is_active FROM users WHERE id=? AND institution=?",
                      (user_id, session.get("institution"))).fetchone()
    if not user:
        abort(404)
    if user["username"] == session.get("username"):
        flash("You cannot deactivate your own account.", "error")
        return redirect(url_for("admin_users"))
    active = 0 if user["is_active"] else 1
    db.execute("UPDATE users SET is_active=?,updated_at=? WHERE id=? AND institution=?",
               (active, now(), user_id, session.get("institution")))
    record_event(session.get("institution"), session.get("username"),
                 "account.activated" if active else "account.deactivated",
                 "user", str(user_id), {"username": user["username"]})
    db.commit()
    flash("Account " + ("activated." if active else "deactivated."), "success")
    return redirect(url_for("admin_users"))


# ---------------------------------------------------------
# Shared template context and security headers
# ---------------------------------------------------------

@app.after_request
def headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.context_processor
def inject_globals():
    return {
        "current_year": datetime.now().year,
        "csrf_token": lambda: session.get("_csrf_token", ""),
    }


# ---------------------------------------------------------
# Dashboard
# ---------------------------------------------------------

@app.route("/demo")
def demo_page():
    """Temporary browser-only demo using synthetic records; never writes to the database."""
    return render_template("demo.html")


@app.route("/identity-reconciliation")
@login_required
@role_required("institution_admin", "operator", "verifier", "auditor")
def identity_reconciliation_page():
    """Show synthetic/demo cross-institution candidates only when explicitly enabled."""
    if not app.config.get("ENABLE_SHARED_DEMO_RECONCILIATION", False):
        abort(503, description="Shared-database reconciliation is disabled by default. Enable it only for an isolated synthetic-data demo.")
    institution = session.get("institution", "")
    with connect_db() as db:
        records = [dict(row) for row in db.execute("""SELECT id,institution_student_id,full_name,institution,
            apaar_id,archived_at FROM students WHERE archived_at IS NULL AND trim(apaar_id)<>''
            ORDER BY institution,id""").fetchall()]
    candidates = reconcile_records(records, institution)
    audit("identity_reconciliation.viewed", "identity_reconciliation", institution,
          f"Viewed {len(candidates)} institution-scoped candidate(s); ruleset {IDENTITY_RECONCILIATION_RULESET_VERSION}; no identifiers logged")
    return render_template("identity_reconciliation.html", candidates=candidates,
                           ruleset_version=IDENTITY_RECONCILIATION_RULESET_VERSION)


@app.route("/")
@login_required
@role_required("institution_admin", "operator", "verifier", "auditor")
def dashboard():
    with connect_db() as db:
        institution = session.get("institution")
        total = db.execute("SELECT COUNT(*) FROM students WHERE institution=? AND archived_at IS NULL", (institution,)).fetchone()[0]

        latest_results = db.execute("""SELECT s.status AS student_status,v.status AS run_status,v.provider_name,
            v.provider_outcome,v.overall_json FROM students s JOIN verification_runs v ON v.id=(
                SELECT id FROM verification_runs WHERE student_id=s.id AND institution_id=s.institution
                ORDER BY created_at DESC,id DESC LIMIT 1)
            WHERE s.institution=? AND s.archived_at IS NULL""", (institution,)).fetchall()
        verified = demo_validated = 0
        for result in latest_results:
            if result["student_status"] != result["run_status"] or result["provider_outcome"] != "match":
                continue
            try:
                provider = json.loads(result["overall_json"]).get("provider", {})
            except (TypeError, ValueError):
                continue
            if result["student_status"] == "Demo-validated" and result["provider_name"] == "synthetic_mock" and provider.get("authoritative") is False:
                demo_validated += 1
            elif result["student_status"] == "Verified against source" and result["provider_name"] not in {"synthetic_mock", "disabled"} and provider.get("authoritative") is True:
                verified += 1

        pending = db.execute(
            "SELECT COUNT(*) FROM students WHERE institution=? AND archived_at IS NULL AND status IN ('Pending','Pending verification','Draft','In progress')", (institution,)
        ).fetchone()[0]

        review = db.execute(
            "SELECT COUNT(*) FROM students WHERE institution=? AND archived_at IS NULL AND status IN ('Needs review','Discrepancy detected','Failed to verify','Expired or stale')", (institution,)
        ).fetchone()[0]
        cases_attention = db.execute("""SELECT COUNT(*) FROM workflow_cases
            WHERE institution_id=? AND status IN ('open','in_review','waiting_for_evidence','escalated')""",
            (institution,)).fetchone()[0]
        assignment_counts = db.execute("""SELECT
            SUM(CASE WHEN COALESCE(assigned_to,'')<>'' THEN 1 ELSE 0 END),
            SUM(CASE WHEN COALESCE(assigned_to,'')='' THEN 1 ELSE 0 END)
            FROM workflow_cases WHERE institution_id=?
              AND status IN ('open','in_review','waiting_for_evidence','escalated')""",
            (institution,)).fetchone()
        assigned_cases, unassigned_cases = (assignment_counts[0] or 0, assignment_counts[1] or 0)
        duplicate_reviews = db.execute("""SELECT COUNT(*) FROM duplicate_candidates
            WHERE institution_id=? AND status='pending_review'""", (institution,)).fetchone()[0]
        pending_imports = db.execute("SELECT COUNT(*) FROM import_jobs WHERE institution=? AND status='preview'", (institution,)).fetchone()[0]
        candidate_student_ids = {value for row in db.execute("""SELECT student_a_id,student_b_id
            FROM duplicate_candidates WHERE institution_id=? AND status='pending_review'""", (institution,))
            for value in row}
        quality_rows = db.execute("SELECT * FROM students WHERE institution=? AND archived_at IS NULL", (institution,)).fetchall()
        unresolved_comparison_ids = {row[0] for row in db.execute("""SELECT DISTINCT student_id
            FROM workflow_cases WHERE institution_id=? AND case_type='institution_source_comparison'
            AND status IN ('open','in_review','waiting_for_evidence','escalated')""", (institution,))}
        readiness_scores = []
        quality_issue_count = 0
        for row in quality_rows:
            record = dict(row)
            pending_duplicate = row["id"] in candidate_student_ids
            issues = validate_student_record(record, potential_duplicate=pending_duplicate)
            quality_issue_count += bool(issues)
            readiness_scores.append(score_student_readiness(
                record, issues, pending_duplicate=pending_duplicate,
                unresolved_discrepancy=(record["status"] == "Discrepancy detected"
                                        or row["id"] in unresolved_comparison_ids),
            )["score"])
        quality_issues = quality_issue_count
        average_readiness = round(sum(readiness_scores) / len(readiness_scores)) if readiness_scores else 0
        low_readiness = sum(score < 70 for score in readiness_scores)
        status_distribution = db.execute("""SELECT status,COUNT(*) AS count FROM students
            WHERE institution=? AND archived_at IS NULL GROUP BY status ORDER BY count DESC,status""",
            (institution,)).fetchall()
        case_age_distribution = db.execute("""SELECT CASE
            WHEN julianday(created_at) IS NULL THEN 'Unknown age'
            WHEN julianday('now')-julianday(created_at)<7 THEN 'Under 7 days'
            WHEN julianday('now')-julianday(created_at)<30 THEN '7-29 days'
            ELSE '30+ days' END AS age_band,COUNT(*) AS count
            FROM workflow_cases WHERE institution_id=?
            AND status IN ('open','in_review','waiting_for_evidence','escalated')
            GROUP BY age_band ORDER BY CASE age_band WHEN 'Under 7 days' THEN 1 WHEN '7-29 days' THEN 2 ELSE 3 END""",
            (institution,)).fetchall()
        recent_import_rows = db.execute("""SELECT id,file_name,status,accepted_count,rejected_count,created_at
            FROM import_jobs WHERE institution=? ORDER BY created_at DESC LIMIT 5""", (institution,)).fetchall()
        recent_import_ids = [row["id"] for row in recent_import_rows]
        recent_warning_counts = {job_id: 0 for job_id in recent_import_ids}
        if recent_import_ids:
            placeholders = ",".join("?" for _ in recent_import_ids)
            counts = db.execute(f"""SELECT job_id,SUM(CASE WHEN trim(warnings_json) NOT IN ('','[]') THEN 1 ELSE 0 END) AS count
                FROM import_job_rows WHERE job_id IN ({placeholders}) GROUP BY job_id""", recent_import_ids).fetchall()
            recent_warning_counts.update({row["job_id"]: row["count"] or 0 for row in counts})
        recent_imports = [{**dict(row), "warning_rows": recent_warning_counts[row["id"]]} for row in recent_import_rows]

        recent = db.execute(
            "SELECT * FROM students WHERE institution=? AND archived_at IS NULL ORDER BY updated_at DESC LIMIT 6", (institution,)
        ).fetchall()

        logs = db.execute("""SELECT actor,action,entity,entity_id,details,created_at FROM (
            SELECT actor,action,entity,entity_id,details,created_at FROM audit_logs WHERE institution=?
            UNION ALL
            SELECT actor_id AS actor,action,entity_type AS entity,entity_id,
                COALESCE(reason,payload_json) AS details,created_at FROM audit_events WHERE institution_id=?
        ) ORDER BY created_at DESC LIMIT 6""", (institution, institution)).fetchall()

    return render_template(
        "dashboard.html",
        total=total,
        verified=verified,
        demo_validated=demo_validated,
        pending=pending,
        review=review,
        cases_attention=cases_attention,
        assigned_cases=assigned_cases,
        unassigned_cases=unassigned_cases,
        duplicate_reviews=duplicate_reviews,
        pending_imports=pending_imports,
        quality_issues=quality_issues,
        average_readiness=average_readiness,
        low_readiness=low_readiness,
        status_distribution=status_distribution,
        case_age_distribution=case_age_distribution,
        recent_imports=recent_imports,
        recent=recent,
        logs=logs,
    )


# ---------------------------------------------------------
# Student listing and search
# ---------------------------------------------------------

@app.route("/students")
@login_required
@role_required("institution_admin", "operator", "verifier", "auditor")
def students():
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()
    course = request.args.get("course", "").strip()[:160]
    semester = request.args.get("semester", "").strip()[:40]
    try:
        page = max(1, int(request.args.get("page", "1")))
    except ValueError:
        page = 1
    try:
        per_page = int(request.args.get("per_page", "50"))
    except ValueError:
        per_page = 50
    if per_page not in (25, 50, 100):
        per_page = 50
    where = " WHERE institution=? AND archived_at IS NULL"
    args = [session.get("institution")]

    if q:
        where += """
            AND (
                full_name LIKE ?
                OR institution_student_id LIKE ?
                OR institution LIKE ?
                OR course LIKE ?
            )
        """
        args += [f"%{q}%"] * 4

    if status in ("Draft", "Pending", "Pending verification", "In progress", "Verified against source", "Demo-validated", "Needs review", "Discrepancy detected", "Failed to verify", "Expired or stale", "Cancelled"):
        where += " AND status=?"
        args.append(status)
    else:
        status = ""
    if course:
        where += " AND course=?"
        args.append(course)
    if semester:
        where += " AND semester=?"
        args.append(semester)

    qualified_where = (where.replace("institution=?", "s.institution=?")
        .replace("archived_at IS NULL", "s.archived_at IS NULL")
        .replace("full_name LIKE", "s.full_name LIKE")
        .replace("institution_student_id LIKE", "s.institution_student_id LIKE")
        .replace("institution LIKE", "s.institution LIKE")
        .replace("course LIKE", "s.course LIKE")
        .replace("status=?", "s.status=?")
        .replace("course=?", "s.course=?")
        .replace("semester=?", "s.semester=?"))
    with connect_db() as db:
        institution = session.get("institution")
        total_count = db.execute("SELECT COUNT(*) FROM students" + where, args).fetchone()[0]
        pages = max(1, (total_count + per_page - 1) // per_page)
        page = min(page, pages)
        rows = db.execute("""SELECT s.*,
            EXISTS(SELECT 1 FROM duplicate_candidates d WHERE d.institution_id=s.institution
                AND d.status='pending_review' AND (d.student_a_id=s.id OR d.student_b_id=s.id)) AS pending_duplicate,
            EXISTS(SELECT 1 FROM workflow_cases c WHERE c.institution_id=s.institution
                AND c.student_id=s.id AND c.case_type='institution_source_comparison'
                AND c.status IN ('open','in_review','waiting_for_evidence','escalated')) AS unresolved_comparison,
            EXISTS(SELECT 1 FROM students other WHERE other.institution=s.institution
                AND other.archived_at IS NULL AND other.id<>s.id
                AND lower(other.institution_student_id)=lower(s.institution_student_id)) AS duplicate_code
            FROM students s""" + qualified_where +
            " ORDER BY s.updated_at DESC LIMIT ? OFFSET ?",
            [*args, per_page, (page - 1) * per_page]).fetchall()
        courses = [row[0] for row in db.execute("SELECT DISTINCT course FROM students WHERE institution=? AND archived_at IS NULL AND trim(course)<>'' ORDER BY course", (institution,))]
        semesters = [row[0] for row in db.execute("SELECT DISTINCT semester FROM students WHERE institution=? AND archived_at IS NULL AND trim(semester)<>'' ORDER BY semester", (institution,))]

    students_with_readiness = []
    for row in rows:
        row_data = dict(row)
        quality = validate_student_record(
            row_data, duplicate_code=bool(row["duplicate_code"]),
            potential_duplicate=bool(row["pending_duplicate"]),
        )
        row_data["readiness"] = score_student_readiness(
            row_data, quality,
            pending_duplicate=bool(row["pending_duplicate"]),
            unresolved_discrepancy=(row_data["status"] == "Discrepancy detected"
                                    or bool(row["unresolved_comparison"])),
        )
        students_with_readiness.append(row_data)

    return render_template(
        "students.html",
        students=students_with_readiness,
        q=q,
        status=status,
        course=course,
        semester=semester,
        courses=courses,
        semesters=semesters,
        page=page,
        pages=pages,
        per_page=per_page,
        total_count=total_count,
    )


# ---------------------------------------------------------
# Create and edit student
# ---------------------------------------------------------

@app.route("/students/new", methods=["GET", "POST"])
@app.route("/students/<int:student_id>/edit", methods=["GET", "POST"])
@login_required
@role_required("institution_admin", "operator")
def student_form(student_id=None):
    with connect_db() as db:
        student = (
            db.execute(
                "SELECT * FROM students WHERE id=? AND institution=? AND archived_at IS NULL",
                (student_id, session.get("institution"))
            ).fetchone()
            if student_id else None
        )

    if student_id and not student:
        flash("Student record not found.", "error")
        return redirect(url_for("students"))

    if request.method == "POST":
        fields = (
            "institution_student_id", "full_name", "institution",
            "course", "semester", "apaar_id", "email", "notes"
        )
        values = {
            key: request.form.get(key, "").strip()
            for key in fields
        }
        if student_id and not values["apaar_id"]:
            values["apaar_id"] = student["apaar_id"] or ""
        # Institution membership is server supplied; a form field cannot move a record.
        values["institution"] = session.get("institution", "")

        if (
            not values["institution_student_id"]
            or not values["full_name"]
            or not values["institution"]
        ):
            flash(
                "Institutional student ID, full name, and institution are required.",
                "error",
            )
            return render_template(
                "student_form.html",
                student=student,
                values=values,
            )

        with connect_db() as db:
            duplicate_code = db.execute("SELECT 1 FROM students WHERE lower(trim(institution))=lower(trim(?)) AND lower(trim(institution_student_id))=lower(trim(?)) AND id<>COALESCE(?, -1)",
                (values["institution"], values["institution_student_id"], student_id)).fetchone() is not None
        field_issues = validate_student_record(values, duplicate_code=duplicate_code)
        field_errors = [issue for issue in field_issues if issue["severity"] == "error"]
        if field_errors:
            flash("Record not saved. " + " ".join(f"{issue['message']} {issue['next_action']}" for issue in field_errors), "error")
            return render_template("student_form.html", student=student, values=values)

        try:
            with connect_db() as db:
                if student_id:
                    db.execute("""
                        UPDATE students
                        SET institution_student_id=?, full_name=?,
                            institution=?, course=?, semester=?,
                            apaar_id=?, email=?, notes=?, updated_at=?
                        WHERE id=? AND institution=?
                    """, (
                        *[values[k] for k in fields],
                        now(),
                        student_id,
                        session.get("institution"),
                    ))
                else:
                    db.execute("""
                        INSERT INTO students(
                            institution_student_id, full_name, institution,
                            course, semester, apaar_id, email, notes,
                            status, created_at, updated_at
                        ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                    """, (
                        *[values[k] for k in fields],
                        "Pending verification", now(), now(),
                    ))
                    student_id = db.execute(
                        "SELECT last_insert_rowid()"
                    ).fetchone()[0]

                db.commit()

        except sqlite3.IntegrityError:
            flash("That institutional student ID already exists.", "error")
            return render_template(
                "student_form.html",
                student=student,
                values=values,
            )

        audit(
            "update" if student else "create",
            "student",
            student_id,
            "Student record saved; sensitive fields omitted",
        )
        flash("Student record saved.", "success")
        return redirect(
            url_for("student_detail", student_id=student_id)
        )

    return render_template(
        "student_form.html",
        student=student,
        values=({**dict(student), "apaar_id": ""} if student else {}),
    )


# ---------------------------------------------------------
# Purpose-limited data-use authorization register
# ---------------------------------------------------------

AUTHORIZATION_PURPOSES = {"admissions_submission", "verification_review", "source_comparison"}
AUTHORIZATION_BASES = {"consent", "guardian_authorization", "statutory_authority", "institutional_policy", "other_authority"}
AUTHORIZATION_CATEGORIES = {"identity", "academic_record", "contact_details", "admissions_record"}


@app.route("/students/<int:student_id>/authorizations", methods=["POST"])
@login_required
@role_required("institution_admin", "operator")
@write_role_required("institution_admin", "operator")
def authorization_create(student_id):
    institution = session.get("institution", "")
    purpose = request.form.get("purpose", "").strip()
    basis = request.form.get("authority_basis", "").strip()
    categories = sorted(set(request.form.getlist("data_categories")))
    evidence_reference = request.form.get("evidence_reference", "").strip()[:128]
    note = request.form.get("note", "").strip()[:500]
    valid_until = request.form.get("valid_until", "").strip() or None
    if purpose not in AUTHORIZATION_PURPOSES or basis not in AUTHORIZATION_BASES:
        flash("Choose a supported purpose and authority basis.", "error")
        return redirect(url_for("student_detail", student_id=student_id))
    if not categories or any(category not in AUTHORIZATION_CATEGORIES for category in categories):
        flash("Select at least one supported data category.", "error")
        return redirect(url_for("student_detail", student_id=student_id))
    if valid_until:
        try:
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", valid_until):
                raise ValueError
            datetime.strptime(valid_until, "%Y-%m-%d")
        except ValueError:
            flash("Expiry must be a valid date in YYYY-MM-DD format.", "error")
            return redirect(url_for("student_detail", student_id=student_id))
    try:
        with connect_db() as db:
            db.execute("BEGIN IMMEDIATE")
            student = db.execute("SELECT id FROM students WHERE id=? AND institution=? AND archived_at IS NULL", (student_id, institution)).fetchone()
            if not student:
                db.rollback()
                abort(404)
            effective = db.execute("""SELECT id FROM data_use_authorizations
                WHERE institution=? AND student_id=? AND purpose=? AND status='active'
                  AND (valid_until IS NULL OR valid_until>=?) LIMIT 1""",
                (institution, student_id, purpose, datetime.now(timezone.utc).date().isoformat())).fetchone()
            if effective:
                db.rollback()
                flash("An effective authorization already exists for this purpose. Withdraw it before recording a replacement.", "error")
                return redirect(url_for("student_detail", student_id=student_id))
            db.execute("""INSERT INTO data_use_authorizations(
                institution,student_id,purpose,authority_basis,data_categories_json,evidence_reference,note,
                status,valid_until,recorded_by,recorded_at)
                VALUES(?,?,?,?,?,?,?,'active',?,?,?)""",
                (institution, student_id, purpose, basis, json.dumps(categories), evidence_reference, note,
                 valid_until, session["username"], now()))
            authorization_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
            db.commit()
        audit("privacy.authorization_recorded", "data_use_authorization", authorization_id,
              f"Purpose={purpose}; basis={basis}; categories={','.join(categories)}; evidence_ref_present={bool(evidence_reference)}")
        flash("Authorization record saved. Confirm the underlying authority and evidence independently.", "success")
    except sqlite3.IntegrityError:
        flash("The authorization record could not be saved; verify the student and selected values.", "error")
    return redirect(url_for("student_detail", student_id=student_id))


@app.route("/students/<int:student_id>/authorizations/<int:authorization_id>/withdraw", methods=["POST"])
@login_required
@role_required("institution_admin", "operator")
@write_role_required("institution_admin", "operator")
def authorization_withdraw(student_id, authorization_id):
    institution = session.get("institution", "")
    with connect_db() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT id,status FROM data_use_authorizations WHERE id=? AND student_id=? AND institution=?",
                         (authorization_id, student_id, institution)).fetchone()
        if not row:
            db.rollback()
            abort(404)
        if row["status"] != "active":
            db.rollback()
            flash("This authorization has already been withdrawn.", "error")
            return redirect(url_for("student_detail", student_id=student_id))
        timestamp = now()
        db.execute("UPDATE data_use_authorizations SET status='withdrawn',withdrawn_by=?,withdrawn_at=? WHERE id=? AND student_id=? AND institution=? AND status='active'",
                   (session["username"], timestamp, authorization_id, student_id, institution))
        db.commit()
    audit("privacy.authorization_withdrawn", "data_use_authorization", authorization_id,
          "Authorization withdrawn; prior submissions retain their recorded authorization reference")
    flash("Authorization withdrawn for future submissions. Existing submissions were not deleted.", "success")
    return redirect(url_for("student_detail", student_id=student_id))


# ---------------------------------------------------------
# Student details and history
# ---------------------------------------------------------

@app.route("/students/<int:student_id>")
@login_required
@role_required("institution_admin", "operator", "verifier", "auditor")
def student_detail(student_id):
    from backend.db import get_db
    db = get_db()
    student = db.execute(
        "SELECT * FROM students WHERE id=? AND institution=? AND archived_at IS NULL",
        (student_id, session.get("institution"))
    ).fetchone()
    cases = db.execute("""
        SELECT * FROM workflow_cases
        WHERE student_id=? AND institution_id=? ORDER BY created_at DESC
    """, (student_id, session.get("institution"))).fetchall()
    last_run = db.execute("SELECT overall_json FROM verification_runs WHERE student_id=? AND institution_id=? ORDER BY created_at DESC LIMIT 1",
                          (student_id, session.get("institution"))).fetchone()
    verification_result = json.loads(last_run["overall_json"]) if last_run else None
    if verification_result:
        provider_result = verification_result.setdefault("provider", {})
        provider_result.setdefault("state", "SIMULATED" if provider_result.get("provider") in {"mock", "synthetic_mock"} else "NOT_CONFIGURED")

    if not student:
        flash("Student record not found.", "error")
        return redirect(url_for("students"))

    source_datasets = db.execute("""SELECT d.id,d.name,u.version,u.id AS upload_id
        FROM institution_source_datasets d JOIN institution_source_uploads u
          ON u.dataset_id=d.id AND u.institution=d.institution AND u.status='committed'
        WHERE d.institution=? AND u.version=(SELECT MAX(u2.version) FROM institution_source_uploads u2
          WHERE u2.dataset_id=d.id AND u2.institution=d.institution AND u2.status='committed')
        ORDER BY d.name""", (session.get("institution"),)).fetchall()
    source_comparisons = db.execute("""SELECT c.*,d.name AS dataset_name,s.updated_at AS current_student_updated_at,
        (SELECT MAX(u.version) FROM institution_source_uploads u
         WHERE u.dataset_id=c.dataset_id AND u.institution=c.institution AND u.status='committed') AS latest_dataset_version
        FROM institution_source_comparisons c
        JOIN institution_source_datasets d ON d.id=c.dataset_id AND d.institution=c.institution
        JOIN students s ON s.id=c.student_id AND s.institution=c.institution
        WHERE c.student_id=? AND c.institution=? ORDER BY c.created_at DESC LIMIT 10""",
        (student_id, session.get("institution"))).fetchall()

    authorizations = db.execute("""SELECT id,purpose,authority_basis,data_categories_json,evidence_reference,note,status,
        valid_until,recorded_by,recorded_at,withdrawn_by,withdrawn_at
        FROM data_use_authorizations WHERE institution=? AND student_id=?
        ORDER BY recorded_at DESC,id DESC LIMIT 50""",
        (session.get("institution"), student_id)).fetchall()

    possible_duplicate = db.execute("""SELECT 1 FROM duplicate_candidates
        WHERE institution_id=? AND status='pending_review'
        AND (student_a_id=? OR student_b_id=?) LIMIT 1""",
        (session.get("institution"), student_id, student_id)).fetchone() is not None
    quality_issues = validate_student_record(dict(student), potential_duplicate=possible_duplicate)
    unresolved_discrepancy = student["status"] == "Discrepancy detected" or any(
        case["case_type"] == "institution_source_comparison"
        and case["status"] in {"open", "in_review", "waiting_for_evidence", "escalated"}
        for case in cases
    )
    readiness = score_student_readiness(
        dict(student), quality_issues,
        pending_duplicate=possible_duplicate,
        unresolved_discrepancy=unresolved_discrepancy,
    )
    duplicate_records = db.execute("""SELECT c.id,c.status,c.score,c.decision_by,c.decided_at,
        CASE WHEN c.student_a_id=? THEN b.id ELSE a.id END AS other_student_id,
        CASE WHEN c.student_a_id=? THEN b.institution_student_id ELSE a.institution_student_id END AS other_student_code
        FROM duplicate_candidates c
        JOIN students a ON a.id=c.student_a_id AND a.institution=c.institution_id
        JOIN students b ON b.id=c.student_b_id AND b.institution=c.institution_id
        WHERE c.institution_id=? AND (c.student_a_id=? OR c.student_b_id=?)
        ORDER BY CASE WHEN c.status='pending_review' THEN 0 ELSE 1 END,c.created_at DESC LIMIT 20""",
        (student_id, student_id, session.get("institution"), student_id, student_id)).fetchall()

    return render_template(
        "student_detail.html",
        student=student,
        cases=cases,
        authorizations=[{**dict(row), "data_categories": json.loads(row["data_categories_json"])} for row in authorizations],
        can_manage_authorizations=session.get("role") in {"admin", "institution_admin", "operator"},
        verification_result=verification_result,
        quality_issues=quality_issues,
        readiness=readiness,
        duplicate_records=duplicate_records,
        can_edit=session.get("role") in {"admin", "institution_admin", "operator"},
        can_validate=session.get("role") in {"admin", "institution_admin", "operator", "verifier"},
        can_open_case=session.get("role") in {"admin", "institution_admin", "operator", "verifier"},
        source_datasets=source_datasets,
        source_comparisons=[{
            **dict(row), "fields": json.loads(row["fields_json"]),
            "is_stale": (row["dataset_version"] != row["latest_dataset_version"]
                         or row["student_updated_at_snapshot"] != row["current_student_updated_at"]
                         or row["ruleset_version"] != SOURCE_COMPARISON_RULESET_VERSION),
        } for row in source_comparisons],
        can_compare_source=session.get("role") in {"admin", "institution_admin", "operator", "verifier"},
        provider_configuration=provider_configuration(),
    )


# ---------------------------------------------------------
# Institution-provided source datasets (separate from student records)
# ---------------------------------------------------------

@app.route("/source-datasets", methods=["GET", "POST"])
@login_required
@role_required("institution_admin", "operator")
@write_role_required("institution_admin", "operator")
def source_datasets():
    institution = session.get("institution", "")
    report = None
    with connect_db() as db:
        history_rows = db.execute("""SELECT u.*,d.name FROM institution_source_uploads u
            LEFT JOIN institution_source_datasets d ON d.id=u.dataset_id AND d.institution=u.institution
            WHERE u.institution=? ORDER BY u.created_at DESC LIMIT 30""", (institution,)).fetchall()
        history = [{**dict(row), "changes": json.loads(row["change_summary_json"] or "{}")} for row in history_rows]
    preview_id = request.args.get("upload_id", "")
    if preview_id:
        with connect_db() as db:
            upload = db.execute("SELECT * FROM institution_source_uploads WHERE id=? AND institution=?",
                                (preview_id, institution)).fetchone()
            previous_rows = []
            if upload and upload["status"] == "preview":
                dataset = db.execute("SELECT id FROM institution_source_datasets WHERE institution=? AND name=?",
                                     (institution, upload["dataset_name"])).fetchone()
                if dataset:
                    previous_version = db.execute("SELECT MAX(version) FROM institution_source_uploads WHERE dataset_id=? AND status='committed'",
                                                  (dataset["id"],)).fetchone()[0]
                    if previous_version:
                        previous_rows = [dict(row) for row in db.execute("""SELECT institution_student_id,full_name,course,semester,email
                            FROM institution_source_records WHERE institution=? AND dataset_id=? AND dataset_version=?""",
                            (institution,dataset["id"],previous_version)).fetchall()]
        if upload:
            rows = json.loads(upload["preview_json"])
            current_rows = [row["record"] for row in rows if not row["errors"]]
            changes = json.loads(upload["change_summary_json"] or "{}") if upload["status"] == "committed" else version_diff(previous_rows, current_rows)
            report = {"job": upload, "rows": rows, "change_summary": changes}

    if request.method == "POST":
        name = request.form.get("dataset_name", "").strip()
        upload = request.files.get("file")
        if not name or len(name) > 120:
            flash("Provide a dataset name of 1 to 120 characters.", "error")
            return redirect(url_for("source_datasets"))
        if not upload or not upload.filename or not upload.filename.lower().endswith(".csv"):
            audit("source_dataset.import_rejected", "institution_source_dataset", "upload",
                  "Unsupported source file type; no file content stored")
            flash("Choose a CSV file. SQLite files and server paths are not accepted.", "error")
            return redirect(url_for("source_datasets"))
        raw = upload.stream.read(MAX_SOURCE_BYTES + 1)
        parsed, file_errors = parse_source_csv(raw)
        if file_errors:
            audit("source_dataset.import_rejected", "institution_source_dataset", "upload",
                  "Upload validation rejected; personal row data omitted")
            flash(file_errors[0], "error")
            return redirect(url_for("source_datasets"))
        digest = hashlib.sha256(raw).hexdigest()
        accepted = sum(not row["errors"] for row in parsed)
        rejected = len(parsed) - accepted
        upload_id = secrets.token_hex(16)
        stamp = now()
        try:
            with connect_db() as db:
                prior = db.execute("SELECT id FROM institution_source_uploads WHERE institution=? AND content_hash=?",
                                   (institution, digest)).fetchone()
                if prior:
                    flash("This exact source file was already previewed or imported. Its existing record is shown.", "success")
                    return redirect(url_for("source_datasets", upload_id=prior["id"]))
                db.execute("""INSERT INTO institution_source_uploads
                    (id,institution,dataset_name,created_by,file_name,content_hash,status,preview_json,accepted_count,rejected_count,created_at)
                    VALUES(?,?,?,?,?,?,'preview',?,?,?,?)""",
                    (upload_id,institution,name,session.get("username",""),upload.filename.replace("\\", "/").rsplit("/", 1)[-1][:255],digest,
                     encode_preview(parsed),accepted,rejected,stamp))
        except sqlite3.IntegrityError:
            flash("This source file has already been submitted for this institution.", "error")
            return redirect(url_for("source_datasets"))
        flash("Source dataset preview ready. No reference records were saved.", "success")
        return redirect(url_for("source_datasets", upload_id=upload_id))

    return render_template("source_datasets.html", history=history, report=report)


@app.post("/source-datasets/<upload_id>/confirm")
@login_required
@role_required("institution_admin", "operator")
def confirm_source_dataset(upload_id):
    institution, stamp = session.get("institution", ""), now()
    db = connect_db()
    try:
        db.execute("BEGIN IMMEDIATE")
        upload = db.execute("SELECT * FROM institution_source_uploads WHERE id=? AND institution=?",
                            (upload_id, institution)).fetchone()
        if not upload:
            db.rollback()
            flash("Source preview not found.", "error")
            return redirect(url_for("source_datasets"))
        if upload["status"] == "committed":
            db.rollback()
            flash("This source dataset version was already saved.", "success")
            return redirect(url_for("source_datasets", upload_id=upload_id))
        rows = json.loads(upload["preview_json"])
        accepted = [row for row in rows if not row["errors"]]
        if not accepted:
            db.rollback()
            audit("source_dataset.import_rejected", "institution_source_dataset", upload_id,
                  "Source preview had no valid rows; no dataset was committed")
            flash("This preview contains no valid source rows and cannot be confirmed.", "error")
            return redirect(url_for("source_datasets", upload_id=upload_id))
        dataset = db.execute("SELECT id FROM institution_source_datasets WHERE institution=? AND name=?",
                             (institution, upload["dataset_name"])).fetchone()
        if dataset:
            dataset_id = dataset["id"]
        else:
            dataset_id = secrets.token_hex(16)
            db.execute("INSERT INTO institution_source_datasets(id,institution,name,created_by,created_at) VALUES(?,?,?,?,?)",
                       (dataset_id,institution,upload["dataset_name"],session.get("username",""),stamp))
        version = db.execute("SELECT COALESCE(MAX(version),0)+1 FROM institution_source_uploads WHERE dataset_id=? AND status='committed'",
                             (dataset_id,)).fetchone()[0]
        previous_version = version - 1
        previous_rows = []
        if previous_version:
            previous_rows = [dict(row) for row in db.execute("""SELECT institution_student_id,full_name,course,semester,email
                FROM institution_source_records WHERE institution=? AND dataset_id=? AND dataset_version=?""",
                (institution,dataset_id,previous_version)).fetchall()]
        accepted_records = [row["record"] for row in accepted]
        changes = version_diff(previous_rows, accepted_records)
        db.execute("UPDATE institution_source_uploads SET dataset_id=?,version=?,status='committed',confirmed_at=? WHERE id=? AND institution=? AND status='preview'",
                   (dataset_id,version,stamp,upload_id,institution))
        db.execute("UPDATE institution_source_uploads SET change_summary_json=? WHERE id=? AND institution=?",
                   (json.dumps(changes,sort_keys=True),upload_id,institution))
        db.executemany("""INSERT INTO institution_source_records
            (institution,dataset_id,upload_id,dataset_version,row_number,institution_student_id,full_name,course,semester,email)
            VALUES(?,?,?,?,?,?,?,?,?,?)""",
            [(institution,dataset_id,upload_id,version,row["line"],row["record"]["institution_student_id"],
              row["record"]["full_name"],row["record"].get("course",""),row["record"].get("semester",""),
              row["record"].get("email","")) for row in accepted])
        db.execute("INSERT INTO audit_logs(institution,actor,action,entity,entity_id,details,created_at) VALUES(?,?,?,?,?,?,?)",
                   (institution,session.get("username",""),"source_dataset_imported","institution_source_dataset",dataset_id,
                    f"Imported source dataset version {version}; {len(accepted)} records; sensitive values omitted.",stamp))
        db.commit()
    except sqlite3.Error:
        db.rollback()
        audit("source_dataset.import_failed", "institution_source_dataset", upload_id,
              "Source confirmation failed; no partial dataset records were committed")
        flash("Source dataset could not be saved. No partial records were committed.", "error")
        return redirect(url_for("source_datasets", upload_id=upload_id))
    finally:
        db.close()
    from backend.db import get_db
    workflow_db = get_db()
    record_event(institution, session.get("username"), "source_dataset.imported", "institution_source_dataset",
                 dataset_id, {"version": version, "record_count": len(accepted)})
    workflow_db.commit()
    flash(f"Institution-provided source dataset saved as version {version} ({len(accepted)} records).", "success")
    return redirect(url_for("source_datasets", upload_id=upload_id))


@app.post("/students/<int:student_id>/compare-source")
@login_required
@role_required("institution_admin", "operator", "verifier")
def compare_institution_source(student_id):
    from backend.db import get_db
    from backend.cases import create_case
    from backend.audit import record_event
    institution = session.get("institution", "")
    dataset_id = request.form.get("dataset_id", "")
    with connect_db() as db:
        student = db.execute("SELECT * FROM students WHERE id=? AND institution=? AND archived_at IS NULL",
                             (student_id,institution)).fetchone()
        source = db.execute("""SELECT d.id AS dataset_id,d.name,u.version,u.content_hash FROM institution_source_datasets d
            JOIN institution_source_uploads u ON u.dataset_id=d.id AND u.institution=d.institution AND u.status='committed'
            WHERE d.id=? AND d.institution=? AND u.version=(SELECT MAX(u2.version) FROM institution_source_uploads u2
              WHERE u2.dataset_id=d.id AND u2.institution=d.institution AND u2.status='committed')""",
            (dataset_id,institution)).fetchone()
        if not student or not source:
            flash("Student or institution source dataset was not found.", "error")
            return redirect(url_for("students"))
        source_rows = [dict(row) for row in db.execute("""SELECT institution_student_id,full_name,course,semester,email
            FROM institution_source_records WHERE institution=? AND dataset_id=? AND dataset_version=?""",
            (institution,dataset_id,source["version"])).fetchall()]
        duplicate_candidate = db.execute("""SELECT 1 FROM duplicate_candidates WHERE institution_id=?
            AND status='pending_review' AND (student_a_id=? OR student_b_id=?) LIMIT 1""",
            (institution,student_id,student_id)).fetchone() is not None
        result = compare_student(dict(student), source_rows, duplicate_candidate=duplicate_candidate)
        comparison_id = secrets.token_hex(16)
        stamp = now()
        fields_json = json.dumps(result["fields"], sort_keys=True, separators=(",", ":"))
        outcome_counts_json = json.dumps({result["outcome"]: 1}, sort_keys=True, separators=(",", ":"))
        provenance = {
            "dataset_id": source["dataset_id"], "dataset_version": source["version"],
            "input_digest": source["content_hash"], "ruleset_version": SOURCE_COMPARISON_RULESET_VERSION,
            "outcome": result["outcome"], "fields": result["fields"],
            "explanation": result["explanation"],
        }
        result_digest = hashlib.sha256(json.dumps(
            provenance, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")).hexdigest()
        db.execute("""INSERT INTO institution_source_comparisons
            (id,institution,dataset_id,dataset_version,student_id,actor,outcome,explanation,fields_json,
             run_status,ruleset_version,input_digest,result_digest,student_updated_at_snapshot,outcome_counts_json,created_at)
            VALUES(?,?,?,?,?,?,?,?,?,'completed',?,?,?,?,?,?)""",
            (comparison_id,institution,dataset_id,source["version"],student_id,session.get("username",""),
             result["outcome"],result["explanation"],fields_json,SOURCE_COMPARISON_RULESET_VERSION,
             source["content_hash"],result_digest,student["updated_at"],outcome_counts_json,stamp))
        db.execute("INSERT INTO audit_logs(institution,actor,action,entity,entity_id,details,created_at) VALUES(?,?,?,?,?,?,?)",
                   (institution,session.get("username",""),"source_comparison","student",str(student_id),
                    f"Compared with institution dataset version {source['version']}; outcome {result['outcome']}; field values omitted.",stamp))
        db.commit()
    workflow_db = get_db()
    record_event(institution, session.get("username"), "source_comparison.completed", "source_comparison",
                 comparison_id, {"dataset_id": source["dataset_id"], "dataset_version": source["version"],
                                 "input_digest": source["content_hash"],
                                 "ruleset_version": SOURCE_COMPARISON_RULESET_VERSION,
                                 "run_status": "completed", "result_digest": result_digest,
                                 "outcome": result["outcome"], "fields": result["fields"]})
    if result["manual_review_required"]:
        try:
            create_case(workflow_db, institution_id=institution, student_id=str(student_id),
                case_type="institution_source_comparison", reason=f"Institution source comparison requires review: {result['outcome']}.",
                actor_id=session.get("username"), priority="high" if result["outcome"] == "MISMATCH" else "normal",
                summary=f"Institution-provided dataset comparison: {result['outcome']}",
                findings=result["explanation"], source=f"institution source dataset version {source['version']}; comparison {comparison_id}")
        except (LookupError, ValueError):
            workflow_db.rollback()
            flash("Comparison was saved, but the review case could not be created.", "error")
            return redirect(url_for("student_detail", student_id=student_id))
    workflow_db.commit()
    flash(f"Comparison against institution-provided data: {result['outcome']}. No student record was changed.",
          "success" if result["outcome"] == "MATCH" else "warning")
    return redirect(url_for("student_detail", student_id=student_id))


# ---------------------------------------------------------
# Delete student
# ---------------------------------------------------------

@app.route("/students/<int:student_id>/archive", methods=["POST"])
@login_required
@role_required("institution_admin")
def student_archive(student_id):
    with connect_db() as db:
        row = db.execute(
            "SELECT institution_student_id FROM students WHERE id=? AND institution=? AND archived_at IS NULL",
            (student_id, session.get("institution"))
        ).fetchone()

        if not row:
            flash("Student record not found.", "error")
        else:
            db.execute(
                "UPDATE students SET archived_at=?, updated_at=? WHERE id=? AND institution=? AND archived_at IS NULL",
                (now(), now(), student_id, session.get("institution"))
            )
            db.commit()

            audit(
                "archive", "student", student_id,
                "Archived student record; institutional identifier omitted",
            )
            from backend.db import get_db
            workflow_db = get_db()
            record_event(session.get("institution"), session.get("username"),
                         "student.archived", "student", str(student_id), {})
            workflow_db.commit()
            flash("Student record archived.", "success")

    return redirect(url_for("students"))


@app.get("/students/archived")
@login_required
@role_required("institution_admin")
def archived_students():
    with connect_db() as db:
        rows = db.execute("""
            SELECT * FROM students WHERE institution=? AND archived_at IS NOT NULL
            ORDER BY archived_at DESC LIMIT 200
        """, (session.get("institution"),)).fetchall()
    return render_template("archived_students.html", students=rows)


@app.post("/students/<int:student_id>/restore")
@login_required
@role_required("institution_admin")
def student_restore(student_id):
    institution = session.get("institution")
    replacement_code = request.form.get("institution_student_id", "").strip()
    db = connect_db()
    try:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("""
            SELECT institution_student_id FROM students
            WHERE id=? AND institution=? AND archived_at IS NOT NULL
        """, (student_id, institution)).fetchone()
        if not row:
            db.rollback()
            flash("Archived student record was not found.", "error")
            return redirect(url_for("archived_students"))
        code = replacement_code or row["institution_student_id"]
        if not code or len(code) > 80:
            db.rollback()
            flash("Provide an institutional student ID up to 80 characters.", "error")
            return redirect(url_for("archived_students"))
        conflict = db.execute(
            "SELECT id FROM students WHERE lower(trim(institution))=lower(trim(?)) AND lower(trim(institution_student_id))=lower(trim(?)) AND id<>?",
            (institution, code, student_id),
        ).fetchone()
        if conflict:
            db.rollback()
            flash("That student ID belongs to another record. Enter a new ID to resolve the conflict before restoring.", "error")
            return redirect(url_for("archived_students"))
        db.execute("""
            UPDATE students SET institution_student_id=?,archived_at=NULL,updated_at=?
            WHERE id=? AND institution=? AND archived_at IS NOT NULL
        """, (code, now(), student_id, institution))
        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
        flash("The record could not be restored because its student ID conflicts with another record.", "error")
        return redirect(url_for("archived_students"))
    finally:
        db.close()
    audit("restore", "student", student_id, "Restored archived student record")
    from backend.db import get_db
    workflow_db = get_db()
    record_event(institution, session.get("username"), "student.restored",
                 "student", str(student_id), {})
    workflow_db.commit()
    flash("Student record restored with its original internal ID and history.", "success")
    return redirect(url_for("student_detail", student_id=student_id))


# ---------------------------------------------------------
# Local demo verification
# ---------------------------------------------------------

@app.route("/students/<int:student_id>/verify", methods=["POST"])
@login_required
@role_required("institution_admin", "operator", "verifier")
def verify_student(student_id):
    from backend.db import get_db
    db = get_db()
    student = db.execute(
        "SELECT * FROM students WHERE id=? AND institution=? AND archived_at IS NULL",
        (student_id, session.get("institution"))
    ).fetchone()

    if not student:
        flash("Student record not found.", "error")
        return redirect(url_for("students"))

    from backend.verification import persist_result
    scenario = request.form.get("mock_scenario", "")
    try:
        run_id, result = persist_result(db, student, session.get("institution"), session.get("username"), scenario or None)
    except ValueError as exc:
        db.rollback()
        flash(str(exc), "error")
        return redirect(url_for("student_detail", student_id=student_id))
    summary = f"{result['status']}: {result['explanation']}"
    findings_text = "\n".join(rule["explanation"] for rule in result["rules"] if rule["outcome"] != "pass") or "Local checks completed; provider result is synthetic and non-authoritative."
    create_case(
        db, institution_id=session.get("institution"), student_id=student_id,
        case_type="verification_run", reason=summary,
        actor_id=session.get("username"),
        initial_status="open" if result["manual_review_required"] else "recorded", summary=summary,
        findings=findings_text, source=f"ruleset local-rules-1.0; run {run_id}; synthetic provider only",
    )
    record_event(session.get("institution"), session.get("username"), "verification.completed",
        "verification_run", run_id, {"ruleset_version": "local-rules-1.0", "status": result["status"],
        "provider": result["provider"]["provider"], "provider_outcome": result["provider"]["outcome"],
        "provider_state": result["provider"]["state"],
        "manual_review_required": result["manual_review_required"]})
    db.commit()

    audit(
        "verify", "student", student_id,
        f"Verification run {run_id}; synthetic provider outcome {result['provider']['outcome']}; identifier omitted",
    )
    flash(
        "Local checks completed. No official APAAR lookup was performed.",
        "success",
    )
    return redirect(
        url_for("student_detail", student_id=student_id)
    )


# ---------------------------------------------------------
# CSV import
# ---------------------------------------------------------

@app.route("/imports", methods=["GET", "POST"])
@login_required
@role_required("institution_admin", "operator", "auditor")
@write_role_required("institution_admin", "operator")
def imports():
    institution = session.get("institution", "")
    report = None
    with connect_db() as db:
        history_rows = db.execute("SELECT * FROM import_jobs WHERE institution=? ORDER BY created_at DESC LIMIT 20", (institution,)).fetchall()
        history_ids = [row["id"] for row in history_rows]
        warning_counts = {job_id: 0 for job_id in history_ids}
        if history_ids:
            placeholders = ",".join("?" for _ in history_ids)
            warning_rows = db.execute(f"""SELECT job_id,SUM(CASE WHEN trim(warnings_json) NOT IN ('','[]') THEN 1 ELSE 0 END) AS count
                FROM import_job_rows WHERE job_id IN ({placeholders}) GROUP BY job_id""", history_ids).fetchall()
            warning_counts.update({row["job_id"]: row["count"] or 0 for row in warning_rows})
        history = [{**dict(row), "warning_rows": warning_counts[row["id"]]} for row in history_rows]
    selected_id = request.args.get("job_id", "")
    if selected_id:
        with connect_db() as db:
            job = db.execute("SELECT * FROM import_jobs WHERE id=? AND institution=?", (selected_id, institution)).fetchone()
            rows = db.execute("SELECT * FROM import_job_rows WHERE job_id=? ORDER BY row_number", (selected_id,)).fetchall() if job else []
        if job:
            report_rows = []
            for row in rows:
                item = dict(row)
                item["errors"] = json.loads(item.pop("errors_json"))
                item["warnings"] = json.loads(item.pop("warnings_json"))
                report_rows.append(item)
            report = {"job": job, "rows": report_rows,
                      "warning_rows": sum(bool(item["warnings"]) for item in report_rows),
                      "total_rows": len(report_rows)}

    if request.method == "POST":
        upload = request.files.get("file")
        if not upload or not upload.filename or not upload.filename.lower().endswith(".csv"):
            flash("Choose a CSV file.", "error")
            return redirect(url_for("imports"))
        raw = upload.stream.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            flash("Upload exceeds the 2 MB demo limit.", "error")
            return redirect(url_for("imports"))
        digest = hashlib.sha256(raw).hexdigest()
        with connect_db() as db:
            old_job = db.execute("SELECT id FROM import_jobs WHERE institution=? AND content_hash=?", (institution, digest)).fetchone()
        if old_job:
            flash("This file was already reviewed. Its existing preview or import result is shown.", "success")
            return redirect(url_for("imports", job_id=old_job["id"]))
        try:
            csv_text = raw.decode("utf-8-sig", errors="strict")
            reader = csv.DictReader(io.StringIO(csv_text, newline=""), strict=True)
            raw_headers = reader.fieldnames or []
        except UnicodeDecodeError:
            flash("CSV must use UTF-8 encoding. Save the file as UTF-8 and try again.", "error")
            return redirect(url_for("imports"))
        except csv.Error:
            flash("CSV header is malformed. Check the file and try again.", "error")
            return redirect(url_for("imports"))

        # Map common CSV header variants to canonical app fields.
        def _header_key(value):
            return "".join(ch for ch in str(value or "").strip().casefold() if ch.isalnum())

        _aliases = {
            "institution_student_id": {"institutionstudentid", "studentid", "studentcode", "institutionalstudentid", "rollnumber", "rollno", "enrollmentnumber", "enrolmentnumber", "registrationnumber", "regno"},
            "full_name": {"fullname", "studentname", "name", "nameofstudent", "learnername"},
            "course": {"course", "program", "programme", "degree", "courseprogram"},
            "semester": {"semester", "term", "yearsemester", "currentsemester"},
            "apaar_id": {"apaarid", "apaaridentifier"},
            "email": {"email", "emailaddress", "studentemail", "mail"},
            "notes": {"notes", "comments", "remarks", "remark"},
        }
        _canonical_headers = {}
        _duplicate_header_keys = set()
        for _header in raw_headers:
            _key = _header_key(_header)
            if not _key:
                continue
            if _key in _canonical_headers:
                _duplicate_header_keys.add(_key)
            _canonical_headers[_key] = _header
        if _duplicate_header_keys:
            flash("CSV has duplicate column headers after normalization. Rename duplicate columns and upload again.", "error")
            return redirect(url_for("imports"))

        _header_map = {}
        for _canonical, _names in _aliases.items():
            _matches = [h for h in raw_headers if _header_key(h) in _names]
            if len(_matches) > 1:
                flash(f"Multiple CSV columns appear to map to {_canonical}. Keep only one matching column and upload again.", "error")
                return redirect(url_for("imports"))
            if _matches:
                _header_map[_canonical] = _matches[0]
        _missing = [field for field in ("institution_student_id", "full_name") if field not in _header_map]
        if _missing:
            flash("Could not identify required columns: " + ", ".join(_missing) +
                  ". Try headers such as student_id / roll_no and name / student_name.", "error")
            return redirect(url_for("imports"))
        job_id, created_at, parsed, seen = secrets.token_hex(16), now(), [], set()
        accepted = rejected = 0
        with connect_db() as db:
            existing_codes = {str(r[0]).casefold().strip() for r in db.execute("SELECT institution_student_id FROM students WHERE institution=?", (institution,))}
            names = {" ".join((r[0] or "").casefold().split()) for r in db.execute("SELECT full_name FROM students WHERE institution=? AND archived_at IS NULL", (institution,))}
            emails = {str(r[0]).casefold().strip() for r in db.execute("SELECT email FROM students WHERE institution=? AND archived_at IS NULL AND email<>''", (institution,))}
            for line_number, raw_row in enumerate(reader, start=2):
                # Reject rows with extra or missing cells instead of silently misreading them.
                malformed_width = None in raw_row or any(value is None for value in raw_row.values())
                row = {}
                for canonical, source_header in _header_map.items():
                    value = raw_row.get(source_header, "")
                    row[canonical] = str(value or "").strip() if value is not None else ""
                code, name = row.get("institution_student_id", ""), row.get("full_name", "")
                course, semester = row.get("course", ""), row.get("semester", "")
                apaar_id, email, notes = row.get("apaar_id", ""), row.get("email", ""), row.get("notes", "")
                folded_code = code.casefold()
                duplicate_code = bool(folded_code and (folded_code in existing_codes or folded_code in seen))
                if folded_code: seen.add(folded_code)
                normalized_name = " ".join(name.casefold().split())
                duplicate_name = bool(normalized_name and normalized_name in names)
                duplicate_email = bool(email and email.casefold() in emails)
                quality_issues = validate_student_record(
                    {"institution_student_id": code, "full_name": name, "email": email,
                     "course": course, "semester": semester, "apaar_id": apaar_id, "notes": notes},
                    duplicate_code=duplicate_code, duplicate_name=duplicate_name,
                    duplicate_email=duplicate_email,
                )
                errors = [f"[{item['code']}] {item['message']} Next step: {item['next_action']}"
                          for item in quality_issues if item["severity"] == "error"]
                warnings = [f"[{item['code']}] {item['message']} Next step: {item['next_action']}"
                            for item in quality_issues if item["severity"] == "warning"]
                if malformed_width:
                    errors.append("[malformed_column_count] This row has a different number of cells than the header. Correct the CSV row and re-upload.")
                valid = int(not errors)
                accepted += valid
                rejected += 1 - valid
                parsed.append((job_id,line_number,code,name,course,semester,apaar_id,email,notes,json.dumps(errors),json.dumps(warnings),valid))
            db.execute("INSERT INTO import_jobs(id,institution,created_by,file_name,content_hash,status,accepted_count,rejected_count,created_at) VALUES(?,?,?,?,?,'preview',?,?,?)",
                (job_id,institution,session.get("username",""),os.path.basename(upload.filename)[:255],digest,accepted,rejected,created_at))
            db.executemany("""INSERT INTO import_job_rows(job_id,row_number,student_code,full_name,course,semester,apaar_id,email,notes,errors_json,warnings_json,is_valid)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""", parsed)
            db.commit()
        flash("Preview ready. No student records were written.", "success")
        return redirect(url_for("imports", job_id=job_id))
    return render_template("imports.html", report=report, history=history)


@app.route("/imports/<job_id>/confirm", methods=["POST"])
@login_required
@role_required("institution_admin", "operator")
def confirm_import(job_id):
    institution, stamp = session.get("institution", ""), now()
    db = connect_db()
    try:
        db.execute("BEGIN IMMEDIATE")
        job = db.execute("SELECT * FROM import_jobs WHERE id=? AND institution=?", (job_id,institution)).fetchone()
        if not job:
            db.rollback()
            flash("Import preview not found.", "error")
            return redirect(url_for("imports"))
        if job["status"] == "committed":
            db.rollback()
            flash("This import was already committed; no records were added again.", "success")
            return redirect(url_for("imports", job_id=job_id))
        rows = db.execute("SELECT * FROM import_job_rows WHERE job_id=? AND is_valid=1 ORDER BY row_number", (job_id,)).fetchall()
        existing = {str(r[0]).casefold().strip() for r in db.execute("SELECT institution_student_id FROM students WHERE institution=?", (institution,))}
        if any(r["student_code"].casefold().strip() in existing for r in rows):
            db.rollback()
            flash("A record changed after preview. Upload a corrected file to create a fresh preview.", "error")
            return redirect(url_for("imports", job_id=job_id))
        for row in rows:
            db.execute("""INSERT INTO students(institution_student_id,full_name,institution,course,semester,apaar_id,email,notes,status,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)""", (row["student_code"],row["full_name"],institution,row["course"],row["semester"],row["apaar_id"],row["email"],row["notes"],"Pending verification",stamp,stamp))
        db.execute("UPDATE import_jobs SET status='committed',confirmed_at=? WHERE id=? AND institution=?", (stamp,job_id,institution))
        db.execute("INSERT INTO audit_logs(institution,actor,action,entity,entity_id,details,created_at) VALUES(?,?,?,?,?,?,?)",
            (institution,session.get("username",""),"csv_import","students",job_id,f"Committed {len(rows)} rows from {job['file_name']}; sensitive fields omitted",stamp))
        db.commit()
        flash(f"Import confirmed: {len(rows)} valid student record(s) saved. Review data-quality findings in the student directory.", "success")
    except sqlite3.IntegrityError:
        db.rollback()
        flash("Import conflicts with existing data. No records were added.", "error")
    finally:
        db.close()
    return redirect(url_for("imports", job_id=job_id))


@app.route("/imports/<job_id>/errors.csv")
@login_required
@role_required("institution_admin", "operator")
def import_errors(job_id):
    institution = session.get("institution", "")
    with connect_db() as db:
        job = db.execute("SELECT id FROM import_jobs WHERE id=? AND institution=?", (job_id,institution)).fetchone()
        if not job:
            return {"error": "not_found"}, 404
        rows = db.execute("SELECT row_number,student_code,errors_json,warnings_json FROM import_job_rows WHERE job_id=? AND is_valid=0 ORDER BY row_number", (job_id,)).fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["row_number","institution_student_id","errors","warnings"])
    writer.writerows([(r["row_number"],spreadsheet_safe(r["student_code"]),"; ".join(json.loads(r["errors_json"])),"; ".join(json.loads(r["warnings_json"]))) for r in rows])
    return Response(output.getvalue(),mimetype="text/csv",headers={"Content-Disposition":"attachment; filename=import-errors.csv"})


# CSV export
# ---------------------------------------------------------

@app.route("/students/export.csv")
@login_required
@role_required("institution_admin", "operator", "verifier", "auditor")
def export_students():
    with connect_db() as db:
        rows = db.execute("""
            SELECT institution_student_id, full_name, institution,
                   course, semester, status, email, updated_at
            FROM students WHERE institution=? AND archived_at IS NULL ORDER BY id
        """, (session.get("institution"),)).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "institution_student_id", "full_name", "institution",
        "course", "semester", "status", "email", "updated_at",
    ])
    writer.writerows([tuple(spreadsheet_safe(value) for value in row) for row in rows])

    audit(
        "export", "students", "csv",
        f"Exported {len(rows)} rows; APAAR identifiers excluded",
    )

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
                "attachment; filename=student_records.csv"
        },
    )


# ---------------------------------------------------------
# Audit page
# ---------------------------------------------------------

@app.route("/audit")
@login_required
@role_required("institution_admin", "auditor")
def audit_page():
    action = request.args.get("action", "").strip()[:100]
    actor = request.args.get("actor", "").strip()[:120]
    action_like = f"%{action}%"
    actor_like = f"%{actor}%"
    with connect_db() as db:
        logs = db.execute("""
            SELECT * FROM audit_logs WHERE institution=? AND (?='' OR action LIKE ?)
                AND (?='' OR actor LIKE ?) ORDER BY id DESC LIMIT 300
        """, (session.get("institution"), action, action_like, actor, actor_like)).fetchall()
        workflow_events = db.execute("""
            SELECT actor_id, action, entity_type, entity_id, reason, created_at
            FROM audit_events WHERE institution_id=? AND (?='' OR action LIKE ?)
                AND (?='' OR actor_id LIKE ?) ORDER BY id DESC LIMIT 200
        """, (session.get("institution"), action, action_like, actor, actor_like)).fetchall()

    return render_template("audit.html", logs=logs, workflow_events=workflow_events,
        workflow_integrity=verify_chain(session.get("institution", "")), action=action, actor=actor)


# ---------------------------------------------------------
# Health check
# ---------------------------------------------------------

@app.route("/health")
def health():
    try:
        with connect_db() as db:
            db.execute("SELECT 1")

        return {
            "status": "ok",
            "database": "ok",
            "mode": "demo",
        }, 200

    except sqlite3.Error:
        return {
            "status": "error",
            "database": "unavailable",
        }, 503


# ---------------------------------------------------------
# Error handling
# ---------------------------------------------------------

@app.errorhandler(413)
def too_large(_error):
    if request.path.startswith("/source-datasets"):
        audit("source_dataset.import_rejected", "institution_source_dataset", "upload",
              "Source upload exceeded the configured request limit; file content omitted")
    flash("Upload exceeds the 2 MB limit.", "error")
    return redirect(url_for("source_datasets" if request.path.startswith("/source-datasets") else "imports"))


# ---------------------------------------------------------
# Admissions and intake workflow (institution-scoped)
# ---------------------------------------------------------



# ---------------------------------------------------------
# Central institutional submission workflow (synthetic prototype)
# ---------------------------------------------------------

CENTRAL_BATCH_STATUSES = (
    "submitted", "processing", "requires_review", "accepted",
    "returned_for_correction", "superseded"
)
CENTRAL_STATUS_TRANSITIONS = {
    "submitted": {"processing", "requires_review", "returned_for_correction"},
    "processing": {"requires_review", "accepted", "returned_for_correction"},
    "requires_review": {"processing", "accepted", "returned_for_correction"},
    "returned_for_correction": set(),
    "accepted": {"superseded"},
    "superseded": set(),
}


def _central_batch_integrity(batch):
    """Check the stored snapshot against its digest; this is not a signature."""
    try:
        payload = batch["snapshot_json"]
        return hmac.compare_digest(
            hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            batch["content_hash"],
        )
    except (KeyError, TypeError, AttributeError):
        return False


@app.route("/central-submissions", methods=["GET", "POST"])
@login_required
@role_required("institution_admin", "operator", "verifier", "auditor")
def central_submission_workspace():
    """Institution-scoped submission of frozen admissions snapshots to the demo central register."""
    institution = session.get("institution", "")
    if request.method == "POST":
        if session.get("role") not in {"admin", "institution_admin", "operator"}:
            abort(403)
        try:
            academic_year = int(request.form.get("academic_year", ""))
        except (TypeError, ValueError):
            flash("Choose a valid academic year.", "error")
            return redirect(url_for("central_submission_workspace"))
        current_year = datetime.now().year
        if academic_year < 2000 or academic_year > current_year + 5:
            flash("Academic year is outside the supported range.", "error")
            return redirect(url_for("central_submission_workspace"))

        with connect_db() as db:
            # Only the latest version of each enrolment, still awaiting review, is eligible.
            rows = db.execute("""
                SELECT sub.id AS local_submission_id, sub.enrolment_id, sub.version,
                       sub.status AS local_submission_status, sub.submitted_at,
                       sub.snapshot_json, sub.snapshot_hash
                FROM enrolment_submissions sub
                JOIN (
                    SELECT enrolment_id, MAX(version) AS latest_version
                    FROM enrolment_submissions
                    WHERE institution=?
                    GROUP BY enrolment_id
                ) latest ON latest.enrolment_id=sub.enrolment_id
                         AND latest.latest_version=sub.version
                WHERE sub.institution=? AND sub.status='submitted'
                ORDER BY sub.enrolment_id
            """, (institution, institution)).fetchall()

            snapshots = []
            for row in rows:
                try:
                    item = json.loads(row["snapshot_json"])
                except (TypeError, json.JSONDecodeError):
                    continue
                if int(item.get("intake_year", -1)) != academic_year:
                    continue
                # Keep the central payload minimal. No APAAR-like identifier, email,
                # notes, or local database primary keys are transmitted.
                snapshots.append({
                    "institutional_enrolment_id": str(item.get("institutional_enrolment_id", "")),
                    "institution_student_id": str(item.get("institution_student_id", "")),
                    "student_name": str(item.get("full_name", "")),
                    "programme_code": str(item.get("programme_code", "")),
                    "programme_name": str(item.get("programme_name", "")),
                    "academic_year": academic_year,
                    "enrolment_status": str(item.get("enrolment_status", "submitted")),
                    "student_category": str(item.get("student_category", "unknown")),
                    "seat_type": str(item.get("seat_type", "regular")),
                    "configured_capacity": int(item.get("configured_capacity", 0) or 0),
                    "local_submission_version": int(row["version"]),
                    "source_snapshot_hash": str(row["snapshot_hash"] or ""),
                })

            if not snapshots:
                flash("No latest, submitted admissions records were found for that academic year. Submit eligible enrolments first.", "error")
                return redirect(url_for("central_submission_workspace"))

            # Count enrolments by programme. These signals use institution-configured
            # capacity only; they are not regulatory findings or approved-intake checks.
            groups = {}
            for item in snapshots:
                key = (item["programme_code"], item["academic_year"])
                groups.setdefault(key, {"count": 0, "capacity": item["configured_capacity"]})
                groups[key]["count"] += 1
            flagged_groups = {
                key for key, summary in groups.items()
                if summary["capacity"] > 0 and summary["count"] > summary["capacity"]
            }
            flagged_count = 0
            for item in snapshots:
                key = (item["programme_code"], item["academic_year"])
                item["preliminary_flags"] = (
                    ["CONFIGURED_CAPACITY_EXCEEDED"] if key in flagged_groups else []
                )
                if item["preliminary_flags"]:
                    flagged_count += 1

            snapshot_doc = {
                "schema": "central-admissions-batch-v1",
                "authority_level": "DEMO_ONLY_NOT_OFFICIAL_AICTE_SUBMISSION",
                "institution": institution,
                "academic_year": academic_year,
                "record_count": len(snapshots),
                "records": snapshots,
            }
            snapshot_json = json.dumps(snapshot_doc, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            content_hash = hashlib.sha256(snapshot_json.encode("utf-8")).hexdigest()
            existing = db.execute(
                "SELECT id FROM central_submission_batches WHERE institution=? AND content_hash=?",
                (institution, content_hash),
            ).fetchone()
            if existing:
                flash(f"This exact batch was already submitted (reference {existing['id']}). Duplicate processing was prevented.", "warning")
                return redirect(url_for("central_submission_workspace"))

            db.execute("BEGIN IMMEDIATE")
            version = db.execute(
                "SELECT COALESCE(MAX(version),0)+1 FROM central_submission_batches WHERE institution=?",
                (institution,),
            ).fetchone()[0]
            previous = db.execute(
                "SELECT id FROM central_submission_batches WHERE institution=? ORDER BY version DESC LIMIT 1",
                (institution,),
            ).fetchone()
            batch_id = secrets.token_hex(12)
            timestamp = now()
            db.execute("""
                INSERT INTO central_submission_batches(
                    id,institution,version,academic_year,status,submitted_by,submitted_at,
                    record_count,flagged_count,previous_batch_id,content_hash,snapshot_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                batch_id, institution, version, academic_year, "submitted",
                session["username"], timestamp, len(snapshots), flagged_count,
                previous["id"] if previous else None, content_hash, snapshot_json,
            ))
            db.execute("""
                INSERT INTO central_submission_events(
                    batch_id,institution,actor,event_type,from_status,to_status,note,created_at
                ) VALUES(?,?,?,?,?,?,?,?)
            """, (batch_id, institution, session["username"], "batch_submitted", None,
                  "submitted", "Synthetic demo batch created from frozen admissions submission snapshots.", timestamp))
            db.commit()

        audit("central_submission.created", "central_submission_batch", batch_id,
              f"Created synthetic batch v{version}; records={len(snapshots)}; flags={flagged_count}; no APAAR IDs included")
        flash(f"Demo central batch {batch_id} created with {len(snapshots)} record(s). This is not an official AICTE submission.", "success")
        return redirect(url_for("central_submission_workspace"))

    with connect_db() as db:
        batches = db.execute("""
            SELECT id,institution,version,academic_year,status,submitted_by,submitted_at,
                   reviewed_by,reviewed_at,review_note,record_count,flagged_count,
                   previous_batch_id,content_hash,snapshot_json
            FROM central_submission_batches
            WHERE institution=?
            ORDER BY submitted_at DESC,version DESC LIMIT 100
        """, (institution,)).fetchall()
        batches = [dict(row, integrity_ok=_central_batch_integrity(row)) for row in batches]
        year_rows = db.execute("""
            SELECT snapshot_json FROM enrolment_submissions
            WHERE institution=? AND status='submitted' AND snapshot_json IS NOT NULL
            ORDER BY submitted_at DESC
        """, (institution,)).fetchall()
        available_years = set()
        for year_row in year_rows:
            try:
                value = json.loads(year_row["snapshot_json"]).get("intake_year")
                year_value = int(value)
                if 2000 <= year_value <= datetime.now().year + 5:
                    available_years.add(year_value)
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
    return render_template("central_submissions.html", batches=batches,
                           available_years=sorted(available_years, reverse=True),
                           statuses=CENTRAL_BATCH_STATUSES, current_year=datetime.now().year)


@app.route("/central-oversight", methods=["GET"])
@login_required
@role_required("platform_admin")
def central_oversight_dashboard():
    """Platform-wide, read-only oversight of synthetic demo batches."""
    with connect_db() as db:
        totals = db.execute("""
            SELECT COUNT(*) AS batch_count,
                   COALESCE(SUM(record_count),0) AS record_count,
                   COALESCE(SUM(flagged_count),0) AS flagged_count,
                   SUM(CASE WHEN status IN ('submitted','processing','requires_review','returned_for_correction') THEN 1 ELSE 0 END) AS open_count
            FROM central_submission_batches
        """).fetchone()
        batches = db.execute("""
            SELECT id,institution,version,academic_year,status,submitted_by,submitted_at,
                   reviewed_by,reviewed_at,review_note,record_count,flagged_count,
                   previous_batch_id,content_hash,snapshot_json
            FROM central_submission_batches
            ORDER BY CASE status WHEN 'requires_review' THEN 0 WHEN 'submitted' THEN 1
                WHEN 'processing' THEN 2 WHEN 'returned_for_correction' THEN 3 ELSE 4 END,
                submitted_at DESC LIMIT 250
        """).fetchall()
        batches = [dict(row, integrity_ok=_central_batch_integrity(row)) for row in batches]
        institutions = db.execute("""
            SELECT institution,COUNT(*) AS batch_count,MAX(submitted_at) AS last_submission,
                   SUM(record_count) AS records, SUM(flagged_count) AS flagged
            FROM central_submission_batches GROUP BY institution ORDER BY institution
        """).fetchall()
    return render_template("central_oversight.html", totals=totals, batches=batches,
                           institutions=institutions, current_year=datetime.now().year)


@app.route("/central-oversight/<batch_id>", methods=["GET", "POST"])
@login_required
@role_required("platform_admin")
def central_batch_detail(batch_id):
    """Central reviewer can inspect minimal snapshot fields and make a recorded state transition."""
    with connect_db() as db:
        batch = db.execute("SELECT * FROM central_submission_batches WHERE id=?", (batch_id,)).fetchone()
        if not batch:
            abort(404)
        integrity_ok = _central_batch_integrity(batch)
        if request.method == "POST":
            target = request.form.get("status", "").strip()
            note = request.form.get("review_note", "").strip()[:1000]
            allowed = CENTRAL_STATUS_TRANSITIONS.get(batch["status"], set())
            if target not in allowed:
                flash("That status transition is not permitted.", "error")
                return redirect(url_for("central_batch_detail", batch_id=batch_id))
            if target in {"requires_review", "returned_for_correction"} and not note:
                flash("Add a reason for a review or correction request.", "error")
                return redirect(url_for("central_batch_detail", batch_id=batch_id))
            if not integrity_ok:
                flash("Snapshot integrity check failed. The batch is read-only and cannot be advanced.", "error")
                return redirect(url_for("central_batch_detail", batch_id=batch_id))
            timestamp = now()
            updated = db.execute("""
                UPDATE central_submission_batches
                SET status=?,reviewed_by=?,reviewed_at=?,review_note=?
                WHERE id=? AND status=?
            """, (target, session["username"], timestamp, note, batch_id, batch["status"])).rowcount
            if not updated:
                db.rollback()
                flash("The batch changed during review. Refresh before trying again.", "error")
                return redirect(url_for("central_batch_detail", batch_id=batch_id))
            db.execute("""
                INSERT INTO central_submission_events(
                    batch_id,institution,actor,event_type,from_status,to_status,note,created_at
                ) VALUES(?,?,?,?,?,?,?,?)
            """, (batch_id, batch["institution"], session["username"], "status_changed",
                  batch["status"], target, note, timestamp))
            db.commit()
            audit("central_submission.status_changed", "central_submission_batch", batch_id,
                  f"{batch['status']} -> {target}; note required where applicable")
            flash("Central review decision recorded.", "success")
            return redirect(url_for("central_batch_detail", batch_id=batch_id))

        try:
            snapshot = json.loads(batch["snapshot_json"])
        except (TypeError, json.JSONDecodeError):
            snapshot = {"records": []}
        events = db.execute("""
            SELECT actor,event_type,from_status,to_status,note,created_at
            FROM central_submission_events WHERE batch_id=? ORDER BY id
        """, (batch_id,)).fetchall()
    return render_template("central_batch_detail.html", batch=batch, snapshot=snapshot,
                           events=events, integrity_ok=integrity_ok,
                           transitions=sorted(CENTRAL_STATUS_TRANSITIONS.get(batch["status"], set())),
                           current_year=datetime.now().year)



# ---------------------------------------------------------
# Phase 5: institution registry and authenticated submissions
# ---------------------------------------------------------

def _new_institution_token():
    return "apaar_inst_" + secrets.token_urlsafe(36)


def _token_digest(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@app.route("/central-institutions", methods=["GET", "POST"])
@login_required
@role_required("platform_admin")
def central_institutions():
    """Manage institution onboarding and one-time service credential issuance."""
    revealed_token = None
    if request.method == "POST":
        action = request.form.get("action", "create").strip()
        try:
            institution_id = int(request.form.get("institution_id", "0"))
        except (TypeError, ValueError):
            institution_id = 0
        timestamp = now()
        if action == "create":
            code = request.form.get("institution_code", "").strip().upper()
            name = request.form.get("institution_name", "").strip()
            if not re.fullmatch(r"[A-Z0-9][A-Z0-9_-]{1,31}", code) or not name or len(name) > 160:
                flash("Use a 2–32 character institution code (letters, numbers, _ or -) and a name up to 160 characters.", "error")
            else:
                try:
                    with connect_db() as db:
                        db.execute("""INSERT INTO institution_registry(
                            institution_code,institution_name,status,created_by,created_at,updated_at
                        ) VALUES(?,?,'active',?,?,?)""",
                                   (code, name, session["username"], timestamp, timestamp))
                        db.commit()
                    audit("institution_registry.created", "institution", code, "Institution onboarded in prototype registry")
                    flash("Institution registered. Create a service credential separately and share it securely.", "success")
                except sqlite3.IntegrityError:
                    flash("That institution code or name is already registered.", "error")
        elif action == "status":
            target = request.form.get("status", "").strip()
            if target not in {"active", "suspended"} or institution_id <= 0:
                flash("Invalid institution status update.", "error")
            else:
                with connect_db() as db:
                    row = db.execute("SELECT institution_code,institution_name,status FROM institution_registry WHERE id=?",
                                     (institution_id,)).fetchone()
                    if not row:
                        flash("Institution not found.", "error")
                    else:
                        db.execute("UPDATE institution_registry SET status=?,updated_at=? WHERE id=?",
                                   (target, timestamp, institution_id))
                        db.commit()
                        audit("institution_registry.status_changed", "institution", row["institution_code"],
                              f"{row['status']} -> {target}")
                        flash(f"Institution status updated to {target}.", "success")
        elif action == "issue_credential":
            if institution_id <= 0:
                flash("Select a valid institution.", "error")
            else:
                token = _new_institution_token()
                with connect_db() as db:
                    institution = db.execute("SELECT * FROM institution_registry WHERE id=?",
                                             (institution_id,)).fetchone()
                    if not institution:
                        flash("Institution not found.", "error")
                    elif institution["status"] != "active":
                        flash("Credentials cannot be issued to a suspended institution.", "error")
                    else:
                        db.execute("""INSERT INTO institution_api_credentials(
                            institution_id,token_hash,token_prefix,created_by,created_at
                        ) VALUES(?,?,?,?,?)""",
                                   (institution_id, _token_digest(token), token[:18],
                                    session["username"], timestamp))
                        db.commit()
                        revealed_token = {"institution_name": institution["institution_name"], "token": token}
                        audit("institution_api.credential_issued", "institution", institution["institution_code"],
                              "A one-time service credential was issued; raw token is not stored.")
        else:
            flash("Unknown registry action.", "error")

    with connect_db() as db:
        institutions = db.execute("""
            SELECT i.*,
              (SELECT COUNT(*) FROM institution_api_credentials c
               WHERE c.institution_id=i.id AND c.revoked_at IS NULL) AS active_credentials,
              (SELECT MAX(c.last_used_at) FROM institution_api_credentials c
               WHERE c.institution_id=i.id AND c.revoked_at IS NULL) AS last_api_use
            FROM institution_registry i ORDER BY i.institution_name
        """).fetchall()
        credentials = db.execute("""
            SELECT c.id,c.institution_id,c.token_prefix,c.created_by,c.created_at,c.last_used_at,c.revoked_at,
                   i.institution_name,i.institution_code
            FROM institution_api_credentials c JOIN institution_registry i ON i.id=c.institution_id
            ORDER BY c.created_at DESC LIMIT 200
        """).fetchall()
    return render_template("central_institutions.html", institutions=institutions,
                           credentials=credentials, revealed_token=revealed_token,
                           current_year=datetime.now().year)


@app.post("/central-institutions/credentials/<int:credential_id>/revoke")
@login_required
@role_required("platform_admin")
def revoke_institution_credential(credential_id):
    timestamp = now()
    with connect_db() as db:
        credential = db.execute("""SELECT c.id,c.revoked_at,i.institution_code
            FROM institution_api_credentials c JOIN institution_registry i ON i.id=c.institution_id
            WHERE c.id=?""", (credential_id,)).fetchone()
        if not credential:
            abort(404)
        if credential["revoked_at"] is None:
            db.execute("UPDATE institution_api_credentials SET revoked_at=? WHERE id=?",
                       (timestamp, credential_id))
            db.commit()
            audit("institution_api.credential_revoked", "institution", credential["institution_code"],
                  "Service credential revoked by platform administrator.")
            flash("Service credential revoked.", "success")
        else:
            flash("Credential was already revoked.", "info")
    return redirect(url_for("central_institutions"))


def _authenticate_institution_api():
    """Return active registry and credential rows or a JSON error response."""
    auth = request.headers.get("Authorization", "")
    scheme, _, token = auth.partition(" ")
    if scheme.lower() != "bearer" or not token or len(token) > 256:
        return None, ({"error": "unauthorized", "message": "A valid Bearer service credential is required."}, 401)
    digest = _token_digest(token)
    with connect_db() as db:
        credential = db.execute("""
            SELECT c.id AS credential_id,c.institution_id,c.token_hash,c.revoked_at,
                   i.institution_code,i.institution_name,i.status
            FROM institution_api_credentials c
            JOIN institution_registry i ON i.id=c.institution_id
            WHERE c.token_hash=?
        """, (digest,)).fetchone()
        if not credential or credential["revoked_at"] is not None:
            return None, ({"error": "unauthorized", "message": "Credential is invalid or revoked."}, 401)
        if credential["status"] != "active":
            return None, ({"error": "forbidden", "message": "Institution is suspended."}, 403)
        db.execute("UPDATE institution_api_credentials SET last_used_at=? WHERE id=?",
                   (now(), credential["credential_id"]))
        db.commit()
        return dict(credential), None


@app.route("/api/v1/institution-submissions", methods=["POST"])
def institutional_submission_api():
    """
    Versioned service-to-service endpoint. This accepts only a defined minimal
    payload; it does not claim official APAAR/AICTE verification.
    """
    institution, error = _authenticate_institution_api()
    if error:
        body, status = error
        return Response(json.dumps(body), status=status, mimetype="application/json")
    if not request.is_json:
        return Response(json.dumps({"error": "invalid_request", "message": "Content-Type must be application/json."}),
                        status=415, mimetype="application/json")
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return Response(json.dumps({"error": "invalid_request", "message": "JSON object required."}),
                        status=400, mimetype="application/json")
    try:
        academic_year = int(body.get("academic_year"))
    except (TypeError, ValueError, OverflowError):
        academic_year = 0
    current_year = datetime.now().year
    records = body.get("records")
    if not (2000 <= academic_year <= current_year + 5):
        return Response(json.dumps({"error": "invalid_academic_year", "message": "Academic year is outside the accepted range."}),
                        status=400, mimetype="application/json")
    if not isinstance(records, list) or not records or len(records) > 5000:
        return Response(json.dumps({"error": "invalid_records", "message": "records must contain 1 to 5000 items."}),
                        status=400, mimetype="application/json")

    allowed_statuses = {"draft", "submitted", "under_review", "approved", "rejected", "withdrawn", "returned_for_correction"}
    normalized = []
    seen_ids = set()
    required_fields = ("institutional_enrolment_id", "institution_student_id", "student_name",
                       "programme_code", "programme_name", "enrolment_status")
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            return Response(json.dumps({"error": "invalid_record", "message": f"Record {index + 1} must be an object."}),
                            status=400, mimetype="application/json")
        item = {"academic_year": academic_year, "preliminary_flags": []}
        for field in required_fields:
            value = record.get(field)
            if not isinstance(value, str) or not value.strip():
                return Response(json.dumps({"error": "invalid_record", "message": f"Record {index + 1} requires {field}."}),
                                status=400, mimetype="application/json")
            value = value.strip()
            max_lengths = {"institutional_enrolment_id": 80, "institution_student_id": 80,
                           "student_name": 160, "programme_code": 32, "programme_name": 160,
                           "enrolment_status": 32}
            if len(value) > max_lengths[field]:
                return Response(json.dumps({"error": "invalid_record", "message": f"Record {index + 1} field {field} exceeds its length limit."}),
                                status=400, mimetype="application/json")
            item[field] = value
        if item["enrolment_status"] not in allowed_statuses:
            return Response(json.dumps({"error": "invalid_record", "message": f"Record {index + 1} has an unsupported enrolment_status."}),
                            status=400, mimetype="application/json")
        # Optional, backward-compatible classification fields for monitoring only.
        category = record.get("student_category", "unknown")
        seat_type = record.get("seat_type", "regular")
        if not isinstance(category, str) or not isinstance(seat_type, str):
            return Response(json.dumps({"error": "invalid_record", "message": f"Record {index + 1} student_category and seat_type must be strings."}),
                            status=400, mimetype="application/json")
        item["student_category"] = category.strip()
        item["seat_type"] = seat_type.strip()
        if item["student_category"] not in {"domestic", "nri", "oci", "foreign_national", "unknown"}:
            return Response(json.dumps({"error": "invalid_record", "message": f"Record {index + 1} has an unsupported student_category."}),
                            status=400, mimetype="application/json")
        if item["seat_type"] not in {"regular", "supernumerary"}:
            return Response(json.dumps({"error": "invalid_record", "message": f"Record {index + 1} has an unsupported seat_type."}),
                            status=400, mimetype="application/json")
        unique_id = item["institutional_enrolment_id"].casefold()
        if unique_id in seen_ids:
            return Response(json.dumps({"error": "duplicate_record_id", "message": f"Duplicate institutional_enrolment_id in record {index + 1}."}),
                            status=400, mimetype="application/json")
        seen_ids.add(unique_id)
        normalized.append(item)

    snapshot = {"schema_version": "institution-submission-v1", "institution_code": institution["institution_code"],
                "institution_name": institution["institution_name"], "academic_year": academic_year,
                "records": normalized}
    canonical = json.dumps(snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    request_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    idempotency_key = request.headers.get("Idempotency-Key", "").strip()
    if not idempotency_key or len(idempotency_key) > 128 or not re.fullmatch(r"[A-Za-z0-9._:-]{8,128}", idempotency_key):
        return Response(json.dumps({"error": "idempotency_key_required", "message": "Send an Idempotency-Key header (8–128 letters, numbers, . _ : or -)."}),
                        status=400, mimetype="application/json")

    with connect_db() as db:
        # Serialize idempotency/content checks with batch creation to avoid race-created duplicate batches.
        db.execute("BEGIN IMMEDIATE")
        previous_request = db.execute("""
            SELECT request_hash,batch_id FROM institution_api_idempotency
            WHERE institution_id=? AND idempotency_key=?
        """, (institution["institution_id"], idempotency_key)).fetchone()
        if previous_request:
            if not hmac.compare_digest(previous_request["request_hash"], request_hash):
                db.rollback()
                return Response(json.dumps({"error": "idempotency_conflict", "message": "This Idempotency-Key was already used with a different payload."}),
                                status=409, mimetype="application/json")
            batch = db.execute("SELECT id,version,status,content_hash,submitted_at FROM central_submission_batches WHERE id=?",
                               (previous_request["batch_id"],)).fetchone()
            db.commit()
            return Response(json.dumps({"batch": dict(batch), "idempotent_replay": True}),
                            status=200, mimetype="application/json")
        duplicate = db.execute("""SELECT id,version,status FROM central_submission_batches
            WHERE institution=? AND content_hash=?""",
                                (institution["institution_name"], request_hash)).fetchone()
        if duplicate:
            db.rollback()
            return Response(json.dumps({"error": "duplicate_submission", "message": "Identical content already exists as a central batch.",
                                        "existing_batch_id": duplicate["id"], "version": duplicate["version"]}),
                            status=409, mimetype="application/json")
        previous = db.execute("""SELECT id,version FROM central_submission_batches
            WHERE institution=? ORDER BY version DESC LIMIT 1""", (institution["institution_name"],)).fetchone()
        version = int(previous["version"]) + 1 if previous else 1
        batch_id = secrets.token_urlsafe(18)
        timestamp = now()
        db.execute("""INSERT INTO central_submission_batches(
            id,institution,version,academic_year,status,submitted_by,submitted_at,
            record_count,flagged_count,previous_batch_id,content_hash,snapshot_json
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                   (batch_id, institution["institution_name"], version, academic_year, "submitted",
                    f"service:{institution['institution_code']}", timestamp, len(normalized), 0,
                    previous["id"] if previous else None, request_hash, canonical))
        db.execute("""INSERT INTO central_submission_events(
            batch_id,institution,actor,event_type,from_status,to_status,note,created_at
        ) VALUES(?,?,?,?,?,?,?,?)""",
                   (batch_id, institution["institution_name"], f"service:{institution['institution_code']}",
                    "api_batch_submitted", None, "submitted",
                    "Authenticated institutional API submission; no authoritative APAAR verification performed.", timestamp))
        db.execute("""INSERT INTO institution_api_idempotency(
            institution_id,idempotency_key,request_hash,batch_id,created_at
        ) VALUES(?,?,?,?,?)""",
                   (institution["institution_id"], idempotency_key, request_hash, batch_id, timestamp))
        db.execute("""INSERT INTO audit_logs(institution,actor,action,entity,entity_id,details,created_at)
            VALUES(?,?,?,?,?,?,?)""",
                   (institution["institution_name"], f"service:{institution['institution_code']}",
                    "institution_api.submission_created", "central_submission_batch", batch_id,
                    f"API v1 submission; records={len(normalized)}; idempotency key stored; no APAAR IDs accepted.", timestamp))
        db.commit()
    return Response(json.dumps({"batch": {"id": batch_id, "version": version, "status": "submitted",
                                         "academic_year": academic_year, "record_count": len(normalized),
                                         "content_hash": request_hash, "submitted_at": timestamp},
                                "idempotent_replay": False}),
                    status=201, mimetype="application/json")


@app.route("/admissions/approved-intake", methods=["POST"])
@login_required
@role_required("institution_admin", "operator")
def approved_intake_create():
    """Record a versioned intake figure with references; it is not independently verified."""
    try:
        programme_id = int(request.form.get("programme_id", ""))
        year = int(request.form.get("intake_year", ""))
        sanctioned_intake = int(request.form.get("sanctioned_intake", ""))
        supernumerary_limit = int(request.form.get("supernumerary_limit", "0"))
        approval_reference = request.form.get("approval_reference", "").strip()
        source_reference = request.form.get("source_reference", "").strip()
        approval_date = request.form.get("approval_date", "").strip() or None
        if not (2000 <= year <= 2100 and 1 <= sanctioned_intake <= 100000 and 0 <= supernumerary_limit <= 100000):
            raise ValueError
        if not approval_reference or len(approval_reference) > 120 or not source_reference or len(source_reference) > 240:
            raise ValueError
        if approval_date:
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", approval_date):
                raise ValueError
            datetime.strptime(approval_date, "%Y-%m-%d")
        with connect_db() as db:
            db.execute("BEGIN IMMEDIATE")
            programme = db.execute("SELECT id,code FROM programmes WHERE id=? AND institution=? AND active=1",
                                   (programme_id, session["institution"])).fetchone()
            if not programme:
                db.rollback()
                flash("Choose an active programme belonging to your institution.", "error")
                return redirect(url_for("admissions_monitoring"))
            latest = db.execute("SELECT COALESCE(MAX(version),0) FROM approved_intake_records WHERE institution=? AND programme_id=? AND intake_year=?",
                                (session["institution"], programme_id, year)).fetchone()[0]
            timestamp = now()
            db.execute("UPDATE approved_intake_records SET status='superseded',superseded_at=? WHERE institution=? AND programme_id=? AND intake_year=? AND status='current'",
                       (timestamp, session["institution"], programme_id, year))
            db.execute("""INSERT INTO approved_intake_records(
                institution,programme_id,intake_year,version,sanctioned_intake,supernumerary_limit,
                approval_reference,source_reference,approval_date,status,recorded_by,recorded_at
            ) VALUES(?,?,?,?,?,?,?,?,?,'current',?,?)""",
                       (session["institution"], programme_id, year, latest + 1, sanctioned_intake,
                        supernumerary_limit, approval_reference, source_reference, approval_date,
                        session["username"], timestamp))
            db.commit()
        audit("admissions.approved_intake_recorded", "approved_intake_record",
              f"{programme['code']}:{year}:v{latest + 1}",
              f"Recorded sanctioned intake={sanctioned_intake}, supernumerary limit={supernumerary_limit}; source={source_reference}; not independently verified.")
        flash("Approved-intake reference recorded as a new version. The source document has not been independently verified by this application.", "success")
    except (ValueError, TypeError, sqlite3.IntegrityError):
        flash("Check programme, year, seat counts, approval reference, source reference, and date.", "error")
    return redirect(url_for("admissions_monitoring"))


@app.route("/admissions/monitoring", methods=["GET"])
@login_required
@role_required("institution_admin", "operator", "verifier", "auditor")
def admissions_monitoring():
    """Explainable, institution-scoped admissions checks; category rules are not inferred."""
    institution = session.get("institution")
    with connect_db() as db:
        programmes = db.execute("SELECT id,code,name FROM programmes WHERE institution=? AND active=1 ORDER BY name", (institution,)).fetchall()
        rows = db.execute("""SELECT a.id AS allocation_id,a.intake_year,a.capacity AS configured_capacity,
            p.id AS programme_id,p.code AS programme_code,p.name AS programme_name,
            air.id AS approved_intake_id,air.version AS approved_intake_version,
            air.sanctioned_intake,air.supernumerary_limit,air.approval_reference,air.source_reference,
            air.approval_date,air.recorded_at AS intake_recorded_at,
            (SELECT COUNT(*) FROM enrolments e WHERE e.allocation_id=a.id AND e.status IN ('submitted','under_review','approved','returned_for_correction')) AS active_count,
            (SELECT COUNT(*) FROM enrolments e WHERE e.allocation_id=a.id AND e.status='approved') AS approved_count,
            (SELECT COUNT(*) FROM enrolments e WHERE e.allocation_id=a.id AND e.status IN ('submitted','under_review','returned_for_correction')) AS pending_count,
            (SELECT COUNT(*) FROM enrolments e WHERE e.allocation_id=a.id AND e.status IN ('submitted','under_review','approved','returned_for_correction') AND e.seat_type='supernumerary') AS supernumerary_count,
            (SELECT COUNT(*) FROM enrolments e WHERE e.allocation_id=a.id AND e.status='approved' AND e.seat_type='supernumerary') AS approved_supernumerary_count,
            (SELECT COUNT(*) FROM enrolments e WHERE e.allocation_id=a.id AND e.status IN ('submitted','under_review','approved','returned_for_correction') AND e.student_category='unknown') AS unknown_category_count,
            (SELECT COUNT(*) FROM enrolments e WHERE e.allocation_id=a.id AND e.status IN ('submitted','under_review','approved','returned_for_correction') AND e.student_category='nri') AS nri_count,
            (SELECT COUNT(*) FROM enrolments e WHERE e.allocation_id=a.id AND e.status IN ('submitted','under_review','approved','returned_for_correction') AND e.student_category='oci') AS oci_count,
            (SELECT COUNT(*) FROM enrolments e WHERE e.allocation_id=a.id AND e.status IN ('submitted','under_review','approved','returned_for_correction') AND e.student_category='foreign_national') AS foreign_national_count,
            (SELECT COUNT(*) FROM enrolments e WHERE e.allocation_id=a.id AND e.status IN ('submitted','under_review','approved','returned_for_correction') AND e.student_category='domestic') AS domestic_count
            FROM intake_allocations a JOIN programmes p ON p.id=a.programme_id AND p.institution=a.institution
            LEFT JOIN approved_intake_records air ON air.institution=a.institution AND air.programme_id=a.programme_id
                AND air.intake_year=a.intake_year AND air.status='current'
            WHERE a.institution=? ORDER BY a.intake_year DESC,p.name""", (institution,)).fetchall()
        history = db.execute("""SELECT r.*,p.code AS programme_code,p.name AS programme_name
            FROM approved_intake_records r JOIN programmes p ON p.id=r.programme_id AND p.institution=r.institution
            WHERE r.institution=? ORDER BY r.intake_year DESC,p.name,r.version DESC LIMIT 200""", (institution,)).fetchall()
    monitored = []
    for row in rows:
        item = dict(row)
        alerts = []
        if item["approved_intake_id"] is None:
            alerts.append("Approved-intake reference missing")
        else:
            if item["approved_count"] > item["sanctioned_intake"]:
                alerts.append("Approved intake exceeded")
            elif item["active_count"] > item["sanctioned_intake"]:
                alerts.append("Potential intake excess (pending records included)")
            if item["approved_supernumerary_count"] > item["supernumerary_limit"]:
                alerts.append("Supernumerary limit exceeded")
            elif item["supernumerary_count"] > item["supernumerary_limit"]:
                alerts.append("Potential supernumerary excess (pending records included)")
        if item["unknown_category_count"]:
            alerts.append("Category information missing")
        item["alerts"] = alerts or ["Within recorded limits"]
        item["alert_level"] = "alert" if any("exceeded" in x.lower() or "missing" in x.lower() for x in alerts) else ("review" if alerts else "ok")
        monitored.append(item)
    audit("admissions.monitoring_viewed", "admissions_monitoring", "institution", "Viewed institution-scoped explainable intake and category checks")
    return render_template("admissions_monitoring.html", monitored=monitored, programmes=programmes,
                           intake_history=history, can_write=session.get("role") in ("admin", "institution_admin", "operator"),
                           current_year=datetime.now().year)


@app.route("/admissions", methods=["GET"])
@login_required
@role_required("institution_admin", "operator", "verifier", "auditor")
def admissions_workspace():
    institution = session.get("institution")
    with connect_db() as db:
        programmes = db.execute("SELECT * FROM programmes WHERE institution=? ORDER BY name", (institution,)).fetchall()
        students = db.execute("SELECT id,full_name,institution_student_id FROM students WHERE institution=? AND archived_at IS NULL ORDER BY full_name LIMIT 500", (institution,)).fetchall()
        allocations = db.execute("""SELECT a.*,p.code AS programme_code,p.name AS programme_name,
            (SELECT COUNT(*) FROM enrolments e WHERE e.allocation_id=a.id AND e.status NOT IN ('withdrawn','rejected')) AS enrolled
            FROM intake_allocations a JOIN programmes p ON p.id=a.programme_id
            WHERE a.institution=? ORDER BY a.intake_year DESC,p.name""", (institution,)).fetchall()
        enrolments = db.execute("""SELECT e.*,s.full_name,s.institution_student_id,a.intake_year,p.code AS programme_code,p.name AS programme_name
            FROM enrolments e JOIN students s ON s.id=e.student_id
            JOIN intake_allocations a ON a.id=e.allocation_id JOIN programmes p ON p.id=a.programme_id
            WHERE e.institution=? ORDER BY e.updated_at DESC,e.id DESC LIMIT 100""", (institution,)).fetchall()
    allocations = [dict(row) for row in allocations]
    for allocation in allocations:
        allocation["utilization_pct"] = round((allocation["enrolled"] / allocation["capacity"]) * 100, 1) if allocation["capacity"] else 0
        allocation["over_capacity"] = allocation["enrolled"] > allocation["capacity"]
        allocation["remaining"] = max(0, allocation["capacity"] - allocation["enrolled"])
    return render_template("admissions.html", programmes=programmes, students=students, allocations=allocations, enrolments=enrolments,
                           can_write=session.get("role") in ("admin", "institution_admin", "operator"), current_year=datetime.now().year)


@app.route("/admissions/programmes", methods=["POST"])
@login_required
@role_required("institution_admin", "operator")
def programme_create():
    code = request.form.get("code", "").strip().upper()
    name = request.form.get("name", "").strip()
    if not code or len(code) > 32 or not name or len(name) > 120:
        flash("Enter a programme code (up to 32 characters) and name (up to 120 characters).", "error")
        return redirect(url_for("admissions_workspace"))
    try:
        with connect_db() as db:
            db.execute("INSERT INTO programmes(institution,code,name,created_by,created_at) VALUES(?,?,?,?,?)",
                       (session["institution"], code, name, session["username"], now()))
            db.commit()
        audit("admissions.programme_created", "programme", code, "Programme created")
        flash("Programme created.", "success")
    except sqlite3.IntegrityError:
        flash("That programme code already exists in this institution.", "error")
    return redirect(url_for("admissions_workspace"))


@app.route("/admissions/intakes", methods=["POST"])
@login_required
@role_required("institution_admin", "operator")
def intake_create():
    try:
        programme_id = int(request.form.get("programme_id", ""))
        year = int(request.form.get("intake_year", ""))
        capacity = int(request.form.get("capacity", ""))
        status = request.form.get("status", "draft")
        if not (2000 <= year <= 2100 and 1 <= capacity <= 100000 and status in {"draft", "open", "closed"}):
            raise ValueError
        with connect_db() as db:
            programme = db.execute("SELECT id FROM programmes WHERE id=? AND institution=? AND active=1",
                                  (programme_id, session["institution"])).fetchone()
            if not programme:
                flash("Choose a programme belonging to your institution.", "error")
                return redirect(url_for("admissions_workspace"))
            db.execute("INSERT INTO intake_allocations(institution,programme_id,intake_year,capacity,status,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                       (session["institution"], programme_id, year, capacity, status, session["username"], now(), now()))
            db.commit()
        audit("admissions.intake_created", "intake_allocation", f"{programme_id}:{year}", f"Capacity {capacity}; status {status}")
        flash("Intake allocation created.", "success")
    except (ValueError, TypeError, sqlite3.IntegrityError):
        flash("Check the programme, year, capacity, and duplicate intake details.", "error")
    return redirect(url_for("admissions_workspace"))


@app.route("/admissions/enrolments", methods=["POST"])
@login_required
@role_required("institution_admin", "operator")
def enrolment_create():
    code = request.form.get("institutional_enrolment_id", "").strip()
    student_category = request.form.get("student_category", "unknown").strip()
    seat_type = request.form.get("seat_type", "regular").strip()
    if student_category not in {"domestic", "nri", "oci", "foreign_national", "unknown"} or seat_type not in {"regular", "supernumerary"}:
        flash("Choose a supported student category and seat type.", "error")
        return redirect(url_for("admissions_workspace"))
    try:
        student_id = int(request.form.get("student_id", ""))
        allocation_id = int(request.form.get("allocation_id", ""))
        if not code or len(code) > 64:
            raise ValueError
        with connect_db() as db:
            # Serialize capacity checks and inserts. Without an immediate write lock,
            # two concurrent requests could both observe the final available place.
            db.execute("BEGIN IMMEDIATE")
            institution = session["institution"]
            student = db.execute("SELECT id FROM students WHERE id=? AND institution=? AND archived_at IS NULL", (student_id, institution)).fetchone()
            allocation = db.execute("SELECT id,capacity,status FROM intake_allocations WHERE id=? AND institution=?", (allocation_id, institution)).fetchone()
            if not student or not allocation or allocation["status"] != "open":
                db.rollback()
                flash("Choose an active student and an open intake from your institution.", "error")
                return redirect(url_for("admissions_workspace"))
            duplicate_code = db.execute("SELECT 1 FROM enrolments WHERE lower(trim(institution))=lower(trim(?)) AND lower(trim(institutional_enrolment_id))=lower(trim(?)) LIMIT 1", (institution, code)).fetchone()
            if duplicate_code:
                db.rollback()
                flash("That enrolment ID already exists in this institution.", "error")
                return redirect(url_for("admissions_workspace"))
            count = db.execute("SELECT COUNT(*) FROM enrolments WHERE allocation_id=? AND status NOT IN ('withdrawn','rejected')", (allocation_id,)).fetchone()[0]
            if count >= allocation["capacity"]:
                db.rollback()
                flash("This intake has reached its configured capacity.", "error")
                return redirect(url_for("admissions_workspace"))
            timestamp = now()
            db.execute("INSERT INTO enrolments(institution,student_id,allocation_id,institutional_enrolment_id,student_category,seat_type,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                       (institution, student_id, allocation_id, code, student_category, seat_type, session["username"], timestamp, timestamp))
            db.commit()
        audit("admissions.enrolment_created", "enrolment", code, "Draft enrolment created")
        flash("Draft enrolment created.", "success")
    except (ValueError, TypeError, sqlite3.IntegrityError):
        flash("Check the student, intake, enrolment ID, and existing enrolments.", "error")
    return redirect(url_for("admissions_workspace"))


@app.route("/admissions/submissions", methods=["GET"])
@login_required
@role_required("institution_admin", "operator", "verifier", "auditor")
def admissions_submission_register():
    """Institution-scoped register of versioned admissions submissions."""
    institution = session.get("institution")
    status_filter = request.args.get("status", "").strip()
    allowed_statuses = {"submitted", "under_review", "approved", "rejected", "returned_for_correction"}
    with connect_db() as db:
        query = """SELECT sub.id AS submission_id,sub.enrolment_id,sub.version,sub.status AS submission_status,
            sub.submitted_by,sub.submitted_at,sub.reviewed_by,sub.reviewed_at,sub.review_note,sub.snapshot_hash,
            e.institutional_enrolment_id,s.full_name,s.institution_student_id,p.code AS programme_code,
            a.intake_year FROM enrolment_submissions sub
            JOIN enrolments e ON e.id=sub.enrolment_id AND e.institution=sub.institution
            JOIN students s ON s.id=e.student_id AND s.institution=e.institution
            JOIN intake_allocations a ON a.id=e.allocation_id AND a.institution=e.institution
            JOIN programmes p ON p.id=a.programme_id AND p.institution=a.institution
            WHERE sub.institution=?"""
        params = [institution]
        if status_filter in allowed_statuses:
            query += " AND sub.status=?"
            params.append(status_filter)
        query += " ORDER BY sub.submitted_at DESC,sub.id DESC LIMIT 250"
        submissions = db.execute(query, params).fetchall()
    audit("admissions.submission_register_viewed", "enrolment_submission", "register", "Viewed institution-scoped submission register")
    return render_template("admissions_submissions.html", submissions=submissions,
                           status_filter=status_filter if status_filter in allowed_statuses else "",
                           statuses=sorted(allowed_statuses), current_year=datetime.now().year)


@app.route("/admissions/enrolments/<int:enrolment_id>", methods=["GET", "POST"])
@login_required
@role_required("institution_admin", "operator", "verifier", "auditor")
def enrolment_detail(enrolment_id):
    institution = session.get("institution")
    with connect_db() as db:
        enrolment = db.execute("""SELECT e.*,s.full_name,s.institution_student_id,p.name AS programme_name,p.code AS programme_code,a.intake_year
            FROM enrolments e JOIN students s ON s.id=e.student_id JOIN intake_allocations a ON a.id=e.allocation_id
            JOIN programmes p ON p.id=a.programme_id WHERE e.id=? AND e.institution=?""", (enrolment_id,institution)).fetchone()
        if not enrolment:
            abort(404)
        if request.method == "POST":
            action = request.form.get("action", "")
            note = request.form.get("note", "").strip()[:1000]
            role = {"admin":"institution_admin"}.get(session.get("role"),session.get("role"))
            if action == "classification" and role in {"institution_admin", "operator"} and enrolment["status"] in {"draft", "returned_for_correction"}:
                student_category = request.form.get("student_category", "").strip()
                seat_type = request.form.get("seat_type", "").strip()
                if student_category not in {"domestic", "nri", "oci", "foreign_national", "unknown"} or seat_type not in {"regular", "supernumerary"}:
                    flash("Choose a supported student category and seat type.", "error")
                else:
                    timestamp = now()
                    db.execute("UPDATE enrolments SET student_category=?,seat_type=?,updated_at=? WHERE id=? AND institution=?",
                               (student_category, seat_type, timestamp, enrolment_id, institution))
                    db.commit()
                    audit("admissions.classification_updated", "enrolment", enrolment_id,
                          f"Student category={student_category}; seat type={seat_type}")
                    flash("Admissions classification updated. This is a recorded classification, not an eligibility decision.", "success")
            elif action == "submit" and role in {"institution_admin","operator"} and enrolment["status"] in {"draft","returned_for_correction"}:
                # Lock before calculating the version to prevent duplicate version races.
                db.execute("BEGIN IMMEDIATE")
                current_status = db.execute("SELECT status FROM enrolments WHERE id=? AND institution=?", (enrolment_id, institution)).fetchone()
                if not current_status or current_status["status"] not in {"draft", "returned_for_correction"}:
                    db.rollback()
                    flash("This enrolment has already been submitted. Refresh and check its current status.", "error")
                    return redirect(url_for("enrolment_detail", enrolment_id=enrolment_id))
                authorization = db.execute("""SELECT id,data_categories_json FROM data_use_authorizations
                    WHERE institution=? AND student_id=(SELECT student_id FROM enrolments WHERE id=? AND institution=?)
                      AND purpose='admissions_submission' AND status='active'
                      AND (valid_until IS NULL OR valid_until>=?)
                    ORDER BY recorded_at DESC,id DESC LIMIT 1""",
                    (institution, enrolment_id, institution, datetime.now(timezone.utc).date().isoformat())).fetchone()
                required_categories = {"identity", "academic_record", "admissions_record"}
                authorized_categories = set(json.loads(authorization["data_categories_json"])) if authorization else set()
                if not authorization or not required_categories.issubset(authorized_categories):
                    db.rollback()
                    flash("An effective admissions authorization covering identity, academic record, and admissions record is required before submission.", "error")
                    return redirect(url_for("enrolment_detail", enrolment_id=enrolment_id))
                version = db.execute("SELECT COALESCE(MAX(version),0)+1 FROM enrolment_submissions WHERE enrolment_id=?", (enrolment_id,)).fetchone()[0]
                # Freeze the submitted version so later edits to the student/intake record
                # cannot silently rewrite what was reviewed. Exclude APAAR identifier/email.
                snapshot_row = db.execute("""SELECT e.institution,e.institutional_enrolment_id,e.status AS enrolment_status,
                    e.student_category,e.seat_type,s.id AS local_student_record_id,s.institution_student_id,s.full_name,s.course,s.semester,
                    p.code AS programme_code,p.name AS programme_name,a.intake_year,a.capacity AS configured_capacity
                    FROM enrolments e JOIN students s ON s.id=e.student_id
                    JOIN intake_allocations a ON a.id=e.allocation_id JOIN programmes p ON p.id=a.programme_id
                    WHERE e.id=? AND e.institution=? AND s.institution=? AND a.institution=? AND p.institution=?""",
                    (enrolment_id,institution,institution,institution,institution)).fetchone()
                if not snapshot_row:
                    db.rollback()
                    flash("The enrolment could not be safely snapshotted. No submission was created.", "error")
                    return redirect(url_for("enrolment_detail", enrolment_id=enrolment_id))
                snapshot = {key: snapshot_row[key] for key in snapshot_row.keys()}
                snapshot["submitted_status"] = "submitted"
                snapshot["snapshot_schema"] = "admissions-submission-v1"
                snapshot_json = json.dumps(snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                snapshot_hash = hashlib.sha256(snapshot_json.encode("utf-8")).hexdigest()
                timestamp = now()
                db.execute("INSERT INTO enrolment_submissions(institution,enrolment_id,version,status,submitted_by,submitted_at,authorization_id,snapshot_json,snapshot_hash) VALUES(?,?,?,?,?,?,?,?,?)",
                           (institution,enrolment_id,version,"submitted",session["username"],timestamp,authorization["id"],snapshot_json,snapshot_hash))
                db.execute("UPDATE enrolments SET status='submitted',updated_at=? WHERE id=? AND institution=?", (timestamp,enrolment_id,institution))
                db.commit()
                audit("admissions.submitted", "enrolment", enrolment_id, f"Submission version {version}")
                flash("Enrolment submitted for review.", "success")
            elif action in {"approve","reject","return"} and role in {"institution_admin","verifier"} and enrolment["status"] in {"submitted","under_review"}:
                if action in {"reject", "return"} and not note:
                    flash("Provide a reason when rejecting or returning a submission.", "error")
                    return redirect(url_for("enrolment_detail", enrolment_id=enrolment_id))
                mapping = {"approve":("approved","approved"),"reject":("rejected","rejected"),"return":("returned_for_correction","returned_for_correction")}
                submission_status, enrolment_status = mapping[action]
                db.execute("BEGIN IMMEDIATE")
                timestamp = now()
                updated = db.execute("UPDATE enrolment_submissions SET status=?,reviewed_by=?,reviewed_at=?,review_note=? WHERE enrolment_id=? AND version=(SELECT MAX(version) FROM enrolment_submissions WHERE enrolment_id=?) AND status IN ('submitted','under_review')",
                           (submission_status,session["username"],timestamp,note,enrolment_id,enrolment_id)).rowcount
                if not updated:
                    db.rollback()
                    flash("The submission has already been reviewed. Refresh and check its current status.", "error")
                    return redirect(url_for("enrolment_detail", enrolment_id=enrolment_id))
                db.execute("UPDATE enrolments SET status=?,updated_at=? WHERE id=? AND institution=?", (enrolment_status,timestamp,enrolment_id,institution))
                db.commit()
                audit("admissions."+action, "enrolment", enrolment_id, note or "Approved")
                flash("Review decision recorded.", "success")
            else:
                flash("This action is not allowed for your role or the current workflow state.", "error")
            return redirect(url_for("enrolment_detail", enrolment_id=enrolment_id))
        submissions = db.execute("SELECT * FROM enrolment_submissions WHERE enrolment_id=? AND institution=? ORDER BY version DESC", (enrolment_id,institution)).fetchall()
    return render_template("enrolment_detail.html", enrolment=enrolment, submissions=submissions,
                           current_role={"admin":"institution_admin"}.get(session.get("role"),session.get("role")), current_year=datetime.now().year)


# Initialize the existing application database.
init_db()


if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
    )

