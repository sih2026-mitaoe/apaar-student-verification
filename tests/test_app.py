import os
import sqlite3
import tempfile
import io
from pathlib import Path
import pytest
from werkzeug.security import generate_password_hash
from app import app as flask_app
import app as app_module
from conftest import login_client

@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("APAAR_DB_PATH", str(db_path))
    # app initializes its DB at import time, so reinitialize against test path.
    import app as app_module
    app_module.DB_PATH = str(db_path)
    app_module.init_db()
    flask_app.config.update(TESTING=True, SECRET_KEY="test-secret", APAAR_DB_PATH=str(db_path))
    from backend.db import init_db as init_backend_db
    with flask_app.app_context():
        init_backend_db()
    with flask_app.test_client() as client:
        yield client

def login(client):
    login_client(client)
    return client.get("/", follow_redirects=True)


def test_secret_key_placeholder_is_never_used_as_a_real_secret():
    with pytest.raises(RuntimeError, match="private SECRET_KEY"):
        app_module.resolve_secret_key("replace-with-a-random-secret-key", production=True)
    generated = app_module.resolve_secret_key("replace-with-a-random-secret-key", production=False)
    assert len(generated) >= 64
    assert generated != "replace-with-a-random-secret-key"
    assert app_module.resolve_secret_key("a-real-configured-secret") == "a-real-configured-secret"


def test_context_managed_database_connections_are_closed():
    with app_module.connect_db() as db:
        db.execute("SELECT 1")
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        db.execute("SELECT 1")

def test_login_and_dashboard(client):
    response = login(client)
    assert response.status_code == 200
    assert b"Student Data Management" in response.data or b"Total student records" in response.data
    assert b"Student record status" in response.data
    assert b"Work queue" in response.data
    assert b"Authoritative source verified" in response.data
    assert b"Record status distribution" in response.data
    assert b"not official verification results" in response.data


def test_dashboard_status_chart_uses_institution_records(client):
    login(client)
    with sqlite3.connect(app_module.DB_PATH) as db:
        db.execute("""INSERT INTO students(institution_student_id,full_name,institution,course,semester,status,created_at,updated_at)
            VALUES('CHART-SYN-1','Chart Synthetic Student','MITAOE Demo Campus','Computing','1','Pending','2026-10-01','2026-10-01')""")
        pending, total = db.execute("SELECT SUM(status='Pending'),COUNT(*) FROM students WHERE institution='MITAOE Demo Campus' AND archived_at IS NULL").fetchone()
    response = client.get("/")
    assert response.status_code == 200
    assert b"Record status distribution" in response.data
    percent = round(pending / total * 100, 1)
    assert f"{pending} records, {percent} percent marked Pending".encode() in response.data
    assert b"Action centre" in response.data
    assert b"Recent import outcomes" in response.data


def test_case_allocation_metrics_and_assignment_filters_use_persisted_scoped_cases(client):
    login(client)
    first = client.post("/api/v1/verification/cases", json={
        "student_id": "1", "case_type": "allocation_test",
        "reason": "Synthetic assigned workload item",
    })
    second = client.post("/api/v1/verification/cases", json={
        "student_id": "1", "case_type": "allocation_test",
        "reason": "Synthetic unassigned workload item",
    })
    assert first.status_code == second.status_code == 201
    with sqlite3.connect(app_module.DB_PATH) as db:
        db.execute("UPDATE workflow_cases SET assigned_to='synthetic-verifier' WHERE id=?", (first.json["id"],))
        assigned, unassigned = db.execute("""SELECT
            SUM(CASE WHEN COALESCE(assigned_to,'')<>'' THEN 1 ELSE 0 END),
            SUM(CASE WHEN COALESCE(assigned_to,'')='' THEN 1 ELSE 0 END)
            FROM workflow_cases WHERE institution_id='MITAOE Demo Campus'
            AND status IN ('open','in_review','waiting_for_evidence','escalated')""").fetchone()
    dashboard = client.get("/")
    assert f">{assigned}</strong>".encode() in dashboard.data
    assert f">{unassigned}</strong>".encode() in dashboard.data
    assigned_queue = client.get("/api/v1/review?case_assignee=assigned")
    unassigned_queue = client.get("/api/v1/review?case_assignee=unassigned")
    assert f'id="case-{first.json["id"]}"'.encode() in assigned_queue.data
    assert f'id="case-{second.json["id"]}"'.encode() not in assigned_queue.data
    assert f'id="case-{second.json["id"]}"'.encode() in unassigned_queue.data
    assert f'id="case-{first.json["id"]}"'.encode() not in unassigned_queue.data


def test_auditor_directory_hides_student_write_action_and_enforces_read_only(client):
    login(client)
    with sqlite3.connect(app_module.DB_PATH) as db:
        db.execute("INSERT INTO users(username,password_hash,role,institution) VALUES(?,?,?,?)", (
            "directory-auditor", generate_password_hash("AuditorPassword123!"),
            "auditor", "MITAOE Demo Campus"))
    auditor = flask_app.test_client()
    login_client(auditor, "directory-auditor", "AuditorPassword123!")
    directory = auditor.get("/students")
    assert directory.status_code == 200
    assert b"Export CSV" in directory.data
    assert b">Add student</a>" not in directory.data
    before = auditor.get("/api/v1/students").json["count"]
    denied = auditor.post("/students/new", data={
        "institution_student_id": "AUDITOR-CANNOT-WRITE",
        "full_name": "Synthetic Read Only Test",
        "csrf_token": auditor.environ_base["HTTP_X_CSRF_TOKEN"],
    })
    assert denied.status_code == 302
    assert auditor.get("/api/v1/students").json["count"] == before


def test_student_detail_shows_actionable_quality_findings(client):
    login(client)
    created = client.post("/api/v1/students", json={
        "student_code": "QUALITY-SYN-1", "full_name": "Synthetic Quality Student",
    })
    assert created.status_code == 201
    detail = client.get(f"/students/{created.json['id']}")
    assert detail.status_code == 200
    assert b"Data-quality findings" in detail.data
    assert b"incomplete.course" in detail.data
    assert b"Suggested next step" in detail.data
    assert b"Record verification summary" in detail.data
    assert b"Internal record status" in detail.data
    assert b"not official APAAR verification" in detail.data
    assert b"Open a review case" in detail.data


def test_review_workbench_collects_existing_tasks_and_filters_by_type(client):
    login(client)
    created = client.post("/api/v1/students", json={
        "student_code": "WORKBENCH-QUALITY-1", "full_name": "Synthetic Workbench Student",
    })
    assert created.status_code == 201
    case = client.post("/api/v1/verification/cases", json={
        "student_id": str(created.json["id"]), "case_type": "workbench_followup",
        "reason": "Synthetic workbench case for queue coverage",
    })
    assert case.status_code == 201
    detail = client.get(f"/students/{created.json['id']}")
    assert b"Related duplicate reviews" in detail.data
    assert b"Related verification cases" in detail.data
    assert f"?case_student={created.json['id']}".encode() in detail.data
    create_case_form = client.get(f"/api/v1/review?case_student={created.json['id']}")
    assert f'<option value="{created.json["id"]}" selected'.encode() in create_case_form.data
    with app_module.connect_db() as db:
        other_student = db.execute("SELECT id FROM students WHERE institution='MITAOE Demo Campus' AND id<>? LIMIT 1",
                                   (created.json["id"],)).fetchone()[0]
        db.execute("""INSERT INTO duplicate_candidates
            (id,institution_id,student_a_id,student_b_id,score,signals_json,status,created_at)
            VALUES('WORKBENCH-DUP-1','MITAOE Demo Campus',?,?,76,'[\"similar_normalized_name\"]','pending_review','2026-10-22T00:00:00+00:00')""",
            (created.json["id"], other_student))
    summary = client.get(f"/students/{created.json['id']}")
    assert b"WORKBENCH-DUP-1" in summary.data or b"Open candidate review" in summary.data
    assert b"pending review" in summary.data
    preview = client.post("/imports", data={
        "file": (io.BytesIO(b"institution_student_id,full_name\nWORKBENCH-IMPORT-1,Synthetic Import Student\n"), "workbench.csv")
    }, follow_redirects=True)
    assert preview.status_code == 200
    with app_module.connect_db() as db:
        import_id = db.execute("SELECT id FROM import_jobs WHERE file_name='workbench.csv'").fetchone()[0]

    page = client.get("/api/v1/review?work_type=all")
    assert page.status_code == 200
    assert b"Actionable work" in page.data
    assert b"Records with quality findings" in page.data
    assert b"WORKBENCH-QUALITY-1" in page.data
    assert b"#case-" + case.json["id"].encode() in page.data
    assert b"#candidate-WORKBENCH-DUP-1" in page.data
    assert b"workbench.csv" in page.data
    quality_only = client.get("/api/v1/review?work_type=quality")
    assert quality_only.status_code == 200
    assert b"WORKBENCH-QUALITY-1" in quality_only.data
    assert b"workbench.csv" not in quality_only.data
    imports_only = client.get("/api/v1/review?work_type=imports")
    assert b"workbench.csv" in imports_only.data
    assert b'class="work-item-kind">Record quality' not in imports_only.data
    assert client.get(f"/imports?job_id={import_id}").status_code == 200


def test_review_workbench_is_institution_scoped_and_auditors_get_read_only_summary(client):
    login(client)
    case = client.post("/api/v1/verification/cases", json={
        "student_id": "1", "case_type": "private_case", "reason": "Synthetic private institution case",
    })
    assert case.status_code == 201
    from werkzeug.security import generate_password_hash
    with app_module.connect_db() as db:
        db.execute("INSERT INTO users(username,password_hash,role,institution) VALUES(?,?,?,?)",
                   ("workbench-auditor", generate_password_hash("AuditorPass123!"), "auditor", "Other Synthetic Campus"))
    other = flask_app.test_client()
    login_client(other, "workbench-auditor", "AuditorPass123!")
    page = other.get("/api/v1/review")
    assert page.status_code == 200
    assert case.json["id"].encode() not in page.data
    assert b"Create review case" not in page.data
    assert b"Run duplicate scan" not in page.data
    assert b'class="upload-form"' not in other.get("/imports").data
    assert b"Add student" not in other.get("/").data
    assert other.post("/api/v1/verification/cases", json={
        "student_id": "1", "case_type": "forbidden", "reason": "Auditor cannot create cases",
    }).status_code == 403


def test_case_workspace_filters_status_reason_priority_and_age(client):
    login(client)
    old = client.post("/api/v1/verification/cases", json={
        "student_id": "1", "case_type": "quality_followup", "priority": "high",
        "reason": "Synthetic old case for age filter testing",
    })
    recent = client.post("/api/v1/verification/cases", json={
        "student_id": "1", "case_type": "record_followup", "priority": "low",
        "reason": "Synthetic recent case for filter testing",
    })
    assert old.status_code == recent.status_code == 201
    with sqlite3.connect(app_module.DB_PATH) as db:
        db.execute("UPDATE workflow_cases SET created_at='2026-01-01T00:00:00+00:00' WHERE id=?", (old.json["id"],))
        db.execute("UPDATE workflow_cases SET created_at='2026-10-22T00:00:00+00:00' WHERE id=?", (recent.json["id"],))
        db.execute("UPDATE workflow_cases SET status='closed' WHERE id=?", (recent.json["id"],))
    filtered = client.get("/api/v1/review?case_status=active&case_priority=high&case_age=30&case_q=old%20case")
    assert filtered.status_code == 200
    assert b"Synthetic old case for age filter testing" in filtered.data
    assert b"Synthetic recent case for filter testing" not in filtered.data
    closed = client.get("/api/v1/review?case_status=closed")
    assert b"Synthetic recent case for filter testing" in closed.data


def test_review_queue_explains_duplicate_score_as_a_signal(client):
    login(client)
    response = client.get("/api/v1/review")
    assert response.status_code == 200
    assert b"similarity score and its signals are prompts for review" in response.data
    assert b"not proof" in response.data


def test_duplicate_review_compares_fields_without_showing_email_values(client):
    login(client)
    with sqlite3.connect(app_module.DB_PATH) as db:
        ids = db.execute("SELECT id FROM students WHERE institution='MITAOE Demo Campus' ORDER BY id LIMIT 2").fetchall()
        db.execute("""INSERT INTO duplicate_candidates(id,institution_id,student_a_id,student_b_id,score,signals_json,status,created_at)
            VALUES('COMPARE-SYN','MITAOE Demo Campus',?,?,75,'[\"similar_normalized_name\"]','pending_review','2026-10-01T00:00:00')""",
            (ids[0][0], ids[1][0]))
        db.execute("UPDATE students SET email='private-one@example.test' WHERE id=?", (ids[0][0],))
        db.execute("UPDATE students SET email='private-two@example.test' WHERE id=?", (ids[1][0],))
    page = client.get("/api/v1/review")
    assert b"Field comparison" in page.data
    assert b"Email" in page.data and b"Differs" in page.data
    assert b"private-one@example.test" not in page.data
    assert b"private-two@example.test" not in page.data

def test_students_page(client):
    login(client)
    response = client.get("/students")
    assert response.status_code == 200
    assert b"DEMO-1001" in response.data


def test_student_directory_filters_and_paginates(client):
    login(client)
    with sqlite3.connect(app_module.DB_PATH) as db:
        db.executemany("""INSERT INTO students(institution_student_id,full_name,institution,course,semester,status,created_at,updated_at)
            VALUES(?,?,?,?,?,'Pending','2026-01-01','2026-01-01')""",
            [(f"PAGE-{index:03}",f"Page Student {index}","MITAOE Demo Campus","Engineering","1") for index in range(55)])
    page = client.get("/students?page=2")
    assert page.status_code == 200
    assert b"Showing 9 of 59 matching records" in page.data
    filtered = client.get("/students?status=Pending&q=Page%20Student")
    assert filtered.status_code == 200
    assert b"Showing 50 of 55 matching records" in filtered.data


def test_student_directory_filters_by_course_and_semester(client):
    login(client)
    with sqlite3.connect(app_module.DB_PATH) as db:
        db.executemany("""INSERT INTO students(institution_student_id,full_name,institution,course,semester,status,created_at,updated_at)
            VALUES(?,?,?,?,?,'Pending','2026-01-01','2026-01-01')""", [
            ("FILTER-ENG-1", "Engineering Filter Student", "MITAOE Demo Campus", "Engineering", "1"),
            ("FILTER-ART-2", "Arts Filter Student", "MITAOE Demo Campus", "Arts", "2"),
        ])
    response = client.get("/students?course=Engineering&semester=1")
    assert response.status_code == 200
    assert b"FILTER-ENG-1" in response.data
    assert b"FILTER-ART-2" not in response.data


def test_audit_filters_are_applied_to_institution_events(client):
    login(client)
    with sqlite3.connect(app_module.DB_PATH) as db:
        db.executemany("""INSERT INTO audit_logs(institution,actor,action,entity,entity_id,details,created_at)
            VALUES('MITAOE Demo Campus',?,?,?,?,?,?)""", [
            ("admin", "student.created", "student", "10", "Synthetic audit test", "2026-10-01T00:00:00"),
            ("admin", "csv_import", "students", "11", "Synthetic import test", "2026-10-02T00:00:00"),
        ])
    filtered = client.get("/audit?action=student.created&actor=admin")
    assert filtered.status_code == 200
    assert b"Synthetic audit test" in filtered.data
    assert b"Synthetic import test" not in filtered.data


def test_duplicate_review_links_candidates_to_both_student_records(client):
    login(client)
    with sqlite3.connect(app_module.DB_PATH) as db:
        rows = db.execute("SELECT id FROM students WHERE institution='MITAOE Demo Campus' ORDER BY id LIMIT 2").fetchall()
        assert len(rows) == 2
        db.execute("""INSERT INTO duplicate_candidates(id,institution_id,student_a_id,student_b_id,score,signals_json,status,created_at)
            VALUES('UX-CANDIDATE','MITAOE Demo Campus',?,?,87,'[\"similar_normalized_name\"]','pending_review','2026-10-01T00:00:00')""",
            (rows[0][0], rows[1][0]))
    response = client.get("/api/v1/review")
    assert response.status_code == 200
    assert b"Match score (review signal)" in response.data
    assert f'href="/students/{rows[0][0]}"'.encode() in response.data
    assert f'href="/students/{rows[1][0]}"'.encode() in response.data

def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json["status"] == "ok"

def test_local_verification_is_not_official(client):
    login(client)
    response = client.post("/students/1/verify", follow_redirects=True)
    assert response.status_code == 200
    assert b"No official APAAR lookup was performed" in response.data


def test_csrf_rejects_state_changes_without_token(client):
    login(client)
    response = client.post("/api/v1/students", json={
        "student_code": "CSRF-001", "full_name": "Blocked Request",
    }, headers={"X-CSRF-Token": "invalid"})
    assert response.status_code == 400


def test_login_throttles_repeated_failures():
    client = flask_app.test_client()
    for _ in range(5):
        response = login_client(client, "admin", "WrongPassword")
        assert response.status_code == 200
    blocked = login_client(client, "admin", "WrongPassword")
    assert blocked.status_code == 429
    app_module.login_failures.pop("127.0.0.1", None)


def test_archive_preserves_student_history_and_hides_record(client):
    login(client)
    details = client.get("/students/1")
    assert details.status_code == 200
    verified = client.post("/students/1/verify", follow_redirects=True)
    assert verified.status_code == 200
    archived = client.post("/students/1/archive", follow_redirects=True)
    assert archived.status_code == 200
    assert b"Student record archived" in archived.data
    assert client.get("/students/1").status_code == 302
    assert b"No records match these filters" in client.get("/students?q=DEMO-1001").data
    with sqlite3.connect(app_module.DB_PATH) as db:
        row = db.execute("SELECT archived_at FROM students WHERE id=1").fetchone()
        assert row and row[0]
        assert db.execute("SELECT count(*) FROM workflow_cases WHERE student_id=1").fetchone()[0] == 1


def test_archive_restore_preserves_id_and_requires_conflict_resolution(client):
    login(client)
    client.post("/students/1/verify")
    archived = client.post("/students/1/archive", follow_redirects=True)
    assert archived.status_code == 200
    assert client.get("/students/archived").status_code == 200
    conflict = client.post("/students/1/restore", data={
        "institution_student_id": "DEMO-1002",
    }, follow_redirects=True)
    assert b"belongs to another record" in conflict.data
    with sqlite3.connect(app_module.DB_PATH) as db:
        assert db.execute("SELECT archived_at FROM students WHERE id=1").fetchone()[0]
        assert db.execute("SELECT COUNT(*) FROM workflow_cases WHERE student_id=1").fetchone()[0] == 1
    restored = client.post("/students/1/restore", data={
        "institution_student_id": "RESTORED-1001",
    }, follow_redirects=True)
    assert restored.status_code == 200
    assert b"Student record restored" in restored.data
    with sqlite3.connect(app_module.DB_PATH) as db:
        assert db.execute("SELECT institution_student_id,archived_at FROM students WHERE id=1").fetchone() == ("RESTORED-1001", None)
        assert db.execute("SELECT COUNT(*) FROM workflow_cases WHERE student_id=1").fetchone()[0] == 1


def test_institution_admin_user_management_hashes_password_and_limits_roles(client):
    login(client)
    assert client.get("/admin/users").status_code == 200
    created = client.post("/admin/users", data={
        "username": "new-auditor", "email": "new-auditor@example.test", "password": "A-Strong-Temporary-Password-42", "role": "auditor",
    }, follow_redirects=True)
    assert created.status_code == 200 and b"User account created" in created.data
    with sqlite3.connect(app_module.DB_PATH) as db:
        row = db.execute("SELECT password_hash,role,institution,is_active FROM users WHERE username='new-auditor'").fetchone()
        assert row and row[0] != "A-Strong-Temporary-Password-42"
        assert row[1:] == ("auditor", "MITAOE Demo Campus", 1)
    denied_admin = client.post("/admin/users", data={
        "username": "self-promote-test", "password": "A-Strong-Temporary-Password-42", "role": "institution_admin",
    }, follow_redirects=True)
    assert b"approved non-administrator role" in denied_admin.data
    with sqlite3.connect(app_module.DB_PATH) as db:
        user_id = db.execute("SELECT id FROM users WHERE username='new-auditor'").fetchone()[0]
    changed = client.post(f"/admin/users/{user_id}/role", data={"role": "verifier"}, follow_redirects=True)
    assert b"Account role updated" in changed.data
    self_change = client.post("/admin/users/1/role", data={"role": "auditor"}, follow_redirects=True)
    assert b"cannot change your own role" in self_change.data
    disabled = client.post(f"/admin/users/{user_id}/active", follow_redirects=True)
    assert disabled.status_code == 200
    activated = client.post(f"/admin/users/{user_id}/active", follow_redirects=True)
    assert b"Account activated" in activated.data
    with sqlite3.connect(app_module.DB_PATH) as db:
        assert db.execute("SELECT is_active,role FROM users WHERE username='new-auditor'").fetchone() == (1, "verifier")
        assert db.execute("SELECT COUNT(*) FROM audit_events WHERE action='account.created'").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM audit_events WHERE action='account.role_changed'").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM audit_events WHERE action IN ('account.deactivated','account.activated')").fetchone()[0] == 2


def test_production_first_admin_requires_private_password(tmp_path, monkeypatch):
    production_db = tmp_path / "production-empty.db"
    monkeypatch.setattr(app_module, "DB_PATH", str(production_db))
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.delenv("DEMO_ADMIN_PASSWORD", raising=False)
    with pytest.raises(RuntimeError, match="DEMO_ADMIN_PASSWORD"):
        app_module.init_db()
    with sqlite3.connect(production_db) as db:
        assert db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
    production_login = flask_app.test_client().get("/login")
    assert production_login.status_code == 200
    assert b"ChangeMe123!" not in production_login.data


def test_csv_export_neutralizes_spreadsheet_formulas(client):
    login(client)
    client.post("/students/new", data={
        "institution_student_id": "CSV-FORMULA-1", "full_name": "=HYPERLINK(\"https://example.invalid\")",
        "institution": "Demo", "course": "Engineering", "semester": "1",
    })
    response = client.get("/students/export.csv")
    assert response.status_code == 200
    assert b"'=HYPERLINK" in response.data


def test_case_timeline_shows_chronological_events_and_linked_audit(client):
    login(client)
    created = client.post("/api/v1/verification/cases", json={
        "student_id": "1", "case_type": "timeline_test",
        "reason": "Synthetic timeline case reason",
    })
    case_id = created.json["id"]
    moved = client.post(f"/api/v1/review/cases/{case_id}/transition", data={
        "status": "in_review", "note": "Synthetic reviewer started review",
    }, follow_redirects=True)
    assert moved.status_code == 200
    with sqlite3.connect(app_module.DB_PATH) as db:
        db.execute("UPDATE case_events SET created_at='2026-10-20T00:00:00+00:00' WHERE case_id=? AND event_type='case.created'", (case_id,))
        db.execute("UPDATE case_events SET created_at='2026-10-21T00:00:00+00:00' WHERE case_id=? AND event_type='case.transitioned'", (case_id,))
    page = client.get("/api/v1/review?case_status=all")
    assert page.status_code == 200
    assert b"Case activity timeline" in page.data
    assert b"Synthetic timeline case reason" in page.data
    assert b"Synthetic reviewer started review" in page.data
    assert b"Linked audit records" in page.data
    assert page.data.index(b"case created") < page.data.index(b"case transitioned")
    timeline = client.get(f"/api/v1/verification/cases/{case_id}/timeline")
    assert timeline.status_code == 200
    assert len(timeline.json["audit_events"]) == 2


def test_case_age_categories_handle_configured_thresholds_and_bad_timestamps(client):
    login(client)
    created = client.post("/api/v1/verification/cases", json={
        "student_id": "1", "case_type": "age_test", "reason": "Synthetic age category case",
    })
    case_id = created.json["id"]
    flask_app.config["CASE_AGE_THRESHOLDS_DAYS"] = (2, 5)
    try:
        with sqlite3.connect(app_module.DB_PATH) as db:
            db.execute("UPDATE workflow_cases SET created_at='2026-10-15T00:00:00+00:00' WHERE id=?", (case_id,))
        page = client.get("/api/v1/review")
        assert b"Internal review target bands: under 2 days / 2-4 days / 5+ days" in page.data
        assert b"5+ days" in page.data
        with sqlite3.connect(app_module.DB_PATH) as db:
            db.execute("UPDATE workflow_cases SET created_at='not-a-date' WHERE id=?", (case_id,))
        malformed = client.get("/api/v1/review")
        assert malformed.status_code == 200
        assert b"Age unavailable" in malformed.data
    finally:
        flask_app.config["CASE_AGE_THRESHOLDS_DAYS"] = (7, 30)


def test_filtered_case_export_is_authorized_scoped_and_formula_safe(client):
    response = flask_app.test_client().get("/api/v1/reports/cases.csv")
    assert response.status_code == 401
    login(client)
    first = client.post("/api/v1/verification/cases", json={
        "student_id": "1", "case_type": "=1+1", "priority": "high",
        "reason": "Synthetic formula case",
    })
    second = client.post("/api/v1/verification/cases", json={
        "student_id": "1", "case_type": "other_category", "priority": "low",
        "reason": "Synthetic excluded case",
    })
    assert first.status_code == second.status_code == 201
    report = client.get("/api/v1/reports/cases.csv?case_status=open&case_priority=high&case_q=formula")
    assert report.status_code == 200
    assert b"'=1+1" in report.data
    assert first.json["id"].encode() in report.data
    assert second.json["id"].encode() not in report.data
    assert b"full_name" not in report.data and b"student_code" not in report.data and b"email" not in report.data
    with app_module.connect_db() as db:
        assert db.execute("SELECT COUNT(*) FROM audit_events WHERE action='verification_cases.exported'").fetchone()[0] == 1

    from werkzeug.security import generate_password_hash
    with app_module.connect_db() as db:
        db.execute("INSERT INTO users(username,password_hash,role,institution) VALUES(?,?,?,?)",
                   ("case-export-other", generate_password_hash("AnotherPass123!"), "operator", "Other Synthetic Institution"))
    other_client = flask_app.test_client()
    login_client(other_client, "case-export-other", "AnotherPass123!")
    other_report = other_client.get("/api/v1/reports/cases.csv?case_status=all")
    assert other_report.status_code == 200
    assert first.json["id"].encode() not in other_report.data
    assert b"=1+1" not in other_report.data


def test_additive_schema_upgrade_creates_verified_backup_and_preserves_rows(tmp_path, monkeypatch):
    db_path = tmp_path / "legacy-main.db"
    with sqlite3.connect(db_path) as db:
        db.executescript("""
        CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'admin');
        CREATE TABLE students(id INTEGER PRIMARY KEY, institution_student_id TEXT NOT NULL UNIQUE, full_name TEXT NOT NULL,
            institution TEXT NOT NULL DEFAULT 'Demo', course TEXT NOT NULL DEFAULT '', semester TEXT NOT NULL DEFAULT '',
            apaar_id TEXT NOT NULL DEFAULT '', email TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'Pending',
            notes TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE verification_cases(id INTEGER PRIMARY KEY, student_id INTEGER NOT NULL, status TEXT NOT NULL,
            summary TEXT NOT NULL, findings TEXT NOT NULL, source TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE institution_source_comparisons(id TEXT PRIMARY KEY,institution TEXT NOT NULL,dataset_id TEXT NOT NULL,
            dataset_version INTEGER NOT NULL,student_id INTEGER NOT NULL,actor TEXT NOT NULL,outcome TEXT NOT NULL,
            explanation TEXT NOT NULL,fields_json TEXT NOT NULL,created_at TEXT NOT NULL);
        CREATE TABLE audit_logs(id INTEGER PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, entity TEXT NOT NULL,
            entity_id TEXT NOT NULL, details TEXT NOT NULL, created_at TEXT NOT NULL);
        INSERT INTO users(username,password_hash,role) VALUES('admin','hash','admin');
        INSERT INTO students(institution_student_id,full_name,institution,created_at,updated_at)
            VALUES('KEEP-001','Synthetic Legacy','Demo','2026-01-01','2026-01-01');
        INSERT INTO verification_cases(student_id,status,summary,findings,source,created_at)
            VALUES(1,'Pending','Existing history','Existing finding','Legacy local rules','2026-01-01');
        """)
    monkeypatch.setattr(app_module, "DB_PATH", str(db_path))
    app_module.backup_before_schema_upgrade()
    backups = list(tmp_path.glob("legacy-main.pre-upgrade-*.db"))
    assert len(backups) == 1
    with sqlite3.connect(backups[0]) as backup:
        assert backup.execute("SELECT count(*) FROM students").fetchone()[0] == 1
        assert "archived_at" not in {row[1] for row in backup.execute("PRAGMA table_info(students)")}
    app_module.init_db()
    with sqlite3.connect(db_path) as upgraded:
        assert upgraded.execute("SELECT institution_student_id FROM students WHERE id=1").fetchone()[0] == "KEEP-001"
        assert upgraded.execute("SELECT count(*) FROM verification_cases WHERE student_id=1").fetchone()[0] == 1
        comparison_columns = {row[1] for row in upgraded.execute("PRAGMA table_info(institution_source_comparisons)")}
        assert {"run_status", "ruleset_version", "input_digest", "result_digest",
                "student_updated_at_snapshot", "outcome_counts_json"}.issubset(comparison_columns)
        assert upgraded.execute("PRAGMA integrity_check").fetchone()[0] == "ok"



def test_shared_database_identity_reconciliation_is_disabled_by_default(client):
    import app as app_module
    from conftest import login_client

    login_client(client)
    app_module.app.config["ENABLE_SHARED_DEMO_RECONCILIATION"] = False
    response = client.get("/identity-reconciliation")
    assert response.status_code == 503
