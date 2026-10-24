import sqlite3

from conftest import login_client
import app as app_module


def _csrf(client):
    with client.session_transaction() as sess:
        return sess["_csrf_token"]


def _setup_programme_and_intake():
    with sqlite3.connect(app_module.DB_PATH) as db:
        db.execute("INSERT INTO programmes(institution,code,name,created_by,created_at) VALUES(?,?,?,?,?)",
                   ("MITAOE Demo Campus", "MON-CSE", "Monitoring CSE", "admin", "2026-10-24"))
        programme_id = db.execute("SELECT id FROM programmes WHERE institution=? AND code='MON-CSE'",
                                  ("MITAOE Demo Campus",)).fetchone()[0]
        db.execute("INSERT INTO intake_allocations(institution,programme_id,intake_year,capacity,status,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                   ("MITAOE Demo Campus", programme_id, 2026, 100, "open", "admin", "2026-10-24", "2026-10-24"))
        allocation_id = db.execute("SELECT id FROM intake_allocations WHERE institution=? AND programme_id=? AND intake_year=2026",
                                   ("MITAOE Demo Campus", programme_id)).fetchone()[0]
        db.commit()
    return programme_id, allocation_id


def test_phase6_schema_adds_categories_and_versioned_intake(client):
    with sqlite3.connect(app_module.DB_PATH) as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(enrolments)")}
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"student_category", "seat_type"} <= columns
    assert "approved_intake_records" in tables


def test_approved_intake_reference_is_versioned_and_history_preserved(client):
    login_client(client)
    programme_id, _ = _setup_programme_and_intake()
    for count in (60, 62):
        response = client.post("/admissions/approved-intake", data={
            "csrf_token": _csrf(client), "programme_id": programme_id, "intake_year": "2026",
            "sanctioned_intake": str(count), "supernumerary_limit": "4",
            "approval_reference": "ORDER-SYN-001", "source_reference": "SYNTHETIC-FILE-001",
            "approval_date": "2026-07-01",
        }, follow_redirects=True)
        assert response.status_code == 200
    with sqlite3.connect(app_module.DB_PATH) as db:
        rows = db.execute("SELECT version,sanctioned_intake,status FROM approved_intake_records WHERE programme_id=? ORDER BY version",
                          (programme_id,)).fetchall()
    assert rows == [(1, 60, "superseded"), (2, 62, "current")]


def test_monitoring_flags_excess_and_missing_category(client):
    login_client(client)
    programme_id, allocation_id = _setup_programme_and_intake()
    response = client.post("/admissions/approved-intake", data={
        "csrf_token": _csrf(client), "programme_id": programme_id, "intake_year": "2026",
        "sanctioned_intake": "1", "supernumerary_limit": "0",
        "approval_reference": "ORDER-SYN-002", "source_reference": "SYNTHETIC-FILE-002",
        "approval_date": "2026-07-01",
    }, follow_redirects=True)
    assert response.status_code == 200
    with sqlite3.connect(app_module.DB_PATH) as db:
        for idx, category, seat in [(1, "unknown", "regular"), (2, "nri", "supernumerary")]:
            db.execute("INSERT INTO students(institution_student_id,full_name,institution,course,semester,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                       (f"MON-STU-{idx}", f"Synthetic Monitoring Student {idx}", "MITAOE Demo Campus", "CSE", "1", "Pending", "2026-10-24", "2026-10-24"))
            student_id = db.execute("SELECT id FROM students WHERE institution_student_id=?", (f"MON-STU-{idx}",)).fetchone()[0]
            db.execute("INSERT INTO enrolments(institution,student_id,allocation_id,institutional_enrolment_id,status,student_category,seat_type,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                       ("MITAOE Demo Campus", student_id, allocation_id, f"MON-ENR-{idx}", "approved", category, seat, "admin", "2026-10-24", "2026-10-24"))
        db.commit()
    page = client.get("/admissions/monitoring")
    assert page.status_code == 200
    assert b"Approved intake exceeded" in page.data
    assert b"Supernumerary limit exceeded" in page.data
    assert b"Category information missing" in page.data
    assert b"NRI 1" in page.data


def test_monitoring_is_institution_scoped(client):
    login_client(client)
    _setup_programme_and_intake()
    with sqlite3.connect(app_module.DB_PATH) as db:
        db.execute("INSERT INTO programmes(institution,code,name,created_by,created_at) VALUES(?,?,?,?,?)",
                   ("Another Synthetic Institution", "OTHER-001", "Other Programme", "admin", "2026-10-24"))
        other_programme = db.execute("SELECT id FROM programmes WHERE institution='Another Synthetic Institution'").fetchone()[0]
        db.execute("INSERT INTO intake_allocations(institution,programme_id,intake_year,capacity,status,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                   ("Another Synthetic Institution", other_programme, 2026, 10, "open", "admin", "2026-10-24", "2026-10-24"))
        db.commit()
    page = client.get("/admissions/monitoring")
    assert page.status_code == 200
    assert b"MON-CSE" in page.data
    assert b"OTHER-001" not in page.data
