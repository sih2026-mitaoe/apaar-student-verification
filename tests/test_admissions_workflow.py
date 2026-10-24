import sqlite3
from conftest import login_client
import app as app_module


def test_admissions_workflow_scopes_programmes_and_enrolments_to_institution(client):
    login_client(client)
    with sqlite3.connect(app_module.DB_PATH) as db:
        db.execute("INSERT INTO students(institution_student_id,full_name,institution,course,semester,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                   ("ADM-SYN-1", "Synthetic Admissions Student", "MITAOE Demo Campus", "Computing", "1", "Pending", "2026-10-23", "2026-10-23"))
        student_id = db.execute("SELECT id FROM students WHERE institution_student_id='ADM-SYN-1'").fetchone()[0]
    response = client.post("/admissions/programmes", data={"csrf_token": _csrf(client), "code": "BTECH-CSE", "name": "B.Tech Computer Science"}, follow_redirects=True)
    assert response.status_code == 200
    assert b"B.Tech Computer Science" in response.data
    with sqlite3.connect(app_module.DB_PATH) as db:
        programme_id = db.execute("SELECT id FROM programmes WHERE institution='MITAOE Demo Campus' AND code='BTECH-CSE'").fetchone()[0]
    response = client.post("/admissions/intakes", data={"csrf_token": _csrf(client), "programme_id": programme_id, "intake_year": "2026", "capacity": "1", "status": "open"}, follow_redirects=True)
    assert response.status_code == 200
    with sqlite3.connect(app_module.DB_PATH) as db:
        allocation_id = db.execute("SELECT id FROM intake_allocations WHERE institution='MITAOE Demo Campus' AND programme_id=?", (programme_id,)).fetchone()[0]
    response = client.post("/admissions/enrolments", data={"csrf_token": _csrf(client), "student_id": student_id, "allocation_id": allocation_id, "institutional_enrolment_id": "ENR-SYN-1"}, follow_redirects=True)
    assert response.status_code == 200
    with sqlite3.connect(app_module.DB_PATH) as db:
        enrolment_id = db.execute("SELECT id FROM enrolments WHERE institution='MITAOE Demo Campus' AND institutional_enrolment_id='ENR-SYN-1'").fetchone()[0]
    detail = client.get(f"/admissions/enrolments/{enrolment_id}")
    assert detail.status_code == 200
    assert b"Submit for review" in detail.data
    # Admissions submission must be backed by a current purpose-limited authorization.
    response = client.post(f"/students/{student_id}/authorizations", data={
        "csrf_token": _csrf(client), "purpose": "admissions_submission", "authority_basis": "institutional_policy",
        "data_categories": ["identity", "academic_record", "admissions_record"],
        "evidence_reference": "SYNTHETIC-AUTH-001", "note": "Synthetic test authorization"
    }, follow_redirects=True)
    assert response.status_code == 200
    response = client.post(f"/admissions/enrolments/{enrolment_id}", data={"csrf_token": _csrf(client), "action": "submit"}, follow_redirects=True)
    assert response.status_code == 200
    assert b"submitted" in response.data.lower()
    response = client.post(f"/admissions/enrolments/{enrolment_id}", data={"csrf_token": _csrf(client), "action": "approve", "note": "Synthetic record checked"}, follow_redirects=True)
    assert response.status_code == 200
    with sqlite3.connect(app_module.DB_PATH) as db:
        status = db.execute("SELECT status FROM enrolments WHERE id=?", (enrolment_id,)).fetchone()[0]
        submission_status = db.execute("SELECT status FROM enrolment_submissions WHERE enrolment_id=?", (enrolment_id,)).fetchone()[0]
        authorization_id, snapshot_json, snapshot_hash = db.execute("SELECT authorization_id,snapshot_json,snapshot_hash FROM enrolment_submissions WHERE enrolment_id=?", (enrolment_id,)).fetchone()
        authorization_status = db.execute("SELECT status FROM data_use_authorizations WHERE id=?", (authorization_id,)).fetchone()[0]
    assert status == submission_status == "approved"
    assert authorization_id is not None and authorization_status == "active"
    import hashlib, json
    snapshot = json.loads(snapshot_json)
    assert snapshot["institutional_enrolment_id"] == "ENR-SYN-1"
    assert snapshot["full_name"] == "Synthetic Admissions Student"
    assert snapshot["student_category"] == "unknown"
    assert snapshot["seat_type"] == "regular"
    assert "apaar_id" not in snapshot and "email" not in snapshot
    assert snapshot_hash == hashlib.sha256(snapshot_json.encode("utf-8")).hexdigest()
    register = client.get("/admissions/submissions")
    assert register.status_code == 200
    assert b"ENR-SYN-1" in register.data
    assert b"Snapshot integrity" in register.data


def test_admissions_rejects_intake_capacity_overflow(client):
    login_client(client)
    with sqlite3.connect(app_module.DB_PATH) as db:
        db.execute("INSERT INTO students(institution_student_id,full_name,institution,course,semester,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                   ("ADM-SYN-2", "Second Synthetic Student", "MITAOE Demo Campus", "Computing", "1", "Pending", "2026-10-23", "2026-10-23"))
        student_id = db.execute("SELECT id FROM students WHERE institution_student_id='ADM-SYN-2'").fetchone()[0]
        programme_id = db.execute("SELECT id FROM programmes WHERE institution='MITAOE Demo Campus' LIMIT 1").fetchone()
        if not programme_id:
            db.execute("INSERT INTO programmes(institution,code,name,created_by,created_at) VALUES(?,?,?,?,?)", ("MITAOE Demo Campus", "CAPACITY-TEST", "Capacity Test", "admin", "2026-10-23"))
            programme_id = db.execute("SELECT id FROM programmes WHERE institution='MITAOE Demo Campus' AND code='CAPACITY-TEST'").fetchone()
        programme_id = programme_id[0]
        db.execute("INSERT OR IGNORE INTO intake_allocations(institution,programme_id,intake_year,capacity,status,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", ("MITAOE Demo Campus", programme_id, 2099, 1, "open", "admin", "2026-10-23", "2026-10-23"))
        allocation_id = db.execute("SELECT id FROM intake_allocations WHERE institution='MITAOE Demo Campus' AND programme_id=? AND intake_year=2099", (programme_id,)).fetchone()[0]
        db.execute("INSERT INTO enrolments(institution,student_id,allocation_id,institutional_enrolment_id,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", ("MITAOE Demo Campus", student_id, allocation_id, "ENR-CAPACITY-FULL", "admin", "2026-10-23", "2026-10-23"))
        db.commit()
    response = client.post("/admissions/enrolments", data={"csrf_token": _csrf(client), "student_id": student_id, "allocation_id": allocation_id, "institutional_enrolment_id": "ENR-CAPACITY-OVERFLOW"}, follow_redirects=True)
    assert response.status_code == 200
    assert b"reached its configured capacity" in response.data
    with sqlite3.connect(app_module.DB_PATH) as db:
        assert db.execute("SELECT COUNT(*) FROM enrolments WHERE institutional_enrolment_id='ENR-CAPACITY-OVERFLOW'").fetchone()[0] == 0


def _csrf(client):
    with client.session_transaction() as sess:
        return sess["_csrf_token"]


def test_enrolment_id_duplicate_is_case_insensitive_and_institution_scoped(client):
    login_client(client)
    with sqlite3.connect(app_module.DB_PATH) as db:
        db.execute("INSERT INTO students(institution_student_id,full_name,institution,course,semester,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                   ("DUP-ENR-STU", "Duplicate Check Student", "MITAOE Demo Campus", "Computing", "1", "Pending", "2026-10-23", "2026-10-23"))
        student_id = db.execute("SELECT id FROM students WHERE institution_student_id='DUP-ENR-STU'").fetchone()[0]
        programme = db.execute("SELECT id FROM programmes WHERE institution='MITAOE Demo Campus' LIMIT 1").fetchone()
        if not programme:
            db.execute("INSERT INTO programmes(institution,code,name,created_by,created_at) VALUES(?,?,?,?,?)",
                       ("MITAOE Demo Campus", "DUP-CHECK", "Duplicate Check", "admin", "2026-10-23"))
            programme = db.execute("SELECT id FROM programmes WHERE institution='MITAOE Demo Campus' AND code='DUP-CHECK'").fetchone()
        programme_id = programme[0]
        db.execute("INSERT OR IGNORE INTO intake_allocations(institution,programme_id,intake_year,capacity,status,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                   ("MITAOE Demo Campus", programme_id, 2098, 5, "open", "admin", "2026-10-23", "2026-10-23"))
        allocation_id = db.execute("SELECT id FROM intake_allocations WHERE institution='MITAOE Demo Campus' AND programme_id=? AND intake_year=2098", (programme_id,)).fetchone()[0]
        db.execute("INSERT INTO enrolments(institution,student_id,allocation_id,institutional_enrolment_id,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                   ("MITAOE Demo Campus", student_id, allocation_id, "Case-Code-01", "admin", "2026-10-23", "2026-10-23"))
        db.commit()
    response = client.post("/admissions/enrolments", data={"csrf_token": _csrf(client), "student_id": student_id,
        "allocation_id": allocation_id, "institutional_enrolment_id": " case-code-01 "}, follow_redirects=True)
    assert response.status_code == 200
    assert b"enrolment ID already exists" in response.data
    with sqlite3.connect(app_module.DB_PATH) as db:
        assert db.execute("SELECT COUNT(*) FROM enrolments WHERE lower(trim(institutional_enrolment_id))='case-code-01'").fetchone()[0] == 1


def test_rejection_requires_a_reason(client):
    login_client(client)
    with sqlite3.connect(app_module.DB_PATH) as db:
        db.execute("INSERT INTO students(institution_student_id,full_name,institution,course,semester,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                   ("REASON-STU", "Review Reason Student", "MITAOE Demo Campus", "Computing", "1", "Pending", "2026-10-23", "2026-10-23"))
        student_id = db.execute("SELECT id FROM students WHERE institution_student_id='REASON-STU'").fetchone()[0]
        db.execute("INSERT INTO programmes(institution,code,name,created_by,created_at) VALUES(?,?,?,?,?)",
                   ("MITAOE Demo Campus", "REASON-PROG", "Reason Test", "admin", "2026-10-23"))
        programme_id = db.execute("SELECT id FROM programmes WHERE institution='MITAOE Demo Campus' AND code='REASON-PROG'").fetchone()[0]
        db.execute("INSERT INTO intake_allocations(institution,programme_id,intake_year,capacity,status,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                   ("MITAOE Demo Campus", programme_id, 2097, 5, "open", "admin", "2026-10-23", "2026-10-23"))
        allocation_id = db.execute("SELECT id FROM intake_allocations WHERE programme_id=?", (programme_id,)).fetchone()[0]
        db.execute("INSERT INTO enrolments(institution,student_id,allocation_id,institutional_enrolment_id,created_by,created_at,updated_at,status) VALUES(?,?,?,?,?,?,?,'submitted')",
                   ("MITAOE Demo Campus", student_id, allocation_id, "ENR-REASON", "admin", "2026-10-23", "2026-10-23"))
        enrolment_id = db.execute("SELECT id FROM enrolments WHERE institutional_enrolment_id='ENR-REASON'").fetchone()[0]
        db.execute("INSERT INTO enrolment_submissions(institution,enrolment_id,version,status,submitted_by,submitted_at) VALUES(?,?,1,'submitted','operator','2026-10-23')",
                   ("MITAOE Demo Campus", enrolment_id))
        db.commit()
    response = client.post(f"/admissions/enrolments/{enrolment_id}", data={"csrf_token": _csrf(client), "action": "reject", "note": ""}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Provide a reason" in response.data
    with sqlite3.connect(app_module.DB_PATH) as db:
        assert db.execute("SELECT status FROM enrolments WHERE id=?", (enrolment_id,)).fetchone()[0] == "submitted"
        assert db.execute("SELECT status FROM enrolment_submissions WHERE enrolment_id=?", (enrolment_id,)).fetchone()[0] == "submitted"


def test_submission_requires_effective_authorization(client):
    login_client(client)
    with sqlite3.connect(app_module.DB_PATH) as db:
        student_id = db.execute("SELECT id FROM students WHERE institution='MITAOE Demo Campus' AND archived_at IS NULL LIMIT 1").fetchone()[0]
        programme = db.execute("SELECT id FROM programmes WHERE institution='MITAOE Demo Campus' LIMIT 1").fetchone()
        if not programme:
            db.execute("INSERT INTO programmes(institution,code,name,created_by,created_at) VALUES(?,?,?,?,?)", ("MITAOE Demo Campus", "AUTH-GATE", "Authorization Gate", "admin", "2026-10-23"))
            programme = db.execute("SELECT id FROM programmes WHERE institution='MITAOE Demo Campus' AND code='AUTH-GATE'").fetchone()
        programme_id = programme[0]
        db.execute("INSERT OR IGNORE INTO intake_allocations(institution,programme_id,intake_year,capacity,status,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", ("MITAOE Demo Campus", programme_id, 2096, 20, "open", "admin", "2026-10-23", "2026-10-23"))
        allocation_id = db.execute("SELECT id FROM intake_allocations WHERE institution='MITAOE Demo Campus' AND programme_id=? AND intake_year=2096", (programme_id,)).fetchone()[0]
        db.execute("INSERT INTO enrolments(institution,student_id,allocation_id,institutional_enrolment_id,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", ("MITAOE Demo Campus", student_id, allocation_id, "ENR-AUTH-GATE", "admin", "2026-10-23", "2026-10-23"))
        enrolment_id = db.execute("SELECT id FROM enrolments WHERE institutional_enrolment_id='ENR-AUTH-GATE'").fetchone()[0]
        db.commit()
    response = client.post(f"/admissions/enrolments/{enrolment_id}", data={"csrf_token": _csrf(client), "action": "submit"}, follow_redirects=True)
    assert response.status_code == 200
    assert b"authorization" in response.data.lower()
    with sqlite3.connect(app_module.DB_PATH) as db:
        assert db.execute("SELECT status FROM enrolments WHERE id=?", (enrolment_id,)).fetchone()[0] == "draft"
        assert db.execute("SELECT COUNT(*) FROM enrolment_submissions WHERE enrolment_id=?", (enrolment_id,)).fetchone()[0] == 0
