import hashlib
import json

import pytest
from werkzeug.security import generate_password_hash

import app as app_module
from app import app as flask_app


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "phase5.db"
    monkeypatch.setenv("APAAR_DB_PATH", str(db_path))
    app_module.DB_PATH = str(db_path)
    app_module.init_db()
    with app_module.connect_db() as db:
        db.execute("""INSERT INTO users(username,password_hash,role,institution,is_active,created_at,updated_at,session_version)
            VALUES(?,?,?,?,1,?,?,0)""",
            ("platform-admin", generate_password_hash("phase5-test-password"), "platform_admin",
             "Central Oversight (Synthetic Demo)", app_module.now(), app_module.now()))
        db.commit()
    flask_app.config.update(TESTING=True, SECRET_KEY="phase5-test-secret", APAAR_DB_PATH=str(db_path))
    with flask_app.test_client() as test_client:
        yield test_client


def platform_session(client):
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "phase5-csrf"
        sess["username"] = "platform-admin"
        sess["role"] = "platform_admin"
        sess["institution"] = "Central Oversight (Synthetic Demo)"
        sess["session_version"] = 0


def register_institution(client, code="CAMPUS_001", name="Synthetic Campus One"):
    platform_session(client)
    response = client.post("/central-institutions", data={
        "csrf_token": "phase5-csrf", "action": "create",
        "institution_code": code, "institution_name": name,
    }, follow_redirects=True)
    assert response.status_code == 200
    with app_module.connect_db() as db:
        return db.execute("SELECT * FROM institution_registry WHERE institution_code=?", (code,)).fetchone()


def issue_token(client, institution_id):
    platform_session(client)
    response = client.post("/central-institutions", data={
        "csrf_token": "phase5-csrf", "action": "issue_credential",
        "institution_id": str(institution_id),
    })
    assert response.status_code == 200
    # Token appears only in the one-time HTML response and is not stored raw.
    import re
    match = re.search(rb'<textarea id="new-token" rows="3" readonly>([^<]+)</textarea>', response.data)
    assert match
    return match.group(1).decode()


def payload():
    return {
        "academic_year": 2026,
        "records": [{
            "institutional_enrolment_id": "ENR-001",
            "institution_student_id": "STU-001",
            "student_name": "Synthetic Student",
            "programme_code": "CSE",
            "programme_name": "Computer Science",
            "enrolment_status": "submitted",
        }],
    }


def test_phase5_registry_schema_exists(client):
    with app_module.connect_db() as db:
        tables = {row["name"] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"institution_registry", "institution_api_credentials", "institution_api_idempotency"} <= tables


def test_service_api_requires_bearer_token(client):
    response = client.post("/api/v1/institution-submissions", json=payload(),
                           headers={"Idempotency-Key": "submission-0001"})
    assert response.status_code == 401


def test_api_submission_and_idempotent_replay(client):
    institution = register_institution(client)
    token = issue_token(client, institution["id"])
    headers = {"Authorization": f"Bearer {token}", "Idempotency-Key": "submission-0001"}
    first = client.post("/api/v1/institution-submissions", json=payload(), headers=headers)
    assert first.status_code == 201
    first_json = first.get_json()
    assert first_json["batch"]["status"] == "submitted"
    assert first_json["batch"]["record_count"] == 1
    replay = client.post("/api/v1/institution-submissions", json=payload(), headers=headers)
    assert replay.status_code == 200
    assert replay.get_json()["idempotent_replay"] is True
    assert replay.get_json()["batch"]["id"] == first_json["batch"]["id"]


def test_idempotency_key_cannot_be_reused_for_different_content(client):
    institution = register_institution(client)
    token = issue_token(client, institution["id"])
    headers = {"Authorization": f"Bearer {token}", "Idempotency-Key": "submission-0002"}
    assert client.post("/api/v1/institution-submissions", json=payload(), headers=headers).status_code == 201
    changed = payload()
    changed["records"][0]["student_name"] = "Different Synthetic Student"
    response = client.post("/api/v1/institution-submissions", json=changed, headers=headers)
    assert response.status_code == 409
    assert response.get_json()["error"] == "idempotency_conflict"


def test_suspended_institution_cannot_submit(client):
    institution = register_institution(client)
    token = issue_token(client, institution["id"])
    platform_session(client)
    client.post("/central-institutions", data={
        "csrf_token": "phase5-csrf", "action": "status",
        "institution_id": str(institution["id"]), "status": "suspended",
    })
    response = client.post("/api/v1/institution-submissions", json=payload(), headers={
        "Authorization": f"Bearer {token}", "Idempotency-Key": "submission-0003",
    })
    assert response.status_code == 403


def test_revoked_credential_cannot_submit(client):
    institution = register_institution(client)
    token = issue_token(client, institution["id"])
    with app_module.connect_db() as db:
        credential = db.execute("SELECT id FROM institution_api_credentials WHERE institution_id=?",
                                 (institution["id"],)).fetchone()
    platform_session(client)
    client.post(f"/central-institutions/credentials/{credential['id']}/revoke",
                data={"csrf_token": "phase5-csrf"})
    response = client.post("/api/v1/institution-submissions", json=payload(), headers={
        "Authorization": f"Bearer {token}", "Idempotency-Key": "submission-0004",
    })
    assert response.status_code == 401


def test_duplicate_ids_in_single_payload_are_rejected(client):
    institution = register_institution(client)
    token = issue_token(client, institution["id"])
    body = payload()
    body["records"].append(dict(body["records"][0]))
    response = client.post("/api/v1/institution-submissions", json=body, headers={
        "Authorization": f"Bearer {token}", "Idempotency-Key": "submission-0005",
    })
    assert response.status_code == 400
    assert response.get_json()["error"] == "duplicate_record_id"


def test_api_rejects_non_string_classification_without_server_error(client):
    institution = register_institution(client)
    token = issue_token(client, institution["id"])
    body = payload()
    body["records"][0]["student_category"] = ["nri"]
    response = client.post("/api/v1/institution-submissions", json=body, headers={
        "Authorization": f"Bearer {token}", "Idempotency-Key": "submission-0006",
    })
    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_record"


def test_api_rejects_case_insensitive_duplicate_enrolment_ids(client):
    institution = register_institution(client)
    token = issue_token(client, institution["id"])
    body = payload()
    second = dict(body["records"][0])
    second["institutional_enrolment_id"] = "enr-001"
    body["records"].append(second)
    response = client.post("/api/v1/institution-submissions", json=body, headers={
        "Authorization": f"Bearer {token}", "Idempotency-Key": "submission-0007",
    })
    assert response.status_code == 400
    assert response.get_json()["error"] == "duplicate_record_id"


def test_api_accepts_optional_monitoring_categories(client):
    institution = register_institution(client)
    token = issue_token(client, institution["id"])
    body = payload()
    body["records"][0]["student_category"] = "nri"
    body["records"][0]["seat_type"] = "supernumerary"
    response = client.post("/api/v1/institution-submissions", json=body, headers={
        "Authorization": f"Bearer {token}", "Idempotency-Key": "submission-0008",
    })
    assert response.status_code == 201
    with app_module.connect_db() as db:
        batch = db.execute("SELECT snapshot_json FROM central_submission_batches WHERE id=?",
                           (response.get_json()["batch"]["id"],)).fetchone()
    snapshot = json.loads(batch["snapshot_json"])
    assert snapshot["records"][0]["student_category"] == "nri"
    assert snapshot["records"][0]["seat_type"] == "supernumerary"
