import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from werkzeug.security import generate_password_hash

import app as app_module
from app import app as flask_app


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "central-workflow.db"
    monkeypatch.setenv("APAAR_DB_PATH", str(db_path))
    app_module.DB_PATH = str(db_path)
    app_module.init_db()
    flask_app.config.update(TESTING=True, SECRET_KEY="central-test-secret", APAAR_DB_PATH=str(db_path))
    with flask_app.test_client() as client:
        yield client


def set_session(client, username, role, institution):
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "test-csrf-token"
        sess["username"] = username
        sess["role"] = role
        sess["institution"] = institution
        sess["session_version"] = 0


def add_user(username, role, institution):
    with app_module.connect_db() as db:
        db.execute("""
            INSERT OR REPLACE INTO users(username,password_hash,role,institution,is_active,created_at,updated_at,session_version)
            VALUES(?,?,?,?,1,?,?,0)
        """, (username, generate_password_hash("test-password-long-enough"), role,
              institution, app_module.now(), app_module.now()))
        db.commit()


def test_central_schema_is_additive_and_present(client):
    with app_module.connect_db() as db:
        tables = {r["name"] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "central_submission_batches" in tables
    assert "central_submission_events" in tables
    assert "enrolments" in tables
    assert "enrolment_submissions" in tables


def test_snapshot_digest_detects_mutation():
    payload = json.dumps({"records": [{"student_ref": "SYN-1"}]}, sort_keys=True)
    row = {"snapshot_json": payload, "content_hash": hashlib.sha256(payload.encode()).hexdigest()}
    assert app_module._central_batch_integrity(row) is True
    row["snapshot_json"] += " "
    assert app_module._central_batch_integrity(row) is False


def test_platform_admin_can_view_central_oversight(client):
    add_user("central-reviewer", "platform_admin", "Central Oversight (Synthetic Demo)")
    set_session(client, "central-reviewer", "platform_admin", "Central Oversight (Synthetic Demo)")
    response = client.get("/central-oversight")
    assert response.status_code == 200
    assert b"Central oversight" in response.data
    assert b"not a live AICTE repository" in response.data


def test_institution_user_cannot_access_platform_oversight(client):
    add_user("campus-operator", "operator", "Synthetic Campus A")
    set_session(client, "campus-operator", "operator", "Synthetic Campus A")
    response = client.get("/central-oversight")
    assert response.status_code in {302, 403}
    assert b"Central oversight" not in response.data


def test_central_transition_policy_blocks_skipping_review():
    assert app_module.CENTRAL_STATUS_TRANSITIONS["submitted"] == {
        "processing", "requires_review", "returned_for_correction"
    }
    assert "accepted" not in app_module.CENTRAL_STATUS_TRANSITIONS["submitted"]
    assert app_module.CENTRAL_STATUS_TRANSITIONS["superseded"] == set()
