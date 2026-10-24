"""Production configuration regression tests run in isolated subprocesses."""
import os
import subprocess
import sys


def _environment(db_path, *, admin_password):
    env = os.environ.copy()
    env.update({
        "APP_ENV": "production",
        "FLASK_ENV": "",
        "SECRET_KEY": "test-only-secret-key-" + ("x" * 48),
        "COOKIE_SECURE": "0",
        "DEMO_ADMIN_PASSWORD": admin_password,
        "APAAR_DB_PATH": str(db_path),
        "ENABLE_SHARED_DEMO_RECONCILIATION": "1",
    })
    return env


def test_app_env_production_forces_secure_cookie_even_if_cookie_secure_is_false(tmp_path):
    db_path = tmp_path / "production-config.db"
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import app; "
            "assert app.app.config['SESSION_COOKIE_SECURE'] is True; "
            "assert app.app.config['ENABLE_SHARED_DEMO_RECONCILIATION'] is False",
        ],
        cwd=os.path.dirname(os.path.dirname(__file__)),
        env=_environment(db_path, admin_password="long-test-password-for-production"),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_app_env_production_rejects_short_initial_admin_password(tmp_path):
    db_path = tmp_path / "production-short-password.db"
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import app",
        ],
        cwd=os.path.dirname(os.path.dirname(__file__)),
        env=_environment(db_path, admin_password="short"),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode != 0
    assert "at least 16 characters" in result.stdout + result.stderr
