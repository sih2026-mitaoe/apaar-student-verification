"""Create a dedicated central oversight account.

Usage: python bootstrap_platform_admin.py
The target database must already be initialized. This tool never changes an existing account.
"""
import getpass
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from werkzeug.security import generate_password_hash

APP_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("APAAR_DB_PATH", str(APP_DIR / "instance" / "apaar_demo.db")))


def main():
    if not DB_PATH.is_file():
        print(f"ERROR: Database not found: {DB_PATH}", file=sys.stderr)
        print("Start the application once to initialize it, then retry.", file=sys.stderr)
        return 1
    username = os.environ.get("APAAR_PLATFORM_ADMIN_USERNAME", "").strip() or input("Platform admin username: ").strip()
    email = os.environ.get("APAAR_PLATFORM_ADMIN_EMAIL", "").strip().lower() or input("Platform admin email: ").strip().lower()
    password = os.environ.get("APAAR_PLATFORM_ADMIN_PASSWORD", "")
    if not password:
        password = getpass.getpass("Password (hidden): ")
        confirmation = getpass.getpass("Confirm password: ")
        if password != confirmation:
            print("ERROR: Passwords do not match; no changes made.", file=sys.stderr)
            return 1
    if not re.fullmatch(r"[A-Za-z0-9._-]{3,40}", username):
        print("ERROR: Username must be 3-40 letters, numbers, dots, underscores, or hyphens.", file=sys.stderr)
        return 1
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(email) > 254:
        print("ERROR: A valid email address is required for OTP sign-in.", file=sys.stderr)
        return 1
    if len(password) < 16 or len(password) > 256:
        print("ERROR: Password must be 16-256 characters.", file=sys.stderr)
        return 1
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with sqlite3.connect(DB_PATH) as db:
        existing = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if existing:
            print("ERROR: Username already exists. This script will not modify an existing account.", file=sys.stderr)
            return 1
        db.execute("""
            INSERT INTO users(username,password_hash,role,institution,is_active,created_at,updated_at,email)
            VALUES(?,?,?,?,1,?,?,?)
        """, (username, generate_password_hash(password), "platform_admin",
              "Central Oversight (Synthetic Demo)", timestamp, timestamp, email))
    print("Created a dedicated platform_admin account.")
    print("Configure email delivery and verify the email before using OTP sign-in.")
    print("This role is for synthetic prototype oversight only; it is not an official AICTE account.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
