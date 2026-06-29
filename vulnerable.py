"""
secure_app.py
-------------
Hardened version of vulnerable_app.py — safe for production use.

Fixes applied:
  V1  - SQL Injection        → Parameterized queries
  V2  - Command Injection    → subprocess with argument list + input validation
  V3  - Hardcoded credentials → Environment variables via os.environ
  V4  - Path Traversal       → Path canonicalization + base-directory check
  V5  - Insecure deserialization → Replaced pickle with JSON
  V6  - Weak cryptography    → bcrypt for password hashing
  V7  - Open Redirect        → URL allowlist validation
  V8  - Debug mode           → Controlled by FLASK_DEBUG env var (default off)
  V9  - SSRF                 → Allowlist of permitted hosts + timeout
  V10 - Sensitive data logged → Password never written to logs
"""

import os
import re
import json
import sqlite3
import hashlib
import logging
import ipaddress
from urllib.parse import urlparse

import bcrypt
import requests
from flask import Flask, request, redirect, send_file, abort

# ------------------------------------------------------------------ #
# V3 FIX – Load credentials from environment variables, never hardcode
# ------------------------------------------------------------------ #
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable must be set")

# DB_USER / DB_PASSWORD are consumed by your DB driver the same way:
# DB_USER     = os.environ["DB_USER"]
# DB_PASSWORD = os.environ["DB_PASSWORD"]

app = Flask(__name__)
app.secret_key = SECRET_KEY

# ------------------------------------------------------------------ #
# V10 FIX – Use WARNING level in production; never log sensitive fields
# ------------------------------------------------------------------ #
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
# Allowlists used by V7 and V9 fixes
# ------------------------------------------------------------------ #
ALLOWED_REDIRECT_HOSTS = {"example.com", "www.example.com"}
ALLOWED_FETCH_HOSTS    = {"api.example.com", "partner.example.com"}

# Uploads base directory (resolved once at startup)
UPLOAD_BASE = os.path.realpath("/var/app/uploads")


# ------------------------------------------------------------------ #
# V1 FIX – Parameterized query (no string concatenation)
# ------------------------------------------------------------------ #
def get_user(username: str):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Use a placeholder so the driver handles escaping
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchone()


# ------------------------------------------------------------------ #
# V2 FIX – Validate input, use argument list (no shell=True)
# ------------------------------------------------------------------ #
def ping_host(host: str):
    # Accept only plain hostnames / IPv4 addresses
    if not re.fullmatch(r"[A-Za-z0-9.\-]{1,253}", host):
        raise ValueError(f"Invalid host: {host!r}")

    # Try parsing as an IP to block private/loopback ranges if needed
    try:
        addr = ipaddress.ip_address(host)
        if addr.is_private or addr.is_loopback:
            raise ValueError("Private/loopback addresses are not allowed")
    except ValueError as exc:
        # Not an IP address — hostname pattern already validated above
        if "Private" in str(exc) or "loopback" in str(exc):
            raise

    # Pass args as a list — no shell interpretation possible
    import subprocess
    subprocess.run(["ping", "-c", "1", host], check=True, timeout=5)


# ------------------------------------------------------------------ #
# V4 FIX – Canonicalize path and assert it stays inside UPLOAD_BASE
# ------------------------------------------------------------------ #
@app.route("/download")
def download_file():
    filename = request.args.get("file", "")
    if not filename:
        abort(400, "Missing file parameter")

    # Resolve symlinks and ".." components
    requested_path = os.path.realpath(os.path.join(UPLOAD_BASE, filename))

    # Ensure the resolved path is still inside the upload directory
    if not requested_path.startswith(UPLOAD_BASE + os.sep):
        abort(400, "Invalid file path")

    return send_file(requested_path)


# ------------------------------------------------------------------ #
# V5 FIX – Replace pickle with JSON (safe, text-based deserialization)
# ------------------------------------------------------------------ #
@app.route("/load_session", methods=["POST"])
def load_session():
    try:
        data = request.get_data(as_text=True)
        session_obj = json.loads(data)          # JSON cannot execute code
    except (json.JSONDecodeError, ValueError):
        abort(400, "Invalid session data")
    return str(session_obj)


# ------------------------------------------------------------------ #
# V6 FIX – bcrypt for password hashing (slow, salted, purpose-built)
# ------------------------------------------------------------------ #
def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def verify_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)


# ------------------------------------------------------------------ #
# V7 FIX – Open Redirect → validate against an allowlist of hosts
# ------------------------------------------------------------------ #
@app.route("/redirect")
def safe_redirect():
    url = request.args.get("url", "/")
    parsed = urlparse(url)

    # Allow relative paths (no host component)
    if parsed.netloc == "":
        return redirect(url)

    if parsed.netloc not in ALLOWED_REDIRECT_HOSTS:
        abort(400, "Redirect destination not permitted")

    return redirect(url)


# ------------------------------------------------------------------ #
# V9 FIX – SSRF → restrict outbound requests to an explicit allowlist
# ------------------------------------------------------------------ #
@app.route("/fetch")
def fetch_url():
    target = request.args.get("url", "")
    if not target:
        abort(400, "Missing url parameter")

    parsed = urlparse(target)

    # Must use https and be in the allowlist
    if parsed.scheme != "https" or parsed.netloc not in ALLOWED_FETCH_HOSTS:
        abort(400, "URL not permitted")

    # Set a timeout to avoid indefinite hangs
    response = requests.get(target, timeout=10)
    return response.text


# ------------------------------------------------------------------ #
# V10 FIX – Never log the password (only log the username at WARNING)
# ------------------------------------------------------------------ #
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # Log only the username, never the password
    logger.warning("Login attempt for user: %s", username)

    user = get_user(username)
    if user and verify_password(password, user[2]):
        return "Login successful"
    return "Login failed", 401


# ------------------------------------------------------------------ #
# V8 FIX – Debug mode driven by environment variable (default: False)
# ------------------------------------------------------------------ #
if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
