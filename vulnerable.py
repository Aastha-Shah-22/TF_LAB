"""
partially_fixed_app.py
----------------------
Partially remediated version for SAST delta testing.
DO NOT use in production — vulnerabilities remain.

Remediation status
==================
FIXED   V1  SQL Injection           → parameterised query
FIXED   V2  Command Injection       → subprocess with arg list (no shell)
FIXED   V3  Hardcoded credentials   → loaded from environment variables
FIXED   V4  Path Traversal          → realpath + prefix check
FIXED   V5  Insecure deserialisation→ replaced pickle with JSON
FIXED   V6  Weak cryptography       → bcrypt instead of MD5
FIXED   V7  Open Redirect           → URL validated against allowlist
FIXED   V8  Debug mode              → debug flag from env var (default False)
---------
REMAIN  V9  SSRF                    → user-supplied URL still fetched as-is
REMAIN  V10 Sensitive data in logs  → password still logged in plaintext
---------
NEW     V11 XML External Entity (XXE) injection → unsafe XML parsing added
"""

import os
import sqlite3
import json
import hashlib
import subprocess
import logging
import requests
import bcrypt
from lxml import etree
from urllib.parse import urlparse
from flask import Flask, request, redirect, send_file

app = Flask(__name__)

# ------------------------------------------------------------------ #
# FIX V3 – Credentials loaded from environment variables
# ------------------------------------------------------------------ #
DB_USER     = os.environ.get("DB_USER", "")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
# FIX V1 – Parameterised query eliminates SQL injection
# ------------------------------------------------------------------ #
def get_user(username: str):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchone()


# ------------------------------------------------------------------ #
# FIX V2 – Command injection removed; shell=False, args as list
# ------------------------------------------------------------------ #
def ping_host(host: str):
    subprocess.run(["ping", "-c", "1", host], shell=False, check=False)


# ------------------------------------------------------------------ #
# FIX V4 – Path traversal mitigated with realpath prefix check
# ------------------------------------------------------------------ #
UPLOAD_DIR = os.path.realpath("/var/app/uploads")

@app.route("/download")
def download_file():
    filename = request.args.get("file", "")
    requested = os.path.realpath(os.path.join(UPLOAD_DIR, filename))
    if not requested.startswith(UPLOAD_DIR + os.sep):
        return "Access denied", 403
    return send_file(requested)


# ------------------------------------------------------------------ #
# FIX V5 – Replaced pickle with JSON (safe deserialization)
# ------------------------------------------------------------------ #
@app.route("/load_session", methods=["POST"])
def load_session():
    try:
        data = request.get_json(force=True)
        return str(data)
    except (ValueError, TypeError):
        return "Invalid session data", 400


# ------------------------------------------------------------------ #
# FIX V6 – bcrypt replaces MD5 for password hashing
# ------------------------------------------------------------------ #
def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def check_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)


# ------------------------------------------------------------------ #
# FIX V7 – Open redirect blocked via allowlist
# ------------------------------------------------------------------ #
ALLOWED_HOSTS = {"example.com", "www.example.com", "app.example.com"}

@app.route("/redirect")
def safe_redirect():
    url = request.args.get("url", "/")
    parsed = urlparse(url)
    if parsed.netloc and parsed.netloc not in ALLOWED_HOSTS:
        return "Redirect not allowed", 400
    return redirect(url)


# ------------------------------------------------------------------ #
# REMAIN V9 – SSRF: user-supplied URL is still fetched without restriction
# ------------------------------------------------------------------ #
@app.route("/fetch")
def fetch_url():
    target = request.args.get("url", "")
    # BUG: no allowlist or SSRF guard; internal network still reachable
    response = requests.get(target, timeout=5)
    return response.text


# ------------------------------------------------------------------ #
# REMAIN V10 – Password still logged in plaintext
# ------------------------------------------------------------------ #
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    # BUG: password must NOT appear in logs
    logger.info("Login attempt — user: %s  password: %s", username, password)
    user = get_user(username)
    if user and check_password(password, user[2]):
        return "Login successful"
    return "Login failed", 401


# ------------------------------------------------------------------ #
# NEW V11 – XXE Injection: untrusted XML parsed with external entities enabled
# ------------------------------------------------------------------ #
@app.route("/parse_xml", methods=["POST"])
def parse_xml():
    """
    Accepts an XML document and returns the text of the first <item> element.

    VULNERABLE: lxml's etree.fromstring resolves external entities by default
    when resolve_entities=True (the default). An attacker can supply:

        <?xml version="1.0"?>
        <!DOCTYPE foo [
          <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <root><item>&xxe;</item></root>

    …and receive the contents of /etc/passwd in the response.
    Fix: use defusedxml or set resolve_entities=False in a custom parser.
    """
    xml_data = request.get_data()
    # BUG: no safe parser; external entity resolution is active
    parser = etree.XMLParser()                        # resolve_entities defaults to True
    tree   = etree.fromstring(xml_data, parser)
    item   = tree.find("item")
    return item.text if item is not None else "", 200


# ------------------------------------------------------------------ #
# FIX V8 – Debug mode controlled by environment variable
# ------------------------------------------------------------------ #
if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
