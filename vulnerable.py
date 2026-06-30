"""
vulnerable_app.py
-----------------
Intentionally vulnerable Python file for SAST testing.
DO NOT use in production.

Vulnerabilities present:
  V1  - SQL Injection (string-formatted query)
  V2  - Command Injection (os.system with user input)
  V3  - Hardcoded credentials
  V4  - Path Traversal (unsanitized file path)
  V5  - Insecure deserialization (pickle.loads on untrusted data)
  V6  - Weak cryptography (MD5 for password hashing)
  V7  - Open redirect
  V8  - Debug mode enabled in production
  V9  - SSRF (requests to user-supplied URL)
  V10 - Sensitive data logged in plaintext
"""

import os
import sqlite3
import pickle
import hashlib
import subprocess
import logging
import requests
from flask import Flask, request, redirect, send_file

app = Flask(__name__)

# ------------------------------------------------------------------ #
# V3 – Hardcoded credentials
# ------------------------------------------------------------------ #
DB_USER     = "admin"
DB_PASSWORD = "SuperSecret123!"          # hardcoded password
SECRET_KEY  = "hardcoded-secret-key"     # hardcoded Flask secret

app.secret_key = SECRET_KEY

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
# V1 – SQL Injection
# ------------------------------------------------------------------ #
def get_user(username: str):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Dangerous: user input concatenated directly into the query
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()


# ------------------------------------------------------------------ #
# V2 – Command Injection
# ------------------------------------------------------------------ #
def ping_host(host: str):
    # Dangerous: host is passed directly to the shell
    os.system("ping -c 1 " + host)


# ------------------------------------------------------------------ #
# V4 – Path Traversal
# ------------------------------------------------------------------ #
@app.route("/download")
def download_file():
    filename = request.args.get("file", "")
    # Dangerous: no sanitisation; allows ../../etc/passwd
    filepath = os.path.join("/var/app/uploads", filename)
    return send_file(filepath)


# ------------------------------------------------------------------ #
# V5 – Insecure Deserialization
# ------------------------------------------------------------------ #
@app.route("/load_session", methods=["POST"])
def load_session():
    data = request.get_data()
    # Dangerous: deserializing arbitrary user-supplied bytes
    session_obj = pickle.loads(data)
    return str(session_obj)


# ------------------------------------------------------------------ #
# V6 – Weak cryptography (MD5 for passwords)
# ------------------------------------------------------------------ #
def hash_password(password: str) -> str:
    # MD5 is cryptographically broken; never use for passwords
    return hashlib.md5(password.encode()).hexdigest()


# ------------------------------------------------------------------ #
# V7 – Open Redirect
# ------------------------------------------------------------------ #
@app.route("/redirect")
def open_redirect():
    url = request.args.get("url", "/")
    # Dangerous: no validation of destination URL
    return redirect(url)


# ------------------------------------------------------------------ #
# V9 – SSRF (Server-Side Request Forgery)
# ------------------------------------------------------------------ #
@app.route("/fetch")
def fetch_url():
    target = request.args.get("url", "")
    # Dangerous: allows internal network probing
    response = requests.get(target)
    return response.text


# ------------------------------------------------------------------ #
# V10 – Sensitive data logged in plaintext
# ------------------------------------------------------------------ #
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    # Dangerous: password written to log file in plaintext
    logger.debug("Login attempt — user: %s  password: %s", username, password)
    user = get_user(username)
    if user and user[2] == hash_password(password):
        return "Login successful"
    return "Login failed", 401


# ------------------------------------------------------------------ #
# V8 – Debug mode enabled (exposes interactive debugger)
# ------------------------------------------------------------------ #
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)   # debug=True in production
