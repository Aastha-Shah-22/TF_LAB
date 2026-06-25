"""
secure_app.py
-------------
Hardened Flask application for SAST testing.
"""

import ipaddress
import logging
import os
import socket
import sqlite3
import subprocess
from pathlib import Path

import bcrypt
import requests
from flask import Flask, abort, redirect, request, send_file
from lxml import etree

app = Flask(__name__)

# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------

UPLOAD_DIR = Path("/var/app/uploads").resolve()

app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("FLASK_SECRET_KEY must be configured")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MAX_UPLOAD_SIZE = 1024 * 1024
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_SIZE

# ------------------------------------------------------------------
# Allowlists
# ------------------------------------------------------------------

SAFE_REDIRECTS = {
    "home": "/",
    "profile": "/profile",
    "dashboard": "/dashboard",
}

SAFE_ENDPOINTS = {
    "posts": "https://jsonplaceholder.typicode.com/posts",
    "users": "https://jsonplaceholder.typicode.com/users",
}

# ------------------------------------------------------------------
# Security Headers
# ------------------------------------------------------------------

@app.after_request
def add_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response

# ------------------------------------------------------------------
# Database
# ------------------------------------------------------------------

def get_user(username: str):
    conn = sqlite3.connect("users.db")

    try:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT username,password FROM users WHERE username=?",
            (username,),
        )

        return cursor.fetchone()

    finally:
        conn.close()

# ------------------------------------------------------------------
# Safe Ping
# ------------------------------------------------------------------

def ping_host(host: str):

    try:
        socket.gethostbyname(host)
    except socket.gaierror:
        raise ValueError("Invalid hostname")

    subprocess.run(
        ["ping", "-c", "1", host],
        shell=False,
        timeout=5,
        check=False,
    )

# ------------------------------------------------------------------
# Safe Download
# ------------------------------------------------------------------

@app.route("/download")
def download():

    filename = request.args.get("file", "")

    if "/" in filename or "\\" in filename:
        abort(400)

    target = (UPLOAD_DIR / filename).resolve()

    try:
        target.relative_to(UPLOAD_DIR)
    except ValueError:
        abort(403)

    if not target.is_file():
        abort(404)

    return send_file(target)

# ------------------------------------------------------------------
# JSON
# ------------------------------------------------------------------

@app.route("/load_session", methods=["POST"])
def load_session():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return "Invalid JSON", 400

    return data

# ------------------------------------------------------------------
# Password Hashing
# ------------------------------------------------------------------

def hash_password(password: str):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def check_password(password: str, hashed):

    if isinstance(hashed, str):
        hashed = hashed.encode()

    return bcrypt.checkpw(password.encode(), hashed)

# ------------------------------------------------------------------
# Safe Redirect
# ------------------------------------------------------------------

@app.route("/redirect")
def safe_redirect():

    destination = request.args.get("dest", "home")

    if destination not in SAFE_REDIRECTS:
        abort(400)

    return redirect(SAFE_REDIRECTS[destination])

# ------------------------------------------------------------------
# Fetch (No SSRF)
# ------------------------------------------------------------------

@app.route("/fetch")
def fetch():

    endpoint = request.args.get("endpoint")

    if endpoint not in SAFE_ENDPOINTS:
        abort(400)

    response = requests.get(
        SAFE_ENDPOINTS[endpoint],
        timeout=5,
        allow_redirects=False,
    )

    return response.text, response.status_code

# ------------------------------------------------------------------
# Login
# ------------------------------------------------------------------

@app.route("/login", methods=["POST"])
def login():

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    logger.info("Login attempt")

    user = get_user(username)

    if not user:
        return "Login failed", 401

    if check_password(password, user[1]):
        return "Login successful"

    return "Login failed", 401

# ------------------------------------------------------------------
# XML
# ------------------------------------------------------------------

@app.route("/parse_xml", methods=["POST"])
def parse_xml():

    xml_data = request.get_data()

    parser = etree.XMLParser(
        resolve_entities=False,
        load_dtd=False,
        no_network=True,
        huge_tree=False,
    )

    try:
        root = etree.fromstring(xml_data, parser)
    except etree.XMLSyntaxError:
        return "Invalid XML", 400

    item = root.find("item")

    return item.text if item is not None else ""

# ------------------------------------------------------------------
# Health
# ------------------------------------------------------------------

@app.route("/")
def home():
    return "OK"

# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )
