"""
secure_app.py
-------------
Example Flask application with common security vulnerabilities remediated.

This code is intended for SAST testing and educational purposes.
"""

import ipaddress
import logging
import os
import socket
import sqlite3
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import bcrypt
import requests
from flask import Flask, abort, redirect, request, send_file
from lxml import etree

app = Flask(__name__)

# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------

UPLOAD_DIR = Path("/var/app/uploads").resolve()

DB_USER = os.environ.get("DB_USER", "")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")

app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ALLOWED_REDIRECT_HOSTS = {
    "example.com",
    "www.example.com",
    "app.example.com",
}

ALLOWED_FETCH_HOSTS = {
    "api.example.com",
    "jsonplaceholder.typicode.com",
}


# ------------------------------------------------------------------
# Database
# ------------------------------------------------------------------

def get_user(username: str):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,),
    )

    result = cursor.fetchone()
    conn.close()
    return result


# ------------------------------------------------------------------
# Safe command execution
# ------------------------------------------------------------------

def ping_host(host: str):

    if not host.replace(".", "").replace("-", "").isalnum():
        raise ValueError("Invalid hostname")

    subprocess.run(
        ["ping", "-c", "1", host],
        shell=False,
        check=False,
        timeout=5,
    )


# ------------------------------------------------------------------
# Safe download
# ------------------------------------------------------------------

@app.route("/download")
def download_file():

    filename = request.args.get("file", "")

    target = (UPLOAD_DIR / filename).resolve()

    if not str(target).startswith(str(UPLOAD_DIR)):
        abort(403)

    if not target.exists():
        abort(404)

    return send_file(target)


# ------------------------------------------------------------------
# Safe JSON
# ------------------------------------------------------------------

@app.route("/load_session", methods=["POST"])
def load_session():

    data = request.get_json(silent=True)

    if data is None:
        return "Invalid JSON", 400

    return data


# ------------------------------------------------------------------
# Password hashing
# ------------------------------------------------------------------

def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def check_password(password: str, hashed: bytes):
    return bcrypt.checkpw(password.encode(), hashed)


# ------------------------------------------------------------------
# Safe Redirect
# ------------------------------------------------------------------

@app.route("/redirect")
def safe_redirect():

    url = request.args.get("url", "/")

    parsed = urlparse(url)

    if parsed.netloc and parsed.hostname not in ALLOWED_REDIRECT_HOSTS:
        return "Redirect blocked", 400

    return redirect(url)


# ------------------------------------------------------------------
# SSRF Protection
# ------------------------------------------------------------------

def is_private_host(hostname: str) -> bool:
    try:
        ip = socket.gethostbyname(hostname)
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True


@app.route("/fetch")
def fetch():

    url = request.args.get("url", "")

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        return "Invalid URL", 400

    host = parsed.hostname

    if not host:
        return "Invalid URL", 400

    if host not in ALLOWED_FETCH_HOSTS:
        return "Host not allowed", 403

    if is_private_host(host):
        return "Private addresses blocked", 403

    response = requests.get(
        url,
        timeout=5,
        allow_redirects=False,
    )

    return response.text


# ------------------------------------------------------------------
# Login
# ------------------------------------------------------------------

@app.route("/login", methods=["POST"])
def login():

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    logger.info("Login attempt for user '%s'", username)

    user = get_user(username)

    if user and check_password(password, user[2]):
        return "Login successful"

    return "Login failed", 401


# ------------------------------------------------------------------
# Safe XML Parsing
# ------------------------------------------------------------------

@app.route("/parse_xml", methods=["POST"])
def parse_xml():

    xml_data = request.get_data()

    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
    )

    try:
        root = etree.fromstring(xml_data, parser)

    except etree.XMLSyntaxError:
        return "Invalid XML", 400

    item = root.find("item")

    return item.text if item is not None else ""


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

if __name__ == "__main__":

    debug_mode = (
        os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    )

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=debug_mode,
    )
