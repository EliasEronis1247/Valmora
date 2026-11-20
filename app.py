from __future__ import annotations

import math
import os
import secrets
import sqlite3
import sys
import uuid
from contextlib import closing
from getpass import getpass
from pathlib import Path
from urllib.parse import urlparse
from datetime import timedelta

from flask import Flask, abort, jsonify, request, send_from_directory, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash, generate_password_hash

ROOT = Path(__file__).resolve().parent
INSTANCE = ROOT / "instance"
DATABASE = INSTANCE / "products.sqlite3"
SESSION_KEY_FILE = INSTANCE / "session.key"
CATEGORIES = {"cleansers", "serums", "skincare"}
DEFAULT_ALLOWED_ORIGINS = {
    "http://127.0.0.1:5500",
    "http://localhost:5500",
}
ALLOWED_ORIGINS = {
    origin.strip()
    for origin in os.environ.get(
        "FRONTEND_ORIGINS",
        ",".join(DEFAULT_ALLOWED_ORIGINS),
    ).split(",")
    if origin.strip()
}

INSTANCE.mkdir(exist_ok=True)
app = Flask(__name__, static_folder=None)
if not SESSION_KEY_FILE.exists():
    try:
        SESSION_KEY_FILE.write_text(secrets.token_hex(32), encoding="ascii")
    except FileExistsError:
        pass
app.config.update(
    SECRET_KEY=SESSION_KEY_FILE.read_text(encoding="ascii").strip(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
    headers_enabled=True,
)


def connect_database() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database() -> None:
    INSTANCE.mkdir(exist_ok=True)
    with closing(connect_database()) as connection:
        with connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS products (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    category TEXT NOT NULL,
                    description TEXT NOT NULL,
                    price REAL NOT NULL CHECK (price > 0),
                    size TEXT NOT NULL DEFAULT '',
                    image TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS admin_account (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    email TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL
                )
                """
            )


def product_from_row(row: sqlite3.Row) -> dict[str, object]:
    return {
        "id": row["id"],
        "name": row["name"],
        "category": row["category"],
        "description": row["description"],
        "price": row["price"],
        "size": row["size"],
        "image": row["image"],
    }


def csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def csrf_is_valid() -> bool:
    supplied_token = request.headers.get("X-CSRF-Token", "")
    expected_token = session.get("csrf_token", "")
    return bool(expected_token) and secrets.compare_digest(supplied_token, expected_token)


def is_admin_authenticated() -> bool:
    return session.get("admin_id") == 1


initialize_database()


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    if app.config["SESSION_COOKIE_SECURE"]:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    origin = request.headers.get("Origin")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-CSRF-Token"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.vary.add("Origin")
    return response


@app.get("/")
def home():
    return send_from_directory(ROOT, "index-1.html")


@app.get("/<path:filename>")
def frontend_file(filename: str):
    if filename in {"index-1.html", "products.html", "checkout.html", "login.html", "style.css"}:
        return send_from_directory(ROOT, filename)
    if filename.startswith("images/"):
        return send_from_directory(ROOT, filename)
    abort(404)


@app.get("/api/products")
def list_products():
    with closing(connect_database()) as connection:
        rows = connection.execute(
            "SELECT * FROM products ORDER BY created_at DESC, rowid DESC"
        ).fetchall()
    return jsonify([product_from_row(row) for row in rows])


@app.get("/api/auth")
def auth_status():
    return jsonify(
        authenticated=is_admin_authenticated(),
        csrfToken=csrf_token(),
    )


@app.post("/api/login")
@limiter.limit("5 per minute")
@limiter.limit("20 per hour")
def admin_login():
    if not csrf_is_valid():
        return jsonify(error="Your session expired. Refresh the page and try again."), 403
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error="Send login details as a JSON object."), 400

    email = payload.get("email")
    password = payload.get("password")
    if not isinstance(email, str) or not isinstance(password, str):
        return jsonify(error="Invalid email or password."), 401

    with closing(connect_database()) as connection:
        admin = connection.execute(
            "SELECT id, email, password_hash FROM admin_account WHERE id = 1"
        ).fetchone()
    if (
        admin is None
        or not secrets.compare_digest(email.strip().lower(), admin["email"])
        or not check_password_hash(admin["password_hash"], password)
    ):
        return jsonify(error="Invalid email or password."), 401

    session.clear()
    session.permanent = payload.get("remember") is True
    session["admin_id"] = admin["id"]
    return jsonify(authenticated=True, csrfToken=csrf_token())


@app.post("/api/logout")
def admin_logout():
    if not csrf_is_valid():
        return jsonify(error="Your session expired. Refresh the page and try again."), 403
    session.clear()
    return jsonify(authenticated=False, csrfToken=csrf_token())


@app.post("/api/products")
def add_product():
    if not is_admin_authenticated():
        return jsonify(error="Admin sign-in is required to add products."), 401
    if not csrf_is_valid():
        return jsonify(error="Your session expired. Refresh the page and try again."), 403

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error="Send product details as a JSON object."), 400

    name = payload.get("name")
    category = payload.get("category")
    description = payload.get("description")
    size = payload.get("size", "")
    image = payload.get("image", "")
    price_value = payload.get("price")

    if not isinstance(name, str) or not name.strip() or len(name.strip()) > 80:
        return jsonify(error="Product name must be between 1 and 80 characters."), 400
    if not isinstance(category, str) or category not in CATEGORIES:
        return jsonify(error="Choose a valid product category."), 400
    if not isinstance(description, str) or not description.strip() or len(description.strip()) > 180:
        return jsonify(error="Description must be between 1 and 180 characters."), 400
    if not isinstance(size, str) or len(size.strip()) > 30:
        return jsonify(error="Size must be 30 characters or fewer."), 400
    if not isinstance(image, str) or len(image.strip()) > 500:
        return jsonify(error="Image URL must be 500 characters or fewer."), 400
    if image.strip():
        parsed_image = urlparse(image.strip())
        if parsed_image.scheme not in {"http", "https"} or not parsed_image.netloc:
            return jsonify(error="Image URL must start with http:// or https://."), 400

    if isinstance(price_value, bool):
        return jsonify(error="Price must be a positive number."), 400
    try:
        price = float(price_value)
    except (TypeError, ValueError):
        return jsonify(error="Price must be a positive number."), 400
    if not math.isfinite(price) or price <= 0 or price > 99999:
        return jsonify(error="Price must be greater than 0 and no more than 99,999."), 400

    product = {
        "id": f"custom-{uuid.uuid4().hex}",
        "name": name.strip(),
        "category": category,
        "description": description.strip(),
        "price": price,
        "size": size.strip(),
        "image": image.strip(),
    }
    with closing(connect_database()) as connection:
        with connection:
            connection.execute(
                """
                INSERT INTO products (id, name, category, description, price, size, image)
                VALUES (:id, :name, :category, :description, :price, :size, :image)
                """,
                product,
            )
    return jsonify(product), 201


def create_admin_account() -> None:
    email = input("Admin email: ").strip().lower()
    if "@" not in email or len(email) > 254:
        raise SystemExit("Enter a valid email address.")
    password = getpass("Admin password (at least 12 characters): ")
    if len(password) < 12:
        raise SystemExit("Password must be at least 12 characters.")
    confirmation = getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")

    with closing(connect_database()) as connection:
        with connection:
            connection.execute(
                """
                INSERT INTO admin_account (id, email, password_hash)
                VALUES (1, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    email = excluded.email,
                    password_hash = excluded.password_hash
                """,
                (email, generate_password_hash(password)),
            )
    print("Admin account saved. Keep your password private.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "create-admin":
        create_admin_account()
    else:
        app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
