"""
secure_app/app.py
-----------------------------
REMEDIATED / SECURE version of the same Flask application.
Each fix references the CWE it addresses.
"""
from dotenv import load_dotenv
load_dotenv()   # Load .env BEFORE any os.environ.get() calls

import sqlite3
import os
import subprocess
import hashlib
import secrets
import re
import logging
from functools import wraps
from flask import Flask, request, render_template, redirect, session, abort, g
from flask_wtf import CSRFProtect                  # pip install flask-wtf
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape

# ─── Logging setup ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ─── FIX 1: Secret key loaded from environment variable, never hard-coded ─────
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
# FIX: Secure session cookie settings
# SESSION_COOKIE_SECURE must be False on plain HTTP (local dev).
# Set COOKIE_SECURE=1 in .env when deploying over HTTPS.
_secure_cookies = os.environ.get("COOKIE_SECURE", "0") == "1"
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=_secure_cookies,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800,  # 30-minute session timeout
    WTF_CSRF_ENABLED=True,
)

# ─── FIX 12: CSRF protection ──────────────────────────────────────────────────
csrf = CSRFProtect(app)

# ─── FIX 2: DB path from env, never hard-coded credentials ────────────────────
DB_PATH = os.environ.get("DB_PATH", "secure_users.db")

# ─────────────────────────────────────────────────────────────────────────────
# Database helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_db():
    """Return a per-request DB connection (stored on Flask's g object)."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, username TEXT UNIQUE, "
        " password_hash TEXT, role TEXT)"
    )
    # ── FIX 3: Passwords stored as bcrypt hashes, never plain-text ────────────
    admin_hash = generate_password_hash(
        os.environ.get("ADMIN_PASSWORD", secrets.token_hex(16))
    )
    db.execute(
        "INSERT OR IGNORE INTO users VALUES (1, 'admin', ?, 'admin')",
        (admin_hash,),
    )
    db.commit()

# ── Auto-initialise DB on first request (works with both `flask run` and direct) ──
_db_initialised = False

@app.before_request
def ensure_db():
    global _db_initialised
    if not _db_initialised:
        init_db()
        _db_initialised = True

# ─────────────────────────────────────────────────────────────────────────────
# Auth helpers
# ─────────────────────────────────────────────────────────────────────────────

def login_required(f):
    """Decorator: redirect to login if user not in session."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    """Decorator: abort 403 unless the session role is 'admin'."""
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if session.get("role") != "admin":
            logger.warning("Unauthorised admin access attempt by %s", session.get("user"))
            abort(403)
        return f(*args, **kwargs)
    return decorated

# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ─── FIX 4: Parameterised query → no SQL injection ────────────────────────────
# ─── FIX 5: render_template (Jinja2 auto-escaping) → no XSS ──────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        # Parameterised query – user input never interpolated into SQL
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            # Prevent session fixation — clear old session then repopulate
            session.clear()
            session["user"] = username
            session["role"] = user["role"]
            logger.info("Successful login: %s", username)

            # Safe open-redirect check
            next_url = request.args.get("next", "/dashboard")
            if not next_url.startswith("/"):
                next_url = "/dashboard"
            return redirect(next_url)
        else:
            error = "Invalid credentials"
            logger.warning("Failed login attempt for username: %s", username)

    # render_template uses Jinja2 auto-escaping; 'error' is never raw HTML
    return render_template("login.html", error=error)


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=session["user"])


# ─── FIX 6: Role-based access control decorator ───────────────────────────────
# ─── FIX 7: Passwords never returned; sensitive fields excluded ───────────────
@app.route("/admin")
@admin_required
def admin():
    db = get_db()
    # Return only non-sensitive columns
    users = db.execute("SELECT id, username, role FROM users").fetchall()
    return render_template("admin.html", users=users)


# ─── FIX 8: OS Command Injection → use subprocess list form + allowlist ───────
ALLOWED_HOSTS_RE = re.compile(r"^[a-zA-Z0-9.\-]{1,253}$")

@app.route("/ping")
@login_required
def ping():
    host = request.args.get("host", "127.0.0.1")
    if not ALLOWED_HOSTS_RE.match(host):
        abort(400, "Invalid hostname")
    # List form – no shell expansion; shell=False is the default
    result = subprocess.run(
        ["ping", "-c", "1", host],
        capture_output=True, text=True, timeout=5, shell=False
    )
    return render_template("ping.html", output=escape(result.stdout))


# ─── FIX 9: Insecure deserialisation → use JSON instead of pickle ─────────────
import json

@app.route("/load_profile", methods=["POST"])
@login_required
def load_profile():
    try:
        profile = json.loads(request.data)          # Safe structured format
        # Validate expected keys
        allowed_keys = {"name", "bio", "theme"}
        profile = {k: str(v) for k, v in profile.items() if k in allowed_keys}
    except (json.JSONDecodeError, ValueError):
        abort(400, "Invalid profile data")
    return render_template("profile.html", profile=profile)


# ─── FIX 10: Path Traversal → validate & restrict to safe directory ───────────
ALLOWED_FILES = {"readme.txt", "help.txt", "changelog.txt"}   # explicit allowlist

@app.route("/read_file")
@login_required
def read_file():
    filename = request.args.get("file", "")
    # Allowlist approach – only whitelisted basenames allowed
    if filename not in ALLOWED_FILES:
        abort(400, "File not permitted")
    safe_path = os.path.join(
        os.path.abspath("static"), os.path.basename(filename)
    )
    if not safe_path.startswith(os.path.abspath("static")):
        abort(400, "Invalid path")
    with open(safe_path) as f:
        return render_template("file.html", content=escape(f.read()))


# ─── FIX 11: Password hashing → werkzeug bcrypt-backed PBKDF2 ─────────────────
@app.route("/reset_password", methods=["POST"])
@login_required
def reset_password():
    new_pass = request.form.get("password", "")
    if len(new_pass) < 12:
        abort(400, "Password must be at least 12 characters")
    # generate_password_hash uses PBKDF2-HMAC-SHA256 with random salt
    hashed = generate_password_hash(new_pass)
    db = get_db()
    db.execute(
        "UPDATE users SET password_hash = ? WHERE username = ?",
        (hashed, session["user"]),
    )
    db.commit()
    logger.info("Password reset for user: %s", session["user"])
    return render_template("reset_ok.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ─── FIX 13: Debug mode OFF; host restricted in production ────────────────────
if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode, host="127.0.0.1", port=5000)
