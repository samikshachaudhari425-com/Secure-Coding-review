"""
vulnerable_app/app.py
-----------------------------
INTENTIONALLY VULNERABLE Flask application.
Purpose : Secure Coding Review – target application to audit.
Language: Python 3 / Flask
DO NOT deploy this application in production.
"""

import sqlite3
import os
import subprocess
import pickle
import hashlib
from flask import Flask, request, render_template_string, redirect, session

app = Flask(__name__)

# ─── VULNERABILITY 1: Hard-coded secret key ───────────────────────────────────
app.secret_key = "supersecret123"          # CWE-798

# ─── VULNERABILITY 2: Hard-coded DB credentials / path ────────────────────────
DB_PATH = "users.db"                       # CWE-259
ADMIN_PASSWORD = "admin123"                # CWE-798

# ─────────────────────────────────────────────────────────────────────────────
# Database helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_db():
    return sqlite3.connect(DB_PATH)

def init_db():
    db = get_db()
    db.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)"
    )
    # ── VULNERABILITY 3: Passwords stored as plain-text ──────────────────────
    db.execute(
        "INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin')"
    )
    db.execute(
        "INSERT OR IGNORE INTO users VALUES (2, 'alice', 'password', 'user')"
    )
    db.commit()
    db.close()

# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return "<h1>Welcome to VulnApp</h1><a href='/login'>Login</a>"


# ─── VULNERABILITY 4: SQL Injection ───────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        db = get_db()
        # Direct string interpolation → SQL injection (CWE-89)
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        cur = db.execute(query)
        user = cur.fetchone()
        db.close()

        if user:
            session["user"] = username
            session["role"] = user[3]
            return redirect("/dashboard")
        else:
            error = "Invalid credentials"

    # ── VULNERABILITY 5: Reflected XSS ───────────────────────────────────────
    # User-supplied 'error' parameter echoed into HTML without escaping (CWE-79)
    next_param = request.args.get("next", "")
    html = f"""
    <html><body>
    <h2>Login</h2>
    <p style='color:red'>{error}</p>
    <p>Redirect: {next_param}</p>
    <form method='POST'>
      Username: <input name='username'><br>
      Password: <input name='password' type='password'><br>
      <input type='submit' value='Login'>
    </form>
    </body></html>
    """
    return render_template_string(html)


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")
    return f"<h2>Welcome {session['user']}!</h2><a href='/admin'>Admin Panel</a> | <a href='/ping'>Ping Tool</a> | <a href='/logout'>Logout</a>"


# ─── VULNERABILITY 6: Broken Access Control ───────────────────────────────────
# No role check – any logged-in user can access /admin (CWE-285)
@app.route("/admin")
def admin():
    if "user" not in session:
        return redirect("/login")
    db = get_db()
    # ── VULNERABILITY 7: Sensitive data exposure ──────────────────────────────
    # Returns ALL user records including plain-text passwords (CWE-200)
    users = db.execute("SELECT * FROM users").fetchall()
    db.close()
    return f"<h2>Admin Panel</h2><pre>{users}</pre>"


# ─── VULNERABILITY 8: OS Command Injection ────────────────────────────────────
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # Unsanitised user input passed to shell (CWE-78)
    result = subprocess.check_output(f"ping -n 1 {host}", shell=True, text=True)
    return f"<pre>{result}</pre>"


# ─── VULNERABILITY 9: Insecure Deserialisation ────────────────────────────────
@app.route("/load_profile", methods=["POST"])
def load_profile():
    # Deserialising untrusted data with pickle (CWE-502)
    data = request.data
    profile = pickle.loads(data)
    return f"Profile loaded: {profile}"


# ─── VULNERABILITY 10: Path Traversal ────────────────────────────────────────
@app.route("/read_file")
def read_file():
    filename = request.args.get("file", "readme.txt")
    # No path sanitisation → directory traversal (CWE-22)
    with open(os.path.join("static", filename)) as f:
        return f"<pre>{f.read()}</pre>"


# ─── VULNERABILITY 11: Weak Hashing (MD5) ─────────────────────────────────────
@app.route("/reset_password", methods=["POST"])
def reset_password():
    new_pass = request.form.get("password", "")
    # MD5 is cryptographically broken for password hashing (CWE-327)
    hashed = hashlib.md5(new_pass.encode()).hexdigest()
    return f"Password hash stored: {hashed}"


# ─── VULNERABILITY 12: Missing CSRF protection ────────────────────────────────
# Flask-WTF / CSRF tokens are never used anywhere (CWE-352)

# ─── VULNERABILITY 13: Debug mode enabled in production ───────────────────────
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


if __name__ == "__main__":
    init_db()
    # Debug=True exposes interactive debugger to the network (CWE-94 / CVE class)
    app.run(debug=True, host="0.0.0.0", port=5001)
