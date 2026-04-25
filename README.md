# Secure-Coding-review
# 🔐 Secure Coding Review — Flask Demo Project

A side-by-side comparison of an **intentionally vulnerable** Flask application and its **fully remediated, secure** counterpart. Built for educational purposes to demonstrate real-world web application vulnerabilities and their fixes.

> ⚠️ **Warning:** The `vulnerable_app` contains deliberate security flaws. **Never deploy it in production or expose it to the internet.**

---

## 📁 Project Structure

```
Samiksha1/
├── vulnerable_app/
│   ├── app.py          # Intentionally insecure Flask app
│   └── users.db        # SQLite database (plain-text passwords)
│
├── secure_app/
│   ├── app.py          # Remediated / secure Flask app
│   ├── requirements.txt
│   ├── .env            # Environment variables (secrets, DB path)
│   ├── secure_users.db # SQLite database (hashed passwords)
│   └── templates/
│       ├── base.html
│       ├── index.html
│       ├── login.html
│       ├── dashboard.html
│       ├── admin.html
│       └── ping.html
│
├── bandit_results.json # Static analysis results (Bandit)
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.9+
- pip

### 1. Install Dependencies

```bash
pip install flask flask-wtf werkzeug markupsafe python-dotenv
```

> Dependencies are listed in `secure_app/requirements.txt`. The vulnerable app only requires Flask.

### 2. Run the Vulnerable App

```bash
cd vulnerable_app
python app.py
```

Runs on → **http://127.0.0.1:5001**

| Credential | Value |
|------------|-------|
| Username   | `admin` |
| Password   | `admin123` |

### 3. Run the Secure App

```bash
cd secure_app
python app.py
```

Runs on → **http://127.0.0.1:5000**

| Credential | Value |
|------------|-------|
| Username   | `admin` |
| Password   | `Admin@Secure2026!` *(set in `.env`)* |

---

## 🛣️ Application Routes

| Route | Method | Description |
|-------|--------|-------------|
| `/` | GET | Home / landing page |
| `/login` | GET, POST | User login |
| `/dashboard` | GET | User dashboard (auth required) |
| `/admin` | GET | Admin panel (admin role required in secure app) |
| `/ping?host=<host>` | GET | Ping a host |
| `/load_profile` | POST | Load user profile data |
| `/read_file?file=<name>` | GET | Read a whitelisted static file |
| `/reset_password` | POST | Reset current user's password |
| `/logout` | GET | Clear session and log out |

---

## 🐛 Vulnerabilities Covered

Each vulnerability is labelled by its [CWE](https://cwe.mitre.org/) identifier.

| # | Vulnerability | CWE | Vulnerable App | Secure App Fix |
|---|---------------|-----|----------------|----------------|
| 1 | Hard-coded secret key | CWE-798 | `app.secret_key = "supersecret123"` | Loaded from `SECRET_KEY` env variable |
| 2 | Hard-coded DB credentials | CWE-259 | `DB_PATH = "users.db"` literal | Loaded from `DB_PATH` env variable |
| 3 | Plain-text password storage | CWE-256 | Stored as `'admin123'` | `werkzeug` PBKDF2-HMAC-SHA256 hash |
| 4 | SQL Injection | CWE-89 | String interpolation in query | Parameterised queries (`?` placeholders) |
| 5 | Reflected XSS | CWE-79 | `render_template_string` with raw user input | Jinja2 `render_template` with auto-escaping |
| 6 | Broken Access Control | CWE-285 | No role check on `/admin` | `@admin_required` decorator enforces role |
| 7 | Sensitive Data Exposure | CWE-200 | Returns all columns incl. passwords | Only `id`, `username`, `role` selected |
| 8 | OS Command Injection | CWE-78 | `shell=True` with raw user input | Allowlist regex + `shell=False` list form |
| 9 | Insecure Deserialisation | CWE-502 | `pickle.loads(request.data)` | `json.loads()` with key allowlist |
| 10 | Path Traversal | CWE-22 | No path sanitisation | Explicit filename allowlist + `os.path` check |
| 11 | Weak Hashing (MD5) | CWE-327 | `hashlib.md5` for passwords | `generate_password_hash` (PBKDF2) |
| 12 | Missing CSRF Protection | CWE-352 | No CSRF tokens used | `Flask-WTF` `CSRFProtect` enabled globally |
| 13 | Debug Mode in Production | CWE-94 | `debug=True, host="0.0.0.0"` | `debug=False`, host `127.0.0.1`, via `.env` |

---

## 🔧 Environment Configuration (`secure_app/.env`)

```env
SECRET_KEY=change-me-to-a-long-random-string-in-production
ADMIN_PASSWORD=Admin@Secure2026!
DB_PATH=secure_users.db
FLASK_DEBUG=0
```

> Copy `.env` and customise values before deploying. Never commit real secrets to version control.

---

## 🛡️ Security Features in Secure App

- ✅ **Parameterised SQL queries** — eliminates SQL injection
- ✅ **Jinja2 auto-escaping** — prevents XSS via `render_template`
- ✅ **PBKDF2 password hashing** — via `werkzeug.security`
- ✅ **CSRF protection** — via `Flask-WTF`
- ✅ **Role-based access control** — `@login_required` / `@admin_required` decorators
- ✅ **Secure session cookies** — `HttpOnly`, `SameSite=Lax`, 30-min timeout
- ✅ **Session fixation prevention** — `session.clear()` before re-populating on login
- ✅ **Safe subprocess execution** — allowlist regex + list args, `shell=False`
- ✅ **JSON deserialization** — replaces unsafe `pickle`
- ✅ **File access allowlist** — explicit whitelist of permitted filenames
- ✅ **Secrets from environment** — no hard-coded credentials
- ✅ **Debug mode off** — configured via `.env`
- ✅ **Structured logging** — failed logins and unauthorised access attempts logged

---

## 📊 Static Analysis

Bandit was used to perform static analysis on both apps. Results are saved in:

```
bandit_results.json
```

To regenerate:

```bash
pip install bandit
bandit -r vulnerable_app/ -f json -o bandit_results.json
```

---

## 📚 References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [Flask Security Guide](https://flask.palletsprojects.com/en/latest/security/)
- [Werkzeug Password Hashing](https://werkzeug.palletsprojects.com/en/latest/utils/#werkzeug.security.generate_password_hash)
- [Flask-WTF CSRF](https://flask-wtf.readthedocs.io/en/stable/csrf/)

---

## 📝 License

This project is for **educational and research purposes only**.  
Do not use the vulnerable application outside of a controlled, isolated environment.
