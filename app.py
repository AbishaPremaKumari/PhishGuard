import os
import time
import ipaddress
import csv
import secrets
from datetime import timedelta
from io import StringIO

from flask import Flask, request, redirect, url_for, session, render_template_string, Response
from urllib.parse import urlparse
import re
from dotenv import load_dotenv
from werkzeug.security import check_password_hash, generate_password_hash

from detector import analyze_url
from database import get_connection


# ============================================================
# LOAD ENVIRONMENT VARIABLES
# ============================================================

load_dotenv()


# ============================================================
# FLASK APP
# ============================================================

app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("SECRET_KEY is missing. Add SECRET_KEY to the .env file before starting PhishGuard.")

# Security-focused session and response settings for the local Flask application.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)


# ============================================================
# CSRF PROTECTION
# ============================================================

def csrf_token():
    """Return a per-session CSRF token for POST forms."""
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_post_requests():
    """Reject state-changing POST requests without a valid CSRF token."""
    if request.method != "POST":
        return None

    submitted_token = request.form.get("csrf_token", "")
    stored_token = session.get("csrf_token", "")

    if not submitted_token or not stored_token or not secrets.compare_digest(submitted_token, stored_token):
        return "Invalid or missing security token. Please refresh the page and try again.", 400

    return None


@app.after_request
def add_security_headers(response):
    """Add basic browser security headers to application responses."""
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    if request.endpoint and request.endpoint.startswith("admin_"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


# ============================================================
# USER ACCOUNT / IDENTITY SUPPORT
# ============================================================

USER_SCHEMA_READY = False

def ensure_user_schema():
    """Create the user table and add ownership columns to existing tables."""

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(255) NULL UNIQUE,
            password_hash VARCHAR(255) NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    def add_column_if_missing(table_name, column_name, column_definition):
        cursor.execute("""
            SELECT COUNT(*)
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
              AND TABLE_NAME = %s
              AND COLUMN_NAME = %s
        """, (table_name, column_name))

        exists = cursor.fetchone()[0]

        if not exists:
            cursor.execute(
                f"ALTER TABLE `{table_name}` ADD COLUMN `{column_name}` {column_definition}"
            )

    add_column_if_missing("users", "password_hash", "VARCHAR(255) NULL")
    # Email is retained for existing records/admin reporting, but user login no longer requires it.
    cursor.execute("""
        ALTER TABLE users MODIFY COLUMN email VARCHAR(255) NULL
    """)

    # Existing PhishGuard databases may have the legacy users.email column marked NOT NULL.
    # New name+password accounts do not require an email, so make that column nullable.
    cursor.execute("""
        SELECT IS_NULLABLE
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'users'
          AND COLUMN_NAME = 'email'
    """)
    email_nullable = cursor.fetchone()
    if email_nullable and email_nullable[0] != 'YES':
        cursor.execute("ALTER TABLE users MODIFY COLUMN email VARCHAR(255) NULL")

    add_column_if_missing("analysis_history", "user_id", "INT NULL")
    add_column_if_missing("reports", "user_id", "INT NULL")
    add_column_if_missing("reports", "status", "VARCHAR(50) NOT NULL DEFAULT 'Pending'")
    add_column_if_missing("reports", "reviewed_at", "TIMESTAMP NULL")
    add_column_if_missing("reports", "reviewed_by", "INT NULL")

    def create_index_if_missing(table_name, index_name, column_name):
        cursor.execute("""
            SELECT COUNT(*)
            FROM INFORMATION_SCHEMA.STATISTICS
            WHERE TABLE_SCHEMA = DATABASE()
              AND TABLE_NAME = %s
              AND INDEX_NAME = %s
        """, (table_name, index_name))

        exists = cursor.fetchone()[0]

        if not exists:
            cursor.execute(
                f"CREATE INDEX `{index_name}` ON `{table_name}` (`{column_name}`)"
            )

    create_index_if_missing("analysis_history", "idx_analysis_history_user_id", "user_id")
    create_index_if_missing("reports", "idx_reports_user_id", "user_id")

    connection.commit()
    cursor.close()
    connection.close()


def authenticate_user(name, password):
    """Authenticate an existing user using name + password only."""
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id, name, email, password_hash
        FROM users
        WHERE name = %s
        ORDER BY id ASC
    """, (name,))

    matches = cursor.fetchall()

    for user in matches:
        if user[3] and check_password_hash(user[3], password):
            cursor.close()
            connection.close()
            return user

    cursor.close()
    connection.close()
    return None


def create_user(name, password):
    """Create a new PhishGuard user account."""
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT id FROM users WHERE name = %s LIMIT 1", (name,))
    existing = cursor.fetchone()

    if existing:
        cursor.close()
        connection.close()
        return None

    password_hash = generate_password_hash(password)
    cursor.execute("""
        INSERT INTO users (name, email, password_hash)
        VALUES (%s, NULL, %s)
    """, (name, password_hash))
    connection.commit()

    user_id = cursor.lastrowid
    cursor.execute("""
        SELECT id, name, email, password_hash
        FROM users
        WHERE id = %s
    """, (user_id,))
    user = cursor.fetchone()

    cursor.close()
    connection.close()
    return user


@app.before_request
def initialize_user_schema():
    """Initialize the small user-account migration once before requests."""
    global USER_SCHEMA_READY

    if USER_SCHEMA_READY:
        return None

    if request.endpoint == "static":
        return None

    ensure_user_schema()
    USER_SCHEMA_READY = True
    return None


# ============================================================
# DATE / TIME DISPLAY
# ============================================================

def format_datetime(value):

    if value is None:
        return "-"

    try:
        return value.strftime("%d %b %Y • %I:%M %p")
    except AttributeError:
        return str(value)


app.jinja_env.filters["pretty_datetime"] = format_datetime


def shorten_url(value, max_length=55):

    if not value:
        return "-"

    value = str(value)

    if len(value) <= max_length:
        return value

    return value[:max_length].rstrip() + "…"


app.jinja_env.filters["shorten_url"] = shorten_url


def build_score_breakdown(url, result):
    """Build a visual explanation of the rule contributions for the current analysis."""

    if result.get("risk") == "Invalid URL":
        return []

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path_and_query = f"{parsed.path or ''}{('?' + parsed.query) if parsed.query else ''}"
    url_lower = url.lower()

    rules = [
        ("HTTPS not used", "The URL uses HTTP instead of HTTPS.", 10, parsed.scheme.lower() != "https"),
        ("Long URL", "URL length is greater than 100 characters.", 15, len(url) > 100),
        ("@ symbol", "The URL contains the @ symbol.", 20, "@" in url),
        ("IP address", "The hostname is an IPv4 address instead of a domain name.", 25, False),
        ("Suspicious keyword", "A security-related keyword such as login, verify or account is present.", 10, False),
        ("Many subdomains", "The hostname contains more than three domain sections.", 15, hostname.count(".") > 3),
        ("Non-standard port", "The URL uses a port other than 80 or 443.", 10, False),
        ("Punycode domain", "The hostname contains the xn-- punycode pattern.", 15, "xn--" in hostname),
        ("Encoded character %", "The URL contains a percent-encoded character.", 5, "%" in url),
        ("Double slash in path", "The path contains // after the hostname.", 10, "//" in path_and_query),
        ("Multiple hyphens", "The hostname contains three or more hyphens.", 10, hostname.count("-") >= 3),
    ]

    try:
        ipaddress.ip_address(hostname)
        rules[3] = (rules[3][0], rules[3][1], rules[3][2], True)
    except ValueError:
        pass

    suspicious_keywords = [
        "login", "verify", "account", "bank", "secure",
        "update", "signin", "password", "confirm", "wallet"
    ]

    matched_keywords = [
        word for word in suspicious_keywords
        if word in url_lower
    ]

    if matched_keywords:
        keyword_text = ", ".join(matched_keywords)
        rules[4] = (
            f"Suspicious keywords: {keyword_text}",
            f"Detected keyword(s) in the URL: {keyword_text}.",
            rules[4][2],
            True
        )

    try:
        port = parsed.port
        rules[6] = (rules[6][0], rules[6][1], rules[6][2], port is not None and port not in (80, 443))
    except ValueError:
        pass

    breakdown = []
    calculated = 0
    for name, description, points, triggered in rules:
        if triggered:
            breakdown.append({"name": name, "description": description, "points": points})
            calculated += points

    actual_score = int(result.get("score", 0))
    difference = actual_score - calculated
    if difference > 0:
        breakdown.append({
            "name": "Additional detector contribution",
            "description": "Additional rule contribution used by the active detector.",
            "points": difference
        })

    return breakdown


# ============================================================
# ANALYSIS DETAILS
# ============================================================

@app.route("/analysis/<int:analysis_id>")
def analysis_details(analysis_id):

    is_admin = bool(session.get("admin_logged_in"))
    is_user = bool(session.get("user_logged_in"))

    if not is_admin and not is_user:
        return redirect(url_for("user_login"))

    connection = get_connection()
    cursor = connection.cursor()

    if is_admin:
        cursor.execute("""
            SELECT id, user_id, url, score, risk, reasons, analyzed_at
            FROM analysis_history
            WHERE id = %s
        """, (analysis_id,))
    else:
        cursor.execute("""
            SELECT id, user_id, url, score, risk, reasons, analyzed_at
            FROM analysis_history
            WHERE id = %s AND user_id = %s
        """, (analysis_id, session.get("user_id")))

    record = cursor.fetchone()
    cursor.close()
    connection.close()

    if not record:
        return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Analysis Not Found - PhishGuard</title>
<style>
body{font-family:Arial,sans-serif;background:#020617;color:white;margin:0;padding:50px;}
.box{max-width:700px;margin:60px auto;background:#0f172a;border:1px solid #1e293b;border-radius:18px;padding:35px;text-align:center;}
a{display:inline-block;margin-top:18px;color:#38bdf8;text-decoration:none;padding:10px 16px;border:1px solid #334155;border-radius:8px;}
</style>
</head>
<body><div class="box"><div style="font-size:44px;">🔎</div><h1>Analysis Not Found</h1><p style="color:#94a3b8;">The requested analysis record does not exist or you do not have permission to view it.</p><a href="{{ back_url }}">← Go Back</a></div></body>
</html>
""", back_url=url_for("admin_history") if is_admin else url_for("history"))

    analysis_id_db, user_id, url, score, risk, reasons_text, analyzed_at = record
    reasons = [item.strip() for item in (reasons_text or "").split("|") if item.strip()]
    result = {
        "score": int(score),
        "risk": risk,
        "reasons": reasons,
    }
    result["breakdown"] = build_score_breakdown(url, result)

    if is_admin:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute("""
            SELECT COALESCE(u.name, 'Previous / Unknown User'),
                   COALESCE(u.email, '-')
            FROM analysis_history h
            LEFT JOIN users u ON h.user_id = u.id
            WHERE h.id = %s
        """, (analysis_id,))
        user_record = cursor.fetchone()
        cursor.close()
        connection.close()
        viewer_name = user_record[0] if user_record else "Previous / Unknown User"
        viewer_email = user_record[1] if user_record else "-"
        back_url = url_for("admin_history")
        page_title = "Analysis Details - Admin"
    else:
        viewer_name = session.get("user_name", "User")
        viewer_email = session.get("user_email", "-")
        back_url = url_for("history")
        page_title = "Analysis Details"

    return render_template_string(r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ page_title }} - PhishGuard</title>
<style>
*{box-sizing:border-box;}
body{margin:0;min-height:100vh;font-family:Arial,sans-serif;background:radial-gradient(circle at top left,#172554,transparent 35%),radial-gradient(circle at bottom right,#312e81,transparent 35%),#020617;color:white;}
.container{max-width:1050px;margin:45px auto;padding:0 20px 50px;}
.top{display:flex;justify-content:space-between;align-items:center;gap:18px;flex-wrap:wrap;margin-bottom:22px;}
.top h1{margin:0;}
a{color:#38bdf8;text-decoration:none;}
.back{display:inline-block;padding:10px 15px;border:1px solid #334155;border-radius:9px;background:#0f172a;}
.card{background:rgba(15,23,42,.94);border:1px solid #1e293b;border-radius:18px;padding:25px;margin-bottom:20px;}
.label{color:#94a3b8;font-size:13px;margin-bottom:7px;text-transform:uppercase;letter-spacing:.04em;}
.url{font-size:18px;line-height:1.6;word-break:break-word;color:#e2e8f0;}
.meta-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:15px;margin-top:18px;}
.meta{background:#020617;border:1px solid #1e293b;border-radius:12px;padding:16px;}
.value{font-size:16px;color:#e2e8f0;word-break:break-word;}
.score-risk{display:grid;grid-template-columns:220px 1fr;gap:18px;margin-top:20px;}
.score-box{background:#020617;border:1px solid #1e293b;border-radius:14px;padding:25px;text-align:center;}
.score{font-size:44px;font-weight:bold;color:#38bdf8;}
.score-label{color:#94a3b8;margin-top:5px;}
.risk-meter{margin-top:18px;text-align:left;}
.risk-meter-bar{position:relative;height:14px;border-radius:999px;background:linear-gradient(to right,#22c55e 0%,#22c55e 19%,#facc15 19%,#facc15 39%,#ef4444 39%,#ef4444 100%);overflow:hidden;border:1px solid rgba(255,255,255,0.08);}
.risk-meter-fill{position:absolute;top:0;left:0;height:100%;background:rgba(2,6,23,.78);border-right:2px solid white;}
.risk-meter-scale{display:flex;justify-content:space-between;gap:8px;margin-top:8px;color:#64748b;font-size:11px;flex-wrap:wrap;}
.risk{padding:12px 16px;border-radius:10px;display:inline-block;font-weight:bold;font-size:18px;}
.low{color:#4ade80;background:rgba(74,222,128,.1);}.suspicious{color:#facc15;background:rgba(250,204,21,.1);}.high{color:#f87171;background:rgba(248,113,113,.1);}.invalid{color:#fbbf24;background:rgba(251,191,36,.1);}
.details-list{list-style:none;padding:0;margin:0;}
.details-list li{padding:12px 0;border-bottom:1px solid #1e293b;color:#cbd5e1;line-height:1.5;}
.details-list li:last-child{border-bottom:none;}
.score-breakdown{margin-top:0;background:#020617;border:1px solid #1e293b;border-radius:14px;padding:20px;}
.breakdown-title{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:12px;}
.breakdown-title h2{font-size:20px;margin:0;}
.breakdown-total{color:#38bdf8;font-weight:bold;}
.breakdown-item{padding:13px 0;border-bottom:1px solid #1e293b;}
.breakdown-item:last-child{border-bottom:none;}
.breakdown-row{display:flex;justify-content:space-between;gap:15px;}
.breakdown-name{color:#e2e8f0;font-weight:600;}
.breakdown-points{color:#fbbf24;font-weight:bold;white-space:nowrap;}
.breakdown-description{margin-top:5px;color:#94a3b8;font-size:13px;line-height:1.5;}
.empty{color:#94a3b8;line-height:1.6;padding:10px 0;}
.note{margin-top:16px;color:#64748b;font-size:12px;line-height:1.5;}
@media(max-width:760px){.meta-grid{grid-template-columns:1fr;}.score-risk{grid-template-columns:1fr;}.container{margin-top:25px;}}
</style>
</head>
<body>
<div class="container">
    <div class="top">
        <h1>🔍 Analysis Details</h1>
        <a class="back" href="{{ back_url }}">← Back</a>
    </div>

    <div class="card">
        <div class="label">Analyzed URL</div>
        <div class="url">{{ url }}</div>

        <div class="meta-grid">
            <div class="meta"><div class="label">Analysis ID</div><div class="value">#{{ analysis_id_db }}</div></div>
            <div class="meta"><div class="label">User</div><div class="value">{{ viewer_name }}</div></div>
            <div class="meta"><div class="label">Email</div><div class="value">{{ viewer_email }}</div></div>
            <div class="meta"><div class="label">Analyzed At</div><div class="value">{{ analyzed_at|pretty_datetime }}</div></div>
            <div class="meta">
                <div class="label">Stored Score</div>
                <div class="value">{{ result.score }}/100</div>
                <div class="risk-meter" aria-label="Risk score meter">
                    <div class="risk-meter-bar">
                        <div class="risk-meter-fill" style="width: {{ result.score }}%;"></div>
                    </div>
                    <div class="risk-meter-scale">
                        <span>0</span><span>19</span><span>39</span><span>100</span>
                    </div>
                </div>
            </div>
            <div class="meta"><div class="label">Risk Classification</div><div class="value">
                <span class="risk {% if result.risk == 'Low Risk' %}low{% elif result.risk == 'Suspicious' %}suspicious{% elif result.risk == 'High Risk' %}high{% else %}invalid{% endif %}">
                    {% if result.risk == 'Low Risk' %}🟢{% elif result.risk == 'Suspicious' %}🟡{% elif result.risk == 'High Risk' %}🔴{% else %}⚠️{% endif %} {{ result.risk }}
                </span>
            </div></div>
        </div>
    </div>

    <div class="card">
        <h2>🧾 Detection Details</h2>
        {% if result.reasons %}
        <ul class="details-list">
            {% for reason in result.reasons %}<li>✓ {{ reason }}</li>{% endfor %}
        </ul>
        {% else %}
        <div class="empty">No specific risk indicators were recorded for this analysis.</div>
        {% endif %}
    </div>

    <div class="card score-breakdown">
        <div class="breakdown-title">
            <h2>📊 Score Breakdown</h2>
            <span class="breakdown-total">{{ result.score }}/100</span>
        </div>
        {% if result.breakdown %}
            {% for item in result.breakdown %}
            <div class="breakdown-item">
                <div class="breakdown-row"><span class="breakdown-name">{{ item.name }}</span><span class="breakdown-points">+{{ item.points }}</span></div>
                <div class="breakdown-description">{{ item.description }}</div>
            </div>
            {% endfor %}
        {% else %}
            <div class="empty">✅ No risk indicators were triggered by the current rule checks.</div>
        {% endif %}
        <div class="note">The stored score and classification come from the analysis record. The breakdown explains the active rule contributions for this URL.</div>
    </div>
</div>
</body>
</html>
""", page_title=page_title, back_url=back_url, analysis_id_db=analysis_id_db, viewer_name=viewer_name, viewer_email=viewer_email, url=url, analyzed_at=analyzed_at, result=result)


# ============================================================
# ADMIN SESSION TIMEOUT
# ============================================================

ADMIN_SESSION_TIMEOUT = 30 * 60  # 30 minutes


@app.before_request
def check_admin_session_timeout():

    if not session.get("admin_logged_in"):
        return None

    if request.endpoint in ["admin_login", "static"]:
        return None

    last_activity = session.get("admin_last_activity")
    current_time = time.time()

    if last_activity is not None:

        if current_time - last_activity > ADMIN_SESSION_TIMEOUT:

            session.clear()

            return redirect(url_for("admin_login"))

    session["admin_last_activity"] = current_time

    return None


# ============================================================
# USER LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def user_login():

    error = None

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        password = request.form.get("password", "")

        if not name:
            error = "Please enter your user name."

        elif len(name) > 100:
            error = "User name must be 100 characters or fewer."

        elif len(password) < 6:
            error = "Password must be at least 6 characters."

        if error is None:
            user = authenticate_user(name, password)

            if user:
                session.clear()
                session["user_logged_in"] = True
                session["user_id"] = user[0]
                session["user_name"] = user[1]
                session["user_email"] = user[2] or ""

                return redirect(url_for("user_dashboard"))

            error = "Invalid user name or incorrect password. Please try again."

    return render_template_string("""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>User Login - PhishGuard</title>
<style>
body { margin:0; min-height:100vh; display:flex; justify-content:center; align-items:center; background:#020617; color:white; font-family:Arial,sans-serif; }
.login-box { width:390px; background:#0f172a; padding:35px; border-radius:18px; border:1px solid #1e293b; box-shadow:0 20px 50px rgba(0,0,0,0.4); }
h1 { text-align:center; margin-bottom:10px; }
.subtitle { text-align:center; color:#94a3b8; margin-bottom:28px; line-height:1.5; }
input { width:100%; padding:14px; margin-bottom:15px; border-radius:8px; border:1px solid #334155; background:#020617; color:white; box-sizing:border-box; font-size:15px; }
button { width:100%; padding:14px; border:none; border-radius:8px; background:#0284c7; color:white; font-weight:bold; cursor:pointer; font-size:15px; }
.error { background:rgba(239,68,68,0.12); color:#f87171; padding:12px; border-radius:8px; margin-bottom:15px; text-align:center; line-height:1.4; }
.note { margin-top:18px; text-align:center; color:#64748b; font-size:12px; line-height:1.5; }
.register { display:block; margin-top:16px; text-align:center; color:#38bdf8; text-decoration:none; font-size:14px; }
</style>
</head>
<body>
<div class="login-box">
    <h1>🛡️ PhishGuard</h1>
    <div class="subtitle">Enter your user name and password to access your personal PhishGuard workspace.</div>
    {% if error %}<div class="error">{{ error }}</div>{% endif %}
    <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <input type="text" name="name" placeholder="Enter your user name" maxlength="100" required>
        <input type="password" name="password" placeholder="Enter your password" minlength="6" required>
        <button type="submit">Login to PhishGuard</button>
    </form>
    <a class="register" href="/register">➕ New user? Create an account</a>
    <div class="note">Your analysis history and reports are linked to your PhishGuard account.</div>
</div>
</body>
</html>
""")


@app.route("/register", methods=["GET", "POST"])
def register():

    error = None
    success = None

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not name:
            error = "Please enter a user name."
        elif len(name) > 100:
            error = "User name must be 100 characters or fewer."
        elif len(password) < 6:
            error = "Password must be at least 6 characters."
        elif password != confirm_password:
            error = "Passwords do not match."
        elif not re.fullmatch(r"[A-Za-z0-9 ._-]+", name):
            error = "User name can contain letters, numbers, spaces, dot, underscore and hyphen only."

        if error is None:
            user = create_user(name, password)
            if user:
                session.clear()
                session["user_logged_in"] = True
                session["user_id"] = user[0]
                session["user_name"] = user[1]
                session["user_email"] = ""
                return redirect(url_for("user_dashboard"))
            error = "That user name already exists. Please choose another one."

    return render_template_string("""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Create Account - PhishGuard</title>
<style>
body { margin:0; min-height:100vh; display:flex; justify-content:center; align-items:center; background:#020617; color:white; font-family:Arial,sans-serif; }
.login-box { width:390px; background:#0f172a; padding:35px; border-radius:18px; border:1px solid #1e293b; box-shadow:0 20px 50px rgba(0,0,0,0.4); }
h1 { text-align:center; margin-bottom:10px; }
.subtitle { text-align:center; color:#94a3b8; margin-bottom:28px; line-height:1.5; }
input { width:100%; padding:14px; margin-bottom:15px; border-radius:8px; border:1px solid #334155; background:#020617; color:white; box-sizing:border-box; font-size:15px; }
button { width:100%; padding:14px; border:none; border-radius:8px; background:#0284c7; color:white; font-weight:bold; cursor:pointer; font-size:15px; }
.error { background:rgba(239,68,68,0.12); color:#f87171; padding:12px; border-radius:8px; margin-bottom:15px; text-align:center; line-height:1.4; }
.back { display:block; margin-top:16px; text-align:center; color:#38bdf8; text-decoration:none; font-size:14px; }
.note { margin-top:18px; text-align:center; color:#64748b; font-size:12px; line-height:1.5; }
</style>
</head>
<body>
<div class="login-box">
    <h1>🛡️ Create PhishGuard Account</h1>
    <div class="subtitle">Create a user name and password for your personal workspace.</div>
    {% if error %}<div class="error">{{ error }}</div>{% endif %}
    <form method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <input type="text" name="name" placeholder="Choose a user name" maxlength="100" required>
        <input type="password" name="password" placeholder="Create a password" minlength="6" required>
        <input type="password" name="confirm_password" placeholder="Confirm password" minlength="6" required>
        <button type="submit">Create Account</button>
    </form>
    <a class="back" href="{{ url_for('user_login') }}">← Back to Login</a>
    <div class="note">Use a unique user name and remember your password.</div>
</div>
</body>
</html>
""")


@app.route("/logout")
def user_logout():
    session.clear()
    return redirect(url_for("user_login"))


# ============================================================
# SAVE ANALYSIS HISTORY
# ============================================================

def validate_url(url):
    """Perform basic structural validation before security analysis."""

    url = url.strip()

    if not url:
        return False, "Please enter a URL."

    if len(url) > 2048:
        return False, "URL is too long. Please enter a URL shorter than 2048 characters."

    if any(ord(character) < 32 or ord(character) == 127 for character in url):
        return False, "URL contains invalid control characters."

    parsed_url = urlparse(url)

    if parsed_url.scheme.lower() not in ("http", "https"):
        return False, "URL must start with http:// or https://."

    if not parsed_url.netloc:
        return False, "URL must contain a valid domain or IP address."

    try:
        hostname = parsed_url.hostname
        port = parsed_url.port
    except ValueError:
        return False, "URL contains an invalid hostname or port."

    if not hostname:
        return False, "URL must contain a valid domain or IP address."

    hostname = hostname.lower().rstrip(".")

    if ".." in hostname:
        return False, "Domain contains consecutive dots."

    # IPv6 hostnames contain colons and are valid when urlparse accepts them.
    if ":" not in hostname:
        labels = hostname.split(".")

        for label in labels:
            if not label:
                return False, "Domain contains an empty section."

            if label.startswith("-") or label.endswith("-"):
                return False, "Domain labels cannot start or end with a hyphen."

            if not re.fullmatch(r"[a-z0-9-]+", label, re.IGNORECASE):
                return False, "Domain contains invalid characters."

    return True, ""


def save_analysis(url, result):

    connection = get_connection()
    cursor = connection.cursor()

    reasons = " | ".join(result["reasons"])

    query = """
        INSERT INTO analysis_history
        (user_id, url, score, risk, reasons)
        VALUES (%s, %s, %s, %s, %s)
    """

    cursor.execute(
        query,
        (
            session.get("user_id"),
            url,
            result["score"],
            result["risk"],
            reasons
        )
    )

    connection.commit()

    cursor.close()
    connection.close()



# ============================================================
# USER DASHBOARD
# ============================================================

@app.route("/dashboard")
def user_dashboard():

    if not session.get("user_logged_in"):
        return redirect(url_for("user_login"))

    user_id = session.get("user_id")
    user_name = session.get("user_name", "User")
    user_email = session.get("user_email", "")

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM analysis_history WHERE user_id = %s",
        (user_id,)
    )
    total_analyses = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM analysis_history WHERE user_id = %s AND risk = %s",
        (user_id, "Low Risk")
    )
    low_risk = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM analysis_history WHERE user_id = %s AND risk = %s",
        (user_id, "Suspicious")
    )
    suspicious = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM analysis_history WHERE user_id = %s AND risk = %s",
        (user_id, "High Risk")
    )
    high_risk = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM reports WHERE user_id = %s",
        (user_id,)
    )
    total_reports = cursor.fetchone()[0]

    cursor.execute("""
        SELECT id, url, score, risk, analyzed_at
        FROM analysis_history
        WHERE user_id = %s
        ORDER BY analyzed_at DESC
        LIMIT 5
    """, (user_id,))
    recent_analyses = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>User Dashboard - PhishGuard</title>
<style>
* { box-sizing: border-box; }
body { margin:0; min-height:100vh; font-family:Arial,sans-serif; background:radial-gradient(circle at top left,#172554,transparent 35%),radial-gradient(circle at bottom right,#312e81,transparent 35%),#020617; color:white; }
.navbar { width:100%; padding:20px 7%; display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid rgba(255,255,255,0.08); gap:20px; }
.logo { font-size:24px; font-weight:bold; color:#38bdf8; }
.nav-links { display:flex; gap:10px; align-items:center; flex-wrap:wrap; justify-content:flex-end; }
.nav-links a { color:#cbd5e1; text-decoration:none; padding:9px 14px; border-radius:8px; background:rgba(255,255,255,0.05); }
.nav-links a:hover { background:rgba(56,189,248,0.12); color:#38bdf8; }
.container { max-width:1100px; margin:45px auto; padding:0 20px 40px; }
.welcome { background:rgba(15,23,42,0.88); border:1px solid rgba(255,255,255,0.08); padding:30px; border-radius:18px; margin-bottom:24px; }
.welcome h1 { margin:0 0 8px; }
.welcome p { margin:0; color:#94a3b8; }
.stats { display:grid; grid-template-columns:repeat(5,1fr); gap:16px; margin-bottom:24px; }
.card { background:#0f172a; border:1px solid #1e293b; border-radius:14px; padding:20px; }
.card-title { color:#94a3b8; font-size:14px; margin-bottom:10px; }
.card-number { font-size:32px; font-weight:bold; }
.blue { color:#38bdf8; } .green { color:#4ade80; } .yellow { color:#facc15; } .red { color:#f87171; }
.actions { display:grid; grid-template-columns:repeat(3,1fr); gap:16px; margin-bottom:24px; }
.action { text-decoration:none; color:white; background:#0f172a; border:1px solid #1e293b; border-radius:14px; padding:22px; transition:0.2s; }
.action:hover { transform:translateY(-2px); border-color:#38bdf8; }
.action h3 { margin:0 0 8px; color:#38bdf8; } .action p { margin:0; color:#94a3b8; line-height:1.5; }
.section { background:#0f172a; border:1px solid #1e293b; border-radius:15px; padding:24px; }
table { width:100%; border-collapse:collapse; } th,td { padding:14px; text-align:left; border-bottom:1px solid #1e293b; } th { color:#38bdf8; } td { color:#cbd5e1; }
.low { color:#4ade80; font-weight:bold; } .suspicious { color:#facc15; font-weight:bold; } .high { color:#f87171; font-weight:bold; }
.empty { text-align:center; padding:25px; color:#94a3b8; }
@media(max-width:900px){ .stats{grid-template-columns:repeat(2,1fr);} .actions{grid-template-columns:1fr;} }
@media(max-width:600px){ .stats{grid-template-columns:1fr;} .navbar{padding:18px 5%; align-items:flex-start;} .nav-links{justify-content:flex-start;} }
</style>
</head>
<body>
<div class="navbar">
    <div class="logo">🛡️ PhishGuard</div>
    <div class="nav-links">
        <span style="color:#94a3b8; padding:9px 5px;">Hi, {{ user_name }}</span>
        <a href="/">🔎 Scanner</a>
        <a href="/history">📋 My History</a>
        <a href="/my-reports">🚨 My Reports</a>
        <a href="/admin/login">🔐 Admin</a>
        <a href="/logout">Logout</a>
    </div>
</div>

<div class="container">
    <div class="welcome">
        <h1>📊 Welcome, {{ user_name }} 👋</h1>
        <p>{{ user_email }}</p>
    </div>

    <div class="stats">
        <div class="card"><div class="card-title">Total Analyses</div><div class="card-number blue">{{ total_analyses }}</div></div>
        <div class="card"><div class="card-title">Low Risk</div><div class="card-number green">{{ low_risk }}</div></div>
        <div class="card"><div class="card-title">Suspicious</div><div class="card-number yellow">{{ suspicious }}</div></div>
        <div class="card"><div class="card-title">High Risk</div><div class="card-number red">{{ high_risk }}</div></div>
        <div class="card"><div class="card-title">Reports Submitted</div><div class="card-number red">{{ total_reports }}</div></div>
    </div>

    <div class="actions">
        <a class="action" href="/">
            <h3>🔎 Scan a URL</h3>
            <p>Analyze a website URL and view its explainable risk score.</p>
        </a>
        <a class="action" href="/history">
            <h3>📋 My History</h3>
            <p>View your previous URL analyses and filter them by risk level.</p>
        </a>
        <a class="action" href="/my-reports">
            <h3>🚨 My Reports</h3>
            <p>Review your submitted suspicious URLs and track their review status.</p>
        </a>
    </div>

    <div class="section">
        <h2>🕒 Recent Analyses</h2>
        <p style="color:#94a3b8;">Your five most recent URL analyses.</p>
        {% if recent_analyses %}
        <table>
            <tr><th>ID</th><th>URL</th><th>Score</th><th>Risk</th><th>Analyzed At</th><th>Details</th></tr>
            {% for analysis in recent_analyses %}
            <tr>
                <td>{{ analysis[0] }}</td>
                <td title="{{ analysis[1] }}">{{ analysis[1]|shorten_url }}</td>
                <td>{{ analysis[2] }}/100</td>
                <td class="{% if analysis[3] == 'Low Risk' %}low{% elif analysis[3] == 'Suspicious' %}suspicious{% else %}high{% endif %}">{{ analysis[3] }}</td>
                <td>{{ analysis[4]|pretty_datetime }}</td>
                <td><a href="{{ url_for('analysis_details', analysis_id=analysis[0]) }}">View Details</a></td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
        <div class="empty">📭 No URL analyses yet. Start by scanning a URL.</div>
        {% endif %}
    </div>
</div>
</body>
</html>
""", user_name=user_name, user_email=user_email, total_analyses=total_analyses, low_risk=low_risk, suspicious=suspicious, high_risk=high_risk, total_reports=total_reports, recent_analyses=recent_analyses)


# ============================================================
# HOME PAGE
# ============================================================

@app.route("/", methods=["GET", "POST"])
def home():

    if not session.get("user_logged_in"):
        return redirect(url_for("user_login"))

    result = None
    url = ""

    if request.method == "POST":

        url = request.form.get("url", "").strip()

        if url:

            is_valid, validation_message = validate_url(url)

            if not is_valid:
                result = {
                    "score": 0,
                    "risk": "Invalid URL",
                    "reasons": [validation_message],
                    "breakdown": []
                }
            else:
                result = analyze_url(url)
                result["breakdown"] = build_score_breakdown(url, result)
                save_analysis(url, result)

    return render_template_string("""
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>PhishGuard - URL Security Scanner</title>

<style>

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {

    font-family: Arial, sans-serif;

    background:
        radial-gradient(circle at top left, #172554, transparent 35%),
        radial-gradient(circle at bottom right, #312e81, transparent 35%),
        #020617;

    color: white;

    min-height: 100vh;
}

.navbar {

    width: 100%;

    padding: 22px 8%;

    display: flex;

    justify-content: space-between;

    align-items: center;

    border-bottom: 1px solid rgba(255,255,255,0.08);
}

.logo {

    font-size: 25px;

    font-weight: bold;

    color: #38bdf8;
}

.nav-links {

    display: flex;

    gap: 15px;
}

.nav-links a {

    text-decoration: none;

    color: #cbd5e1;

    padding: 9px 15px;

    border-radius: 8px;

    background: rgba(255,255,255,0.05);

    transition: 0.3s;
}

.nav-links a:hover {

    background: rgba(56,189,248,0.15);

    color: #38bdf8;
}

.hero {

    max-width: 900px;

    margin: 70px auto 30px;

    padding: 0 20px;

    text-align: center;
}

.badge {

    display: inline-block;

    padding: 7px 14px;

    border-radius: 20px;

    background: rgba(56,189,248,0.1);

    color: #38bdf8;

    font-size: 13px;

    margin-bottom: 20px;
}

.hero h1 {

    font-size: 50px;

    margin-bottom: 18px;
}

.hero h1 span {

    color: #38bdf8;
}

.hero p {

    color: #94a3b8;

    font-size: 17px;

    line-height: 1.7;
}

.scanner {

    max-width: 850px;

    margin: 35px auto;

    padding: 25px;

    background: rgba(15,23,42,0.85);

    border: 1px solid rgba(148,163,184,0.15);

    border-radius: 18px;

    box-shadow: 0 20px 50px rgba(0,0,0,0.3);
}

.scanner form {

    display: flex;

    gap: 12px;
}

.scanner input {

    flex: 1;

    padding: 16px;

    border-radius: 10px;

    border: 1px solid #334155;

    background: #020617;

    color: white;

    outline: none;

    font-size: 15px;
}

.scanner input:focus {

    border-color: #38bdf8;
}

.scanner button {

    padding: 16px 25px;

    border: none;

    border-radius: 10px;

    background: #0284c7;

    color: white;

    font-weight: bold;

    cursor: pointer;
}

.scanner button:hover {

    background: #0369a1;
}

.result {

    max-width: 850px;

    margin: 25px auto;

    padding: 28px;

    border-radius: 18px;

    background: rgba(15,23,42,0.9);

    border: 1px solid rgba(255,255,255,0.1);
}

.result-header {

    display: flex;

    justify-content: space-between;

    align-items: center;

    gap: 20px;

    margin-bottom: 25px;
}

.result-header h2 {

    margin-bottom: 8px;
}

.result-url {

    color: #94a3b8;

    word-break: break-all;
}

.risk {

    padding: 12px 18px;

    border-radius: 30px;

    font-weight: bold;

    white-space: nowrap;
}

.low {

    background: rgba(34,197,94,0.15);

    color: #4ade80;
}

.suspicious {

    background: rgba(234,179,8,0.15);

    color: #facc15;
}

.high {

    background: rgba(239,68,68,0.15);

    color: #f87171;
}

.invalid {

    background: rgba(249,115,22,0.15);

    color: #fb923c;
}

.score-box {

    text-align: center;

    margin: 20px 0 30px;
}

.score {

    font-size: 55px;

    font-weight: bold;

    color: #38bdf8;
}

.score-label {

    color: #94a3b8;
}

.risk-meter {
    margin-top: 18px;
    text-align: left;
}

.risk-meter-bar {
    position: relative;
    height: 14px;
    border-radius: 999px;
    background: linear-gradient(to right, #22c55e 0%, #22c55e 19%, #facc15 19%, #facc15 39%, #ef4444 39%, #ef4444 100%);
    overflow: hidden;
    border: 1px solid rgba(255,255,255,0.08);
}

.risk-meter-fill {
    position: absolute;
    top: 0;
    left: 0;
    height: 100%;
    width: 0;
    background: rgba(2,6,23,0.78);
    transition: width 0.3s ease;
    border-right: 2px solid white;
}

.risk-meter-scale {
    display: flex;
    justify-content: space-between;
    gap: 8px;
    margin-top: 8px;
    color: #64748b;
    font-size: 11px;
}

.details {

    background: #020617;

    border-radius: 12px;

    padding: 20px;
}

.details h3 {

    margin-bottom: 15px;
}

.details li {

    list-style: none;

    padding: 10px 0;

    color: #cbd5e1;

    border-bottom: 1px solid rgba(255,255,255,0.06);
}

.result-grid {
    display: grid;
    grid-template-columns: minmax(0, 1.45fr) minmax(280px, 0.75fr);
    gap: 20px;
    align-items: start;
}

.score-breakdown {
    background: linear-gradient(145deg, rgba(15,23,42,0.98), rgba(2,6,23,0.98));
    border: 1px solid rgba(56,189,248,0.18);
    border-radius: 14px;
    padding: 18px;
    box-shadow: 0 12px 30px rgba(0,0,0,0.2);
}

.breakdown-title {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 10px;
    margin-bottom: 16px;
}

.breakdown-title h3 { font-size: 18px; }
.breakdown-total { color: #38bdf8; font-weight: bold; font-size: 14px; }

.breakdown-item {
    padding: 12px 0;
    border-bottom: 1px solid rgba(255,255,255,0.06);
}

.breakdown-item:last-child { border-bottom: none; }

.breakdown-row {
    display: flex;
    justify-content: space-between;
    gap: 12px;
    align-items: center;
}

.breakdown-name { color: #e2e8f0; font-weight: 600; font-size: 14px; }
.breakdown-points { color: #fbbf24; font-weight: bold; white-space: nowrap; }
.breakdown-description { margin-top: 5px; color: #94a3b8; font-size: 12px; line-height: 1.5; }
.breakdown-empty { color: #94a3b8; line-height: 1.6; font-size: 14px; }
.breakdown-note {
    margin-top: 14px;
    padding-top: 12px;
    border-top: 1px solid rgba(255,255,255,0.07);
    color: #64748b;
    font-size: 11px;
    line-height: 1.5;
}

.report-btn {

    margin-top: 20px;

    display: inline-block;

    padding: 11px 18px;

    border-radius: 8px;

    text-decoration: none;

    background: #dc2626;

    color: white;

    font-weight: bold;
}

.features {

    max-width: 1000px;

    margin: 60px auto;

    padding: 0 20px;

    display: grid;

    grid-template-columns: repeat(3, 1fr);

    gap: 20px;
}

.feature {

    background: rgba(15,23,42,0.75);

    padding: 25px;

    border-radius: 15px;

    border: 1px solid rgba(255,255,255,0.08);
}

.feature h3 {

    margin-bottom: 10px;

    color: #38bdf8;
}

.feature p {

    color: #94a3b8;

    line-height: 1.6;
}

footer {

    text-align: center;

    color: #64748b;

    padding: 30px;
}

@media(max-width:700px) {

    .hero h1 {

        font-size: 36px;
    }

    .scanner form {

        flex-direction: column;
    }

    .features {

        grid-template-columns: 1fr;
    }

    .result-header {

        flex-direction: column;

        align-items: flex-start;
    }
}


.clear-btn {
    background: #7f1d1d;
    color: white;
    border: 1px solid #ef4444;
    padding: 10px 16px;
    border-radius: 8px;
    cursor: pointer;
    font-weight: 600;
}

.clear-btn:hover {
    background: #991b1b;
}

.admin-search {
    display: flex;
    gap: 10px;
    align-items: flex-end;
    flex-wrap: wrap;
    margin: 14px 0 16px;
    padding: 14px;
    background: rgba(2,6,23,0.65);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 12px;
}

.search-field {
    display: flex;
    flex-direction: column;
    gap: 6px;
}

.search-field.search-text {
    flex: 1 1 320px;
    min-width: 260px;
}

.search-field.search-date {
    flex: 0 1 165px;
}

.search-field input[type="date"] {
    color-scheme: dark;
}

.search-field label {
    font-size: 12px;
    font-weight: 700;
    color: #cbd5e1;
}

.admin-search input {
    width: 100%;
    padding: 11px 13px;
    border-radius: 8px;
    border: 1px solid #334155;
    background: #020617;
    color: white;
    outline: none;
    font-size: 14px;
}

.admin-search input:focus {
    border-color: #38bdf8;
    box-shadow: 0 0 0 2px rgba(56,189,248,0.10);
}

.admin-search button {
    padding: 11px 17px;
    border: none;
    border-radius: 8px;
    background: #0284c7;
    color: white;
    font-weight: bold;
    cursor: pointer;
    white-space: nowrap;
}

.admin-search .search-clear {
    color: #cbd5e1;
    text-decoration: none;
    padding: 10px 4px;
    white-space: nowrap;
}

.date-hint {
    font-size: 11px;
    color: #64748b;
    padding-bottom: 10px;
    white-space: nowrap;
}
</style>

</head>

<body>

<div class="navbar">

    <div class="logo">🛡️ PhishGuard</div>

    <div class="nav-links">

        <span style="color:#94a3b8; padding:9px 5px;">Hi, {{ session.get("user_name") }}</span>

        <a href="/dashboard">📊 Dashboard</a>

        <a href="/history">📋 My History</a>

        <a href="/admin/login">🔐 Admin</a>

        <a href="/logout">Logout</a>

    </div>

</div>


<div class="hero">

    <div class="badge">

        🔎 Explainable URL Security Analysis

    </div>

    <h1>

        Detect

        <span>Phishing Websites</span>

        Before You Trust Them

    </h1>

    <p>

        Analyze suspicious URLs using rule-based security checks

        and understand why a URL may be considered risky.

    </p>

</div>


<div class="scanner">

    <form method="POST">

        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

        <input

            type="text"

            name="url"

            placeholder="Enter a website URL..."

            value=""

            required

        >

        <button type="submit">

            🔍 Analyze URL

        </button>

    </form>

</div>


{% if result %}

<div class="result">

    <div class="result-header">

        <div>

            <h2>Analysis Result</h2>

            <div class="result-url">

                {{ url }}

            </div>

        </div>

        <div class="risk

        {% if result.risk == 'Low Risk' %}

            low

        {% elif result.risk == 'Suspicious' %}

            suspicious

        {% elif result.risk == 'Invalid URL' %}

            invalid

        {% else %}

            high

        {% endif %}

        ">

            {% if result.risk == 'Low Risk' %}

                🟢

            {% elif result.risk == 'Suspicious' %}

                🟡

            {% elif result.risk == 'Invalid URL' %}

                ⚠️

            {% else %}

                🔴

            {% endif %}

            {{ result.risk }}

        </div>

    </div>


    <div class="result-grid">

        <div>

            <div class="score-box">

                <div class="score">
                    {{ result.score }}/100
                </div>

                <div class="score-label">Risk Score</div>

                <div class="risk-meter" aria-label="Risk score meter">
                    <div class="risk-meter-bar">
                        <div class="risk-meter-fill" style="width: {{ result.score }}%;"></div>
                    </div>
                    <div class="risk-meter-scale">
                        <span>0</span>
                        <span>19 Low</span>
                        <span>39 Suspicious</span>
                        <span>100 High</span>
                    </div>
                </div>

            </div>

            <div class="details">
                <h3>Detection Details</h3>
                <ul>
                {% for reason in result.reasons %}
                    <li>✓ {{ reason }}</li>
                {% endfor %}
                </ul>
            </div>

        </div>

        <div class="score-breakdown">
            <div class="breakdown-title">
                <h3>📊 Score Breakdown</h3>
                <span class="breakdown-total">{{ result.score }}/100</span>
            </div>

            {% if result.breakdown %}
                {% for item in result.breakdown %}
                    <div class="breakdown-item">
                        <div class="breakdown-row">
                            <span class="breakdown-name">{{ item.name }}</span>
                            <span class="breakdown-points">+{{ item.points }}</span>
                        </div>
                        <div class="breakdown-description">{{ item.description }}</div>
                    </div>
                {% endfor %}
            {% else %}
                <div class="breakdown-empty">
                    ✅ No risk indicators were triggered by the current rule checks.
                </div>
            {% endif %}

            <div class="breakdown-note">
                The score is generated by PhishGuard's rule-based URL checks.
            </div>
        </div>

    </div>


    {% if result.risk not in ['Low Risk', 'Invalid URL'] %}

        <a

            class="report-btn"

            href="/report?url={{ url | urlencode }}"

        >

            🚨 Report Suspicious URL

        </a>

    {% endif %}

</div>

{% endif %}


<div class="features">

    <div class="feature">

        <h3>🔍 URL Analysis</h3>

        <p>

            Checks URL structure, HTTPS usage,

            suspicious keywords, IP addresses,

            ports and other indicators.

        </p>

    </div>

    <div class="feature">

        <h3>📊 Risk Classification</h3>

        <p>

            Produces an explainable risk score

            and classifies the URL as Low Risk,

            Suspicious or High Risk.

        </p>

    </div>

    <div class="feature">

        <h3>🚨 User Reporting</h3>

        <p>

            Users can report suspicious URLs

            and administrators can monitor

            submitted reports.

        </p>

    </div>

</div>


<footer>

    PhishGuard • Intelligent Phishing Website Detection & Reporting System

</footer>

</body>

</html>
""", result=result, url=url)


# ============================================================
# HISTORY PAGE
# ============================================================

@app.route("/admin/clear-history", methods=["POST"])
def clear_history():

    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("DELETE FROM analysis_history")

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(url_for("history"))


@app.route("/history/export")
def export_user_history():

    if not session.get("user_logged_in"):
        return redirect(url_for("user_login"))

    search = request.args.get("search", "").strip()
    risk_filter = request.args.get("risk", "").strip()

    connection = get_connection()
    cursor = connection.cursor()

    query = """
        SELECT id, url, score, risk, reasons, analyzed_at
        FROM analysis_history
        WHERE user_id = %s
    """

    params = [session.get("user_id")]

    if search:
        query += " AND url LIKE %s"
        params.append(f"%{search}%")

    if risk_filter in ["Low Risk", "Suspicious", "High Risk"]:
        query += " AND risk = %s"
        params.append(risk_filter)

    query += " ORDER BY analyzed_at DESC"

    cursor.execute(query, tuple(params))
    records = cursor.fetchall()

    cursor.close()
    connection.close()

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "URL", "Score", "Risk", "Reasons", "Analyzed At"])

    for record in records:
        writer.writerow(list(record))

    response = Response(output.getvalue(), mimetype="text/csv; charset=utf-8")
    response.headers["Content-Disposition"] = "attachment; filename=phishguard_my_history.csv"
    return response


@app.route("/history")
def history():

    if not session.get("user_logged_in"):
        return redirect(url_for("user_login"))

    search = request.args.get("search", "").strip()
    risk_filter = request.args.get("risk", "").strip()

    connection = get_connection()
    cursor = connection.cursor()

    query = """
        SELECT id, url, score, risk, reasons, analyzed_at
        FROM analysis_history
        WHERE user_id = %s
    """

    params = [session.get("user_id")]

    if search:
        query += " AND url LIKE %s"
        params.append(f"%{search}%")

    if risk_filter in ["Low Risk", "Suspicious", "High Risk"]:
        query += " AND risk = %s"
        params.append(risk_filter)

    query += " ORDER BY analyzed_at DESC"

    cursor.execute(query, tuple(params))
    records = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template_string("""
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>Analysis History - PhishGuard</title>

<style>

body {

    font-family: Arial, sans-serif;

    background: #020617;

    color: white;

    margin: 0;

    padding: 40px;
}

.container {

    max-width: 1200px;

    margin: auto;
}

.top {

    display: flex;

    justify-content: space-between;

    align-items: center;

    margin-bottom: 25px;
}

a {

    color: #38bdf8;

    text-decoration: none;
}

.filters {

    background: #0f172a;

    padding: 18px;

    border-radius: 12px;

    margin-bottom: 22px;

    display: flex;

    gap: 10px;

    align-items: center;

    flex-wrap: wrap;
}

.filters input,
.filters select {

    background: #020617;

    color: white;

    border: 1px solid #334155;

    padding: 10px 12px;

    border-radius: 8px;

    font-size: 14px;
}

.filters input {

    min-width: 280px;
}

.filter-button {

    background: #0284c7;

    color: white;

    border: none;

    padding: 10px 16px;

    border-radius: 8px;

    cursor: pointer;

    font-weight: bold;
}

.clear-filter {

    color: #94a3b8;

    padding: 10px;
}

table {

    width: 100%;

    border-collapse: collapse;

    background: #0f172a;

    border-radius: 12px;

    overflow: hidden;
}

th, td {

    padding: 15px;

    text-align: left;

    border-bottom: 1px solid #1e293b;
}

th {

    background: #111827;

    color: #38bdf8;
}

td {

    color: #cbd5e1;

    word-break: break-word;
}

.low {

    color: #4ade80;

    font-weight: bold;
}

.suspicious {

    color: #facc15;

    font-weight: bold;
}

.high {

    color: #f87171;

    font-weight: bold;
}

.no-results {

    background: #0f172a;

    padding: 35px;

    border-radius: 14px;

    text-align: center;

    color: #94a3b8;
}

</style>

</head>

<body>

<div class="container">

<div class="top">

    <h1>📋 My Analysis History</h1>

    <div>

        <a href="/">← Back to Scanner</a>

        <a href="/dashboard" style="margin-left:15px;">📊 Dashboard</a>

        <a href="/admin/login" style="margin-left:15px;">🔐 Admin</a>


    </div>

</div>

<form method="GET" action="{{ url_for('history') }}" class="filters">

    <input
        type="text"
        name="search"
        placeholder="🔎 Search URL..."
        value="{{ search }}"
    >

    <select name="risk" onchange="this.form.submit()">

        <option value="" {% if not risk_filter %}selected{% endif %}>All Risk Levels</option>

        <option value="Low Risk" {% if risk_filter == 'Low Risk' %}selected{% endif %}>🟢 Low Risk</option>

        <option value="Suspicious" {% if risk_filter == 'Suspicious' %}selected{% endif %}>🟡 Suspicious</option>

        <option value="High Risk" {% if risk_filter == 'High Risk' %}selected{% endif %}>🔴 High Risk</option>

    </select>

    <button type="submit" class="filter-button">🔍 Search</button>

    <a href="{{ url_for('export_user_history', search=search, risk=risk_filter) }}" class="export-button">⬇️ Export CSV</a>

    {% if search or risk_filter %}

    <a href="{{ url_for('history') }}" class="clear-filter">✕ Clear Filters</a>

    {% endif %}

</form>

{% if records %}

<p style="color:#94a3b8;">Showing {{ records|length }} matching record(s).</p>

<table>

<tr>

    <th>ID</th>

    <th>URL</th>

    <th>Score</th>

    <th>Risk</th>

    <th>Analyzed At</th>
    <th>Details</th>

</tr>

{% for record in records %}

<tr>

    <td>{{ record[0] }}</td>

    <td>{{ record[1] }}</td>

    <td>{{ record[2] }}/100</td>

    <td class="

    {% if record[3] == 'Low Risk' %}

        low

    {% elif record[3] == 'Suspicious' %}

        suspicious

    {% else %}

        high

    {% endif %}

    ">

        {{ record[3] }}

    </td>

    <td>{{ record[5]|pretty_datetime }}</td>
    <td><a href="{{ url_for('analysis_details', analysis_id=record[0]) }}">View Details</a></td>

</tr>

{% endfor %}

</table>

{% else %}

<div class="no-results">

    <div style="font-size:32px;">🔎</div>

    {% if search or risk_filter %}

    <h2 style="color:white;">No Matching Results</h2>

    <p>No analysis records match the selected search or risk filter.</p>

    <a href="{{ url_for('history') }}">Clear Filters</a>

    {% else %}

    <h2 style="color:white;">No Analysis History</h2>

    <p>There are currently no analyzed URLs in the history.</p>

    {% endif %}

</div>

{% endif %}

</div>

</body>

</html>
""", records=records, search=search, risk_filter=risk_filter)


# ============================================================
# REPORT SUSPICIOUS URL
# ============================================================

@app.route("/report")
def report():

    if not session.get("user_logged_in"):
        return redirect(url_for("user_login"))

    url = request.args.get("url", "").strip()

    if not url:

        return redirect(url_for("home"))

    connection = get_connection()
    cursor = connection.cursor()

    # Prevent the same user from submitting duplicate reports for the exact same URL.
    cursor.execute("""
        SELECT id, status
        FROM reports
        WHERE user_id = %s AND url = %s
        ORDER BY reported_at DESC, id DESC
        LIMIT 1
    """, (session.get("user_id"), url))

    existing_report = cursor.fetchone()

    if existing_report:
        report_id, report_status = existing_report
        cursor.close()
        connection.close()

        return render_template_string("""
<!DOCTYPE html>
<html>
<head>
<title>Already Reported - PhishGuard</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body { background:#020617; color:white; font-family:Arial; text-align:center; padding:100px 20px; }
.box { max-width:620px; margin:auto; background:#0f172a; padding:40px; border-radius:18px; border:1px solid #1e293b; }
h1 { color:#facc15; }
p { color:#cbd5e1; line-height:1.6; }
.status { display:inline-block; margin:12px 0; padding:10px 15px; border-radius:10px; background:#1e293b; color:#e2e8f0; font-weight:bold; }
a { display:inline-block; margin:10px 6px 0; color:#38bdf8; text-decoration:none; padding:10px 16px; border:1px solid #334155; border-radius:9px; }
</style>
</head>
<body>
<div class="box">
    <div style="font-size:46px;">ℹ️</div>
    <h1>Already Reported</h1>
    <p>You have already reported this URL. A duplicate report was not created.</p>
    <div class="status">Current Status: {{ report_status }}</div>
    <div>
        <a href="{{ url_for('my_reports') }}">🚨 View My Reports</a>
        <a href="{{ url_for('home') }}">← Back to Scanner</a>
    </div>
</div>
</body>
</html>
""", report_status=report_status)

    query = """
        INSERT INTO reports (user_id, url, reason)
        VALUES (%s, %s, %s)
    """

    cursor.execute(
        query,
        (
            session.get("user_id"),
            url,
            "User reported this URL as suspicious."
        )
    )

    connection.commit()

    cursor.close()
    connection.close()

    return render_template_string("""
<!DOCTYPE html>

<html>

<head>

<title>Report Submitted</title>

<style>

body {

    background: #020617;

    color: white;

    font-family: Arial;

    text-align: center;

    padding: 100px 20px;
}

.box {

    max-width: 600px;

    margin: auto;

    background: #0f172a;

    padding: 40px;

    border-radius: 18px;
}

h1 {

    color: #4ade80;
}

a {

    display: inline-block;

    margin-top: 20px;

    color: #38bdf8;

    text-decoration: none;
}

</style>

</head>

<body>

<div class="box">

    <h1>✅ Report Submitted</h1>

    <p>

        Thank you. The suspicious URL has been

        submitted for administrator review.

    </p>

    <a href="/">← Back to Scanner</a>

</div>

</body>

</html>
""")


# ============================================================
# USER REPORT HISTORY
# ============================================================

@app.route("/my-reports")
def my_reports():

    if not session.get("user_logged_in"):
        return redirect(url_for("user_login"))

    search = request.args.get("search", "").strip()
    status_filter = request.args.get("status", "").strip()

    connection = get_connection()
    cursor = connection.cursor()

    query = """
        SELECT id, url, reason, reported_at,
               COALESCE(status, 'Pending') AS status,
               reviewed_at
        FROM reports
        WHERE user_id = %s
    """

    params = [session.get("user_id")]

    if search:
        query += " AND (url LIKE %s OR reason LIKE %s)"
        search_value = f"%{search}%"
        params.extend([search_value, search_value])

    if status_filter in VALID_REPORT_STATUSES:
        query += " AND COALESCE(status, 'Pending') = %s"
        params.append(status_filter)

    query += " ORDER BY reported_at DESC"

    cursor.execute(query, tuple(params))
    records = cursor.fetchall()

    cursor.close()
    connection.close()

    status_counts = {
        "Pending": 0,
        "Reviewed": 0,
        "Confirmed Phishing": 0,
        "Rejected": 0
    }
    for record in records:
        status = record[4] if record[4] in status_counts else "Pending"
        status_counts[status] += 1

    return render_template_string(r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>My Reports - PhishGuard</title>
<style>
*{box-sizing:border-box;}
body{margin:0;min-height:100vh;font-family:Arial,sans-serif;background:radial-gradient(circle at top left,#172554,transparent 35%),radial-gradient(circle at bottom right,#312e81,transparent 35%),#020617;color:white;}
.navbar{width:100%;padding:20px 7%;display:flex;justify-content:space-between;align-items:center;gap:20px;border-bottom:1px solid rgba(255,255,255,.08);}
.logo{font-size:24px;font-weight:bold;color:#38bdf8;}
.nav-links{display:flex;gap:10px;align-items:center;flex-wrap:wrap;justify-content:flex-end;}
.nav-links a{color:#cbd5e1;text-decoration:none;padding:9px 14px;border-radius:8px;background:rgba(255,255,255,.05);}
.nav-links a:hover{background:rgba(56,189,248,.12);color:#38bdf8;}
.container{max-width:1150px;margin:40px auto;padding:0 20px 50px;}
.header{display:flex;justify-content:space-between;align-items:center;gap:15px;flex-wrap:wrap;margin-bottom:20px;}
.header h1{margin:0;}
.header p{margin:6px 0 0;color:#94a3b8;}
.card{background:#0f172a;border:1px solid #1e293b;border-radius:16px;padding:22px;margin-bottom:20px;}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px;}
.stat{background:#020617;border:1px solid #1e293b;border-radius:12px;padding:18px;}
.stat-label{color:#94a3b8;font-size:13px;margin-bottom:7px;}
.stat-number{font-size:28px;font-weight:bold;}
.pending{color:#fbbf24;}.reviewed{color:#38bdf8;}.confirmed{color:#f87171;}.rejected{color:#4ade80;}
.filters{display:grid;grid-template-columns:1.7fr 1.2fr auto auto;gap:10px;align-items:end;}
.field{display:flex;flex-direction:column;gap:6px;}
.field label{font-size:12px;color:#94a3b8;}
input,select{width:100%;padding:11px 12px;border-radius:9px;border:1px solid #334155;background:#020617;color:#e2e8f0;}
button,.button{border:none;cursor:pointer;text-decoration:none;padding:11px 14px;border-radius:9px;background:#0ea5e9;color:white;font-weight:bold;text-align:center;}
.clear{background:#334155;}
.table-wrap{overflow-x:auto;}
table{width:100%;border-collapse:collapse;min-width:850px;}
th,td{padding:13px;text-align:left;border-bottom:1px solid #1e293b;vertical-align:top;}
th{color:#38bdf8;background:#111827;}
td{color:#cbd5e1;}
.url{max-width:360px;word-break:break-word;}
.reason{max-width:260px;word-break:break-word;color:#94a3b8;}
.status-badge{display:inline-block;padding:7px 10px;border-radius:999px;font-size:13px;font-weight:bold;white-space:nowrap;}
.status-pending{color:#fbbf24;background:rgba(251,191,36,.1);}
.status-reviewed{color:#38bdf8;background:rgba(56,189,248,.1);}
.status-confirmed{color:#f87171;background:rgba(248,113,113,.1);}
.status-rejected{color:#4ade80;background:rgba(74,222,128,.1);}
.empty{text-align:center;padding:35px;color:#94a3b8;}
.note{margin-top:14px;color:#64748b;font-size:12px;line-height:1.5;}
@media(max-width:850px){.stats{grid-template-columns:repeat(2,1fr);}.filters{grid-template-columns:1fr 1fr;}.navbar{padding:18px 5%;align-items:flex-start;}.nav-links{justify-content:flex-start;}}
@media(max-width:600px){.stats{grid-template-columns:1fr;}.filters{grid-template-columns:1fr;}.container{margin-top:25px;}}
</style>
</head>
<body>
<div class="navbar">
    <div class="logo">🛡️ PhishGuard</div>
    <div class="nav-links">
        <a href="/">🔎 Scanner</a>
        <a href="/dashboard">📊 Dashboard</a>
        <a href="/history">📋 My History</a>
        <a href="/my-reports">🚨 My Reports</a>
        <a href="/admin/login">🔐 Admin</a>
        <a href="/logout">Logout</a>
    </div>
</div>
<div class="container">
    <div class="header">
        <div>
            <h1>🚨 My Reports</h1>
            <p>Track the suspicious URLs you submitted and see their current review status.</p>
        </div>
    </div>

    <div class="stats">
        <div class="stat"><div class="stat-label">🕒 Pending</div><div class="stat-number pending">{{ status_counts['Pending'] }}</div></div>
        <div class="stat"><div class="stat-label">👁️ Reviewed</div><div class="stat-number reviewed">{{ status_counts['Reviewed'] }}</div></div>
        <div class="stat"><div class="stat-label">🚨 Confirmed Phishing</div><div class="stat-number confirmed">{{ status_counts['Confirmed Phishing'] }}</div></div>
        <div class="stat"><div class="stat-label">❌ Rejected</div><div class="stat-number rejected">{{ status_counts['Rejected'] }}</div></div>
    </div>

    <div class="card">
        <form method="GET" action="{{ url_for('my_reports') }}" class="filters">
            <div class="field">
                <label for="search">Search</label>
                <input id="search" type="text" name="search" placeholder="🔎 Search URL or reason..." value="{{ search }}">
            </div>
            <div class="field">
                <label for="status">Status</label>
                <select id="status" name="status" onchange="this.form.submit()">
                    <option value="" {% if not status_filter %}selected{% endif %}>All Statuses</option>
                    <option value="Pending" {% if status_filter == 'Pending' %}selected{% endif %}>🕒 Pending</option>
                    <option value="Reviewed" {% if status_filter == 'Reviewed' %}selected{% endif %}>👁️ Reviewed</option>
                    <option value="Confirmed Phishing" {% if status_filter == 'Confirmed Phishing' %}selected{% endif %}>🚨 Confirmed Phishing</option>
                    <option value="Rejected" {% if status_filter == 'Rejected' %}selected{% endif %}>❌ Rejected</option>
                </select>
            </div>
            <button type="submit">🔍 Search</button>
            {% if search or status_filter %}<a class="button clear" href="{{ url_for('my_reports') }}">✕ Clear</a>{% endif %}
        </form>
        <div class="note">Status is controlled by the administrator after reviewing your submitted report.</div>
    </div>

    <div class="card">
        {% if records %}
        <div class="table-wrap">
        <table>
            <tr><th>ID</th><th>URL</th><th>Reason</th><th>Reported At</th><th>Status</th><th>Reviewed At</th></tr>
            {% for record in records %}
            {% set status = record[4] %}
            <tr>
                <td>#{{ record[0] }}</td>
                <td class="url" title="{{ record[1] }}">{{ record[1]|shorten_url }}</td>
                <td class="reason">{{ record[2] or '—' }}</td>
                <td>{{ record[3]|pretty_datetime }}</td>
                <td>
                    <span class="status-badge {% if status == 'Pending' %}status-pending{% elif status == 'Reviewed' %}status-reviewed{% elif status == 'Confirmed Phishing' %}status-confirmed{% else %}status-rejected{% endif %}">
                        {% if status == 'Pending' %}🕒{% elif status == 'Reviewed' %}👁️{% elif status == 'Confirmed Phishing' %}🚨{% else %}❌{% endif %} {{ status }}
                    </span>
                </td>
                <td>{{ record[5]|pretty_datetime if record[5] else '—' }}</td>
            </tr>
            {% endfor %}
        </table>
        </div>
        {% else %}
        <div class="empty">📭 No reports found for the selected filters.</div>
        {% endif %}
    </div>
</div>
</body>
</html>
""", records=records, search=search, status_filter=status_filter, status_counts=status_counts)


# ============================================================
# ADMIN LOGIN
# ============================================================

@app.route("/admin/clear-recent-analysis", methods=["POST"])
def clear_recent_analysis():

    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        DELETE FROM analysis_history
        WHERE id IN (
            SELECT id FROM (
                SELECT id
                FROM analysis_history
                ORDER BY analyzed_at DESC
                LIMIT 8
            ) AS recent_ids
        )
    """)

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():

    error = None

    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_SECONDS = 300

    failed_attempts = session.get("login_failed_attempts", 0)
    lockout_until = session.get("login_lockout_until", 0)

    if lockout_until and time.time() < lockout_until:

        remaining_seconds = int(lockout_until - time.time())
        remaining_minutes = max(1, (remaining_seconds + 59) // 60)
        error = (
            f"Too many failed login attempts. "
            f"Please try again in about {remaining_minutes} minute(s)."
        )

    elif lockout_until:

        session.pop("login_lockout_until", None)
        session["login_failed_attempts"] = 0
        failed_attempts = 0

    if request.method == "POST" and error is None:

        username = request.form.get("username", "").strip()

        password = request.form.get("password", "")

        connection = get_connection()
        cursor = connection.cursor()

        query = """
            SELECT id, password
            FROM admin_users
            WHERE username = %s
        """

        cursor.execute(
            query,
            (username,)
        )

        admin = cursor.fetchone()

        cursor.close()
        connection.close()

        if admin and check_password_hash(admin[1], password):

            session.clear()
            session["admin_logged_in"] = True
            session["admin_id"] = admin[0]
            session["admin_last_activity"] = time.time()

            return redirect(
                url_for("admin_dashboard")
            )

        failed_attempts = session.get("login_failed_attempts", 0) + 1
        session["login_failed_attempts"] = failed_attempts

        if failed_attempts >= MAX_FAILED_ATTEMPTS:

            session["login_lockout_until"] = time.time() + LOCKOUT_SECONDS
            error = (
                "Too many failed login attempts. "
                "Login is temporarily locked for 5 minutes."
            )

        else:

            attempts_left = MAX_FAILED_ATTEMPTS - failed_attempts
            error = (
                "Invalid username or password. "
                f"{attempts_left} attempt(s) remaining."
            )

    return render_template_string("""
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>Admin Login - PhishGuard</title>

<style>

body {

    margin: 0;

    min-height: 100vh;

    display: flex;

    justify-content: center;

    align-items: center;

    background: #020617;

    color: white;

    font-family: Arial, sans-serif;
}

.login-box {

    width: 380px;

    background: #0f172a;

    padding: 35px;

    border-radius: 18px;

    border: 1px solid #1e293b;

    box-shadow: 0 20px 50px rgba(0,0,0,0.4);
}

h1 {

    text-align: center;

    margin-bottom: 10px;
}

.subtitle {

    text-align: center;

    color: #94a3b8;

    margin-bottom: 30px;
}

input {

    width: 100%;

    padding: 14px;

    margin-bottom: 15px;

    border-radius: 8px;

    border: 1px solid #334155;

    background: #020617;

    color: white;

    box-sizing: border-box;
}

button {

    width: 100%;

    padding: 14px;

    border: none;

    border-radius: 8px;

    background: #0284c7;

    color: white;

    font-weight: bold;

    cursor: pointer;
}

.error {

    background: rgba(239,68,68,0.1);

    color: #f87171;

    padding: 10px;

    border-radius: 8px;

    margin-bottom: 15px;

    text-align: center;
}

.back {

    display: block;

    text-align: center;

    margin-top: 20px;

    color: #38bdf8;

    text-decoration: none;
}

</style>

</head>

<body>

<div class="login-box">

    <h1>🔐 Admin Login</h1>

    <div class="subtitle">

        PhishGuard Administration

    </div>

    {% if error %}

        <div class="error">

            {{ error }}

        </div>

    {% endif %}

    <form method="POST">

        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

        <input

            type="text"

            name="username"

            placeholder="Username"

            required

        >

        <input

            type="password"

            name="password"

            placeholder="Password"

            required

        >

        <button type="submit">

            Login

        </button>

    </form>

    <a class="back" href="/">

        ← Back to Scanner

    </a>

</div>

</body>

</html>
""")


# ============================================================
# ADMIN ANALYSIS HISTORY
# ============================================================

@app.route("/admin/history/export")
def export_admin_history():

    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    search = request.args.get("search", "").strip()
    risk_filter = request.args.get("risk", "").strip()

    connection = get_connection()
    cursor = connection.cursor()

    query = """
        SELECT h.id,
               COALESCE(u.name, 'Previous / Unknown User'),
               COALESCE(u.email, '-'),
               h.url, h.score, h.risk, h.reasons, h.analyzed_at
        FROM analysis_history h
        LEFT JOIN users u ON h.user_id = u.id
        WHERE 1 = 1
    """

    params = []

    if search:
        query += " AND (h.url LIKE %s OR u.name LIKE %s OR u.email LIKE %s)"
        search_value = f"%{search}%"
        params.extend([search_value, search_value, search_value])

    if risk_filter in ["Low Risk", "Suspicious", "High Risk"]:
        query += " AND h.risk = %s"
        params.append(risk_filter)

    query += " ORDER BY h.analyzed_at DESC"

    cursor.execute(query, tuple(params))
    records = cursor.fetchall()

    cursor.close()
    connection.close()

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "User", "Email", "URL", "Score", "Risk", "Reasons", "Analyzed At"])

    for record in records:
        writer.writerow(list(record))

    response = Response(output.getvalue(), mimetype="text/csv; charset=utf-8")
    response.headers["Content-Disposition"] = "attachment; filename=phishguard_all_analysis_history.csv"
    return response


@app.route("/admin/history")
def admin_history():

    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    search = request.args.get("search", "").strip()
    risk_filter = request.args.get("risk", "").strip()

    connection = get_connection()
    cursor = connection.cursor()

    query = """
        SELECT h.id, h.url, h.score, h.risk, h.analyzed_at,
               COALESCE(u.name, 'Previous / Unknown User') AS user_name,
               COALESCE(u.email, '-') AS user_email
        FROM analysis_history h
        LEFT JOIN users u ON h.user_id = u.id
        WHERE 1 = 1
    """

    params = []

    if search:
        query += " AND (h.url LIKE %s OR u.name LIKE %s OR u.email LIKE %s)"
        search_value = f"%{search}%"
        params.extend([search_value, search_value, search_value])

    if risk_filter in ["Low Risk", "Suspicious", "High Risk"]:
        query += " AND h.risk = %s"
        params.append(risk_filter)

    query += " ORDER BY h.analyzed_at DESC"

    cursor.execute(query, tuple(params))
    records = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template_string("""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>All Analysis History - PhishGuard</title>
<style>
body{font-family:Arial,sans-serif;background:#020617;color:white;margin:0;padding:40px;}
.container{max-width:1300px;margin:auto;}
.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:25px;gap:20px;flex-wrap:wrap;}
a{color:#38bdf8;text-decoration:none;}
.filters{background:#0f172a;padding:18px;border-radius:12px;margin-bottom:22px;display:flex;gap:10px;align-items:center;flex-wrap:wrap;}
.filters input,.filters select{background:#020617;color:white;border:1px solid #334155;padding:10px 12px;border-radius:8px;font-size:14px;}
.filters input{min-width:300px;}
.filter-button{background:#0284c7;color:white;border:none;padding:10px 16px;border-radius:8px;cursor:pointer;font-weight:bold;}
.clear-filter{color:#94a3b8;padding:10px;}
table{width:100%;border-collapse:collapse;background:#0f172a;border-radius:12px;overflow:hidden;}
th,td{padding:14px;text-align:left;border-bottom:1px solid #1e293b;}
th{background:#111827;color:#38bdf8;}
td{color:#cbd5e1;word-break:break-word;}
.low{color:#4ade80;font-weight:bold;}.suspicious{color:#facc15;font-weight:bold;}.high{color:#f87171;font-weight:bold;}
.no-results{background:#0f172a;padding:35px;border-radius:14px;text-align:center;color:#94a3b8;}
</style>
</head>
<body>
<div class="container">
<div class="top">
    <h1>📋 All User Analysis History</h1>
    <div><a href="{{ url_for('admin_dashboard') }}">← Back to Dashboard</a></div>
</div>
<form method="GET" action="{{ url_for('admin_history') }}" class="filters">
    <input type="text" name="search" placeholder="🔎 Search URL, name or email..." value="{{ search }}">
    <select name="risk" onchange="this.form.submit()">
        <option value="" {% if not risk_filter %}selected{% endif %}>All Risk Levels</option>
        <option value="Low Risk" {% if risk_filter == 'Low Risk' %}selected{% endif %}>🟢 Low Risk</option>
        <option value="Suspicious" {% if risk_filter == 'Suspicious' %}selected{% endif %}>🟡 Suspicious</option>
        <option value="High Risk" {% if risk_filter == 'High Risk' %}selected{% endif %}>🔴 High Risk</option>
    </select>
    <button type="submit" class="filter-button">🔍 Search</button>
    <a href="{{ url_for('export_admin_history', search=search, risk=risk_filter) }}" class="filter-button" style="background:#16a34a; text-decoration:none;">⬇️ Export CSV</a>
    {% if search or risk_filter %}<a href="{{ url_for('admin_history') }}" class="clear-filter">✕ Clear Filters</a>{% endif %}
</form>
{% if records %}
<p style="color:#94a3b8;">Showing {{ records|length }} matching record(s).</p>
<table>
<tr><th>ID</th><th>User</th><th>Email</th><th>URL</th><th>Score</th><th>Risk</th><th>Analyzed At</th><th>Details</th></tr>
{% for record in records %}
<tr>
<td>{{ record[0] }}</td><td>{{ record[5] }}</td><td>{{ record[6] }}</td><td>{{ record[1] }}</td><td>{{ record[2] }}/100</td>
<td class="{% if record[3] == 'Low Risk' %}low{% elif record[3] == 'Suspicious' %}suspicious{% else %}high{% endif %}">
{{ record[3] }}</td><td>{{ record[4]|pretty_datetime }}</td><td><a href="{{ url_for('analysis_details', analysis_id=record[0]) }}">View Details</a></td>
</tr>
{% endfor %}
</table>
{% else %}
<div class="no-results"><div style="font-size:32px;">🔎</div><h2 style="color:white;">No Matching Results</h2><p>No analysis records match the selected search or risk filter.</p><a href="{{ url_for('admin_history') }}">Clear Filters</a></div>
{% endif %}
</div>
</body>
</html>
""", records=records, search=search, risk_filter=risk_filter)


# ============================================================
# ADMIN DASHBOARD
# ============================================================

@app.route("/admin/export-analysis")
def export_admin_dashboard_analysis():

    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    recent_search = request.args.get("recent_search", "").strip()
    recent_from = request.args.get("recent_from", "").strip()
    recent_to = request.args.get("recent_to", "").strip()

    connection = get_connection()
    cursor = connection.cursor()

    query = """
        SELECT h.id,
               COALESCE(u.name, 'Previous / Unknown User'),
               COALESCE(u.email, '-'),
               h.url, h.score, h.risk, h.analyzed_at
        FROM analysis_history h
        LEFT JOIN users u ON h.user_id = u.id
        WHERE 1 = 1
    """
    params = []

    if recent_search:
        query += " AND (h.url LIKE %s OR u.name LIKE %s OR u.email LIKE %s)"
        search_value = f"%{recent_search}%"
        params.extend([search_value, search_value, search_value])

    if recent_from and recent_to:
        query += " AND DATE(h.analyzed_at) BETWEEN %s AND %s"
        params.extend([recent_from, recent_to])
    elif recent_from:
        query += " AND DATE(h.analyzed_at) >= %s"
        params.append(recent_from)
    elif recent_to:
        query += " AND DATE(h.analyzed_at) <= %s"
        params.append(recent_to)

    query += " ORDER BY h.analyzed_at DESC"

    cursor.execute(query, tuple(params))
    records = cursor.fetchall()
    cursor.close()
    connection.close()

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "User", "Email", "URL", "Score", "Risk", "Analyzed At"])
    for record in records:
        writer.writerow(list(record))

    response = Response(output.getvalue(), mimetype="text/csv; charset=utf-8")
    response.headers["Content-Disposition"] = "attachment; filename=phishguard_recent_analysis.csv"
    return response


@app.route("/admin/export-reports")
def export_admin_reports():

    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    report_search = request.args.get("report_search", "").strip()
    report_from = request.args.get("report_from", "").strip()
    report_to = request.args.get("report_to", "").strip()
    report_status = request.args.get("report_status", "").strip()

    connection = get_connection()
    cursor = connection.cursor()

    query = """
        SELECT r.id,
               COALESCE(u.name, 'Previous / Unknown User'),
               COALESCE(u.email, '-'),
               r.url, r.reason, r.reported_at,
               COALESCE(r.status, 'Pending'), r.reviewed_at
        FROM reports r
        LEFT JOIN users u ON r.user_id = u.id
        WHERE 1 = 1
    """
    params = []

    if report_search:
        query += " AND (r.url LIKE %s OR r.reason LIKE %s OR u.name LIKE %s OR u.email LIKE %s)"
        search_value = f"%{report_search}%"
        params.extend([search_value, search_value, search_value, search_value])

    if report_status in VALID_REPORT_STATUSES:
        query += " AND COALESCE(r.status, 'Pending') = %s"
        params.append(report_status)

    if report_from and report_to:
        query += " AND DATE(r.reported_at) BETWEEN %s AND %s"
        params.extend([report_from, report_to])
    elif report_from:
        query += " AND DATE(r.reported_at) >= %s"
        params.append(report_from)
    elif report_to:
        query += " AND DATE(r.reported_at) <= %s"
        params.append(report_to)

    query += " ORDER BY r.reported_at DESC"

    cursor.execute(query, tuple(params))
    records = cursor.fetchall()
    cursor.close()
    connection.close()

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "User", "Email", "URL", "Reason", "Reported At", "Status", "Reviewed At"])
    for record in records:
        writer.writerow(list(record))

    response = Response(output.getvalue(), mimetype="text/csv; charset=utf-8")
    response.headers["Content-Disposition"] = "attachment; filename=phishguard_reported_urls.csv"
    return response


@app.route("/admin/dashboard")
def admin_dashboard():

    if not session.get("admin_logged_in"):

        return redirect(
            url_for("admin_login")
        )

    recent_search = request.args.get("recent_search", "").strip()
    recent_from = request.args.get("recent_from", "").strip()
    recent_to = request.args.get("recent_to", "").strip()
    report_search = request.args.get("report_search", "").strip()
    report_from = request.args.get("report_from", "").strip()
    report_to = request.args.get("report_to", "").strip()
    report_status = request.args.get("report_status", "").strip()

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM analysis_history"
    )

    total_analyzed = cursor.fetchone()[0]

    cursor.execute("""
        SELECT risk, COUNT(*)
        FROM analysis_history
        GROUP BY risk
    """)

    risk_data = cursor.fetchall()

    cursor.execute("""
        SELECT DATE_FORMAT(analyzed_at, '%d %b') AS day_label, COUNT(*)
        FROM analysis_history
        WHERE analyzed_at >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
        GROUP BY DATE(analyzed_at), DATE_FORMAT(analyzed_at, '%d %b')
        ORDER BY DATE(analyzed_at)
    """)

    daily_activity_data = cursor.fetchall()

    low_risk = 0
    suspicious = 0
    high_risk = 0

    for risk, count in risk_data:

        if risk == "Low Risk":

            low_risk = count

        elif risk == "Suspicious":

            suspicious = count

        elif risk == "High Risk":

            high_risk = count

    cursor.execute(
        "SELECT COUNT(*) FROM reports"
    )

    total_reports = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]

    recent_query = """
        SELECT h.id, h.url, h.score, h.risk, h.analyzed_at,
               COALESCE(u.name, 'Previous / Unknown User'),
               COALESCE(u.email, '-')
        FROM analysis_history h
        LEFT JOIN users u ON h.user_id = u.id
    """

    recent_params = []

    if recent_search:
        recent_query += " AND (h.url LIKE %s OR u.name LIKE %s OR u.email LIKE %s)"
        search_value = f"%{recent_search}%"
        recent_params.extend([search_value, search_value, search_value])

    if recent_from and recent_to:
        recent_query += " AND DATE(h.analyzed_at) BETWEEN %s AND %s"
        recent_params.extend([recent_from, recent_to])
    elif recent_from:
        recent_query += " AND DATE(h.analyzed_at) >= %s"
        recent_params.append(recent_from)
    elif recent_to:
        recent_query += " AND DATE(h.analyzed_at) <= %s"
        recent_params.append(recent_to)

    recent_query += " ORDER BY h.analyzed_at DESC"
    if not (recent_from or recent_to):
        recent_query += " LIMIT 8"

    cursor.execute(recent_query, tuple(recent_params))
    recent_analyses = cursor.fetchall()

    if total_analyzed > 0:
        low_percent = round((low_risk / total_analyzed) * 100, 1)
        suspicious_percent = round((suspicious / total_analyzed) * 100, 1)
        high_percent = round((high_risk / total_analyzed) * 100, 1)
    else:
        low_percent = 0
        suspicious_percent = 0
        high_percent = 0

    max_daily_activity = max((count for _, count in daily_activity_data), default=1)

    report_query = """
        SELECT r.id, r.url, r.reason, r.reported_at,
               COALESCE(u.name, 'Previous / Unknown User'),
               COALESCE(u.email, '-'),
               COALESCE(r.status, 'Pending'),
               r.reviewed_at
        FROM reports r
        LEFT JOIN users u ON r.user_id = u.id
    """

    report_params = []

    if report_search:
        report_query += " AND (r.url LIKE %s OR r.reason LIKE %s OR u.name LIKE %s OR u.email LIKE %s)"
        search_value = f"%{report_search}%"
        report_params.extend([search_value, search_value, search_value, search_value])

    if report_status in VALID_REPORT_STATUSES:
        report_query += " AND COALESCE(r.status, 'Pending') = %s"
        report_params.append(report_status)

    if report_from and report_to:
        report_query += " AND DATE(r.reported_at) BETWEEN %s AND %s"
        report_params.extend([report_from, report_to])
    elif report_from:
        report_query += " AND DATE(r.reported_at) >= %s"
        report_params.append(report_from)
    elif report_to:
        report_query += " AND DATE(r.reported_at) <= %s"
        report_params.append(report_to)

    report_query += " ORDER BY r.reported_at DESC"

    cursor.execute(report_query, tuple(report_params))
    reports = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template_string("""
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>Admin Dashboard - PhishGuard</title>

<style>

* {

    box-sizing: border-box;
}

body {

    margin: 0;

    font-family: Arial, sans-serif;

    background: #020617;

    color: white;
}

.navbar {

    padding: 20px 7%;

    display: flex;

    justify-content: space-between;

    align-items: center;

    border-bottom: 1px solid #1e293b;
}

.logo {

    font-size: 24px;

    font-weight: bold;

    color: #38bdf8;
}

.navbar a {

    color: #cbd5e1;

    text-decoration: none;

    margin-left: 15px;
}

.container {

    max-width: 1200px;

    margin: 40px auto;

    padding: 0 20px;
}

h1 {

    margin-bottom: 30px;
}

.stats {

    display: grid;

    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));

    gap: 20px;

    margin-bottom: 35px;
}

.card {

    background: #0f172a;

    padding: 25px;

    border-radius: 15px;

    border: 1px solid #1e293b;
}

.card-title {

    color: #94a3b8;

    margin-bottom: 10px;
}

.card-number {

    font-size: 35px;

    font-weight: bold;
}

.blue {

    color: #38bdf8;
}

.green {

    color: #4ade80;
}

.yellow {

    color: #facc15;
}

.red {

    color: #f87171;
}

.risk-summary {

    background: #0f172a;

    padding: 25px;

    border-radius: 15px;

    border: 1px solid #1e293b;

    margin-bottom: 35px;
}

.risk-row {

    margin: 18px 0;
}

.dashboard-charts {

    display: grid;

    grid-template-columns: repeat(2, minmax(0, 1fr));

    gap: 20px;

    margin-bottom: 35px;
}

.chart-card {

    background: #0f172a;

    padding: 25px;

    border-radius: 15px;

    border: 1px solid #1e293b;
}

.chart-title {

    margin: 0 0 6px 0;

    font-size: 21px;
}

.chart-subtitle {

    color: #94a3b8;

    margin: 0 0 20px 0;

}

.risk-donut-wrap {

    display: flex;

    align-items: center;

    gap: 25px;

    flex-wrap: wrap;
}

.risk-donut {

    width: 185px;

    height: 185px;

    border-radius: 50%;

    background: conic-gradient(
        #4ade80 0 {{ low_percent }}%,
        #facc15 {{ low_percent }}% {{ low_percent + suspicious_percent }}%,
        #f87171 {{ low_percent + suspicious_percent }}% 100%
    );

    display: flex;

    align-items: center;

    justify-content: center;

    flex-shrink: 0;
}

.risk-donut::after {

    content: 'Risk';

    width: 105px;

    height: 105px;

    border-radius: 50%;

    background: #0f172a;

    display: flex;

    align-items: center;

    justify-content: center;

    color: #cbd5e1;

    font-weight: bold;

}

.legend {

    display: grid;

    gap: 12px;

    min-width: 180px;
}

.legend-item {

    display: flex;

    justify-content: space-between;

    gap: 20px;

    color: #cbd5e1;

}

.activity-chart {

    display: flex;

    align-items: flex-end;

    gap: 12px;

    min-height: 230px;

    padding-top: 20px;

}

.activity-bar-wrap {

    flex: 1;

    display: flex;

    flex-direction: column;

    align-items: center;

    justify-content: flex-end;

    height: 200px;

    gap: 8px;

}

.activity-bar {

    width: min(42px, 85%);

    min-height: 4px;

    border-radius: 8px 8px 2px 2px;

    background: linear-gradient(to top, #2563eb, #38bdf8);

}

.activity-count {

    color: #f8fafc;

    font-size: 13px;

    font-weight: bold;

}

.activity-label {

    color: #94a3b8;

    font-size: 12px;

    white-space: nowrap;

}

.risk-label {

    display: flex;

    justify-content: space-between;

    margin-bottom: 8px;

    color: #cbd5e1;
}

.progress {

    width: 100%;

    height: 12px;

    background: #1e293b;

    border-radius: 20px;

    overflow: hidden;
}

.progress-bar {

    height: 100%;

    border-radius: 20px;
}

.progress-low { background: #4ade80; }
.progress-suspicious { background: #facc15; }
.progress-high { background: #f87171; }

.section {

    background: #0f172a;

    padding: 25px;

    border-radius: 15px;

    border: 1px solid #1e293b;
}

table {

    width: 100%;

    border-collapse: collapse;
}

th, td {

    padding: 15px;

    text-align: left;

    border-bottom: 1px solid #1e293b;
}

th {

    color: #38bdf8;
}

td {

    color: #cbd5e1;
}

.delete {

    color: #f87171;

    text-decoration: none;
}

.status-badge {
    display: inline-block;
    padding: 6px 9px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 700;
    white-space: nowrap;
}

.status-pending { background: rgba(250,204,21,0.12); color: #facc15; border: 1px solid rgba(250,204,21,0.30); }
.status-reviewed { background: rgba(56,189,248,0.12); color: #38bdf8; border: 1px solid rgba(56,189,248,0.30); }
.status-confirmed { background: rgba(248,113,113,0.12); color: #f87171; border: 1px solid rgba(248,113,113,0.30); }
.status-rejected { background: rgba(148,163,184,0.12); color: #cbd5e1; border: 1px solid rgba(148,163,184,0.30); }

.status-form {
    display: flex;
    gap: 6px;
    align-items: center;
    margin-bottom: 8px;
    flex-wrap: wrap;
}

.status-form select {
    padding: 8px 9px;
    border-radius: 8px;
    border: 1px solid #334155;
    background: #020617;
    color: white;
    font-size: 12px;
    max-width: 170px;
}

.status-update-btn {
    padding: 8px 11px;
    border: none;
    border-radius: 8px;
    background: #0284c7;
    color: white;
    font-weight: 700;
    cursor: pointer;
    font-size: 12px;
}

.status-update-btn:hover { background: #0369a1; }

@media(max-width:800px) {

    .stats {

        grid-template-columns: repeat(2, 1fr);
    }

    .dashboard-charts {

        grid-template-columns: 1fr;
    }

    .navbar {
        padding: 16px 5%;
        flex-direction: column;
        align-items: flex-start;
        gap: 12px;
    }

    .navbar > div:last-child {
        width: 100%;
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
    }

    .navbar a {
        margin-left: 0;
        padding: 8px 11px;
        display: inline-block;
    }

    .container {
        margin: 25px auto;
        padding: 0 12px 30px;
    }

    .section, .risk-summary, .chart-card {
        padding: 18px;
    }

    .section {
        overflow-x: auto;
    }

    .section table {
        min-width: 920px;
    }

    .admin-search {
        display: grid;
        grid-template-columns: 1fr 1fr;
        align-items: end;
    }

    .search-field.search-text {
        grid-column: 1 / -1;
        min-width: 0;
    }

    .search-field.search-date {
        min-width: 0;
    }

    .admin-search button {
        width: 100%;
    }

    .date-hint, .admin-search .search-clear {
        grid-column: 1 / -1;
        padding-bottom: 0;
    }

    .status-form {
        min-width: 190px;
    }

    .status-form select {
        flex: 1 1 135px;
        max-width: none;
    }

    .status-update-btn {
        flex: 0 0 auto;
    }
}

@media(max-width:480px) {

    .stats {
        grid-template-columns: 1fr;
    }

    .logo {
        font-size: 21px;
    }

    h1 {
        font-size: 27px;
    }

    h2 {
        font-size: 21px;
    }

    .admin-search {
        grid-template-columns: 1fr;
    }

    .search-field.search-text,
    .search-field.search-date,
    .date-hint,
    .admin-search .search-clear {
        grid-column: 1;
    }

    .clear-btn, .delete-selected {
        width: 100%;
        text-align: center;
    }

    .risk-donut {
        width: 150px;
        height: 150px;
        margin: 0 auto;
    }

    .legend {
        width: 100%;
    }
}

</style>

</head>

<body>

<div class="navbar">

    <div class="logo">

        🛡️ PhishGuard Admin

    </div>

    <div>

        <a href="{{ url_for('admin_history') }}">All History</a>

        <a href="/admin/logout">Logout</a>

    </div>

</div>


<div class="container">

    <h1>📊 Admin Dashboard</h1>

    <p style="color:#94a3b8;">Manage users, review URL activity and monitor reported suspicious URLs.</p>


    <div class="stats">

        <div class="card">

            <div class="card-title">

                Total Analyses

            </div>

            <div class="card-number blue">

                {{ total_analyzed }}

            </div>

        </div>


        <div class="card">

            <div class="card-title">

                Total Users

            </div>

            <div class="card-number blue">

                {{ total_users }}

            </div>

        </div>


        <div class="card">

            <div class="card-title">

                Low Risk

            </div>

            <div class="card-number green">

                {{ low_risk }}

            </div>

        </div>


        <div class="card">

            <div class="card-title">

                Suspicious

            </div>

            <div class="card-number yellow">

                {{ suspicious }}

            </div>

        </div>


        <div class="card">

            <div class="card-title">

                High Risk

            </div>

            <div class="card-number red">

                {{ high_risk }}

            </div>

        </div>

    </div>


    <div class="risk-summary">

        <h2>📈 Risk Distribution</h2>

        <p style="color:#94a3b8;">Overview of analyzed URLs by risk classification.</p>

        <div class="risk-row">
            <div class="risk-label"><span>🟢 Low Risk</span><span>{{ low_risk }} ({{ low_percent }}%)</span></div>
            <div class="progress"><div class="progress-bar progress-low" style="width: {{ low_percent }}%;"></div></div>
        </div>

        <div class="risk-row">
            <div class="risk-label"><span>🟡 Suspicious</span><span>{{ suspicious }} ({{ suspicious_percent }}%)</span></div>
            <div class="progress"><div class="progress-bar progress-suspicious" style="width: {{ suspicious_percent }}%;"></div></div>
        </div>

        <div class="risk-row">
            <div class="risk-label"><span>🔴 High Risk</span><span>{{ high_risk }} ({{ high_percent }}%)</span></div>
            <div class="progress"><div class="progress-bar progress-high" style="width: {{ high_percent }}%;"></div></div>
        </div>

    </div>

    <div class="stats">

        <div class="card">

            <div class="card-title">

                Reported URLs

            </div>

            <div class="card-number red">

                {{ total_reports }}

            </div>

        </div>

    </div>


    <div class="dashboard-charts">

        <div class="chart-card">

            <h2 class="chart-title">🍩 Risk Distribution Chart</h2>
            <p class="chart-subtitle">Visual breakdown of all analyzed URLs by risk level.</p>

            <div class="risk-donut-wrap">
                <div class="risk-donut"></div>

                <div class="legend">
                    <div class="legend-item"><span>🟢 Low Risk</span><strong>{{ low_risk }} ({{ low_percent }}%)</strong></div>
                    <div class="legend-item"><span>🟡 Suspicious</span><strong>{{ suspicious }} ({{ suspicious_percent }}%)</strong></div>
                    <div class="legend-item"><span>🔴 High Risk</span><strong>{{ high_risk }} ({{ high_percent }}%)</strong></div>
                </div>
            </div>

        </div>

        <div class="chart-card">

            <h2 class="chart-title">📊 Analysis Activity</h2>
            <p class="chart-subtitle">URL analyses recorded during the last 7 days.</p>

            <div class="activity-chart">
                {% if daily_activity_data %}
                    {% for day_label, count in daily_activity_data %}
                    <div class="activity-bar-wrap">
                        <div class="activity-count">{{ count }}</div>
                        <div class="activity-bar" style="height: {{ ((count / max_daily_activity) * 160)|round(0) }}px;" title="{{ day_label }}: {{ count }} analyses"></div>
                        <div class="activity-label">{{ day_label }}</div>
                    </div>
                    {% endfor %}
                {% else %}
                    <div style="width:100%; text-align:center; color:#94a3b8; padding:60px 0;">No analysis activity in the last 7 days.</div>
                {% endif %}
            </div>

        </div>

    </div>


    <div class="section">

        <h2>🕒 Recent Analysis</h2>

        <p style="color:#94a3b8;">Search by URL, user or email, and optionally choose a date range.</p>

        <div style="margin:10px 0 14px;">
            <a href="{{ url_for('export_admin_dashboard_analysis', recent_search=recent_search, recent_from=recent_from, recent_to=recent_to) }}" class="clear-btn" style="display:inline-block; text-decoration:none;">⬇️ Export Analysis CSV</a>
        </div>

        <form method="GET" action="{{ url_for('admin_dashboard') }}" class="admin-search">
            <div class="search-field search-text">
                <label for="recent-search">Search by URL, Name or Email</label>
                <input
                    id="recent-search"
                    type="text"
                    name="recent_search"
                    value="{{ recent_search }}"
                    placeholder="e.g. example.com or Abisha or user@email.com"
                >
            </div>

            <div class="search-field search-date">
                <label for="recent-from">From Date</label>
                <input
                    id="recent-from"
                    type="date"
                    name="recent_from"
                    value="{{ recent_from }}"
                >
            </div>

            <div class="search-field search-date">
                <label for="recent-to">To Date</label>
                <input
                    id="recent-to"
                    type="date"
                    name="recent_to"
                    value="{{ recent_to }}"
                >
            </div>

            <input type="hidden" name="report_search" value="{{ report_search }}">
            <input type="hidden" name="report_from" value="{{ report_from }}">
            <input type="hidden" name="report_to" value="{{ report_to }}">
            <button type="submit">🔎 Search</button>
            <span class="date-hint">Date range is inclusive</span>
            {% if recent_search or recent_from or recent_to %}
                <a class="search-clear" href="{{ url_for('admin_dashboard', report_search=report_search, report_from=report_from, report_to=report_to) }}">✕ Clear</a>
            {% endif %}
        </form>

        <form method="POST" action="{{ url_for('clear_recent_analysis') }}" style="display:inline-block; margin-top:4px;" onsubmit="return confirm('Clear the latest 8 analysis records from Recent Analysis?');">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <button type="submit" class="clear-btn">🗑️ Clear Recent Analysis</button>
        </form>


        {% if recent_analyses %}
        <table>
            <tr>
                <th>ID</th>
                <th>User</th>
                <th>Email</th>
                <th>URL</th>
                <th>Score</th>
                <th>Risk</th>
                <th>Analyzed At</th>
                <th>Details</th>
            </tr>

            {% for analysis in recent_analyses %}
            <tr>
                <td>{{ analysis[0] }}</td>
                <td>{{ analysis[5] }}</td>
                <td>{{ analysis[6] }}</td>
                <td style="max-width: 420px;">
                    <span title="{{ analysis[1] }}" style="display:inline-block; max-width:320px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; vertical-align:middle;">
                        {{ analysis[1]|shorten_url }}
                    </span>
                    <a href="{{ analysis[1] }}" target="_blank" rel="noopener noreferrer" style="margin-left:8px; white-space:nowrap;">View</a>
                </td>
                <td>{{ analysis[2] }}/100</td>
                <td>
                    {% if analysis[3] == 'Low Risk' %}
                        🟢 Low Risk
                    {% elif analysis[3] == 'Suspicious' %}
                        🟡 Suspicious
                    {% else %}
                        🔴 High Risk
                    {% endif %}
                </td>
                <td>{{ analysis[4]|pretty_datetime }}</td>
                <td><a href="{{ url_for('analysis_details', analysis_id=analysis[0]) }}">View Details</a></td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
        <div class="empty-state" style="padding: 30px; text-align: center; border: 1px dashed rgba(255,255,255,0.2); border-radius: 12px; margin-top: 10px;">
            <div style="font-size: 36px; margin-bottom: 10px;">📭</div>
            <h3 style="margin: 0 0 8px 0;">No Analysis Yet</h3>
            <p style="margin: 0; opacity: 0.75;">No URL analysis records are available yet.</p>
        </div>
        {% endif %}

    </div>


    <div class="section">

        <h2>🚨 Reported Suspicious URLs</h2>

        <p style="color:#94a3b8;">Search by URL, user, email or reason, and optionally choose a date range.</p>

        <div style="margin:10px 0 14px;">
            <a href="{{ url_for('export_admin_reports', report_search=report_search, report_from=report_from, report_to=report_to, report_status=report_status) }}" class="clear-btn" style="display:inline-block; text-decoration:none;">⬇️ Export Reports CSV</a>
        </div>

        <form method="GET" action="{{ url_for('admin_dashboard') }}" class="admin-search">
            <div class="search-field search-text">
                <label for="report-search">Search by URL, Name, Email or Reason</label>
                <input
                    id="report-search"
                    type="text"
                    name="report_search"
                    value="{{ report_search }}"
                    placeholder="e.g. example.com or Abisha or suspicious reason"
                >
            </div>

            <div class="search-field search-date">
                <label for="report-from">From Date</label>
                <input
                    id="report-from"
                    type="date"
                    name="report_from"
                    value="{{ report_from }}"
                >
            </div>

            <div class="search-field search-date">
                <label for="report-to">To Date</label>
                <input
                    id="report-to"
                    type="date"
                    name="report_to"
                    value="{{ report_to }}"
                >
            </div>

            <div class="search-field search-status">
                <label for="report-status">Status</label>
                <select id="report-status" name="report_status">
                    <option value="" {% if not report_status %}selected{% endif %}>All Statuses</option>
                    <option value="Pending" {% if report_status == 'Pending' %}selected{% endif %}>Pending</option>
                    <option value="Reviewed" {% if report_status == 'Reviewed' %}selected{% endif %}>Reviewed</option>
                    <option value="Confirmed Phishing" {% if report_status == 'Confirmed Phishing' %}selected{% endif %}>Confirmed Phishing</option>
                    <option value="Rejected" {% if report_status == 'Rejected' %}selected{% endif %}>Rejected</option>
                </select>
            </div>

            <input type="hidden" name="recent_search" value="{{ recent_search }}">
            <input type="hidden" name="recent_from" value="{{ recent_from }}">
            <input type="hidden" name="recent_to" value="{{ recent_to }}">
            <button type="submit">🔎 Search</button>
            <span class="date-hint">Date range is inclusive</span>
            {% if report_search or report_from or report_to or report_status %}
                <a class="search-clear" href="{{ url_for('admin_dashboard', recent_search=recent_search, recent_from=recent_from, recent_to=recent_to) }}">✕ Clear</a>
            {% endif %}
        </form>

        <form method="POST" action="{{ url_for('delete_selected_reports') }}" onsubmit="return confirmSelectedDelete();">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

            <div style="margin-bottom: 15px;">
                <label style="font-weight: bold;">
                    <input type="checkbox" id="selectAll" onclick="toggleAllReports(this)">
                    Select All
                </label>

                <button type="submit" class="delete-selected">
                    🗑️ Delete Selected
                </button>
            </div>

            {% if reports %}
            <table>
                <tr>
                    <th>Select</th>
                    <th>ID</th>
                    <th>User</th>
                    <th>Email</th>
                    <th>URL</th>
                    <th>Reason</th>
                    <th>Reported At</th>
                    <th>Status</th>
                    <th>Reviewed At</th>
                    <th>Action</th>
                </tr>

                {% for report in reports %}
                <tr>
                    <td>
                        <input type="checkbox" name="report_ids" value="{{ report[0] }}" class="report-checkbox" onclick="updateSelectAll()">
                    </td>
                    <td>{{ report[0] }}</td>
                    <td>{{ report[4] }}</td>
                    <td>{{ report[5] }}</td>
                    <td>{{ report[1] }}</td>
                    <td>{{ report[2] }}</td>
                    <td>{{ report[3]|pretty_datetime }}</td>
                    <td>
                        {% if report[6] == 'Pending' %}
                            <span class="status-badge status-pending">🕒 Pending</span>
                        {% elif report[6] == 'Reviewed' %}
                            <span class="status-badge status-reviewed">👁️ Reviewed</span>
                        {% elif report[6] == 'Confirmed Phishing' %}
                            <span class="status-badge status-confirmed">🚨 Confirmed Phishing</span>
                        {% else %}
                            <span class="status-badge status-rejected">❌ Rejected</span>
                        {% endif %}
                    </td>
                    <td>
                        {% if report[7] %}
                            {{ report[7]|pretty_datetime }}
                        {% else %}
                            <span style="color:#94a3b8;">—</span>
                        {% endif %}
                    </td>
                    <td>
                        <form method="POST" action="{{ url_for('update_report_status', report_id=report[0]) }}" class="status-form">
                            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                            <select name="status" aria-label="Update report status">
                                <option value="Pending" {% if report[6] == 'Pending' %}selected{% endif %}>Pending</option>
                                <option value="Reviewed" {% if report[6] == 'Reviewed' %}selected{% endif %}>Reviewed</option>
                                <option value="Confirmed Phishing" {% if report[6] == 'Confirmed Phishing' %}selected{% endif %}>Confirmed Phishing</option>
                                <option value="Rejected" {% if report[6] == 'Rejected' %}selected{% endif %}>Rejected</option>
                            </select>
                            <input type="hidden" name="recent_search" value="{{ recent_search }}">
                            <input type="hidden" name="recent_from" value="{{ recent_from }}">
                            <input type="hidden" name="recent_to" value="{{ recent_to }}">
                            <input type="hidden" name="report_search" value="{{ report_search }}">
                            <input type="hidden" name="report_from" value="{{ report_from }}">
                            <input type="hidden" name="report_to" value="{{ report_to }}">
                            <input type="hidden" name="report_status" value="{{ report_status }}">
                            <button type="submit" class="status-update-btn">Update</button>
                        </form>
                        <form method="POST" action="{{ url_for('delete_report', report_id=report[0]) }}" style="display:inline;" onsubmit="return confirm('Delete this report?');">
                            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                            <button type="submit" class="delete" style="border:0; background:none; padding:0; cursor:pointer;">Delete</button>
                        </form>
                    </td>
                </tr>
                {% endfor %}
            </table>
            {% else %}
            <div class="empty-state" style="padding: 30px; text-align: center; border: 1px dashed rgba(255,255,255,0.2); border-radius: 12px; margin-top: 10px;">
                <div style="font-size: 36px; margin-bottom: 10px;">✅</div>
                <h3 style="margin: 0 0 8px 0;">No Suspicious URLs Reported</h3>
                <p style="margin: 0; opacity: 0.75;">There are currently no user-submitted suspicious URL reports to review.</p>
            </div>
            {% endif %}

        </form>

        <script>
            function toggleAllReports(source) {
                document.querySelectorAll('.report-checkbox').forEach(function(checkbox) {
                    checkbox.checked = source.checked;
                });
            }

            function updateSelectAll() {
                const checkboxes = document.querySelectorAll('.report-checkbox');
                const selectAll = document.getElementById('selectAll');
                selectAll.checked = checkboxes.length > 0 && Array.from(checkboxes).every(function(checkbox) {
                    return checkbox.checked;
                });
            }

            function confirmSelectedDelete() {
                const selected = document.querySelectorAll('.report-checkbox:checked');

                if (selected.length === 0) {
                    alert('Please select at least one report to delete.');
                    return false;
                }

                return confirm('Are you sure you want to delete ' + selected.length + ' selected report(s)?');
            }
        </script>

    </div>

</div>

</body>

</html>
""",
        total_analyzed=total_analyzed,
        low_risk=low_risk,
        suspicious=suspicious,
        high_risk=high_risk,
        total_reports=total_reports,
        total_users=total_users,
        recent_analyses=recent_analyses,
        reports=reports,
        low_percent=low_percent,
        suspicious_percent=suspicious_percent,
        high_percent=high_percent,
        daily_activity_data=daily_activity_data,
        max_daily_activity=max_daily_activity,
        recent_search=recent_search,
        recent_from=recent_from,
        recent_to=recent_to,
        report_search=report_search,
        report_from=report_from,
        report_to=report_to
    )


# ============================================================
# ADMIN LOGOUT
# ============================================================

@app.route("/admin/logout")
def admin_logout():

    session.pop("admin_logged_in", None)
    session.pop("login_failed_attempts", None)
    session.pop("login_lockout_until", None)

    return redirect(
        url_for("admin_login")
    )


# ============================================================
# DELETE SELECTED REPORTS
# ============================================================

@app.route("/admin/delete-selected", methods=["POST"])
def delete_selected_reports():

    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    report_ids = request.form.getlist("report_ids")

    if not report_ids:
        return redirect(url_for("admin_dashboard"))

    connection = get_connection()
    cursor = connection.cursor()

    query = """
        DELETE FROM reports
        WHERE id = %s
    """

    for report_id in report_ids:
        try:
            report_id = int(report_id)
        except ValueError:
            continue

        cursor.execute(query, (report_id,))

    connection.commit()
    cursor.close()
    connection.close()

    return redirect(url_for("admin_dashboard"))


# ============================================================
# UPDATE REPORT STATUS
# ============================================================

VALID_REPORT_STATUSES = [
    "Pending",
    "Reviewed",
    "Confirmed Phishing",
    "Rejected"
]

@app.route("/admin/update-report-status/<int:report_id>", methods=["POST"])
def update_report_status(report_id):

    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    new_status = request.form.get("status", "").strip()

    if new_status not in VALID_REPORT_STATUSES:
        return redirect(url_for("admin_dashboard"))

    connection = get_connection()
    cursor = connection.cursor()

    if new_status == "Pending":
        cursor.execute("""
            UPDATE reports
            SET status = %s, reviewed_at = NULL, reviewed_by = NULL
            WHERE id = %s
        """, (new_status, report_id))
    else:
        cursor.execute("""
            UPDATE reports
            SET status = %s, reviewed_at = CURRENT_TIMESTAMP, reviewed_by = %s
            WHERE id = %s
        """, (new_status, session.get("admin_id"), report_id))

    connection.commit()
    cursor.close()
    connection.close()

    return redirect(url_for(
        "admin_dashboard",
        recent_search=request.form.get("recent_search", ""),
        recent_from=request.form.get("recent_from", ""),
        recent_to=request.form.get("recent_to", ""),
        report_search=request.form.get("report_search", ""),
        report_from=request.form.get("report_from", ""),
        report_to=request.form.get("report_to", ""),
        report_status=request.form.get("report_status", "")
    ))


# ============================================================
# DELETE REPORT
# ============================================================

@app.route("/admin/delete/<int:report_id>", methods=["POST"])
def delete_report(report_id):

    if not session.get("admin_logged_in"):

        return redirect(
            url_for("admin_login")
        )

    connection = get_connection()
    cursor = connection.cursor()

    query = """
        DELETE FROM reports
        WHERE id = %s
    """

    cursor.execute(
        query,
        (report_id,)
    )

    connection.commit()

    cursor.close()
    connection.close()

    return redirect(
        url_for("admin_dashboard")
    )


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":

    app.run(debug=True)
