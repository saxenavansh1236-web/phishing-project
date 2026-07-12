"""
app.py  --  Phishing URL Detection — Flask Application
"""

from flask import Flask, render_template, request, redirect, session
import sqlite3
import joblib
import os
from functools import wraps

from utils.feature import extract_features
from utils.vt_api import check_url_virustotal
from utils.explain import explain_prediction
from utils.whois_check import get_domain_age_info
from utils.typosquat_check import check_typosquatting
from utils.ssl_check import check_ssl_certificate
from utils.qr_check import decode_qr_from_filestorage, looks_like_url
from utils.bulk_check import parse_urls_from_csv
from utils.redirect_check import trace_redirect_chain
from utils.alert import send_alert_if_high_risk
from utils.favicon_check import check_favicon_similarity

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-fallback-change-me")

model = joblib.load("phishing_model.pkl")


ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

# ── DATABASE SETUP ─────────────────────────────────────────────
#
# Render's free-tier web service filesystem is EPHEMERAL — any file
# written locally (like a SQLite users.db) gets wiped on every restart,
# redeploy, or free-tier spin-down after inactivity. To keep registered
# users and scan history permanently, we use Render's free PostgreSQL
# database instead whenever a DATABASE_URL environment variable is set.
#
# Locally (on your own machine, with no DATABASE_URL set), the app
# automatically falls back to a plain SQLite file — so local development
# still works exactly as before, with zero setup needed.

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
USE_POSTGRES = bool(DATABASE_URL)

if USE_POSTGRES:
    import psycopg2
    import psycopg2.extras
else:
    DB_PATH = os.environ.get("DB_PATH", "users.db")


def get_db():
    """Returns a live database connection. Works transparently whether
    we're on Postgres (production) or SQLite (local dev)."""
    if USE_POSTGRES:
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
        return conn
    else:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn


def q(sql_sqlite, sql_postgres):
    """Pick the right SQL dialect for the current backend.
    SQLite uses '?' placeholders and AUTOINCREMENT; Postgres uses
    '%s' placeholders and SERIAL — this small helper keeps every
    query written once, in both dialects, side by side."""
    return sql_postgres if USE_POSTGRES else sql_sqlite


def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute(q(
        """
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT    UNIQUE NOT NULL,
            password TEXT    NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS users (
            id       SERIAL PRIMARY KEY,
            username TEXT   UNIQUE NOT NULL,
            password TEXT   NOT NULL
        )
        """
    ))
    c.execute(q(
        """
        CREATE TABLE IF NOT EXISTS history (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT    NOT NULL,
            url      TEXT    NOT NULL,
            result   TEXT    NOT NULL,
            risk     INTEGER NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS history (
            id       SERIAL PRIMARY KEY,
            username TEXT    NOT NULL,
            url      TEXT    NOT NULL,
            result   TEXT    NOT NULL,
            risk     INTEGER NOT NULL
        )
        """
    ))
    c.execute(q(
        """
        CREATE TABLE IF NOT EXISTS logins (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    NOT NULL,
            ip_address    TEXT,
            user_agent    TEXT,
            logged_in_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS logins (
            id            SERIAL PRIMARY KEY,
            username      TEXT NOT NULL,
            ip_address    TEXT,
            user_agent    TEXT,
            logged_in_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    ))
    conn.commit()
    conn.close()


# IMPORTANT: this must run unconditionally at import time, because Render
# runs this app via gunicorn ("gunicorn app:app"), which imports this file
# as a module and NEVER executes the `if __name__ == "__main__":` block
# below. If init_db() is only called inside that block, the database
# tables never get created in production and every query fails with
# "no such table".
init_db()


def ph(sql):
    """Convert a '?'-style query into the right placeholder style for
    the active backend. Write every query using '?' as usual; this
    swaps them to '%s' automatically when running on Postgres."""
    return sql.replace("?", "%s") if USE_POSTGRES else sql


def execute(conn, sql, params=()):
    """Run a query on either backend and return a cursor you can call
    .fetchone()/.fetchall() on — sqlite3's connection object supports
    .execute() directly, but psycopg2's does not (only its cursor does),
    so this wrapper makes both backends usable with the same call style
    everywhere else in the app."""
    cur = conn.cursor()
    cur.execute(ph(sql), params)
    return cur


# Postgres and SQLite raise different exception types for a unique-
# constraint violation (e.g. registering a username that already
# exists) — catch whichever one is relevant for the active backend.
if USE_POSTGRES:
    IntegrityErrorType = psycopg2.errors.UniqueViolation
else:
    IntegrityErrorType = sqlite3.IntegrityError


def truncate_url(url, length=55):
    """Truncate a URL for display — done in Python, not in Jinja2."""
    return url if len(url) <= length else url[:length] + "…"


def run_full_scan(url, username):
    """
    Runs the full detection pipeline on a single URL and logs it to
    history. Shared by the typed-URL dashboard scan, the QR-code scan
    route, and bulk CSV scanning, so none of them drift apart.

    Pipeline order:
      1. Redirect-chain tracing (expand shorteners, follow all hops)
      2. ML model prediction — runs on the FINAL resolved URL, since
         that's the actual destination a victim would land on
      3. Explainability / WHOIS / typosquat / SSL / VirusTotal / Favicon
         similarity — all run against the final URL for the same reason
      4. Log to history
      5. Fire a webhook alert if the result is high-risk

    Returns a dict of everything result.html needs.
    """
    redirect_info = trace_redirect_chain(url)
    scan_target = redirect_info["final_url"]  # scan where the link actually leads

    feature_vector = extract_features(scan_target)
    prediction = model.predict([feature_vector])[0]

    if prediction == 1:
        result = "PHISHING URL 🚨"
        risk = 90
    else:
        result = "SAFE URL ✅"
        risk = 10

    # A resolved redirect chain is itself a mild risk signal — nudge the
    # score up a little if the link hid behind 2+ hops, without letting
    # it override a model verdict of SAFE into PHISHING outright.
    if redirect_info["was_shortened"] and redirect_info["hop_count"] >= 2 and risk < 90:
        risk = min(risk + 15, 65)

    reasons = explain_prediction(model, feature_vector) if prediction == 1 else []
    domain_info = get_domain_age_info(scan_target)
    typo_result = check_typosquatting(scan_target)
    ssl_info = check_ssl_certificate(scan_target)
    vt_result = check_url_virustotal(scan_target)
    favicon_info = check_favicon_similarity(scan_target)

    # A confirmed visual clone (a known brand's favicon on a domain that
    # ISN'T that brand's real domain) is a very strong phishing signal —
    # treat it with the same weight as a confirmed model/typosquat hit.
    if favicon_info.get("is_visual_clone") and risk < 90:
        risk = 90
        result = "PHISHING URL 🚨"

    conn = get_db()
    execute(conn, 
        "INSERT INTO history(username, url, result, risk) VALUES (?,?,?,?)",
        (username, url, result, risk),
    )
    conn.commit()
    conn.close()

    scan_data = {
        "result": result,
        "risk": risk,
        "url": url,
        "vt_result": vt_result,
        "reasons": reasons,
        "domain_info": domain_info,
        "typo_result": typo_result,
        "ssl_info": ssl_info,
        "redirect_info": redirect_info,
        "favicon_info": favicon_info,
    }

    send_alert_if_high_risk(scan_data, username)  # best-effort, never raises

    return scan_data


# ── USER ROUTES ────────────────────────────────────────────────

@app.route("/")
def index():
    return redirect("/login")


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        if not username or not password:
            error = "Username and password are required."
        else:
            try:
                conn = get_db()
                execute(conn, 
                    "INSERT INTO users(username, password) VALUES (?, ?)",
                    (username, password),
                )
                conn.commit()
                conn.close()
                return redirect("/login")
            except IntegrityErrorType:
                if USE_POSTGRES:
                    conn.rollback()
                conn.close()
                error = "Username already exists."
    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        conn = get_db()
        user = execute(conn, 
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, password),
        ).fetchone()

        if user:
            session["user"] = username
            # Log this login for the admin panel's "Login Activity" view
            execute(conn, 
                "INSERT INTO logins(username, ip_address, user_agent) VALUES (?, ?, ?)",
                (username, request.remote_addr, request.headers.get("User-Agent", "")),
            )
            conn.commit()
            conn.close()
            return redirect("/dashboard")

        conn.close()
        error = "Invalid username or password."
    return render_template("login.html", error=error)


@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user" not in session:
        return redirect("/login")

    if request.method == "POST":
        url = request.form["url"].strip()
        scan_data = run_full_scan(url, session["user"])
        return render_template("result.html", **scan_data)

    return render_template("dashboard.html")


@app.route("/scan-qr", methods=["GET", "POST"])
def scan_qr():
    if "user" not in session:
        return redirect("/login")

    if request.method == "POST":
        qr_file = request.files.get("qr_image")

        if not qr_file or qr_file.filename == "":
            return render_template("scan_qr.html", error="Please choose a QR code image to upload.")

        decoded = decode_qr_from_filestorage(qr_file)

        if not decoded["success"]:
            return render_template("scan_qr.html", error=decoded["error"])

        decoded_text = decoded["data"]

        if not looks_like_url(decoded_text):
            # QR decoded fine, but it's not a URL — show it instead of
            # silently feeding non-URL text into the URL scan pipeline
            return render_template(
                "scan_qr.html",
                error=None,
                non_url_warning=True,
                decoded_text=decoded_text,
            )

        scan_data = run_full_scan(decoded_text, session["user"])
        scan_data["from_qr"] = True
        return render_template("result.html", **scan_data)

    return render_template("scan_qr.html")


@app.route("/bulk-scan", methods=["GET", "POST"])
def bulk_scan():
    if "user" not in session:
        return redirect("/login")

    if request.method == "POST":
        csv_file = request.files.get("csv_file")

        if not csv_file or csv_file.filename == "":
            return render_template("bulk_scan.html", error="Please choose a CSV file to upload.")

        parsed = parse_urls_from_csv(csv_file)

        if not parsed["success"]:
            return render_template("bulk_scan.html", error=parsed["error"])

        urls = parsed["urls"]
        batch_results = []
        for u in urls:
            scan_data = run_full_scan(u, session["user"])
            batch_results.append(scan_data)

        phishing_count = sum(1 for r in batch_results if "PHISHING" in r["result"])
        safe_count = len(batch_results) - phishing_count

        return render_template(
            "bulk_results.html",
            batch_results=batch_results,
            total=len(batch_results),
            phishing_count=phishing_count,
            safe_count=safe_count,
            truncated=parsed.get("truncated", False),
        )

    return render_template("bulk_scan.html")


@app.route("/history")
def history():
    if "user" not in session:
        return redirect("/login")
    conn = get_db()
    data = execute(conn, 
        "SELECT url, result, risk FROM history WHERE username=? ORDER BY id DESC",
        (session["user"],),
    ).fetchall()
    conn.close()
    return render_template("history.html", data=data)


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/login")


# ── ADMIN ROUTES ───────────────────────────────────────────────

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("admin") != ADMIN_USERNAME:
            return redirect("/admin/login")
        return f(*args, **kwargs)
    return decorated


def get_login_activity(limit=50):
    """Most recent user logins, newest first — feeds the admin panel."""
    conn = get_db()
    rows = execute(conn, 
        "SELECT username, ip_address, user_agent, logged_in_at "
        "FROM logins ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_admin_stats():
    conn = get_db()

    users_raw = execute(conn, "SELECT username FROM users").fetchall()
    users = []
    for u in users_raw:
        uname = u["username"]
        scan_count = execute(conn, 
            "SELECT COUNT(*) AS cnt FROM history WHERE username=?", (uname,)
        ).fetchone()["cnt"]
        phish_count = execute(conn, 
            "SELECT COUNT(*) AS cnt FROM history WHERE username=? AND result LIKE '%PHISHING%'",
            (uname,),
        ).fetchone()["cnt"]
        login_count = execute(conn, 
            "SELECT COUNT(*) AS cnt FROM logins WHERE username=?", (uname,)
        ).fetchone()["cnt"]
        users.append({
            "username": uname,
            "scan_count": scan_count,
            "phish_count": phish_count,
            "login_count": login_count,
        })

    all_scans_raw = execute(conn, 
        "SELECT id, username, url, result, risk FROM history ORDER BY id DESC"
    ).fetchall()

    all_scans = []
    for row in all_scans_raw:
        s = dict(row)
        s["url_short"] = truncate_url(s["url"], 55)
        all_scans.append(s)

    recent_scans = []
    for s in all_scans[:10]:
        rs = dict(s)
        rs["url_short"] = truncate_url(s["url"], 60)
        recent_scans.append(rs)

    phishing_scans = [s for s in all_scans if "PHISHING" in s["result"]]

    total_users = len(users)
    total_scans = len(all_scans)
    phishing_count = len(phishing_scans)
    safe_count = total_scans - phishing_count
    detection_rate = round((phishing_count / total_scans * 100), 1) if total_scans else 0

    total_logins = execute(conn, "SELECT COUNT(*) AS cnt FROM logins").fetchone()["cnt"]

    conn.close()

    return {
        "users": users,
        "all_scans": all_scans,
        "phishing_scans": phishing_scans,
        "recent_scans": recent_scans,
        "total_users": total_users,
        "total_scans": total_scans,
        "phishing_count": phishing_count,
        "safe_count": safe_count,
        "detection_rate": detection_rate,
        "total_logins": total_logins,
        "admin_user": ADMIN_USERNAME,
    }


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["admin"] = ADMIN_USERNAME
            return redirect("/admin")
        error = "Invalid admin credentials."
    return render_template("admin_login.html", error=error)


@app.route("/admin")
@admin_required
def admin_panel():
    stats = get_admin_stats()
    logins = get_login_activity()
    return render_template(
        "admin.html",
        message=request.args.get("msg"),
        logins=logins,
        **stats
    )


@app.route("/admin/delete-user", methods=["POST"])
@admin_required
def admin_delete_user():
    username = request.form.get("username", "").strip()
    if username and username != ADMIN_USERNAME:
        conn = get_db()
        execute(conn, "DELETE FROM users   WHERE username=?", (username,))
        execute(conn, "DELETE FROM history WHERE username=?", (username,))
        execute(conn, "DELETE FROM logins  WHERE username=?", (username,))
        conn.commit()
        conn.close()
    return redirect("/admin?msg=User+" + username + "+deleted.")


@app.route("/admin/delete-scan", methods=["POST"])
@admin_required
def admin_delete_scan():
    scan_id = request.form.get("scan_id", "")
    if scan_id:
        conn = get_db()
        execute(conn, "DELETE FROM history WHERE id=?", (scan_id,))
        conn.commit()
        conn.close()
    return redirect("/admin?msg=Scan+record+deleted.")


@app.route("/admin/clear-history", methods=["POST"])
@admin_required
def admin_clear_history():
    conn = get_db()
    execute(conn, "DELETE FROM history")
    conn.commit()
    conn.close()
    return redirect("/admin?msg=All+scan+history+cleared.")


@app.route("/admin/clear-logins", methods=["POST"])
@admin_required
def admin_clear_logins():
    conn = get_db()
    execute(conn, "DELETE FROM logins")
    conn.commit()
    conn.close()
    return redirect("/admin?msg=Login+history+cleared.")


@app.route("/admin/change-password", methods=["POST"])
@admin_required
def admin_change_password():
    global ADMIN_PASSWORD
    current = request.form.get("current_password", "")
    new_pw = request.form.get("new_password", "")
    if current != ADMIN_PASSWORD:
        stats = get_admin_stats()
        return render_template(
            "admin.html",
            error="Current password is incorrect.",
            logins=get_login_activity(),
            **stats
        )
    if len(new_pw) < 6:
        stats = get_admin_stats()
        return render_template(
            "admin.html",
            error="New password must be at least 6 characters.",
            logins=get_login_activity(),
            **stats
        )
    ADMIN_PASSWORD = new_pw
    return redirect("/admin?msg=Password+updated+successfully.")


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect("/admin/login")


if __name__ == "__main__":
    app.run(debug=True)
