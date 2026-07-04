"""
app.py  --  Phishing URL Detection — Flask Application
"""

from flask import Flask, render_template, request, redirect, session
import sqlite3
import joblib
import os

from utils.feature import extract_features
from utils.vt_api import check_url_virustotal

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder="../templates",
    static_folder="../static"
)
app.secret_key = "secret123"

MODEL_PATH = os.path.join(BASE_DIR, "../phishing_model.pkl")
model = joblib.load(MODEL_PATH)

# In app.py replace lines 17-18 with:
import os
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")


def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT    UNIQUE NOT NULL,
            password TEXT    NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT    NOT NULL,
            url      TEXT    NOT NULL,
            result   TEXT    NOT NULL,
            risk     INTEGER NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn


def truncate_url(url, length=55):
    """Truncate a URL for display — done in Python, not in Jinja2."""
    return url if len(url) <= length else url[:length] + "…"


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
                conn.execute(
                    "INSERT INTO users(username, password) VALUES (?, ?)",
                    (username, password),
                )
                conn.commit()
                conn.close()
                return redirect("/login")
            except sqlite3.IntegrityError:
                error = "Username already exists."
    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, password),
        ).fetchone()
        conn.close()
        if user:
            session["user"] = username
            return redirect("/dashboard")
        error = "Invalid username or password."
    return render_template("login.html", error=error)


@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user" not in session:
        return redirect("/login")
    if request.method == "POST":
        url = request.form["url"].strip()
        features   = [extract_features(url)]
        prediction = model.predict(features)[0]
        if prediction == 1:
            result = "PHISHING URL 🚨"
            risk   = 90
        else:
            result = "SAFE URL ✅"
            risk   = 10
        vt_result = check_url_virustotal(url)
        conn = get_db()
        conn.execute(
            "INSERT INTO history(username, url, result, risk) VALUES (?,?,?,?)",
            (session["user"], url, result, risk),
        )
        conn.commit()
        conn.close()
        return render_template(
            "result.html", result=result, risk=risk,
            url=url, vt_result=vt_result,
        )
    return render_template("dashboard.html")


@app.route("/history")
def history():
    if "user" not in session:
        return redirect("/login")
    conn = get_db()
    data = conn.execute(
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
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("admin") != ADMIN_USERNAME:
            return redirect("/admin/login")
        return f(*args, **kwargs)
    return decorated


def get_admin_stats():
    conn = get_db()

    users_raw = conn.execute("SELECT username FROM users").fetchall()
    users = []
    for u in users_raw:
        uname = u["username"]
        scan_count = conn.execute(
            "SELECT COUNT(*) FROM history WHERE username=?", (uname,)
        ).fetchone()[0]
        phish_count = conn.execute(
            "SELECT COUNT(*) FROM history WHERE username=? AND result LIKE '%PHISHING%'",
            (uname,),
        ).fetchone()[0]
        users.append({
            "username":   uname,
            "scan_count": scan_count,
            "phish_count": phish_count,
        })

    all_scans_raw = conn.execute(
        "SELECT id, username, url, result, risk FROM history ORDER BY id DESC"
    ).fetchall()

    # Build scan dicts — add url_short here so Jinja2 never needs to slice
    all_scans = []
    for row in all_scans_raw:
        s = dict(row)
        s["url_short"] = truncate_url(s["url"], 55)
        all_scans.append(s)

    # Recent 10 for activity feed — url_short truncated to 60 chars
    recent_scans = []
    for s in all_scans[:10]:
        rs = dict(s)
        rs["url_short"] = truncate_url(s["url"], 60)
        recent_scans.append(rs)

    # Phishing-only list (pre-filtered — avoids Jinja2 loop-filter bug)
    phishing_scans = [s for s in all_scans if "PHISHING" in s["result"]]

    total_users    = len(users)
    total_scans    = len(all_scans)
    phishing_count = len(phishing_scans)
    safe_count     = total_scans - phishing_count
    detection_rate = round((phishing_count / total_scans * 100), 1) if total_scans else 0

    conn.close()

    return {
        "users":          users,
        "all_scans":      all_scans,
        "phishing_scans": phishing_scans,
        "recent_scans":   recent_scans,
        "total_users":    total_users,
        "total_scans":    total_scans,
        "phishing_count": phishing_count,
        "safe_count":     safe_count,
        "detection_rate": detection_rate,
        "admin_user":     ADMIN_USERNAME,
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
    return render_template("admin.html", message=request.args.get("msg"), **stats)


@app.route("/admin/delete-user", methods=["POST"])
@admin_required
def admin_delete_user():
    username = request.form.get("username", "").strip()
    if username and username != ADMIN_USERNAME:
        conn = get_db()
        conn.execute("DELETE FROM users   WHERE username=?", (username,))
        conn.execute("DELETE FROM history WHERE username=?", (username,))
        conn.commit()
        conn.close()
    return redirect("/admin?msg=User+" + username + "+deleted.")


@app.route("/admin/delete-scan", methods=["POST"])
@admin_required
def admin_delete_scan():
    scan_id = request.form.get("scan_id", "")
    if scan_id:
        conn = get_db()
        conn.execute("DELETE FROM history WHERE id=?", (scan_id,))
        conn.commit()
        conn.close()
    return redirect("/admin?msg=Scan+record+deleted.")


@app.route("/admin/clear-history", methods=["POST"])
@admin_required
def admin_clear_history():
    conn = get_db()
    conn.execute("DELETE FROM history")
    conn.commit()
    conn.close()
    return redirect("/admin?msg=All+scan+history+cleared.")


@app.route("/admin/change-password", methods=["POST"])
@admin_required
def admin_change_password():
    global ADMIN_PASSWORD
    current = request.form.get("current_password", "")
    new_pw  = request.form.get("new_password", "")
    if current != ADMIN_PASSWORD:
        stats = get_admin_stats()
        return render_template("admin.html", error="Current password is incorrect.", **stats)
    if len(new_pw) < 6:
        stats = get_admin_stats()
        return render_template("admin.html", error="New password must be at least 6 characters.", **stats)
    ADMIN_PASSWORD = new_pw
    return redirect("/admin?msg=Password+updated+successfully.")


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect("/admin/login")


    init_db()

if __name__ == "__main__":
    app.run()