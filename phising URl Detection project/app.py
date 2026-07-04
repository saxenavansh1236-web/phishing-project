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
from utils.redirect_check import trace_redirect_chain          # NEW
from utils.alert import send_alert_if_high_risk                # NEW
from utils.favicon_check import check_favicon_similarity       # NEW

app = Flask(__name__)
app.secret_key = "secret123"

model = joblib.load("phishing_model.pkl")

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
    favicon_info = check_favicon_similarity(scan_target)   # NEW

    # A confirmed visual clone (a known brand's favicon on a domain that
    # ISN'T that brand's real domain) is a very strong phishing signal —
    # treat it with the same weight as a confirmed model/typosquat hit.
    if favicon_info.get("is_visual_clone") and risk < 90:
        risk = 90
        result = "PHISHING URL 🚨"

    conn = get_db()
    conn.execute(
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
        "redirect_info": redirect_info,   # chain + final destination for the template
        "favicon_info": favicon_info,     # NEW — visual brand-clone detection for the template
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
            "username": uname,
            "scan_count": scan_count,
            "phish_count": phish_count,
        })

    all_scans_raw = conn.execute(
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
    new_pw = request.form.get("new_password", "")
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


if __name__ == "__main__":
    init_db()
    app.run(debug=True)