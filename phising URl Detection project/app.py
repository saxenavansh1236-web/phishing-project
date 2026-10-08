"""
app.py  --  Phishing URL Detection — Flask Application
"""

import csv
import hmac
import io
import json
import os
import re
import secrets
import sqlite3
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import quote_plus, urlparse

import joblib
from dotenv import load_dotenv
from flask import Flask, Response, abort, render_template, request, redirect, session
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash

# Load .env BEFORE anything reads os.environ (this call was missing before,
# so SECRET_KEY / ADMIN_* / VT_API_KEY / ALERT_* were silently ignored).
load_dotenv()

from api import create_api_blueprint, init_api_tables
from utils.features import extract_features, FEATURE_NAMES
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
from utils.page_check import analyze_page
from utils.risk import compute_risk

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-fallback-change-me")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,                 # JavaScript can't read the session cookie
    SESSION_COOKIE_SAMESITE="Lax",                # browser won't send it on cross-site POSTs (CSRF)
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE") == "1",   # set to 1 behind HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,           # QR-image / CSV uploads capped at 5 MB
)
# Behind a reverse proxy (Render, nginx) the real client IP and host arrive in X-Forwarded-* headers.
# Only enable this when you really are behind exactly one trusted proxy.
if os.environ.get("TRUST_PROXY") == "1":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

model = joblib.load("phishing_model.pkl")
if getattr(model, "n_features_in_", len(FEATURE_NAMES)) != len(FEATURE_NAMES):
    raise RuntimeError(
        f"phishing_model.pkl expects {model.n_features_in_} features but utils/features.py "
        f"defines {len(FEATURE_NAMES)}. Re-run `python model.py` to retrain the model."
    )

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

if app.secret_key == "dev-only-fallback-change-me" or ADMIN_PASSWORD == "admin123":
    print("WARNING: SECRET_KEY and/or ADMIN_PASSWORD are still the insecure defaults. "
          "Set real values in .env before deploying.")

# ── DATABASE SETUP ─────────────────────────────────────────────
DB_PATH = os.environ.get("DB_PATH", "users.db")


def get_db():
    """Returns a live SQLite database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT    UNIQUE NOT NULL,
            password TEXT    NOT NULL
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS history (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT    NOT NULL,
            url      TEXT    NOT NULL,
            result   TEXT    NOT NULL,
            risk     INTEGER NOT NULL
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS logins (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    NOT NULL,
            ip_address    TEXT,
            user_agent    TEXT,
            logged_in_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS rate_events (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            scope   TEXT NOT NULL,
            subject TEXT NOT NULL DEFAULT '',
            ip      TEXT NOT NULL,
            ts      REAL NOT NULL
        )
        """
    )
    c.execute("CREATE INDEX IF NOT EXISTS idx_rate_events ON rate_events(scope, ip, ts)")
    conn.commit()
    conn.close()


# IMPORTANT: must run unconditionally at import time — gunicorn imports this
# module and never executes the `if __name__ == "__main__":` block.
init_db()


def execute(conn, sql, params=()):
    """Run a query and return a cursor you can call .fetchone()/.fetchall() on."""
    cur = conn.cursor()
    cur.execute(sql, params)
    return cur


IntegrityErrorType = sqlite3.IntegrityError


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _add_column(conn, table, name, ddl):
    cols = {r["name"] for r in execute(conn, f"PRAGMA table_info({table})").fetchall()}
    if name not in cols:
        execute(conn, f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")


def migrate_db():
    """Adds columns needed by the admin dashboard to databases created by older versions."""
    conn = get_db()
    _add_column(conn, "history", "scanned_at", "TEXT")                 # old rows stay NULL (undated)
    _add_column(conn, "history", "source", "TEXT DEFAULT 'unknown'")   # web | qr | bulk | api
    _add_column(conn, "users", "disabled", "INTEGER NOT NULL DEFAULT 0")
    _add_column(conn, "users", "created_at", "TEXT")
    conn.commit()
    conn.close()


migrate_db()


def truncate_url(url, length=55):
    """Truncate a URL for display — done in Python, not in Jinja2."""
    return url if len(url) <= length else url[:length] + "…"


# ── PASSWORD HELPERS ───────────────────────────────────────────

def is_hashed(stored):
    return stored.startswith(("pbkdf2:", "scrypt:"))


def verify_password(stored, supplied):
    """Supports hashed passwords AND legacy plaintext rows (upgraded on login)."""
    if is_hashed(stored):
        return check_password_hash(stored, supplied)
    return hmac.compare_digest(stored.encode(), supplied.encode())


def _ensure_scheme(url):
    """Bare domains like 'google.com' are accepted; give them https:// for scanning."""
    url = url.strip()
    return url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url) else "https://" + url


# ── RATE LIMITING ──────────────────────────────────────────────
# Stored in SQLite (not memory) so limits survive restarts and are shared by all
# gunicorn workers. Failed attempts that are blocked are NOT recorded, so a locked-out
# client can't extend its own lockout.
LOGIN_MAX_FAILS = 5            # failed logins per (account, IP) ...
LOGIN_MAX_FAILS_PER_IP = 20    # ... or per IP across all accounts ...
LOGIN_WINDOW = 15 * 60         # ... within 15 minutes
ADMIN_MAX_FAILS = 5            # failed admin logins per IP in the same window
REGISTER_MAX = 10              # sign-ups per IP ...
REGISTER_WINDOW = 60 * 60      # ... per hour

DUMMY_HASH = generate_password_hash("not-a-real-password")   # equalises timing for unknown usernames


def client_ip():
    return request.remote_addr or "unknown"


def record_event(scope, subject=""):
    now = time.time()
    conn = get_db()
    execute(conn, "INSERT INTO rate_events(scope, subject, ip, ts) VALUES (?,?,?,?)",
            (scope, subject.lower(), client_ip(), now))
    execute(conn, "DELETE FROM rate_events WHERE ts < ?", (now - 86400,))
    conn.commit()
    conn.close()


def clear_events(scope, subject=None):
    conn = get_db()
    if subject is None:
        execute(conn, "DELETE FROM rate_events WHERE scope=? AND ip=?", (scope, client_ip()))
    else:
        execute(conn, "DELETE FROM rate_events WHERE scope=? AND ip=? AND subject=?",
                (scope, client_ip(), subject.lower()))
    conn.commit()
    conn.close()


def retry_after(scope, limit, window, subject=None):
    """Seconds until this client may try again, or 0 if it is not rate-limited."""
    now = time.time()
    conn = get_db()
    if subject is None:
        rows = execute(conn, "SELECT ts FROM rate_events WHERE scope=? AND ip=? AND ts>? ORDER BY ts",
                       (scope, client_ip(), now - window)).fetchall()
    else:
        rows = execute(conn, "SELECT ts FROM rate_events WHERE scope=? AND ip=? AND subject=? AND ts>? ORDER BY ts",
                       (scope, client_ip(), subject.lower(), now - window)).fetchall()
    conn.close()
    if len(rows) >= limit:
        return int(rows[len(rows) - limit]["ts"] + window - now) + 1
    return 0


def _minutes(seconds):
    return max(1, -(-seconds // 60))


# ── CSRF DEFENCE ───────────────────────────────────────────────
# Two layers, no template changes needed:
#   1. the session cookie is SameSite=Lax, so browsers don't attach it to cross-site POSTs;
#   2. every state-changing request must come from this site: its Origin (or, if absent,
#      Referer) host must equal our own host. Browsers always send Origin on cross-origin POSTs.
# /api/* is exempt: it authenticates with an API key header, not a cookie, so a malicious
# web page can't make a victim's browser send it.
@app.before_request
def block_cross_site_posts():
    if request.method in ("GET", "HEAD", "OPTIONS") or request.path.startswith("/api/"):
        return None
    source = request.headers.get("Origin") or request.headers.get("Referer") or ""
    if source and source != "null" and urlparse(source).netloc == request.host:
        return None
    # logged so a legitimate form that gets blocked is easy to diagnose
    print(f"[CSRF] blocked {request.method} {request.path}: "
          f"Origin={request.headers.get('Origin')!r} Referer={request.headers.get('Referer')!r} host={request.host!r}")
    return ("Cross-site request blocked.", 403)


@app.before_request
def drop_disabled_or_deleted_sessions():
    name = session.get("user")
    if name and not request.path.startswith("/static"):
        conn = get_db()
        row = execute(conn, "SELECT disabled FROM users WHERE username=?", (name,)).fetchone()
        conn.close()
        if row is None or row["disabled"]:
            session.pop("user", None)


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")                 # no clickjacking
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return resp


# ── CORE SCAN PIPELINE ─────────────────────────────────────────

def run_full_scan(url, username, source="web"):
    """
    Runs the full detection pipeline on a single URL and logs it to
    history. Shared by the typed-URL dashboard scan, the QR-code scan
    route, bulk CSV scanning and the REST API.

    Pipeline order:
      1. Redirect-chain tracing (SSRF-checked at every hop)
      2. ML model probability on the FINAL resolved URL
      3. WHOIS / typosquat / SSL / VirusTotal / Favicon / page content analysis
      4. Combine ALL evidence into one risk score + verdict (utils/risk.py)
      5. Log to history
      6. Fire a webhook alert if the result is high-risk
    """
    scan_url = _ensure_scheme(url)
    redirect_info = trace_redirect_chain(scan_url)

    # URL (or a redirect hop) points at a private/internal address or uses an
    # unsupported scheme: do NOT touch it with any other network check.
    if redirect_info.get("blocked"):
        return {
            "result": "BLOCKED: unsafe or unsupported URL 🚫",
            "risk": 0,
            "blocked": True,
            "url": url,
            "vt_result": "Skipped: " + (redirect_info.get("error") or "URL was blocked."),
            "reasons": [],
            "domain_info": None,
            "typo_result": None,
            "ssl_info": None,
            "redirect_info": redirect_info,
            "favicon_info": None,
            "page_info": None,
        }

    scan_target = redirect_info["final_url"]  # scan where the link actually leads

    feature_vector = extract_features(scan_target)
    proba = float(model.predict_proba([feature_vector])[0][1])
    model_flagged = proba >= 0.5

    domain_info = get_domain_age_info(scan_target)
    typo_result = check_typosquatting(scan_target)
    ssl_info = check_ssl_certificate(scan_target)
    vt_result = check_url_virustotal(scan_target)
    # All-zero counts mean VirusTotal has no analysis yet (a brand-new URL), NOT that the URL is clean
    if re.search(r"Malicious:\s*0\s*\|\s*Suspicious:\s*0\s*\|\s*Harmless:\s*0\s*\|\s*Undetected:\s*0", str(vt_result)):
        vt_result = ("VirusTotal: no analysis results yet. This URL is new to VirusTotal, "
                     "so there is no verdict either way.")
    favicon_info = check_favicon_similarity(scan_target)
    page_info = analyze_page(scan_target)

    # The ML model only sees the URL's origin and is a weak prior on its own, so the
    # verdict comes from ALL evidence combined (see utils/risk.py). The breakdown is
    # kept so the UI/API can show exactly how the score was reached.
    assessment = compute_risk(proba, redirect_info, domain_info, typo_result,
                              ssl_info, vt_result, favicon_info, page_info)
    risk = assessment["risk"]
    result = "PHISHING URL 🚨" if assessment["verdict"] == "phishing" else "SAFE URL ✅"

    # "Why this was flagged" explains the ML model's own reasons
    reasons = explain_prediction(model, feature_vector) if model_flagged else []

    conn = get_db()
    execute(conn,
        "INSERT INTO history(username, url, result, risk, scanned_at, source) VALUES (?,?,?,?,?,?)",
        (username, url, result, risk, utc_now(), source),
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
        "page_info": page_info,
        "risk_breakdown": assessment["signals"],
        "model_probability": round(proba * 100),
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
        wait = retry_after("register", REGISTER_MAX, REGISTER_WINDOW)
        if wait:
            return render_template(
                "register.html",
                error=f"Too many sign-up attempts from this address. Try again in {_minutes(wait)} minute(s)."), 429
        username = request.form["username"].strip()
        password = request.form["password"]
        if not username or not password:
            error = "Username and password are required."
        elif not 3 <= len(username) <= 64:
            error = "Username must be 3-64 characters long."
        elif len(password) < 8:
            error = "Password must be at least 8 characters long."
        else:
            record_event("register")
            conn = get_db()
            try:
                execute(conn,
                    "INSERT INTO users(username, password, created_at) VALUES (?, ?, ?)",
                    (username, generate_password_hash(password), utc_now()),
                )
                conn.commit()
                return redirect("/login")
            except IntegrityErrorType:
                error = "Username already exists."
            finally:
                conn.close()
    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        wait = max(retry_after("login", LOGIN_MAX_FAILS, LOGIN_WINDOW, subject=username),
                   retry_after("login", LOGIN_MAX_FAILS_PER_IP, LOGIN_WINDOW))
        if wait:
            return render_template(
                "login.html",
                error=f"Too many failed login attempts. Try again in {_minutes(wait)} minute(s)."), 429

        conn = get_db()
        user = execute(conn,
            "SELECT * FROM users WHERE username=?", (username,),
        ).fetchone()

        if user:
            valid = verify_password(user["password"], password)
        else:
            check_password_hash(DUMMY_HASH, password)   # same work as a real check: no username-guessing by timing
            valid = False

        if valid and user["disabled"]:
            conn.close()
            return render_template(
                "login.html", error="This account has been disabled. Please contact the administrator."), 403

        if valid:
            # Silently upgrade legacy plaintext passwords to hashes on login
            if not is_hashed(user["password"]):
                execute(conn, "UPDATE users SET password=? WHERE id=?",
                        (generate_password_hash(password), user["id"]))
            session.clear()                 # fresh session on login (prevents session fixation)
            session.permanent = True
            session["user"] = username
            execute(conn,
                "INSERT INTO logins(username, ip_address, user_agent) VALUES (?, ?, ?)",
                (username, request.remote_addr, request.headers.get("User-Agent", "")),
            )
            conn.commit()
            conn.close()
            clear_events("login", username)
            return redirect("/dashboard")

        conn.close()
        record_event("login", username)
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
            return render_template(
                "scan_qr.html",
                error=None,
                non_url_warning=True,
                decoded_text=decoded_text,
            )

        scan_data = run_full_scan(decoded_text, session["user"], source="qr")
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
            scan_data = run_full_scan(u, session["user"], source="bulk")
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


def _csv_safe(v):
    """Stop spreadsheet formula injection: cells starting with = + - @ get a leading apostrophe."""
    t = "" if v is None else str(v)
    return "'" + t if t[:1] in ("=", "+", "-", "@", "\t", "\r") else t


def admin_redirect(msg, section):
    """Back to the admin panel, on the tab the admin was using, with a flash message."""
    return redirect("/admin?msg=" + quote_plus(msg) + "#" + section)


def get_admin_extras(all_scans, users):
    """Analytics, security-centre and system data for the advanced admin sections."""
    conn = get_db()
    today = datetime.now(timezone.utc).date()
    rows = execute(conn,
        "SELECT date(scanned_at) d, COUNT(*) n, SUM(CASE WHEN result LIKE '%PHISHING%' THEN 1 ELSE 0 END) p "
        "FROM history WHERE scanned_at >= date('now','-13 days') GROUP BY d").fetchall()
    by_day = {r["d"]: (r["n"], r["p"] or 0) for r in rows}
    days = [(today - timedelta(days=i)).isoformat() for i in range(13, -1, -1)]
    daily = {"labels": [d[5:] for d in days],
             "phishing": [by_day.get(d, (0, 0))[1] for d in days],
             "safe": [by_day.get(d, (0, 0))[0] - by_day.get(d, (0, 0))[1] for d in days]}

    src = execute(conn, "SELECT COALESCE(source,'unknown') s, COUNT(*) n FROM history GROUP BY s").fetchall()
    edges = [(0, 19), (20, 39), (40, 59), (60, 79), (80, 100)]
    risk = {"labels": [f"{a}-{b}" for a, b in edges],
            "counts": [sum(1 for x in all_scans if a <= x["risk"] <= b) for a, b in edges]}
    phish = [x for x in all_scans if "PHISHING" in x["result"]]
    domains = Counter((urlparse(_ensure_scheme(x["url"])).hostname or x["url"]) for x in phish)

    locked = []
    for r in execute(conn,
            "SELECT scope, ip, COUNT(*) c FROM rate_events WHERE scope IN ('login','admin_login') AND ts>? "
            "GROUP BY scope, ip HAVING c>=3 ORDER BY c DESC", (time.time() - LOGIN_WINDOW,)).fetchall():
        hard = (r["scope"] == "admin_login" and r["c"] >= ADMIN_MAX_FAILS) or r["c"] >= LOGIN_MAX_FAILS_PER_IP
        locked.append({"scope": r["scope"], "ip": r["ip"], "count": r["c"],
                       "status": "Locked" if hard else ("Suspicious" if r["c"] >= LOGIN_MAX_FAILS else "Warning")})
    keys = [dict(r) for r in execute(conn,
            "SELECT username, key_prefix, created_at FROM api_keys ORDER BY id DESC").fetchall()]
    accounts = [dict(r) for r in execute(conn,
            "SELECT username, disabled, created_at FROM users ORDER BY id").fetchall()]
    conn.close()

    try:
        with open("model_metrics.json") as f:
            card = json.load(f)
        card["top_features"] = list(card.get("feature_importances", {}).items())[:6]
        if "deployed_model" not in card:      # metrics file from an older training script
            card = None
    except (OSError, ValueError):
        card = None

    return {
        "analytics": {
            "daily": daily,
            "verdicts": {"phishing": len(phish), "safe": len(all_scans) - len(phish)},
            "risk": risk,
            "sources": {"labels": [r["s"] for r in src], "counts": [r["n"] for r in src]},
            "top_domains": [{"domain": d, "count": n} for d, n in domains.most_common(8)],
            "top_users": [{"username": u["username"], "scans": u["scan_count"], "phishing": u["phish_count"]}
                          for u in sorted(users, key=lambda u: -u["scan_count"])[:5] if u["scan_count"]],
        },
        "locked": locked,
        "api_keys": keys,
        "accounts": accounts,
        "model_card": card,
        "integrations": [("VirusTotal API key", bool(os.environ.get("VT_API_KEY"))),
                         ("Alert webhook", bool(os.environ.get("ALERT_WEBHOOK_URL"))),
                         ("Secure SECRET_KEY", app.secret_key != "dev-only-fallback-change-me"),
                         ("Secure admin password", ADMIN_PASSWORD != "admin123")],
    }


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
            "SELECT COUNT(*) AS cnt FROM history WHERE username=? AND result LIKE ?",
            (uname, "%PHISHING%"),
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
        **get_admin_extras(all_scans, users),
    }


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None
    if request.method == "POST":
        wait = retry_after("admin_login", ADMIN_MAX_FAILS, LOGIN_WINDOW)
        if wait:
            return render_template(
                "admin_login.html",
                error=f"Too many failed attempts. Try again in {_minutes(wait)} minute(s)."), 429
        username = request.form["username"].strip()
        password = request.form["password"]
        if (hmac.compare_digest(username.encode(), ADMIN_USERNAME.encode())
                and hmac.compare_digest(password.encode(), ADMIN_PASSWORD.encode())):
            clear_events("admin_login")
            session.clear()
            session.permanent = True
            session["admin"] = ADMIN_USERNAME
            return redirect("/admin")
        record_event("admin_login", username)
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
    raw = request.form.get("username", "")
    username = raw.strip()
    if not username:
        print(f"[admin] delete-user got no 'username' field; form fields were: {list(request.form.keys())}")
        return admin_redirect("Delete failed: the form did not send a username.", "users")
    if username == ADMIN_USERNAME:
        return admin_redirect("The admin account cannot be deleted.", "users")

    conn = get_db()
    deleted = execute(conn, "DELETE FROM users WHERE username=?", (raw,)).rowcount
    if not deleted and raw != username:
        deleted = execute(conn, "DELETE FROM users WHERE username=?", (username,)).rowcount
    if deleted:
        for table in ("history", "logins", "api_keys"):
            execute(conn, f"DELETE FROM {table} WHERE username=?", (username,))
        execute(conn, "DELETE FROM rate_events WHERE subject=?", (username.lower(),))
    conn.commit()
    conn.close()
    return admin_redirect(f"User {username} deleted." if deleted else f"User {username} was not found.", "users")


@app.route("/admin/delete-scan", methods=["POST"])
@admin_required
def admin_delete_scan():
    scan_id = request.form.get("scan_id", "")
    if scan_id:
        conn = get_db()
        execute(conn, "DELETE FROM history WHERE id=?", (scan_id,))
        conn.commit()
        conn.close()
    return redirect("/admin?msg=Scan+record+deleted.#scans")


@app.route("/admin/clear-history", methods=["POST"])
@admin_required
def admin_clear_history():
    conn = get_db()
    execute(conn, "DELETE FROM history")
    conn.commit()
    conn.close()
    return redirect("/admin?msg=All+scan+history+cleared.#settings")


@app.route("/admin/clear-logins", methods=["POST"])
@admin_required
def admin_clear_logins():
    conn = get_db()
    execute(conn, "DELETE FROM logins")
    conn.commit()
    conn.close()
    return redirect("/admin?msg=Login+history+cleared.#settings")


@app.route("/admin/change-password", methods=["POST"])
@admin_required
def admin_change_password():
    global ADMIN_PASSWORD
    current = request.form.get("current_password", "")
    new_pw = request.form.get("new_password", "")
    if not hmac.compare_digest(current.encode(), ADMIN_PASSWORD.encode()):
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
    return redirect("/admin?msg=Password+updated+successfully.#settings")


@app.route("/admin/toggle-user", methods=["POST"])
@admin_required
def admin_toggle_user():
    username = request.form.get("username", "").strip()
    if not username or username == ADMIN_USERNAME:
        return admin_redirect("That account cannot be disabled.", "security")
    conn = get_db()
    row = execute(conn, "SELECT disabled FROM users WHERE username=?", (username,)).fetchone()
    if row is None:
        conn.close()
        return admin_redirect(f"User {username} was not found.", "security")
    now_disabled = 0 if row["disabled"] else 1
    execute(conn, "UPDATE users SET disabled=? WHERE username=?", (now_disabled, username))
    conn.commit()
    conn.close()
    return admin_redirect(f"User {username} {'disabled' if now_disabled else 'enabled'}.", "security")


@app.route("/admin/unlock", methods=["POST"])
@admin_required
def admin_unlock():
    scope, ip = request.form.get("scope", ""), request.form.get("ip", "")
    if scope not in ("login", "admin_login") or not ip:
        return admin_redirect("Unlock failed: invalid request.", "security")
    conn = get_db()
    execute(conn, "DELETE FROM rate_events WHERE scope=? AND ip=?", (scope, ip))
    conn.commit()
    conn.close()
    return admin_redirect(f"Unlocked {ip}.", "security")


@app.route("/admin/revoke-key", methods=["POST"])
@admin_required
def admin_revoke_key():
    username = request.form.get("username", "")
    conn = get_db()
    n = execute(conn, "DELETE FROM api_keys WHERE username=?", (username,)).rowcount
    conn.commit()
    conn.close()
    return admin_redirect(f"API key for {username} revoked." if n else "No such API key.", "security")


@app.route("/admin/export/<kind>.csv")
@admin_required
def admin_export(kind):
    conn = get_db()
    if kind == "scans":
        header = ["id", "username", "url", "result", "risk", "scanned_at", "source"]
        rows = execute(conn, "SELECT id, username, url, result, risk, scanned_at, source "
                             "FROM history ORDER BY id DESC").fetchall()
    elif kind == "logins":
        header = ["username", "ip_address", "user_agent", "logged_in_at"]
        rows = execute(conn, "SELECT username, ip_address, user_agent, logged_in_at "
                             "FROM logins ORDER BY id DESC").fetchall()
    elif kind == "users":                     # never includes passwords or hashes
        header = ["username", "created_at", "disabled", "scans", "phishing_found", "logins"]
        rows = execute(conn,
            "SELECT u.username, u.created_at, u.disabled, "
            "(SELECT COUNT(*) FROM history h WHERE h.username=u.username), "
            "(SELECT COUNT(*) FROM history h WHERE h.username=u.username AND h.result LIKE '%PHISHING%'), "
            "(SELECT COUNT(*) FROM logins l WHERE l.username=u.username) FROM users u").fetchall()
    else:
        conn.close()
        abort(404)
    conn.close()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(header)
    for r in rows:
        writer.writerow([_csv_safe(v) for v in r])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={kind}.csv"})


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect("/admin/login")


# ── REST API (v1) + API-key page ───────────────────────────────
# Registered last so run_full_scan, get_db and execute already exist.
init_api_tables(get_db, execute)
app.register_blueprint(create_api_blueprint(run_full_scan, get_db, execute))


if __name__ == "__main__":
    # Never run the Werkzeug debugger on a reachable server (it allows code execution).
    # For local debugging:  set FLASK_DEBUG=1
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
