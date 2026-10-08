"""
api.py -- REST API (v1) + API-key management.

Wire-up in app.py (after run_full_scan is defined):
    from api import create_api_blueprint, init_api_tables
    init_api_tables(get_db, execute)
    app.register_blueprint(create_api_blueprint(run_full_scan, get_db, execute))
"""
import hashlib
import json
import secrets
import time
from collections import defaultdict, deque
from functools import wraps

from flask import Blueprint, g, jsonify, redirect, render_template_string, request, session

RATE_LIMIT = 30   # requests per key...
WINDOW = 60       # ...per this many seconds (in-memory; use Redis/Flask-Limiter with >1 worker)
_hits = defaultdict(deque)


def _hash(key):
    return hashlib.sha256(key.encode()).hexdigest()  # keys are high-entropy, so SHA-256 is fine


def init_api_tables(get_db, execute):
    conn = get_db()
    execute(conn, """
        CREATE TABLE IF NOT EXISTS api_keys (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            username     TEXT NOT NULL,
            key_hash     TEXT UNIQUE NOT NULL,
            key_prefix   TEXT NOT NULL,
            created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
        )""")
    conn.commit()
    conn.close()


def _retry_after(key_hash):
    now = time.time()
    q = _hits[key_hash]
    while q and now - q[0] > WINDOW:
        q.popleft()
    if len(q) >= RATE_LIMIT:
        return int(WINDOW - (now - q[0])) + 1
    q.append(now)
    return 0


def _jsonable(obj):
    return json.loads(json.dumps(obj, default=str))


KEY_PAGE = """
<!doctype html><title>API key</title>
<link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
<div class="container" style="max-width:560px;margin:40px auto">
  <h2>API key</h2>
  {% if new_key %}
    <p>Copy this now. It won't be shown again.</p>
    <pre style="padding:12px;background:#111;color:#0f0;overflow:auto">{{ new_key }}</pre>
  {% elif prefix %}
    <p>Current key: <code>{{ prefix }}…</code></p>
  {% else %}
    <p>You don't have a key yet.</p>
  {% endif %}
  <form method="post"><button type="submit">{{ 'Replace key' if prefix or new_key else 'Create key' }}</button></form>
  <p><a href="/dashboard">Back to dashboard</a></p>
</div>
"""


def create_api_blueprint(run_full_scan, get_db, execute):
    bp = Blueprint("api", __name__)

    def require_api_key(f):
        @wraps(f)
        def wrapper(*a, **kw):
            key = request.headers.get("X-API-Key") or request.headers.get(
                "Authorization", "").removeprefix("Bearer ").strip()
            if not key:
                return jsonify(error="Missing API key (send X-API-Key header)"), 401
            h = _hash(key)
            conn = get_db()
            row = execute(conn, "SELECT username FROM api_keys WHERE key_hash=?", (h,)).fetchone()
            conn.close()
            if not row:
                return jsonify(error="Invalid API key"), 401
            wait = _retry_after(h)
            if wait:
                resp = jsonify(error=f"Rate limit exceeded ({RATE_LIMIT}/{WINDOW}s)")
                resp.headers["Retry-After"] = str(wait)
                return resp, 429
            g.api_user = row["username"]
            return f(*a, **kw)
        return wrapper

    @bp.route("/api/v1/health")
    def health():
        return jsonify(status="ok")

    @bp.route("/api/v1/scan", methods=["POST"])
    @require_api_key
    def scan():
        data = request.get_json(silent=True) or {}
        url = data.get("url")
        if not isinstance(url, str) or not url.strip():
            return jsonify(error="JSON body must include a 'url' string"), 400
        url = url.strip()
        if len(url) > 2048 or not url.lower().startswith(("http://", "https://")):
            return jsonify(error="URL must start with http:// or https:// and be under 2048 characters"), 400

        s = run_full_scan(url, g.api_user, source="api")
        redirect_info = s.get("redirect_info") or {}
        page = s.get("page_info") or {}
        return jsonify(_jsonable({
            "url": url,
            "final_url": redirect_info.get("final_url", url),
            "verdict": "blocked" if s.get("blocked") else ("phishing" if "PHISHING" in s["result"] else "safe"),
            "risk": s["risk"],
            "model_probability": s.get("model_probability"),
            "risk_breakdown": s.get("risk_breakdown", []),
            "reasons": [(r.get("explanation") if isinstance(r, dict) else str(r)) for r in s.get("reasons", [])],
            "page_findings": [x["text"] for x in page.get("findings", [])],
            "details": {
                "domain_info": s.get("domain_info"),
                "typosquat": s.get("typo_result"),
                "ssl": s.get("ssl_info"),
                "redirects": redirect_info,
                "favicon": s.get("favicon_info"),
                "virustotal": s.get("vt_result"),
                "page": page,
            },
        }))

    @bp.route("/account/api-key", methods=["GET", "POST"])
    def api_key_page():
        user = session.get("user")
        if not user:
            return redirect("/login")
        conn = get_db()
        new_key = None
        if request.method == "POST":
            new_key = "pg_" + secrets.token_urlsafe(32)
            execute(conn, "DELETE FROM api_keys WHERE username=?", (user,))
            execute(conn, "INSERT INTO api_keys(username, key_hash, key_prefix) VALUES (?,?,?)",
                    (user, _hash(new_key), new_key[:8]))
            conn.commit()
        row = execute(conn, "SELECT key_prefix FROM api_keys WHERE username=?", (user,)).fetchone()
        conn.close()
        return render_template_string(KEY_PAGE, new_key=new_key, prefix=row["key_prefix"] if row else None)

    return bp