# 🛡️ Phishing URL Detection System

A machine learning-powered web application, REST API and Chrome extension that detect phishing URLs in real time, built with Python and Flask.

---

## 📸 Overview

This project combines a trained machine learning model with the VirusTotal API and a set of contextual checks to decide whether a URL is **safe** or a **phishing attempt**. It includes a full user authentication system, a REST API with per-user API keys, a Chrome extension, and an admin panel for monitoring all activity.

Beyond basic classification, every scan performs deep contextual analysis: it explains *why* a URL was flagged, checks domain age, detects brand impersonation (both textual and **visual**), inspects SSL certificates, unwraps shortened/redirect-chained links, **analyses the content of the destination page** (credential forms, hidden iframes, obfuscated scripts), alerts a webhook on high-risk detections, and supports QR code and bulk CSV scanning for SOC-style workflows. Because the scanner fetches user-supplied URLs, all outbound requests are protected against **SSRF**.

---

## 📊 Model Performance

Trained and evaluated by `model.py` on a real dataset built by `scripts/build_dataset.py` (phishing URLs from **PhishTank** and **OpenPhish**, legitimate sites from the **Tranco** top-sites list). Train and test sets are split **by registered domain**, so the same domain never appears on both sides — a random split would leak near-duplicates and inflate the scores. Metrics are on the held-out test set and are saved to `model_metrics.json`.

| Metric | Value |
|--------|-------|
| Dataset size | 9,999 URLs (5,000 phishing / 4,999 legitimate) |
| Train / Test split | 7,999 / 2,000 (grouped by domain) |
| Deployed model | Gradient Boosting |
| Accuracy | 85.05% |
| Precision | 91.38% |
| Recall | 77.40% |
| F1-score | 83.81% |
| ROC AUC | 0.927 |
| Confusion matrix | `[[927, 73], [226, 774]]` (format: `[[TN, FP], [FN, TP]]`) |

**Model comparison** (5-fold cross-validation on the training split, then one evaluation on the test split):

| Model | CV F1 | Test F1 | Test ROC AUC |
|-------|-------|---------|--------------|
| **Gradient Boosting** (deployed) | 0.826 ± 0.008 | 0.838 | 0.927 |
| Random Forest | 0.817 ± 0.008 | 0.837 | 0.902 |
| Decision Tree | 0.794 ± 0.020 | 0.815 | 0.904 |
| Logistic Regression | 0.813 ± 0.012 | 0.850 | 0.922 |

The deployed model is chosen by cross-validation F1 on the training data (never by the test set) among the models that expose feature importances, because the app's "Why this was flagged" explanations need them. Cross-validation and test scores agree closely, which suggests the model is not overfitting.

**How to read these numbers honestly**
- The model judges only the **origin** (scheme + host) of a URL, never the path — see "Feature Extraction Details". Many real phishing pages live on compromised, normal-looking sites, so a host-only model cannot catch all of them; that is why recall is 77%.
- On this balanced test set about **7% of legitimate sites are wrongly flagged**. Real traffic is overwhelmingly legitimate, so the model is **one signal among many**, not the whole verdict — WHOIS, SSL, typosquatting, favicon, page content and VirusTotal add independent evidence.
- The legitimate sites come from a popularity list, so they are short, well-known domains, and about 60% of them were given a *synthetic* subdomain prefix (`www`, `mail`, …) to stop the model learning "subdomain ⇒ phishing". Obscure legitimate sites are under-represented, so expect more false positives on them than the test set suggests.
- **The model leans on length.** `python scripts/ablation.py` (retrain with features removed) shows that dropping `url_length` alone costs 4.5 F1 points, and dropping the length/size group (`url_length`, `dot_count`, `subdomain_count`) collapses F1 from 0.84 to 0.60. Part of that is a dataset effect — famous legitimate domains are short, phishing hosts are often long — so on obscure but legitimate long domains the model alone will over-flag. `python scripts/stress_test.py` measures exactly that on domains the model never saw.
- This is why the final verdict combines the model with independent evidence (see "Risk logic") instead of trusting the model alone.

To retrain with fresh data: `python scripts/build_dataset.py --username yourname`, then `python model.py`.

---

## ✨ Features

### Core Detection
- 🔍 **ML-Based Detection** — A Gradient Boosting model, trained on ~10,000 real URLs and compared against three other model families, classifies a URL from 15 origin-level features
- 🦠 **VirusTotal Integration** — Cross-checks URLs against 70+ antivirus engines via the VirusTotal API
- 👤 **User Authentication** — Register, login and logout with session management; passwords are stored **hashed** (legacy plaintext rows are upgraded automatically on next login)
- 📋 **Scan History** — Every user can view their personal scan history
- 🛡️ **Admin Panel** — A dark, professional dashboard with analytics charts, user management (disable / delete), a security centre (lockouts, API keys), CSV export, a model card and a persistent admin-password change
- 📊 **Explainable Risk Scoring** — Every scan gets a 0–100 risk score built from all evidence (ML model, VirusTotal, WHOIS age, SSL, page content, favicon, typosquatting), with a line-by-line **Risk Breakdown** showing how each signal added or removed points
- 🔐 **Secure Credentials** — Secrets (admin credentials, VirusTotal key, webhook URL) are loaded from environment variables

### Advanced Threat Analysis
- 🧠 **Explainable Predictions** — Every flagged URL shows the specific reasons it was classified as phishing (URL length, domain hyphen count, HTTPS scheme, domain dot/subdomain depth, `@` symbol presence, etc.). Structural checks (hyphen count, dot count) are evaluated against the **parsed domain (`netloc`) only** — never the full URL string — so a hyphenated path such as `meet.google.com/tbj-dudh-fex` is never mistaken for a suspicious domain. The HTTPS check reads the actual URL **scheme** rather than searching for the substring `"https"`
- 📄 **Page Content Analysis** — Fetches the destination page (HTML only, JavaScript is never executed) and looks for behaviour URL-only checks cannot see:
  - password forms that submit to a **different site**, to a `mailto:` address, or over plain HTTP
  - hidden iframes and disabled right-click
  - obfuscated JavaScript (`eval`/`atob`/escaped strings)
  - meta-refresh redirects to another site
  - a page title that claims a brand (PayPal, Google, SBI, HDFC, Paytm …) the domain doesn't belong to
  
  A strong signal (e.g. a brand-named login page posting credentials to another domain) escalates the verdict to phishing; weaker signals raise the risk score
- 🌐 **WHOIS Domain Age Lookup** — Freshly registered domains (under 30 days) are flagged as high risk, one of the strongest real-world phishing signals
- 🎭 **Typosquatting Detection** — Compares scanned domains against well-known brands using edit-distance matching to catch `paypa1.com` or `g00gle.com`
- 🔒 **SSL Certificate Inspection** — Flags missing, expired and self-signed certificates and identifies the issuing CA
- 🔗 **Redirect Chain Tracing & Shortener Expansion** — Expands shorteners (bit.ly, tinyurl, t.co, …) and follows the *entire* redirect chain (up to 8 hops, loop-safe). The ML model, WHOIS, typosquat, SSL, VirusTotal, favicon and page checks all scan the **resolved final URL**
- 🖼️ **Favicon Visual Similarity Detection** — Perceptual hashing (phash) compares a site's favicon against known-brand favicons. A close match on a domain that isn't that brand's own is flagged as a likely visual clone
- 📣 **Webhook / Slack Alerting** — Fires a Slack/Discord-compatible webhook whenever a scan crosses a configurable risk threshold

### Scanning Methods
- ⌨️ **Typed URL** — bare domains such as `google.com` are accepted and scanned as `https://google.com`
- 📷 **QR Code Scanning** — Upload a QR image to extract and scan its URL, defending against "quishing" attacks
- 📋 **Bulk URL Upload** — Upload a CSV (up to 100 URLs) and get one batch report for SOC-style triage
- 🔌 **REST API** — Scan URLs programmatically with a personal API key (see "REST API")
- 🧩 **Chrome Extension** — Scan the current page or any link from the browser (see "Chrome Extension")

### Security Hardening
- 🚧 **SSRF protection** — every outbound fetch (redirect tracing, page analysis, favicon download) refuses private, loopback, link-local and reserved addresses, non-HTTP schemes and unusual ports, re-validates **every redirect hop**, and caps response size
- 🔑 **API keys stored as SHA-256 hashes**, shown only once, with per-key rate limiting
- 🔐 Hashed user passwords (8+ characters required), constant-time credential comparison for the admin login, no Werkzeug debugger unless explicitly enabled
- 🛑 **Login rate limiting** — 5 failed logins per account+IP (20 per IP) in 15 minutes lock that client out with HTTP 429; admin login allows 5 failures per IP; sign-ups are capped at 10 per IP per hour. Counters live in SQLite, so they survive restarts and are shared by all workers. Unknown usernames cost the same time as real ones, so usernames can't be guessed by timing
- 🧱 **CSRF defence** — session cookies are `SameSite=Lax`, and every state-changing request must carry an `Origin` (or `Referer`) header matching this site, otherwise it is rejected with 403. The API is exempt because it authenticates with an API-key header, not a cookie
- 👮 **Account controls** — admins can disable accounts (sessions end immediately), unlock rate-limited IPs and revoke API keys; the admin password changed in Settings is stored hashed and persists across restarts; `REQUIRE_SECRETS=1` blocks startup with default secrets
- 🍪 **Hardened sessions & headers** — `HttpOnly` cookies, 8-hour session lifetime, fresh session on login (no session fixation), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, a referrer policy, and a 5 MB upload cap

---

## 🖥️ Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | Python, Flask |
| Database | SQLite (`users.db`) |
| ML Model | Scikit-learn: Gradient Boosting deployed, Random Forest / Decision Tree / Logistic Regression compared; Joblib |
| Admin charts | Chart.js (loaded from cdnjs) |
| Frontend | HTML, CSS, Jinja2 |
| Browser extension | Chrome Manifest V3 (vanilla JavaScript) |
| Security API | VirusTotal v3 API |
| Auth | Flask sessions, Werkzeug password hashing, API keys |
| Domain Intel | python-whois |
| Brand Match (text) | python-Levenshtein |
| Brand Match (visual) | Pillow, ImageHash (perceptual hashing) |
| Page Analysis | BeautifulSoup4, tldextract |
| SSL Analysis | cryptography, ssl, socket |
| QR Decoding | OpenCV (`cv2.QRCodeDetector`) |
| Redirect Tracing | requests (manual hop-by-hop resolution) |
| Network safety | `ipaddress`, `socket` (SSRF guard) |
| Alerting | requests (Slack/Discord-compatible webhooks) |

---

## 📁 Project Structure

```
phishing-url-detection/
│
├── static/
│   ├── style.css              # Global stylesheet
│   ├── admin_pro.css          # Admin panel theme (layered on top of admin.html's styles)
│   └── admin_pro.js           # Admin polish: status dots, avatar, "View all" links
│
├── templates/
│   ├── index.html             # Landing page
│   ├── login.html             # User login
│   ├── register.html          # User registration
│   ├── dashboard.html         # URL scan page
│   ├── result.html            # Scan result (explainability, WHOIS, typosquat, SSL,
│   │                          #   redirect chain, favicon match, page analysis)
│   ├── scan_qr.html           # QR code upload page
│   ├── bulk_scan.html         # Bulk CSV upload page
│   ├── bulk_results.html      # Bulk scan batch report
│   ├── history.html           # User scan history
│   ├── admin_login.html       # Admin login
│   ├── admin.html             # Admin dashboard (includes admin_extra.html)
│   └── admin_extra.html       # Analytics + Security Centre sections
│
├── utils/
│   ├── features.py            # URL feature extraction (domain-scoped)
│   ├── vt_api.py              # VirusTotal integration (key from .env)
│   ├── explain.py             # Explainable prediction reasoning
│   ├── whois_check.py         # Domain age / WHOIS lookup
│   ├── typosquat_check.py     # Text-based brand impersonation detection
│   ├── ssl_check.py           # SSL/TLS certificate inspection
│   ├── qr_check.py            # QR code decoding
│   ├── bulk_check.py          # Bulk CSV parsing
│   ├── net_safety.py          # SSRF guard: safe_get(), check_url_safe(), size caps
│   ├── risk.py                # Combines all evidence into one explainable risk score
│   ├── redirect_check.py      # Shortener expansion + SSRF-checked redirect tracing
│   ├── page_check.py          # Page content analysis (forms, iframes, obfuscation …)
│   ├── favicon_check.py       # Favicon perceptual-hash similarity (SSRF-safe)
│   ├── known_favicons.json    # Known-brand favicon hashes (built offline)
│   └── alert.py               # Webhook/Slack/Discord alerting
│
├── extension/                 # Chrome extension (Manifest V3)
│   ├── manifest.json
│   ├── shared.js              # API client shared by popup and background worker
│   ├── background.js          # Right-click "Scan link with PhishGuard"
│   ├── popup.html / popup.js / popup.css
│
├── scripts/
│   ├── build_favicon_db.py    # One-time script to populate known_favicons.json
│   ├── build_dataset.py       # Builds dataset.csv from PhishTank + OpenPhish + Tranco
│   ├── ablation.py            # Feature-removal experiment (what does the model rely on?)
│   └── stress_test.py         # False-positive check on obscure legitimate domains
│
├── app.py                     # Main Flask application
├── api.py                     # REST API blueprint + API-key management
├── model.py                   # Model training; saves metrics to model_metrics.json
├── phishing_model.pkl         # Trained model (generated by model.py, not committed)
├── model_metrics.json         # Latest evaluation metrics
├── dataset.csv                # Training dataset (generated by scripts/build_dataset.py, not committed)
├── LICENSE                    # MIT
├── requirements.txt           # Python dependencies
├── .env                       # Secret credentials (never committed)
├── .env.example               # Template for required environment variables
├── .gitignore
└── README.md
```

---

## ⚙️ Setup & Installation

### 1. Clone the repository
```bash
git clone https://github.com/your-username/phishing-url-detection.git
cd phishing-url-detection
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Create your `.env` file
Create a file named `.env` in the project root:

```env
ADMIN_USERNAME=your_admin_email
ADMIN_PASSWORD=your_admin_password   # used until you change it in Admin > Settings
SECRET_KEY=generate_a_random_secret_here

# VirusTotal API key — required for the VirusTotal check.
# Free key: https://www.virustotal.com/gui/join-us
VT_API_KEY=

# Optional — Slack or Discord incoming-webhook URL.
# If unset, alerting is silently skipped.
ALERT_WEBHOOK_URL=
ALERT_RISK_THRESHOLD=70

# Optional — path of the SQLite file (default: users.db)
DB_PATH=users.db

# Production only (behind HTTPS and exactly one reverse proxy, e.g. Render)
# SESSION_COOKIE_SECURE=1   # send the session cookie over HTTPS only
# TRUST_PROXY=1             # trust X-Forwarded-For/Host so rate limits use the real client IP
# REQUIRE_SECRETS=1         # refuse to start while SECRET_KEY / ADMIN_PASSWORD are still the defaults
```
A ready-made template is in `.env.example`.

Generate a strong secret with:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```
The app prints a warning at startup if `SECRET_KEY` or `ADMIN_PASSWORD` are still the insecure defaults (set `REQUIRE_SECRETS=1` in production to make it refuse to start instead).

**Changing the admin password:** edit `ADMIN_PASSWORD` in `.env`, or use **Admin → Settings → Change Admin Password**. A password changed in Settings is stored *hashed in the database* and survives restarts; from then on it takes precedence over `.env`. If you forget it, delete that override and the `.env` password applies again:
```bash
python -c "import sqlite3; c=sqlite3.connect('users.db'); c.execute(\"DELETE FROM settings WHERE key='admin_password_hash'\"); c.commit()"
```

**Never hardcode the VirusTotal API key in `utils/vt_api.py`** — it is read from `VT_API_KEY`. If an old copy of the project had a key hardcoded, rotate it in your VirusTotal account immediately.

### 4. Build the favicon brand database (one-time)
```bash
python scripts/build_favicon_db.py
```
Edit the `BRANDS` list at the top of that script to add or remove brands. The app works without this step; the favicon check simply reports that no database was found.

### 5. Build the dataset and train the model
```bash
python scripts/build_dataset.py --username yourname   # downloads PhishTank + OpenPhish + Tranco -> dataset.csv
python model.py                                       # compares models, saves phishing_model.pkl + model_metrics.json
```
Anonymous PhishTank downloads are limited to a few per day; a free application key from phishtank.org (`--phishtank-key`) removes the limit. Optional: `python scripts/ablation.py` shows which features the model depends on.
**Always re-run this after changing `utils/features.py`.** The model learns from whatever feature extraction existed at training time; if the live feature logic changes without retraining, the model silently scores features it was never trained on.

### 6. Run the application
```bash
python app.py
```
Open **http://127.0.0.1:5000**. For local debugging set `FLASK_DEBUG=1` (never enable it on a reachable server — the Werkzeug debugger allows code execution).

For production use a WSGI server, e.g. `gunicorn app:app`.

---

## 🔌 REST API

Every user can create a personal API key at **`/account/api-key`** (also linked in the navigation bar). The key is shown **once**; the server stores only its SHA-256 hash. Clicking *Replace key* immediately invalidates the old one.

### `POST /api/v1/scan`

Headers: `X-API-Key: pg_...` (or `Authorization: Bearer pg_...`), `Content-Type: application/json`

```bash
curl -X POST http://127.0.0.1:5000/api/v1/scan \
  -H "X-API-Key: pg_your_key_here" \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal-login-security.xyz"}'
```

Response:
```json
{
  "url": "http://paypal-login-security.xyz",
  "final_url": "http://paypal-login-security.xyz",
  "verdict": "phishing",
  "risk": 90,
  "model_probability": 88,
  "risk_breakdown": [{"label": "VirusTotal: 14 engines flag it as malicious", "points": 70}],
  "reasons": ["Domain contains a hyphen, often used to mimic real brand names"],
  "page_findings": [],
  "details": {
    "domain_info": {}, "typosquat": {}, "ssl": {}, "redirects": {},
    "favicon": {}, "virustotal": "...", "page": {}
  }
}
```

`verdict` is `phishing`, `safe` or `blocked` (the URL points to a private/internal address or uses an unsupported scheme, so no request was made to it).

### `GET /api/v1/health`
Unauthenticated; returns `{"status": "ok"}`. Used by the extension's "Test connection" button.

### Errors

| Status | Meaning |
|--------|---------|
| 400 | Missing/invalid `url` (must start with `http://` or `https://`, max 2048 chars) |
| 401 | Missing or invalid API key |
| 429 | Rate limit exceeded (30 requests / 60 s per key); see the `Retry-After` header |

### Python example
```python
import requests

r = requests.post(
    "http://127.0.0.1:5000/api/v1/scan",
    headers={"X-API-Key": "pg_your_key_here"},
    json={"url": "https://bit.ly/example"},
    timeout=60,
)
data = r.json()
print(data["verdict"], data["risk"], data["final_url"])
```

> Scans take a few seconds because they include WHOIS, SSL, VirusTotal and page fetching — use a generous timeout. The API-key rate limiter is in-memory and per-process; with several workers use a shared store (Redis / Flask-Limiter). Login and sign-up limits are different: they are stored in SQLite and shared by all workers.

---

## 🧩 Chrome Extension

The extension talks to your PhishGuard server through the REST API.

1. Open `chrome://extensions` and enable **Developer mode**.
2. Click **Load unpacked** and select the `extension/` folder.
3. Open the extension popup → **Settings**, enter your server address (e.g. `http://127.0.0.1:5000`) and your API key, then **Save**. **Test connection** checks the server is reachable.
4. Use it:
   - **Scan this page** in the popup scans the current tab.
   - **Right-click any link → "Scan link with PhishGuard"** shows the verdict in an alert.

Notes:
- A page or link is only sent to your server when **you** press the button — nothing is scanned automatically, so your browsing history isn't streamed anywhere.
- `host_permissions` in `manifest.json` cover `127.0.0.1:5000`, `localhost:5000` and `*.onrender.com`. If you deploy elsewhere, add your domain there.
- The popup renders server text with `textContent` only, so a malicious page cannot inject HTML or script into the extension through a scan result.

---

## 🔐 Admin Panel

Open **http://127.0.0.1:5000/admin/login**. The panel has a Dashboard, Users, Login Activity, All Scans, Phishing Detections and Settings, plus two sections added in `templates/admin_extra.html`:

**📈 Analytics**
- Scans per day (last 14 days, safe vs phishing), verdict split, risk-score distribution and where scans come from (web / QR / bulk / API)
- Most-flagged domains and most active users
- **Detection model card** read from `model_metrics.json`: algorithm, training date, dataset size, accuracy / precision / recall / F1 / ROC AUC and top feature importances
- **CSV export** of scans, users and logins (spreadsheet-formula injection is neutralised, and password hashes are never exported)

**⚙️ Settings**
- Change the admin password (stored hashed in the database; survives restarts) and clear scan or login history

**🛡️ Security Centre**
- **Accounts:** disable or re-enable a user (a disabled user is logged out immediately and cannot log back in)
- **Failed-login sources** from the rate limiter, with one-click **Unlock**
- **API keys** of all users, with **Revoke**
- Integration checklist: VirusTotal key, alert webhook, non-default `SECRET_KEY`, non-default admin password

**Interface:** the panel keeps your original `admin.html` and layers a consistent dark theme on top (`static/admin_pro.css`, `static/admin_pro.js`): line icons instead of emoji, one row of stat cards, tidy activity lists, an admin avatar and "View all" links. Charts need internet access to load Chart.js from cdnjs.

Deleting a user also removes their scans, logins, API key and rate-limit entries, and the panel returns to the tab you were on with a message saying what happened. Scan dates are recorded from the day the dashboard was upgraded; older scans stay undated and appear as source "unknown".

---

## 🗄️ Database

The app uses **SQLite** (`users.db`, or the path in `DB_PATH`) with tables `users` (incl. `disabled`, `created_at`), `history` (incl. `scanned_at`, `source`), `logins`, `api_keys`, `settings` (the persistent admin password hash) and `rate_events` (the rate-limit counters). Tables are created automatically at startup and older databases are upgraded in place; no data is lost. On hosts with an ephemeral filesystem (e.g. Render's free tier) the file is wiped on every restart or redeploy; use a persistent disk or add a PostgreSQL backend if you need durable data (see Roadmap).

---

## 🧠 How It Works

```
URL submitted (typed, decoded from QR, read from CSV, or sent via API / extension)
        ↓
Redirect Chain Tracing — expand shorteners, follow every hop,
validate EVERY hop against the SSRF guard           (utils/redirect_check.py)
        ↓                         └─ private/internal target → BLOCKED, scan stops
Feature Extraction on the FINAL url, domain-scoped  (utils/features.py)
        ↓
ML Model Prediction                                  (phishing_model.pkl)
        ↓
Explainability — why was this flagged?               (utils/explain.py)
        ↓
WHOIS Domain Age Check                               (utils/whois_check.py)
        ↓
Typosquatting / Brand Impersonation Check            (utils/typosquat_check.py)
        ↓
SSL Certificate Inspection                           (utils/ssl_check.py)
        ↓
VirusTotal API Check                                 (utils/vt_api.py)
        ↓
Favicon Visual Similarity — phash vs known brands    (utils/favicon_check.py)
        ↓
Page Content Analysis — forms, iframes, obfuscation,
brand/domain mismatch                                (utils/page_check.py)
        ↓
Combine all evidence into one risk score + verdict       (utils/risk.py)
        ↓
Result displayed / returned as JSON with full risk breakdown
        ↓
Saved to scan history (database)
        ↓
Webhook alert fired if risk crosses threshold        (utils/alert.py)
```

**Risk logic (`utils/risk.py`):** the verdict is **not** the ML model's alone. The model only sees a URL's origin, and a feature-ablation experiment showed it leans heavily on length-type cues, so it is treated as a *weak prior*: it sets a starting score of 15–60 depending on its probability, and independent evidence then moves the score up or down. A score of **60 or more is phishing**.

| Evidence | Effect on score |
|----------|----------------|
| ML model probability | +15 … +60 (starting point) |
| VirusTotal: ≥5 engines malicious / 2–4 / 1 | +70 / +35 / +10 |
| VirusTotal: no engine flags it | −15 |
| Favicon copies a known brand on the wrong domain | +70 |
| Page content: credential form posting to another site, or brand-named login on the wrong domain | +70 (other page signals up to +15) |
| Typosquatting / brand impersonation | +40 |
| Domain registered < 30 days / < 180 days ago | +25 / +10 |
| Domain older than 2 years | −12 |
| No valid SSL certificate / valid certificate | +8 / −3 |
| 2+ hop redirect chain | +10 |

Reassuring evidence is halved when strong warning signs are present, so a hacked old domain can't "launder" a credential-stealing page. Every contribution is shown in the **Risk Breakdown** box on the result page and returned by the API, so no score is a black box. The weights are judgement calls and should be tuned on labelled data.

### Why the final URL, not the typed URL?
Phishing links are very often hidden behind a shortener or redirect chain precisely to defeat URL-based checks. Every check after redirect tracing runs against the **resolved final destination**.

### Feature Extraction Details (`utils/features.py`)

The model sees **15 features computed from the URL's origin only** (`scheme://host[:port]`). `FEATURE_NAMES` in `utils/features.py` is the single source of truth: `model.py`, `utils/explain.py` and `app.py` all import it, and `app.py` refuses to start if the saved model was trained on a different number of features.

| Feature | Meaning |
|---------|---------|
| `url_length` | Length of `scheme://host[:port]` |
| `has_at_symbol` | `@` inside the authority (`paypal.com@evil.net` trick) — not in the path, so `medium.com/@user` is fine |
| `dot_count`, `subdomain_count` | Dots in the host; nested subdomains (leading `www` ignored) |
| `has_https` | Real scheme, not a substring search |
| `has_hyphen`, `hyphen_count` | Hyphens in the **host** |
| `digit_ratio` | Digits ÷ host length |
| `domain_entropy` | Shannon entropy of the registrable label (random-looking names) |
| `suspicious_tld` | TLD heavily abused for phishing (`.xyz`, `.top`, `.tk`, …) |
| `is_ip_host` | Raw IP instead of a domain |
| `has_punycode` | `xn--` labels (IDN lookalikes) |
| `host_keyword_count` | `login`, `verify`, `secure`, … inside the host |
| `has_nonstandard_port` | Port other than 80/443 |
| `brand_in_host_mismatch` | A known brand name in the host, but not that brand's real domain |

**Why origin-only?** Path and query features cause false positives on legitimate links (an earlier whole-URL version flagged `meet.google.com/tbj-dudh-fex` at 90% because of hyphens in the room code), and the legitimate training data (Tranco) contains only domains, so a model could never learn anything real from paths — it would just learn "has a path ⇒ phishing". Path-level signals are covered by page content analysis and VirusTotal instead.

**Always re-run `python model.py` after changing `utils/features.py`.**

---

### SSRF Protection (`utils/net_safety.py`)

A scanner that fetches URLs supplied by strangers is itself an attack surface: without protection, someone could submit `http://169.254.169.254/` (cloud metadata) or `http://127.0.0.1:5000/admin` and make **your server** request it. `safe_get()` therefore:

- allows only `http`/`https` on ports 80, 443, 8080, 8443
- resolves the hostname and rejects private, loopback, link-local, CGNAT and reserved addresses
- follows redirects manually and **re-validates every hop**
- caps response bodies (1 MB pages, 300 KB favicons) and image pixel counts
- treats an unresolvable domain as *unreachable*, not as an attack (taken-down phishing sites are common)

Redirect tracing, page analysis and favicon download all use it. If a URL (or any redirect hop) is blocked, the scan stops before any other network check runs.

**Known limit:** DNS is resolved once for the check and again by `requests`, so a DNS-rebinding attacker could race it. Full protection needs connecting to the validated IP directly or running the fetcher in a network-isolated sandbox.

---

## 📦 Requirements

```
flask
scikit-learn
pandas
numpy
joblib
requests
python-dotenv
python-whois
python-Levenshtein
cryptography
opencv-python-headless
Pillow
imagehash
beautifulsoup4
tldextract
gunicorn          # production only
```

```bash
pip install -r requirements.txt
```

---

## 🔒 Security Notes

- Never commit `.env` — it is listed in `.gitignore`. Never share your VirusTotal key, webhook URL or API keys.
- Set a real `SECRET_KEY` and `ADMIN_PASSWORD` before deploying; the defaults are for local development only. `REQUIRE_SECRETS=1` enforces this at startup.
- The admin password changed in Settings is stored only as a salted hash; changing `ADMIN_PASSWORD` in `.env` afterwards has no effect until that override is deleted (see "Changing the admin password").
- User passwords are hashed; API keys are stored only as SHA-256 hashes and shown once.
- All outbound fetches go through the SSRF guard (see above).
- Page analysis never executes JavaScript from the scanned site; only the HTML is parsed.
- Bulk scans are capped at 100 URLs per upload.
- WHOIS lookups can fail or be rate-limited — the app shows "unavailable" instead of crashing.
- Redirect tracing is capped at 8 hops and detects loops.
- Webhook alerting is best-effort: a broken webhook never makes a scan fail.
- The favicon check only flags a **visual clone** when a close brand match appears on a domain that isn't that brand's own; having no match never raises risk.
- `ssl_check.py` connects to the host that the SSRF-checked redirect trace resolved; it is not yet pinned to a validated IP (see the DNS-rebinding note above).
- CSRF protection relies on `SameSite=Lax` cookies plus Origin/Referer verification (OWASP's defence-in-depth approach), not per-form tokens; a synchronizer token would be a further layer (see Roadmap). Behind a proxy, set `TRUST_PROXY=1` so the host comparison and rate limiting see the real values.
- Login lockouts are per account **and** IP, so an attacker cannot lock a victim out from a different address.
- No Content-Security-Policy yet: the templates use inline styles and scripts, which a strict CSP would block.

---

## 🐞 Known Issues / Fix Log

- **Fixed:** `extract_features()` counted hyphens and dots across the whole URL, flagging legitimate links like Google Meet room codes. Structural checks are now domain-only.
- **Fixed:** the HTTPS check searched for the substring `"https"` anywhere in the URL; it now reads `urlparse(url).scheme`.
- **Fixed:** `utils/vt_api.py` had a real API key hardcoded and an undefined `VT_SCAN_URL`. The key is now loaded strictly from `VT_API_KEY`.
- **Fixed:** `load_dotenv()` was imported but never called, so `.env` values were ignored. It now runs before any environment variable is read.
- **Fixed:** the redirect tracer and favicon check fetched arbitrary URLs without SSRF protection; they now use `safe_get()`.
- **Fixed:** the last hop of a redirect chain that hit the hop limit was never validated.
- **Fixed:** user passwords were stored in plaintext; they are now hashed (existing rows migrate on login).
- **Fixed:** the delete-user redirect put the raw username in the URL (now URL-encoded) and `register` could leak a connection on error.
- **Fixed:** the admin panel's delete actions gave no feedback ("User deleted" was shown even when nothing was deleted). They now report the real outcome and return to the tab you were on.
- **Fixed:** the admin Settings page changed the password only in memory, so it silently reverted to the `.env` value (or `admin123`) after a restart. It is now stored hashed in the database.
- **Fixed:** login, admin login and registration had no brute-force protection and no CSRF defence; both are now in place (see "Security Hardening").
- **Fixed:** page analysis flagged Google Meet for "obfuscated JavaScript". Obfuscation is now a medium warning only on pages that ask for a password, and a weak hint elsewhere.
- **Fixed:** the scanner identified itself with an unusual User-Agent, so some sites (e.g. Google Meet) redirected it to an "unsupported browser" page; it now sends a normal browser User-Agent.
- **Fixed:** VirusTotal returning all-zero counts (a URL it hasn't analysed yet) was displayed as "CLEAN"; it now reads "no analysis results yet" and earns no trust credit.
- **Fixed:** the model was trained on 6 URLs. It now trains on ~10,000 real URLs with a domain-grouped evaluation (see "Model Performance").
- **Known limitation:** the model sees only the origin, and its legitimate training data is popularity-biased (see "How to read these numbers honestly"); about 7% of legitimate test sites are flagged and 23% of phishing sites are missed by the model alone.
- **Note:** `phishing_model.pkl` must be retrained (`python model.py`) whenever `utils/features.py` changes.

---

## 🗺️ Roadmap

- Calibrate the risk-score weights on labelled data (they are currently judgement calls)
- Automated tests (`pytest`) for the risk scoring, SSRF guard, rate limiting and admin routes
- Add real legitimate URLs with paths and obscure domains to the dataset to reduce popularity bias
- Full model-comparison page in the web UI (the admin model card already shows the deployed model; the comparison table is in `model_metrics.json`)
- Homograph / punycode (IDN) detection alongside typosquatting
- Email (`.eml`) analysis: extract links, check SPF/DKIM/DMARC and reply-to mismatches
- Sandboxed screenshot of the destination page
- PhishTank / OpenPhish threat-feed lookup as a fast first pass
- Per-form CSRF tokens (Flask-WTF) and a Content-Security-Policy on top of the existing Origin check
- Password-reset flow and optional two-factor login
- PostgreSQL backend for persistent hosting; shared rate-limit store
- PDF scan reports

---

## 📄 License

Released under the [MIT License](LICENSE). Built as a cybersecurity/ML academic project.

**Data:** the training dataset is *not* included in this repository. `scripts/build_dataset.py` downloads it from [PhishTank](https://phishtank.org/), [OpenPhish](https://openphish.com/) and the [Tranco list](https://tranco-list.eu/); please follow each provider's terms of use (PhishTank and OpenPhish restrict some commercial uses).

**Responsible use:** this tool only analyses URLs and pages; it never executes JavaScript from scanned sites, and it blocks requests to private/internal addresses. Its verdicts are a signal, not a guarantee. Don't rely on it as your only defence.

---

## 👨‍💻 Author

**Vansh Saxena**  
📧 saxenavansh1236@gmail.com
