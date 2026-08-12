# 🛡️ Phishing URL Detection System

A machine learning-powered web application that detects phishing URLs in real time, built with Python and Flask.

---

## 📸 Overview

This project uses a trained machine learning model combined with the VirusTotal API to analyze URLs and determine whether they are **safe** or **phishing attempts**. It includes a full user authentication system and a powerful admin panel for monitoring all activity.

Beyond basic classification, the system performs deep contextual analysis on every scan — explaining *why* a URL was flagged, checking domain age, detecting brand impersonation (both textual and **visual**), inspecting SSL certificates, unwrapping shortened/redirect-chained links, alerting a webhook on high-risk detections, and supporting both QR code and bulk CSV scanning for SOC-style workflows.

---

## 📊 Model Performance

Metrics are computed automatically by `model.py` on a held-out test split and saved to `model_metrics.json`:

| Metric | Value |
|--------|-------|
| Dataset size | 6 URLs |
| Train / Test split | 4 / 2 |
| Accuracy | 100% |
| Precision | 100% |
| Recall | 100% |
| F1-score | 100% |
| Confusion matrix | `[[1, 0], [0, 1]]` (format: `[[TN, FP], [FN, TP]]`) |

> ⚠️ **Important caveat:** the current `dataset.csv` used for training contains only **6 labeled URLs** (4 train / 2 test). Metrics from a dataset this small are **not statistically meaningful** — a 100% score here reflects that both test examples happened to be classified correctly, not that the model generalizes well to real, unseen phishing URLs. These numbers should be treated as proof that the evaluation pipeline works correctly, not as a real accuracy claim.
>
> **To get a trustworthy accuracy figure**, the dataset needs to be expanded to at least a few hundred labeled URLs (a mix of confirmed phishing and legitimate sites) — e.g. from [PhishTank](https://phishtank.org/) for phishing examples and the [Tranco list](https://tranco-list.eu/) or Kaggle's "Phishing URL Dataset" for a larger, more representative set of legitimate URLs. Re-run `python model.py` after expanding `dataset.csv` — it regenerates `phishing_model.pkl` and overwrites `model_metrics.json` with real numbers.

---

## ✨ Features

### Core Detection
- 🔍 **ML-Based Detection** — Trained model analyzes URL patterns to classify phishing vs safe URLs
- 🦠 **VirusTotal Integration** — Cross-checks URLs against 70+ antivirus engines via the VirusTotal API
- 👤 **User Authentication** — Register, login, and logout functionality with session management
- 📋 **Scan History** — Every user can view their personal scan history
- 🛡️ **Admin Panel** — Full dashboard with user management, scan records, and threat monitoring
- 📊 **Risk Scoring** — Each scan gets a risk score with a visual progress bar
- 🔐 **Secure Credentials** — Environment variables used to protect sensitive data (admin credentials, VirusTotal API key)

### Advanced Threat Analysis
- 🧠 **Explainable Predictions** — Every flagged URL shows the specific reasons it was classified as phishing (URL length, domain hyphen count, HTTPS scheme, domain dot/subdomain depth, `@` symbol presence, etc.), not just a verdict. Structural checks (hyphen count, dot count) are evaluated against the **parsed domain (`netloc`) only** — never the full URL string — so a hyphenated path or query string (e.g. a Google Meet code like `meet.google.com/tbj-dudh-fex`) is never mistaken for a suspicious domain. The HTTPS check reads the actual URL **scheme** (`urlparse(url).scheme`) rather than searching for the substring `"https"` anywhere in the URL, so a plain-`http://` link with the word "https" somewhere in its path can't slip through as secure
- 🌐 **WHOIS Domain Age Lookup** — Checks how recently a domain was registered; freshly registered domains (under 30 days) are flagged as high risk, since this is one of the strongest real-world phishing signals
- 🎭 **Typosquatting Detection** — Compares scanned domains against well-known brands (PayPal, Google, Amazon, major banks, etc.) using edit-distance matching to catch impersonation attempts like `paypa1.com` or `g00gle.com`
- 🔒 **SSL Certificate Inspection** — Flags missing certificates, expired certificates, self-signed certificates, and identifies the issuing CA
- 🔗 **Redirect Chain Tracing & Shortener Expansion** — Automatically expands shortened links (bit.ly, tinyurl, t.co, etc.) and follows the *entire* redirect chain (up to 8 hops, loop-safe) to the real final destination. The ML model, WHOIS, typosquat, SSL, VirusTotal, and favicon checks all scan the **resolved final URL**, not the shortener link — closing a major real-world evasion technique where the real malicious domain hides behind a shortener
- 🖼️ **Favicon Visual Similarity Detection** — Uses perceptual image hashing (phash) to compare a scanned site's favicon against a local database of known-brand favicons. If a site's icon closely matches a trusted brand (e.g. PayPal, Google, a major bank) **but its domain isn't that brand's real domain**, it's flagged as a likely visual clone/impersonation attempt — catching phishing pages that pass every text-based check but visually copy a brand's identity
- 📣 **Webhook / Slack Alerting** — Automatically fires a webhook notification (Slack- and Discord-compatible) whenever a scan crosses a configurable risk threshold, turning the tool from a passive scanner into something that can sit inside a live monitoring pipeline

### Scanning Methods
- 📷 **QR Code Scanning** — Upload a QR code image to extract and scan its embedded URL, defending against "quishing" (QR phishing) attacks where malicious links are hidden inside QR codes instead of typed out
- 📋 **Bulk URL Upload** — Upload a CSV of multiple URLs (e.g. links pulled from a suspicious email) and get a single batch report showing verdict, risk score, redirect chain, SSL status, domain age, and typosquat flags for every URL at once — built for SOC-analyst-style triage workflows

---

## 🖥️ Tech Stack

| Layer            | Technology                          |
|-------------------|--------------------------------------|
| Backend           | Python, Flask                        |
| Database          | SQLite (local dev) / PostgreSQL (production, via `DATABASE_URL`) |
| ML Model          | Scikit-learn (RandomForestClassifier), Joblib |
| Frontend          | HTML, CSS, Jinja2                    |
| Security API      | VirusTotal v3 API                    |
| Auth              | Flask Sessions                       |
| Domain Intel      | python-whois                         |
| Brand Match (text)| python-Levenshtein                   |
| Brand Match (visual)| Pillow, ImageHash (perceptual hashing) |
| SSL Analysis      | cryptography, ssl, socket            |
| QR Decoding       | OpenCV (cv2.QRCodeDetector)          |
| Redirect Tracing  | requests (manual hop-by-hop resolution) |
| Alerting          | requests (Slack/Discord-compatible webhooks) |

---

## 📁 Project Structure

phishing-url-detection/
│
├── static/
│ └── style.css # Global stylesheet
│
├── templates/
│ ├── index.html # Landing page
│ ├── login.html # User login
│ ├── register.html # User registration
│ ├── dashboard.html # URL scan page
│ ├── result.html # Scan result display (explainability, WHOIS, typosquat,
│ │ # SSL, redirect chain, favicon visual match)
│ ├── scan_qr.html # QR code upload page
│ ├── bulk_scan.html # Bulk CSV upload page
│ ├── bulk_results.html # Bulk scan batch report (incl. redirect chain column)
│ ├── history.html # User scan history
│ ├── admin_login.html # Admin login
│ └── admin.html # Admin dashboard
│
├── utils/
│ ├── feature.py # URL feature extraction (domain-scoped — see "Feature
│ │ # Extraction Details" below)
│ ├── vt_api.py # VirusTotal API integration (key loaded from .env)
│ ├── explain.py # Explainable prediction reasoning
│ ├── whois_check.py # Domain age / WHOIS lookup
│ ├── typosquat_check.py # Text-based brand impersonation detection
│ ├── ssl_check.py # SSL/TLS certificate inspection
│ ├── qr_check.py # QR code decoding
│ ├── bulk_check.py # Bulk CSV parsing
│ ├── redirect_check.py # Shortener expansion + full redirect chain tracing
│ ├── favicon_check.py # Favicon perceptual-hash visual similarity detection
│ ├── known_favicons.json # Local database of known-brand favicon hashes (built offline)
│ ├── alert.py # Webhook/Slack/Discord high-risk alerting
│ └── database.py # Database utilities
│
├── scripts/
│ └── build_favicon_db.py # One-time offline script to populate known_favicons.json
│
├── app.py # Main Flask application (SQLite locally, Postgres in production)
├── model.py # ML model training script — now also computes and saves
│ # accuracy/precision/recall/F1 to model_metrics.json
├── phishing_model.pkl # Trained ML model
├── model_metrics.json # Latest training run's evaluation metrics (see "Model Performance")
├── dataset.csv # Training dataset
├── requirements.txt # Python dependencies
├── .env # Secret credentials (not uploaded)
├── .env.example # Template for required environment variables
├── .gitignore # Git ignored files
└── README.md # Project documentation


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

ADMIN_USERNAME=your_admin_email
ADMIN_PASSWORD=your_admin_password
SECRET_KEY=generate_a_random_secret_here

VirusTotal API key — required for the VirusTotal check to work.
Get a free key at: https://www.virustotal.com/gui/join-us

VT_API_KEY=

Optional — webhook alerting (Slack or Discord incoming webhook URL).
If left unset, alerting is silently skipped and the app works normally.

ALERT_WEBHOOK_URL=
ALERT_RISK_THRESHOLD=70

Optional — set only in production (e.g. Render). If unset, the app
falls back to a local SQLite file automatically.

DATABASE_URL=


**Never hardcode the VirusTotal API key directly in `utils/vt_api.py`** — it's loaded from the `VT_API_KEY` environment variable at runtime. If you're editing an older copy of this project where the key was hardcoded, rotate/regenerate that key in your VirusTotal account immediately, since a hardcoded key is one accidental `git push` away from being publicly exposed.

### 4. Build the favicon brand database (one-time, offline)
Run this once from a machine with normal internet access to populate `utils/known_favicons.json` with real perceptual hashes for well-known brands (PayPal, Google, Amazon, major banks, etc.):
```bash
python scripts/build_favicon_db.py
```
Add or remove brands by editing the `BRANDS` list at the top of that script. The app runs fine without this step — the favicon check simply reports "no known-brand database found" until it's populated.

### 5. Train (or re-train) the model
```bash
python model.py
```
This computes accuracy, precision, recall, F1-score, and a confusion matrix on a held-out test split, prints them to the console, and saves them to `model_metrics.json`.

**Always re-run this after changing `utils/feature.py`.** The model is trained on whatever feature-extraction logic exists at training time — if the live app's feature extraction changes shape or meaning (e.g. domain-only vs whole-URL counts) without retraining, `phishing_model.pkl` will be scoring features it was never actually trained on, which silently degrades accuracy instead of raising an error.

**A note on dataset size:** metrics computed from a very small dataset (see "Model Performance" above) aren't statistically reliable. If you're expanding `dataset.csv`, aim for at least a few hundred labeled URLs before treating the printed metrics as a real accuracy claim.

### 6. Run the application
```bash
python app.py
```

### 7. Open in browser

http://127.0.0.1:5000


---

## 🔐 Admin Panel

Access the admin panel at:

http://127.0.0.1:5000/admin/login


Admin features include:
- 📊 Dashboard with live stats (total users, scans, detection rate)
- 👥 User management (view and delete users)
- 🔍 All scan records with risk scores
- 🚨 Phishing-only detections view
- 🕵️ Login activity log (username, IP, user agent, timestamp)
- ⚙️ Settings (change admin password, clear scan history, clear login history)

---

## 🗄️ Database

The app uses **SQLite** locally by default (`users.db`), requiring zero setup. In production (e.g. Render's free tier), the filesystem is ephemeral — anything written to a local SQLite file is wiped on every restart or redeploy. To persist data in production, set the `DATABASE_URL` environment variable to a PostgreSQL connection string; the app automatically switches to Postgres whenever `DATABASE_URL` is present, with no code changes needed. All queries are written once and translated to the correct SQL dialect for whichever backend is active (see `q()` and `ph()` in `app.py`).

---

## 🧠 How It Works

URL submitted (typed, decoded from QR, or read from CSV)
↓
Redirect Chain Tracing — expand shorteners, follow every hop
(utils/redirect_check.py) → resolves to the FINAL destination URL
↓
Feature Extraction on the final URL, domain-scoped (utils/feature.py)
↓
ML Model Prediction (phishing_model.pkl)
↓
Explainability — why was this flagged? (utils/explain.py)
↓
WHOIS Domain Age Check (utils/whois_check.py)
↓
Typosquatting / Text-Based Brand Impersonation Check (utils/typosquat_check.py)
↓
SSL Certificate Inspection (utils/ssl_check.py)
↓
Favicon Visual Similarity Check — perceptual hash vs known brands
(utils/favicon_check.py)
↓
VirusTotal API Check (utils/vt_api.py)
↓
Result displayed with full risk breakdown (incl. redirect chain + favicon match)
↓
Saved to scan history (database)
↓
Webhook alert fired if risk crosses threshold (utils/alert.py)


### Why the final URL, not the typed URL?
Every check after redirect tracing — the ML model, WHOIS, typosquat, SSL, favicon, and VirusTotal — runs against the **resolved final destination**, not whatever the user originally pasted in. This matters because a phishing link is very often hidden behind a URL shortener or a chain of redirects specifically to defeat exactly these kinds of checks; scanning the shortener link itself would tell you almost nothing.

### Feature Extraction Details (`utils/feature.py`)

All structural features are computed from the **parsed URL**, not the raw string, to avoid misreading the path/query as if it were the domain:

```python
from urllib.parse import urlparse

def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc  # e.g. "meet.google.com" — excludes path/query

    features = []

    # URL Length — kept as the full URL; overall length is a legitimate whole-URL signal
    features.append(len(url))

    # Has @ symbol — kept as full URL; an @ anywhere is a classic destination-hiding trick
    features.append(1 if '@' in url else 0)

    # Count dots — DOMAIN ONLY; subdomain depth (e.g. paypal.com.verify-login.xyz)
    # is the real signal, not dots that happen to sit in a path or query string
    features.append(domain.count('.'))

    # HTTPS check — actual scheme, not a substring search over the whole URL
    features.append(1 if parsed.scheme == 'https' else 0)

    # Has hyphen — DOMAIN ONLY; a hyphenated path (e.g. a Google Meet room code
    # like /tbj-dudh-fex) is completely unrelated to domain-based brand mimicry
    features.append(1 if '-' in domain else 0)

    return features
```

**Why this matters in practice:** the earlier, whole-URL version of this function flagged legitimate links like `https://meet.google.com/tbj-dudh-fex` as high-risk (90%) purely because of hyphens in the Google Meet room code — a false positive with only one contributing signal. Scoping the hyphen/dot checks to `domain` instead of the full `url` string closes that gap without needing a hard-coded allow-list of "trusted" domains, which would itself be a soft spot for attackers to target (e.g. via open redirects or subdomain takeovers on an allow-listed domain).

### Scanning Methods
- **Typed URL** → `/dashboard` → runs the full pipeline above
- **QR Code Image** → `/scan-qr` → decodes the embedded URL, then runs the same pipeline
- **Bulk CSV Upload** → `/bulk-scan` → runs the pipeline on every URL in the file (up to 100 per upload) and returns a single batch report, including the redirect chain for each row

---

## 📦 Requirements

flask
scikit-learn
joblib
requests
python-dotenv
python-whois
python-Levenshtein
cryptography
opencv-python-headless
Pillow
imagehash
psycopg2-binary


Install all with:
```bash
pip install -r requirements.txt
```

---

## 🔒 Security Notes

- Never upload your `.env` file to GitHub — it is listed in `.gitignore`
- Never hardcode or share your VirusTotal API key, webhook URL, or database credentials publicly — all are loaded from environment variables, never committed to source
- Change the default `app.secret_key` / `SECRET_KEY` before deploying
- Bulk scans are capped at 100 URLs per upload to prevent server overload
- WHOIS lookups may fail or be rate-limited for some domains/registrars — the app handles this gracefully and shows "unavailable" rather than crashing
- Redirect-chain tracing is capped at 8 hops and detects redirect loops to prevent a malicious link from hanging a scan
- Webhook alerting is best-effort: a broken or unreachable webhook will never cause a scan to fail
- The favicon similarity check only flags a **visual clone** when a close match to a known brand is found on a domain that ISN'T that brand's own — it never penalizes a site simply for having no matching favicon in the database
- Structural features (hyphen count, dot count) are evaluated **domain-only**, not on the full URL string — see "Feature Extraction Details" above. This was a fixed false-positive bug (Google Meet links, and any legitimate URL with a hyphenated/dotted path or query string, were previously miscategorized as suspicious)

---

## 🐞 Known Issues / Fix Log

- **Fixed:** `extract_features()` previously counted hyphens and dots across the entire raw URL (including path and query string), causing legitimate links with hyphenated paths — such as Google Meet room codes (`meet.google.com/tbj-dudh-fex`) — to be flagged as high-risk phishing based on a single misfiring signal. Structural checks are now scoped to the parsed domain (`urlparse(url).netloc`) only.
- **Fixed:** The HTTPS check previously searched for the substring `"https"` anywhere in the URL rather than reading the actual scheme, which could misclassify a plain `http://` URL containing the word "https" in its path. It now reads `urlparse(url).scheme` directly.
- **Fixed:** `utils/vt_api.py` previously had a real VirusTotal API key hardcoded as the fallback default and referenced an undefined `VT_SCAN_URL` variable (would raise `NameError` on every scan). The key is now loaded strictly from the `VT_API_KEY` environment variable with no hardcoded fallback, and `VT_SCAN_URL` is properly defined.
- **Known limitation:** `dataset.csv` currently contains only 6 labeled URLs — see "Model Performance" above. Model metrics are not statistically meaningful until this is expanded.
- **Note:** `phishing_model.pkl` must be retrained (`python model.py`) any time `utils/feature.py` changes, since the model's learned weights are tied to the exact feature definitions used at training time.

---

## 📄 License

This project is built for educational purposes as part of a cybersecurity/ML academic project.

---

## 👨‍💻 Author

**Vansh Saxena**  
📧 saxenavansh1236@gmail.com
