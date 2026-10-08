"""
utils/page_check.py -- Page content analysis.

Fetches the destination page (HTML only, never executes JavaScript) and looks
for behaviours URL-only checks can't see: credential forms posting to another
site, hidden iframes, disabled right-click, obfuscated scripts, and a page
title that claims to be a brand the domain doesn't belong to.

All fetching goes through utils.net_safety.safe_get() (SSRF-protected).
"""
import re
from urllib.parse import urlparse, urljoin

import requests
import tldextract
from bs4 import BeautifulSoup

from utils.net_safety import safe_get, read_capped, UnsafeURL, UNRESOLVED

# offline: use the bundled public-suffix snapshot, never fetch a list at runtime
_tld = tldextract.TLDExtract(suffix_list_urls=())

BRANDS = {
    "paypal": ["paypal.com"],
    "google": ["google.com", "gstatic.com", "googleusercontent.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "microsoftonline.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.in"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "netflix": ["netflix.com"],
    "linkedin": ["linkedin.com"],
    "dropbox": ["dropbox.com"],
    "whatsapp": ["whatsapp.com"],
    "paytm": ["paytm.com"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi"],
    "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"],
}

_HIDDEN_STYLE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden", re.I)
_OBFUSCATION = re.compile(r"eval\s*\(|atob\s*\(|unescape\s*\(|fromCharCode|document\.write\s*\(\s*unescape", re.I)
_HEX_BLOB = re.compile(r"(?:\\x[0-9a-fA-F]{2}){20,}")


def _reg_domain(url):
    ext = _tld(urlparse(url).hostname or "")
    if hasattr(type(ext), "top_domain_under_public_suffix"):   # newer tldextract
        return ext.top_domain_under_public_suffix.lower()
    return ext.registered_domain.lower()


def _add(findings, severity, points, text):
    findings.append({"severity": severity, "points": points, "text": text})


def analyze_page(url):
    """
    Returns:
        {
            "fetched": bool,
            "error": str | None,        # why the page couldn't be analysed
            "title": str,
            "findings": [{"severity": "high|medium|low", "points": int, "text": str}],
            "risk_points": int,         # 0-100
            "strong_signal": bool,      # True if any high-severity finding
        }
    """
    out = {"fetched": False, "error": None, "title": "", "findings": [],
           "risk_points": 0, "strong_signal": False}
    try:
        resp, final_url = safe_get(url)
        ctype = resp.headers.get("Content-Type", "").lower()
        if "html" not in ctype:
            resp.close()
            out["error"] = "Not an HTML page, so there is no page content to analyse."
            return out
        raw = read_capped(resp)
        html = raw.decode(resp.encoding or "utf-8", errors="replace")
    except UnsafeURL as e:
        if str(e) == UNRESOLVED:
            out["error"] = "Page not reachable: the domain does not resolve (the site may be offline or taken down)."
        else:
            out["error"] = f"Page was not fetched for safety reasons: {e}"
        return out
    except requests.RequestException:
        out["error"] = "The page could not be fetched (connection error or timeout)."
        return out

    out["fetched"] = True
    soup = BeautifulSoup(html, "html.parser")
    page_domain = _reg_domain(final_url)
    page_host = (urlparse(final_url).hostname or "").lower()
    title = (soup.title.string or "").strip() if soup.title and soup.title.string else ""
    out["title"] = title[:120]
    f = out["findings"]

    # 1. Credential forms
    has_password = bool(soup.find("input", {"type": re.compile("^password$", re.I)}))
    for form in soup.find_all("form"):
        if not form.find("input", {"type": re.compile("^password$", re.I)}):
            continue
        action = (form.get("action") or "").strip()
        if action.lower().startswith("mailto:"):
            _add(f, "high", 25, "Login form sends the entered details to an email address")
            continue
        target = urljoin(final_url, action) if action else final_url
        if urlparse(target).scheme in ("http", "https"):
            if _reg_domain(target) != page_domain:
                _add(f, "high", 40, f"Password form submits to a different site ({urlparse(target).hostname})")
            elif urlparse(target).scheme == "http":
                _add(f, "medium", 20, "Password form submits over unencrypted HTTP")
    if has_password and urlparse(final_url).scheme == "http":
        _add(f, "medium", 15, "Password field on a page that isn't served over HTTPS")

    # 2. Hidden iframes
    for fr in soup.find_all("iframe"):
        w, h = str(fr.get("width", "")).strip(), str(fr.get("height", "")).strip()
        if fr.has_attr("hidden") or _HIDDEN_STYLE.search(fr.get("style", "")) or w in ("0", "1") or h in ("0", "1"):
            _add(f, "medium", 15, "Hidden iframe embedded in the page")
            break

    # 3. Right-click disabled
    if re.search(r"oncontextmenu\s*=\s*[\"']?\s*(return\s+false|event\.preventDefault)", html, re.I) or (
        re.search(r"addEventListener\(\s*[\"']contextmenu[\"']", html) and "preventDefault" in html
    ):
        _add(f, "medium", 10, "Right-click is disabled (often used to block inspecting the page)")

    # 4. Obfuscated JavaScript
    scripts = "\n".join(s.get_text() for s in soup.find_all("script"))
    if len(_OBFUSCATION.findall(scripts)) >= 2 or _HEX_BLOB.search(scripts):
        if has_password:
            _add(f, "medium", 15, "Obfuscated JavaScript on a page that asks for a password")
        else:
            # big legitimate web apps (Google Meet, Gmail ...) ship minified code that trips
            # this heuristic, so without a password field it is only a weak hint
            _add(f, "low", 4, "Obfuscated or minified JavaScript (common on large web apps; weak signal)")

    # 5. Meta-refresh redirect to another site
    meta = soup.find("meta", attrs={"http-equiv": re.compile("^refresh$", re.I)})
    if meta and "url=" in (meta.get("content") or "").lower():
        dest = urljoin(final_url, meta["content"].split("=", 1)[1].strip(" '\""))
        if _reg_domain(dest) and _reg_domain(dest) != page_domain:
            _add(f, "medium", 15, "Page auto-redirects to a different site")

    # 6. Title claims a brand the domain doesn't belong to
    low_title = title.lower()
    for brand, domains in BRANDS.items():
        if re.search(rf"\b{re.escape(brand)}\b", low_title) and not any(
            page_host == d or page_host.endswith("." + d) for d in domains
        ):
            if has_password:
                _add(f, "high", 40, f"Page title mentions “{brand}” and asks for a password, but the domain isn't {domains[0]}")
            else:
                _add(f, "low", 10, f"Page title mentions “{brand}”, but the domain isn't {domains[0]}")
            break

    out["risk_points"] = min(sum(x["points"] for x in f), 100)
    out["strong_signal"] = any(x["severity"] == "high" for x in f)
    return out