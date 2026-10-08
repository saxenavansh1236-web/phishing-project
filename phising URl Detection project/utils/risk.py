"""
utils/risk.py -- combines ALL evidence into one risk score (0-100).

Why this exists: the ML model only sees the origin (scheme + host) of a URL, and
the ablation experiment showed it leans heavily on length-type cues, so on its own
it is a weak prior. Letting it decide the verdict alone produced contradictions
(a 28-year-old domain with 0 VirusTotal detections shown as PHISHING). Now the model
sets a starting point and independent evidence moves the score up or down.

Every contribution is returned as a signed list, so the UI/API can show exactly
why a score came out the way it did (nothing is hidden inside a black box).
The weights are judgement calls -- tune them against labelled data.
"""
import re

PHISHING_THRESHOLD = 60   # risk >= this => verdict "phishing"


def _vt_counts(vt_result):
    text = str(vt_result or "")

    def grab(label):
        m = re.search(label + r":\s*(\d+)", text)
        return int(m.group(1)) if m else None

    return grab("Malicious"), grab("Suspicious"), grab("Harmless")


def compute_risk(model_proba, redirect_info, domain_info, typo_result,
                 ssl_info, vt_result, favicon_info, page_info):
    redirect_info = redirect_info or {}
    domain_info = domain_info or {}
    typo_result = typo_result or {}
    ssl_info = ssl_info or {}
    favicon_info = favicon_info or {}
    page_info = page_info or {}

    signals = []

    def add(label, points):
        if points:
            signals.append({"label": label, "points": int(points)})

    p = 0.0 if model_proba is None else max(0.0, min(1.0, float(model_proba)))
    signals.append({"label": f"URL-pattern model ({round(p * 100)}% phishing probability)",
                    "points": round(15 + 45 * p)})

    # ── strong evidence of phishing ──
    malicious, suspicious, harmless = _vt_counts(vt_result)
    vt_bad = False
    if malicious is not None:
        if malicious >= 5:
            add(f"VirusTotal: {malicious} engines flag it as malicious", 70); vt_bad = True
        elif malicious >= 2:
            add(f"VirusTotal: {malicious} engines flag it as malicious", 35); vt_bad = True
        elif malicious == 1:
            add("VirusTotal: 1 engine flags it as malicious", 10)
        if suspicious is not None and suspicious >= 3:
            add(f"VirusTotal: {suspicious} engines call it suspicious", 5)

    if favicon_info.get("is_visual_clone"):
        add(f"Favicon copies {favicon_info.get('matched_brand', 'a known brand')} but the domain isn't theirs", 70)

    strong_page = bool(page_info.get("strong_signal"))
    if strong_page:
        first = next((f["text"] for f in page_info.get("findings", []) if f.get("severity") == "high"),
                     "high-risk page behaviour")
        add(f"Page content: {first}", 70)
    elif page_info.get("risk_points"):
        add("Page content: suspicious behaviour found", min(page_info["risk_points"] // 4, 15))

    if typo_result.get("is_typosquat"):
        add(f"Domain imitates {typo_result.get('likely_target', 'a known brand')}", 40)

    age = domain_info.get("domain_age_days")
    if age is not None and age < 30:
        add(f"Domain registered only {age} day(s) ago", 25)
    elif age is not None and age < 180:
        add(f"Domain is fairly new ({age} days old)", 10)

    if ssl_info.get("risk") == "high":
        add("No valid SSL certificate, or a serious certificate problem", 8)

    if redirect_info.get("was_shortened") and redirect_info.get("hop_count", 0) >= 2:
        add(f"Hidden behind a {redirect_info['hop_count']}-hop redirect chain", 10)

    # ── reassuring evidence (halved when strong phishing signals are present, so a
    #    hacked old domain can't "launder" a credential-stealing page) ──
    strong_bad = strong_page or bool(favicon_info.get("is_visual_clone")) or bool(typo_result.get("is_typosquat"))
    f = 0.5 if (strong_bad or vt_bad) else 1.0
    note = " (reduced: other warning signs present)" if f < 1 else ""

    if malicious == 0 and harmless is not None and harmless >= 30:
        add("VirusTotal: no engine flags it" + note, -round(15 * f))
    if age is not None and age >= 730:
        add(f"Established domain ({age // 365} years old)" + note, -round(12 * f))
    if ssl_info.get("risk") == "low":
        add("Valid SSL certificate" + note, -round(3 * f))

    risk = max(0, min(100, sum(s["points"] for s in signals)))
    return {
        "risk": int(risk),
        "verdict": "phishing" if risk >= PHISHING_THRESHOLD else "safe",
        "signals": signals,
    }