"""
utils/alert.py

Sends a webhook notification (Slack- or Discord-compatible incoming
webhook) whenever a high-risk phishing URL is detected. This mirrors
the alerting pattern used in the OSINT platform / HoneyShield projects,
turning this tool from a passive scanner into something that can sit
in a live monitoring pipeline.

Configure via environment variable ALERT_WEBHOOK_URL. If it's not set,
alerts are silently skipped (so the app still runs fine without it).
"""

import os
import requests

ALERT_WEBHOOK_URL = os.environ.get("ALERT_WEBHOOK_URL", "").strip()
ALERT_RISK_THRESHOLD = int(os.environ.get("ALERT_RISK_THRESHOLD", "70"))
REQUEST_TIMEOUT = 5


def _build_payload(scan_data: dict, username: str) -> dict:
    """
    Builds a Slack-compatible payload. Discord incoming webhooks also
    accept the same {"text": ...} shape, so this works for both without
    extra branching.
    """
    url = scan_data.get("url", "unknown")
    risk = scan_data.get("risk", 0)
    result = scan_data.get("result", "UNKNOWN")
    reasons = scan_data.get("reasons", [])
    redirect_info = scan_data.get("redirect_info")

    lines = [
        f"🚨 *High-risk URL detected* (risk score: {risk})",
        f"*User:* {username}",
        f"*URL:* {url}",
        f"*Verdict:* {result}",
    ]

    if redirect_info and redirect_info.get("was_shortened"):
        lines.append(
            f"*Redirect chain:* {redirect_info['hop_count']} hop(s) → "
            f"final destination: {redirect_info['final_url']}"
        )

    if reasons:
        lines.append("*Reasons flagged:*")
        for r in reasons[:5]:
            lines.append(f"  • {r}")

    return {"text": "\n".join(lines)}


def send_alert_if_high_risk(scan_data: dict, username: str) -> bool:
    """
    Fires a webhook alert if risk >= ALERT_RISK_THRESHOLD and a webhook
    URL is configured. Returns True if an alert was sent, False otherwise.
    Never raises — a broken webhook should never break a scan.
    """
    if not ALERT_WEBHOOK_URL:
        return False

    if scan_data.get("risk", 0) < ALERT_RISK_THRESHOLD:
        return False

    try:
        payload = _build_payload(scan_data, username)
        resp = requests.post(ALERT_WEBHOOK_URL, json=payload, timeout=REQUEST_TIMEOUT)
        return resp.status_code in (200, 204)
    except requests.exceptions.RequestException:
        # Alerting is best-effort; never let a webhook failure break a scan.
        return False