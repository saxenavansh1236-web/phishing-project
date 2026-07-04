"""
vt_api.py  --  VirusTotal URL scanning helper
"""

import base64
import time
import requests

VT_API_KEY     = "f25a4b987d25e26457ba53aa87d7f6588c808eaf9753e5e127ae95d388cf5ccf"   # <- paste your key here
VT_SCAN_URL    = "https://www.virustotal.com/api/v3/urls"
VT_REPORT_URL  = "https://www.virustotal.com/api/v3/urls/{}"
REQUEST_TIMEOUT = 15


def scan_url_virustotal(url: str) -> str:
    if not VT_API_KEY or VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY":
        return "VirusTotal: API key not configured."

    headers = {"x-apikey": VT_API_KEY}

    try:
        # Step 1 — submit the URL for scanning
        scan_resp = requests.post(
            VT_SCAN_URL,
            headers=headers,
            data={"url": url},
            timeout=REQUEST_TIMEOUT,
        )

        if scan_resp.status_code != 200:
            return (
                f"VirusTotal: submission failed "
                f"(HTTP {scan_resp.status_code}). Check your API key."
            )

        # Step 2 — FIX: compute the correct URL ID
        # VirusTotal v3 uses base64url(url) WITHOUT padding, not sha256
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

        # Wait for the scan to complete
        time.sleep(3)

        # Step 3 — fetch the report
        report_resp = requests.get(
            VT_REPORT_URL.format(url_id),
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )

        if report_resp.status_code == 404:
            return "VirusTotal: URL not in database yet. Try scanning again in a moment."

        if report_resp.status_code != 200:
            return (
                f"VirusTotal: could not retrieve report "
                f"(HTTP {report_resp.status_code})."
            )

        stats = (
            report_resp.json()
            .get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )

        malicious  = stats.get("malicious",  0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless",   0)
        undetected = stats.get("undetected", 0)

        if malicious > 0:
            verdict = "⚠️ MALICIOUS"
        elif suspicious > 0:
            verdict = "⚠️ SUSPICIOUS"
        else:
            verdict = "✅ CLEAN"

        return (
            f"VirusTotal [{verdict}] — "
            f"Malicious: {malicious} | "
            f"Suspicious: {suspicious} | "
            f"Harmless: {harmless} | "
            f"Undetected: {undetected}"
        )

    except requests.exceptions.ConnectionError:
        return "VirusTotal: network connection failed."
    except requests.exceptions.Timeout:
        return "VirusTotal: request timed out."
    except requests.exceptions.RequestException as exc:
        return f"VirusTotal: request error — {exc}"
    except Exception as exc:
        return f"VirusTotal: unexpected error — {exc}"


check_url_virustotal = scan_url_virustotal