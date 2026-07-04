"""
qr_check.py
Decodes a QR code from an uploaded image and extracts the embedded URL
(or raw text, if it's not a URL). Used for "quishing" (QR phishing) detection —
the user uploads a QR image instead of typing a URL, and we feed whatever
it decodes back into the normal scan pipeline.

Uses OpenCV's built-in QRCodeDetector — no external system library required
(unlike pyzbar, which needs the zbar shared library and can fail to load
on some Windows/Python version combinations).
"""

import cv2
import numpy as np

_detector = cv2.QRCodeDetector()


def decode_qr_from_filestorage(file_storage):
    """
    file_storage: a Flask request.files['qr_image'] FileStorage object.
    Returns a dict:
      { "success": True,  "data": "<decoded text/url>" }
      { "success": False, "error": "<reason>" }
    Never raises — always safe to call directly in a route.
    """
    try:
        file_bytes = np.frombuffer(file_storage.read(), dtype=np.uint8)
        if file_bytes.size == 0:
            return {"success": False, "error": "Uploaded file is empty."}

        img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
        if img is None:
            return {"success": False, "error": "Could not read image. Make sure it's a valid PNG/JPG."}

        # Primary attempt
        data, points, _ = _detector.detectAndDecode(img)

        if not data:
            # Fallback: grayscale + Otsu threshold helps with low-contrast
            # or photographed (not screenshotted) QR codes
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            thresh_bgr = cv2.cvtColor(thresh, cv2.COLOR_GRAY2BGR)
            data, points, _ = _detector.detectAndDecode(thresh_bgr)

        if not data:
            return {"success": False, "error": "No QR code detected in this image."}

        return {"success": True, "data": data.strip()}

    except Exception as e:
        return {"success": False, "error": f"Failed to process QR image: {e}"}


def looks_like_url(text):
    """Quick check so we can warn the user if the QR didn't actually contain a URL."""
    return text.startswith("http://") or text.startswith("https://") or text.startswith("www.")