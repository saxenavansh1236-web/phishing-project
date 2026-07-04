"""
bulk_check.py
Parses an uploaded CSV of URLs for the Bulk URL Upload feature.
Accepts either a single column of bare URLs (no header), or a CSV
with a header row containing a column named one of: url, urls, link, links.
"""

import csv
import io

MAX_URLS_PER_BATCH = 100  # hard cap so one upload can't hang the server


def parse_urls_from_csv(file_storage):
    """
    file_storage: a Flask request.files['csv_file'] FileStorage object.
    Returns: { "success": True, "urls": [...] } or { "success": False, "error": "..." }
    Never raises.
    """
    try:
        raw = file_storage.read()
        if not raw:
            return {"success": False, "error": "Uploaded file is empty."}

        text = raw.decode("utf-8-sig", errors="replace")  # utf-8-sig strips Excel's BOM
        reader = csv.reader(io.StringIO(text))
        rows = [row for row in reader if row and any(cell.strip() for cell in row)]

        if not rows:
            return {"success": False, "error": "CSV file has no data rows."}

        urls = []

        first_row = [c.strip().lower() for c in rows[0]]
        url_col_names = {"url", "urls", "link", "links"}
        header_col_index = None
        for i, cell in enumerate(first_row):
            if cell in url_col_names:
                header_col_index = i
                break

        if header_col_index is not None:
            # Has a recognizable header — skip row 0, read that column from every other row
            for row in rows[1:]:
                if header_col_index < len(row):
                    val = row[header_col_index].strip()
                    if val:
                        urls.append(val)
        else:
            # No recognizable header — treat column 0 of every row as a URL
            for row in rows:
                val = row[0].strip()
                if val:
                    urls.append(val)

        # de-duplicate while preserving order
        seen = set()
        deduped = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                deduped.append(u)
        urls = deduped

        if not urls:
            return {"success": False, "error": "No URLs found in the CSV. Use a 'url' column or one URL per line."}

        truncated = False
        if len(urls) > MAX_URLS_PER_BATCH:
            urls = urls[:MAX_URLS_PER_BATCH]
            truncated = True

        return {"success": True, "urls": urls, "truncated": truncated}

    except Exception as e:
        return {"success": False, "error": f"Failed to parse CSV: {e}"}