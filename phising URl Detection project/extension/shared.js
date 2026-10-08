// Shared by the popup and the background worker.
async function getConfig() {
  const c = await chrome.storage.local.get({ apiBase: "http://127.0.0.1:5000", apiKey: "" });
  return { apiBase: c.apiBase.replace(/\/+$/, ""), apiKey: c.apiKey };
}

async function scanUrl(url) {
  const { apiBase, apiKey } = await getConfig();
  if (!apiKey) throw new Error("No API key yet. Open the extension popup and add one under Settings.");
  let r;
  try {
    r = await fetch(`${apiBase}/api/v1/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-API-Key": apiKey },
      body: JSON.stringify({ url }),
    });
  } catch {
    throw new Error(`Can't reach ${apiBase}. Is the server running?`);
  }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || `Server error (${r.status})`);
  return data;
}