const $ = (id) => document.getElementById(id);
let tabUrl = "";

function showError(msg) { $("error").textContent = msg; $("error").hidden = !msg; }

function addItem(list, text) {           // textContent only: server/page text is never trusted as HTML
  const li = document.createElement("li");
  li.textContent = text;
  list.appendChild(li);
}

function render(d) {
  const phishing = d.verdict === "phishing";
  $("verdict").textContent = `${phishing ? "Phishing" : "Looks safe"} · risk ${d.risk}%`;
  $("verdict").className = phishing ? "phishing" : "safe";
  $("fill").style.width = d.risk + "%";
  $("fill").style.background = d.risk >= 70 ? "var(--danger)" : d.risk >= 40 ? "var(--warn)" : "var(--safe)";

  const moved = d.final_url && d.final_url !== d.url;
  $("final").hidden = !moved;
  if (moved) $("final").textContent = "Leads to: " + d.final_url;

  const list = $("reasons");
  list.replaceChildren();
  [...(d.reasons || []), ...(d.page_findings || [])].forEach((t) => addItem(list, t));
  $("result").hidden = false;
}

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  tabUrl = tab?.url || "";
  const scannable = /^https?:\/\//i.test(tabUrl);
  $("current").textContent = scannable ? tabUrl : "This page type can't be scanned.";
  $("scan").disabled = !scannable;

  const c = await getConfig();
  $("apiBase").value = c.apiBase;
  $("apiKey").value = c.apiKey;
  if (!c.apiKey) $("settings").open = true;
}

$("scan").addEventListener("click", async () => {
  showError("");
  $("result").hidden = true;
  $("scan").disabled = true;
  $("scan").textContent = "Scanning…";
  try { render(await scanUrl(tabUrl)); }
  catch (e) { showError(e.message); }
  $("scan").disabled = false;
  $("scan").textContent = "Scan this page";
});

$("save").addEventListener("click", async () => {
  await chrome.storage.local.set({ apiBase: $("apiBase").value.trim(), apiKey: $("apiKey").value.trim() });
  $("settingsMsg").textContent = "Saved.";
});

$("test").addEventListener("click", async () => {
  const base = $("apiBase").value.trim().replace(/\/+$/, "");
  try {
    const r = await fetch(`${base}/api/v1/health`);
    $("settingsMsg").textContent = r.ok ? "Server reachable." : `Server answered ${r.status}.`;
  } catch { $("settingsMsg").textContent = "Can't reach that address. Check the URL and host permissions."; }
});

init();