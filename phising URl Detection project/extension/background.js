importScripts("shared.js");

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "pg-scan-link",
    title: "Scan link with PhishGuard",
    contexts: ["link"],
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== "pg-scan-link" || !info.linkUrl || !tab) return;
  let msg;
  try {
    const d = await scanUrl(info.linkUrl);
    const verdict = d.verdict === "phishing" ? "PHISHING - do not open" : "Looks safe";
    msg = `${verdict} (risk ${d.risk}%)\n\n${info.linkUrl}`;
    if (d.final_url && d.final_url !== info.linkUrl) msg += `\n\nLeads to: ${d.final_url}`;
    if (d.verdict === "phishing" && d.reasons.length) msg += `\n\nWhy: ${d.reasons.slice(0, 3).join("; ")}`;
  } catch (e) {
    msg = "PhishGuard: " + e.message;
  }
  chrome.scripting.executeScript({ target: { tabId: tab.id }, func: (m) => alert(m), args: [msg] });
});