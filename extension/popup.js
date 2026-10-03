(async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const box = document.getElementById("verdict");
  const btn = document.getElementById("allow");

  let host = null;
  try { host = new URL(tab.url).hostname.replace(/^www\./, ""); } catch {}

  const { userAllowlist = [] } = await chrome.storage.local.get("userAllowlist");
  const entry = (await chrome.storage.session.get("tab:" + tab.id))["tab:" + tab.id];

  if (host && (userAllowlist.includes(host) || DEFAULTS.some(d => host === d || host.endsWith("." + d)))) {
    box.innerHTML = `<b>${host}</b> is allowlisted.`;
    btn.style.display = "none";
  } else if (entry?.result) {
    const r = entry.result;
    box.innerHTML =
      `<b>${host}</b><br>Risk <b>${r.risk_score}/100</b> · <b>${r.threat_level}</b><br>` +
      `${r.classification} · model confidence ${Math.round(r.confidence * 100)}%`;
  } else {
    box.textContent = "No assessment for this tab yet. Reload the page.";
  }

  btn.addEventListener("click", async () => {
    if (!host) return;
    await chrome.runtime.sendMessage({ type: "allow", host });
    box.textContent = `${host} allowlisted. Reload the page to skip scanning.`;
    btn.style.display = "none";
  });
})();

const DEFAULTS = [
  "google.com", "youtube.com", "wikipedia.org", "github.com", "amazon.com",
  "apple.com", "microsoft.com", "stackoverflow.com", "linkedin.com", "localhost",
];