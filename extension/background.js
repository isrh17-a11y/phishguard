const API_BASE = "http://localhost:8000";   // ← swap to Railway URL after deploy
const WEB_APP  = "http://localhost:3000";   // ← swap to Vercel URL after deploy

const BLOCK_LEVELS = ["HIGH RISK", "CRITICAL"];
const CACHE_TTL_MS = 10 * 60 * 1000;

const DEFAULT_ALLOWLIST = [
  "google.com", "youtube.com", "wikipedia.org", "github.com", "amazon.com",
  "apple.com", "microsoft.com", "stackoverflow.com", "linkedin.com", "localhost",
];

// ---------- helpers ----------
const hostOf = (u) => { try { return new URL(u).hostname; } catch { return null; } };

async function isAllowlisted(host) {
  if (!host) return true;
  const { userAllowlist = [] } = await chrome.storage.local.get("userAllowlist");
  const all = [...DEFAULT_ALLOWLIST, ...userAllowlist];
  return all.some(d => host === d || host.endsWith("." + d));
}

// ---------- scan (session cache — cleared when browser closes, never stale) ----------
async function scan(url) {
  const key = "scan:" + url;
  const cached = (await chrome.storage.session.get(key))[key];
  if (cached && Date.now() - cached.t < CACHE_TTL_MS) return cached.result;

  // save=false → stateless assessment, browsing does not flood History/Insights
  const res = await fetch(`${API_BASE}/api/scan?save=false`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  if (!res.ok) throw new Error("API " + res.status);
  const result = await res.json();
  await chrome.storage.session.set({ [key]: { t: Date.now(), result } });
  return result;
}

// ---------- badge ----------
const BADGE_COLORS = {
  SAFE: "#10b981", "LOW RISK": "#a3e635", "MEDIUM RISK": "#f59e0b",
  "HIGH RISK": "#f97316", CRITICAL: "#ef4444",
};

function setBadge(tabId, result) {
  chrome.action.setBadgeText({ tabId, text: String(result.risk_score) });
  chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLORS[result.threat_level] ?? "#64748b" });
}

// ---------- core: scan every top-level navigation (also catches pop-ups/new tabs) ----------
chrome.webNavigation.onBeforeNavigate.addListener(async (d) => {
  if (d.frameId !== 0) return;
  let u;
  try { u = new URL(d.url); } catch { return; }
  if (!/^https?:$/.test(u.protocol)) return;
  if (await isAllowlisted(u.hostname)) return;

  const { bypass = {} } = await chrome.storage.session.get("bypass");
  if (bypass[u.hostname]) return;

  try {
    const result = await scan(d.url);
    setBadge(d.tabId, result);                    // ← badge always appears, even on cold cache
    await chrome.storage.session.set({ ["tab:" + d.tabId]: { url: d.url, result } });

    if (BLOCK_LEVELS.includes(result.threat_level)) {
      const params = new URLSearchParams({
        url: d.url,
        score: result.risk_score,
        level: result.threat_level,
        signals: (result.signals ?? [])
          .filter(s => s.severity !== "INFO")
          .map(s => `${s.severity} — ${s.title} (+${s.points})`)
          .join("|"),
      });
      chrome.tabs.update(d.tabId, { url: chrome.runtime.getURL("blocked.html") + "?" + params });
    }
  } catch (e) {
    console.warn("PhishGuard scan failed:", e);
    chrome.action.setBadgeText({ tabId: d.tabId, text: "?" });
    chrome.action.setBadgeBackgroundColor({ tabId: d.tabId, color: "#64748b" });
  }
});

// backup: restore badge from cache if the scan finished after page load
chrome.webNavigation.onCompleted.addListener(async (d) => {
  if (d.frameId !== 0) return;
  const entry = (await chrome.storage.session.get("scan:" + d.url))["scan:" + d.url];
  if (entry) setBadge(d.tabId, entry.result);
});

chrome.tabs.onRemoved.addListener((tabId) => chrome.storage.session.remove("tab:" + tabId));

// ---------- right-click: scan link → full saved report in the web app ----------
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "phishguard-scan",
    title: "Scan this link with PhishGuard",
    contexts: ["link"],
  });
});

chrome.contextMenus.onClicked.addListener(async (info) => {
  if (info.menuItemId !== "phishguard-scan" || !info.linkUrl) return;
  try {
    const res = await fetch(`${API_BASE}/api/scan`, {      // no save=false → this one IS saved
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: info.linkUrl }),
    });
    const result = await res.json();
    chrome.tabs.create({ url: `${WEB_APP}/scan/${result.id}` });
  } catch {
    chrome.tabs.create({ url: WEB_APP });
  }
});

// ---------- messages from popup ----------
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === "allow") {
    chrome.storage.local.get("userAllowlist").then(({ userAllowlist = [] }) => {
      const merged = [...new Set([...userAllowlist, msg.host])];
      return chrome.storage.local.set({ userAllowlist: merged });
    }).then(() => sendResponse({ ok: true }));
    return true;
  }
});