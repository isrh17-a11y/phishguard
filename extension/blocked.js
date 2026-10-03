const p = new URLSearchParams(location.search);
const target = p.get("url") || "";

document.getElementById("level").textContent = p.get("level") || "";
document.getElementById("score").textContent = (p.get("score") || "?") + " / 100";
document.getElementById("url").textContent = target;

const list = document.getElementById("signals");
(p.get("signals") || "").split("|").filter(Boolean).forEach((s) => {
  const li = document.createElement("li");
  li.textContent = s;
  list.appendChild(li);
});

document.getElementById("back").onclick = () => {
  if (history.length > 1) history.back();
  else window.close();
};

document.getElementById("proceed").onclick = async () => {
  const host = new URL(target).hostname;
  await chrome.runtime.sendMessage({ type: "bypass", host });
  location.href = target;
};