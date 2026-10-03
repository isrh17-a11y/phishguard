PhishGuard — Know Before You Click
AI-powered URL security intelligence. PhishGuard combines a trained XGBoostclassifier with a transparent, rule-based risk engine to assess any URL — andshows the user exactly why a link is safe or dangerous.

🔗 Live app: https://phishguard-ten-ruddy.vercel.app⚡ API + docs: https://phishguard-production-7b6e.up.railway.app/docs🧩 Browser extension: real-time protection in Chrome — see extension/

Architecture
graph TD    U[User] --> F[Next.js UI · Vercel]    E[Chrome Extension · MV3] -->|auto-scan every navigation| A[FastAPI · Docker · Railway]    F -->|POST /api/scan| A    A --> P[Feature extraction — 28 lexical/structural features]    P --> M[XGBoost classifier]    M --> R[Risk engine — ML points + heuristic signals]    R --> D[(PostgreSQL)]    R -->|explainable assessment| F    R -->|badge + block page| E

How it works:
1. Feature extraction — 28 features computed from the URL string alone
(lengths, subdomains, entropy, digits, hyphens, suspicious TLDs, IP hosts,
shorteners, punycode…). No page is ever visited — analyzing a hostile link
is safe for the user and instant.
2. ML classification — XGBoost trained on the
PhiUSIIL Phishing URL Dataset
(~235k URLs). Three candidates (Logistic Regression, Random Forest, XGBoost)
were evaluated; the final model was selected on validation F1 (0.9976;
test F1 0.9978, ROC-AUC 0.9988). SHAP analysis shows is_https,
path_length, num_subdomains and url_length as the dominant drivers.
4. Risk engine — the ML probability is combined with heuristic signals
(brand impersonation, suspicious keywords, abuse-prone TLDs, IP hosts,
shorteners…) into a 0–100 score: SAFE → LOW → MEDIUM → HIGH → CRITICAL.
Every point is attributable — the UI shows the exact composition
(e.g. "ML 70 pts + heuristics 30 pts").
5. Delivery — FastAPI + PostgreSQL backend, Next.js dashboard, and a
Chrome extension that scans every navigation, badges each tab with the
risk score, and blocks HIGH/CRITICAL pages with a full explanation.

API 
| Endpoint | Purpose |
|---|---|
| `POST /api/scan` | Full assessment (features, ML probability, signals, breakdown). `?save=false` for stateless scans |
| `GET /api/history` | Paginated scan history with search + level filter |
| `GET /api/history/{id}` | Full stored report |
| `GET /api/stats` | Aggregates for the insights dashboard |
| `GET /api/health` | Liveness of API, model and database |

Stack
Python 3.13 · FastAPI · SQLAlchemy · PostgreSQL · scikit-learn · XGBoost · SHAP ·
Docker · Railway · Next.js 16 · Tailwind CSS · Recharts · Vercel · Chrome MV3

Running Locally 
# backend (requires a local PostgreSQL, or set DATABASE_URL)
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn backend.app.main:app --reload --port 8000

# frontend
cd frontend && npm install && npm run dev

Known limitations & future work
Detection is lexical-only: page content, WHOIS/domain age and SSL
intelligence are not yet used (deliberate trade-off — safety and speed).
The public API is unauthenticated; rate limiting is future work.
Extension allowlist + 10-minute bypass keep browsing usable; a
declarativeNetRequest fast-path is a possible optimization.
text


Adjust anything that feels off — but the bones are accurate to what you built.

**Then:** copy `ml/artifacts/*.png` into `docs/` (already planned), commit everything, and screenshot the live site's hero + CRITICAL report + insights **on the public URL** — those three screenshots prove deployment in your report.

## The demo script (≈90 seconds, for recording or viva)

1. **Live hero** → paste `https://paypal-secure-login.xyz/verify-account` → staged animation → CRITICAL report: gauge 100 → three signal cards with points → model bars → **"ML 70 pts + heuristics 30 pts"** → URL intelligence
2. **google.com** → SAFE, model confidence shown — *"the model genuinely evaluates, it doesn't perform drama"*
3. **bit.ly** → LOW RISK — *"borderline cases are surfaced, not hidden"*
4. **History** → search "paypal" → click a row → report reopens from the cloud database
5. **Extension**: navigate to the phishing URL → red "100" badge → block page with signals → right-click any link → *Scan this link* → report opens on the live site
6. **Insights** → *"the scans I just performed from the browser are now in these charts"* — the system is a loop, not a page
7. Close: *"Three models evaluated, one selected on validation F1. Explainability at global level through SHAP, per-scan through the risk engine. And it's deployed."*

## What's left (all optional, ranked)

1. **SHAP per-scan panel** — tomorrow's first task if you want it; ~1.5h, the strongest remaining DS flex
2. **Demo GIF** in the README — 30 min with any screen recorder + gifski/ezgif
3. Extension link-hover tooltips, Framer Motion polish
4. **Rest.** Seriously — the mandatory scope is *done*. Everything above is cherry-picking.

**Send me** the README once it's up (I'll sanity-check the rendered version on GitHub), and tell me which of the optional items you want tomorrow — my vote is the SHAP panel, then sleep on a finished project.

