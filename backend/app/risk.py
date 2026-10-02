"""
PhishGuard risk engine.

Combines the ML model's phishing probability with heuristic URL signals
into a 0-100 risk score, a threat level, human-readable signals and a
plain-English recommendation.

Scoring design (document this in the report):

    score = 70 * P(phishing)  +  min(sum(signal_points), 30)

    * the ML model is the primary contributor (up to 70 points)
    * heuristic signals contribute at most 30 points combined
    * clamped to [0, 100]
    * hard red flags (IP host, '@' trick, punycode, brand impersonation)
      floor the score at 61 (HIGH RISK)

Threat-level thresholds are a design choice for this project,
NOT an industry standard:

    0-20    SAFE          <= 40   classification: LEGITIMATE
    21-40   LOW RISK
    41-60   MEDIUM RISK   41-60   classification: SUSPICIOUS
    61-80   HIGH RISK     >= 61   classification: PHISHING
    81-100  CRITICAL

Self-test (from the project root):
    python backend/app/risk.py
"""

from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import urlparse

import tldextract

# Use tldextract's bundled public-suffix snapshot: no network fetch at
# scan time, so this never fails because a request timed out.
_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

ML_WEIGHT = 70         # max points from the ML probability
HEURISTIC_CAP = 30     # max combined points from heuristic signals
HARD_FLAG_FLOOR = 61   # minimum score when a hard red flag is present

HARD_FLAG_IDS = {"ip_host", "at_trick", "punycode", "brand_impersonation"}

THREAT_LEVELS = (
    (20, "SAFE"),
    (40, "LOW RISK"),
    (60, "MEDIUM RISK"),
    (80, "HIGH RISK"),
    (100, "CRITICAL"),
)

RECOMMENDATIONS = {
    "SAFE": "No significant risk indicators found. As always, check the "
            "address bar before entering credentials or personal information.",
    "LOW RISK": "Minor risk indicators detected. Likely safe, but stay alert "
                "for anything unusual after you open the page.",
    "MEDIUM RISK": "Several risk indicators detected. Avoid entering "
                   "passwords, payment details or personal data unless you "
                   "can independently confirm this is the real site.",
    "HIGH RISK": "Strong phishing indicators detected. Do not enter "
                 "credentials, payment details or personal information "
                 "on this site.",
    "CRITICAL": "Multiple strong phishing indicators detected. Do not visit "
                "this link or share it with others. If it arrived by email "
                "or message, report it as phishing.",
}

SUSPICIOUS_KEYWORDS = (
    "login", "log-in", "signin", "sign-in", "verify", "verification",
    "secure", "security", "account", "update", "confirm", "billing",
    "invoice", "payment", "bank", "unlock", "suspended", "limited",
    "webscr", "wallet", "recovery",
)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "cutt.ly",
    "shorturl.at", "rebrand.ly", "rb.gy", "tiny.cc", "ow.ly", "buff.ly",
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "click", "link",
    "work", "fit", "rest", "cam", "monster", "quest", "cfd",
}

BRAND_KEYWORDS = (
    "login", "signin", "verify", "secure", "support", "update",
    "account", "billing", "service", "help", "confirm", "alert", "team",
)

BRANDS = {
    "paypal": "paypal.com",
    "apple": "apple.com",
    "icloud": "icloud.com",
    "gmail": "gmail.com",
    "google": "google.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "microsoft": "microsoft.com",
    "outlook": "outlook.com",
    "office": "office.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "linkedin": "linkedin.com",
    "binance": "binance.com",
    "coinbase": "coinbase.com",
    "dropbox": "dropbox.com",
    "adobe": "adobe.com",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "hsbc": "hsbc.com",
    "steam": "steampowered.com",
}

IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

EXECUTABLE_EXTS = (
    ".exe", ".msi", ".bat", ".cmd", ".scr", ".apk", ".jar", ".dmg", ".pkg",
)


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _brand_impersonation(hostname: str, registrable: str) -> str | None:
    """Return the impersonated brand, if the *hostname* references a known
    brand on a domain that is not that brand's official domain.

    Hostname only, never the path — pages *about* a brand
    (e.g. reddit.com/r/paypal) must not be flagged.
    """
    reg = registrable.lower()
    labels = [l for l in hostname.split(".") if l]
    tokens = [t for t in re.split(r"[^a-z0-9]+", hostname) if t]

    for brand, official in BRANDS.items():
        if reg == official:
            continue
        # brand as a standalone token: paypal-login.com
        if brand in tokens:
            return brand
        # brand fused with a security keyword: paypalsupport.xyz
        for label in labels:
            if brand in label and any(k in label for k in BRAND_KEYWORDS):
                return brand
    return None


def heuristic_signals(url: str) -> list[dict]:
    """Detect structural/lexical red flags in a URL.

    Each signal: {id, severity, points, title, description}.
    """
    raw = url.strip()
    if "://" not in raw:
        raw = "http://" + raw

    parsed = urlparse(raw)
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return []

    ext = _EXTRACTOR(raw)
    registrable = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    subdomains = [s for s in ext.subdomain.split(".") if s and s != "www"]
    path = parsed.path or ""
    signals: list[dict] = []

    def add(sid, severity, points, title, description):
        signals.append({"id": sid, "severity": severity, "points": points,
                        "title": title, "description": description})

    # ---- hard red flags --------------------------------------------------
    if IPV4_RE.match(hostname) or ":" in hostname:
        add("ip_host", "HIGH", 15,
            "IP address used instead of a domain name",
            "The link points to a raw IP address. Legitimate websites "
            "almost never do this; it is a common way to hide the host.")

    if "@" in parsed.netloc:
        add("at_trick", "HIGH", 12,
            "'@' trick in the address",
            "Everything before an '@' is ignored by browsers, so the text "
            "after it is where you would actually land. A classic trick to "
            "make a malicious address look trustworthy.")

    if any(label.startswith("xn--") for label in hostname.split(".")):
        add("punycode", "HIGH", 12,
            "Look-alike (punycode) domain",
            "The hostname uses punycode (xn--...), which can display "
            "characters from other alphabets — often abused to imitate "
            "real domains (homograph attacks).")

    brand = _brand_impersonation(hostname, registrable)
    if brand:
        add("brand_impersonation", "HIGH", 15,
            f"Possible {brand} impersonation",
            f"The address references '{brand}' but does not sit on "
            f"{BRANDS[brand]}. Attackers commonly attach trusted brand "
            "names to unrelated domains.")

    # ---- softer signals ----------------------------------------------------
    if parsed.scheme == "http":
        add("no_https", "MEDIUM", 6,
            "No HTTPS encryption",
            "The connection is unencrypted. Sites that handle logins or "
            "payments are essentially always HTTPS today.")

    haystack = f"{hostname}{path}"
    found = [k for k in SUSPICIOUS_KEYWORDS if k in haystack]
    if found:
        in_host = any(k in hostname for k in found)
        add("suspicious_keywords",
            "HIGH" if in_host else "MEDIUM",
            12 if in_host else 6,
            "Suspicious keyword(s) in the URL",
            "Keywords such as "
            + ", ".join(f"'{k}'" for k in found[:4])
            + " are frequently used in phishing pages to pressure users.")

    if registrable in SHORTENERS:
        add("shortener", "MEDIUM", 8,
            "Link shortener hides the destination",
            "A shortening service hides where the link really goes, which "
            "is often abused to route people to phishing pages.")

    if ext.suffix in SUSPICIOUS_TLDS:
        add("suspicious_tld", "MEDIUM", 8,
            f"Abuse-prone domain ending '.{ext.suffix}'",
            "This top-level domain is cheap to register and appears "
            "disproportionately often in phishing campaigns.")

    if len(subdomains) >= 4:
        add("excessive_subdomains", "MEDIUM", 6,
            f"{len(subdomains)} subdomain levels",
            "Deeply nested subdomains are used to make an untrustworthy "
            "domain look like a page belonging to a real organisation.")

    if hostname.count("-") >= 3:
        add("many_hyphens", "LOW", 4,
            "Multiple hyphens in the hostname",
            "Legitimate domains rarely need many hyphens; attackers use "
            "them to pack brand names and keywords into one address.")

    if len(url) >= 150:
        add("long_url", "MEDIUM", 6, "Unusually long URL",
            "Very long URLs are used to bury the real domain beyond the "
            "point where users stop reading.")
    elif len(url) >= 100:
        add("long_url", "LOW", 3, "Long URL",
            "The URL is long enough that its important parts may be hard "
            "to read at a glance.")

    if len(hostname) >= 18 and _shannon_entropy(hostname) >= 4.1:
        add("high_entropy", "LOW", 3,
            "Random-looking hostname",
            "The hostname reads like a random character string, typical "
            "of throwaway phishing domains.")

    if raw.count("%") >= 3:
        add("encoded_chars", "MEDIUM", 6,
            "Multiple URL-encoded characters",
            "Percent-encoded characters can conceal what the address "
            "actually contains.")

    if path.lower().endswith(EXECUTABLE_EXTS):
        add("executable", "MEDIUM", 8,
            "Points to an executable file",
            "The link leads to a downloadable program rather than a web "
            "page — a common malware delivery trick.")

    try:
        port = parsed.port
    except ValueError:
        port = -1
    if port and port not in (80, 443):
        add("nonstandard_port", "LOW", 3,
            f"Non-standard port ({port})",
            "The link connects on an unusual port instead of the normal "
            "web ports (80/443).")

    signals.sort(key=lambda s: s["points"], reverse=True)
    return signals


def compute_risk(url: str, ml_probability: float) -> dict:
    """Combine the ML probability with heuristic signals into the full
    risk report the API will serve."""
    p = float(ml_probability)
    if not 0.0 <= p <= 1.0:
        raise ValueError("ml_probability must be between 0 and 1")
    if not url or not url.strip():
        raise ValueError("url is empty")

    signals = heuristic_signals(url)
    if not signals:
        signals.append({"id": "no_red_flags", "severity": "INFO",
                        "points": 0, "title": "No structural red flags",
                        "description": "The URL structure shows none of "
                                       "the common phishing patterns this "
                                       "engine checks for."})

    heuristic_points = sum(s["points"] for s in signals)
    ml_points = ML_WEIGHT * p
    score = ml_points + min(heuristic_points, HEURISTIC_CAP)

    floored = False
    if any(s["id"] in HARD_FLAG_IDS for s in signals) and score < HARD_FLAG_FLOOR:
        score, floored = HARD_FLAG_FLOOR, True

    score = int(round(max(0.0, min(score, 100.0))))
    level = next(name for ceiling, name in THREAT_LEVELS if score <= ceiling)

    if score <= 40:
        classification = "LEGITIMATE"
    elif score <= 60:
        classification = "SUSPICIOUS"
    else:
        classification = "PHISHING"

    return {
        "risk_score": score,
        "threat_level": level,
        "classification": classification,
        "confidence": round(max(p, 1.0 - p), 2),
        "signals": signals,
        "recommendation": RECOMMENDATIONS[level],
        "risk_breakdown": {
            "ml_points": round(ml_points, 1),
            "heuristic_points": min(heuristic_points, HEURISTIC_CAP),
            "hard_flag_floor_applied": floored,
        },
    }


if __name__ == "__main__":
    # Probabilities below are hand-assigned to demonstrate the plumbing.
    # From Day 2 onwards the real probability comes from model.pkl.
    SAMPLES = [
        ("https://www.google.com", 0.02),
        ("http://192.168.0.1/paypal/login/verify", 0.91),
        ("https://paypal-secure-login.xyz/verify-account", 0.78),
        ("https://en.wikipedia.org/wiki/Phishing", 0.01),
        ("https://bit.ly/3xYzAbC", 0.45),
        ("http://secure-updates.info/account/billing", 0.66),
    ]
    for url, fake_p in SAMPLES:
        r = compute_risk(url, fake_p)
        print(f"\n{url}")
        print(f"  score={r['risk_score']:>3}  level={r['threat_level']:<12}"
              f" class={r['classification']:<11} (demo ML p={fake_p})")
        for s in r["signals"]:
            print(f"   [{s['severity']:<6}] +{s['points']:<2} {s['title']}")
        print(f"  breakdown: {r['risk_breakdown']}")