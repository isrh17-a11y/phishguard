"""URL feature extraction for PhishGuard.

extract_features(url) -> dict of numeric features, always the same keys in the
same order (FEATURE_NAMES). Used by BOTH training and the FastAPI inference
path, so the two can never drift apart.
"""
import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlparse

import tldextract

# Offline extractor: uses the suffix list bundled with tldextract, so it never
# makes a network call at runtime (important for deployment and speed).
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy",
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "account", "update",
    "confirm", "banking", "bank", "password", "wallet", "paypal", "ebay",
    "webscr", "support", "billing", "invoice", "suspend", "unlock", "recover",
    "free", "bonus", "gift", "prize",
]

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "link", "work",
    "zip", "country", "kim", "loan", "men", "review", "icu", "cyou",
}

SPECIAL_CHARS = set("!#$%^&*()+=[]{};:'\",<>?|\\~`")

FEATURE_NAMES = [
    "url_length", "hostname_length", "domain_length", "path_length",
    "query_length", "num_dots", "num_hyphens", "num_hyphens_in_host",
    "num_underscores", "num_digits", "digit_ratio", "num_special_chars",
    "num_subdomains", "has_ip_host", "is_https", "has_at_symbol",
    "is_shortener", "num_suspicious_keywords", "url_entropy",
    "hostname_entropy", "num_encoded_chars", "num_params", "path_depth",
    "has_port", "suspicious_tld", "double_slash_in_path", "has_punycode",
    "longest_digit_run",
]


def normalize_url(url: str) -> str:
    """Strip whitespace and add a scheme if missing so urlparse behaves."""
    url = (url or "").strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_ip(host: str) -> bool:
    host = host.strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # decimal / hex encoded IPs like http://3232235777 or http://0xC0A80001
    return bool(re.fullmatch(r"\d{8,10}|0x[0-9a-fA-F]{6,8}", host))


def extract_features(url: str) -> dict:
    raw = (url or "").strip()
    norm = normalize_url(raw)
    try:
        p = urlparse(norm)
        host = (p.hostname or "").lower()
        path = p.path or ""
        query = p.query or ""
        port = p.port
    except ValueError:
        # malformed (e.g. bad port / bracket): fall back to safe defaults
        host, path, query, port = "", "", "", None
        p = urlparse("http://invalid")

    ext = _extract(host) if host and not _is_ip(host) else None
    subdomain = ext.subdomain if ext else ""
    suffix = ext.suffix if ext else ""
    domain = ext.domain if ext else host
    lower = norm.lower()

    num_digits = sum(ch.isdigit() for ch in raw)
    digit_runs = re.findall(r"\d+", raw)

    feats = {
        "url_length": len(raw),
        "hostname_length": len(host),
        "domain_length": len(domain),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": raw.count("."),
        "num_hyphens": raw.count("-"),
        "num_hyphens_in_host": host.count("-"),
        "num_underscores": raw.count("_"),
        "num_digits": num_digits,
        "digit_ratio": num_digits / len(raw) if raw else 0.0,
        "num_special_chars": sum(ch in SPECIAL_CHARS for ch in raw),
        "num_subdomains": len([s for s in subdomain.split(".") if s and s != "www"]),
        "has_ip_host": int(_is_ip(host)) if host else 0,
        "is_https": int(p.scheme == "https"),
        "has_at_symbol": int("@" in raw),
        "is_shortener": int(host in SHORTENERS),
        "num_suspicious_keywords": sum(k in lower for k in SUSPICIOUS_KEYWORDS),
        "url_entropy": shannon_entropy(raw),
        "hostname_entropy": shannon_entropy(host),
        "num_encoded_chars": len(re.findall(r"%[0-9a-fA-F]{2}", raw)),
        "num_params": len([q for q in query.split("&") if q]),
        "path_depth": len([s for s in path.split("/") if s]),
        "has_port": int(port is not None and port not in (80, 443)),
        "suspicious_tld": int(suffix.split(".")[-1] in SUSPICIOUS_TLDS) if suffix else 0,
        "double_slash_in_path": int("//" in path),
        "has_punycode": int("xn--" in host),
        "longest_digit_run": max((len(d) for d in digit_runs), default=0),
    }
    # guarantee stable column order
    return {k: feats[k] for k in FEATURE_NAMES}


if __name__ == "__main__":
    tests = [
        "https://www.google.com",
        "http://192.168.1.1/login.php",
        "http://secure-paypal-login.verify-account.xyz/webscr?cmd=_login&id=%2F123",
        "bit.ly/3abcde",
        "",
    ]
    for t in tests:
        print(t, "->", extract_features(t))
