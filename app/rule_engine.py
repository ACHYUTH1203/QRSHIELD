import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = {
    "login", "verify", "secure", "bank", "password", 
    "otp", "payment", "account", "signin", "wallet", 
    "update", "confirm"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly"
}

def analyze_url(url: str):
    score = 0
    reasons = []
    
    parsed = urlparse(url)
    hostname = parsed.netloc.lower()
    protocol = parsed.scheme.upper() if parsed.scheme else "UNKNOWN"
    domain = hostname if hostname else "Unknown Domain"

    # Tracking exact evaluations for dashboard checklist metric
    checks = {
        "uses_http": False,
        "long_url": False,
        "contains_at": False,
        "uses_ip": False,
        "url_shortener": False,
        "too_many_subdomains": False,
        "too_many_hyphens": False,
        "too_many_digits": False,
        "suspicious_keywords": False
    }

    if parsed.scheme == "http":
        score += 15
        reasons.append("Uses HTTP instead of HTTPS")
        checks["uses_http"] = True

    if len(url) > 75:
        score += 10
        reasons.append("Very long URL")
        checks["long_url"] = True

    if "@" in url:
        score += 25
        reasons.append("Contains '@'")
        checks["contains_at"] = True

    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", hostname):
        score += 30
        reasons.append("Uses IP Address")
        checks["uses_ip"] = True

    if hostname in URL_SHORTENERS:
        score += 20
        reasons.append("Uses URL Shortener")
        checks["url_shortener"] = True

    if hostname.count(".") > 3:
        score += 15
        reasons.append("Too many subdomains")
        checks["too_many_subdomains"] = True

    hyphens = hostname.count("-")
    if hyphens >= 3:
        score += 10
        reasons.append("Too many hyphens")
        checks["too_many_hyphens"] = True

    digits = sum(c.isdigit() for c in hostname)
    if digits > 10:
        score += 10
        reasons.append("Too many digits")
        checks["too_many_digits"] = True

    found = [word for word in SUSPICIOUS_KEYWORDS if word in url.lower()]
    if found:
        score += min(len(found) * 5, 20)
        reasons.append("Suspicious Keywords: " + ", ".join(found))
        checks["suspicious_keywords"] = True

    if score >= 60:
        verdict = "Malicious"
    elif score >= 30:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    return {
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
        "domain": domain,
        "protocol": protocol,
        "checks": checks
    }