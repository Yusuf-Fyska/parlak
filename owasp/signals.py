"""
Signal generation for OWASP categories. Uses passive/low-impact checks.
"""

from typing import Dict, List, Tuple


def security_headers(headers: Dict[str, str]) -> List[Tuple[str, str]]:
    findings = []
    required = {
        "content-security-policy": "Missing Content-Security-Policy header",
        "x-frame-options": "Missing X-Frame-Options header",
        "x-content-type-options": "Missing X-Content-Type-Options header",
        "referrer-policy": "Missing Referrer-Policy header",
    }
    for h, msg in required.items():
        if h not in headers:
            findings.append(("Security Misconfiguration", msg))
    if headers.get("strict-transport-security") is None:
        findings.append(("Security Misconfiguration", "Missing HSTS header"))
    return findings


def cookie_flags(headers: Dict[str, str]) -> List[Tuple[str, str]]:
    cookies = headers.get("set-cookie", "")
    findings = []
    if cookies:
        if "secure" not in cookies.lower():
            findings.append(("Security Misconfiguration", "Cookies missing Secure flag"))
        if "httponly" not in cookies.lower():
            findings.append(("Security Misconfiguration", "Cookies missing HttpOnly flag"))
    return findings


def cors_policy(headers: Dict[str, str]) -> List[Tuple[str, str]]:
    origin = headers.get("access-control-allow-origin")
    credentials = headers.get("access-control-allow-credentials")
    if origin == "*":
        return [("Security Misconfiguration", "CORS allows any origin" + (" with credentials" if credentials else ""))]
    return []


def verbose_errors(body: bytes) -> List[Tuple[str, str]]:
    text = body.decode(errors="ignore")
    indicators = ["stack trace", "exception in", "traceback", "fatal error"]
    for ind in indicators:
        if ind in text.lower():
            return [("Injection", f"Verbose error leaks stack trace ({ind})")]
    return []


def outdated_components(headers: Dict[str, str]) -> List[Tuple[str, str]]:
    findings = []
    server = headers.get("server")
    x_powered = headers.get("x-powered-by")
    if server:
        findings.append(("Outdated Components", f"Server header reveals version: {server}"))
    if x_powered:
        findings.append(("Outdated Components", f"X-Powered-By reveals stack: {x_powered}"))
    return findings


def aggregate(meta: Dict, body: bytes) -> List[Tuple[str, str]]:
    headers = meta.get("headers", {})
    signals = []
    signals += security_headers(headers)
    signals += cookie_flags(headers)
    signals += cors_policy(headers)
    signals += verbose_errors(body)
    signals += outdated_components(headers)
    return signals
