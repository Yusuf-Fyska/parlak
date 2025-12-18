from __future__ import annotations

from typing import Dict, List

from core.models import Evidence, EvidenceResponse, Finding


def analyze(ctx: Dict) -> List[Finding]:
    findings: List[Finding] = []
    meta = ctx.get("meta") or {}
    headers = meta.get("headers", {})
    status = meta.get("status")
    url = ctx.get("url")

    set_cookie = headers.get("set-cookie", "")
    if not set_cookie:
        return findings

    lower = set_cookie.lower()
    candidates = ["session", "sid", "jwt", "token"]
    session_like = any(c in lower for c in candidates)

    def add(rule_id: str, title: str, severity: str, impact: str, rec: str, confidence: int = 70):
        ev = Evidence(
            response=EvidenceResponse(status_code=status, headers={"set-cookie": set_cookie}),
        )
        findings.append(
            Finding(
                asset=ctx["asset"],
                ip=ctx["ip"],
                port=ctx["port"],
                service_guess="https" if ctx.get("use_ssl") else "http",
                url=url,
                normalized_url=url,
                rule_id=rule_id,
                category_bucket="cookies",
                owasp_category="Security Misconfiguration",
                owasp_id="Security Misconfiguration",
                title=title,
                description=title,
                impact={"technical": impact, "business": "Oturum çalınması riski"},
                exploitability={"prerequisites": ["Kurban tarayıcıda oturum açık"], "attack_scenario": "Cookie çalınarak yetki ele geçirilir"},
                reproduction={"curl": f"curl -I {url}"},
                recommendation=[rec],
                evidence=ev,
                references=[],
                confidence=confidence,
                severity=severity,
                scan_profile="pass2",
                affected_assets=[ctx["asset"]],
                owner_hint="backend / auth",
            )
        )

    if "secure" not in lower:
        sev = "High" if session_like else "Medium"
        add("COOKIE_INSECURE", "Cookie Secure flag eksik", sev, "Taşıma katmanında çalınabilir.", "Set-Cookie: ...; Secure")
    if "httponly" not in lower:
        sev = "High" if session_like else "Medium"
        add("COOKIE_HTTPONLY_MISSING", "Cookie HttpOnly eksik", sev, "JS ile okunabilir.", "Set-Cookie: ...; HttpOnly")
    if "samesite" not in lower:
        add("COOKIE_SAMESITE_MISSING", "SameSite eksik", "Medium", "CSRF riski artar.", "Set-Cookie: ...; SameSite=Lax")
    if "samesite=none" in lower and "secure" not in lower:
        add("COOKIE_SAMESITE_NONE_INSECURE", "SameSite=None ama Secure yok", "High", "Tarayıcı kabul etmeyebilir / riskli.", "SameSite=None için Secure zorunludur.", confidence=80)

    return findings
