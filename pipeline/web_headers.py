from __future__ import annotations

from typing import Dict, List

from core.models import Evidence, EvidenceResponse, Finding


def _severity_for_csp(headers: Dict[str, str]) -> str:
    csp = headers.get("content-security-policy")
    if not csp:
        return "Medium"
    if "unsafe-eval" in csp or "unsafe-inline" in csp:
        return "High"
    if "report-only" in csp:
        return "Medium"
    return "Low"


def analyze(ctx: Dict) -> List[Finding]:
    meta = ctx.get("meta") or {}
    headers = meta.get("headers", {})
    status = meta.get("status")
    url = ctx.get("url")
    findings: List[Finding] = []

    def add(rule_id: str, bucket: str, title: str, severity: str, impact: str, rec: str):
        ev = Evidence(
            response=EvidenceResponse(status_code=status, headers=headers),
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
                category_bucket=bucket,
                owasp_category="Security Misconfiguration",
                owasp_id="Security Misconfiguration",
                title=title,
                description=title,
                impact={"technical": impact, "business": "Tarayıcı tabanlı sömürü riski"},
                exploitability={
                    "prerequisites": ["Kullanıcı tarayıcı üzerinden siteyi ziyaret eder"],
                    "attack_scenario": "Eksik/zayıf header üzerinden XSS/Clickjacking mümkün olur",
                },
                reproduction={"curl": f"curl -I {url}"},
                recommendation=[rec],
                references=[],
                evidence=ev,
                confidence=80 if status and status < 400 else 60,
                severity=severity,
                scan_profile="pass2",
                affected_assets=[ctx["asset"]],
                owner_hint="frontend / reverse-proxy",
            )
        )

    # CSP
    csp = headers.get("content-security-policy")
    if not csp:
        add("HDR_CSP_MISSING", "headers", "CSP header missing", "Medium", "Tarayıcı tabanlı XSS/çerçevelemeye karşı zayıf.", "CSP ekleyin (default-src 'self').")
    else:
        if "unsafe-inline" in csp or "unsafe-eval" in csp:
            add("HDR_CSP_WEAK", "headers", "CSP zayıf (unsafe-inline/eval)", "High", "Zayıf CSP XSS riskini arttırır.", "CSP'den unsafe-inline/eval kaldırın.")

    # HSTS
    hsts = headers.get("strict-transport-security")
    if not hsts:
        add("HDR_HSTS_MISSING", "headers", "HSTS header missing", "High", "HTTPS downgrade mümkündür.", "Strict-Transport-Security: max-age=15552000; includeSubDomains; preload")
    # XFO
    if "x-frame-options" not in headers:
        add("HDR_XFO_MISSING", "headers", "X-Frame-Options missing", "Medium", "Clickjacking riski artar.", "X-Frame-Options: SAMEORIGIN veya frame-ancestors CSP ekleyin.")
    # XCTO
    if "x-content-type-options" not in headers:
        add("HDR_XCTO_MISSING", "headers", "X-Content-Type-Options missing", "Medium", "MIME sniffing riski artar.", "X-Content-Type-Options: nosniff")
    # Referrer
    if "referrer-policy" not in headers:
        add("HDR_REFERRER_POLICY_WEAK", "headers", "Referrer-Policy eksik", "Low", "Referrer bilgisi sızabilir.", "Referrer-Policy: strict-origin-when-cross-origin")
    # Permissions-Policy
    if "permissions-policy" not in headers:
        add("HDR_PERMISSIONS_POLICY_MISSING", "headers", "Permissions-Policy eksik", "Low", "Tarayıcı özellikleri sınırlanmamış.", "Permissions-Policy: geolocation=(), camera=() ...")

    return findings
