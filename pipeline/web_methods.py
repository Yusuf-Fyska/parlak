from __future__ import annotations

from typing import Dict, List

from core.models import Evidence, EvidenceResponse, Finding


def analyze(ctx: Dict) -> List[Finding]:
    meta = ctx.get("meta") or {}
    headers = meta.get("headers", {})
    status = meta.get("status")
    allow = headers.get("allow", "")
    url = ctx.get("url")
    findings: List[Finding] = []

    if not allow:
        return findings

    allow_lower = allow.lower()

    def add(rule_id: str, title: str, severity: str, impact: str, rec: str):
        ev = Evidence(response=EvidenceResponse(status_code=status, headers={"allow": allow}))
        findings.append(
            Finding(
                asset=ctx["asset"],
                ip=ctx["ip"],
                port=ctx["port"],
                service_guess="https" if ctx.get("use_ssl") else "http",
                url=url,
                normalized_url=url,
                rule_id=rule_id,
                category_bucket="methods",
                owasp_category="Security Misconfiguration",
                owasp_id="Security Misconfiguration",
                title=title,
                description=title,
                impact=impact,
                recommendation=rec,
                evidence=ev,
                references=[],
                confidence=70,
                severity=severity,
                scan_profile="pass2",
            )
        )

    if "trace" in allow_lower:
        add("HTTP_METHOD_TRACE_ENABLED", "TRACE metodu açık", "High", "TRACE, header yansımasıyla bilgi sızdırabilir.", "TRACE metodunu kapatın.")
    if "put" in allow_lower or "delete" in allow_lower:
        add("HTTP_METHOD_PUT_DELETE_OPEN", "PUT/DELETE açık", "High", "Yanlış yapılandırma veri bütünlüğünü etkileyebilir.", "PUT/DELETE metodlarını kısıtlayın.")
    if "options" in allow_lower and "," not in allow_lower:
        add("HTTP_ALLOW_OPTIONS_ENUM", "OPTIONS listesi açık", "Low", "Metod keşfi yapılabilir.", "Allow header'ını sınırlayın.")

    return findings
