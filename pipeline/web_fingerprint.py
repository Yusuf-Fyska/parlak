from __future__ import annotations

from typing import Dict, List

from core.models import Evidence, EvidenceResponse, Finding


def analyze(ctx: Dict) -> List[Finding]:
    findings: List[Finding] = []
    meta = ctx.get("meta") or {}
    headers = meta.get("headers", {})
    status = meta.get("status")
    url = ctx.get("url")

    stack = []
    if headers.get("server"):
        stack.append(f"Server: {headers['server']}")
    if headers.get("x-powered-by"):
        stack.append(f"X-Powered-By: {headers['x-powered-by']}")

    if stack:
        ev = Evidence(response=EvidenceResponse(status_code=status, headers=headers))
        findings.append(
            Finding(
                asset=ctx["asset"],
                ip=ctx["ip"],
                port=ctx["port"],
                service_guess="https" if ctx.get("use_ssl") else "http",
                url=url,
                normalized_url=url,
                rule_id="TECH_STACK_IDENTIFIED",
                category_bucket="tech",
                owasp_category="Security Misconfiguration",
                owasp_id="Security Misconfiguration",
                title="Teknoloji yığını sızdırıldı",
                description="; ".join(stack),
                impact={"technical": "Stack bilgisi keşfi kolaylaştırır", "business": "Hedefli istismar yüzeyi artar"},
                exploitability={"prerequisites": [], "attack_scenario": "Versiyon bilgisiyle CVE araştırması yapılır"},
                reproduction={"curl": f"curl -I {url}"},
                recommendation=["Versiyon/headereye sınır koyun veya kaldırın."],
                evidence=ev,
                references=[],
                confidence=60,
                severity="Low",
                scan_profile="pass2",
                affected_assets=[ctx["asset"]],
                owner_hint="devops / web",
            )
        )

    return findings
