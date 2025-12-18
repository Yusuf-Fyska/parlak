from __future__ import annotations

from typing import Dict, List

from core.models import Evidence, EvidenceHTTP, EvidenceResponse, Finding


def analyze(ctx: Dict) -> List[Finding]:
    findings: List[Finding] = []
    options = ctx.get("options_meta") or {}
    headers = options.get("headers", {})
    status = options.get("status")
    url = ctx.get("url")

    acao = headers.get("access-control-allow-origin")
    acc = headers.get("access-control-allow-credentials")
    origin = "https://scanner.local"

    def add(rule_id: str, title: str, severity: str, impact: str, rec: str):
        ev = Evidence(
            request=EvidenceHTTP(method="OPTIONS", url=url, headers={"Origin": origin}),
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
                category_bucket="cors",
                owasp_category="Security Misconfiguration",
                owasp_id="Security Misconfiguration",
                title=title,
                description=title,
                impact={"technical": impact, "business": "Account/data leakage riski"},
                exploitability={
                    "prerequisites": ["Victim logged in", "Browser honors credentials"],
                    "attack_scenario": "Malicious site origin yansımasını kullanarak veri çeker",
                },
                reproduction={"curl": f"curl -X OPTIONS -H \"Origin: https://evil.example\" {url}"},
                recommendation=[rec, "Wildcard yerine sabit origin listesi kullanın", "Credentials'ı kapatın"],
                references=["https://cheatsheetseries.owasp.org/cheatsheets/CORS_Cheat_Sheet.html"],
                evidence=ev,
                confidence=90 if status and status < 400 else 60,
                severity=severity,
                scan_profile="pass2",
                affected_assets=[ctx["asset"]],
                owner_hint="backend / api gateway",
            )
        )

    if not headers:
        return findings

    if acao == "*" and (acc or "").lower() == "true":
        add("CORS_WILDCARD_CREDS", "CORS wildcard + credentials açık", "Critical", "Her origin oturum bilgisiyle çağrı yapabilir.", "CORS'u kısıtla; wildcard + credentials kombinasyonunu kapat.")
    elif acao == "*" and not acc:
        add("CORS_OVERPERMISSIVE", "CORS wildcard açık", "Medium", "Her origin içerik çekebilir.", "Özel origin listesi kullanın.")
    elif acao and origin in acao:
        add("CORS_REFLECT_CREDS", "CORS origin yansıtılıyor", "High", "Rastgele origin yansıtılıyor olabilir.", "Origin yansıtma yerine sabit liste kullanın.")

    return findings
