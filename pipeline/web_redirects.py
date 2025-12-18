from __future__ import annotations

from typing import Dict, List

from core.models import Evidence, EvidenceResponse, Finding


def analyze(ctx: Dict) -> List[Finding]:
    findings: List[Finding] = []
    redirects = ctx.get("redirects") or []
    meta = ctx.get("meta") or {}
    headers = meta.get("headers", {})
    status = meta.get("status")
    url = ctx.get("url")

    # If no redirect info, infer basic http->https check from headers
    if not redirects and headers.get("location"):
        redirects = [{"status": status, "location": headers.get("location")}]

    def add(rule_id: str, title: str, severity: str, impact: str, rec: str):
        ev = Evidence(
            response=EvidenceResponse(status_code=status, headers=headers, redirects=redirects),
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
                category_bucket="redirects",
                owasp_category="Security Misconfiguration",
                owasp_id="Security Misconfiguration",
                title=title,
                description=title,
                impact={"technical": impact, "business": "Güvenlik kontrolü atlanabilir"},
                exploitability={"prerequisites": ["Kullanıcı HTTP ile bağlanabilir"], "attack_scenario": "HTTP downgrade/loop ile kullanıcı yönlendirilir"},
                reproduction={"curl": f"curl -I {url}"},
                recommendation=[rec],
                evidence=ev,
                confidence=70,
                severity=severity,
                scan_profile="pass2",
                references=[],
                affected_assets=[ctx["asset"]],
                owner_hint="reverse-proxy",
            )
        )

    # HTTPS enforcement check
    if not ctx.get("use_ssl"):
        loc = headers.get("location", "")
        if loc and loc.startswith("https://"):
            pass  # enforced
        else:
            add("REDIRECT_NO_HTTPS_ENFORCEMENT", "HTTPS enforcement yok", "High", "HTTP trafik downgrade kalabilir.", "HTTP'den HTTPS'e zorunlu redirect ekleyin.")

    # Loop detection
    if redirects and len(redirects) > 4:
        add("REDIRECT_LOOP", "Redirect zinciri şüpheli/loop", "Medium", "Çoklu hop kullanıcı deneyimini ve güvenliği etkiler.", "Redirect zincirini sadeleştirin.")

    return findings
