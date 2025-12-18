from __future__ import annotations

from typing import Dict, List

from core.models import Evidence, EvidenceResponse, Finding


def analyze(ctx: Dict) -> List[Finding]:
    findings: List[Finding] = []
    meta = ctx.get("meta") or {}
    status = meta.get("status")
    headers = meta.get("headers", {})
    url = ctx.get("url")

    if status in (521, 522, 530):
        ev = Evidence(response=EvidenceResponse(status_code=status, headers=headers))
        findings.append(
            Finding(
                asset=ctx["asset"],
                ip=ctx["ip"],
                port=ctx["port"],
                service_guess="https" if ctx.get("use_ssl") else "http",
                url=url,
                normalized_url=url,
                rule_id="AVAIL_CF_UPSTREAM_ERROR",
                category_bucket="availability",
                owasp_category="Availability",
                owasp_id="Availability",
                title=f"Upstream availability hatası ({status})",
                description="CDN/Upstream yanıt veremedi.",
                impact="Hizmet erişimi kısıtlı olabilir.",
                recommendation="CDN/Origin sağlığını kontrol edin.",
                evidence=ev,
                references=[],
                confidence=60,
                severity="Low",
                scan_profile="pass2",
            )
        )
    return findings
