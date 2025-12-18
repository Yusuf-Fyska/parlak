from __future__ import annotations

from typing import Dict, List

from core.models import Evidence, EvidenceResponse, Finding
from probers import http_probe

SENSITIVE_PATHS = [
    ("/.git/HEAD", "FILE_GIT_EXPOSED", "Critical"),
    ("/.env", "FILE_ENV_EXPOSED", "Critical"),
    ("/security.txt", "FILE_WELLKNOWN_SECURITYTXT", "Low"),
    ("/wp-json/", "FILE_WP_JSON_EXPOSED", "Medium"),
    ("/swagger", "FILE_SWAGGER_EXPOSED", "Medium"),
    ("/openapi.json", "FILE_SWAGGER_EXPOSED", "Medium"),
]


def analyze(ctx: Dict) -> List[Finding]:
    findings: List[Finding] = []
    policy = ctx.get("policy")
    if not policy:
        return findings
    asset = ctx["asset"]
    host = ctx["asset"]
    port = ctx["port"]
    use_ssl = ctx.get("use_ssl")

    for path, rule_id, default_sev in SENSITIVE_PATHS:
        if not policy.can_request(ctx["state"]):
            break
        if policy.sensitive_paths and path not in policy.sensitive_paths:
            continue
        try:
            meta, body = http_probe.http_get(host, port, use_ssl, path=path)
        except Exception:
            continue
        status = meta.get("status")
        if not status or status >= 400:
            continue
        url = f"{'https' if use_ssl else 'http'}://{asset}:{port}{path}"
        ev = Evidence(
            response=EvidenceResponse(
                status_code=status,
                headers=meta.get("headers", {}),
                body_hash=meta.get("hash"),
                content_type=meta.get("headers", {}).get("content-type"),
                content_length=int(meta.get("headers", {}).get("content-length", "0") or 0),
            )
        )
        impact = "Kritik dosya herkese açık." if default_sev == "Critical" else "Bilgi sızıntısı riski."
        rec = "Erişimi kapatın veya kimlik doğrulama arkasına alın."
        findings.append(
            Finding(
                asset=asset,
                ip=ctx["ip"],
                port=port,
                service_guess="https" if use_ssl else "http",
                url=url,
                normalized_url=url,
                rule_id=rule_id,
                category_bucket="exposure",
                owasp_category="Sensitive Data Exposure",
                owasp_id="Sensitive Data Exposure",
                title=f"Exposed path {path}",
                description=f"{path} herkese açık",
                impact=impact,
                recommendation=rec,
                evidence=ev,
                references=[],
                confidence=90,
                severity=default_sev,
                scan_profile="pass2",
            )
        )

    return findings
