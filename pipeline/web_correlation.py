from __future__ import annotations

from typing import Dict, List

from core.models import Finding

SCORES = {"Critical": 100, "High": 80, "Medium": 55, "Low": 25, "Info": 10}


def correlate(findings: List[Finding]) -> Dict[str, int]:
    """
    Basit korelasyon: bazı kombinasyonlar severity skoruna ek puan getirir.
    Sonuç risk_meter (0-100) ve neden listesi için katkı puanları döner.
    """
    contributions: List[str] = []
    score = 0

    # Baz kurallar
    for f in findings[:20]:
        s = SCORES.get(f.severity.title(), 10)
        score += s

    # Korelasyon örnekleri
    has_hsts = any(f.rule_id == "HDR_HSTS_MISSING" for f in findings)
    has_login = any("login" in (f.url or "") for f in findings)
    has_session_cookie = any(f.category_bucket == "cookies" for f in findings)
    if has_hsts and has_login and has_session_cookie:
        score += 20
        contributions.append("+20 HSTS missing + login surface + cookie")

    if any(f.rule_id == "CORS_WILDCARD_CREDS" for f in findings):
        score += 30
        contributions.append("+30 validated CORS creds")

    if any(f.rule_id == "FILE_ENV_EXPOSED" for f in findings):
        score += 40
        contributions.append("+40 .env exposed")

    if not any(f.category_bucket == "exposure" for f in findings):
        score -= 10
        contributions.append("-10 no sensitive endpoints")

    score = max(0, min(100, score // max(1, len(findings[:20]))))
    return {"risk_meter": score, "why": contributions}
