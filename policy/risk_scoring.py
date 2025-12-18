"""
Risk scoring: simple heuristic combining surface hints with repeatable
signals. Outputs risk.score (0-100) plus hints that guide probing.
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class RiskScore:
    score: int
    confidence: int
    hints: List[str] = field(default_factory=list)


def compute_risk(target_profile: dict) -> RiskScore:
    score = 10
    hints: List[str] = []
    if target_profile.get("web_var"):
        score += 30
        hints.append("web")
    if target_profile.get("tls_var"):
        score += 10
    if "ssh" in target_profile.get("tech_hints", []):
        score += 10
        hints.append("ssh")
    if "db" in target_profile.get("tech_hints", []):
        score += 10
        hints.append("db")
    rtt = target_profile.get("rtt_estimate_ms")
    if rtt and rtt < 50:
        score += 10
    score = min(100, score)
    confidence = 50 + len(hints) * 10
    return RiskScore(score=score, confidence=min(confidence, 90), hints=hints)
