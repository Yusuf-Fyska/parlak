"""
Adaptive policy engine implementing budgeting, prioritization, and
rate/backoff knobs. The engine maintains per-target state and exposes
decisions to the orchestrator/pipeline.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from core.config import settings
from policy.risk_scoring import RiskScore


@dataclass
class TargetState:
    asset: str
    start_ts: float = field(default_factory=time.time)
    rtt_ms: Optional[float] = None
    open_ports: List[int] = field(default_factory=list)
    depth: int = 0
    backoff_until: float = 0.0
    budget_s: int = settings.scan_time_budget_per_target
    requests_made: int = 0

    def time_left(self) -> float:
        return max(0.0, self.budget_s - (time.time() - self.start_ts))


class PolicyEngine:
    def __init__(self):
        self.global_tokens = settings.global_concurrency
        self.per_target_tokens: Dict[str, int] = {}
        self.rate_limit_window_s = 1.0
        self.last_tick = time.time()
        self.enabled_rules: Set[str] = set()  # empty => all enabled
        self.max_requests_per_target: int = 40
        self.sensitive_paths: List[str] = [
            "/.git/HEAD",
            "/.env",
            "/wp-json/",
            "/swagger",
            "/openapi.json",
            "/api-docs",
        ]

    def _refresh_tokens(self):
        now = time.time()
        if now - self.last_tick >= self.rate_limit_window_s:
            self.global_tokens = settings.global_concurrency
            self.per_target_tokens = {}
            self.last_tick = now

    def allow_probe(self, target: str) -> bool:
        self._refresh_tokens()
        tgt_tokens = self.per_target_tokens.get(target, settings.per_target_concurrency)
        if self.global_tokens <= 0 or tgt_tokens <= 0:
            return False
        self.global_tokens -= 1
        self.per_target_tokens[target] = tgt_tokens - 1
        return True

    def backoff(self, state: TargetState, reason: str, duration: float = 5.0):
        state.backoff_until = time.time() + duration

    def is_backing_off(self, state: TargetState) -> bool:
        return time.time() < state.backoff_until

    def can_request(self, state: TargetState) -> bool:
        if state.requests_made >= self.max_requests_per_target:
            return False
        if state.time_left() <= 0:
            return False
        state.requests_made += 1
        return True

    def choose_ports(self, state: TargetState, risk: RiskScore) -> List[int]:
        ports = list(settings.top_ports_web)
        if "ssh" in risk.hints:
            ports += [22]
        if "db" in risk.hints:
            ports += settings.top_ports_db
        if risk.score > 60:
            ports += [8081, 8888]
        return sorted({p for p in ports if p < 65536})

    def should_expand(self, state: TargetState, risk: RiskScore) -> bool:
        return risk.score > 75 and state.time_left() > 20

    def rule_enabled(self, rule_id: str) -> bool:
        if not self.enabled_rules:
            return True
        return rule_id in self.enabled_rules
