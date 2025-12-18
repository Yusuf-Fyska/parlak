"""
Single-node orchestrator: inline pipeline execution with in-memory state
and Elasticsearch bulk output. No queues, workers, Postgres or Redis.
"""

import logging
import time
from typing import Dict, List

from core.authz_scope import is_authorized_target
from core.config import settings
from core.models import Finding
from core.state import StateManager
from elk.adapter import ElasticsearchAdapter
from pipeline import stages
from policy.policy_engine import PolicyEngine, TargetState

log = logging.getLogger(__name__)


class Orchestrator:
    def __init__(self):
        self.policy = PolicyEngine()
        self.state = StateManager()
        self.elk = ElasticsearchAdapter() if settings.elasticsearch_url else None

    def _ensure_authorized(self, target: str):
        if not is_authorized_target(target):
            raise ValueError(f"target {target} not in allowlist or allowlist missing")

    def _emit(self, index: str, docs: List[Dict]):
        if not docs:
            return
        if index == "surface-assets":
            self.state.record_assets(docs)
        elif index == "surface-open-ports":
            self.state.record_open_ports(docs)
        elif index == "surface-owasp-signals":
            self.state.record_signals(docs)
        elif index == "surface-web-findings":
            self.state.record_findings(docs)
        if self.elk:
            self.elk.bulk_index(index, docs)

    def discover(self, target: str) -> Dict:
        self._ensure_authorized(target)
        state = TargetState(asset=target)
        profile, asset_doc = stages.pass0_fast_fingerprint(target, self.policy, state)
        self._emit("surface-assets", [asset_doc])
        return {"profile": profile.dict(), "asset_doc": asset_doc}

    def scan(self, target: str) -> Dict:
        self._ensure_authorized(target)
        state = TargetState(asset=target)
        profile, asset_doc = stages.pass0_fast_fingerprint(target, self.policy, state)
        open_ports, open_docs = stages.pass1_l4_discovery(profile, self.policy, state)
        signals, findings = stages.pass2_web_signals(profile, open_ports, state)

        self._emit("surface-assets", [asset_doc])
        self._emit("surface-open-ports", open_docs)
        self._emit("surface-owasp-signals", signals)
        finding_docs = [self._finding_to_doc(f) for f in findings]
        self._emit("surface-web-findings", finding_docs)

        return {
            "profile": profile.dict(),
            "asset_doc": asset_doc,
            "open_ports": open_ports,
            "signals": signals,
            "findings": finding_docs,
        }

    def report(self, asset: str) -> List[Dict]:
        if self.elk and asset:
            docs = self.elk.search_by_asset("surface-web-findings", asset, size=100)
            if docs:
                return docs
        return self.state.list_findings(asset)

    def verify(self, write_test_doc: bool = False) -> Dict[str, bool]:
        allowlist_ok = bool(settings.allowlist_cidrs or settings.allowlist_domains)
        elk_ok = False
        test_doc_written = False
        if self.elk:
            elk_ok = self.elk.ping()
            if write_test_doc:
                test_doc = {
                    "timestamp": time.time(),
                    "asset": "verify-test",
                    "ip": "127.0.0.1",
                    "confidence": 100,
                    "port": None,
                    "owasp_id": None,
                    "note": "health-check",
                }
                self.elk.bulk_index("surface-assets", [test_doc])
                test_doc_written = True
        return {"allowlist": allowlist_ok, "elk": elk_ok, "test_doc_written": test_doc_written}

    @staticmethod
    def _finding_to_doc(f: Finding) -> Dict:
        return {
            "timestamp": f.timestamp.isoformat(),
            "asset": f.asset,
            "ip": f.ip,
            "port": f.port,
            "confidence": f.confidence,
            "owasp_id": f.owasp_id or f.owasp_category,
            "service_guess": f.service_guess,
            "url": str(f.url) if f.url else None,
            "title": f.title,
            "description": f.description,
            "evidence": f.evidence.dict(),
            "severity": f.severity,
            "recommendation": f.recommendation,
            "scan_profile": f.scan_profile,
            "policy_params": f.policy_params,
        }


def run_single(target: str) -> List[dict]:
    orch = Orchestrator()
    results = orch.scan(target)
    return results.get("findings", [])
