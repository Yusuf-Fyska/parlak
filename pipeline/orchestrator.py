"""
Single-node orchestrator: inline pipeline execution with in-memory state
and Elasticsearch bulk output. No queues, workers, Postgres or Redis.
"""

import json
import logging
import time
from typing import Any, Dict, List, Optional

from core.authz_scope import is_authorized_target
from core.config import settings
from core.models import Finding
from core.state import StateManager
from elk.adapter import ElasticsearchAdapter
from pipeline import stages
from policy.policy_engine import PolicyEngine, TargetState

log = logging.getLogger(__name__)


class Orchestrator:
    def __init__(self) -> None:
        self.policy = PolicyEngine()
        self.state = StateManager()
        self.elk = ElasticsearchAdapter() if settings.elasticsearch_url else None
        self.degraded = False

    def _ensure_authorized(self, target: str) -> None:
        if not is_authorized_target(target):
            raise ValueError(f"target {target} not in allowlist or allowlist missing")

    @staticmethod
    def _safe_asset_doc(asset_doc: Dict[str, Any], asset_hint: str | None = None) -> Dict[str, Any]:
        """
        Elasticsearch'e yazarken mapping/field-name sorunları çıkarsa
        dokümanı "raw" altında güvenli şekilde saklamak için normalize eder.

        - Üst düzeyde birkaç sabit alan bırakır.
        - Ham dokümanı raw içine koyar (raw: object enabled:false gibi mappinglerle uyumlu).
        - JSON serialize edilemeyen değerleri string'e çevirir.
        """
        def to_jsonable(obj: Any) -> Any:
            try:
                json.dumps(obj)
                return obj
            except Exception:
                return str(obj)

        # bazı yaygın anahtarlar (dokümanda varsa kullan)
        asset = (
            asset_doc.get("asset")
            or asset_doc.get("target")
            or asset_doc.get("domain")
            or asset_hint
        )

        ip_val = asset_doc.get("ip") or asset_doc.get("ip_address") or asset_doc.get("ipv4")
        domain_val = asset_doc.get("domain") or asset_doc.get("fqdn")

        safe = {
            "created_at": time.time(),
            "asset": asset,
            "domain": domain_val,
            "ip": ip_val,
            "raw": {k: to_jsonable(v) for k, v in (asset_doc or {}).items()},
        }
        return safe

    def _emit(self, index: str, docs: List[Dict[str, Any]]) -> None:
        if not docs:
            return

        # In-memory state
        if index == "surface-assets":
            self.state.record_assets(docs)
        elif index == "surface-open-ports":
            self.state.record_open_ports(docs)
        elif index == "surface-owasp-signals":
            self.state.record_signals(docs)
        elif index == "surface-web-findings":
            self.state.record_findings(docs)

        # Elasticsearch output
        if not self.elk:
            return

        try:
            self.elk.bulk_index(index, docs)
            self.degraded = False
        except Exception as e:
            # Burada genelde BulkIndexError gelir; CLI bunu özet geçiyordu.
            log.exception("ELK bulk_index failed | index=%s | err=%s", index, e)
            self.degraded = True

            # surface-assets için: dokümanı güvenli formata çevirip tekrar dene (tarama ölmesin)
            if index == "surface-assets":
                try:
                    fallback_docs = [self._safe_asset_doc(d, asset_hint=str(d.get("asset") or d.get("target") or "")) for d in docs]
                    log.warning("Retrying surface-assets with safe fallback docs (raw encapsulation).")
                    self.elk.bulk_index(index, fallback_docs)
                    self.degraded = False
                except Exception as e2:
                    log.exception("ELK fallback bulk_index also failed | index=%s | err=%s", index, e2)
                    # burada raise etmiyoruz; pipeline akışı devam edebilsin
                    self.degraded = True

    def discover(self, target: str) -> Dict[str, Any]:
        self._ensure_authorized(target)
        state = TargetState(asset=target)
        profile, asset_doc = stages.pass0_fast_fingerprint(target, self.policy, state)

        # Debug görmek istersen aç:
        # log.info("asset_doc=%s", json.dumps(asset_doc, ensure_ascii=False)[:4000])

        self._emit("surface-assets", [asset_doc])
        return {"profile": profile.dict(), "asset_doc": asset_doc, "degraded": self.degraded}

    def scan(self, target: str) -> Dict[str, Any]:
        self._ensure_authorized(target)
        state = TargetState(asset=target)

        profile, asset_doc = stages.pass0_fast_fingerprint(target, self.policy, state)
        open_ports, open_docs = stages.pass1_l4_discovery(profile, self.policy, state)
        signals, findings = stages.pass2_web_intel(profile, open_ports, self.policy, state)
        # dedupe by finding_id if present
        uniq = {}
        for f in findings:
            key = f.finding_id or f.rule_id + str(f.url)
            if key not in uniq:
                uniq[key] = f
        findings = list(uniq.values())

        self._emit("surface-assets", [asset_doc])
        self._emit("surface-open-ports", open_docs)
        self._emit("surface-owasp-signals", signals)

        finding_docs = [self._finding_to_doc(f) for f in findings]
        self._emit("surface-web-findings", finding_docs)

        summary = self._build_summary(findings, open_ports)

        return {
            "profile": profile.dict(),
            "asset_doc": asset_doc,
            "open_ports_map": open_ports,
            "open_ports": open_docs,
            "signals": signals,
            "findings": finding_docs,
            "summary": summary,
            "degraded": self.degraded,
        }

    def report(self, asset: str) -> List[Dict[str, Any]]:
        if self.elk and asset:
            docs = self.elk.search_by_asset("surface-web-findings", asset, size=100)
            if docs:
                return docs
        return self.state.list_findings(asset)

    def list_assets(self, query: Optional[str] = None, size: int = 50) -> List[Dict[str, Any]]:
        if self.elk:
            docs = self.elk.search_assets(query=query, size=size)
            if docs:
                return docs
        assets = self.state.assets
        if query:
            q = query.lower()
            assets = [a for a in assets if q in str(a.get("asset", "")).lower() or q in str(a.get("ip", "")).lower()]
        return assets[:size]

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

        return {"allowlist": allowlist_ok, "elk": elk_ok, "test_doc_written": test_doc_written, "degraded": self.degraded}

    @staticmethod
    def _finding_to_doc(f: Finding) -> Dict[str, Any]:
        return {
            "timestamp": f.timestamp.isoformat(),
            "asset": f.asset,
            "ip": f.ip,
            "port": f.port,
            "confidence": f.confidence,
            "owasp_id": f.owasp_id or f.owasp_category,
            "service_guess": f.service_guess,
            "url": str(f.url) if f.url else None,
            "normalized_url": f.normalized_url,
            "rule_id": f.rule_id,
            "category_bucket": f.category_bucket,
            "title": f.title,
            "description": f.description,
            "impact": f.impact,
            "evidence": f.evidence.dict(),
            "severity": f.severity,
            "recommendation": f.recommendation,
            "scan_profile": f.scan_profile,
            "policy_params": f.policy_params,
            "references": f.references,
            "finding_id": f.finding_id,
            "extra": f.extra,
        }

    @staticmethod
    def _build_summary(findings: List[Finding], open_ports: Dict[str, Any]) -> Dict[str, Any]:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        owasp: Dict[str, int] = {}
        ports = list(open_ports.keys())
        for f in findings:
            sev = f.severity.title() if f.severity else "Info"
            counts[sev] = counts.get(sev, 0) + 1
            if f.owasp_id:
                owasp[f.owasp_id] = owasp.get(f.owasp_id, 0) + 1
        top_owasp = sorted(owasp.items(), key=lambda x: x[1], reverse=True)[:5]
        return {
            "counts_by_severity": counts,
            "top_owasp": [k for k, _ in top_owasp],
            "ports_scanned": ports,
            "ports_open": ports,
            "time_spent_ms": {},
            "degraded": False,
        }


def run_single(target: str) -> List[dict]:
    orch = Orchestrator()
    results = orch.scan(target)
    return results.get("findings", [])
