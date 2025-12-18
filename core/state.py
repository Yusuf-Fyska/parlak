"""
In-memory state manager with optional JSON cache for single-node mode.
Keeps the latest run results available for CLI report and local debugging.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

from core.config import settings

log = logging.getLogger(__name__)


class StateManager:
    def __init__(self):
        self.assets: List[Dict] = []
        self.open_ports: List[Dict] = []
        self.signals: List[Dict] = []
        self.findings: List[Dict] = []
        self.cache_path = Path(settings.json_cache_path) if settings.json_cache_path else None
        self._load_cache()

    def _load_cache(self):
        if self.cache_path and self.cache_path.exists():
            try:
                data = json.loads(self.cache_path.read_text())
                self.assets = data.get("assets", [])
                self.open_ports = data.get("open_ports", [])
                self.signals = data.get("signals", [])
                self.findings = data.get("findings", [])
            except Exception:  # noqa: BLE001
                log.warning("failed to load cache from %s", self.cache_path)

    def _persist(self):
        if not self.cache_path:
            return
        snapshot = {
            "assets": self.assets,
            "open_ports": self.open_ports,
            "signals": self.signals,
            "findings": self.findings,
        }
        try:
            self.cache_path.write_text(json.dumps(snapshot, indent=2, default=str))
        except Exception:  # noqa: BLE001
            log.warning("failed to persist cache to %s", self.cache_path)

    def record_assets(self, docs: List[Dict]):
        if not docs:
            return
        self.assets.extend(docs)
        self._persist()

    def record_open_ports(self, docs: List[Dict]):
        if not docs:
            return
        self.open_ports.extend(docs)
        self._persist()

    def record_signals(self, docs: List[Dict]):
        if not docs:
            return
        self.signals.extend(docs)
        self._persist()

    def record_findings(self, docs: List[Dict]):
        if not docs:
            return
        self.findings.extend(docs)
        self._persist()

    def list_findings(self, asset: Optional[str] = None) -> List[Dict]:
        if asset:
            return [f for f in self.findings if f.get("asset") == asset]
        return list(self.findings)
