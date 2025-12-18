"""
FastAPI proxy exposing scanner actions without exposing Elasticsearch directly.
Reads ES credentials from .env (via core.config) and forwards to orchestrator.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from pipeline.orchestrator import Orchestrator

log = logging.getLogger(__name__)

app = FastAPI(title="Surface Scanner API", version="1.0")
orch = Orchestrator()


class TargetPayload(BaseModel):
    target: str


@app.post("/api/discover")
def api_discover(payload: TargetPayload):
    try:
        return orch.discover(payload.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        log.exception("discover failed")
        raise HTTPException(status_code=500, detail="discover failed") from exc


@app.post("/api/scan")
def api_scan(payload: TargetPayload):
    try:
        return orch.scan(payload.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        log.exception("scan failed")
        raise HTTPException(status_code=500, detail="scan failed") from exc


@app.get("/api/report")
def api_report(asset: str = Query(...)):
    try:
        return {"findings": orch.report(asset)}
    except Exception as exc:  # noqa: BLE001
        log.exception("report failed")
        raise HTTPException(status_code=500, detail="report failed") from exc


@app.get("/api/assets")
def api_assets(query: Optional[str] = Query(None), size: int = Query(50, ge=1, le=200)):
    try:
        return {"assets": orch.list_assets(query=query, size=size)}
    except Exception as exc:  # noqa: BLE001
        log.exception("assets search failed")
        raise HTTPException(status_code=500, detail="assets search failed") from exc


@app.get("/api/health")
def api_health():
    try:
        return orch.verify()
    except Exception as exc:  # noqa: BLE001
        log.exception("health check failed")
        raise HTTPException(status_code=500, detail="health check failed") from exc
