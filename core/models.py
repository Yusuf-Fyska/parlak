"""
Shared data models for pipeline interchange and Elasticsearch documents.
Lightweight to keep single-node mode simple: Asset -> IP/Port -> Service -> URL -> Finding.
"""

from __future__ import annotations

import datetime as dt
from typing import List, Optional

from pydantic import BaseModel, Field, HttpUrl


class Evidence(BaseModel):
    headers: dict = Field(default_factory=dict)
    status_code: Optional[int] = None
    snippet_hash: Optional[str] = None
    cert: Optional[dict] = None
    tls: Optional[dict] = None
    extra: dict = Field(default_factory=dict)


class Finding(BaseModel):
    asset: str
    ip: str
    port: int
    service_guess: Optional[str] = None
    url: Optional[HttpUrl] = None
    owasp_category: str
    owasp_id: Optional[str] = None
    title: str
    description: str
    evidence: Evidence = Field(default_factory=Evidence)
    confidence: int = Field(ge=0, le=100)
    severity: str
    recommendation: Optional[str] = None
    timestamp: dt.datetime = Field(default_factory=dt.datetime.utcnow)
    timestamps: dict = Field(default_factory=lambda: {"created_at": dt.datetime.utcnow().isoformat()})
    scan_profile: Optional[str] = None
    policy_params: dict = Field(default_factory=dict)


class TargetProfile(BaseModel):
    asset: str
    ip: str
    web_var: bool = False
    tls_var: bool = False
    rtt_estimate_ms: Optional[float] = None
    tech_hints: List[str] = Field(default_factory=list)
    likely_ports: List[int] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)
