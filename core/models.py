"""
Shared data models for pipeline interchange and Elasticsearch documents.
Lightweight to keep single-node mode simple: Asset -> IP/Port -> Service -> URL -> Finding.
"""

from __future__ import annotations

import datetime as dt
from typing import List, Optional

from pydantic import BaseModel, Field, HttpUrl


class EvidenceHTTP(BaseModel):
    method: Optional[str] = None
    url: Optional[str] = None
    headers: dict = Field(default_factory=dict)


class EvidenceResponse(BaseModel):
    status_code: Optional[int] = None
    headers: dict = Field(default_factory=dict)
    redirects: List[dict] = Field(default_factory=list)
    body_hash: Optional[str] = None
    snippet_hash: Optional[str] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None


class Evidence(BaseModel):
    request: EvidenceHTTP = Field(default_factory=EvidenceHTTP)
    response: EvidenceResponse = Field(default_factory=EvidenceResponse)
    extra: dict = Field(default_factory=dict)


class Finding(BaseModel):
    asset: str
    ip: str
    port: int
    service_guess: Optional[str] = None
    url: Optional[HttpUrl] = None
    normalized_url: Optional[str] = None
    rule_id: str
    category_bucket: str
    owasp_category: str
    owasp_id: Optional[str] = None
    title: str
    description: str
    impact: Optional[str] = None
    recommendation: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    evidence: Evidence = Field(default_factory=Evidence)
    confidence: int = Field(ge=0, le=100)
    severity: str
    timestamp: dt.datetime = Field(default_factory=dt.datetime.utcnow)
    scan_profile: Optional[str] = None
    policy_params: dict = Field(default_factory=dict)
    finding_id: Optional[str] = None
    category: Optional[str] = None  # legacy compat
    extra: dict = Field(default_factory=dict)


class TargetProfile(BaseModel):
    asset: str
    ip: str
    web_var: bool = False
    tls_var: bool = False
    rtt_estimate_ms: Optional[float] = None
    tech_hints: List[str] = Field(default_factory=list)
    likely_ports: List[int] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)
