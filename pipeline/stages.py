"""
Three-pass state machine (single process):
Pass-0: fast passive fingerprint
Pass-1: L4 discovery
Pass-2: Web + OWASP signals
"""

import datetime as dt
import time
from typing import Dict, List, Tuple

from core.models import Evidence, Finding, TargetProfile
from owasp import evidence as evidence_utils
from owasp import signals as signals_utils
from policy.policy_engine import PolicyEngine, TargetState
from policy.risk_scoring import compute_risk
from probers import http_probe, l4_tcp, tls_fingerprint, web_discovery


def pass0_fast_fingerprint(host: str, policy: PolicyEngine, state: TargetState) -> Tuple[TargetProfile, Dict]:
    start = time.time()
    tech_hints: List[str] = []
    tls_var = False
    web_var = False
    rtt = None
    likely_ports: List[int] = []
    try:
        t0 = time.time()
        open_, _ = l4_tcp.tcp_probe(host, 80, timeout=2.0)
        if open_:
            web_var = True
            rtt = (time.time() - t0) * 1000
            likely_ports.append(80)
    except Exception:
        pass
    try:
        tls_meta = tls_fingerprint.tls_probe(host, 443, timeout=policy.rate_limit_window_s)
        if tls_meta:
            tls_var = True
            web_var = True
            likely_ports.append(443)
    except Exception:
        tls_meta = None
    profile = TargetProfile(
        asset=host,
        ip=host,
        web_var=web_var,
        tls_var=tls_var,
        rtt_estimate_ms=rtt,
        tech_hints=tech_hints,
        likely_ports=likely_ports,
        metadata={"tls": tls_meta, "duration_ms": int((time.time() - start) * 1000)},
    )
    asset_doc = {
        "timestamp": dt.datetime.utcnow().isoformat(),
        "asset": host,
        "ip": host,
        "confidence": 60 if web_var or tls_var else 40,
        "port": None,
        "owasp_id": None,
        "metadata": profile.metadata,
    }
    return profile, asset_doc


def pass1_l4_discovery(profile: TargetProfile, policy: PolicyEngine, state: TargetState) -> Tuple[Dict[int, Dict], List[Dict]]:
    risk = compute_risk(profile.dict())
    ports = policy.choose_ports(state, risk)
    open_ports: Dict[int, Dict] = {}
    open_docs: List[Dict] = []
    for port, is_open, banner in l4_tcp.scan_ports(profile.ip, ports, timeout=2.0):
        if not policy.allow_probe(profile.asset):
            break
        if is_open:
            open_ports[port] = {"banner": banner}
            open_docs.append(
                {
                    "timestamp": dt.datetime.utcnow().isoformat(),
                    "asset": profile.asset,
                    "ip": profile.ip,
                    "port": port,
                    "confidence": 70,
                    "owasp_id": None,
                    "banner": banner,
                }
            )
    state.open_ports = list(open_ports.keys())
    return open_ports, open_docs


def pass2_web_signals(profile: TargetProfile, open_ports: Dict[int, Dict], state: TargetState | None = None) -> Tuple[List[Dict], List[Finding]]:
    signals_docs: List[Dict] = []
    findings: List[Finding] = []
    for port in open_ports:
        if state and state.time_left() <= 0:
            break
        use_ssl = port in (443, 8443, 9443)
        try:
            meta, body = http_probe.http_get(profile.asset, port, use_ssl)
        except Exception:
            continue
        signal_list = signals_utils.aggregate(meta, body)
        for category, desc in signal_list:
            evid_doc = evidence_utils.evidence_from_http(meta, body)
            signals_docs.append(
                {
                    "timestamp": dt.datetime.utcnow().isoformat(),
                    "asset": profile.asset,
                    "ip": profile.ip,
                    "port": port,
                    "confidence": 60,
                    "owasp_id": category,
                    "signal": desc,
                    "evidence": evid_doc,
                }
            )
            findings.append(
                Finding(
                    asset=profile.asset,
                    ip=profile.ip,
                    port=port,
                    service_guess="https" if use_ssl else "http",
                    url=f"http{'s' if use_ssl else ''}://{profile.asset}:{port}/",
                    owasp_category=category,
                    owasp_id=category,
                    title=desc,
                    description=desc,
                    evidence=Evidence(**evid_doc),
                    confidence=70,
                    severity="medium",
                    recommendation="Review configuration and apply hardening per policy.",
                    scan_profile="pass2",
                )
            )
        for path, meta_path in web_discovery.discover(profile.asset, port, use_ssl):
            evid_doc = evidence_utils.evidence_from_http(meta_path, b"")
            findings.append(
                Finding(
                    asset=profile.asset,
                    ip=profile.ip,
                    port=port,
                    service_guess="https" if use_ssl else "http",
                    url=f"http{'s' if use_ssl else ''}://{profile.asset}:{port}{path}",
                    owasp_category="Security Misconfiguration",
                    owasp_id="Security Misconfiguration",
                    title=f"Discovered {path}",
                    description="Default/known path exposed; review access control.",
                    evidence=Evidence(**evid_doc),
                    confidence=50,
                    severity="low",
                    recommendation="Protect or remove default endpoints.",
                    scan_profile="pass2",
                )
            )
    return signals_docs, findings
