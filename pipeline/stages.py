"""
Three-pass state machine (single process):
Pass-0: fast fingerprint
Pass-1: L4 discovery
Pass-2: Web intelligence modules (headers, cors, cookies, exposure, methods, redirects, fingerprint, availability)
"""

import datetime as dt
import hashlib
import socket
import time
from typing import Dict, List, Tuple

from core.models import Finding, TargetProfile
from policy.policy_engine import PolicyEngine, TargetState
from policy.risk_scoring import compute_risk
from probers import http_probe, l4_tcp, tls_fingerprint, web_discovery
from pipeline import web_headers, web_cors, web_cookies, web_redirects, web_methods, web_exposure, web_fingerprint, web_availability


def _hash(text: str) -> str:
    return hashlib.sha1(text.encode()).hexdigest()


def _normalized_url(asset: str, port: int, use_ssl: bool, path: str = "/") -> str:
    scheme = "https" if use_ssl else "http"
    default_port = 443 if use_ssl else 80
    port_part = "" if port == default_port else f":{port}"
    return f"{scheme}://{asset}{port_part}{path}"


def _finding_id(rule_id: str, asset: str, url: str, port: int) -> str:
    return _hash(f"{rule_id}:{asset}:{url}:{port}")


def pass0_fast_fingerprint(host: str, policy: PolicyEngine, state: TargetState) -> Tuple[TargetProfile, Dict]:
    start = time.time()
    tech_hints: List[str] = []
    tls_var = False
    web_var = False
    rtt = None
    likely_ports: List[int] = []
    dns_meta = {}

    # DNS resolve (A/AAAA)
    try:
        infos = socket.getaddrinfo(host, None)
        addrs = list({info[4][0] for info in infos})
        dns_meta["addresses"] = addrs
        dns_meta["ttl"] = None
    except Exception:
        dns_meta["addresses"] = []

    # TCP/RTT
    try:
        t0 = time.time()
        open_, _ = l4_tcp.tcp_probe(host, 80, timeout=2.0)
        if open_:
            web_var = True
            rtt = (time.time() - t0) * 1000
            likely_ports.append(80)
    except Exception:
        pass

    # TLS check
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
        metadata={
            "dns": dns_meta,
            "tls": tls_meta,
            "duration_ms": int((time.time() - start) * 1000),
            "http_chain": [],
        },
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
                    "service_guess": "https" if port in (443, 8443, 9443) else "http" if port in (80, 8080, 8000, 3000, 5000) else "tcp",
                }
            )
    state.open_ports = list(open_ports.keys())
    return open_ports, open_docs


def _analyze_port(profile: TargetProfile, port: int, policy: PolicyEngine, state: TargetState):
    use_ssl = port in (443, 8443, 9443)
    url = _normalized_url(profile.asset, port, use_ssl)
    meta = None
    body = b""
    try:
        if not policy.can_request(state):
            return None, []
        meta, body = http_probe.http_get(profile.asset, port, use_ssl)
    except Exception:
        return None, []

    findings: List[Finding] = []
    redirects = []  # placeholder
    options_meta = None
    try:
        if policy.can_request(state):
            options_meta, _ = http_probe.http_options(profile.asset, port, use_ssl, origin="https://scanner.local")
    except Exception:
        options_meta = None

    ctx = {
        "asset": profile.asset,
        "ip": profile.ip,
        "port": port,
        "use_ssl": use_ssl,
        "url": url,
        "meta": meta,
        "body": body,
        "redirects": redirects,
        "options_meta": options_meta,
        "profile": profile,
        "policy": policy,
        "state": state,
    }

    modules = [
        web_headers.analyze,
        web_cors.analyze,
        web_cookies.analyze,
        web_redirects.analyze,
        web_methods.analyze,
        web_exposure.analyze,
        web_fingerprint.analyze,
        web_availability.analyze,
    ]
    for mod in modules:
        if not policy.can_request(state):
            break
        for f in mod(ctx):
            f.asset = profile.asset
            f.ip = profile.ip
            f.port = port
            f.url = f.url or url
            f.normalized_url = f.normalized_url or url
            f.finding_id = _finding_id(f.rule_id, f.asset, f.normalized_url, f.port)
            findings.append(f)
    return meta, findings


def pass2_web_intel(profile: TargetProfile, open_ports: Dict[int, Dict], policy: PolicyEngine, state: TargetState | None = None) -> Tuple[List[Dict], List[Finding]]:
    signals_docs: List[Dict] = []
    findings: List[Finding] = []
    for port in open_ports:
        if state and state.time_left() <= 0:
            break
        _, fnds = _analyze_port(profile, port, policy, state or TargetState(asset=profile.asset))
        findings.extend(fnds)
    # signals_docs is legacy placeholder
    return signals_docs, findings
