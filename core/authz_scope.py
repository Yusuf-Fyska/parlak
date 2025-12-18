"""
Scope enforcement: ensures all scan targets are within allowlisted
CIDRs/domains to avoid unauthorized scanning.
"""

import ipaddress
import socket
from typing import Iterable, List

from .config import settings


def _resolve_host(host: str) -> List[str]:
    try:
        infos = socket.getaddrinfo(host, None)
        return list({info[4][0] for info in infos})
    except socket.gaierror:
        return []


def _cidr_match(ip: str, cidrs: Iterable[str]) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            if ip_obj in ipaddress.ip_network(cidr):
                return True
        except ValueError:
            continue
    return False


def _domain_match(host: str, domains: Iterable[str]) -> bool:
    host = host.lower()
    for d in domains:
        d = d.lower()
        if host == d or host.endswith("." + d):
            return True
    return False


def is_authorized_target(target: str) -> bool:
    """
    Validate target (hostname or IP) against allowlist CIDRs/domains.
    DNS is resolved to bind host to IPs and checked against CIDR list.
    """
    cidrs = settings.allowlist_cidrs
    domains = settings.allowlist_domains
    if not cidrs and not domains:
        return False  # explicit allowlist required

    resolved_ips = _resolve_host(target)
    if _domain_match(target, domains):
        if cidrs:
            return any(_cidr_match(ip, cidrs) for ip in resolved_ips)
        return True
    if any(_cidr_match(ip, cidrs) for ip in resolved_ips):
        return True
    return False
