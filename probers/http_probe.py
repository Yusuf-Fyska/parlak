"""
HTTP probing with HEAD/GET, minimal redirects and timeouts.
"""

import hashlib
import http.client
import ssl
from typing import Dict, Optional, Tuple

from core.config import settings


def _do_request(method: str, host: str, port: int, use_ssl: bool, path: str = "/") -> Tuple[Dict, bytes]:
    timeout = settings.http_timeout_s
    conn_cls = http.client.HTTPSConnection if use_ssl else http.client.HTTPConnection
    context = ssl._create_unverified_context() if use_ssl else None
    conn = conn_cls(host, port, timeout=timeout, context=context) if use_ssl else conn_cls(host, port, timeout=timeout)
    headers = {"User-Agent": settings.user_agent}
    conn.request(method, path, headers=headers)
    resp = conn.getresponse()
    data = resp.read(4096)
    headers_out = {k.lower(): v for k, v in resp.getheaders()}
    return (
        {
            "status": resp.status,
            "reason": resp.reason,
            "headers": headers_out,
            "hash": hashlib.sha1(data).hexdigest(),
        },
        data,
    )


def http_head(host: str, port: int, use_ssl: bool) -> Tuple[Dict, bytes]:
    return _do_request("HEAD", host, port, use_ssl)


def http_get(host: str, port: int, use_ssl: bool, path: str = "/") -> Tuple[Dict, bytes]:
    return _do_request("GET", host, port, use_ssl, path=path)
