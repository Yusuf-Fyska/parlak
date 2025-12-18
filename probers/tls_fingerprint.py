"""
Lightweight TLS fingerprinting: SNI, cert, ALPN, and cipher info.
"""

import ssl
import socket
from typing import Optional

from core.config import settings


def tls_probe(host: str, port: int = 443, timeout: float = 5.0) -> Optional[dict]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
            return {
                "sni": host,
                "cert_subject": cert.get("subject"),
                "cert_san": cert.get("subjectAltName"),
                "notAfter": cert.get("notAfter"),
                "alpn": tls.selected_alpn_protocol(),
                "cipher": tls.cipher(),
                "version": tls.version(),
            }
    return None
