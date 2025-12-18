"""
TCP connect scanner using safe connect() without crafting raw packets.
Designed to run under policy rate limits.
"""

import socket
from typing import List, Optional, Tuple


def tcp_probe(ip: str, port: int, timeout: float = 2.0) -> Tuple[bool, Optional[str]]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        try:
            banner = sock.recv(200).decode(errors="ignore").strip()
        except socket.timeout:
            banner = None
        return True, banner
    except (socket.timeout, OSError):
        return False, None
    finally:
        sock.close()


def scan_ports(ip: str, ports: List[int], timeout: float = 2.0):
    for port in ports:
        open_, banner = tcp_probe(ip, port, timeout=timeout)
        yield port, open_, banner
