"""
Web discovery: robots, sitemap, .well-known and a tiny curated path
list. No brute force; designed to be safe.
"""

from typing import Dict, List, Tuple

from probers.http_probe import http_get

COMMON_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/.well-known/change-password",
    "/admin",
    "/login",
    "/server-status",
]


def discover(host: str, port: int, use_ssl: bool) -> List[Tuple[str, Dict]]:
    discovered = []
    for path in COMMON_PATHS:
        try:
            meta, _ = http_get(host, port, use_ssl, path=path)
            discovered.append((path, meta))
        except Exception:
            continue
    return discovered
