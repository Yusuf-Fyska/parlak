"""
Evidence helper to normalize findings for storage/reporting.
"""

import hashlib
from typing import Dict


def evidence_from_http(meta: Dict, body: bytes) -> Dict:
    snippet = body[:200]
    return {
        "headers": meta.get("headers", {}),
        "status_code": meta.get("status"),
        "snippet_hash": hashlib.sha1(snippet).hexdigest(),
    }
