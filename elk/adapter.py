"""
Elasticsearch adapter for bulk writes and simple queries.
Uses official client; keeps retries/backoff minimal and aligned with single-node needs.
"""

from __future__ import annotations

import random
import time
from typing import Dict, Iterable, List

from elasticsearch import Elasticsearch, helpers

from core.config import settings


class ElasticsearchAdapter:
    def __init__(self):
        if not settings.elasticsearch_url:
            raise ValueError("ELASTICSEARCH_URL is required for ElasticsearchAdapter")

        client_args: Dict = {
            "hosts": [settings.elasticsearch_url],
            "verify_certs": settings.elasticsearch_verify_certs,
        }

        if settings.elasticsearch_api_key:
            client_args["api_key"] = settings.elasticsearch_api_key
        elif settings.elasticsearch_user and settings.elasticsearch_pass:
            client_args["basic_auth"] = (settings.elasticsearch_user, settings.elasticsearch_pass)

        if settings.elasticsearch_ca_cert:
            client_args["ca_certs"] = settings.elasticsearch_ca_cert

        self.client = Elasticsearch(**client_args)
        self.batch_size = settings.bulk_batch_size

    def ping(self) -> bool:
        try:
            return bool(self.client.ping())
        except Exception:  # noqa: BLE001
            return False

    def bulk_index(self, index: str, docs: Iterable[Dict]):
        doc_list = list(docs)
        if not doc_list:
            return
        max_attempts = 3
        backoff_base = 1.0

        def _chunks(seq: List[Dict], size: int):
            for i in range(0, len(seq), size):
                yield seq[i : i + size]

        for chunk in _chunks(doc_list, self.batch_size):
            actions = [{"_index": index, "_source": doc} for doc in chunk]
            for attempt in range(1, max_attempts + 1):
                try:
                    helpers.bulk(
                        self.client,
                        actions,
                        stats_only=True,
                        request_timeout=30,
                        raise_on_error=True,
                        max_retries=0,
                    )
                    break
                except Exception:  # noqa: BLE001
                    if attempt >= max_attempts:
                        raise
                    sleep_for = backoff_base * (2 ** (attempt - 1)) + random.random()
                    time.sleep(sleep_for)

    def search_by_asset(self, index: str, asset: str, size: int = 50) -> List[Dict]:
        try:
            res = self.client.search(
                index=index,
                size=size,
                query={"term": {"asset.keyword": asset}},
            )
            hits = res.get("hits", {}).get("hits", [])
            return [h.get("_source", {}) for h in hits]
        except Exception:  # noqa: BLE001
            return []

    def search_assets(self, query: str | None = None, size: int = 50) -> List[Dict]:
        try:
            if query:
                es_query = {"query_string": {"query": f"*{query}*"}}
            else:
                es_query = {"match_all": {}}
            res = self.client.search(
                index="surface-assets",
                size=size,
                query=es_query,
                sort=[{"timestamp": {"order": "desc"}}],
            )
            hits = res.get("hits", {}).get("hits", [])
            return [h.get("_source", {}) for h in hits]
        except Exception:  # noqa: BLE001
            return []
