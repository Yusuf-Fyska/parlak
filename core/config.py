"""
Pydantic-based configuration for control and scan planes.

All knobs are exposed via environment variables so the same codebase
can run as control-plane (API/orchestrator) or scan-plane (worker) by
changing env flags.
"""

from functools import lru_cache
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=False, env_file=".env")

    # Mode selection
    role: str = Field("control", description="control or worker")
    safe_mode: bool = Field(True, env="SAFE_MODE")

    # Networking scope
    allowlist_cidrs: List[str] = Field(default_factory=list, env="ALLOWLIST_CIDRS")
    allowlist_domains: List[str] = Field(default_factory=list, env="ALLOWLIST_DOMAINS")

    # Concurrency and budgeting
    global_concurrency: int = Field(32, env="GLOBAL_CONCURRENCY")
    per_target_concurrency: int = Field(4, env="PER_TARGET_CONCURRENCY")
    scan_time_budget_per_target: int = Field(120, env="SCAN_TIME_BUDGET_PER_TARGET")
    campaign_time_budget: int = Field(900, env="CAMPAIGN_TIME_BUDGET")

    # Timeouts
    http_timeout_s: float = Field(5.0, env="HTTP_TIMEOUTS")
    tls_timeout_s: float = Field(5.0, env="TLS_TIMEOUTS")

    # Port profiles
    top_ports_web: List[int] = Field(
        default_factory=lambda: [80, 443, 8080, 8443, 8000, 3000, 5000], env="TOP_PORTS_WEB"
    )
    top_ports_remote: List[int] = Field(
        default_factory=lambda: [22, 3389], env="TOP_PORTS_REMOTE"
    )
    top_ports_db: List[int] = Field(
        default_factory=lambda: [5432, 3306], env="TOP_PORTS_DB"
    )

    # Elasticsearch
    elasticsearch_url: Optional[str] = Field(None, env="ELASTICSEARCH_URL")
    elasticsearch_user: Optional[str] = Field(None, env="ELASTICSEARCH_USER")
    elasticsearch_pass: Optional[str] = Field(None, env="ELASTICSEARCH_PASS")
    elasticsearch_api_key: Optional[str] = Field(None, env="ELASTICSEARCH_API_KEY")
    elasticsearch_verify_certs: bool = Field(True, env="ELASTICSEARCH_VERIFY_CERTS")
    elasticsearch_ca_cert: Optional[str] = Field(None, env="ELASTICSEARCH_CA_CERT")
    bulk_batch_size: int = Field(500, env="BULK_BATCH_SIZE")

    # Local state/cache
    json_cache_path: Optional[str] = Field(None, env="JSON_CACHE_PATH")
    verify_write_test_doc: bool = Field(False, env="VERIFY_WRITE_TEST_DOC")

    # HTTP user agent
    user_agent: str = Field(
        "SurfaceScan/0.1 (+https://example.org; security research; contact=security@example.org)",
        env="USER_AGENT",
    )

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in {"control", "worker"}:
            raise ValueError("role must be control or worker")
        return v


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
