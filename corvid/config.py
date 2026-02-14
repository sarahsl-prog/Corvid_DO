"""Application configuration using pydantic-settings.

Environment variables are prefixed with CORVID_ (e.g. CORVID_DATABASE_URL).
Defaults are set for local development with Docker Compose.
"""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Global application settings loaded from environment variables."""

    # Database
    database_url: str = "postgresql+asyncpg://corvid:corvid@localhost:5432/corvid"

    # Redis (task queue + cache)
    redis_url: str = "redis://localhost:6379/0"

    # API server
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # Debug mode (enables SQL echo, verbose logging)
    debug: bool = True
    log_level: str = "INFO"

    # Gradient AI (for agent)
    gradient_api_key: str = ""
    gradient_kb_id: str = ""
    gradient_kb_url: str = ""  # Full KB URL (e.g., https://kbaas.do-ai.run/v1/{kb_id})
    gradient_model: str = "gradient-large"

    # External API keys
    abuseipdb_api_key: str = ""
    nvd_api_key: str = ""

    # Production tuning
    max_concurrent_enrichments: int = 5
    agent_timeout_seconds: int = 30
    enrichment_cache_ttl_hours: int = 24

    model_config = {"env_prefix": "CORVID_"}


settings = Settings()
