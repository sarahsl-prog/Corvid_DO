"""Application configuration using pydantic-settings.

Environment variables are prefixed with CORVID_ (e.g. CORVID_DATABASE_URL).
All sensitive values MUST be provided via .env file or environment variables.
Defaults are set for local development with Docker Compose.

Example .env file:
    CORVID_DATABASE_URL=postgresql+asyncpg://user:pass@localhost/db
    CORVID_GRADIENT_API_KEY=dop_v1_...
    CORVID_ABUSEIPDB_API_KEY=...
"""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Global application settings loaded from environment variables.

    The settings automatically loads from:
    1. Environment variables with CORVID_ prefix
    2. .env file in the project root
    3. Default values specified below

    Required fields (marked with Field(...)) will cause the application
    to fail at startup if not provided, preventing accidental deployment
    with missing credentials.
    """

    model_config = SettingsConfigDict(
        env_prefix="CORVID_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",  # Ignore extra env vars that don't match our fields
        case_sensitive=False,  # CORVID_database_url = CORVID_DATABASE_URL
    )

    # Database configuration
    database_url: str = "postgresql+asyncpg://corvid:corvid@localhost:5432/corvid"
    """PostgreSQL async connection string. Default works with docker-compose."""

    # Redis (task queue + cache)
    redis_url: str = "redis://localhost:6379/0"
    """Redis connection string for task queue and caching."""

    # API server configuration
    api_host: str = "0.0.0.0"
    """Host to bind the API server to. 0.0.0.0 binds to all interfaces."""

    api_port: int = 8000
    """Port for the API server."""

    # Debug and logging
    debug: bool = False
    """Enable debug mode (SQL echo, verbose logging). MUST be False in production!"""

    log_level: str = "INFO"
    """Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL"""

    # Gradient AI configuration (REQUIRED for agent functionality)
    gradient_api_key: str = Field(
        ...,  # Required field - no default
        description="Gradient AI API key (dop_v1_...). Required for agent operation.",
    )

    gradient_kb_id: str = Field(
        default="", description="Gradient knowledge base ID. Optional, for RAG functionality."
    )

    gradient_model: str = Field(
        default="gradient-large",
        description="Gradient AI model to use for agent inference (e.g. gradient-large)."
    )

    gradient_kb_url: str = Field(
        default="",
        description="Custom Gradient KB API URL. Leave empty to use default."
    )

    # External threat intelligence API keys (OPTIONAL but recommended)
    abuseipdb_api_key: str = Field(
        default="", description="AbuseIPDB API key for IP reputation checks. Free tier available."
    )

    nvd_api_key: str = Field(
        default="", description="NVD API key for CVE database queries. Increases rate limits."
    )

    # CORS configuration
    cors_origins: list[str] = Field(
        default=["http://localhost:5173", "http://localhost:3000"],
        description="Allowed CORS origins for browser clients. "
        "Includes Vite dev server (5173) and common alternatives.",
    )

    # Rate limiting
    rate_limit_per_minute: int = Field(
        default=100,
        ge=1,
        le=10000,
        description="Default API rate limit per minute per IP address.",
    )

    rate_limit_analyze_per_minute: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Rate limit for the analysis endpoint (compute-intensive operation).",
    )

    # Production tuning parameters
    max_concurrent_enrichments: int = Field(
        default=5,
        ge=1,
        le=50,
        description="Maximum concurrent enrichment tasks. Adjust based on API rate limits.",
    )

    agent_timeout_seconds: int = Field(
        default=30, ge=5, le=300, description="Timeout for agent analysis operations in seconds."
    )

    enrichment_cache_ttl_hours: int = Field(
        default=24,
        ge=1,
        le=168,  # Max 1 week
        description="How long to cache enrichment results in hours.",
    )


# Global settings singleton - import this from other modules
settings = Settings()
