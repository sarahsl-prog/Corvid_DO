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

    model_config = {"env_prefix": "CORVID_"}


settings = Settings()
