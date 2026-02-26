"""Database session factory for async SQLAlchemy."""

from collections.abc import AsyncGenerator
from urllib.parse import urlparse, urlunparse

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from corvid.config import settings


def _mask_db_url(url: str) -> str:
    """Mask password in database URL for safe logging.
    
    Args:
        url: The database connection URL.
        
    Returns:
        URL with password replaced by **** if present.
    """
    try:
        parsed = urlparse(url)
        if parsed.password:
            # Reconstruct netloc with masked password
            netloc = f"{parsed.username}:****@{parsed.hostname}"
            if parsed.port:
                netloc += f":{parsed.port}"
            masked = parsed._replace(netloc=netloc)
            return urlunparse(masked)
    except Exception:
        pass  # Fallback to truncating if parsing fails
    return url[:50] + "..." if len(url) > 50 else url


logger.info("Database URL configured: {}", _mask_db_url(settings.database_url))
engine = create_async_engine(settings.database_url, echo=settings.debug)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async DB session for FastAPI dependency injection."""
    async with async_session() as session:
        yield session
