"""Database session factory for async SQLAlchemy."""

import os
from collections.abc import AsyncGenerator

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from corvid.config import settings

print(f"DEBUG: CORVID_DATABASE_URL env var = {os.environ.get('CORVID_DATABASE_URL', 'NOT SET')}")
print(f"DEBUG: settings.database_url = {settings.database_url}")

logger.info(
    "Database URL configured: {}",
    settings.database_url[:50] + "..."
    if len(settings.database_url) > 50
    else settings.database_url,
)
engine = create_async_engine(settings.database_url, echo=settings.debug)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async DB session for FastAPI dependency injection."""
    async with async_session() as session:
        yield session
