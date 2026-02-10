"""Shared pytest configuration and fixtures.

Configures pytest-asyncio auto mode and registers custom markers.
"""

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from corvid.api.main import app
from corvid.db.models import Base
from corvid.db.session import get_db


def pytest_configure(config: pytest.Config) -> None:
    """Register custom markers."""
    config.addinivalue_line("markers", "phase1: Phase 1 foundation tests")
    config.addinivalue_line("markers", "phase2: Phase 2 enrichment pipeline tests")
    config.addinivalue_line("markers", "phase3: Phase 3 agent and ingestion tests")
    config.addinivalue_line("markers", "phase4: Phase 4 deployment and production tests")


@pytest_asyncio.fixture
async def async_engine():
    """Create an async in-memory SQLite engine for testing.

    Uses aiosqlite as the backend. PostgreSQL-specific column types (JSONB,
    ARRAY) are not tested at the SQL level here; those are covered by
    integration tests against a real Postgres instance.
    """
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(async_engine):
    """Create a test database session."""
    session_factory = async_sessionmaker(
        async_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with session_factory() as session:
        yield session


@pytest_asyncio.fixture
async def client(db_session):
    """Create a test HTTP client with overridden DB dependency."""

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()
