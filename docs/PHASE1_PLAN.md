# Phase 1: Foundation — Implementation Plan

**Goal**: Set up the Python project, define data models, create the database schema, implement basic IOC CRUD endpoints, and establish the local development environment with Docker Compose.

**Estimated effort**: 1 day

---

## Step 1: Project Setup

### 1.1 Create `pyproject.toml`

```toml
[project]
name = "corvid"
version = "0.1.0"
description = "AI-powered cybersecurity threat intelligence platform"
requires-python = ">=3.11"
dependencies = [
    "fastapi>=0.110.0",
    "uvicorn[standard]>=0.29.0",
    "sqlalchemy[asyncio]>=2.0.0",
    "asyncpg>=0.29.0",
    "alembic>=1.13.0",
    "pydantic>=2.6.0",
    "pydantic-settings>=2.2.0",
    "httpx>=0.27.0",
    "redis>=5.0.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0.0",
    "pytest-asyncio>=0.23.0",
    "pytest-cov>=5.0.0",
    "httpx>=0.27.0",
    "factory-boy>=3.3.0",
    "aiosqlite>=0.20.0",
]
```

### 1.2 Create directory structure

```bash
mkdir -p corvid/{api/{routes,models},db/migrations,worker,agent/tools,ingestion,functions}
mkdir -p tests/{api,db,worker}
touch corvid/__init__.py corvid/api/__init__.py corvid/api/routes/__init__.py
touch corvid/api/models/__init__.py corvid/db/__init__.py
touch corvid/worker/__init__.py corvid/agent/__init__.py
touch corvid/agent/tools/__init__.py corvid/ingestion/__init__.py
touch tests/__init__.py tests/api/__init__.py tests/db/__init__.py tests/worker/__init__.py
```

### 1.3 Create `corvid/config.py`

Application configuration using pydantic-settings. Environment variables with sensible defaults for local dev.

```python
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://corvid:corvid@localhost:5432/corvid"
    redis_url: str = "redis://localhost:6379/0"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    debug: bool = True

    model_config = {"env_prefix": "CORVID_"}

settings = Settings()
```

---

## Step 2: Pydantic Models (API layer)

### 2.1 `corvid/api/models/ioc.py`

Define request/response models:

```python
import enum
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, Field, field_validator

class IOCType(str, enum.Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"

class IOCCreate(BaseModel):
    type: IOCType
    value: str = Field(..., min_length=1, max_length=2048)
    tags: list[str] = []

    @field_validator("value")
    @classmethod
    def validate_ioc_value(cls, v, info):
        # Validate format matches declared type (regex per type)
        return v.strip()

class IOCResponse(BaseModel):
    id: UUID
    type: IOCType
    value: str
    first_seen: datetime
    last_seen: datetime
    tags: list[str]
    severity_score: float | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}

class IOCListResponse(BaseModel):
    items: list[IOCResponse]
    total: int
```

### 2.2 `corvid/api/models/analysis.py`

```python
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel

class AnalysisResponse(BaseModel):
    id: UUID
    ioc_ids: list[UUID]
    analysis_text: str
    confidence: float
    mitre_techniques: list[str]
    recommended_actions: list[str]
    created_at: datetime

    model_config = {"from_attributes": True}
```

### Tests for Pydantic models:

**`tests/api/test_models.py`**

```python
import pytest
from corvid.api.models.ioc import IOCCreate, IOCType, IOCResponse
from uuid import uuid4
from datetime import datetime, timezone


class TestIOCCreate:
    def test_valid_ip(self):
        ioc = IOCCreate(type=IOCType.IP, value="192.168.1.1")
        assert ioc.type == IOCType.IP
        assert ioc.value == "192.168.1.1"

    def test_valid_domain(self):
        ioc = IOCCreate(type=IOCType.DOMAIN, value="evil.example.com")
        assert ioc.type == IOCType.DOMAIN

    def test_valid_sha256(self):
        ioc = IOCCreate(type=IOCType.HASH_SHA256, value="a" * 64)
        assert ioc.type == IOCType.HASH_SHA256

    def test_empty_value_rejected(self):
        with pytest.raises(Exception):
            IOCCreate(type=IOCType.IP, value="")

    def test_strips_whitespace(self):
        ioc = IOCCreate(type=IOCType.IP, value="  10.0.0.1  ")
        assert ioc.value == "10.0.0.1"

    def test_tags_default_empty(self):
        ioc = IOCCreate(type=IOCType.IP, value="10.0.0.1")
        assert ioc.tags == []

    def test_tags_provided(self):
        ioc = IOCCreate(type=IOCType.IP, value="10.0.0.1", tags=["malware", "c2"])
        assert ioc.tags == ["malware", "c2"]

    def test_invalid_type_rejected(self):
        with pytest.raises(Exception):
            IOCCreate(type="not_a_type", value="10.0.0.1")

    def test_all_ioc_types_accepted(self):
        for ioc_type in IOCType:
            ioc = IOCCreate(type=ioc_type, value="test_value")
            assert ioc.type == ioc_type


class TestIOCResponse:
    def test_from_dict(self):
        now = datetime.now(timezone.utc)
        data = {
            "id": uuid4(),
            "type": "ip",
            "value": "10.0.0.1",
            "first_seen": now,
            "last_seen": now,
            "tags": ["test"],
            "severity_score": 5.5,
            "created_at": now,
            "updated_at": now,
        }
        resp = IOCResponse(**data)
        assert resp.severity_score == 5.5

    def test_severity_score_nullable(self):
        now = datetime.now(timezone.utc)
        data = {
            "id": uuid4(),
            "type": "ip",
            "value": "10.0.0.1",
            "first_seen": now,
            "last_seen": now,
            "tags": [],
            "severity_score": None,
            "created_at": now,
            "updated_at": now,
        }
        resp = IOCResponse(**data)
        assert resp.severity_score is None
```

---

## Step 3: SQLAlchemy Models (Database layer)

### 3.1 `corvid/db/models.py`

```python
import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Float, DateTime, Text, Enum as SAEnum, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

class Base(DeclarativeBase):
    pass

class IOC(Base):
    __tablename__ = "iocs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    type: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    tags: Mapped[dict] = mapped_column(JSONB, default=list)
    severity_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    enrichments: Mapped[list["Enrichment"]] = relationship(back_populates="ioc", cascade="all, delete-orphan")

class Enrichment(Base):
    __tablename__ = "enrichments"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ioc_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("iocs.id"), nullable=False)
    source: Mapped[str] = mapped_column(String(50), nullable=False)
    raw_response: Mapped[dict] = mapped_column(JSONB, default=dict)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    ttl_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    ioc: Mapped["IOC"] = relationship(back_populates="enrichments")

class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ioc_ids: Mapped[list] = mapped_column(ARRAY(UUID(as_uuid=True)), default=list)
    agent_trace_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    analysis_text: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    mitre_techniques: Mapped[list] = mapped_column(ARRAY(String), default=list)
    recommended_actions: Mapped[dict] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    model_version: Mapped[str | None] = mapped_column(String(100), nullable=True)

class CVEReference(Base):
    __tablename__ = "cve_references"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cve_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    ioc_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("iocs.id"), nullable=True)
    analysis_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("analyses.id"), nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
```

### 3.2 `corvid/db/session.py`

```python
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from corvid.config import settings

engine = create_async_engine(settings.database_url, echo=settings.debug)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

async def get_db() -> AsyncSession:
    async with async_session() as session:
        yield session
```

### Tests for DB models:

**`tests/db/test_models.py`**

```python
import pytest
import uuid
from datetime import datetime, timezone
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from corvid.db.models import Base, IOC, Enrichment, Analysis, CVEReference


@pytest.fixture
def db_engine():
    """Create an in-memory SQLite engine for testing.
    Note: Some PostgreSQL-specific features (ARRAY, JSONB) won't work
    in SQLite. For those, use the integration test suite with a real
    Postgres instance. This tests basic model structure and relationships.
    """
    # For unit tests, we verify model instantiation without a database.
    # Integration tests with Postgres are in Phase 2.
    pass


class TestIOCModel:
    def test_create_ioc_instance(self):
        ioc = IOC(
            id=uuid.uuid4(),
            type="ip",
            value="192.168.1.1",
            tags=["test"],
            severity_score=5.0,
        )
        assert ioc.type == "ip"
        assert ioc.value == "192.168.1.1"
        assert ioc.severity_score == 5.0
        assert ioc.tags == ["test"]

    def test_ioc_defaults(self):
        ioc = IOC(type="domain", value="evil.example.com")
        assert ioc.id is None  # Set by DB default
        assert ioc.severity_score is None

    def test_ioc_all_types(self):
        types = ["ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256", "email"]
        for ioc_type in types:
            ioc = IOC(type=ioc_type, value="test")
            assert ioc.type == ioc_type


class TestEnrichmentModel:
    def test_create_enrichment_instance(self):
        ioc_id = uuid.uuid4()
        enrichment = Enrichment(
            id=uuid.uuid4(),
            ioc_id=ioc_id,
            source="virustotal",
            raw_response={"positives": 15, "total": 70},
            summary="15/70 engines flagged this file.",
        )
        assert enrichment.source == "virustotal"
        assert enrichment.raw_response["positives"] == 15

    def test_enrichment_defaults(self):
        enrichment = Enrichment(
            ioc_id=uuid.uuid4(),
            source="abuseipdb",
            raw_response={},
        )
        assert enrichment.summary is None
        assert enrichment.ttl_expires_at is None


class TestAnalysisModel:
    def test_create_analysis_instance(self):
        analysis = Analysis(
            id=uuid.uuid4(),
            ioc_ids=[uuid.uuid4()],
            analysis_text="This IP is associated with known C2 infrastructure.",
            confidence=0.85,
            mitre_techniques=["T1071.001"],
            recommended_actions=["Block at firewall"],
            model_version="gradient-v1",
        )
        assert analysis.confidence == 0.85
        assert "T1071.001" in analysis.mitre_techniques

    def test_analysis_defaults(self):
        analysis = Analysis(
            analysis_text="Test",
            confidence=0.5,
        )
        assert analysis.agent_trace_id is None
        assert analysis.model_version is None


class TestCVEReferenceModel:
    def test_create_cve_reference(self):
        ref = CVEReference(
            id=uuid.uuid4(),
            cve_id="CVE-2024-21762",
            cvss_score=9.8,
            description="FortiOS out-of-bound write vulnerability",
        )
        assert ref.cve_id == "CVE-2024-21762"
        assert ref.cvss_score == 9.8

    def test_cve_nullable_foreign_keys(self):
        ref = CVEReference(
            cve_id="CVE-2024-0001",
            ioc_id=None,
            analysis_id=None,
        )
        assert ref.ioc_id is None
        assert ref.analysis_id is None
```

---

## Step 4: FastAPI Application & CRUD Endpoints

### 4.1 `corvid/api/main.py`

```python
from fastapi import FastAPI

app = FastAPI(title="Corvid", version="0.1.0", description="Threat Intelligence Platform")

from corvid.api.routes import iocs, analyses
app.include_router(iocs.router, prefix="/api/v1")
app.include_router(analyses.router, prefix="/api/v1")

@app.get("/health")
async def health():
    return {"status": "ok"}
```

### 4.2 `corvid/api/routes/iocs.py`

```python
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from corvid.db.session import get_db
from corvid.db.models import IOC
from corvid.api.models.ioc import IOCCreate, IOCResponse, IOCListResponse

router = APIRouter(prefix="/iocs", tags=["IOCs"])

@router.post("/", response_model=IOCResponse, status_code=201)
async def create_ioc(ioc_in: IOCCreate, db: AsyncSession = Depends(get_db)):
    # Check for existing IOC with same type+value
    stmt = select(IOC).where(IOC.type == ioc_in.type.value, IOC.value == ioc_in.value)
    result = await db.execute(stmt)
    existing = result.scalar_one_or_none()
    if existing:
        # Update last_seen and merge tags
        existing.last_seen = func.now()
        existing.tags = list(set(existing.tags or []) | set(ioc_in.tags))
        await db.commit()
        await db.refresh(existing)
        return existing

    ioc = IOC(type=ioc_in.type.value, value=ioc_in.value, tags=ioc_in.tags)
    db.add(ioc)
    await db.commit()
    await db.refresh(ioc)
    return ioc

@router.get("/", response_model=IOCListResponse)
async def list_iocs(
    type: str | None = None,
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(IOC)
    count_stmt = select(func.count(IOC.id))
    if type:
        stmt = stmt.where(IOC.type == type)
        count_stmt = count_stmt.where(IOC.type == type)
    stmt = stmt.offset(offset).limit(limit).order_by(IOC.created_at.desc())

    result = await db.execute(stmt)
    count_result = await db.execute(count_stmt)
    return IOCListResponse(items=result.scalars().all(), total=count_result.scalar())

@router.get("/{ioc_id}", response_model=IOCResponse)
async def get_ioc(ioc_id: UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(IOC).where(IOC.id == ioc_id))
    ioc = result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    return ioc

@router.delete("/{ioc_id}", status_code=204)
async def delete_ioc(ioc_id: UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(IOC).where(IOC.id == ioc_id))
    ioc = result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    await db.delete(ioc)
    await db.commit()
```

### Tests for API endpoints:

**`tests/api/test_iocs.py`**

```python
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from corvid.db.models import Base
from corvid.api.main import app
from corvid.db.session import get_db


@pytest_asyncio.fixture
async def async_engine():
    """Create an async SQLite engine for testing."""
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
    session_factory = async_sessionmaker(async_engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session


@pytest_asyncio.fixture
async def client(db_session):
    """Create a test client with overridden DB dependency."""
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


class TestHealthEndpoint:
    @pytest.mark.asyncio
    async def test_health(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


class TestCreateIOC:
    @pytest.mark.asyncio
    async def test_create_ip_ioc(self, client):
        resp = await client.post("/api/v1/iocs/", json={
            "type": "ip",
            "value": "192.168.1.1",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["type"] == "ip"
        assert data["value"] == "192.168.1.1"
        assert "id" in data

    @pytest.mark.asyncio
    async def test_create_domain_ioc(self, client):
        resp = await client.post("/api/v1/iocs/", json={
            "type": "domain",
            "value": "evil.example.com",
        })
        assert resp.status_code == 201
        assert resp.json()["type"] == "domain"

    @pytest.mark.asyncio
    async def test_create_hash_ioc(self, client):
        resp = await client.post("/api/v1/iocs/", json={
            "type": "hash_sha256",
            "value": "a" * 64,
            "tags": ["malware"],
        })
        assert resp.status_code == 201
        assert "malware" in resp.json()["tags"]

    @pytest.mark.asyncio
    async def test_create_duplicate_updates_last_seen(self, client):
        payload = {"type": "ip", "value": "10.0.0.1"}
        resp1 = await client.post("/api/v1/iocs/", json=payload)
        resp2 = await client.post("/api/v1/iocs/", json=payload)
        assert resp1.json()["id"] == resp2.json()["id"]

    @pytest.mark.asyncio
    async def test_create_duplicate_merges_tags(self, client):
        await client.post("/api/v1/iocs/", json={
            "type": "ip", "value": "10.0.0.2", "tags": ["c2"],
        })
        resp = await client.post("/api/v1/iocs/", json={
            "type": "ip", "value": "10.0.0.2", "tags": ["botnet"],
        })
        tags = resp.json()["tags"]
        assert "c2" in tags
        assert "botnet" in tags

    @pytest.mark.asyncio
    async def test_create_invalid_type(self, client):
        resp = await client.post("/api/v1/iocs/", json={
            "type": "invalid",
            "value": "test",
        })
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_create_empty_value(self, client):
        resp = await client.post("/api/v1/iocs/", json={
            "type": "ip",
            "value": "",
        })
        assert resp.status_code == 422


class TestListIOCs:
    @pytest.mark.asyncio
    async def test_list_empty(self, client):
        resp = await client.get("/api/v1/iocs/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["total"] == 0

    @pytest.mark.asyncio
    async def test_list_after_create(self, client):
        await client.post("/api/v1/iocs/", json={"type": "ip", "value": "1.2.3.4"})
        await client.post("/api/v1/iocs/", json={"type": "domain", "value": "evil.com"})
        resp = await client.get("/api/v1/iocs/")
        data = resp.json()
        assert data["total"] == 2
        assert len(data["items"]) == 2

    @pytest.mark.asyncio
    async def test_list_filter_by_type(self, client):
        await client.post("/api/v1/iocs/", json={"type": "ip", "value": "1.2.3.4"})
        await client.post("/api/v1/iocs/", json={"type": "domain", "value": "evil.com"})
        resp = await client.get("/api/v1/iocs/?type=ip")
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["type"] == "ip"

    @pytest.mark.asyncio
    async def test_list_pagination(self, client):
        for i in range(5):
            await client.post("/api/v1/iocs/", json={"type": "ip", "value": f"10.0.0.{i}"})
        resp = await client.get("/api/v1/iocs/?limit=2&offset=0")
        assert len(resp.json()["items"]) == 2
        assert resp.json()["total"] == 5


class TestGetIOC:
    @pytest.mark.asyncio
    async def test_get_existing(self, client):
        create_resp = await client.post("/api/v1/iocs/", json={"type": "ip", "value": "1.2.3.4"})
        ioc_id = create_resp.json()["id"]
        resp = await client.get(f"/api/v1/iocs/{ioc_id}")
        assert resp.status_code == 200
        assert resp.json()["value"] == "1.2.3.4"

    @pytest.mark.asyncio
    async def test_get_nonexistent(self, client):
        resp = await client.get("/api/v1/iocs/00000000-0000-0000-0000-000000000000")
        assert resp.status_code == 404


class TestDeleteIOC:
    @pytest.mark.asyncio
    async def test_delete_existing(self, client):
        create_resp = await client.post("/api/v1/iocs/", json={"type": "ip", "value": "1.2.3.4"})
        ioc_id = create_resp.json()["id"]
        del_resp = await client.delete(f"/api/v1/iocs/{ioc_id}")
        assert del_resp.status_code == 204
        get_resp = await client.get(f"/api/v1/iocs/{ioc_id}")
        assert get_resp.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_nonexistent(self, client):
        resp = await client.delete("/api/v1/iocs/00000000-0000-0000-0000-000000000000")
        assert resp.status_code == 404
```

---

## Step 5: Docker Compose for Local Dev

### 5.1 `docker-compose.yml`

```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: corvid
      POSTGRES_PASSWORD: corvid
      POSTGRES_DB: corvid
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  api:
    build: .
    command: uvicorn corvid.api.main:app --host 0.0.0.0 --port 8000 --reload
    ports:
      - "8000:8000"
    environment:
      CORVID_DATABASE_URL: postgresql+asyncpg://corvid:corvid@postgres:5432/corvid
      CORVID_REDIS_URL: redis://redis:6379/0
    depends_on:
      - postgres
      - redis
    volumes:
      - .:/app

volumes:
  pgdata:
```

### 5.2 `Dockerfile`

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir .
COPY . .
EXPOSE 8000
CMD ["uvicorn", "corvid.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

## Step 6: Alembic Setup

```bash
alembic init corvid/db/migrations
```

Edit `corvid/db/migrations/env.py` to import `corvid.db.models.Base.metadata` as `target_metadata`.

Generate initial migration:

```bash
alembic revision --autogenerate -m "initial schema"
alembic upgrade head
```

---

## Test Configuration

### `tests/conftest.py`

```python
import pytest

# Configure pytest-asyncio mode
pytest_plugins = []

def pytest_configure(config):
    config.addinivalue_line("markers", "asyncio: mark test as async")
```

### `pytest.ini` (or in `pyproject.toml`)

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
```

### Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# Run with coverage
pytest --cov=corvid --cov-report=term-missing

# Run specific test file
pytest tests/api/test_iocs.py -v
```

---

## Phase 1 Completion Checklist

- [ ] `pyproject.toml` created with all dependencies
- [ ] Directory structure created
- [ ] `corvid/config.py` with pydantic-settings
- [ ] Pydantic models for IOC and Analysis
- [ ] SQLAlchemy models for all 4 tables
- [ ] DB session factory
- [ ] FastAPI app with health endpoint
- [ ] IOC CRUD routes (create, list, get, delete)
- [ ] Docker Compose with Postgres + Redis + API
- [ ] Dockerfile
- [ ] Alembic initialized with initial migration
- [ ] `tests/api/test_models.py` — Pydantic model validation (9 tests)
- [ ] `tests/db/test_models.py` — SQLAlchemy model instantiation (10 tests)
- [ ] `tests/api/test_iocs.py` — API endpoint integration tests (13 tests)
- [ ] All tests passing with `pytest`
