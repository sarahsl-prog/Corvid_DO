"""SQLAlchemy ORM models for the Corvid database schema.

Tables:
    - iocs: Indicators of Compromise (IP, domain, hash, URL, email)
    - enrichments: Results from external threat intel providers
    - analyses: AI-generated threat analysis results
    - cve_references: CVE cross-references linked to IOCs and analyses

Uses JSON instead of PostgreSQL-specific JSONB/ARRAY so the schema works
with both PostgreSQL (production) and SQLite (testing). On PostgreSQL,
JSON columns automatically use the native JSONB storage via dialect.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Float, ForeignKey, String, Text, Uuid
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all ORM models."""

    pass


class IOC(Base):
    """An Indicator of Compromise (IP, domain, hash, URL, or email)."""

    __tablename__ = "iocs"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    type: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    tags: Mapped[list] = mapped_column(JSON, default=list)
    severity_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    enrichments: Mapped[list["Enrichment"]] = relationship(
        back_populates="ioc", cascade="all, delete-orphan"
    )


class Enrichment(Base):
    """Enrichment data from an external threat intelligence provider."""

    __tablename__ = "enrichments"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    ioc_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("iocs.id"), nullable=False
    )
    source: Mapped[str] = mapped_column(String(50), nullable=False)
    raw_response: Mapped[dict] = mapped_column(JSON, default=dict)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    ttl_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    ioc: Mapped["IOC"] = relationship(back_populates="enrichments")


class Analysis(Base):
    """AI-generated threat analysis for one or more IOCs."""

    __tablename__ = "analyses"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    ioc_ids: Mapped[list] = mapped_column(JSON, default=list)
    agent_trace_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    analysis_text: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    mitre_techniques: Mapped[list] = mapped_column(JSON, default=list)
    recommended_actions: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    model_version: Mapped[str | None] = mapped_column(String(100), nullable=True)


class CVEReference(Base):
    """A CVE cross-reference linked to an IOC and/or analysis."""

    __tablename__ = "cve_references"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    cve_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    ioc_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("iocs.id"), nullable=True
    )
    analysis_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("analyses.id"), nullable=True
    )
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
