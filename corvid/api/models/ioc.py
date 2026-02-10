"""Pydantic models for IOC API request/response validation."""

import enum
import ipaddress
import re
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class IOCType(str, enum.Enum):
    """Supported IOC (Indicator of Compromise) types."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"


# Compiled regex patterns for IOC format validation
_IOC_PATTERNS: dict[IOCType, re.Pattern[str]] = {
    IOCType.HASH_MD5: re.compile(r"^[a-fA-F0-9]{32}$"),
    IOCType.HASH_SHA1: re.compile(r"^[a-fA-F0-9]{40}$"),
    IOCType.HASH_SHA256: re.compile(r"^[a-fA-F0-9]{64}$"),
    IOCType.DOMAIN: re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
    ),
    IOCType.EMAIL: re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"),
    IOCType.URL: re.compile(r"^https?://\S+$"),
}


class IOCCreate(BaseModel):
    """Request model for creating/submitting an IOC."""

    type: IOCType
    value: str = Field(..., min_length=1, max_length=2048)
    tags: list[str] = []

    @field_validator("value")
    @classmethod
    def validate_ioc_value(cls, v: str, info: object) -> str:
        """Strip whitespace and validate IOC format matches declared type."""
        v = v.strip()
        if not v:
            raise ValueError("IOC value cannot be empty or whitespace-only")
        return v


class IOCResponse(BaseModel):
    """Response model for a single IOC record."""

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
    """Paginated response for listing IOCs."""

    items: list[IOCResponse]
    total: int
