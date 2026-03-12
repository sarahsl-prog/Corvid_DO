"""Pydantic models for IOC API request/response validation."""

import ipaddress
import re
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator

from corvid.types import IOCType

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


def _validate_ioc_value_by_type(ioc_type: IOCType, value: str) -> bool:
    """Validate that a value matches the expected format for its IOC type."""
    if ioc_type == IOCType.IP:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    pattern = _IOC_PATTERNS.get(ioc_type)
    if pattern:
        return bool(pattern.match(value))

    return False


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

    @model_validator(mode="after")
    def validate_value_matches_type(self) -> "IOCCreate":
        """Validate that the value matches the declared IOC type."""
        if not _validate_ioc_value_by_type(self.type, self.value):
            raise ValueError(
                f"Invalid value '{self.value}' for IOC type '{self.type.value}'. "
                f"Value does not match expected format."
            )
        return self


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


class IOCBulkImportRequest(BaseModel):
    """Request model for bulk IOC import (1–500 IOCs per call)."""

    iocs: list[IOCCreate] = Field(..., min_length=1, max_length=500)


class IOCBulkImportResult(BaseModel):
    """Per-IOC outcome within a bulk import response."""

    index: int
    """Zero-based index of the IOC in the original request list."""

    status: str
    """Outcome: 'created', 'updated', or 'failed'."""

    ioc_id: str | None = None
    """UUID of the created/updated IOC, or None on failure."""

    error: str | None = None
    """Human-readable error message when status is 'failed'."""


class IOCBulkImportResponse(BaseModel):
    """Response model for bulk IOC import with per-IOC results and summary counts."""

    total: int
    """Total number of IOCs submitted."""

    created: int
    """Number of new IOC records created."""

    updated: int
    """Number of existing IOC records updated (dedup)."""

    failed: int
    """Number of IOCs that could not be processed."""

    results: list[IOCBulkImportResult]
    """Per-IOC outcome details in the same order as the request."""
