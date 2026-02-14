"""Tests for Pydantic API models (IOC and Analysis)."""

import pytest
from datetime import datetime, timezone
from uuid import uuid4

from corvid.api.models.ioc import IOCCreate, IOCType, IOCResponse


class TestIOCCreate:
    """Tests for IOCCreate request model validation."""

    def test_valid_ip(self) -> None:
        ioc = IOCCreate(type=IOCType.IP, value="192.168.1.1")
        assert ioc.type == IOCType.IP
        assert ioc.value == "192.168.1.1"

    def test_valid_domain(self) -> None:
        ioc = IOCCreate(type=IOCType.DOMAIN, value="evil.example.com")
        assert ioc.type == IOCType.DOMAIN

    def test_valid_sha256(self) -> None:
        ioc = IOCCreate(type=IOCType.HASH_SHA256, value="a" * 64)
        assert ioc.type == IOCType.HASH_SHA256

    def test_empty_value_rejected(self) -> None:
        with pytest.raises(Exception):
            IOCCreate(type=IOCType.IP, value="")

    def test_whitespace_only_rejected(self) -> None:
        with pytest.raises(Exception):
            IOCCreate(type=IOCType.IP, value="   ")

    def test_strips_whitespace(self) -> None:
        ioc = IOCCreate(type=IOCType.IP, value="  10.0.0.1  ")
        assert ioc.value == "10.0.0.1"

    def test_tags_default_empty(self) -> None:
        ioc = IOCCreate(type=IOCType.IP, value="10.0.0.1")
        assert ioc.tags == []

    def test_tags_provided(self) -> None:
        ioc = IOCCreate(type=IOCType.IP, value="10.0.0.1", tags=["malware", "c2"])
        assert ioc.tags == ["malware", "c2"]

    def test_invalid_type_rejected(self) -> None:
        with pytest.raises(Exception):
            IOCCreate(type="not_a_type", value="10.0.0.1")

    def test_all_ioc_types_accepted(self) -> None:
        # Test valid values for each IOC type
        valid_values = {
            IOCType.IP: "192.168.1.1",
            IOCType.DOMAIN: "example.com",
            IOCType.URL: "https://example.com/malware.exe",
            IOCType.HASH_MD5: "d41d8cd98f00b204e9800998ecf8427e",
            IOCType.HASH_SHA1: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            IOCType.HASH_SHA256: "a" * 64,
            IOCType.EMAIL: "attacker@example.com",
        }
        for ioc_type in IOCType:
            value = valid_values[ioc_type]
            ioc = IOCCreate(type=ioc_type, value=value)
            assert ioc.type == ioc_type
            assert ioc.value == value


class TestIOCResponse:
    """Tests for IOCResponse serialization."""

    def test_from_dict(self) -> None:
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

    def test_severity_score_nullable(self) -> None:
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
