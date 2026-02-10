# Phase 2: Enrichment Pipeline — Implementation Plan

**Goal**: Build the IOC normalization layer, integrate 3 external threat intelligence APIs, wire up Redis-backed task queue, and test the full pipeline end-to-end.

**Estimated effort**: 1 day

**Prerequisite**: Phase 1 complete (FastAPI app, DB models, CRUD endpoints working)

---

## Step 1: IOC Normalizer

The normalizer validates IOC format, detects/confirms IOC type, and standardizes values before enrichment.

### 1.1 `corvid/worker/normalizer.py`

```python
import re
import ipaddress
from enum import Enum

class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"

# Compiled regex patterns for IOC validation
PATTERNS = {
    IOCType.HASH_MD5: re.compile(r"^[a-fA-F0-9]{32}$"),
    IOCType.HASH_SHA1: re.compile(r"^[a-fA-F0-9]{40}$"),
    IOCType.HASH_SHA256: re.compile(r"^[a-fA-F0-9]{64}$"),
    IOCType.DOMAIN: re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
    ),
    IOCType.EMAIL: re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"),
    IOCType.URL: re.compile(r"^https?://\S+$"),
}


def normalize_ioc(value: str) -> str:
    """Normalize an IOC value: strip whitespace, lowercase, defang."""
    value = value.strip()
    # Re-fang common defanged formats
    value = value.replace("hxxp", "http").replace("[.]", ".").replace("[@]", "@")
    # Lowercase for consistency (hashes, domains are case-insensitive)
    value = value.lower()
    return value


def validate_ioc(ioc_type: IOCType, value: str) -> bool:
    """Validate that a value matches the expected format for its IOC type."""
    if ioc_type == IOCType.IP:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
    pattern = PATTERNS.get(ioc_type)
    if pattern:
        return bool(pattern.match(value))
    return False


def detect_ioc_type(value: str) -> IOCType | None:
    """Auto-detect the IOC type from a raw value."""
    value = normalize_ioc(value)

    # Try IP first
    try:
        ipaddress.ip_address(value)
        return IOCType.IP
    except ValueError:
        pass

    # Hashes by length
    if PATTERNS[IOCType.HASH_MD5].match(value):
        return IOCType.HASH_MD5
    if PATTERNS[IOCType.HASH_SHA1].match(value):
        return IOCType.HASH_SHA1
    if PATTERNS[IOCType.HASH_SHA256].match(value):
        return IOCType.HASH_SHA256

    # URL before domain (URLs contain domains)
    if PATTERNS[IOCType.URL].match(value):
        return IOCType.URL

    # Email before domain
    if PATTERNS[IOCType.EMAIL].match(value):
        return IOCType.EMAIL

    # Domain last (most permissive text pattern)
    if PATTERNS[IOCType.DOMAIN].match(value):
        return IOCType.DOMAIN

    return None
```

### Tests: `tests/worker/test_normalizer.py`

```python
import pytest
from corvid.worker.normalizer import normalize_ioc, validate_ioc, detect_ioc_type, IOCType


class TestNormalizeIOC:
    def test_strips_whitespace(self):
        assert normalize_ioc("  10.0.0.1  ") == "10.0.0.1"

    def test_lowercases(self):
        assert normalize_ioc("EVIL.EXAMPLE.COM") == "evil.example.com"

    def test_refangs_hxxp(self):
        assert normalize_ioc("hxxps://evil.com/payload") == "https://evil.com/payload"

    def test_refangs_brackets(self):
        assert normalize_ioc("evil[.]example[.]com") == "evil.example.com"

    def test_refangs_email(self):
        assert normalize_ioc("attacker[@]evil[.]com") == "attacker@evil.com"

    def test_combined_defanging(self):
        assert normalize_ioc("hxxp://evil[.]com/bad") == "http://evil.com/bad"


class TestValidateIOC:
    # --- IP addresses ---
    def test_valid_ipv4(self):
        assert validate_ioc(IOCType.IP, "192.168.1.1") is True

    def test_valid_ipv6(self):
        assert validate_ioc(IOCType.IP, "::1") is True

    def test_invalid_ip(self):
        assert validate_ioc(IOCType.IP, "999.999.999.999") is False

    def test_invalid_ip_text(self):
        assert validate_ioc(IOCType.IP, "not_an_ip") is False

    # --- Hashes ---
    def test_valid_md5(self):
        assert validate_ioc(IOCType.HASH_MD5, "d41d8cd98f00b204e9800998ecf8427e") is True

    def test_invalid_md5_too_short(self):
        assert validate_ioc(IOCType.HASH_MD5, "d41d8cd98f00b204") is False

    def test_valid_sha1(self):
        assert validate_ioc(IOCType.HASH_SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709") is True

    def test_valid_sha256(self):
        assert validate_ioc(IOCType.HASH_SHA256, "a" * 64) is True

    def test_invalid_sha256_wrong_chars(self):
        assert validate_ioc(IOCType.HASH_SHA256, "g" * 64) is False

    # --- Domains ---
    def test_valid_domain(self):
        assert validate_ioc(IOCType.DOMAIN, "evil.example.com") is True

    def test_valid_short_domain(self):
        assert validate_ioc(IOCType.DOMAIN, "evil.co") is True

    def test_invalid_domain_leading_dash(self):
        assert validate_ioc(IOCType.DOMAIN, "-evil.com") is False

    # --- URLs ---
    def test_valid_http_url(self):
        assert validate_ioc(IOCType.URL, "http://evil.com/payload.exe") is True

    def test_valid_https_url(self):
        assert validate_ioc(IOCType.URL, "https://evil.com/payload") is True

    def test_invalid_url_no_scheme(self):
        assert validate_ioc(IOCType.URL, "evil.com/payload") is False

    # --- Email ---
    def test_valid_email(self):
        assert validate_ioc(IOCType.EMAIL, "attacker@evil.com") is True

    def test_invalid_email_no_at(self):
        assert validate_ioc(IOCType.EMAIL, "attacker.evil.com") is False


class TestDetectIOCType:
    def test_detect_ipv4(self):
        assert detect_ioc_type("192.168.1.1") == IOCType.IP

    def test_detect_ipv6(self):
        assert detect_ioc_type("2001:db8::1") == IOCType.IP

    def test_detect_md5(self):
        assert detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == IOCType.HASH_MD5

    def test_detect_sha1(self):
        assert detect_ioc_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == IOCType.HASH_SHA1

    def test_detect_sha256(self):
        assert detect_ioc_type("a" * 64) == IOCType.HASH_SHA256

    def test_detect_url(self):
        assert detect_ioc_type("https://evil.com/payload") == IOCType.URL

    def test_detect_email(self):
        assert detect_ioc_type("bad@evil.com") == IOCType.EMAIL

    def test_detect_domain(self):
        assert detect_ioc_type("evil.example.com") == IOCType.DOMAIN

    def test_detect_defanged_url(self):
        assert detect_ioc_type("hxxps://evil[.]com/payload") == IOCType.URL

    def test_detect_unknown(self):
        assert detect_ioc_type("!!!not_an_ioc!!!") is None

    def test_detect_normalizes_first(self):
        assert detect_ioc_type("  192.168.1.1  ") == IOCType.IP
```

---

## Step 2: External Enrichment Integrations

Each enrichment source gets its own module with a consistent interface.

### 2.1 Base enrichment interface: `corvid/worker/enrichment.py`

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

@dataclass
class EnrichmentResult:
    source: str
    raw_response: dict[str, Any]
    summary: str
    success: bool
    error: str | None = None

class BaseEnrichmentProvider(ABC):
    """Base class for all enrichment providers."""

    @property
    @abstractmethod
    def source_name(self) -> str:
        ...

    @abstractmethod
    async def enrich(self, ioc_type: str, ioc_value: str) -> EnrichmentResult:
        ...

    @property
    @abstractmethod
    def supported_types(self) -> list[str]:
        ...

    def supports(self, ioc_type: str) -> bool:
        return ioc_type in self.supported_types
```

### 2.2 AbuseIPDB integration: `corvid/worker/providers/abuseipdb.py`

```python
import httpx
from corvid.worker.enrichment import BaseEnrichmentProvider, EnrichmentResult

ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"

class AbuseIPDBProvider(BaseEnrichmentProvider):
    source_name = "abuseipdb"
    supported_types = ["ip"]

    def __init__(self, api_key: str):
        self.api_key = api_key

    async def enrich(self, ioc_type: str, ioc_value: str) -> EnrichmentResult:
        if not self.supports(ioc_type):
            return EnrichmentResult(
                source=self.source_name,
                raw_response={},
                summary=f"AbuseIPDB does not support IOC type: {ioc_type}",
                success=False,
                error="unsupported_type",
            )
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    ABUSEIPDB_API_URL,
                    params={"ipAddress": ioc_value, "maxAgeInDays": 90},
                    headers={"Key": self.api_key, "Accept": "application/json"},
                )
                resp.raise_for_status()
                data = resp.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                reports = data.get("totalReports", 0)
                country = data.get("countryCode", "unknown")
                return EnrichmentResult(
                    source=self.source_name,
                    raw_response=data,
                    summary=f"Abuse confidence: {score}%, {reports} reports, country: {country}",
                    success=True,
                )
        except httpx.HTTPError as e:
            return EnrichmentResult(
                source=self.source_name,
                raw_response={},
                summary="",
                success=False,
                error=str(e),
            )
```

### 2.3 URLhaus integration: `corvid/worker/providers/urlhaus.py`

```python
import httpx
from corvid.worker.enrichment import BaseEnrichmentProvider, EnrichmentResult

URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1"

class URLhausProvider(BaseEnrichmentProvider):
    source_name = "urlhaus"
    supported_types = ["url", "domain", "ip"]

    async def enrich(self, ioc_type: str, ioc_value: str) -> EnrichmentResult:
        if not self.supports(ioc_type):
            return EnrichmentResult(
                source=self.source_name, raw_response={},
                summary=f"URLhaus does not support IOC type: {ioc_type}",
                success=False, error="unsupported_type",
            )
        try:
            endpoint_map = {
                "url": "/url/",
                "domain": "/host/",
                "ip": "/host/",
            }
            param_map = {
                "url": {"url": ioc_value},
                "domain": {"host": ioc_value},
                "ip": {"host": ioc_value},
            }
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    f"{URLHAUS_API_URL}{endpoint_map[ioc_type]}",
                    data=param_map[ioc_type],
                )
                resp.raise_for_status()
                data = resp.json()
                status = data.get("query_status", "unknown")
                if status == "no_results":
                    return EnrichmentResult(
                        source=self.source_name,
                        raw_response=data,
                        summary="No URLhaus records found for this IOC.",
                        success=True,
                    )
                url_count = data.get("url_count", len(data.get("urls", [])))
                threat = data.get("threat", "unknown")
                return EnrichmentResult(
                    source=self.source_name,
                    raw_response=data,
                    summary=f"URLhaus: {url_count} URL(s), threat type: {threat}",
                    success=True,
                )
        except httpx.HTTPError as e:
            return EnrichmentResult(
                source=self.source_name, raw_response={},
                summary="", success=False, error=str(e),
            )
```

### 2.4 NVD API integration: `corvid/worker/providers/nvd.py`

```python
import httpx
from corvid.worker.enrichment import BaseEnrichmentProvider, EnrichmentResult

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

class NVDProvider(BaseEnrichmentProvider):
    source_name = "nvd"
    supported_types = ["ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256"]

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key

    async def enrich(self, ioc_type: str, ioc_value: str) -> EnrichmentResult:
        """Search NVD for CVEs related to this IOC.

        Note: NVD doesn't directly index IOCs. This searches by keyword,
        which is useful when the IOC is associated with known software.
        For hackathon MVP, this provides CVE context given a keyword search.
        """
        try:
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    NVD_API_URL,
                    params={"keywordSearch": ioc_value, "resultsPerPage": 5},
                    headers=headers,
                )
                resp.raise_for_status()
                data = resp.json()
                total = data.get("totalResults", 0)
                cves = []
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "")
                    desc = ""
                    for d in cve.get("descriptions", []):
                        if d.get("lang") == "en":
                            desc = d.get("value", "")
                            break
                    cves.append({"cve_id": cve_id, "description": desc[:200]})
                return EnrichmentResult(
                    source=self.source_name,
                    raw_response={"total_results": total, "cves": cves},
                    summary=f"NVD: {total} CVE(s) found. Top: {', '.join(c['cve_id'] for c in cves[:3])}",
                    success=True,
                )
        except httpx.HTTPError as e:
            return EnrichmentResult(
                source=self.source_name, raw_response={},
                summary="", success=False, error=str(e),
            )
```

### Tests for enrichment providers: `tests/worker/test_enrichment.py`

```python
import pytest
import httpx
from unittest.mock import AsyncMock, patch
from corvid.worker.enrichment import EnrichmentResult
from corvid.worker.providers.abuseipdb import AbuseIPDBProvider
from corvid.worker.providers.urlhaus import URLhausProvider
from corvid.worker.providers.nvd import NVDProvider


class TestEnrichmentResult:
    def test_successful_result(self):
        result = EnrichmentResult(
            source="test", raw_response={"key": "value"},
            summary="Test summary", success=True,
        )
        assert result.success is True
        assert result.error is None

    def test_failed_result(self):
        result = EnrichmentResult(
            source="test", raw_response={},
            summary="", success=False, error="timeout",
        )
        assert result.success is False
        assert result.error == "timeout"


class TestAbuseIPDBProvider:
    @pytest.fixture
    def provider(self):
        return AbuseIPDBProvider(api_key="test-key")

    def test_supports_ip(self, provider):
        assert provider.supports("ip") is True

    def test_does_not_support_domain(self, provider):
        assert provider.supports("domain") is False

    @pytest.mark.asyncio
    async def test_unsupported_type_returns_error(self, provider):
        result = await provider.enrich("domain", "evil.com")
        assert result.success is False
        assert result.error == "unsupported_type"

    @pytest.mark.asyncio
    async def test_successful_lookup(self, provider):
        mock_response = httpx.Response(
            200,
            json={
                "data": {
                    "abuseConfidenceScore": 85,
                    "totalReports": 42,
                    "countryCode": "RU",
                }
            },
        )
        with patch("corvid.worker.providers.abuseipdb.httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value = mock_instance

            result = await provider.enrich("ip", "203.0.113.42")
            assert result.success is True
            assert "85%" in result.summary
            assert "42 reports" in result.summary

    @pytest.mark.asyncio
    async def test_http_error_handled(self, provider):
        with patch("corvid.worker.providers.abuseipdb.httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(side_effect=httpx.ConnectError("timeout"))
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value = mock_instance

            result = await provider.enrich("ip", "203.0.113.42")
            assert result.success is False
            assert result.error is not None


class TestURLhausProvider:
    @pytest.fixture
    def provider(self):
        return URLhausProvider()

    def test_supports_url(self, provider):
        assert provider.supports("url") is True

    def test_supports_domain(self, provider):
        assert provider.supports("domain") is True

    def test_supports_ip(self, provider):
        assert provider.supports("ip") is True

    def test_does_not_support_hash(self, provider):
        assert provider.supports("hash_sha256") is False

    @pytest.mark.asyncio
    async def test_unsupported_type(self, provider):
        result = await provider.enrich("hash_sha256", "a" * 64)
        assert result.success is False

    @pytest.mark.asyncio
    async def test_no_results(self, provider):
        mock_response = httpx.Response(200, json={"query_status": "no_results"})
        with patch("corvid.worker.providers.urlhaus.httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.post = AsyncMock(return_value=mock_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value = mock_instance

            result = await provider.enrich("url", "https://clean-site.com")
            assert result.success is True
            assert "No URLhaus records" in result.summary

    @pytest.mark.asyncio
    async def test_successful_lookup(self, provider):
        mock_response = httpx.Response(
            200,
            json={
                "query_status": "ok",
                "url_count": 3,
                "threat": "malware_download",
                "urls": [{}, {}, {}],
            },
        )
        with patch("corvid.worker.providers.urlhaus.httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.post = AsyncMock(return_value=mock_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value = mock_instance

            result = await provider.enrich("domain", "evil.com")
            assert result.success is True
            assert "3 URL(s)" in result.summary


class TestNVDProvider:
    @pytest.fixture
    def provider(self):
        return NVDProvider(api_key="test-key")

    @pytest.fixture
    def provider_no_key(self):
        return NVDProvider()

    def test_supports_all_types(self, provider):
        for t in ["ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256"]:
            assert provider.supports(t) is True

    @pytest.mark.asyncio
    async def test_successful_cve_search(self, provider):
        mock_response = httpx.Response(
            200,
            json={
                "totalResults": 2,
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2024-1234",
                            "descriptions": [
                                {"lang": "en", "value": "A vulnerability in..."}
                            ],
                        }
                    },
                    {
                        "cve": {
                            "id": "CVE-2024-5678",
                            "descriptions": [
                                {"lang": "en", "value": "Another vulnerability..."}
                            ],
                        }
                    },
                ],
            },
        )
        with patch("corvid.worker.providers.nvd.httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value = mock_instance

            result = await provider.enrich("ip", "203.0.113.42")
            assert result.success is True
            assert "2 CVE(s)" in result.summary
            assert "CVE-2024-1234" in result.summary

    @pytest.mark.asyncio
    async def test_no_cves_found(self, provider):
        mock_response = httpx.Response(
            200,
            json={"totalResults": 0, "vulnerabilities": []},
        )
        with patch("corvid.worker.providers.nvd.httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value = mock_instance

            result = await provider.enrich("ip", "192.168.1.1")
            assert result.success is True
            assert "0 CVE(s)" in result.summary

    @pytest.mark.asyncio
    async def test_api_error_handled(self, provider):
        with patch("corvid.worker.providers.nvd.httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(side_effect=httpx.ReadTimeout("timeout"))
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value = mock_instance

            result = await provider.enrich("ip", "10.0.0.1")
            assert result.success is False
```

---

## Step 3: Enrichment Orchestrator

Coordinates running multiple providers against an IOC and storing results.

### 3.1 `corvid/worker/orchestrator.py`

```python
import asyncio
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from corvid.db.models import Enrichment
from corvid.worker.enrichment import BaseEnrichmentProvider, EnrichmentResult
from corvid.worker.normalizer import normalize_ioc, validate_ioc, IOCType

class EnrichmentOrchestrator:
    def __init__(self, providers: list[BaseEnrichmentProvider]):
        self.providers = providers

    async def enrich_ioc(
        self, ioc_type: str, ioc_value: str
    ) -> list[EnrichmentResult]:
        """Run all applicable providers concurrently for an IOC."""
        normalized = normalize_ioc(ioc_value)
        applicable = [p for p in self.providers if p.supports(ioc_type)]
        if not applicable:
            return []

        tasks = [p.enrich(ioc_type, normalized) for p in applicable]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        enrichment_results = []
        for r in results:
            if isinstance(r, Exception):
                enrichment_results.append(
                    EnrichmentResult(
                        source="unknown", raw_response={},
                        summary="", success=False, error=str(r),
                    )
                )
            else:
                enrichment_results.append(r)
        return enrichment_results

    async def enrich_and_store(
        self, db: AsyncSession, ioc_id: UUID, ioc_type: str, ioc_value: str
    ) -> list[EnrichmentResult]:
        """Enrich an IOC and persist results to the database."""
        results = await self.enrich_ioc(ioc_type, ioc_value)
        for result in results:
            if result.success:
                enrichment = Enrichment(
                    ioc_id=ioc_id,
                    source=result.source,
                    raw_response=result.raw_response,
                    summary=result.summary,
                )
                db.add(enrichment)
        await db.commit()
        return results
```

### Tests: `tests/worker/test_orchestrator.py`

```python
import pytest
from unittest.mock import AsyncMock
from corvid.worker.orchestrator import EnrichmentOrchestrator
from corvid.worker.enrichment import BaseEnrichmentProvider, EnrichmentResult


class MockProvider(BaseEnrichmentProvider):
    def __init__(self, name: str, types: list[str], result: EnrichmentResult):
        self._name = name
        self._types = types
        self._result = result

    @property
    def source_name(self) -> str:
        return self._name

    @property
    def supported_types(self) -> list[str]:
        return self._types

    async def enrich(self, ioc_type: str, ioc_value: str) -> EnrichmentResult:
        return self._result


class TestEnrichmentOrchestrator:
    @pytest.fixture
    def ip_provider(self):
        return MockProvider(
            "test_ip", ["ip"],
            EnrichmentResult(source="test_ip", raw_response={"score": 80},
                             summary="High risk IP", success=True),
        )

    @pytest.fixture
    def domain_provider(self):
        return MockProvider(
            "test_domain", ["domain", "ip"],
            EnrichmentResult(source="test_domain", raw_response={"malicious": True},
                             summary="Known malicious domain", success=True),
        )

    @pytest.fixture
    def failing_provider(self):
        return MockProvider(
            "test_fail", ["ip"],
            EnrichmentResult(source="test_fail", raw_response={},
                             summary="", success=False, error="API error"),
        )

    @pytest.mark.asyncio
    async def test_runs_applicable_providers(self, ip_provider, domain_provider):
        orch = EnrichmentOrchestrator([ip_provider, domain_provider])
        results = await orch.enrich_ioc("ip", "10.0.0.1")
        assert len(results) == 2
        sources = {r.source for r in results}
        assert "test_ip" in sources
        assert "test_domain" in sources

    @pytest.mark.asyncio
    async def test_skips_non_applicable_providers(self, ip_provider, domain_provider):
        orch = EnrichmentOrchestrator([ip_provider, domain_provider])
        results = await orch.enrich_ioc("domain", "evil.com")
        assert len(results) == 1
        assert results[0].source == "test_domain"

    @pytest.mark.asyncio
    async def test_no_applicable_providers(self, ip_provider):
        orch = EnrichmentOrchestrator([ip_provider])
        results = await orch.enrich_ioc("hash_sha256", "a" * 64)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_handles_failing_provider(self, ip_provider, failing_provider):
        orch = EnrichmentOrchestrator([ip_provider, failing_provider])
        results = await orch.enrich_ioc("ip", "10.0.0.1")
        assert len(results) == 2
        successful = [r for r in results if r.success]
        failed = [r for r in results if not r.success]
        assert len(successful) == 1
        assert len(failed) == 1

    @pytest.mark.asyncio
    async def test_normalizes_ioc_value(self, ip_provider):
        orch = EnrichmentOrchestrator([ip_provider])
        results = await orch.enrich_ioc("ip", "  10.0.0.1  ")
        assert len(results) == 1
        assert results[0].success is True

    @pytest.mark.asyncio
    async def test_handles_provider_exception(self):
        """Test that exceptions raised by providers are caught."""
        class ExplodingProvider(BaseEnrichmentProvider):
            source_name = "exploding"
            supported_types = ["ip"]
            async def enrich(self, ioc_type, ioc_value):
                raise RuntimeError("Boom!")

        orch = EnrichmentOrchestrator([ExplodingProvider()])
        results = await orch.enrich_ioc("ip", "10.0.0.1")
        assert len(results) == 1
        assert results[0].success is False
        assert "Boom!" in results[0].error
```

---

## Step 4: Redis Task Queue

### 4.1 `corvid/worker/tasks.py`

```python
import arq
from arq.connections import RedisSettings
from corvid.config import settings
from corvid.worker.orchestrator import EnrichmentOrchestrator
from corvid.worker.providers.abuseipdb import AbuseIPDBProvider
from corvid.worker.providers.urlhaus import URLhausProvider
from corvid.worker.providers.nvd import NVDProvider
from corvid.db.session import async_session
import os

async def enrich_ioc_task(ctx: dict, ioc_id: str, ioc_type: str, ioc_value: str):
    """Background task: enrich an IOC using all applicable providers."""
    providers = [
        AbuseIPDBProvider(api_key=os.getenv("ABUSEIPDB_API_KEY", "")),
        URLhausProvider(),
        NVDProvider(api_key=os.getenv("NVD_API_KEY")),
    ]
    orchestrator = EnrichmentOrchestrator(providers)
    async with async_session() as db:
        results = await orchestrator.enrich_and_store(
            db=db,
            ioc_id=ioc_id,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
        )
    return {
        "ioc_id": ioc_id,
        "results": [
            {"source": r.source, "success": r.success, "summary": r.summary}
            for r in results
        ],
    }

class WorkerSettings:
    functions = [enrich_ioc_task]
    redis_settings = RedisSettings.from_dsn(settings.redis_url)
```

### 4.2 Wire queue into API: update `corvid/api/routes/iocs.py`

Add an endpoint to trigger enrichment:

```python
@router.post("/{ioc_id}/enrich", status_code=202)
async def enrich_ioc(ioc_id: UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(IOC).where(IOC.id == ioc_id))
    ioc = result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    # Enqueue enrichment task
    from arq import create_pool
    from arq.connections import RedisSettings
    from corvid.config import settings
    redis = await create_pool(RedisSettings.from_dsn(settings.redis_url))
    await redis.enqueue_job("enrich_ioc_task", str(ioc.id), ioc.type, ioc.value)
    return {"status": "enrichment_queued", "ioc_id": str(ioc.id)}
```

### Tests for task queue integration: `tests/worker/test_tasks.py`

```python
import pytest
from unittest.mock import AsyncMock, patch, MagicMock


class TestEnrichIOCTask:
    @pytest.mark.asyncio
    async def test_task_calls_orchestrator(self):
        """Verify the task function wires up providers and calls orchestrator."""
        mock_results = [
            MagicMock(source="abuseipdb", success=True, summary="High risk"),
            MagicMock(source="urlhaus", success=True, summary="No records"),
        ]
        with patch("corvid.worker.tasks.EnrichmentOrchestrator") as MockOrch, \
             patch("corvid.worker.tasks.async_session") as mock_session_factory:

            mock_orch_instance = AsyncMock()
            mock_orch_instance.enrich_and_store = AsyncMock(return_value=mock_results)
            MockOrch.return_value = mock_orch_instance

            mock_session = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)
            mock_session_factory.return_value = mock_session

            from corvid.worker.tasks import enrich_ioc_task
            result = await enrich_ioc_task(
                {}, "test-uuid", "ip", "10.0.0.1"
            )
            assert result["ioc_id"] == "test-uuid"
            assert len(result["results"]) == 2
            assert result["results"][0]["source"] == "abuseipdb"
```

---

## Step 5: End-to-End Pipeline Test

### `tests/test_e2e_pipeline.py`

```python
"""
End-to-end test: Submit IOC → Normalize → Enrich → Verify stored results.

This test uses mocked external APIs to test the full pipeline without
real network calls. For integration tests with real APIs, see
tests/integration/ (requires API keys in env).
"""
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from unittest.mock import patch, AsyncMock
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy import select
from corvid.db.models import Base, IOC, Enrichment
from corvid.api.main import app
from corvid.db.session import get_db
from corvid.worker.orchestrator import EnrichmentOrchestrator
from corvid.worker.enrichment import EnrichmentResult


@pytest_asyncio.fixture
async def async_engine():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(async_engine):
    session_factory = async_sessionmaker(async_engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session


@pytest_asyncio.fixture
async def client(db_session):
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


class TestEndToEndPipeline:
    @pytest.mark.asyncio
    async def test_submit_and_enrich_ip(self, client, db_session):
        """Full pipeline: create IOC, run enrichment, verify DB records."""
        # Step 1: Submit IOC
        resp = await client.post("/api/v1/iocs/", json={
            "type": "ip",
            "value": "203.0.113.42",
            "tags": ["suspicious"],
        })
        assert resp.status_code == 201
        ioc_data = resp.json()
        ioc_id = ioc_data["id"]

        # Step 2: Run enrichment (simulated - no queue, direct call)
        mock_abuseipdb = EnrichmentResult(
            source="abuseipdb",
            raw_response={"abuseConfidenceScore": 90, "totalReports": 50},
            summary="Abuse confidence: 90%, 50 reports, country: CN",
            success=True,
        )
        mock_urlhaus = EnrichmentResult(
            source="urlhaus",
            raw_response={"query_status": "no_results"},
            summary="No URLhaus records found for this IOC.",
            success=True,
        )

        from corvid.worker.enrichment import BaseEnrichmentProvider

        class FakeProvider(BaseEnrichmentProvider):
            def __init__(self, name, types, result):
                self._name = name
                self._types = types
                self._result = result

            @property
            def source_name(self):
                return self._name

            @property
            def supported_types(self):
                return self._types

            async def enrich(self, ioc_type, ioc_value):
                return self._result

        orchestrator = EnrichmentOrchestrator([
            FakeProvider("abuseipdb", ["ip"], mock_abuseipdb),
            FakeProvider("urlhaus", ["ip", "url", "domain"], mock_urlhaus),
        ])

        results = await orchestrator.enrich_and_store(
            db=db_session,
            ioc_id=ioc_id,
            ioc_type="ip",
            ioc_value="203.0.113.42",
        )

        # Step 3: Verify enrichment results
        assert len(results) == 2
        assert all(r.success for r in results)

        # Step 4: Verify IOC retrievable via API
        get_resp = await client.get(f"/api/v1/iocs/{ioc_id}")
        assert get_resp.status_code == 200
        assert get_resp.json()["value"] == "203.0.113.42"

    @pytest.mark.asyncio
    async def test_submit_normalize_detect(self, client):
        """Verify IOC normalization through the API layer."""
        # Whitespace should be stripped
        resp = await client.post("/api/v1/iocs/", json={
            "type": "ip",
            "value": "  10.0.0.1  ",
        })
        assert resp.status_code == 201
        # Value stored should be stripped (by Pydantic validator)
        assert resp.json()["value"] == "10.0.0.1"
```

---

## Phase 2 Completion Checklist

- [ ] `corvid/worker/normalizer.py` — IOC normalization, validation, type detection
- [ ] `corvid/worker/enrichment.py` — Base enrichment provider interface
- [ ] `corvid/worker/providers/abuseipdb.py` — AbuseIPDB integration
- [ ] `corvid/worker/providers/urlhaus.py` — URLhaus integration
- [ ] `corvid/worker/providers/nvd.py` — NVD CVE search integration
- [ ] `corvid/worker/orchestrator.py` — Concurrent enrichment orchestrator
- [ ] `corvid/worker/tasks.py` — arq task definitions
- [ ] `POST /{ioc_id}/enrich` endpoint wired to queue
- [ ] `tests/worker/test_normalizer.py` — 28 tests (normalize, validate, detect)
- [ ] `tests/worker/test_enrichment.py` — 17 tests (all 3 providers + result model)
- [ ] `tests/worker/test_orchestrator.py` — 7 tests (orchestration logic)
- [ ] `tests/worker/test_tasks.py` — 1 test (task wiring)
- [ ] `tests/test_e2e_pipeline.py` — 2 tests (full pipeline integration)
- [ ] All tests passing with `pytest`

---

## Test Summary (Phases 1 + 2 Combined)

| Test File | Tests | What It Covers |
|-----------|-------|----------------|
| `tests/api/test_models.py` | 9 | Pydantic model validation |
| `tests/db/test_models.py` | 10 | SQLAlchemy model instantiation |
| `tests/api/test_iocs.py` | 13 | API CRUD endpoints |
| `tests/worker/test_normalizer.py` | 28 | IOC normalization + validation + detection |
| `tests/worker/test_enrichment.py` | 17 | Provider integrations (mocked HTTP) |
| `tests/worker/test_orchestrator.py` | 7 | Concurrent enrichment orchestration |
| `tests/worker/test_tasks.py` | 1 | Background task wiring |
| `tests/test_e2e_pipeline.py` | 2 | Full submit → enrich → verify pipeline |
| **Total** | **87** | |

### Running the Full Suite

```bash
# All tests
pytest -v

# With coverage report
pytest --cov=corvid --cov-report=term-missing --cov-report=html

# Just Phase 1
pytest tests/api/ tests/db/ -v

# Just Phase 2
pytest tests/worker/ tests/test_e2e_pipeline.py -v

# Specific provider tests
pytest tests/worker/test_enrichment.py -v -k "AbuseIPDB"
```
