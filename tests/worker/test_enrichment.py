"""Tests for enrichment providers (AbuseIPDB, URLhaus, NVD).

All external HTTP calls are mocked -- no real API calls are made.
"""

import pytest
import httpx
from unittest.mock import AsyncMock, patch

from corvid.worker.enrichment import EnrichmentResult
from corvid.worker.providers.abuseipdb import AbuseIPDBProvider
from corvid.worker.providers.urlhaus import URLhausProvider
from corvid.worker.providers.nvd import NVDProvider

# Dummy request object needed for httpx.Response.raise_for_status()
_DUMMY_REQUEST = httpx.Request("GET", "https://test.example.com")


class TestEnrichmentResult:
    """Tests for the EnrichmentResult dataclass."""

    def test_successful_result(self) -> None:
        result = EnrichmentResult(
            source="test",
            raw_response={"key": "value"},
            summary="Test summary",
            success=True,
        )
        assert result.success is True
        assert result.error is None

    def test_failed_result(self) -> None:
        result = EnrichmentResult(
            source="test",
            raw_response={},
            summary="",
            success=False,
            error="timeout",
        )
        assert result.success is False
        assert result.error == "timeout"


class TestAbuseIPDBProvider:
    """Tests for the AbuseIPDB enrichment provider."""

    @pytest.fixture
    def provider(self) -> AbuseIPDBProvider:
        return AbuseIPDBProvider(api_key="test-key")

    def test_supports_ip(self, provider: AbuseIPDBProvider) -> None:
        assert provider.supports("ip") is True

    def test_does_not_support_domain(self, provider: AbuseIPDBProvider) -> None:
        assert provider.supports("domain") is False

    def test_does_not_support_hash(self, provider: AbuseIPDBProvider) -> None:
        assert provider.supports("hash_sha256") is False

    @pytest.mark.asyncio
    async def test_unsupported_type_returns_error(
        self, provider: AbuseIPDBProvider
    ) -> None:
        result = await provider.enrich("domain", "evil.com")
        assert result.success is False
        assert result.error == "unsupported_type"

    @pytest.mark.asyncio
    async def test_successful_lookup(self, provider: AbuseIPDBProvider) -> None:
        mock_response = httpx.Response(
            200,
            json={
                "data": {
                    "abuseConfidenceScore": 85,
                    "totalReports": 42,
                    "countryCode": "RU",
                }
            },
            request=_DUMMY_REQUEST,
        )
        with patch(
            "corvid.worker.providers.abuseipdb.httpx.AsyncClient"
        ) as mock_client:
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
    async def test_http_error_handled(self, provider: AbuseIPDBProvider) -> None:
        with patch(
            "corvid.worker.providers.abuseipdb.httpx.AsyncClient"
        ) as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(
                side_effect=httpx.ConnectError("connection refused")
            )
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value = mock_instance

            result = await provider.enrich("ip", "203.0.113.42")
            assert result.success is False
            assert result.error is not None


class TestURLhausProvider:
    """Tests for the URLhaus enrichment provider."""

    @pytest.fixture
    def provider(self) -> URLhausProvider:
        return URLhausProvider()

    def test_supports_url(self, provider: URLhausProvider) -> None:
        assert provider.supports("url") is True

    def test_supports_domain(self, provider: URLhausProvider) -> None:
        assert provider.supports("domain") is True

    def test_supports_ip(self, provider: URLhausProvider) -> None:
        assert provider.supports("ip") is True

    def test_does_not_support_hash(self, provider: URLhausProvider) -> None:
        assert provider.supports("hash_sha256") is False

    @pytest.mark.asyncio
    async def test_unsupported_type(self, provider: URLhausProvider) -> None:
        result = await provider.enrich("hash_sha256", "a" * 64)
        assert result.success is False

    @pytest.mark.asyncio
    async def test_no_results(self, provider: URLhausProvider) -> None:
        mock_response = httpx.Response(200, json={"query_status": "no_results"}, request=_DUMMY_REQUEST)
        with patch(
            "corvid.worker.providers.urlhaus.httpx.AsyncClient"
        ) as mock_client:
            mock_instance = AsyncMock()
            mock_instance.post = AsyncMock(return_value=mock_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value = mock_instance

            result = await provider.enrich("url", "https://clean-site.com")
            assert result.success is True
            assert "No URLhaus records" in result.summary

    @pytest.mark.asyncio
    async def test_successful_lookup(self, provider: URLhausProvider) -> None:
        mock_response = httpx.Response(
            200,
            json={
                "query_status": "ok",
                "url_count": 3,
                "threat": "malware_download",
                "urls": [{}, {}, {}],
            },
            request=_DUMMY_REQUEST,
        )
        with patch(
            "corvid.worker.providers.urlhaus.httpx.AsyncClient"
        ) as mock_client:
            mock_instance = AsyncMock()
            mock_instance.post = AsyncMock(return_value=mock_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value = mock_instance

            result = await provider.enrich("domain", "evil.com")
            assert result.success is True
            assert "3 URL(s)" in result.summary

    @pytest.mark.asyncio
    async def test_http_error_handled(self, provider: URLhausProvider) -> None:
        with patch(
            "corvid.worker.providers.urlhaus.httpx.AsyncClient"
        ) as mock_client:
            mock_instance = AsyncMock()
            mock_instance.post = AsyncMock(
                side_effect=httpx.ConnectError("timeout")
            )
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value = mock_instance

            result = await provider.enrich("ip", "10.0.0.1")
            assert result.success is False


class TestNVDProvider:
    """Tests for the NVD CVE search provider."""

    @pytest.fixture
    def provider(self) -> NVDProvider:
        return NVDProvider(api_key="test-key")

    @pytest.fixture
    def provider_no_key(self) -> NVDProvider:
        return NVDProvider()

    def test_supports_ip(self, provider: NVDProvider) -> None:
        assert provider.supports("ip") is True

    def test_supports_hash(self, provider: NVDProvider) -> None:
        assert provider.supports("hash_sha256") is True

    def test_does_not_support_email(self, provider: NVDProvider) -> None:
        assert provider.supports("email") is False

    @pytest.mark.asyncio
    async def test_successful_cve_search(self, provider: NVDProvider) -> None:
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
            request=_DUMMY_REQUEST,
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
    async def test_no_cves_found(self, provider: NVDProvider) -> None:
        mock_response = httpx.Response(
            200,
            json={"totalResults": 0, "vulnerabilities": []},
            request=_DUMMY_REQUEST,
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
    async def test_api_error_handled(self, provider: NVDProvider) -> None:
        with patch("corvid.worker.providers.nvd.httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(
                side_effect=httpx.ReadTimeout("timeout")
            )
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            mock_client.return_value = mock_instance

            result = await provider.enrich("ip", "10.0.0.1")
            assert result.success is False
