"""Tests for the enrichment orchestrator."""

import pytest

from corvid.worker.enrichment import BaseEnrichmentProvider, EnrichmentResult
from corvid.worker.orchestrator import EnrichmentOrchestrator


class MockProvider(BaseEnrichmentProvider):
    """Mock enrichment provider for testing."""

    def __init__(
        self, name: str, types: list[str], result: EnrichmentResult
    ) -> None:
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


class ExplodingProvider(BaseEnrichmentProvider):
    """Mock provider that raises an exception."""

    source_name = "exploding"
    supported_types = ["ip"]

    async def enrich(self, ioc_type: str, ioc_value: str) -> EnrichmentResult:
        raise RuntimeError("Boom!")


class TestEnrichmentOrchestrator:
    """Tests for EnrichmentOrchestrator concurrent enrichment logic."""

    @pytest.fixture
    def ip_provider(self) -> MockProvider:
        return MockProvider(
            "test_ip",
            ["ip"],
            EnrichmentResult(
                source="test_ip",
                raw_response={"score": 80},
                summary="High risk IP",
                success=True,
            ),
        )

    @pytest.fixture
    def domain_provider(self) -> MockProvider:
        return MockProvider(
            "test_domain",
            ["domain", "ip"],
            EnrichmentResult(
                source="test_domain",
                raw_response={"malicious": True},
                summary="Known malicious domain",
                success=True,
            ),
        )

    @pytest.fixture
    def failing_provider(self) -> MockProvider:
        return MockProvider(
            "test_fail",
            ["ip"],
            EnrichmentResult(
                source="test_fail",
                raw_response={},
                summary="",
                success=False,
                error="API error",
            ),
        )

    @pytest.mark.asyncio
    async def test_runs_applicable_providers(
        self, ip_provider: MockProvider, domain_provider: MockProvider
    ) -> None:
        orch = EnrichmentOrchestrator([ip_provider, domain_provider])
        results = await orch.enrich_ioc("ip", "10.0.0.1")
        assert len(results) == 2
        sources = {r.source for r in results}
        assert "test_ip" in sources
        assert "test_domain" in sources

    @pytest.mark.asyncio
    async def test_skips_non_applicable_providers(
        self, ip_provider: MockProvider, domain_provider: MockProvider
    ) -> None:
        orch = EnrichmentOrchestrator([ip_provider, domain_provider])
        results = await orch.enrich_ioc("domain", "evil.com")
        assert len(results) == 1
        assert results[0].source == "test_domain"

    @pytest.mark.asyncio
    async def test_no_applicable_providers(
        self, ip_provider: MockProvider
    ) -> None:
        orch = EnrichmentOrchestrator([ip_provider])
        results = await orch.enrich_ioc("hash_sha256", "a" * 64)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_handles_failing_provider(
        self, ip_provider: MockProvider, failing_provider: MockProvider
    ) -> None:
        orch = EnrichmentOrchestrator([ip_provider, failing_provider])
        results = await orch.enrich_ioc("ip", "10.0.0.1")
        assert len(results) == 2
        successful = [r for r in results if r.success]
        failed = [r for r in results if not r.success]
        assert len(successful) == 1
        assert len(failed) == 1

    @pytest.mark.asyncio
    async def test_normalizes_ioc_value(
        self, ip_provider: MockProvider
    ) -> None:
        orch = EnrichmentOrchestrator([ip_provider])
        results = await orch.enrich_ioc("ip", "  10.0.0.1  ")
        assert len(results) == 1
        assert results[0].success is True

    @pytest.mark.asyncio
    async def test_handles_provider_exception(self) -> None:
        """Verify that exceptions raised by providers are caught gracefully."""
        orch = EnrichmentOrchestrator([ExplodingProvider()])
        results = await orch.enrich_ioc("ip", "10.0.0.1")
        assert len(results) == 1
        assert results[0].success is False
        assert "Boom!" in results[0].error

    @pytest.mark.asyncio
    async def test_empty_providers_list(self) -> None:
        orch = EnrichmentOrchestrator([])
        results = await orch.enrich_ioc("ip", "10.0.0.1")
        assert len(results) == 0
