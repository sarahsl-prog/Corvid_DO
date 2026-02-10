"""End-to-end pipeline tests: Submit IOC -> Normalize -> Enrich -> Verify.

Uses mocked external APIs -- no real network calls.
"""

import uuid

import pytest

from corvid.worker.enrichment import BaseEnrichmentProvider, EnrichmentResult
from corvid.worker.orchestrator import EnrichmentOrchestrator


class FakeProvider(BaseEnrichmentProvider):
    """Fake enrichment provider for E2E tests."""

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


class TestEndToEndPipeline:
    """Full pipeline integration tests."""

    @pytest.mark.asyncio
    async def test_submit_and_enrich_ip(self, client, db_session) -> None:
        """Full pipeline: create IOC, run enrichment, verify DB records."""
        # Step 1: Submit IOC via API
        resp = await client.post(
            "/api/v1/iocs/",
            json={"type": "ip", "value": "203.0.113.42", "tags": ["suspicious"]},
        )
        assert resp.status_code == 201
        ioc_data = resp.json()
        ioc_id = ioc_data["id"]

        # Step 2: Run enrichment directly (bypassing queue for test)
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

        orchestrator = EnrichmentOrchestrator(
            [
                FakeProvider("abuseipdb", ["ip"], mock_abuseipdb),
                FakeProvider("urlhaus", ["ip", "url", "domain"], mock_urlhaus),
            ]
        )

        results = await orchestrator.enrich_and_store(
            db=db_session,
            ioc_id=uuid.UUID(ioc_id),
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
    async def test_submit_normalize_detect(self, client) -> None:
        """Verify IOC normalization through the API layer (whitespace stripping)."""
        resp = await client.post(
            "/api/v1/iocs/", json={"type": "ip", "value": "  10.0.0.1  "}
        )
        assert resp.status_code == 201
        # Value stored should be stripped by Pydantic validator
        assert resp.json()["value"] == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_enrichment_with_no_applicable_providers(
        self, client, db_session
    ) -> None:
        """Verify enrichment gracefully returns empty for unsupported types."""
        resp = await client.post(
            "/api/v1/iocs/", json={"type": "email", "value": "bad@evil.com"}
        )
        assert resp.status_code == 201
        ioc_id = resp.json()["id"]

        # No providers support email type
        orchestrator = EnrichmentOrchestrator(
            [FakeProvider("abuseipdb", ["ip"], EnrichmentResult(
                source="abuseipdb", raw_response={}, summary="", success=True
            ))]
        )

        results = await orchestrator.enrich_and_store(
            db=db_session,
            ioc_id=uuid.UUID(ioc_id),
            ioc_type="email",
            ioc_value="bad@evil.com",
        )
        assert len(results) == 0
