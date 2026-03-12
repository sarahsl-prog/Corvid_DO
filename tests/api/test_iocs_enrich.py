"""Tests for the IOC enrichment endpoint (POST /api/v1/iocs/{id}/enrich).

Covers lines 100-122 in corvid/api/routes/iocs.py that were not reached
by the existing test_iocs.py suite.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.mark.phase2
class TestEnrichIOCEndpoint:
    """Tests for the POST /api/v1/iocs/{ioc_id}/enrich endpoint."""

    @pytest.mark.asyncio
    async def test_enrich_existing_ioc_returns_202(self, client):
        """Enrichment endpoint returns 202 with results for a known IOC."""
        # First create an IOC
        create_resp = await client.post(
            "/api/v1/iocs/", json={"type": "ip", "value": "203.0.113.42"}
        )
        assert create_resp.status_code == 201
        ioc_id = create_resp.json()["id"]

        # Mock the enrichment orchestrator so we don't hit real APIs
        mock_result = MagicMock()
        mock_result.source = "urlhaus"
        mock_result.success = True
        mock_result.summary = "No matches found"

        with (
            patch(
                "corvid.worker.tasks._build_providers",
                return_value=[],
            ),
            patch(
                "corvid.worker.orchestrator.EnrichmentOrchestrator.enrich_and_store",
                new=AsyncMock(return_value=[mock_result]),
            ),
        ):
            enrich_resp = await client.post(f"/api/v1/iocs/{ioc_id}/enrich")

        assert enrich_resp.status_code == 202
        data = enrich_resp.json()
        assert data["status"] == "enrichment_complete"
        assert str(ioc_id) == data["ioc_id"]
        assert len(data["results"]) == 1
        assert data["results"][0]["source"] == "urlhaus"

    @pytest.mark.asyncio
    async def test_enrich_nonexistent_ioc_returns_404(self, client):
        """Enrichment of a non-existent IOC ID returns 404."""
        fake_id = "00000000-0000-0000-0000-000000000000"
        resp = await client.post(f"/api/v1/iocs/{fake_id}/enrich")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_enrich_failed_provider_still_returns_202(self, client):
        """Even when a provider fails, the endpoint returns 202 with error info."""
        create_resp = await client.post(
            "/api/v1/iocs/", json={"type": "domain", "value": "evil.example.com"}
        )
        assert create_resp.status_code == 201
        ioc_id = create_resp.json()["id"]

        mock_result = MagicMock()
        mock_result.source = "abuseipdb"
        mock_result.success = False
        mock_result.summary = None

        with (
            patch("corvid.worker.tasks._build_providers", return_value=[]),
            patch(
                "corvid.worker.orchestrator.EnrichmentOrchestrator.enrich_and_store",
                new=AsyncMock(return_value=[mock_result]),
            ),
        ):
            resp = await client.post(f"/api/v1/iocs/{ioc_id}/enrich")

        assert resp.status_code == 202
        data = resp.json()
        assert data["results"][0]["success"] is False


@pytest.mark.phase2
class TestIOCRoutesMiscCoverage:
    """Additional coverage for iocs.py CRUD paths."""

    @pytest.mark.asyncio
    async def test_list_iocs_total_count_correct(self, client):
        """list_iocs returns the correct total count with pagination."""
        # Create 3 IOCs
        for i in range(3):
            await client.post(
                "/api/v1/iocs/", json={"type": "ip", "value": f"10.0.0.{i+1}"}
            )

        resp = await client.get("/api/v1/iocs/?limit=2&offset=0")
        assert resp.status_code == 200
        data = resp.json()
        # total should reflect all IOCs, items limited to 2
        assert data["total"] >= 3
        assert len(data["items"]) == 2

    @pytest.mark.asyncio
    async def test_list_iocs_type_filter_excludes_others(self, client):
        """list_iocs type filter returns only matching type."""
        await client.post("/api/v1/iocs/", json={"type": "ip", "value": "192.0.2.1"})
        await client.post(
            "/api/v1/iocs/", json={"type": "domain", "value": "filter-test.example.com"}
        )

        resp = await client.get("/api/v1/iocs/?type=ip")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert all(item["type"] == "ip" for item in items)
