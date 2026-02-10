"""Tests for agent tool implementations.

Tests lookup_ioc, search_cves, enrich_external, and search_kb tools.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from corvid.agent.tools.lookup_ioc import lookup_ioc
from corvid.agent.tools.search_cves import search_cves, _search_nvd
from corvid.agent.tools.enrich_external import enrich_ioc_external, get_available_sources
from corvid.agent.tools.search_kb import search_knowledge_base


@pytest.mark.phase3
class TestLookupIOCTool:
    """Tests for the lookup_ioc agent tool."""

    @pytest.mark.asyncio
    async def test_lookup_ioc_found(self, db_session):
        """Test looking up an IOC that exists in the database."""
        from corvid.db.models import IOC, Enrichment
        from datetime import datetime, timezone

        # Create test IOC with enrichment
        ioc = IOC(
            type="ip",
            value="192.168.1.100",
            tags=["malware", "c2"],
            severity_score=7.5,
        )
        db_session.add(ioc)
        await db_session.flush()

        enrichment = Enrichment(
            ioc_id=ioc.id,
            source="abuseipdb",
            raw_response={"abuse_confidence_score": 85},
            summary="AbuseIPDB: 85% confidence score",
        )
        db_session.add(enrichment)
        await db_session.commit()

        result = await lookup_ioc(db_session, "ip", "192.168.1.100")

        assert result["found"] is True
        assert result["ioc"]["type"] == "ip"
        assert result["ioc"]["value"] == "192.168.1.100"
        assert "malware" in result["ioc"]["tags"]
        assert result["ioc"]["severity_score"] == 7.5
        assert len(result["enrichments"]) == 1
        assert result["enrichments"][0]["source"] == "abuseipdb"

    @pytest.mark.asyncio
    async def test_lookup_ioc_not_found(self, db_session):
        """Test looking up an IOC that doesn't exist."""
        result = await lookup_ioc(db_session, "ip", "10.0.0.1")

        assert result["found"] is False
        assert result["ioc"] is None
        assert len(result["enrichments"]) == 0
        assert "not found" in result["message"].lower()


@pytest.mark.phase3
class TestSearchCVEsTool:
    """Tests for the search_cves agent tool."""

    @pytest.mark.asyncio
    async def test_search_cves_with_results(self, db_session):
        """Test CVE search that returns results from NVD."""
        mock_nvd_response = {
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-21762",
                        "descriptions": [
                            {"lang": "en", "value": "Fortinet FortiOS vulnerability"}
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseScore": 9.8}}
                            ]
                        },
                    }
                }
            ],
        }

        with patch("corvid.agent.tools.search_cves.httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_instance

            mock_response = MagicMock()
            mock_response.json.return_value = mock_nvd_response
            mock_response.raise_for_status = MagicMock()
            mock_instance.get.return_value = mock_response

            result = await search_cves(db_session, "FortiOS", max_results=5)

            assert result["total_found"] >= 1
            assert len(result["nvd_results"]) >= 1
            nvd_cve = result["nvd_results"][0]
            assert nvd_cve["cve_id"] == "CVE-2024-21762"
            assert nvd_cve["cvss_score"] == 9.8

    @pytest.mark.asyncio
    async def test_search_cves_empty(self, db_session):
        """Test CVE search that returns no results."""
        mock_nvd_response = {
            "totalResults": 0,
            "vulnerabilities": [],
        }

        with patch("corvid.agent.tools.search_cves.httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_instance

            mock_response = MagicMock()
            mock_response.json.return_value = mock_nvd_response
            mock_response.raise_for_status = MagicMock()
            mock_instance.get.return_value = mock_response

            result = await search_cves(db_session, "nonexistentproduct12345")

            assert result["total_found"] == 0
            assert len(result["nvd_results"]) == 0
            assert "no cve" in result["message"].lower()


@pytest.mark.phase3
class TestEnrichExternalTool:
    """Tests for the enrich_ioc_external agent tool."""

    @pytest.mark.asyncio
    async def test_enrich_external_delegates_to_orchestrator(self):
        """Test that enrich_external properly calls the orchestrator."""
        mock_enrichment_result = MagicMock()
        mock_enrichment_result.source = "urlhaus"
        mock_enrichment_result.success = True
        mock_enrichment_result.summary = "URLhaus: No matches found"
        mock_enrichment_result.raw_response = {"query_status": "no_results"}
        mock_enrichment_result.error = None

        with patch("corvid.agent.tools.enrich_external._build_providers") as mock_build:
            with patch("corvid.agent.tools.enrich_external.EnrichmentOrchestrator") as mock_orch_class:
                mock_provider = MagicMock()
                mock_provider.source_name = "urlhaus"
                mock_provider.supported_types = ["ip", "domain", "url"]
                mock_build.return_value = [mock_provider]

                mock_orchestrator = AsyncMock()
                mock_orchestrator.enrich_ioc.return_value = [mock_enrichment_result]
                mock_orch_class.return_value = mock_orchestrator

                result = await enrich_ioc_external("ip", "192.168.1.100")

                assert result["success"] is True
                assert result["total_sources"] == 1
                assert result["successful_sources"] == 1
                assert len(result["enrichments"]) == 1
                assert result["enrichments"][0]["source"] == "urlhaus"
                mock_orchestrator.enrich_ioc.assert_called_once_with("ip", "192.168.1.100")

    def test_get_available_sources(self):
        """Test listing available enrichment sources."""
        with patch("corvid.agent.tools.enrich_external._build_providers") as mock_build:
            mock_provider = MagicMock()
            mock_provider.source_name = "test_provider"
            mock_provider.supported_types = ["ip", "domain"]
            mock_build.return_value = [mock_provider]

            sources = get_available_sources()

            assert len(sources) == 1
            assert sources[0]["name"] == "test_provider"
            assert "ip" in sources[0]["supported_types"]


@pytest.mark.phase3
class TestSearchKBTool:
    """Tests for the search_knowledge_base agent tool."""

    @pytest.mark.asyncio
    async def test_search_kb_returns_documents(self):
        """Test KB search returns formatted documents."""
        mock_kb_response = {
            "results": [
                {
                    "id": "CVE-2024-21762",
                    "content": "Fortinet FortiOS out-of-bounds write vulnerability...",
                    "score": 0.95,
                    "metadata": {
                        "title": "CVE-2024-21762: CRITICAL",
                        "doc_type": "cve",
                        "cvss_score": 9.8,
                    },
                },
                {
                    "id": "T1071",
                    "content": "Application Layer Protocol technique...",
                    "score": 0.75,
                    "metadata": {
                        "title": "T1071: Application Layer Protocol",
                        "doc_type": "mitre_technique",
                    },
                },
            ]
        }

        with patch("corvid.agent.tools.search_kb.settings") as mock_settings:
            mock_settings.gradient_api_key = "test-key"
            mock_settings.gradient_kb_id = "test-kb-id"

            with patch("corvid.agent.tools.search_kb.httpx.AsyncClient") as mock_client:
                mock_instance = AsyncMock()
                mock_client.return_value.__aenter__.return_value = mock_instance

                mock_response = MagicMock()
                mock_response.json.return_value = mock_kb_response
                mock_response.raise_for_status = MagicMock()
                mock_instance.post.return_value = mock_response

                result = await search_knowledge_base("FortiOS vulnerability")

                assert result["total_found"] == 2
                assert len(result["documents"]) == 2

                cve_doc = result["documents"][0]
                assert cve_doc["id"] == "CVE-2024-21762"
                assert cve_doc["doc_type"] == "cve"
                assert cve_doc["relevance_score"] == 0.95

                mitre_doc = result["documents"][1]
                assert mitre_doc["id"] == "T1071"
                assert mitre_doc["doc_type"] == "mitre_technique"

    @pytest.mark.asyncio
    async def test_search_kb_empty(self):
        """Test KB search with no matches."""
        mock_kb_response = {"results": []}

        with patch("corvid.agent.tools.search_kb.settings") as mock_settings:
            mock_settings.gradient_api_key = "test-key"
            mock_settings.gradient_kb_id = "test-kb-id"

            with patch("corvid.agent.tools.search_kb.httpx.AsyncClient") as mock_client:
                mock_instance = AsyncMock()
                mock_client.return_value.__aenter__.return_value = mock_instance

                mock_response = MagicMock()
                mock_response.json.return_value = mock_kb_response
                mock_response.raise_for_status = MagicMock()
                mock_instance.post.return_value = mock_response

                result = await search_knowledge_base("completely random nonexistent query")

                assert result["total_found"] == 0
                assert len(result["documents"]) == 0
                assert "no documents" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_search_kb_no_config(self):
        """Test KB search when Gradient is not configured."""
        with patch("corvid.agent.tools.search_kb.settings") as mock_settings:
            mock_settings.gradient_api_key = ""
            mock_settings.gradient_kb_id = ""

            result = await search_knowledge_base("any query")

            assert result["total_found"] == 0
            assert "not configured" in result["message"].lower()
