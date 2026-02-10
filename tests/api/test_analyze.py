"""Tests for the /analyze endpoint.

Tests the full analysis pipeline from API request to response.
"""

import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from corvid.api.models.analysis import AgentAnalysisOutput


@pytest.mark.phase3
class TestAnalyzeEndpoint:
    """Tests for POST /api/v1/analyses/analyze endpoint."""

    @pytest.mark.asyncio
    async def test_analyze_single_ip(self, client, db_session):
        """Test analyzing a single IP IOC."""
        mock_agent_output = AgentAnalysisOutput(
            summary="This IP is associated with malware distribution.",
            severity=7.5,
            confidence=0.8,
            related_cves=["CVE-2024-21762"],
            mitre_techniques=["T1071"],
            enrichment_findings={"abuseipdb": "High abuse score"},
            recommended_actions=["Block at firewall"],
            related_iocs=[],
        )

        with patch("corvid.api.routes.analyses.CorvidAgent") as mock_agent_class:
            mock_agent = AsyncMock()
            mock_agent.analyze_ioc.return_value = mock_agent_output
            mock_agent_class.return_value = mock_agent

            with patch("corvid.api.routes.analyses._build_providers") as mock_providers:
                mock_providers.return_value = []

                response = await client.post(
                    "/api/v1/analyses/analyze",
                    json={
                        "iocs": [{"type": "ip", "value": "192.168.1.100"}],
                        "context": "Found in firewall logs",
                        "priority": "high",
                    },
                )

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "completed"
        assert "analysis_id" in data
        assert len(data["results"]) == 1

        result = data["results"][0]
        assert result["ioc"]["type"] == "ip"
        assert result["ioc"]["value"] == "192.168.1.100"
        assert result["severity"] == 7.5
        assert result["confidence"] == 0.8
        assert "CVE-2024-21762" in result["related_cves"]
        assert "T1071" in result["mitre_techniques"]

    @pytest.mark.asyncio
    async def test_analyze_multiple_iocs(self, client, db_session):
        """Test analyzing multiple IOCs in one request."""
        mock_output1 = AgentAnalysisOutput(
            summary="IP analysis",
            severity=6.0,
            confidence=0.7,
            related_cves=[],
            mitre_techniques=["T1071"],
            enrichment_findings={},
            recommended_actions=["Monitor"],
            related_iocs=[],
        )
        mock_output2 = AgentAnalysisOutput(
            summary="Domain analysis",
            severity=8.0,
            confidence=0.9,
            related_cves=["CVE-2024-11111"],
            mitre_techniques=["T1566"],
            enrichment_findings={},
            recommended_actions=["Block"],
            related_iocs=[],
        )

        with patch("corvid.api.routes.analyses.CorvidAgent") as mock_agent_class:
            mock_agent = AsyncMock()
            mock_agent.analyze_ioc.side_effect = [mock_output1, mock_output2]
            mock_agent_class.return_value = mock_agent

            with patch("corvid.api.routes.analyses._build_providers") as mock_providers:
                mock_providers.return_value = []

                response = await client.post(
                    "/api/v1/analyses/analyze",
                    json={
                        "iocs": [
                            {"type": "ip", "value": "192.168.1.100"},
                            {"type": "domain", "value": "evil.example.com"},
                        ],
                    },
                )

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "completed"
        assert len(data["results"]) == 2

        # Check both results
        ip_result = next(r for r in data["results"] if r["ioc"]["type"] == "ip")
        domain_result = next(r for r in data["results"] if r["ioc"]["type"] == "domain")

        assert ip_result["severity"] == 6.0
        assert domain_result["severity"] == 8.0
        assert "CVE-2024-11111" in domain_result["related_cves"]

    @pytest.mark.asyncio
    async def test_analyze_with_context(self, client, db_session):
        """Test that context is passed through to analysis."""
        mock_output = AgentAnalysisOutput(
            summary="Analysis with context",
            severity=5.0,
            confidence=0.6,
            related_cves=[],
            mitre_techniques=[],
            enrichment_findings={},
            recommended_actions=[],
            related_iocs=[],
        )

        with patch("corvid.api.routes.analyses.CorvidAgent") as mock_agent_class:
            mock_agent = AsyncMock()
            mock_agent.analyze_ioc.return_value = mock_output
            mock_agent_class.return_value = mock_agent

            with patch("corvid.api.routes.analyses._build_providers") as mock_providers:
                mock_providers.return_value = []

                response = await client.post(
                    "/api/v1/analyses/analyze",
                    json={
                        "iocs": [{"type": "ip", "value": "10.0.0.1"}],
                        "context": "Observed in outbound traffic from web server",
                        "priority": "medium",
                    },
                )

        assert response.status_code == 200

        # Verify context was passed to agent
        mock_agent.analyze_ioc.assert_called_once()
        call_kwargs = mock_agent.analyze_ioc.call_args
        assert call_kwargs.kwargs.get("context") == "Observed in outbound traffic from web server"

    @pytest.mark.asyncio
    async def test_analyze_invalid_ioc_rejected(self, client):
        """Test that invalid IOC type returns 422."""
        response = await client.post(
            "/api/v1/analyses/analyze",
            json={
                "iocs": [{"type": "invalid_type", "value": "test"}],
            },
        )

        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_analyze_agent_failure_returns_partial(self, client, db_session):
        """Test that partial failures result in 'partial' status."""
        mock_output_success = AgentAnalysisOutput(
            summary="Successful analysis",
            severity=5.0,
            confidence=0.7,
            related_cves=[],
            mitre_techniques=[],
            enrichment_findings={},
            recommended_actions=[],
            related_iocs=[],
        )

        with patch("corvid.api.routes.analyses.CorvidAgent") as mock_agent_class:
            mock_agent = AsyncMock()
            # First succeeds, second fails
            mock_agent.analyze_ioc.side_effect = [
                mock_output_success,
                Exception("Agent failed"),
            ]
            mock_agent_class.return_value = mock_agent

            with patch("corvid.api.routes.analyses._build_providers") as mock_providers:
                mock_providers.return_value = []

                response = await client.post(
                    "/api/v1/analyses/analyze",
                    json={
                        "iocs": [
                            {"type": "ip", "value": "192.168.1.1"},
                            {"type": "ip", "value": "192.168.1.2"},
                        ],
                    },
                )

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "partial"
        assert len(data["results"]) == 2

        # First should succeed
        assert data["results"][0]["severity"] == 5.0

        # Second should show failure
        assert data["results"][1]["severity"] == 0.0
        assert "failed" in data["results"][1]["summary"].lower()

    @pytest.mark.asyncio
    async def test_analyze_stores_analysis_in_db(self, client, db_session):
        """Test that analysis is stored in the database."""
        from uuid import UUID
        from corvid.db.models import Analysis
        from sqlalchemy import select

        mock_output = AgentAnalysisOutput(
            summary="Test analysis",
            severity=5.0,
            confidence=0.7,
            related_cves=["CVE-2024-12345"],
            mitre_techniques=["T1071"],
            enrichment_findings={},
            recommended_actions=["Test action"],
            related_iocs=[],
        )

        with patch("corvid.api.routes.analyses.CorvidAgent") as mock_agent_class:
            mock_agent = AsyncMock()
            mock_agent.analyze_ioc.return_value = mock_output
            mock_agent_class.return_value = mock_agent

            with patch("corvid.api.routes.analyses._build_providers") as mock_providers:
                mock_providers.return_value = []

                response = await client.post(
                    "/api/v1/analyses/analyze",
                    json={
                        "iocs": [{"type": "ip", "value": "10.0.0.1"}],
                    },
                )

        assert response.status_code == 200
        data = response.json()
        analysis_id = UUID(data["analysis_id"])

        # Verify analysis was stored
        stmt = select(Analysis).where(Analysis.id == analysis_id)
        result = await db_session.execute(stmt)
        analysis = result.scalar_one_or_none()

        assert analysis is not None
        assert analysis.confidence == 0.7
        assert "T1071" in analysis.mitre_techniques
        assert "Test action" in analysis.recommended_actions

    @pytest.mark.asyncio
    async def test_analyze_analysis_retrievable(self, client, db_session):
        """Test that stored analysis can be retrieved via GET endpoint."""
        mock_output = AgentAnalysisOutput(
            summary="Retrievable analysis",
            severity=6.5,
            confidence=0.8,
            related_cves=[],
            mitre_techniques=["T1059"],
            enrichment_findings={},
            recommended_actions=["Check logs"],
            related_iocs=[],
        )

        with patch("corvid.api.routes.analyses.CorvidAgent") as mock_agent_class:
            mock_agent = AsyncMock()
            mock_agent.analyze_ioc.return_value = mock_output
            mock_agent_class.return_value = mock_agent

            with patch("corvid.api.routes.analyses._build_providers") as mock_providers:
                mock_providers.return_value = []

                # Create analysis
                post_response = await client.post(
                    "/api/v1/analyses/analyze",
                    json={
                        "iocs": [{"type": "domain", "value": "test.example.com"}],
                    },
                )

        assert post_response.status_code == 200
        analysis_id = post_response.json()["analysis_id"]

        # Retrieve it
        get_response = await client.get(f"/api/v1/analyses/{analysis_id}")

        assert get_response.status_code == 200
        data = get_response.json()

        assert data["id"] == analysis_id
        assert data["confidence"] == 0.8
        assert "T1059" in data["mitre_techniques"]
        assert "Check logs" in data["recommended_actions"]
