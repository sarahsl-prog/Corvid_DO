"""Tests for background task definitions."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


class TestEnrichIOCTask:
    """Tests for the enrich_ioc_task background task."""

    @pytest.mark.asyncio
    async def test_task_calls_orchestrator(self) -> None:
        """Verify the task function wires up providers and calls orchestrator."""
        mock_results = [
            MagicMock(source="abuseipdb", success=True, summary="High risk"),
            MagicMock(source="urlhaus", success=True, summary="No records"),
        ]

        with (
            patch("corvid.worker.tasks.EnrichmentOrchestrator") as MockOrch,
            patch("corvid.worker.tasks.async_session") as mock_session_factory,
        ):
            mock_orch_instance = AsyncMock()
            mock_orch_instance.enrich_and_store = AsyncMock(
                return_value=mock_results
            )
            MockOrch.return_value = mock_orch_instance

            mock_session = AsyncMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)
            mock_session_factory.return_value = mock_session

            from corvid.worker.tasks import enrich_ioc_task

            result = await enrich_ioc_task({}, "test-uuid", "ip", "10.0.0.1")
            assert result["ioc_id"] == "test-uuid"
            assert len(result["results"]) == 2
            assert result["results"][0]["source"] == "abuseipdb"
            assert result["results"][1]["source"] == "urlhaus"
