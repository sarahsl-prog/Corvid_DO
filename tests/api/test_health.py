"""Tests for the enhanced health check endpoint."""

import pytest
from unittest.mock import AsyncMock, patch


@pytest.mark.phase4
class TestHealthCheck:
    """Tests for the /health endpoint."""

    @pytest.mark.asyncio
    async def test_health_check_returns_ok(self, client) -> None:
        """Test that health check returns status ok when all checks pass."""
        with patch("corvid.api.main.check_db_connection") as mock_db:
            with patch("corvid.api.main.check_redis_connection") as mock_redis:
                with patch("corvid.api.main.check_gradient_connection") as mock_gradient:
                    mock_db.return_value = {"ok": True, "message": "Connected"}
                    mock_redis.return_value = {"ok": True, "message": "Connected"}
                    mock_gradient.return_value = {"ok": True, "message": "API reachable"}

                    response = await client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "checks" in data

    @pytest.mark.asyncio
    async def test_health_check_returns_degraded_when_db_fails(self, client) -> None:
        """Test that health check returns degraded when DB check fails."""
        with patch("corvid.api.main.check_db_connection") as mock_db:
            with patch("corvid.api.main.check_redis_connection") as mock_redis:
                with patch("corvid.api.main.check_gradient_connection") as mock_gradient:
                    mock_db.return_value = {"ok": False, "message": "Connection refused"}
                    mock_redis.return_value = {"ok": True, "message": "Connected"}
                    mock_gradient.return_value = {"ok": True, "message": "API reachable"}

                    response = await client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "degraded"
        assert data["checks"]["db"]["ok"] is False

    @pytest.mark.asyncio
    async def test_health_check_returns_component_status(self, client) -> None:
        """Test that health check includes all component statuses."""
        with patch("corvid.api.main.check_db_connection") as mock_db:
            with patch("corvid.api.main.check_redis_connection") as mock_redis:
                with patch("corvid.api.main.check_gradient_connection") as mock_gradient:
                    mock_db.return_value = {"ok": True, "message": "Connected"}
                    mock_redis.return_value = {"ok": True, "message": "Connected"}
                    mock_gradient.return_value = {
                        "ok": True,
                        "message": "Not configured (optional)",
                    }

                    response = await client.get("/health")

        assert response.status_code == 200
        data = response.json()

        # Verify all components are present
        assert "checks" in data
        assert "db" in data["checks"]
        assert "redis" in data["checks"]
        assert "gradient" in data["checks"]

        # Verify structure of each check
        for component in ["db", "redis", "gradient"]:
            assert "ok" in data["checks"][component]
            assert "message" in data["checks"][component]

    @pytest.mark.asyncio
    async def test_health_check_gradient_not_configured(self, client) -> None:
        """Test health check when Gradient is not configured."""
        with patch("corvid.api.main.check_db_connection") as mock_db:
            with patch("corvid.api.main.check_redis_connection") as mock_redis:
                with patch("corvid.api.main.check_gradient_connection") as mock_gradient:
                    mock_db.return_value = {"ok": True, "message": "Connected"}
                    mock_redis.return_value = {"ok": True, "message": "Connected"}
                    # Gradient not configured should still return ok
                    mock_gradient.return_value = {
                        "ok": True,
                        "message": "Not configured (optional)",
                    }

                    response = await client.get("/health")

        assert response.status_code == 200
        data = response.json()
        # Overall status should still be ok
        assert data["status"] == "ok"
        assert data["checks"]["gradient"]["ok"] is True
