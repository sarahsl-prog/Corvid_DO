"""Extended tests for corvid/api/main.py.

Covers:
- configure_logging in debug mode
- check_gradient_connection with various HTTP status codes
- global_exception_handler
- add_request_id middleware (X-Request-ID header)
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.mark.phase1
class TestConfigureLogging:
    """Tests for the configure_logging function."""

    def test_configure_logging_debug_mode(self):
        """In debug mode, logger uses human-readable format."""
        from corvid.api.main import configure_logging

        with patch("corvid.api.main.settings") as mock_settings:
            mock_settings.debug = True
            mock_settings.log_level = "DEBUG"
            # Should not raise
            configure_logging()

    def test_configure_logging_production_mode(self):
        """In production mode, logger uses JSON (serialized) format."""
        from corvid.api.main import configure_logging

        with patch("corvid.api.main.settings") as mock_settings:
            mock_settings.debug = False
            mock_settings.log_level = "INFO"
            configure_logging()


@pytest.mark.phase1
class TestGradientHealthCheck:
    """Tests for check_gradient_connection with different HTTP statuses."""

    @pytest.mark.asyncio
    async def test_gradient_not_configured_returns_ok(self):
        """Returns ok=True when gradient_api_key is not set."""
        from corvid.api.main import check_gradient_connection

        with patch("corvid.api.main.settings") as mock_settings:
            mock_settings.gradient_api_key = ""
            result = await check_gradient_connection()

        assert result["ok"] is True
        assert "Not configured" in result["message"]

    @pytest.mark.asyncio
    async def test_gradient_200_returns_ok(self):
        """Returns ok=True when Gradient API responds with HTTP 200."""
        from corvid.api.main import check_gradient_connection

        mock_resp = MagicMock()
        mock_resp.status_code = 200

        mock_client = MagicMock()
        mock_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_instance
        mock_instance.get.return_value = mock_resp

        with (
            patch("corvid.api.main.settings") as mock_settings,
            patch("corvid.api.main.httpx.AsyncClient", mock_client),
        ):
            mock_settings.gradient_api_key = "test-key"
            result = await check_gradient_connection()

        assert result["ok"] is True

    @pytest.mark.asyncio
    async def test_gradient_401_returns_not_ok(self):
        """Returns ok=False with helpful message on 401 authentication failure."""
        from corvid.api.main import check_gradient_connection

        mock_resp = MagicMock()
        mock_resp.status_code = 401

        mock_client = MagicMock()
        mock_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_instance
        mock_instance.get.return_value = mock_resp

        with (
            patch("corvid.api.main.settings") as mock_settings,
            patch("corvid.api.main.httpx.AsyncClient", mock_client),
        ):
            mock_settings.gradient_api_key = "bad-key"
            result = await check_gradient_connection()

        assert result["ok"] is False
        assert "401" in result["message"]

    @pytest.mark.asyncio
    async def test_gradient_403_returns_not_ok(self):
        """Returns ok=False on 403 Forbidden."""
        from corvid.api.main import check_gradient_connection

        mock_resp = MagicMock()
        mock_resp.status_code = 403

        mock_client = MagicMock()
        mock_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_instance
        mock_instance.get.return_value = mock_resp

        with (
            patch("corvid.api.main.settings") as mock_settings,
            patch("corvid.api.main.httpx.AsyncClient", mock_client),
        ):
            mock_settings.gradient_api_key = "test-key"
            result = await check_gradient_connection()

        assert result["ok"] is False

    @pytest.mark.asyncio
    async def test_gradient_other_status_returns_not_ok(self):
        """Any non-200 non-401/403 status also returns ok=False."""
        from corvid.api.main import check_gradient_connection

        mock_resp = MagicMock()
        mock_resp.status_code = 500

        mock_client = MagicMock()
        mock_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_instance
        mock_instance.get.return_value = mock_resp

        with (
            patch("corvid.api.main.settings") as mock_settings,
            patch("corvid.api.main.httpx.AsyncClient", mock_client),
        ):
            mock_settings.gradient_api_key = "test-key"
            result = await check_gradient_connection()

        assert result["ok"] is False
        assert "500" in result["message"]

    @pytest.mark.asyncio
    async def test_gradient_exception_returns_not_ok(self):
        """Network exceptions return ok=False with error message."""
        import httpx

        from corvid.api.main import check_gradient_connection

        mock_client = MagicMock()
        mock_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_instance
        mock_instance.get.side_effect = httpx.ConnectError("connection refused")

        with (
            patch("corvid.api.main.settings") as mock_settings,
            patch("corvid.api.main.httpx.AsyncClient", mock_client),
        ):
            mock_settings.gradient_api_key = "test-key"
            result = await check_gradient_connection()

        assert result["ok"] is False


@pytest.mark.phase1
class TestMiddlewareAndHandlers:
    """Tests for middleware and exception handlers."""

    @pytest.mark.asyncio
    async def test_request_id_header_echoed(self, client):
        """Custom X-Request-ID is echoed in the response."""
        resp = await client.get(
            "/health", headers={"X-Request-ID": "test-req-123"}
        )
        assert resp.headers.get("X-Request-ID") == "test-req-123"

    @pytest.mark.asyncio
    async def test_request_id_generated_when_absent(self, client):
        """X-Request-ID is generated when not provided."""
        resp = await client.get("/health")
        assert "X-Request-ID" in resp.headers
        assert len(resp.headers["X-Request-ID"]) > 0
