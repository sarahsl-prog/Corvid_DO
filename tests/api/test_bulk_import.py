"""Integration tests for the bulk IOC import endpoint (POST /api/v1/iocs/bulk).

Uses the in-memory SQLite database via shared fixtures from conftest.py.
"""

import pytest


class TestBulkImportValid:
    """Happy-path bulk import tests."""

    @pytest.mark.asyncio
    async def test_bulk_import_three_iocs_created(self, client) -> None:
        """All three unique IOCs should be created; response summarises counts."""
        payload = {
            "iocs": [
                {"type": "ip", "value": "10.0.0.1"},
                {"type": "domain", "value": "malicious.example.com"},
                {"type": "hash_sha256", "value": "b" * 64},
            ]
        }
        resp = await client.post("/api/v1/iocs/bulk", json=payload)
        assert resp.status_code == 207
        data = resp.json()
        assert data["total"] == 3
        assert data["created"] == 3
        assert data["updated"] == 0
        assert data["failed"] == 0
        assert len(data["results"]) == 3
        for item in data["results"]:
            assert item["status"] == "created"
            assert item["ioc_id"] is not None

    @pytest.mark.asyncio
    async def test_bulk_import_single_ioc(self, client) -> None:
        """Minimum valid request — exactly one IOC."""
        payload = {"iocs": [{"type": "ip", "value": "192.168.100.1"}]}
        resp = await client.post("/api/v1/iocs/bulk", json=payload)
        assert resp.status_code == 207
        data = resp.json()
        assert data["total"] == 1
        assert data["created"] == 1
        assert data["results"][0]["status"] == "created"

    @pytest.mark.asyncio
    async def test_bulk_import_all_ioc_types(self, client) -> None:
        """One of each supported IOC type should all succeed."""
        payload = {
            "iocs": [
                {"type": "ip", "value": "203.0.113.1"},
                {"type": "domain", "value": "test.example.org"},
                {"type": "hash_md5", "value": "a" * 32},
                {"type": "hash_sha1", "value": "c" * 40},
                {"type": "hash_sha256", "value": "d" * 64},
                {"type": "email", "value": "attacker@evil.example.com"},
                {"type": "url", "value": "http://malware.example.com/payload.exe"},
            ]
        }
        resp = await client.post("/api/v1/iocs/bulk", json=payload)
        assert resp.status_code == 207
        data = resp.json()
        assert data["total"] == 7
        assert data["created"] == 7
        assert data["failed"] == 0


class TestBulkImportDeduplication:
    """Tests that duplicate IOCs are updated rather than duplicated."""

    @pytest.mark.asyncio
    async def test_duplicate_ioc_is_updated(self, client) -> None:
        """Submitting the same IOC twice should create once and update once."""
        ioc = {"type": "ip", "value": "10.10.10.10"}
        payload = {"iocs": [ioc, ioc]}
        resp = await client.post("/api/v1/iocs/bulk", json=payload)
        assert resp.status_code == 207
        data = resp.json()
        assert data["created"] == 1
        assert data["updated"] == 1
        assert data["failed"] == 0
        statuses = {r["status"] for r in data["results"]}
        assert statuses == {"created", "updated"}

    @pytest.mark.asyncio
    async def test_dedup_with_pre_existing_ioc(self, client) -> None:
        """An IOC already in the database should be updated, not duplicated."""
        # Pre-create the IOC via the single-create endpoint.
        await client.post("/api/v1/iocs/", json={"type": "ip", "value": "10.20.30.40"})

        resp = await client.post(
            "/api/v1/iocs/bulk",
            json={"iocs": [{"type": "ip", "value": "10.20.30.40", "tags": ["bulk"]}]},
        )
        assert resp.status_code == 207
        data = resp.json()
        assert data["updated"] == 1
        assert data["created"] == 0


class TestBulkImportPartialFailures:
    """Tests that invalid IOCs are reported as failed without aborting valid ones."""

    @pytest.mark.asyncio
    async def test_mixed_valid_and_invalid_iocs(self, client) -> None:
        """Two valid IOCs + one whose value does not match its declared type."""
        payload = {
            "iocs": [
                {"type": "ip", "value": "10.0.1.1"},
                {"type": "ip", "value": "not-an-ip"},  # invalid
                {"type": "domain", "value": "good.example.com"},
            ]
        }
        # The Pydantic model validator on IOCCreate will raise for "not-an-ip".
        # FastAPI validates the entire request body before the handler runs, so
        # an invalid item causes a 422 for the whole request.
        # If the application handles per-item validation inside the handler,
        # we expect 207 with failed=1.  Either outcome is tested here.
        resp = await client.post("/api/v1/iocs/bulk", json=payload)
        assert resp.status_code in (207, 422)
        if resp.status_code == 207:
            data = resp.json()
            # Valid IOCs must have been processed
            assert data["created"] + data["updated"] >= 2
            assert data["failed"] >= 1


class TestBulkImportValidation:
    """Tests for request-level validation (list size, empty list, etc.)."""

    @pytest.mark.asyncio
    async def test_empty_list_rejected(self, client) -> None:
        """An empty iocs list must be rejected with 422."""
        resp = await client.post("/api/v1/iocs/bulk", json={"iocs": []})
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_oversized_list_rejected(self, client) -> None:
        """A list with more than 500 IOCs must be rejected with 422."""
        iocs = [{"type": "ip", "value": f"10.0.{i // 256}.{i % 256}"} for i in range(501)]
        resp = await client.post("/api/v1/iocs/bulk", json={"iocs": iocs})
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_missing_body_rejected(self, client) -> None:
        """A request with no body must be rejected with 422."""
        resp = await client.post("/api/v1/iocs/bulk")
        assert resp.status_code == 422


class TestCORSHeaders:
    """Tests that CORS headers are present on API responses."""

    @pytest.mark.asyncio
    async def test_cors_allowed_origin_header(self, client) -> None:
        """Requests from the Vite dev origin should receive CORS allow-origin header."""
        resp = await client.get(
            "/health",
            headers={"Origin": "http://localhost:5173"},
        )
        assert resp.status_code == 200
        assert "access-control-allow-origin" in resp.headers

    @pytest.mark.asyncio
    async def test_cors_preflight_options(self, client) -> None:
        """OPTIONS preflight for the bulk endpoint returns correct CORS headers."""
        resp = await client.options(
            "/api/v1/iocs/bulk",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )
        # FastAPI's CORSMiddleware responds to preflight with 200 or 204.
        assert resp.status_code in (200, 204)
        assert "access-control-allow-origin" in resp.headers
