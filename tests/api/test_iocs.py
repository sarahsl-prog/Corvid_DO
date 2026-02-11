"""Integration tests for IOC CRUD API endpoints.

Uses an in-memory SQLite database via shared fixtures from conftest.py.
"""

import pytest


class TestHealthEndpoint:
    """Tests for the /health endpoint."""

    @pytest.mark.asyncio
    async def test_health(self, client) -> None:
        resp = await client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] in ("ok", "degraded")
        assert "checks" in data


class TestCreateIOC:
    """Tests for POST /api/v1/iocs/."""

    @pytest.mark.asyncio
    async def test_create_ip_ioc(self, client) -> None:
        resp = await client.post(
            "/api/v1/iocs/", json={"type": "ip", "value": "192.168.1.1"}
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["type"] == "ip"
        assert data["value"] == "192.168.1.1"
        assert "id" in data

    @pytest.mark.asyncio
    async def test_create_domain_ioc(self, client) -> None:
        resp = await client.post(
            "/api/v1/iocs/", json={"type": "domain", "value": "evil.example.com"}
        )
        assert resp.status_code == 201
        assert resp.json()["type"] == "domain"

    @pytest.mark.asyncio
    async def test_create_hash_ioc(self, client) -> None:
        resp = await client.post(
            "/api/v1/iocs/",
            json={"type": "hash_sha256", "value": "a" * 64, "tags": ["malware"]},
        )
        assert resp.status_code == 201
        assert "malware" in resp.json()["tags"]

    @pytest.mark.asyncio
    async def test_create_duplicate_updates_last_seen(self, client) -> None:
        payload = {"type": "ip", "value": "10.0.0.1"}
        resp1 = await client.post("/api/v1/iocs/", json=payload)
        resp2 = await client.post("/api/v1/iocs/", json=payload)
        assert resp1.json()["id"] == resp2.json()["id"]

    @pytest.mark.asyncio
    async def test_create_duplicate_merges_tags(self, client) -> None:
        await client.post(
            "/api/v1/iocs/", json={"type": "ip", "value": "10.0.0.2", "tags": ["c2"]}
        )
        resp = await client.post(
            "/api/v1/iocs/",
            json={"type": "ip", "value": "10.0.0.2", "tags": ["botnet"]},
        )
        tags = resp.json()["tags"]
        assert "c2" in tags
        assert "botnet" in tags

    @pytest.mark.asyncio
    async def test_create_invalid_type(self, client) -> None:
        resp = await client.post(
            "/api/v1/iocs/", json={"type": "invalid", "value": "test"}
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_create_empty_value(self, client) -> None:
        resp = await client.post("/api/v1/iocs/", json={"type": "ip", "value": ""})
        assert resp.status_code == 422


class TestListIOCs:
    """Tests for GET /api/v1/iocs/."""

    @pytest.mark.asyncio
    async def test_list_empty(self, client) -> None:
        resp = await client.get("/api/v1/iocs/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["total"] == 0

    @pytest.mark.asyncio
    async def test_list_after_create(self, client) -> None:
        await client.post("/api/v1/iocs/", json={"type": "ip", "value": "1.2.3.4"})
        await client.post(
            "/api/v1/iocs/", json={"type": "domain", "value": "evil.com"}
        )
        resp = await client.get("/api/v1/iocs/")
        data = resp.json()
        assert data["total"] == 2
        assert len(data["items"]) == 2

    @pytest.mark.asyncio
    async def test_list_filter_by_type(self, client) -> None:
        await client.post("/api/v1/iocs/", json={"type": "ip", "value": "1.2.3.4"})
        await client.post(
            "/api/v1/iocs/", json={"type": "domain", "value": "evil.com"}
        )
        resp = await client.get("/api/v1/iocs/?type=ip")
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["type"] == "ip"

    @pytest.mark.asyncio
    async def test_list_pagination(self, client) -> None:
        for i in range(5):
            await client.post(
                "/api/v1/iocs/", json={"type": "ip", "value": f"10.0.0.{i}"}
            )
        resp = await client.get("/api/v1/iocs/?limit=2&offset=0")
        assert len(resp.json()["items"]) == 2
        assert resp.json()["total"] == 5


class TestGetIOC:
    """Tests for GET /api/v1/iocs/{ioc_id}."""

    @pytest.mark.asyncio
    async def test_get_existing(self, client) -> None:
        create_resp = await client.post(
            "/api/v1/iocs/", json={"type": "ip", "value": "1.2.3.4"}
        )
        ioc_id = create_resp.json()["id"]
        resp = await client.get(f"/api/v1/iocs/{ioc_id}")
        assert resp.status_code == 200
        assert resp.json()["value"] == "1.2.3.4"

    @pytest.mark.asyncio
    async def test_get_nonexistent(self, client) -> None:
        resp = await client.get(
            "/api/v1/iocs/00000000-0000-0000-0000-000000000000"
        )
        assert resp.status_code == 404


class TestDeleteIOC:
    """Tests for DELETE /api/v1/iocs/{ioc_id}."""

    @pytest.mark.asyncio
    async def test_delete_existing(self, client) -> None:
        create_resp = await client.post(
            "/api/v1/iocs/", json={"type": "ip", "value": "1.2.3.4"}
        )
        ioc_id = create_resp.json()["id"]
        del_resp = await client.delete(f"/api/v1/iocs/{ioc_id}")
        assert del_resp.status_code == 204
        get_resp = await client.get(f"/api/v1/iocs/{ioc_id}")
        assert get_resp.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_nonexistent(self, client) -> None:
        resp = await client.delete(
            "/api/v1/iocs/00000000-0000-0000-0000-000000000000"
        )
        assert resp.status_code == 404
