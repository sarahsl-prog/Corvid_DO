"""Smoke tests for the deployed Corvid system.

These tests run against a live deployed instance to verify
end-to-end functionality. They require the CORVID_TEST_URL
environment variable to be set.

Usage:
    CORVID_TEST_URL=https://your-app.ondigitalocean.app pytest tests/smoke/ -v
"""

import os
import pytest
import httpx

# Get the deployed URL from environment
CORVID_TEST_URL = os.environ.get("CORVID_TEST_URL", "").rstrip("/")

# Skip all tests if URL not configured
pytestmark = pytest.mark.skipif(
    not CORVID_TEST_URL,
    reason="CORVID_TEST_URL environment variable not set",
)


@pytest.fixture
def base_url() -> str:
    """Return the base URL for the deployed system."""
    return CORVID_TEST_URL


@pytest.fixture
def client() -> httpx.Client:
    """Create an HTTP client with reasonable timeouts for production."""
    return httpx.Client(timeout=30.0)


class TestDeployedSystem:
    """Smoke tests for the deployed Corvid system."""

    def test_health_endpoint_ok(self, client: httpx.Client, base_url: str) -> None:
        """Test that the health endpoint returns 200 and status ok."""
        response = client.get(f"{base_url}/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ("ok", "degraded")
        assert "checks" in data
        assert "db" in data["checks"]

    def test_create_ioc(self, client: httpx.Client, base_url: str) -> None:
        """Test creating an IOC via the API."""
        response = client.post(
            f"{base_url}/api/v1/iocs/",
            json={
                "type": "ip",
                "value": "192.0.2.100",  # TEST-NET-1, safe for testing
                "tags": ["smoke-test"],
            },
        )

        assert response.status_code == 201
        data = response.json()
        assert data["type"] == "ip"
        assert data["value"] == "192.0.2.100"
        assert "id" in data

        # Clean up: delete the IOC
        ioc_id = data["id"]
        delete_response = client.delete(f"{base_url}/api/v1/iocs/{ioc_id}")
        assert delete_response.status_code == 204

    def test_list_iocs(self, client: httpx.Client, base_url: str) -> None:
        """Test listing IOCs returns a valid response."""
        response = client.get(f"{base_url}/api/v1/iocs/")

        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert isinstance(data["items"], list)
        assert isinstance(data["total"], int)

    def test_enrich_ioc(self, client: httpx.Client, base_url: str) -> None:
        """Test triggering enrichment for an IOC."""
        # First create an IOC
        create_response = client.post(
            f"{base_url}/api/v1/iocs/",
            json={
                "type": "ip",
                "value": "8.8.8.8",  # Google DNS, safe for testing
                "tags": ["smoke-test-enrich"],
            },
        )
        assert create_response.status_code == 201
        ioc_id = create_response.json()["id"]

        try:
            # Trigger enrichment
            enrich_response = client.post(
                f"{base_url}/api/v1/iocs/{ioc_id}/enrich",
                timeout=60.0,  # Enrichment may take longer
            )

            # Accept 200 (sync) or 202 (async) as success
            assert enrich_response.status_code in (200, 202)
            data = enrich_response.json()
            assert "results" in data or "status" in data
        finally:
            # Clean up
            client.delete(f"{base_url}/api/v1/iocs/{ioc_id}")

    def test_analyze_ioc(self, client: httpx.Client, base_url: str) -> None:
        """Test the AI-powered analysis endpoint."""
        response = client.post(
            f"{base_url}/api/v1/analyses/analyze",
            json={
                "iocs": [
                    {"type": "ip", "value": "192.0.2.50", "tags": ["smoke-test"]}
                ],
                "context": "Smoke test analysis",
                "priority": "low",
            },
            timeout=120.0,  # Analysis may take longer
        )

        assert response.status_code == 200
        data = response.json()
        assert "analysis_id" in data
        assert "status" in data
        assert data["status"] in ("completed", "partial", "failed")
        assert "results" in data
        assert len(data["results"]) == 1

        # Store analysis_id for next test
        return data["analysis_id"]

    def test_get_analysis(self, client: httpx.Client, base_url: str) -> None:
        """Test retrieving a stored analysis."""
        # First create an analysis
        analyze_response = client.post(
            f"{base_url}/api/v1/analyses/analyze",
            json={
                "iocs": [
                    {"type": "domain", "value": "example.com", "tags": ["smoke-test"]}
                ],
                "context": "Smoke test for retrieval",
                "priority": "low",
            },
            timeout=120.0,
        )

        assert analyze_response.status_code == 200
        analysis_id = analyze_response.json()["analysis_id"]

        # Now retrieve it
        get_response = client.get(f"{base_url}/api/v1/analyses/{analysis_id}")

        assert get_response.status_code == 200
        data = get_response.json()
        assert data["id"] == analysis_id
        assert "confidence" in data
        assert "mitre_techniques" in data


class TestDeployedHealthChecks:
    """Additional health check tests for production."""

    def test_health_check_includes_db_status(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """Test that health check includes database status."""
        response = client.get(f"{base_url}/health")

        assert response.status_code == 200
        data = response.json()
        assert "checks" in data
        assert "db" in data["checks"]
        assert "ok" in data["checks"]["db"]

    def test_health_check_includes_redis_status(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """Test that health check includes Redis status."""
        response = client.get(f"{base_url}/health")

        assert response.status_code == 200
        data = response.json()
        assert "checks" in data
        assert "redis" in data["checks"]
        assert "ok" in data["checks"]["redis"]

    def test_openapi_docs_available(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """Test that OpenAPI documentation is accessible."""
        response = client.get(f"{base_url}/docs")
        assert response.status_code == 200

        response = client.get(f"{base_url}/openapi.json")
        assert response.status_code == 200
        data = response.json()
        assert data["info"]["title"] == "Corvid"
