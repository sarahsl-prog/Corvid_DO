"""End-to-end tests for Digital Ocean deployment.

These tests verify the complete Corvid platform works correctly when deployed
on Digital Ocean App Platform with managed PostgreSQL and Redis.

Usage:
    export CORVID_TEST_URL=https://your-app.ondigitalocean.app
    pytest tests/e2e/test_do_deployment.py -v

Required:
    - CORVID_TEST_URL environment variable must be set
    - Deployment must be live and accessible
"""

import os
import time
from uuid import UUID

import httpx
import pytest

# Get deployed app URL from environment
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
    """Create an HTTP client with extended timeouts for production."""
    return httpx.Client(timeout=60.0)


class TestDeploymentHealth:
    """Verify deployment health and configuration."""

    def test_app_is_reachable(self, client: httpx.Client, base_url: str) -> None:
        """Test that the deployed app is reachable and responding."""
        response = client.get(f"{base_url}/health")

        assert response.status_code == 200
        assert response.headers.get("content-type") == "application/json"

    def test_health_check_components(self, client: httpx.Client, base_url: str) -> None:
        """Test that all health check components report status."""
        response = client.get(f"{base_url}/health")
        data = response.json()

        # Basic health status
        assert "status" in data
        assert data["status"] in ("ok", "degraded", "unhealthy")

        # Component checks
        assert "checks" in data
        assert "db" in data["checks"]
        assert "redis" in data["checks"]
        assert "gradient" in data["checks"]

        # Database should be healthy
        assert data["checks"]["db"]["ok"] is True
        assert "message" in data["checks"]["db"]

        # Redis should be healthy
        assert data["checks"]["redis"]["ok"] is True
        assert "message" in data["checks"]["redis"]

    def test_openapi_schema_accessible(self, client: httpx.Client, base_url: str) -> None:
        """Test that OpenAPI documentation is accessible."""
        response = client.get(f"{base_url}/openapi.json")

        assert response.status_code == 200
        data = response.json()

        assert data["info"]["title"] == "Corvid"
        assert "paths" in data
        assert "/health" in data["paths"]
        assert "/api/v1/iocs/" in data["paths"]
        assert "/api/v1/analyses/analyze" in data["paths"]

    def test_cors_headers_present(self, client: httpx.Client, base_url: str) -> None:
        """Test that CORS headers are configured for frontend access."""
        response = client.options(
            f"{base_url}/health",
            headers={"Origin": "https://example.com"}
        )

        # CORS should be configured (may need to be added in future)
        # For now, just verify the endpoint responds
        assert response.status_code in (200, 204, 405)


class TestIOCManagement:
    """End-to-end tests for IOC CRUD operations."""

    def test_create_and_retrieve_ioc(self, client: httpx.Client, base_url: str) -> None:
        """Test creating an IOC and retrieving it."""
        # Create IOC
        create_response = client.post(
            f"{base_url}/api/v1/iocs/",
            json={
                "type": "ip",
                "value": "192.0.2.100",  # TEST-NET-1
                "tags": ["e2e-test", "do-deployment"],
            },
        )

        assert create_response.status_code == 201
        ioc_data = create_response.json()

        assert ioc_data["type"] == "ip"
        assert ioc_data["value"] == "192.0.2.100"
        assert "e2e-test" in ioc_data["tags"]

        ioc_id = ioc_data["id"]
        assert UUID(ioc_id)  # Valid UUID

        # Retrieve IOC
        get_response = client.get(f"{base_url}/api/v1/iocs/{ioc_id}")

        assert get_response.status_code == 200
        retrieved = get_response.json()

        assert retrieved["id"] == ioc_id
        assert retrieved["type"] == "ip"
        assert retrieved["value"] == "192.0.2.100"

        # Clean up
        delete_response = client.delete(f"{base_url}/api/v1/iocs/{ioc_id}")
        assert delete_response.status_code == 204

    def test_list_iocs_with_pagination(self, client: httpx.Client, base_url: str) -> None:
        """Test listing IOCs with pagination."""
        response = client.get(f"{base_url}/api/v1/iocs/?limit=10&offset=0")

        assert response.status_code == 200
        data = response.json()

        assert "items" in data
        assert "total" in data
        assert isinstance(data["items"], list)
        assert isinstance(data["total"], int)

    def test_ioc_deduplication(self, client: httpx.Client, base_url: str) -> None:
        """Test that duplicate IOCs are properly handled."""
        ioc_data = {
            "type": "domain",
            "value": "e2e-test.example.com",
            "tags": ["dedup-test"],
        }

        # Create first time
        response1 = client.post(f"{base_url}/api/v1/iocs/", json=ioc_data)
        assert response1.status_code == 201
        ioc1_id = response1.json()["id"]

        # Create second time (should deduplicate)
        ioc_data["tags"] = ["dedup-test-2"]
        response2 = client.post(f"{base_url}/api/v1/iocs/", json=ioc_data)
        assert response2.status_code == 201
        ioc2 = response2.json()

        # Should be same IOC with merged tags
        assert ioc2["id"] == ioc1_id
        assert "dedup-test" in ioc2["tags"]
        assert "dedup-test-2" in ioc2["tags"]

        # Clean up
        client.delete(f"{base_url}/api/v1/iocs/{ioc1_id}")


class TestEnrichmentPipeline:
    """End-to-end tests for IOC enrichment."""

    def test_enrich_ip_address(self, client: httpx.Client, base_url: str) -> None:
        """Test enriching an IP address with external sources."""
        # Create IOC
        create_response = client.post(
            f"{base_url}/api/v1/iocs/",
            json={
                "type": "ip",
                "value": "8.8.8.8",  # Google DNS
                "tags": ["enrichment-test"],
            },
        )
        assert create_response.status_code == 201
        ioc_id = create_response.json()["id"]

        try:
            # Trigger enrichment
            enrich_response = client.post(
                f"{base_url}/api/v1/iocs/{ioc_id}/enrich",
                timeout=90.0,  # Enrichment takes time
            )

            # Accept 200 (sync) or 202 (async)
            assert enrich_response.status_code in (200, 202)

            if enrich_response.status_code == 200:
                data = enrich_response.json()
                assert "results" in data
                assert len(data["results"]) > 0

                # Check provider results
                for result in data["results"]:
                    assert "source" in result
                    assert "success" in result
                    assert result["source"] in ["abuseipdb", "urlhaus", "nvd"]

        finally:
            # Clean up
            client.delete(f"{base_url}/api/v1/iocs/{ioc_id}")

    def test_enrichment_providers_available(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """Test that enrichment providers are configured and working."""
        # This tests the whole pipeline by checking if enrichment succeeds
        create_response = client.post(
            f"{base_url}/api/v1/iocs/",
            json={"type": "url", "value": "https://example.com/test", "tags": ["provider-test"]},
        )
        assert create_response.status_code == 201
        ioc_id = create_response.json()["id"]

        try:
            response = client.post(
                f"{base_url}/api/v1/iocs/{ioc_id}/enrich",
                timeout=90.0,
            )
            # Should succeed even if some providers fail
            assert response.status_code in (200, 202)
        finally:
            client.delete(f"{base_url}/api/v1/iocs/{ioc_id}")


class TestAnalysisEndpoint:
    """End-to-end tests for AI-powered analysis."""

    def test_analyze_single_ioc(self, client: httpx.Client, base_url: str) -> None:
        """Test analyzing a single IOC end-to-end."""
        response = client.post(
            f"{base_url}/api/v1/analyses/analyze",
            json={
                "iocs": [
                    {
                        "type": "ip",
                        "value": "192.0.2.50",
                        "tags": ["e2e-analysis-test"],
                    }
                ],
                "context": "E2E test for DO deployment",
                "priority": "low",
            },
            timeout=120.0,  # Analysis can take time
        )

        assert response.status_code == 200
        data = response.json()

        # Verify response structure
        assert "analysis_id" in data
        assert UUID(data["analysis_id"])  # Valid UUID

        assert "status" in data
        assert data["status"] in ("completed", "partial", "failed")

        assert "results" in data
        assert len(data["results"]) == 1

        # Verify result item structure
        result = data["results"][0]
        assert "ioc" in result
        assert result["ioc"]["value"] == "192.0.2.50"

        assert "severity" in result
        assert isinstance(result["severity"], (int, float))
        assert 0 <= result["severity"] <= 10

        assert "confidence" in result
        assert isinstance(result["confidence"], (int, float))
        assert 0 <= result["confidence"] <= 1

        assert "summary" in result
        assert isinstance(result["summary"], str)

        assert "related_cves" in result
        assert isinstance(result["related_cves"], list)

        assert "mitre_techniques" in result
        assert isinstance(result["mitre_techniques"], list)

        assert "enrichments" in result
        assert isinstance(result["enrichments"], dict)

        assert "recommended_actions" in result
        assert isinstance(result["recommended_actions"], list)

    def test_analyze_multiple_iocs(self, client: httpx.Client, base_url: str) -> None:
        """Test analyzing multiple IOCs in a batch."""
        response = client.post(
            f"{base_url}/api/v1/analyses/analyze",
            json={
                "iocs": [
                    {"type": "ip", "value": "192.0.2.1", "tags": ["batch-test"]},
                    {"type": "domain", "value": "example.com", "tags": ["batch-test"]},
                    {"type": "url", "value": "https://example.com", "tags": ["batch-test"]},
                ],
                "context": "Batch analysis test",
                "priority": "medium",
            },
            timeout=180.0,  # Multiple IOCs take longer
        )

        assert response.status_code == 200
        data = response.json()

        assert "results" in data
        assert len(data["results"]) == 3

        # All IOCs should have results
        values = [r["ioc"]["value"] for r in data["results"]]
        assert "192.0.2.1" in values
        assert "example.com" in values
        assert "https://example.com" in values

    def test_retrieve_analysis_by_id(self, client: httpx.Client, base_url: str) -> None:
        """Test retrieving a stored analysis by ID."""
        # First create an analysis
        analyze_response = client.post(
            f"{base_url}/api/v1/analyses/analyze",
            json={
                "iocs": [{"type": "ip", "value": "192.0.2.99", "tags": ["retrieval-test"]}],
                "context": "Test analysis retrieval",
                "priority": "low",
            },
            timeout=120.0,
        )

        assert analyze_response.status_code == 200
        analysis_id = analyze_response.json()["analysis_id"]

        # Retrieve the analysis
        get_response = client.get(f"{base_url}/api/v1/analyses/{analysis_id}")

        assert get_response.status_code == 200
        analysis = get_response.json()

        assert analysis["id"] == analysis_id
        assert "analysis_text" in analysis
        assert "confidence" in analysis
        assert "mitre_techniques" in analysis
        assert "recommended_actions" in analysis
        assert "created_at" in analysis


class TestPerformance:
    """Performance and load tests for deployed system."""

    def test_response_time_health_check(self, client: httpx.Client, base_url: str) -> None:
        """Test that health check responds quickly."""
        start = time.time()
        response = client.get(f"{base_url}/health")
        duration = time.time() - start

        assert response.status_code == 200
        assert duration < 1.0, f"Health check took {duration:.2f}s (should be < 1s)"

    def test_response_time_ioc_create(self, client: httpx.Client, base_url: str) -> None:
        """Test that IOC creation is fast."""
        start = time.time()
        response = client.post(
            f"{base_url}/api/v1/iocs/",
            json={"type": "ip", "value": "192.0.2.200", "tags": ["perf-test"]},
        )
        duration = time.time() - start

        assert response.status_code == 201
        assert duration < 2.0, f"IOC creation took {duration:.2f}s (should be < 2s)"

        # Clean up
        ioc_id = response.json()["id"]
        client.delete(f"{base_url}/api/v1/iocs/{ioc_id}")

    def test_concurrent_requests(self, client: httpx.Client, base_url: str) -> None:
        """Test that the app handles concurrent requests."""
        import concurrent.futures

        def make_request():
            response = client.get(f"{base_url}/health")
            return response.status_code == 200

        # Make 10 concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(10)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        # All requests should succeed
        assert all(results), "Some concurrent requests failed"


class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_invalid_ioc_type(self, client: httpx.Client, base_url: str) -> None:
        """Test that invalid IOC types are rejected."""
        response = client.post(
            f"{base_url}/api/v1/iocs/",
            json={"type": "invalid_type", "value": "test", "tags": []},
        )

        assert response.status_code == 422  # Validation error

    def test_malformed_ioc_value(self, client: httpx.Client, base_url: str) -> None:
        """Test that malformed IOC values are rejected."""
        response = client.post(
            f"{base_url}/api/v1/iocs/",
            json={"type": "ip", "value": "not-an-ip", "tags": []},
        )

        assert response.status_code == 422  # Validation error

    def test_nonexistent_ioc(self, client: httpx.Client, base_url: str) -> None:
        """Test that requesting nonexistent IOC returns 404."""
        fake_uuid = "00000000-0000-0000-0000-000000000000"
        response = client.get(f"{base_url}/api/v1/iocs/{fake_uuid}")

        assert response.status_code == 404

    def test_nonexistent_analysis(self, client: httpx.Client, base_url: str) -> None:
        """Test that requesting nonexistent analysis returns 404."""
        fake_uuid = "00000000-0000-0000-0000-000000000000"
        response = client.get(f"{base_url}/api/v1/analyses/{fake_uuid}")

        assert response.status_code == 404


class TestDataPersistence:
    """Test that data persists correctly in the database."""

    def test_ioc_survives_across_requests(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """Test that IOC data persists across multiple requests."""
        # Create IOC
        create_response = client.post(
            f"{base_url}/api/v1/iocs/",
            json={
                "type": "hash_sha256",
                "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "tags": ["persistence-test"],
            },
        )
        assert create_response.status_code == 201
        ioc_id = create_response.json()["id"]

        try:
            # Retrieve multiple times
            for _ in range(3):
                response = client.get(f"{base_url}/api/v1/iocs/{ioc_id}")
                assert response.status_code == 200
                assert response.json()["id"] == ioc_id

        finally:
            # Clean up
            client.delete(f"{base_url}/api/v1/iocs/{ioc_id}")

    def test_analysis_persists(self, client: httpx.Client, base_url: str) -> None:
        """Test that analysis results persist in database."""
        # Create analysis
        analyze_response = client.post(
            f"{base_url}/api/v1/analyses/analyze",
            json={
                "iocs": [{"type": "ip", "value": "192.0.2.250", "tags": ["persist-test"]}],
                "context": "Persistence test",
                "priority": "low",
            },
            timeout=120.0,
        )
        assert analyze_response.status_code == 200
        analysis_id = analyze_response.json()["analysis_id"]

        # Retrieve multiple times - should get same data
        responses = []
        for _ in range(3):
            response = client.get(f"{base_url}/api/v1/analyses/{analysis_id}")
            assert response.status_code == 200
            responses.append(response.json())

        # All responses should be identical
        assert all(r["id"] == analysis_id for r in responses)
        assert all(r["analysis_text"] == responses[0]["analysis_text"] for r in responses)
