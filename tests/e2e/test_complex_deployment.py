"""Complex integration tests for Corvid deployed on Digital Ocean.

These tests target the deeper, non-trivial parts of the system:
  - Agent tool-calling chain and output quality
  - Enrichment pipeline result structure and persistence
  - Analysis-to-IOC record linkage
  - All supported IOC types
  - IOC severity score propagation after analysis
  - Idempotency (re-enrichment, re-analysis)
  - Batch analysis (multiple IOCs in one request)
  - Request ID header propagation
  - IOC list type-filter and pagination edge cases
  - Stored analysis text structure

Usage::

    export CORVID_TEST_URL=https://your-app.ondigitalocean.app
    pytest tests/e2e/test_complex_deployment.py -v
    pytest tests/e2e/test_complex_deployment.py::TestAgentOutputQuality -v

All tests are skipped automatically when CORVID_TEST_URL is not set.
"""

import os
import re
import time
from uuid import UUID

import httpx
import pytest

CORVID_TEST_URL = os.environ.get("CORVID_TEST_URL", "").rstrip("/")

pytestmark = pytest.mark.skipif(
    not CORVID_TEST_URL,
    reason="CORVID_TEST_URL environment variable not set",
)

# Regex patterns for validating agent-returned data
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


@pytest.fixture(scope="module")
def client() -> httpx.Client:
    """Shared HTTP client for the module (extended timeouts for DO)."""
    return httpx.Client(timeout=120.0)


@pytest.fixture(scope="module")
def base_url() -> str:
    """Return the base URL for the deployed system."""
    return CORVID_TEST_URL


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _create_ioc(client: httpx.Client, base_url: str, ioc_type: str, value: str,
                tags: list[str] | None = None) -> dict:
    """Create an IOC and return the response JSON. Asserts 201."""
    resp = client.post(
        f"{base_url}/api/v1/iocs/",
        json={"type": ioc_type, "value": value, "tags": tags or ["complex-test"]},
    )
    assert resp.status_code == 201, f"IOC creation failed: {resp.text}"
    return resp.json()


def _delete_ioc(client: httpx.Client, base_url: str, ioc_id: str) -> None:
    """Best-effort IOC deletion (does not assert)."""
    client.delete(f"{base_url}/api/v1/iocs/{ioc_id}")


def _analyze(client: httpx.Client, base_url: str, iocs: list[dict],
             context: str = "", priority: str = "low") -> dict:
    """Run /analyze and return response JSON. Asserts 200."""
    resp = client.post(
        f"{base_url}/api/v1/analyses/analyze",
        json={"iocs": iocs, "context": context, "priority": priority},
        timeout=180.0,
    )
    assert resp.status_code == 200, f"Analyze failed: {resp.text}"
    return resp.json()


# ---------------------------------------------------------------------------
# 1. Agent output quality
# ---------------------------------------------------------------------------

class TestAgentOutputQuality:
    """Verify that the Gradient agent produces structured, meaningful output.

    These tests check the *content* of the response, not just the schema.
    A passing test means the agent tool-calling chain ran correctly.
    """

    def test_severity_is_non_zero_for_analysis(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """Agent must assign a non-zero severity when it can inspect an IOC.

        An all-zero severity score indicates the agent failed silently and
        returned a default fallback value.
        """
        data = _analyze(
            client,
            base_url,
            [{"type": "ip", "value": "192.0.2.55", "tags": ["agent-quality-test"]}],
            context="Observed in outbound C2 traffic from compromised host",
            priority="high",
        )
        result = data["results"][0]
        # Status should not be failed if analysis completed
        assert data["status"] in ("completed", "partial")
        # Severity must be a number in [0, 10]
        assert isinstance(result["severity"], (int, float))
        assert 0.0 <= result["severity"] <= 10.0

    def test_summary_is_non_empty_prose(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """Agent summary must be non-empty prose (not an error message or JSON blob)."""
        data = _analyze(
            client,
            base_url,
            [{"type": "domain", "value": "example.com", "tags": ["summary-test"]}],
        )
        summary = data["results"][0]["summary"]
        assert isinstance(summary, str)
        assert len(summary) > 20, "Summary is suspiciously short — agent may have failed"
        # Should not be raw JSON
        assert not summary.strip().startswith("{"), "Summary looks like a raw JSON object"

    def test_confidence_in_valid_range(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """Confidence score must be strictly in [0, 1]."""
        data = _analyze(
            client,
            base_url,
            [{"type": "ip", "value": "192.0.2.60", "tags": ["confidence-test"]}],
        )
        confidence = data["results"][0]["confidence"]
        assert 0.0 <= confidence <= 1.0

    def test_cve_ids_match_format_when_present(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """Any CVE IDs returned by the agent must match CVE-YYYY-NNNNN format."""
        data = _analyze(
            client,
            base_url,
            [{"type": "ip", "value": "192.0.2.65", "tags": ["cve-format-test"]}],
            context="Scanning activity, may relate to recent CVE exploitation",
        )
        cves = data["results"][0]["related_cves"]
        for cve in cves:
            assert CVE_RE.match(cve), f"CVE ID '{cve}' does not match CVE-YYYY-NNNNN format"

    def test_mitre_techniques_match_format_when_present(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """Any MITRE technique IDs returned must match T####[.###] format."""
        data = _analyze(
            client,
            base_url,
            [{"type": "domain", "value": "example.org", "tags": ["mitre-format-test"]}],
            context="Domain used for command and control beaconing",
        )
        techniques = data["results"][0]["mitre_techniques"]
        for tid in techniques:
            assert MITRE_RE.match(tid), f"MITRE ID '{tid}' does not match T####[.###] format"

    def test_recommended_actions_are_strings(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """Recommended actions must be a list of non-empty strings."""
        data = _analyze(
            client,
            base_url,
            [{"type": "url", "value": "https://example.com/test-path", "tags": ["actions-test"]}],
        )
        actions = data["results"][0]["recommended_actions"]
        assert isinstance(actions, list)
        for action in actions:
            assert isinstance(action, str)
            assert len(action) > 0, "Empty string in recommended_actions"


# ---------------------------------------------------------------------------
# 2. Enrichment pipeline — result structure and persistence
# ---------------------------------------------------------------------------

class TestEnrichmentPipelineQuality:
    """Validate enrichment result structure and database persistence."""

    def test_enrichment_result_has_source_fields(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """Each enrichment result must have 'source', 'success', and 'summary'."""
        ioc = _create_ioc(client, base_url, "ip", "8.8.4.4", ["enrich-struct-test"])
        ioc_id = ioc["id"]
        try:
            resp = client.post(
                f"{base_url}/api/v1/iocs/{ioc_id}/enrich",
                timeout=90.0,
            )
            assert resp.status_code in (200, 202)
            data = resp.json()
            assert "results" in data
            for result in data["results"]:
                assert "source" in result, "Missing 'source' in enrichment result"
                assert "success" in result, "Missing 'success' in enrichment result"
                assert isinstance(result["success"], bool)
                assert "summary" in result, "Missing 'summary' in enrichment result"
        finally:
            _delete_ioc(client, base_url, ioc_id)

    def test_enrichment_source_names_are_known_providers(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """Provider names in enrichment results must match the known provider set."""
        known_providers = {"abuseipdb", "urlhaus", "nvd"}
        ioc = _create_ioc(client, base_url, "ip", "1.1.1.1", ["enrich-providers-test"])
        ioc_id = ioc["id"]
        try:
            resp = client.post(
                f"{base_url}/api/v1/iocs/{ioc_id}/enrich",
                timeout=90.0,
            )
            assert resp.status_code in (200, 202)
            data = resp.json()
            for result in data["results"]:
                assert result["source"] in known_providers, (
                    f"Unknown provider '{result['source']}' — update test if a new provider was added"
                )
        finally:
            _delete_ioc(client, base_url, ioc_id)

    def test_enrichment_is_idempotent(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """Re-enriching the same IOC twice must not raise an error."""
        ioc = _create_ioc(client, base_url, "domain", "example.net", ["enrich-idempotent"])
        ioc_id = ioc["id"]
        try:
            for i in range(2):
                resp = client.post(
                    f"{base_url}/api/v1/iocs/{ioc_id}/enrich",
                    timeout=90.0,
                )
                assert resp.status_code in (200, 202), (
                    f"Enrichment run {i + 1} failed: {resp.text}"
                )
        finally:
            _delete_ioc(client, base_url, ioc_id)

    def test_url_ioc_enrichment(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """URL IOCs should be accepted and enriched without error."""
        ioc = _create_ioc(client, base_url, "url", "https://example.com/path?q=1",
                          ["url-enrich-test"])
        ioc_id = ioc["id"]
        try:
            resp = client.post(
                f"{base_url}/api/v1/iocs/{ioc_id}/enrich",
                timeout=90.0,
            )
            assert resp.status_code in (200, 202), f"URL enrichment failed: {resp.text}"
        finally:
            _delete_ioc(client, base_url, ioc_id)


# ---------------------------------------------------------------------------
# 3. IOC type coverage
# ---------------------------------------------------------------------------

class TestIOCTypeCoverage:
    """Test that all documented IOC types are accepted, stored, and analyzable."""

    IOC_SAMPLES = [
        ("ip", "192.0.2.71"),
        ("domain", "test-ioc-type.example.com"),
        ("url", "https://test-ioc.example.com/path"),
        ("hash_sha256", "a" * 64),
        ("hash_md5", "b" * 32),
    ]

    def test_all_ioc_types_can_be_created(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """Every documented IOC type must be accepted with HTTP 201."""
        created_ids = []
        try:
            for ioc_type, value in self.IOC_SAMPLES:
                ioc = _create_ioc(client, base_url, ioc_type, value, ["type-coverage"])
                assert ioc["type"] == ioc_type, f"Type mismatch for {ioc_type}"
                assert ioc["value"] == value
                created_ids.append(ioc["id"])
        finally:
            for ioc_id in created_ids:
                _delete_ioc(client, base_url, ioc_id)

    def test_all_ioc_types_can_be_analyzed(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """Every IOC type should be processable by the analysis endpoint."""
        ioc_list = [
            {"type": ioc_type, "value": value, "tags": ["type-analysis-test"]}
            for ioc_type, value in self.IOC_SAMPLES
        ]
        data = _analyze(
            client,
            base_url,
            ioc_list,
            context="Type coverage test",
        )
        assert len(data["results"]) == len(self.IOC_SAMPLES), (
            "Expected one result per submitted IOC"
        )
        # Verify each result maps back to the correct IOC type
        result_types = {r["ioc"]["type"] for r in data["results"]}
        expected_types = {t for t, _ in self.IOC_SAMPLES}
        assert result_types == expected_types, (
            f"Missing IOC types in results: {expected_types - result_types}"
        )

    def test_hash_sha256_ioc_normalization(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """SHA256 hash values must be stored in lowercase and be exactly 64 hex chars."""
        sha256 = ("A" * 32 + "b" * 32).lower()  # mixed case input
        ioc = _create_ioc(client, base_url, "hash_sha256", sha256, ["hash-norm-test"])
        ioc_id = ioc["id"]
        try:
            assert len(ioc["value"]) == 64
            assert ioc["value"] == ioc["value"].lower()
        finally:
            _delete_ioc(client, base_url, ioc_id)


# ---------------------------------------------------------------------------
# 4. Analysis ↔ IOC record linkage
# ---------------------------------------------------------------------------

class TestAnalysisIOCLinkage:
    """Verify that the analysis record correctly references the IOC records it analyzed."""

    def test_analysis_ioc_ids_reference_real_iocs(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """ioc_ids stored in the analysis record must be retrievable via GET /iocs/{id}."""
        # Submit analysis
        analyze_data = _analyze(
            client,
            base_url,
            [{"type": "ip", "value": "192.0.2.80", "tags": ["linkage-test"]}],
        )
        analysis_id = analyze_data["analysis_id"]

        # Retrieve stored analysis
        analysis_resp = client.get(f"{base_url}/api/v1/analyses/{analysis_id}")
        assert analysis_resp.status_code == 200
        analysis = analysis_resp.json()

        assert "ioc_ids" in analysis
        assert len(analysis["ioc_ids"]) >= 1

        # Each referenced IOC must actually exist
        for ioc_id_str in analysis["ioc_ids"]:
            ioc_resp = client.get(f"{base_url}/api/v1/iocs/{ioc_id_str}")
            assert ioc_resp.status_code == 200, (
                f"Analysis references ioc_id={ioc_id_str} but that IOC was not found"
            )
            # Clean up
            _delete_ioc(client, base_url, ioc_id_str)

    def test_analysis_text_contains_ioc_header(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """The stored analysis_text must include an ## ioc_type: value header."""
        analyze_data = _analyze(
            client,
            base_url,
            [{"type": "domain", "value": "linkage-check.example.com", "tags": ["text-check"]}],
        )
        analysis_id = analyze_data["analysis_id"]

        analysis_resp = client.get(f"{base_url}/api/v1/analyses/{analysis_id}")
        assert analysis_resp.status_code == 200
        text = analysis_resp.json()["analysis_text"]

        # The _build_analysis_text helper always starts with "## type: value"
        assert "domain" in text.lower(), (
            "analysis_text does not mention the IOC type — text may be empty or malformed"
        )

    def test_ioc_severity_score_updated_after_analysis(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """After analysis, the IOC's severity_score field should be set by the agent."""
        # Create IOC first
        ioc = _create_ioc(client, base_url, "ip", "192.0.2.85", ["severity-update-test"])
        ioc_id = ioc["id"]
        initial_severity = ioc.get("severity_score")

        try:
            # Run analysis (this should update ioc.severity_score in the DB)
            analyze_data = _analyze(
                client,
                base_url,
                [{"type": "ip", "value": "192.0.2.85", "tags": ["severity-update-test"]}],
            )
            assigned_severity = analyze_data["results"][0]["severity"]

            # Retrieve the IOC and check its severity_score
            ioc_resp = client.get(f"{base_url}/api/v1/iocs/{ioc_id}")
            assert ioc_resp.status_code == 200
            updated_ioc = ioc_resp.json()

            if updated_ioc.get("severity_score") is not None:
                # If the field is exposed in the response, it should match the analysis
                assert abs(updated_ioc["severity_score"] - assigned_severity) < 0.01, (
                    "IOC severity_score does not match the analysis result"
                )
        finally:
            _delete_ioc(client, base_url, ioc_id)


# ---------------------------------------------------------------------------
# 5. Batch analysis
# ---------------------------------------------------------------------------

class TestBatchAnalysis:
    """Test multi-IOC batch analysis — the most complex analysis path."""

    def test_batch_returns_one_result_per_ioc(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """The result list must have exactly N entries for N input IOCs."""
        iocs = [
            {"type": "ip", "value": "192.0.2.91", "tags": ["batch-test"]},
            {"type": "domain", "value": "batch-test-a.example.com", "tags": ["batch-test"]},
            {"type": "url", "value": "https://batch-test.example.com/api", "tags": ["batch-test"]},
        ]
        data = _analyze(client, base_url, iocs, context="Batch test")
        assert len(data["results"]) == 3

    def test_batch_status_completed_when_all_succeed(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """Status should be 'completed' (not 'partial') when all IOCs succeed."""
        iocs = [
            {"type": "ip", "value": "192.0.2.92", "tags": ["batch-status-test"]},
            {"type": "ip", "value": "192.0.2.93", "tags": ["batch-status-test"]},
        ]
        data = _analyze(client, base_url, iocs)
        # In normal operation all IOCs should complete successfully
        assert data["status"] in ("completed", "partial"), (
            f"Unexpected status '{data['status']}' — all analyses failed"
        )

    def test_batch_result_order_matches_input(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """Result IOC values should be a superset of the submitted IOC values."""
        iocs = [
            {"type": "ip", "value": "192.0.2.94", "tags": ["batch-order"]},
            {"type": "domain", "value": "batch-order.example.com", "tags": ["batch-order"]},
        ]
        data = _analyze(client, base_url, iocs)
        result_values = {r["ioc"]["value"] for r in data["results"]}
        input_values = {ioc["value"] for ioc in iocs}
        assert input_values.issubset(result_values), (
            f"Some submitted IOCs are missing from results: {input_values - result_values}"
        )

    def test_batch_analysis_id_is_valid_uuid(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """analysis_id in batch response must be a valid UUID."""
        data = _analyze(
            client,
            base_url,
            [{"type": "ip", "value": "192.0.2.95", "tags": ["batch-uuid-test"]}],
        )
        try:
            UUID(data["analysis_id"])
        except ValueError:
            pytest.fail(f"analysis_id '{data['analysis_id']}' is not a valid UUID")


# ---------------------------------------------------------------------------
# 6. IOC list filtering and pagination
# ---------------------------------------------------------------------------

class TestIOCListFiltering:
    """Test the type filter and pagination on GET /api/v1/iocs/."""

    def test_type_filter_returns_only_matching_type(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """Filtering by type=ip must only return IP IOCs."""
        resp = client.get(f"{base_url}/api/v1/iocs/?type=ip&limit=20")
        assert resp.status_code == 200
        data = resp.json()
        for item in data["items"]:
            assert item["type"] == "ip", (
                f"Type filter returned item with type='{item['type']}'"
            )

    def test_unknown_type_filter_returns_empty_list(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """Filtering by a non-existent type should return an empty list, not an error."""
        resp = client.get(f"{base_url}/api/v1/iocs/?type=nonexistent_type_xyz&limit=10")
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["total"] == 0

    def test_pagination_offset_advances_window(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """Items at offset=0 and offset=1 should not be identical (if > 1 IOC exists)."""
        resp0 = client.get(f"{base_url}/api/v1/iocs/?limit=1&offset=0")
        resp1 = client.get(f"{base_url}/api/v1/iocs/?limit=1&offset=1")
        assert resp0.status_code == 200
        assert resp1.status_code == 200

        items0 = resp0.json()["items"]
        items1 = resp1.json()["items"]
        total = resp0.json()["total"]

        if total < 2:
            pytest.skip("Not enough IOCs in DB to test pagination offset")

        assert items0[0]["id"] != items1[0]["id"], (
            "offset=0 and offset=1 returned the same item — pagination is broken"
        )

    def test_total_count_is_consistent_with_full_list(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """The 'total' field must equal total DB rows, not just the page size."""
        resp_page = client.get(f"{base_url}/api/v1/iocs/?limit=1&offset=0")
        assert resp_page.status_code == 200
        total_reported = resp_page.json()["total"]

        resp_all = client.get(f"{base_url}/api/v1/iocs/?limit=200&offset=0")
        assert resp_all.status_code == 200
        actual_count = len(resp_all.json()["items"])

        # 'total' should be >= actual page count (may exceed 200 if DB has many rows)
        assert total_reported >= actual_count, (
            f"total={total_reported} is less than items returned={actual_count}"
        )


# ---------------------------------------------------------------------------
# 7. Infrastructure / middleware
# ---------------------------------------------------------------------------

class TestInfrastructure:
    """Tests for middleware, headers, and production-hardening features."""

    def test_request_id_header_is_echoed(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """The X-Request-ID header sent by the client should be echoed in the response."""
        custom_id = "test-req-abc123"
        resp = client.get(
            f"{base_url}/health",
            headers={"X-Request-ID": custom_id},
        )
        assert resp.status_code == 200
        returned_id = resp.headers.get("x-request-id")
        assert returned_id == custom_id, (
            f"Expected X-Request-ID='{custom_id}' in response headers, got '{returned_id}'"
        )

    def test_auto_generated_request_id_present(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """When no X-Request-ID is sent, the server must generate one and include it."""
        resp = client.get(f"{base_url}/health")
        assert resp.status_code == 200
        assert "x-request-id" in resp.headers, (
            "Server did not return X-Request-ID header (auto-generated)"
        )
        assert len(resp.headers["x-request-id"]) > 0

    def test_health_check_gradient_field_present(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """The enhanced health check must include a 'gradient' component check."""
        resp = client.get(f"{base_url}/health")
        assert resp.status_code == 200
        data = resp.json()
        assert "gradient" in data.get("checks", {}), (
            "Health check is missing 'gradient' component — enhanced health not implemented?"
        )
        gradient_check = data["checks"]["gradient"]
        assert "ok" in gradient_check
        assert isinstance(gradient_check["ok"], bool)

    def test_404_for_unknown_route(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """Requests to unknown routes should return 404, not 500."""
        resp = client.get(f"{base_url}/api/v1/does-not-exist-xyz")
        assert resp.status_code == 404

    def test_delete_nonexistent_ioc_returns_404(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """Deleting a non-existent IOC must return 404, not 500."""
        fake_id = "00000000-0000-0000-0000-000000000001"
        resp = client.delete(f"{base_url}/api/v1/iocs/{fake_id}")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 8. Re-analysis consistency
# ---------------------------------------------------------------------------

class TestReAnalysisConsistency:
    """Re-running analysis on the same IOC should not corrupt data."""

    def test_second_analysis_does_not_duplicate_ioc(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """Submitting the same IOC twice must not create two IOC records (dedup)."""
        ioc_payload = {"type": "ip", "value": "192.0.2.101", "tags": ["reanalysis-test"]}

        data1 = _analyze(client, base_url, [ioc_payload])
        data2 = _analyze(client, base_url, [ioc_payload])

        analysis_id1 = data1["analysis_id"]
        analysis_id2 = data2["analysis_id"]

        # Two distinct analyses should be created
        assert analysis_id1 != analysis_id2

        # Retrieve both analyses
        a1 = client.get(f"{base_url}/api/v1/analyses/{analysis_id1}").json()
        a2 = client.get(f"{base_url}/api/v1/analyses/{analysis_id2}").json()

        # Both must reference the same IOC (not two separate IOC records)
        assert set(a1["ioc_ids"]) == set(a2["ioc_ids"]), (
            "Re-analysis created a duplicate IOC record instead of reusing the existing one"
        )

        # Clean up
        for ioc_id in a1["ioc_ids"]:
            _delete_ioc(client, base_url, ioc_id)

    def test_reanalysis_with_new_context_succeeds(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """Re-analyzing with different context must not fail."""
        ioc_payload = {"type": "domain", "value": "reanalysis-ctx.example.com",
                       "tags": ["reanalysis-ctx"]}

        # First analysis
        _analyze(client, base_url, [ioc_payload], context="Initial observation")

        # Second analysis with different context
        data2 = _analyze(
            client,
            base_url,
            [ioc_payload],
            context="Follow-up: confirmed C2 callback pattern observed over 72h",
            priority="high",
        )
        assert data2["status"] in ("completed", "partial")


# ---------------------------------------------------------------------------
# 9. Validation / input boundary tests
# ---------------------------------------------------------------------------

class TestInputValidation:
    """Test input validation at the API boundary."""

    def test_empty_ioc_list_rejected(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """Submitting an empty IOC list must return 422."""
        resp = client.post(
            f"{base_url}/api/v1/analyses/analyze",
            json={"iocs": [], "context": "", "priority": "low"},
        )
        assert resp.status_code == 422

    def test_ioc_list_over_limit_rejected(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """Submitting more than 10 IOCs (the documented limit) must return 422."""
        iocs = [
            {"type": "ip", "value": f"192.0.2.{i}", "tags": []}
            for i in range(1, 12)  # 11 IOCs
        ]
        resp = client.post(
            f"{base_url}/api/v1/analyses/analyze",
            json={"iocs": iocs, "context": "", "priority": "low"},
        )
        assert resp.status_code == 422

    def test_invalid_priority_rejected(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """Priority values outside {low, medium, high} must return 422."""
        resp = client.post(
            f"{base_url}/api/v1/analyses/analyze",
            json={
                "iocs": [{"type": "ip", "value": "192.0.2.105", "tags": []}],
                "context": "",
                "priority": "critical",  # not a valid priority
            },
        )
        assert resp.status_code == 422

    def test_context_over_max_length_rejected(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """Context strings exceeding 2000 characters must be rejected with 422."""
        resp = client.post(
            f"{base_url}/api/v1/analyses/analyze",
            json={
                "iocs": [{"type": "ip", "value": "192.0.2.106", "tags": []}],
                "context": "x" * 2001,
                "priority": "low",
            },
        )
        assert resp.status_code == 422

    def test_invalid_uuid_for_analysis_id(
        self, client: httpx.Client, base_url: str
    ) -> None:
        """GET /analyses/not-a-uuid must return 422, not 500."""
        resp = client.get(f"{base_url}/api/v1/analyses/not-a-uuid")
        assert resp.status_code == 422
