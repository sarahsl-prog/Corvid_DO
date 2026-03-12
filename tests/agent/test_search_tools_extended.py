"""Extended tests for agent search tools.

Covers:
- corvid/agent/tools/search_cves.py:
  - Local DB CVE ID path (_search_nvd)
  - NVD API search (keyword + CVE ID)
  - NVD HTTP error handling
  - get_cve_details (found, not found, error)

- corvid/agent/tools/search_kb.py:
  - search_knowledge_base with KB configured (success + HTTPError)
  - doc_types filter
  - _truncate_content
  - search_mitre_techniques
  - search_cve_advisories (with and without KEV)
  - get_kev_status (found and not found)
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from corvid.agent.tools.search_cves import _search_nvd, get_cve_details, search_cves
from corvid.agent.tools.search_kb import (
    _truncate_content,
    get_kev_status,
    search_cve_advisories,
    search_knowledge_base,
    search_mitre_techniques,
)
from corvid.db.models import CVEReference


# ---------------------------------------------------------------------------
# search_cves — local DB CVE ID path
# ---------------------------------------------------------------------------


@pytest.mark.phase3
class TestSearchCVESLocalDB:
    """Tests for the local-DB search path in search_cves."""

    @pytest.mark.asyncio
    async def test_cve_id_query_uses_exact_match(self, db_session):
        """When query is a CVE ID, uses exact match in local DB."""
        # Insert a CVEReference so the exact-match path returns something
        cve_ref = CVEReference(
            cve_id="CVE-2024-21762",
            description="Test FortiOS vulnerability",
            cvss_score=9.8,
        )
        db_session.add(cve_ref)
        await db_session.flush()

        with patch("corvid.agent.tools.search_cves._search_nvd", new=AsyncMock(return_value=[])):
            result = await search_cves(db_session, "CVE-2024-21762", max_results=5)

        assert result["total_found"] >= 1
        assert any(r["cve_id"] == "CVE-2024-21762" for r in result["local_results"])

    @pytest.mark.asyncio
    async def test_keyword_query_uses_like_search(self, db_session):
        """Non-CVE-ID query performs ILIKE search on description."""
        cve_ref = CVEReference(
            cve_id="CVE-2024-88888",
            description="Apache Log4j remote code execution",
            cvss_score=10.0,
        )
        db_session.add(cve_ref)
        await db_session.flush()

        with patch("corvid.agent.tools.search_cves._search_nvd", new=AsyncMock(return_value=[])):
            result = await search_cves(db_session, "log4j", max_results=5)

        assert any("CVE-2024-88888" in r["cve_id"] for r in result["local_results"])

    @pytest.mark.asyncio
    async def test_no_results_returns_zero(self, db_session):
        """Returns zero total_found when no matches exist."""
        with patch("corvid.agent.tools.search_cves._search_nvd", new=AsyncMock(return_value=[])):
            result = await search_cves(db_session, "nonexistent_product_xyz", max_results=5)

        assert result["total_found"] == 0
        assert "No CVEs found" in result["message"]


# ---------------------------------------------------------------------------
# _search_nvd — NVD API search
# ---------------------------------------------------------------------------


@pytest.mark.phase3
class TestSearchNVD:
    """Tests for _search_nvd (NVD API wrapper)."""

    @pytest.mark.asyncio
    async def test_keyword_search_returns_results(self):
        """Keyword search hits NVD and returns parsed CVE list."""
        mock_resp_data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-21762",
                        "descriptions": [{"lang": "en", "value": "FortiOS vuln"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseScore": 9.8}}
                            ]
                        },
                    }
                }
            ]
        }

        mock_client = MagicMock()
        mock_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_instance

        resp = MagicMock()
        resp.json.return_value = mock_resp_data
        resp.raise_for_status = MagicMock()
        mock_instance.get.return_value = resp

        with patch("corvid.agent.tools.search_cves.httpx.AsyncClient", mock_client):
            results = await _search_nvd("fortios", 5)

        assert len(results) == 1
        assert results[0]["cve_id"] == "CVE-2024-21762"
        assert results[0]["source"] == "nvd_api"

    @pytest.mark.asyncio
    async def test_cve_id_search_uses_cveId_param(self):
        """CVE ID queries use the cveId parameter."""
        mock_client = MagicMock()
        mock_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_instance

        resp = MagicMock()
        resp.json.return_value = {"vulnerabilities": []}
        resp.raise_for_status = MagicMock()
        mock_instance.get.return_value = resp

        with patch("corvid.agent.tools.search_cves.httpx.AsyncClient", mock_client):
            await _search_nvd("CVE-2024-21762", 5)

        call_kwargs = mock_instance.get.call_args[1]
        assert "cveId" in call_kwargs.get("params", {})

    @pytest.mark.asyncio
    async def test_http_error_returns_empty_list(self):
        """HTTP errors return an empty list rather than raising."""
        import httpx

        mock_client = MagicMock()
        mock_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_instance
        mock_instance.get.side_effect = httpx.HTTPError("timeout")

        with patch("corvid.agent.tools.search_cves.httpx.AsyncClient", mock_client):
            results = await _search_nvd("fortios", 5)

        assert results == []

    @pytest.mark.asyncio
    async def test_nvd_api_key_added_when_configured(self):
        """When nvd_api_key is set, it is included in request headers."""
        mock_client = MagicMock()
        mock_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_instance

        resp = MagicMock()
        resp.json.return_value = {"vulnerabilities": []}
        resp.raise_for_status = MagicMock()
        mock_instance.get.return_value = resp

        with patch("corvid.agent.tools.search_cves.settings") as mock_settings:
            mock_settings.nvd_api_key = "test-nvd-key"

            with patch("corvid.agent.tools.search_cves.httpx.AsyncClient", mock_client):
                await _search_nvd("test", 5)

        call_kwargs = mock_instance.get.call_args[1]
        assert call_kwargs.get("headers", {}).get("apiKey") == "test-nvd-key"


# ---------------------------------------------------------------------------
# get_cve_details
# ---------------------------------------------------------------------------


@pytest.mark.phase3
class TestGetCVEDetails:
    """Tests for get_cve_details full CVE info fetch."""

    @pytest.mark.asyncio
    async def test_returns_full_details(self):
        """Returns dict with all expected keys when CVE exists."""
        mock_data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-21762",
                        "descriptions": [{"lang": "en", "value": "FortiOS OOB write."}],
                        "published": "2024-02-09T00:00:00.000",
                        "lastModified": "2024-02-15T00:00:00.000",
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 9.8,
                                        "baseSeverity": "CRITICAL",
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    }
                                }
                            ]
                        },
                        "references": [{"url": "https://fortiguard.com/advisory"}],
                    }
                }
            ]
        }

        mock_client = MagicMock()
        mock_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_instance

        resp = MagicMock()
        resp.json.return_value = mock_data
        resp.raise_for_status = MagicMock()
        mock_instance.get.return_value = resp

        with patch("corvid.agent.tools.search_cves.httpx.AsyncClient", mock_client):
            details = await get_cve_details("CVE-2024-21762")

        assert details is not None
        assert details["cve_id"] == "CVE-2024-21762"
        assert details["cvss"]["base_score"] == 9.8
        assert len(details["references"]) == 1

    @pytest.mark.asyncio
    async def test_not_found_returns_none(self):
        """Returns None when CVE is not in NVD response."""
        mock_client = MagicMock()
        mock_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_instance

        resp = MagicMock()
        resp.json.return_value = {"vulnerabilities": []}
        resp.raise_for_status = MagicMock()
        mock_instance.get.return_value = resp

        with patch("corvid.agent.tools.search_cves.httpx.AsyncClient", mock_client):
            details = await get_cve_details("CVE-9999-99999")

        assert details is None

    @pytest.mark.asyncio
    async def test_http_error_returns_none(self):
        """Returns None on HTTP error."""
        import httpx

        mock_client = MagicMock()
        mock_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_instance
        mock_instance.get.side_effect = httpx.HTTPError("no connection")

        with patch("corvid.agent.tools.search_cves.httpx.AsyncClient", mock_client):
            details = await get_cve_details("CVE-2024-21762")

        assert details is None


# ---------------------------------------------------------------------------
# search_knowledge_base (configured KB path)
# ---------------------------------------------------------------------------


@pytest.mark.phase3
class TestSearchKnowledgeBase:
    """Tests for search_knowledge_base when KB is configured."""

    def _mock_kb_response(self, results: list) -> MagicMock:
        mock_client = MagicMock()
        mock_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_instance

        resp = MagicMock()
        resp.json.return_value = {"results": results}
        resp.raise_for_status = MagicMock()
        mock_instance.post.return_value = resp

        return mock_client

    @pytest.mark.asyncio
    async def test_returns_documents_when_configured(self):
        """Returns found documents when KB is properly configured."""
        fake_results = [
            {
                "id": "CVE-2024-21762",
                "content": "FortiOS vulnerability",
                "score": 0.95,
                "metadata": {"title": "CVE-2024-21762", "doc_type": "cve"},
            }
        ]
        mock_client = self._mock_kb_response(fake_results)

        with patch("corvid.agent.tools.search_kb.settings") as mock_settings:
            mock_settings.gradient_api_key = "real-key"
            mock_settings.gradient_kb_id = "real-kb-id"
            mock_settings.gradient_kb_url = ""

            with patch("corvid.agent.tools.search_kb.httpx.AsyncClient", mock_client):
                result = await search_knowledge_base("fortios vulnerability", top_k=5)

        assert result["total_found"] == 1
        assert result["documents"][0]["id"] == "CVE-2024-21762"
        assert "Found" in result["message"]

    @pytest.mark.asyncio
    async def test_empty_results_message(self):
        """Returns 'No documents found' message when KB has no matches."""
        mock_client = self._mock_kb_response([])

        with patch("corvid.agent.tools.search_kb.settings") as mock_settings:
            mock_settings.gradient_api_key = "real-key"
            mock_settings.gradient_kb_id = "real-kb-id"
            mock_settings.gradient_kb_url = ""

            with patch("corvid.agent.tools.search_kb.httpx.AsyncClient", mock_client):
                result = await search_knowledge_base("obscure query", top_k=5)

        assert result["total_found"] == 0
        assert "No documents found" in result["message"]

    @pytest.mark.asyncio
    async def test_doc_types_filter_included_in_request(self):
        """doc_types filter is included in the KB request body."""
        mock_client = self._mock_kb_response([])

        with patch("corvid.agent.tools.search_kb.settings") as mock_settings:
            mock_settings.gradient_api_key = "real-key"
            mock_settings.gradient_kb_id = "real-kb-id"
            mock_settings.gradient_kb_url = ""

            with patch("corvid.agent.tools.search_kb.httpx.AsyncClient", mock_client):
                await search_knowledge_base("ransomware", top_k=3, doc_types=["cve", "kev"])

        call_kwargs = mock_client.return_value.__aenter__.return_value.post.call_args[1]
        assert "filters" in call_kwargs.get("json", {})

    @pytest.mark.asyncio
    async def test_http_error_returns_error_message(self):
        """HTTP errors return an error message instead of raising."""
        import httpx

        mock_client = MagicMock()
        mock_instance = AsyncMock()
        mock_client.return_value.__aenter__.return_value = mock_instance
        mock_instance.post.side_effect = httpx.HTTPError("connection reset")

        with patch("corvid.agent.tools.search_kb.settings") as mock_settings:
            mock_settings.gradient_api_key = "real-key"
            mock_settings.gradient_kb_id = "real-kb-id"
            mock_settings.gradient_kb_url = ""

            with patch("corvid.agent.tools.search_kb.httpx.AsyncClient", mock_client):
                result = await search_knowledge_base("test query")

        assert result["total_found"] == 0
        assert "failed" in result["message"].lower() or "error" in result["message"].lower() or "search failed" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_uses_custom_kb_url(self):
        """Uses custom gradient_kb_url when set."""
        mock_client = self._mock_kb_response([])

        with patch("corvid.agent.tools.search_kb.settings") as mock_settings:
            mock_settings.gradient_api_key = "real-key"
            mock_settings.gradient_kb_id = "real-kb-id"
            mock_settings.gradient_kb_url = "https://custom.kb.example.com/v1/knowledge-bases/my-kb"

            with patch("corvid.agent.tools.search_kb.httpx.AsyncClient", mock_client):
                await search_knowledge_base("test")

        call_url = mock_client.return_value.__aenter__.return_value.post.call_args[0][0]
        assert "custom.kb.example.com" in call_url


# ---------------------------------------------------------------------------
# _truncate_content
# ---------------------------------------------------------------------------


@pytest.mark.phase3
class TestTruncateContent:
    """Tests for the _truncate_content helper."""

    def test_short_content_unchanged(self):
        assert _truncate_content("hello world", 100) == "hello world"

    def test_long_content_truncated_with_ellipsis(self):
        long = "A" * 600
        result = _truncate_content(long, 500)
        assert len(result) == 500
        assert result.endswith("...")

    def test_exact_length_unchanged(self):
        content = "X" * 500
        assert _truncate_content(content, 500) == content


# ---------------------------------------------------------------------------
# search_mitre_techniques
# ---------------------------------------------------------------------------


@pytest.mark.phase3
class TestSearchMITRETechniques:
    """Tests for the search_mitre_techniques wrapper."""

    @pytest.mark.asyncio
    async def test_filters_to_mitre_doc_types(self):
        """Passes doc_types=['mitre_technique'] to search_knowledge_base."""
        with patch(
            "corvid.agent.tools.search_kb.search_knowledge_base",
            new=AsyncMock(return_value={"documents": [], "total_found": 0, "message": "ok"}),
        ) as mock_search:
            await search_mitre_techniques("command and control", top_k=3)

        mock_search.assert_called_once_with("command and control", 3, doc_types=["mitre_technique"])


# ---------------------------------------------------------------------------
# search_cve_advisories
# ---------------------------------------------------------------------------


@pytest.mark.phase3
class TestSearchCVEAdvisories:
    """Tests for the search_cve_advisories wrapper."""

    @pytest.mark.asyncio
    async def test_includes_kev_by_default(self):
        """doc_types includes 'kev' when include_kev=True (default)."""
        with patch(
            "corvid.agent.tools.search_kb.search_knowledge_base",
            new=AsyncMock(return_value={"documents": [], "total_found": 0, "message": "ok"}),
        ) as mock_search:
            await search_cve_advisories("log4j", top_k=5, include_kev=True)

        call_args = mock_search.call_args[1]
        assert "kev" in call_args.get("doc_types", [])
        assert "cve" in call_args.get("doc_types", [])

    @pytest.mark.asyncio
    async def test_excludes_kev_when_false(self):
        """doc_types does NOT include 'kev' when include_kev=False."""
        with patch(
            "corvid.agent.tools.search_kb.search_knowledge_base",
            new=AsyncMock(return_value={"documents": [], "total_found": 0, "message": "ok"}),
        ) as mock_search:
            await search_cve_advisories("log4j", top_k=5, include_kev=False)

        call_args = mock_search.call_args[1]
        assert "kev" not in call_args.get("doc_types", [])


# ---------------------------------------------------------------------------
# get_kev_status
# ---------------------------------------------------------------------------


@pytest.mark.phase3
class TestGetKEVStatus:
    """Tests for get_kev_status KEV catalog check."""

    @pytest.mark.asyncio
    async def test_cve_in_kev(self):
        """Returns is_kev=True when CVE is found in KEV documents."""
        kev_doc = {
            "id": "KEV-CVE-2024-21762",
            "title": "KEV: CVE-2024-21762",
            "doc_type": "kev",
            "content_snippet": "Known exploited.",
            "relevance_score": 0.99,
            "metadata": {},
        }

        with patch(
            "corvid.agent.tools.search_kb.search_knowledge_base",
            new=AsyncMock(
                return_value={
                    "documents": [kev_doc],
                    "total_found": 1,
                    "message": "Found 1 kev",
                }
            ),
        ):
            result = await get_kev_status("CVE-2024-21762")

        assert result["is_kev"] is True
        assert result["cve_id"] == "CVE-2024-21762"

    @pytest.mark.asyncio
    async def test_cve_not_in_kev(self):
        """Returns is_kev=False when CVE is not in KEV catalog."""
        with patch(
            "corvid.agent.tools.search_kb.search_knowledge_base",
            new=AsyncMock(
                return_value={
                    "documents": [],
                    "total_found": 0,
                    "message": "No documents",
                }
            ),
        ):
            result = await get_kev_status("CVE-2099-99999")

        assert result["is_kev"] is False
        assert "NOT" in result["message"]

    @pytest.mark.asyncio
    async def test_cve_not_matched_on_partial_id(self):
        """Returns is_kev=False when the returned document ID doesn't match."""
        non_matching_doc = {
            "id": "KEV-CVE-2024-11111",  # Different CVE
            "title": "Other KEV",
            "doc_type": "kev",
            "content_snippet": "something else",
            "relevance_score": 0.5,
            "metadata": {},
        }

        with patch(
            "corvid.agent.tools.search_kb.search_knowledge_base",
            new=AsyncMock(
                return_value={
                    "documents": [non_matching_doc],
                    "total_found": 1,
                    "message": "Found",
                }
            ),
        ):
            result = await get_kev_status("CVE-2024-99999")

        assert result["is_kev"] is False
