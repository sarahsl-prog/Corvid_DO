"""Extended tests for the Corvid agent — covers retry logic, tool execution,
mock response path, and the convenience analyze_ioc function.

These tests supplement test_agent.py to push coverage of corvid/agent/agent.py
from ~46% toward 85%+.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from corvid.agent.agent import SYSTEM_PROMPT, CorvidAgent, analyze_ioc
from corvid.agent.guardrails import GuardrailError
from corvid.api.models.analysis import AgentAnalysisOutput


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_valid_response_json(**overrides) -> str:
    """Return a JSON string with a valid AgentAnalysisOutput payload."""
    payload = {
        "summary": "Test summary of the indicator.",
        "severity": 5.0,
        "confidence": 0.6,
        "related_cves": [],
        "mitre_techniques": [],
        "enrichment_findings": {},
        "recommended_actions": ["Monitor the indicator"],
        "related_iocs": [],
    }
    payload.update(overrides)
    return json.dumps(payload)


def _mock_httpx_client(json_responses: list[dict]) -> MagicMock:
    """Build a mock httpx AsyncClient that returns the given JSON payloads."""
    mock_client = MagicMock()
    mock_instance = AsyncMock()
    mock_client.return_value.__aenter__.return_value = mock_instance

    responses = []
    for data in json_responses:
        resp = MagicMock()
        resp.json.return_value = data
        resp.raise_for_status = MagicMock()
        responses.append(resp)

    mock_instance.post.side_effect = responses
    return mock_client


# ---------------------------------------------------------------------------
# _invoke_agent — real API path
# ---------------------------------------------------------------------------


@pytest.mark.phase3
class TestInvokeAgentRealPath:
    """Tests for _invoke_agent when a real (mocked HTTP) API key is present."""

    @pytest.mark.asyncio
    async def test_invoke_agent_no_tool_calls(self, db_session):
        """Agent returns text directly with no tool calls."""
        final_text = _make_valid_response_json()

        api_response = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": final_text,
                        "tool_calls": [],
                    }
                }
            ]
        }

        with patch("corvid.agent.agent.settings") as mock_settings:
            mock_settings.gradient_api_key = "real-test-key"
            mock_settings.gradient_kb_id = ""
            mock_settings.gradient_model = "gradient-large"
            mock_settings.agent_timeout_seconds = 30

            with patch(
                "corvid.agent.agent.httpx.AsyncClient",
                _mock_httpx_client([api_response]),
            ):
                agent = CorvidAgent()
                result = await agent.analyze_ioc("ip", "1.2.3.4", db=db_session)

        assert isinstance(result, AgentAnalysisOutput)
        assert result.severity == 5.0

    @pytest.mark.asyncio
    async def test_invoke_agent_with_tool_calls(self, db_session):
        """Agent makes one tool call then returns final answer."""
        # First response has a tool call
        tool_call_response = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_001",
                                "function": {
                                    "name": "lookup_ioc",
                                    "arguments": json.dumps(
                                        {"ioc_type": "ip", "ioc_value": "1.2.3.4"}
                                    ),
                                },
                            }
                        ],
                    }
                }
            ]
        }
        # Second response is the final text
        final_response = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": _make_valid_response_json(severity=7.0),
                        "tool_calls": [],
                    }
                }
            ]
        }

        with patch("corvid.agent.agent.settings") as mock_settings:
            mock_settings.gradient_api_key = "real-test-key"
            mock_settings.gradient_kb_id = ""
            mock_settings.gradient_model = "gradient-large"
            mock_settings.agent_timeout_seconds = 30

            with patch(
                "corvid.agent.agent.httpx.AsyncClient",
                _mock_httpx_client([tool_call_response, final_response]),
            ):
                # Mock the lookup_ioc tool so we don't hit DB
                with patch("corvid.agent.agent.lookup_ioc", new=AsyncMock(return_value={"found": False})):
                    agent = CorvidAgent()
                    result = await agent.analyze_ioc("ip", "1.2.3.4", db=db_session)

        assert isinstance(result, AgentAnalysisOutput)
        assert result.severity == 7.0

    @pytest.mark.asyncio
    async def test_invoke_agent_unknown_tool_call(self, db_session):
        """Agent calling an unknown tool returns an error in the tool result."""
        tool_call_response = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_unknown",
                                "function": {
                                    "name": "nonexistent_tool",
                                    "arguments": "{}",
                                },
                            }
                        ],
                    }
                }
            ]
        }
        final_response = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": _make_valid_response_json(),
                        "tool_calls": [],
                    }
                }
            ]
        }

        with patch("corvid.agent.agent.settings") as mock_settings:
            mock_settings.gradient_api_key = "real-test-key"
            mock_settings.gradient_kb_id = ""
            mock_settings.gradient_model = "gradient-large"
            mock_settings.agent_timeout_seconds = 30

            with patch(
                "corvid.agent.agent.httpx.AsyncClient",
                _mock_httpx_client([tool_call_response, final_response]),
            ):
                agent = CorvidAgent()
                result = await agent.analyze_ioc("ip", "1.2.3.4", db=db_session)

        assert isinstance(result, AgentAnalysisOutput)


# ---------------------------------------------------------------------------
# Retry logic (lines 162–174)
# ---------------------------------------------------------------------------


@pytest.mark.phase3
class TestRetryLogic:
    """Verify that bad output triggers one retry and the retry result is used."""

    @pytest.mark.asyncio
    async def test_retry_on_bad_output_succeeds(self, db_session):
        """When first output is invalid JSON, agent retries and succeeds."""
        bad_output = "This is not valid JSON at all."
        good_output = _make_valid_response_json(severity=3.0)

        with patch("corvid.agent.agent.settings") as mock_settings:
            mock_settings.gradient_api_key = ""
            mock_settings.gradient_kb_id = ""
            mock_settings.agent_timeout_seconds = 30

            call_count = 0

            async def side_effect(*args, **kwargs):
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return bad_output
                return good_output

            with patch.object(CorvidAgent, "_mock_agent_response", side_effect=side_effect):
                agent = CorvidAgent()
                result = await agent.analyze_ioc("ip", "1.2.3.4", db=db_session)

        assert isinstance(result, AgentAnalysisOutput)
        assert result.severity == 3.0
        assert call_count == 2  # initial + one retry


# ---------------------------------------------------------------------------
# _execute_tool coverage (lines 323–394)
# ---------------------------------------------------------------------------


@pytest.mark.phase3
class TestExecuteTool:
    """Tests for CorvidAgent._execute_tool covering each branch."""

    @pytest.mark.asyncio
    async def test_execute_lookup_ioc_tool(self, db_session):
        """lookup_ioc tool dispatches to lookup_ioc function."""
        with patch("corvid.agent.agent.settings") as mock_settings:
            mock_settings.gradient_api_key = "key"
            mock_settings.gradient_kb_id = ""
            mock_settings.agent_timeout_seconds = 30

            with patch(
                "corvid.agent.agent.lookup_ioc",
                new=AsyncMock(return_value={"found": False, "ioc": None}),
            ) as mock_lookup:
                from corvid.agent.guardrails import AuditLogger

                agent = CorvidAgent()
                audit = AuditLogger("test-trace")
                result = await agent._execute_tool(
                    "lookup_ioc",
                    {"ioc_type": "ip", "ioc_value": "1.2.3.4"},
                    db_session,
                    audit,
                )
                mock_lookup.assert_called_once()
                assert "found" in result

    @pytest.mark.asyncio
    async def test_execute_search_cves_tool(self, db_session):
        """search_cves tool dispatches to search_cves function."""
        with patch("corvid.agent.agent.settings") as mock_settings:
            mock_settings.gradient_api_key = "key"
            mock_settings.gradient_kb_id = ""
            mock_settings.agent_timeout_seconds = 30

            with patch(
                "corvid.agent.agent.search_cves",
                new=AsyncMock(return_value={"local_results": [], "nvd_results": [], "total_found": 0}),
            ) as mock_search:
                from corvid.agent.guardrails import AuditLogger

                agent = CorvidAgent()
                audit = AuditLogger("test-trace")
                result = await agent._execute_tool(
                    "search_cves",
                    {"query": "fortinet", "max_results": 3},
                    db_session,
                    audit,
                )
                mock_search.assert_called_once()
                assert "total_found" in result

    @pytest.mark.asyncio
    async def test_execute_search_knowledge_base_tool(self, db_session):
        """search_knowledge_base tool dispatches to search_knowledge_base function."""
        with patch("corvid.agent.agent.settings") as mock_settings:
            mock_settings.gradient_api_key = "key"
            mock_settings.gradient_kb_id = ""
            mock_settings.agent_timeout_seconds = 30

            with patch(
                "corvid.agent.agent.search_knowledge_base",
                new=AsyncMock(return_value={"documents": [], "total_found": 0}),
            ) as mock_kb:
                from corvid.agent.guardrails import AuditLogger

                agent = CorvidAgent()
                audit = AuditLogger("test-trace")
                result = await agent._execute_tool(
                    "search_knowledge_base",
                    {"query": "ransomware", "top_k": 3},
                    db_session,
                    audit,
                )
                mock_kb.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_lookup_ioc_tool_no_db(self):
        """lookup_ioc with no db session returns an error dict."""
        with patch("corvid.agent.agent.settings") as mock_settings:
            mock_settings.gradient_api_key = "key"
            mock_settings.gradient_kb_id = ""
            mock_settings.agent_timeout_seconds = 30

            from corvid.agent.guardrails import AuditLogger

            agent = CorvidAgent()
            audit = AuditLogger("test-trace")
            result = await agent._execute_tool(
                "lookup_ioc",
                {"ioc_type": "ip", "ioc_value": "1.2.3.4"},
                None,  # no db
                audit,
            )
            assert "error" in result

    @pytest.mark.asyncio
    async def test_execute_search_cves_tool_no_db(self):
        """search_cves with no db session returns an error dict."""
        with patch("corvid.agent.agent.settings") as mock_settings:
            mock_settings.gradient_api_key = "key"
            mock_settings.gradient_kb_id = ""
            mock_settings.agent_timeout_seconds = 30

            from corvid.agent.guardrails import AuditLogger

            agent = CorvidAgent()
            audit = AuditLogger("test-trace")
            result = await agent._execute_tool(
                "search_cves",
                {"query": "test"},
                None,
                audit,
            )
            assert "error" in result

    @pytest.mark.asyncio
    async def test_execute_enrich_ioc_external_tool_no_db(self):
        """enrich_ioc_external with no db returns an error dict."""
        with patch("corvid.agent.agent.settings") as mock_settings:
            mock_settings.gradient_api_key = "key"
            mock_settings.gradient_kb_id = ""
            mock_settings.agent_timeout_seconds = 30

            from corvid.agent.guardrails import AuditLogger

            agent = CorvidAgent()
            audit = AuditLogger("test-trace")
            result = await agent._execute_tool(
                "enrich_ioc_external",
                {"ioc_type": "ip", "ioc_value": "1.2.3.4"},
                None,
                audit,
            )
            assert "error" in result

    @pytest.mark.asyncio
    async def test_execute_enrich_ioc_external_tool_with_db(self, db_session):
        """enrich_ioc_external with db creates IOC if needed and calls enrichment."""
        with patch("corvid.agent.agent.settings") as mock_settings:
            mock_settings.gradient_api_key = "key"
            mock_settings.gradient_kb_id = ""
            mock_settings.agent_timeout_seconds = 30

            mock_enrich_result = {
                "success": True,
                "enrichments": [],
                "total_sources": 1,
                "successful_sources": 1,
                "message": "ok",
            }

            with patch(
                "corvid.agent.agent.enrich_ioc_external",
                new=AsyncMock(return_value=mock_enrich_result),
            ):
                from corvid.agent.guardrails import AuditLogger

                agent = CorvidAgent()
                audit = AuditLogger("test-trace")
                result = await agent._execute_tool(
                    "enrich_ioc_external",
                    {"ioc_type": "ip", "ioc_value": "192.0.2.1"},
                    db_session,
                    audit,
                )
                assert result["success"] is True

    @pytest.mark.asyncio
    async def test_execute_tool_exception_returns_error(self, db_session):
        """If a tool raises an exception, the result contains an error key."""
        with patch("corvid.agent.agent.settings") as mock_settings:
            mock_settings.gradient_api_key = "key"
            mock_settings.gradient_kb_id = ""
            mock_settings.agent_timeout_seconds = 30

            with patch(
                "corvid.agent.agent.search_knowledge_base",
                new=AsyncMock(side_effect=RuntimeError("boom")),
            ):
                from corvid.agent.guardrails import AuditLogger

                agent = CorvidAgent()
                audit = AuditLogger("test-trace")
                result = await agent._execute_tool(
                    "search_knowledge_base",
                    {"query": "test"},
                    db_session,
                    audit,
                )
                assert "error" in result
                assert "boom" in result["error"]


# ---------------------------------------------------------------------------
# _mock_agent_response (lines 406–444)
# ---------------------------------------------------------------------------


@pytest.mark.phase3
class TestMockAgentResponse:
    """Tests for the fallback mock agent response path."""

    @pytest.mark.asyncio
    async def test_mock_response_returns_valid_json(self, db_session):
        """Mock agent response returns JSON parseable as AgentAnalysisOutput."""
        from corvid.agent.guardrails import AuditLogger
        from corvid.agent.agent import analyze_ioc as analyze_conv

        with patch("corvid.agent.agent.settings") as mock_settings:
            mock_settings.gradient_api_key = ""
            mock_settings.gradient_kb_id = ""
            mock_settings.gradient_model = "gradient-large"
            mock_settings.agent_timeout_seconds = 30

            # Also mock enrich_ioc_external so we don't hit real network
            mock_enrich = {
                "success": False,
                "enrichments": [],
                "total_sources": 0,
                "successful_sources": 0,
                "message": "no providers",
            }

            with patch(
                "corvid.agent.agent.enrich_ioc_external",
                new=AsyncMock(return_value=mock_enrich),
            ):
                agent = CorvidAgent()
                audit = AuditLogger("mock-test")
                raw = await agent._mock_agent_response(
                    "Type: ip\nValue: 10.0.0.1\n", db_session, audit
                )

        result_data = json.loads(raw)
        assert "summary" in result_data
        assert "severity" in result_data
        assert "confidence" in result_data

    @pytest.mark.asyncio
    async def test_mock_response_extracts_ioc_from_message(self):
        """Mock response parses IOC type/value from the user message."""
        with patch("corvid.agent.agent.settings") as mock_settings:
            mock_settings.gradient_api_key = ""
            mock_settings.gradient_kb_id = ""
            mock_settings.gradient_model = "gradient-large"
            mock_settings.agent_timeout_seconds = 30

            mock_enrich = {
                "success": True,
                "enrichments": [{"source": "urlhaus", "success": True, "summary": "clean"}],
                "total_sources": 1,
                "successful_sources": 1,
                "message": "ok",
            }

            with patch(
                "corvid.agent.agent.enrich_ioc_external",
                new=AsyncMock(return_value=mock_enrich),
            ):
                from corvid.agent.guardrails import AuditLogger

                agent = CorvidAgent()
                audit = AuditLogger("mock-test")
                message = "Type: domain\nValue: evil.example.com\nPlease investigate."
                raw = await agent._mock_agent_response(message, None, audit)

        result_data = json.loads(raw)
        assert "domain" in result_data["summary"] or "evil.example.com" in result_data["summary"]


# ---------------------------------------------------------------------------
# Convenience function analyze_ioc (lines 467–468)
# ---------------------------------------------------------------------------


@pytest.mark.phase3
class TestAnalyzeIOCConvenience:
    """Tests for the module-level analyze_ioc convenience function."""

    @pytest.mark.asyncio
    async def test_analyze_ioc_function_returns_output(self, db_session):
        """analyze_ioc() convenience wrapper returns AgentAnalysisOutput."""
        mock_output = _make_valid_response_json(severity=4.0)

        with patch("corvid.agent.agent.settings") as mock_settings:
            mock_settings.gradient_api_key = ""
            mock_settings.gradient_kb_id = ""
            mock_settings.gradient_model = "gradient-large"
            mock_settings.agent_timeout_seconds = 30

            with patch(
                "corvid.agent.agent.enrich_ioc_external",
                new=AsyncMock(
                    return_value={
                        "success": False,
                        "enrichments": [],
                        "total_sources": 0,
                        "successful_sources": 0,
                        "message": "no providers",
                    }
                ),
            ):
                result = await analyze_ioc("ip", "10.10.10.10", db=db_session)

        assert isinstance(result, AgentAnalysisOutput)
