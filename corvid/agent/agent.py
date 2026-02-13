"""Gradient agent configuration for Corvid threat intelligence analysis.

Initializes the Gradient agent client, registers tools, and handles
agent invocation for IOC analysis.
"""

import json
import uuid
from typing import Any

import httpx
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from corvid.agent.guardrails import (
    AuditLogger,
    GuardrailError,
    build_retry_prompt,
    sanitize_context,
    validate_agent_output,
    validate_ioc_input,
)
from corvid.agent.tools import (
    TOOL_SCHEMAS,
    enrich_ioc_external,
    lookup_ioc,
    search_cves,
    search_knowledge_base,
)
from corvid.api.models.analysis import AgentAnalysisOutput
from corvid.config import settings

# System prompt for the Corvid threat intelligence analyst
SYSTEM_PROMPT = """You are Corvid, a cybersecurity threat intelligence analyst.
Given an IOC (Indicator of Compromise), use your tools to gather all available
intelligence, then produce a structured analysis.

## Analysis Process

1. First, use `lookup_ioc` to check if we have existing data on this indicator
2. If limited data, use `enrich_ioc_external` to fetch fresh threat intel
3. Use `search_knowledge_base` to find related CVEs, MITRE techniques, and advisories
4. Use `search_cves` if you need specific CVE details

## Your Analysis MUST Include

1. **Summary**: What is known about this IOC (2-3 sentences, be specific)
2. **Severity**: Score from 0.0-10.0 with brief justification
   - 0-3: Low/benign - no clear malicious indicators
   - 4-6: Medium - suspicious activity or associations
   - 7-8: High - confirmed malicious activity or known threat
   - 9-10: Critical - active exploitation, ransomware, APT
3. **Confidence**: Your confidence level (0.0-1.0) based on data quality
   - 0.0-0.3: Limited data, mostly inference
   - 0.4-0.6: Some corroborating evidence
   - 0.7-0.8: Multiple reliable sources agree
   - 0.9-1.0: Definitive evidence from authoritative sources
4. **Related CVEs**: List CVE IDs found (format: CVE-YYYY-NNNNN)
5. **MITRE ATT&CK**: Map to technique IDs (format: TNNNN or TNNNN.NNN)
6. **Enrichment Findings**: Key findings from each source consulted
7. **Recommended Actions**: Specific, actionable steps for the SOC team
8. **Related IOCs**: Any associated indicators discovered

## Response Format

Always cite which tool/source provided each piece of data.
If data is limited, say so clearly rather than speculating.

Respond ONLY with valid JSON matching this exact schema:
```json
{
  "summary": "string - 2-3 sentence summary",
  "severity": 0.0,
  "confidence": 0.0,
  "related_cves": ["CVE-YYYY-NNNNN"],
  "mitre_techniques": ["TNNNN.NNN"],
  "enrichment_findings": {"source_name": "key finding"},
  "recommended_actions": ["action 1", "action 2"],
  "related_iocs": ["indicator"]
}
```"""


class CorvidAgent:
    """Gradient-powered threat intelligence analyst agent."""

    def __init__(
        self,
        gradient_api_key: str | None = None,
        kb_id: str | None = None,
        model: str | None = None,
    ):
        """Initialize the Corvid agent.

        Args:
            gradient_api_key: Gradient API key (defaults to settings).
            kb_id: Knowledge base ID (defaults to settings).
            model: Gradient model name (defaults to settings).
        """
        self.api_key = gradient_api_key or settings.gradient_api_key
        self.kb_id = kb_id or settings.gradient_kb_id
        self.model = model or settings.gradient_model
        self.timeout = settings.agent_timeout_seconds

        if not self.api_key:
            logger.warning("Gradient API key not configured")

        # Register tools
        self.tools = TOOL_SCHEMAS
        logger.info(
            "CorvidAgent initialized with {} tools: {}",
            len(self.tools),
            [t["name"] for t in self.tools],
        )

    async def analyze_ioc(
        self,
        ioc_type: str,
        ioc_value: str,
        context: str = "",
        db: AsyncSession | None = None,
    ) -> AgentAnalysisOutput:
        """Analyze an IOC using the Gradient agent.

        Args:
            ioc_type: The IOC type (e.g., "ip", "domain").
            ioc_value: The IOC value to analyze.
            context: Optional context about where/how the IOC was observed.
            db: Optional database session for tool calls.

        Returns:
            AgentAnalysisOutput with the analysis results.

        Raises:
            GuardrailError: If input/output validation fails.
            Exception: If the agent fails to produce a valid analysis.
        """
        trace_id = str(uuid.uuid4())[:8]
        audit = AuditLogger(trace_id)

        try:
            # Validate inputs
            ioc_type, ioc_value = validate_ioc_input(ioc_type, ioc_value)
            context = sanitize_context(context)
            audit.log_input(ioc_type, ioc_value, context)

            # Build user message
            user_message = self._build_user_message(ioc_type, ioc_value, context)

            # Invoke agent (with tool calling loop)
            raw_output = await self._invoke_agent(
                user_message=user_message,
                db=db,
                audit=audit,
            )

            # Validate output
            try:
                result = validate_agent_output(raw_output)
                audit.log_output(result, success=True)
                return result
            except GuardrailError as e:
                # Retry once with error feedback
                logger.warning("Agent output validation failed, retrying: {}", e)
                retry_prompt = build_retry_prompt(e, raw_output)
                raw_output = await self._invoke_agent(
                    user_message=retry_prompt,
                    db=db,
                    audit=audit,
                    is_retry=True,
                )
                result = validate_agent_output(raw_output)
                audit.log_output(result, success=True)
                return result

        except Exception as e:
            audit.log_error(e)
            raise

    def _build_user_message(
        self,
        ioc_type: str,
        ioc_value: str,
        context: str,
    ) -> str:
        """Build the user message for the agent.

        Args:
            ioc_type: The IOC type.
            ioc_value: The IOC value.
            context: Optional context string.

        Returns:
            Formatted user message.
        """
        message = f"""Analyze this Indicator of Compromise:

Type: {ioc_type}
Value: {ioc_value}"""

        if context:
            message += f"""

Context provided by analyst:
{context}"""

        message += """

Please investigate this IOC using your available tools and provide a complete analysis."""

        return message

    async def _invoke_agent(
        self,
        user_message: str,
        db: AsyncSession | None,
        audit: AuditLogger,
        is_retry: bool = False,
    ) -> str:
        """Invoke the Gradient agent with tool calling.

        Args:
            user_message: The message to send to the agent.
            db: Database session for tool calls.
            audit: Audit logger for tracing.
            is_retry: Whether this is a retry attempt.

        Returns:
            The agent's final text response.
        """
        if not self.api_key:
            # Fallback for testing without Gradient API
            logger.warning("No Gradient API key, using mock response")
            return await self._mock_agent_response(user_message, db, audit)

        # Gradient API endpoint
        gradient_url = "https://api.gradient.ai/v1/chat/completions"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ]

        max_turns = 1 if is_retry else 10  # Limit tool calling turns

        async with httpx.AsyncClient(timeout=float(self.timeout)) as client:
            for turn in range(max_turns):
                request_body = {
                    "model": self.model,
                    "messages": messages,
                    "tools": [{"type": "function", "function": t} for t in self.tools],
                    "tool_choice": "auto" if turn < max_turns - 1 else "none",
                }

                try:
                    resp = await client.post(
                        gradient_url,
                        json=request_body,
                        headers=headers,
                    )
                    resp.raise_for_status()
                    data = resp.json()
                except httpx.HTTPError as e:
                    logger.error("Gradient API call failed: {}", e)
                    raise RuntimeError(f"Gradient API error: {e}")

                choice = data.get("choices", [{}])[0]
                message = choice.get("message", {})

                # Check for tool calls
                tool_calls = message.get("tool_calls", [])
                if tool_calls:
                    # Process tool calls
                    messages.append(message)  # Add assistant message with tool calls

                    for tool_call in tool_calls:
                        function = tool_call.get("function", {})
                        tool_name = function.get("name", "")
                        tool_args = json.loads(function.get("arguments", "{}"))

                        # Execute tool
                        tool_result = await self._execute_tool(tool_name, tool_args, db, audit)

                        # Add tool result to messages
                        messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": tool_call.get("id"),
                                "content": json.dumps(tool_result),
                            }
                        )
                else:
                    # No tool calls, return the response
                    return message.get("content", "")

        # Max turns reached
        logger.warning("Agent reached max tool calling turns")
        return messages[-1].get("content", "") if messages else ""

    async def _execute_tool(
        self,
        tool_name: str,
        args: dict[str, Any],
        db: AsyncSession | None,
        audit: AuditLogger,
    ) -> dict[str, Any]:
        """Execute an agent tool call.

        Args:
            tool_name: Name of the tool to execute.
            args: Tool arguments.
            db: Database session.
            audit: Audit logger.

        Returns:
            Tool execution result.
        """
        logger.debug("Executing tool: {}({})", tool_name, args)

        try:
            if tool_name == "lookup_ioc":
                if db is None:
                    result = {"error": "Database session not available"}
                else:
                    result = await lookup_ioc(
                        db=db,
                        ioc_type=args.get("ioc_type", ""),
                        ioc_value=args.get("ioc_value", ""),
                    )
            elif tool_name == "search_cves":
                if db is None:
                    result = {"error": "Database session not available"}
                else:
                    result = await search_cves(
                        db=db,
                        query=args.get("query", ""),
                        max_results=args.get("max_results", 5),
                    )
            elif tool_name == "enrich_ioc_external":
                result = await enrich_ioc_external(
                    ioc_type=args.get("ioc_type", ""),
                    ioc_value=args.get("ioc_value", ""),
                    sources=args.get("sources"),
                    db=db,
                )
            elif tool_name == "search_knowledge_base":
                result = await search_knowledge_base(
                    query=args.get("query", ""),
                    top_k=args.get("top_k", 5),
                    doc_types=args.get("doc_types"),
                )
            else:
                result = {"error": f"Unknown tool: {tool_name}"}

            audit.log_tool_call(tool_name, args, result)
            return result

        except Exception as e:
            logger.error("Tool {} failed: {}", tool_name, e)
            audit.log_tool_call(tool_name, args, {"error": str(e)})
            return {"error": str(e)}

    async def _mock_agent_response(
        self,
        user_message: str,
        db: AsyncSession | None,
        audit: AuditLogger,
    ) -> str:
        """Generate a mock response when Gradient API is unavailable.

        Used for testing without API credentials.
        """
        logger.info("Generating mock agent response")

        # Extract IOC info from user message
        ioc_type = "unknown"
        ioc_value = "unknown"
        if "Type:" in user_message:
            lines = user_message.split("\n")
            for line in lines:
                if line.startswith("Type:"):
                    ioc_type = line.split(":")[1].strip()
                elif line.startswith("Value:"):
                    ioc_value = line.split(":")[1].strip()

        # Try to get some real data via tools
        enrichment_result = await enrich_ioc_external(ioc_type, ioc_value)

        # Build mock response
        mock_output = {
            "summary": f"Analysis of {ioc_type} indicator {ioc_value}. "
            f"External enrichment returned {enrichment_result.get('successful_sources', 0)} source(s). "
            "Further investigation recommended.",
            "severity": 5.0,
            "confidence": 0.4,
            "related_cves": [],
            "mitre_techniques": [],
            "enrichment_findings": {
                src["source"]: src.get("summary", "No summary")
                for src in enrichment_result.get("enrichments", [])
                if src.get("success")
            },
            "recommended_actions": [
                "Monitor network traffic for this indicator",
                "Check if indicator appears in other log sources",
                "Consider blocking if confirmed malicious",
            ],
            "related_iocs": [],
        }

        return json.dumps(mock_output)


# Convenience function for one-off analysis
async def analyze_ioc(
    ioc_type: str,
    ioc_value: str,
    context: str = "",
    db: AsyncSession | None = None,
) -> AgentAnalysisOutput:
    """Analyze an IOC using the default Corvid agent.

    Convenience function that creates an agent instance and runs analysis.

    Args:
        ioc_type: The IOC type.
        ioc_value: The IOC value.
        context: Optional context.
        db: Optional database session.

    Returns:
        AgentAnalysisOutput with analysis results.
    """
    agent = CorvidAgent()
    return await agent.analyze_ioc(ioc_type, ioc_value, context, db)
