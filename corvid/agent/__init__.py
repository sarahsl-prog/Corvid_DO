"""Corvid Gradient agent for threat intelligence analysis.

The agent uses Gradient AI with tool-calling to analyze IOCs,
leveraging the knowledge base and external threat intel sources.
"""

from corvid.agent.agent import (
    SYSTEM_PROMPT,
    CorvidAgent,
    analyze_ioc,
)
from corvid.agent.guardrails import (
    AuditLogger,
    GuardrailError,
    sanitize_context,
    validate_agent_output,
    validate_ioc_input,
)

__all__ = [
    # Agent
    "CorvidAgent",
    "SYSTEM_PROMPT",
    "analyze_ioc",
    # Guardrails
    "GuardrailError",
    "validate_ioc_input",
    "sanitize_context",
    "validate_agent_output",
    "AuditLogger",
]
