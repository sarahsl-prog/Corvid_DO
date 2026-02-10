"""Input and output guardrails for the Corvid agent.

Validates IOC inputs before passing to the agent and validates
structured output from the agent response.
"""

import json
import re
from typing import Any

from loguru import logger
from pydantic import ValidationError

from corvid.api.models.analysis import AgentAnalysisOutput
from corvid.api.models.ioc import IOCType

# Patterns for validating identifiers
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
MITRE_TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")

# Maximum context length to prevent prompt injection via very long contexts
MAX_CONTEXT_LENGTH = 2000

# Characters/patterns to sanitize from context (potential injection attempts)
INJECTION_PATTERNS = [
    r"<\|.*?\|>",  # Special tokens
    r"\[INST\].*?\[/INST\]",  # Instruction markers
    r"```system",  # System prompt injection
    r"IGNORE PREVIOUS",  # Common injection phrase
    r"disregard.*instructions",  # Common injection phrase
]


class GuardrailError(Exception):
    """Raised when input or output fails guardrail validation."""

    def __init__(self, message: str, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.details = details or {}


def validate_ioc_input(ioc_type: str, ioc_value: str) -> tuple[str, str]:
    """Validate and sanitize IOC input before passing to agent.

    Args:
        ioc_type: The IOC type string.
        ioc_value: The IOC value.

    Returns:
        Tuple of (validated_type, validated_value).

    Raises:
        GuardrailError: If validation fails.
    """
    # Validate type is known
    ioc_type_lower = ioc_type.strip().lower()
    valid_types = [t.value for t in IOCType]
    if ioc_type_lower not in valid_types:
        raise GuardrailError(
            f"Invalid IOC type: {ioc_type}",
            {"valid_types": valid_types, "received": ioc_type},
        )

    # Validate value is not empty and has reasonable length
    ioc_value_stripped = ioc_value.strip()
    if not ioc_value_stripped:
        raise GuardrailError("IOC value cannot be empty")

    if len(ioc_value_stripped) > 2048:
        raise GuardrailError(
            "IOC value too long",
            {"max_length": 2048, "received_length": len(ioc_value_stripped)},
        )

    # Type-specific validation
    if ioc_type_lower == "ip":
        if not _is_valid_ip(ioc_value_stripped):
            raise GuardrailError(f"Invalid IP address format: {ioc_value_stripped}")
    elif ioc_type_lower in ("hash_md5", "hash_sha1", "hash_sha256"):
        if not _is_valid_hash(ioc_value_stripped, ioc_type_lower):
            raise GuardrailError(f"Invalid hash format for {ioc_type}: {ioc_value_stripped}")

    logger.debug("IOC input validated: {} ({})", ioc_value_stripped[:50], ioc_type_lower)
    return ioc_type_lower, ioc_value_stripped


def sanitize_context(context: str) -> str:
    """Sanitize user-provided context to prevent prompt injection.

    Args:
        context: User-provided context string.

    Returns:
        Sanitized context string.

    Raises:
        GuardrailError: If context contains blocked patterns.
    """
    if not context:
        return ""

    # Enforce max length
    if len(context) > MAX_CONTEXT_LENGTH:
        logger.warning(
            "Context truncated from {} to {} chars",
            len(context),
            MAX_CONTEXT_LENGTH,
        )
        context = context[:MAX_CONTEXT_LENGTH]

    # Check for injection patterns
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, context, re.IGNORECASE):
            logger.warning("Potential injection attempt detected in context")
            raise GuardrailError(
                "Context contains disallowed patterns",
                {"pattern_matched": pattern},
            )

    # Escape any remaining special characters
    # Remove null bytes and other control characters
    context = "".join(char for char in context if ord(char) >= 32 or char in "\n\t")

    return context.strip()


def validate_agent_output(output_text: str) -> AgentAnalysisOutput:
    """Parse and validate the agent's JSON output.

    Args:
        output_text: Raw text output from the agent.

    Returns:
        Validated AgentAnalysisOutput model.

    Raises:
        GuardrailError: If output is invalid.
    """
    # Try to extract JSON from the output
    json_str = _extract_json(output_text)
    if not json_str:
        raise GuardrailError(
            "Agent output does not contain valid JSON",
            {"raw_output": output_text[:500]},
        )

    # Parse JSON
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise GuardrailError(
            f"Invalid JSON in agent output: {e}",
            {"json_error": str(e), "raw_output": json_str[:500]},
        )

    # Validate against Pydantic model
    try:
        result = AgentAnalysisOutput.model_validate(data)
    except ValidationError as e:
        raise GuardrailError(
            "Agent output failed schema validation",
            {"validation_errors": e.errors(), "raw_data": data},
        )

    # Validate CVE ID formats
    invalid_cves = [
        cve for cve in result.related_cves if not CVE_PATTERN.match(cve)
    ]
    if invalid_cves:
        logger.warning("Agent returned invalid CVE IDs: {}", invalid_cves)
        # Filter out invalid CVEs rather than failing
        result.related_cves = [
            cve for cve in result.related_cves if CVE_PATTERN.match(cve)
        ]

    # Validate MITRE technique ID formats
    invalid_techniques = [
        t for t in result.mitre_techniques if not MITRE_TECHNIQUE_PATTERN.match(t)
    ]
    if invalid_techniques:
        logger.warning("Agent returned invalid MITRE technique IDs: {}", invalid_techniques)
        # Filter out invalid techniques rather than failing
        result.mitre_techniques = [
            t for t in result.mitre_techniques if MITRE_TECHNIQUE_PATTERN.match(t)
        ]

    logger.debug("Agent output validated successfully")
    return result


def _extract_json(text: str) -> str | None:
    """Extract JSON object from text that may contain other content.

    Args:
        text: Raw text that may contain a JSON object.

    Returns:
        Extracted JSON string or None if not found.
    """
    # Try to find JSON block in markdown code fence
    json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if json_match:
        return json_match.group(1)

    # Try to find raw JSON object
    # Find the first { and last } and extract
    first_brace = text.find("{")
    last_brace = text.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        return text[first_brace : last_brace + 1]

    return None


def _is_valid_ip(value: str) -> bool:
    """Check if value is a valid IPv4 or IPv6 address."""
    import ipaddress

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_valid_hash(value: str, hash_type: str) -> bool:
    """Check if value is a valid hash of the specified type."""
    expected_lengths = {
        "hash_md5": 32,
        "hash_sha1": 40,
        "hash_sha256": 64,
    }
    expected_len = expected_lengths.get(hash_type, 0)
    if len(value) != expected_len:
        return False
    return all(c in "0123456789abcdefABCDEF" for c in value)


def build_retry_prompt(error: GuardrailError, original_output: str) -> str:
    """Build a prompt for retrying after validation failure.

    Args:
        error: The guardrail error that occurred.
        original_output: The agent's original output.

    Returns:
        A prompt instructing the agent to fix its output.
    """
    return f"""Your previous response failed validation with the following error:

Error: {error}
Details: {json.dumps(error.details, indent=2)}

Please provide a corrected response that:
1. Is valid JSON
2. Matches the required schema
3. Uses valid CVE IDs (format: CVE-YYYY-NNNNN)
4. Uses valid MITRE ATT&CK technique IDs (format: TNNNN or TNNNN.NNN)

Your previous output was:
{original_output[:1000]}

Please respond with ONLY the corrected JSON, no other text."""


class AuditLogger:
    """Logs agent interactions for audit and debugging."""

    def __init__(self, trace_id: str):
        self.trace_id = trace_id
        self.events: list[dict[str, Any]] = []

    def log_input(self, ioc_type: str, ioc_value: str, context: str) -> None:
        """Log the input to the agent."""
        self.events.append(
            {
                "event": "input",
                "trace_id": self.trace_id,
                "ioc_type": ioc_type,
                "ioc_value": ioc_value,
                "context_length": len(context),
            }
        )
        logger.info(
            "[{}] Agent input: {} ({}) with {} chars context",
            self.trace_id,
            ioc_value[:50],
            ioc_type,
            len(context),
        )

    def log_tool_call(self, tool_name: str, args: dict[str, Any], result: Any) -> None:
        """Log a tool call made by the agent."""
        self.events.append(
            {
                "event": "tool_call",
                "trace_id": self.trace_id,
                "tool": tool_name,
                "args": args,
                "result_summary": str(result)[:200],
            }
        )
        logger.debug("[{}] Tool call: {}({})", self.trace_id, tool_name, args)

    def log_output(self, output: AgentAnalysisOutput, success: bool) -> None:
        """Log the agent's output."""
        self.events.append(
            {
                "event": "output",
                "trace_id": self.trace_id,
                "success": success,
                "severity": output.severity,
                "confidence": output.confidence,
                "cve_count": len(output.related_cves),
                "technique_count": len(output.mitre_techniques),
            }
        )
        logger.info(
            "[{}] Agent output: severity={}, confidence={}, success={}",
            self.trace_id,
            output.severity,
            output.confidence,
            success,
        )

    def log_error(self, error: Exception) -> None:
        """Log an error that occurred during processing."""
        self.events.append(
            {
                "event": "error",
                "trace_id": self.trace_id,
                "error_type": type(error).__name__,
                "error_message": str(error),
            }
        )
        logger.error("[{}] Agent error: {}: {}", self.trace_id, type(error).__name__, error)

    def get_trace(self) -> list[dict[str, Any]]:
        """Get the full audit trace."""
        return self.events
