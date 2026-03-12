"""AbuseIPDB enrichment provider.

Queries the AbuseIPDB v2 API for IP reputation data including
abuse confidence score, total reports, country, ISP, and usage type.
"""

import json
import re

import httpx
from loguru import logger

from corvid.worker.enrichment import BaseEnrichmentProvider, EnrichmentResult

ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"

# Patterns to redact from logs (API keys, tokens, auth headers)
_SENSITIVE_PATTERNS = [
    re.compile(r'[Kk]ey[=:]\s*\S+', re.IGNORECASE),
    re.compile(r'[Aa]uthorization[=:]\s*\S+', re.IGNORECASE),
    re.compile(r'[Tt]oken[=:]\s*\S+', re.IGNORECASE),
    re.compile(r'[Aa]pi[_-]?[Kk]ey[=:]?\s*\S+', re.IGNORECASE),
]


def _sanitize_error(error_msg: str) -> str:
    """Redact sensitive patterns from error messages before logging.

    Args:
        error_msg: The original error message.

    Returns:
        Sanitized message with sensitive values replaced with [REDACTED].
    """
    result = error_msg
    for pattern in _SENSITIVE_PATTERNS:
        result = pattern.sub('[REDACTED]', result)
    return result


class AbuseIPDBProvider(BaseEnrichmentProvider):
    """Enrichment provider for AbuseIPDB IP reputation lookups."""

    source_name = "abuseipdb"
    supported_types = ["ip"]

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    async def enrich(self, ioc_type: str, ioc_value: str) -> EnrichmentResult:
        """Look up an IP address in AbuseIPDB.

        Args:
            ioc_type: Must be 'ip'.
            ioc_value: The IP address to check.

        Returns:
            EnrichmentResult with abuse confidence score, report count, and country.
        """
        if not self.supports(ioc_type):
            return EnrichmentResult(
                source=self.source_name,
                raw_response={},
                summary=f"AbuseIPDB does not support IOC type: {ioc_type}",
                success=False,
                error="unsupported_type",
            )

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    ABUSEIPDB_API_URL,
                    params={"ipAddress": ioc_value, "maxAgeInDays": 90},
                    headers={"Key": self.api_key, "Accept": "application/json"},
                )
                resp.raise_for_status()
                try:
                    data = resp.json().get("data", {})
                except json.JSONDecodeError as e:
                    sanitized_error = _sanitize_error(str(e))
                    logger.error(
                        "AbuseIPDB returned invalid JSON for {}: {}", ioc_value, sanitized_error
                    )
                    return EnrichmentResult(
                        source=self.source_name,
                        raw_response={
                            "error": "invalid_json",
                            "preview": resp.text[:500],
                        },
                        summary="",
                        success=False,
                        error=f"Invalid JSON response: {sanitized_error}",
                    )

                score = data.get("abuseConfidenceScore", 0)
                reports = data.get("totalReports", 0)
                country = data.get("countryCode", "unknown")

                logger.info(
                    "AbuseIPDB lookup for {}: score={}, reports={}, country={}",
                    ioc_value,
                    score,
                    reports,
                    country,
                )

                return EnrichmentResult(
                    source=self.source_name,
                    raw_response=data,
                    summary=f"Abuse confidence: {score}%, {reports} reports, country: {country}",
                    success=True,
                )
        except httpx.HTTPError as e:
            sanitized_error = _sanitize_error(str(e))
            logger.error("AbuseIPDB lookup failed for {}: {}", ioc_value, sanitized_error)
            return EnrichmentResult(
                source=self.source_name,
                raw_response={},
                summary="",
                success=False,
                error=sanitized_error,
            )
