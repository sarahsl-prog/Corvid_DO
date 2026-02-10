"""AbuseIPDB enrichment provider.

Queries the AbuseIPDB v2 API for IP reputation data including
abuse confidence score, total reports, country, ISP, and usage type.
"""

import httpx
from loguru import logger

from corvid.worker.enrichment import BaseEnrichmentProvider, EnrichmentResult

ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"


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
                data = resp.json().get("data", {})

                score = data.get("abuseConfidenceScore", 0)
                reports = data.get("totalReports", 0)
                country = data.get("countryCode", "unknown")

                logger.info(
                    "AbuseIPDB lookup for {}: score={}, reports={}, country={}",
                    ioc_value, score, reports, country,
                )

                return EnrichmentResult(
                    source=self.source_name,
                    raw_response=data,
                    summary=f"Abuse confidence: {score}%, {reports} reports, country: {country}",
                    success=True,
                )
        except httpx.HTTPError as e:
            logger.error("AbuseIPDB lookup failed for {}: {}", ioc_value, e)
            return EnrichmentResult(
                source=self.source_name,
                raw_response={},
                summary="",
                success=False,
                error=str(e),
            )
