"""URLhaus (abuse.ch) enrichment provider.

Queries the URLhaus API for malicious URL, domain, and IP intelligence.
URLhaus is a free, community-driven service -- no API key required.
"""

import httpx
from loguru import logger

from corvid.worker.enrichment import BaseEnrichmentProvider, EnrichmentResult

URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1"


class URLhausProvider(BaseEnrichmentProvider):
    """Enrichment provider for URLhaus malicious URL lookups."""

    source_name = "urlhaus"
    supported_types = ["url", "domain", "ip"]

    async def enrich(self, ioc_type: str, ioc_value: str) -> EnrichmentResult:
        """Look up a URL, domain, or IP in URLhaus.

        Args:
            ioc_type: One of 'url', 'domain', or 'ip'.
            ioc_value: The IOC value to check.

        Returns:
            EnrichmentResult with URL count, threat type, and status.
        """
        if not self.supports(ioc_type):
            return EnrichmentResult(
                source=self.source_name,
                raw_response={},
                summary=f"URLhaus does not support IOC type: {ioc_type}",
                success=False,
                error="unsupported_type",
            )

        # Map IOC types to URLhaus API endpoints and parameters
        endpoint_map = {"url": "/url/", "domain": "/host/", "ip": "/host/"}
        param_map = {
            "url": {"url": ioc_value},
            "domain": {"host": ioc_value},
            "ip": {"host": ioc_value},
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    f"{URLHAUS_API_URL}{endpoint_map[ioc_type]}",
                    data=param_map[ioc_type],
                )
                resp.raise_for_status()
                data = resp.json()

                status = data.get("query_status", "unknown")
                if status == "no_results":
                    logger.info("URLhaus: no results for {} ({})", ioc_value, ioc_type)
                    return EnrichmentResult(
                        source=self.source_name,
                        raw_response=data,
                        summary="No URLhaus records found for this IOC.",
                        success=True,
                    )

                url_count = data.get("url_count", len(data.get("urls", [])))
                threat = data.get("threat", "unknown")

                logger.info(
                    "URLhaus lookup for {}: {} URL(s), threat={}",
                    ioc_value, url_count, threat,
                )

                return EnrichmentResult(
                    source=self.source_name,
                    raw_response=data,
                    summary=f"URLhaus: {url_count} URL(s), threat type: {threat}",
                    success=True,
                )
        except httpx.HTTPError as e:
            logger.error("URLhaus lookup failed for {}: {}", ioc_value, e)
            return EnrichmentResult(
                source=self.source_name,
                raw_response={},
                summary="",
                success=False,
                error=str(e),
            )
