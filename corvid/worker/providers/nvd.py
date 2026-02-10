"""NVD (National Vulnerability Database) enrichment provider.

Queries the NVD CVE 2.0 API for vulnerabilities related to an IOC.
NVD doesn't directly index IOCs, so this uses keyword search to find
related CVEs -- most useful when the IOC is associated with known software.
"""

import httpx
from loguru import logger

from corvid.worker.enrichment import BaseEnrichmentProvider, EnrichmentResult

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDProvider(BaseEnrichmentProvider):
    """Enrichment provider for NVD CVE search."""

    source_name = "nvd"
    supported_types = ["ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256"]

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key

    async def enrich(self, ioc_type: str, ioc_value: str) -> EnrichmentResult:
        """Search NVD for CVEs related to this IOC via keyword search.

        Args:
            ioc_type: The IOC type string.
            ioc_value: The IOC value to use as search keyword.

        Returns:
            EnrichmentResult with CVE IDs, descriptions, and total count.
        """
        try:
            headers: dict[str, str] = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    NVD_API_URL,
                    params={"keywordSearch": ioc_value, "resultsPerPage": 5},
                    headers=headers,
                )
                resp.raise_for_status()
                data = resp.json()

                total = data.get("totalResults", 0)
                cves = []
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "")
                    desc = ""
                    for d in cve.get("descriptions", []):
                        if d.get("lang") == "en":
                            desc = d.get("value", "")
                            break
                    cves.append({"cve_id": cve_id, "description": desc[:200]})

                top_ids = ", ".join(c["cve_id"] for c in cves[:3])
                logger.info("NVD search for {}: {} CVE(s) found", ioc_value, total)

                return EnrichmentResult(
                    source=self.source_name,
                    raw_response={"total_results": total, "cves": cves},
                    summary=f"NVD: {total} CVE(s) found. Top: {top_ids}" if top_ids
                    else f"NVD: {total} CVE(s) found.",
                    success=True,
                )
        except httpx.HTTPError as e:
            logger.error("NVD lookup failed for {}: {}", ioc_value, e)
            return EnrichmentResult(
                source=self.source_name,
                raw_response={},
                summary="",
                success=False,
                error=str(e),
            )
