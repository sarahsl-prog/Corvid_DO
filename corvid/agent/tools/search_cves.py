"""Agent tool for searching CVEs related to an IOC or keyword.

Queries both the local cve_references table and the NVD API
to find relevant vulnerabilities.
"""

from typing import Any

import httpx
from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from corvid.config import settings
from corvid.db.models import CVEReference

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


async def search_cves(
    db: AsyncSession,
    query: str,
    max_results: int = 5,
) -> dict[str, Any]:
    """Search for CVEs related to a keyword.

    Queries both the local cve_references table and the NVD API.

    Args:
        db: Async database session.
        query: Search keyword (e.g., product name, vendor, CVE ID).
        max_results: Maximum number of results to return.

    Returns:
        Dict containing:
        - local_results: CVEs found in local database
        - nvd_results: CVEs found via NVD API search
        - total_found: Total unique CVEs found
        - message: Human-readable status
    """
    query_normalized = query.strip()
    logger.debug("Searching CVEs for query: {}", query_normalized)

    results: dict[str, Any] = {
        "local_results": [],
        "nvd_results": [],
        "total_found": 0,
        "message": "",
    }

    # Search local database first
    # Check if query looks like a CVE ID
    if query_normalized.upper().startswith("CVE-"):
        local_stmt = select(CVEReference).where(
            CVEReference.cve_id == query_normalized.upper()
        )
    else:
        # Search in description (basic LIKE search)
        local_stmt = (
            select(CVEReference)
            .where(CVEReference.description.ilike(f"%{query_normalized}%"))
            .limit(max_results)
        )

    local_result = await db.execute(local_stmt)
    local_cves = local_result.scalars().all()

    for cve in local_cves:
        results["local_results"].append(
            {
                "cve_id": cve.cve_id,
                "cvss_score": cve.cvss_score,
                "description": cve.description[:300] if cve.description else None,
                "source": "local_database",
            }
        )

    # Also search NVD API
    nvd_cves = await _search_nvd(query_normalized, max_results)
    results["nvd_results"] = nvd_cves

    # Deduplicate and count
    seen_cve_ids = set()
    for cve in results["local_results"] + results["nvd_results"]:
        seen_cve_ids.add(cve["cve_id"])
    results["total_found"] = len(seen_cve_ids)

    if results["total_found"] > 0:
        results["message"] = (
            f"Found {results['total_found']} CVE(s) matching '{query_normalized}'. "
            f"{len(results['local_results'])} from local DB, "
            f"{len(results['nvd_results'])} from NVD API."
        )
    else:
        results["message"] = f"No CVEs found matching '{query_normalized}'."

    logger.info(
        "CVE search for '{}': {} local, {} NVD",
        query_normalized,
        len(results["local_results"]),
        len(results["nvd_results"]),
    )

    return results


async def _search_nvd(query: str, max_results: int) -> list[dict[str, Any]]:
    """Search NVD API for CVEs matching a keyword.

    Args:
        query: Search keyword.
        max_results: Maximum results to return.

    Returns:
        List of CVE dicts with id, score, description.
    """
    headers: dict[str, str] = {}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    params: dict[str, Any] = {
        "resultsPerPage": max_results,
    }

    # If it looks like a CVE ID, search by ID; otherwise keyword search
    if query.upper().startswith("CVE-"):
        params["cveId"] = query.upper()
    else:
        params["keywordSearch"] = query

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(NVD_API_URL, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()

            cves = []
            for vuln in data.get("vulnerabilities", []):
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id", "")

                # Extract description
                description = ""
                for desc in cve_data.get("descriptions", []):
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break

                # Extract CVSS score
                cvss_score = None
                metrics = cve_data.get("metrics", {})
                for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if metrics.get(version):
                        cvss_data = metrics[version][0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        break

                cves.append(
                    {
                        "cve_id": cve_id,
                        "cvss_score": cvss_score,
                        "description": description[:300] if description else None,
                        "source": "nvd_api",
                    }
                )

            return cves
    except httpx.HTTPError as e:
        logger.error("NVD API search failed: {}", e)
        return []


async def get_cve_details(cve_id: str) -> dict[str, Any] | None:
    """Fetch detailed information about a specific CVE.

    Args:
        cve_id: The CVE ID (e.g., "CVE-2024-21762").

    Returns:
        Dict with full CVE details or None if not found.
    """
    headers: dict[str, str] = {}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                NVD_API_URL,
                params={"cveId": cve_id.upper()},
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None

            cve_data = vulns[0].get("cve", {})

            # Extract description
            description = ""
            for desc in cve_data.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Extract CVSS metrics
            cvss_info = {}
            metrics = cve_data.get("metrics", {})
            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if metrics.get(version):
                    cvss_data = metrics[version][0].get("cvssData", {})
                    cvss_info = {
                        "version": version,
                        "base_score": cvss_data.get("baseScore"),
                        "severity": cvss_data.get("baseSeverity"),
                        "vector": cvss_data.get("vectorString"),
                    }
                    break

            # Extract references
            references = [
                ref.get("url")
                for ref in cve_data.get("references", [])
                if ref.get("url")
            ][:10]

            return {
                "cve_id": cve_data.get("id"),
                "description": description,
                "published": cve_data.get("published"),
                "last_modified": cve_data.get("lastModified"),
                "cvss": cvss_info,
                "references": references,
            }
    except httpx.HTTPError as e:
        logger.error("Failed to fetch CVE {}: {}", cve_id, e)
        return None


# Tool schema for Gradient agent registration
SEARCH_CVES_SCHEMA = {
    "name": "search_cves",
    "description": "Search for CVEs (Common Vulnerabilities and Exposures) related to a keyword, "
    "product name, or vendor. Use this to find vulnerabilities that may be associated "
    "with the IOC being analyzed.",
    "parameters": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "Search keyword (product name, vendor, or CVE ID like 'CVE-2024-21762')",
            },
            "max_results": {
                "type": "integer",
                "description": "Maximum number of results to return (default: 5)",
                "default": 5,
            },
        },
        "required": ["query"],
    },
}
