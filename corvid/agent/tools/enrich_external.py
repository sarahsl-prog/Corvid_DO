"""Agent tool for fetching fresh threat intel from external sources.

Wraps the existing enrichment orchestrator so the agent can trigger
on-demand enrichment during analysis.
"""

from typing import Any
from uuid import UUID

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from corvid.worker.enrichment import EnrichmentResult
from corvid.worker.orchestrator import EnrichmentOrchestrator
from corvid.worker.tasks import _build_providers


async def enrich_ioc_external(
    ioc_type: str,
    ioc_value: str,
    sources: list[str] | None = None,
    db: AsyncSession | None = None,
    ioc_id: UUID | None = None,
) -> dict[str, Any]:
    """Fetch fresh threat intel from external sources.

    Wraps the existing enrichment orchestrator so the agent can trigger
    on-demand enrichment during analysis.

    Args:
        ioc_type: The IOC type (e.g., "ip", "domain").
        ioc_value: The IOC value to enrich.
        sources: Optional list of specific sources to query.
                 If None, queries all applicable sources.
        db: Optional database session for storing results.
        ioc_id: Optional IOC UUID for attaching stored enrichments.

    Returns:
        Dict containing:
        - success: Whether any enrichment succeeded
        - enrichments: List of enrichment results by source
        - total_sources: Number of sources queried
        - successful_sources: Number of successful enrichments
        - message: Human-readable status
    """
    logger.info("External enrichment requested for {} ({})", ioc_value, ioc_type)

    # Build providers
    providers = _build_providers()

    # Filter to requested sources if specified
    if sources:
        sources_lower = [s.lower() for s in sources]
        providers = [p for p in providers if p.source_name.lower() in sources_lower]
        logger.debug("Filtered to {} requested source(s)", len(providers))

    if not providers:
        return {
            "success": False,
            "enrichments": [],
            "total_sources": 0,
            "successful_sources": 0,
            "message": "No enrichment providers available or configured. "
            "Check API key environment variables.",
        }

    orchestrator = EnrichmentOrchestrator(providers)

    # Run enrichment (with optional DB storage)
    if db and ioc_id:
        results = await orchestrator.enrich_and_store(
            db=db,
            ioc_id=ioc_id,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
        )
    else:
        results = await orchestrator.enrich_ioc(ioc_type, ioc_value)

    # Format results
    enrichments = []
    for result in results:
        enrichments.append(
            {
                "source": result.source,
                "success": result.success,
                "summary": result.summary if result.success else None,
                "error": result.error if not result.success else None,
                "raw_response": result.raw_response if result.success else None,
            }
        )

    successful_count = sum(1 for r in results if r.success)
    total_count = len(results)

    # Build message
    if successful_count == 0:
        message = f"Enrichment failed for all {total_count} sources queried."
    elif successful_count == total_count:
        source_names = [r.source for r in results if r.success]
        message = (
            f"Successfully enriched from {successful_count} source(s): "
            + ", ".join(source_names)
        )
    else:
        success_names = [r.source for r in results if r.success]
        failed_names = [r.source for r in results if not r.success]
        message = (
            f"Enriched from {successful_count}/{total_count} sources. "
            f"Success: {', '.join(success_names)}. "
            f"Failed: {', '.join(failed_names)}."
        )

    logger.info(
        "External enrichment complete: {}/{} succeeded",
        successful_count,
        total_count,
    )

    return {
        "success": successful_count > 0,
        "enrichments": enrichments,
        "total_sources": total_count,
        "successful_sources": successful_count,
        "message": message,
    }


def get_available_sources() -> list[dict[str, Any]]:
    """Get information about available enrichment sources.

    Returns:
        List of source info dicts with name and supported IOC types.
    """
    providers = _build_providers()
    return [
        {
            "name": p.source_name,
            "supported_types": p.supported_types,
        }
        for p in providers
    ]


# Tool schema for Gradient agent registration
ENRICH_EXTERNAL_SCHEMA = {
    "name": "enrich_ioc_external",
    "description": "Fetch fresh threat intelligence from external sources for an IOC. "
    "Use this when the local database has no data or you need current intel. "
    "Available sources include AbuseIPDB (IPs), URLhaus (URLs/domains), and NVD (CVE search).",
    "parameters": {
        "type": "object",
        "properties": {
            "ioc_type": {
                "type": "string",
                "description": "The IOC type (ip, domain, url, hash_md5, hash_sha1, hash_sha256, email)",
                "enum": ["ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256", "email"],
            },
            "ioc_value": {
                "type": "string",
                "description": "The IOC value to enrich",
            },
            "sources": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional list of specific sources to query (e.g., ['abuseipdb', 'urlhaus']). "
                "If not specified, all applicable sources are queried.",
            },
        },
        "required": ["ioc_type", "ioc_value"],
    },
}
