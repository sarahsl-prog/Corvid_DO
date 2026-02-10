"""Background task definitions for the enrichment worker.

Tasks are designed to run via arq (Redis-backed async task queue).
Each task is a standalone async function that receives context from the worker.
"""

import os
from typing import Any

from loguru import logger

from corvid.db.session import async_session
from corvid.worker.orchestrator import EnrichmentOrchestrator
from corvid.worker.providers.abuseipdb import AbuseIPDBProvider
from corvid.worker.providers.nvd import NVDProvider
from corvid.worker.providers.urlhaus import URLhausProvider


def _build_providers() -> list:
    """Build the list of enrichment providers from environment config."""
    providers = []

    abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY", "")
    if abuseipdb_key:
        providers.append(AbuseIPDBProvider(api_key=abuseipdb_key))
    else:
        logger.warning("ABUSEIPDB_API_KEY not set, skipping AbuseIPDB provider")

    # URLhaus is free, no key needed
    providers.append(URLhausProvider())

    # NVD works without a key (just rate-limited)
    nvd_key = os.getenv("NVD_API_KEY")
    providers.append(NVDProvider(api_key=nvd_key))

    return providers


async def enrich_ioc_task(
    ctx: dict[str, Any], ioc_id: str, ioc_type: str, ioc_value: str
) -> dict[str, Any]:
    """Background task: enrich an IOC using all applicable providers.

    Args:
        ctx: arq worker context dict.
        ioc_id: UUID string of the IOC to enrich.
        ioc_type: IOC type string (e.g. 'ip', 'domain').
        ioc_value: The IOC value to enrich.

    Returns:
        Dict with ioc_id and per-provider results summary.
    """
    logger.info("Starting enrichment task for IOC {} ({}={})", ioc_id, ioc_type, ioc_value)

    providers = _build_providers()
    orchestrator = EnrichmentOrchestrator(providers)

    async with async_session() as db:
        results = await orchestrator.enrich_and_store(
            db=db,
            ioc_id=ioc_id,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
        )

    summary = {
        "ioc_id": ioc_id,
        "results": [
            {"source": r.source, "success": r.success, "summary": r.summary}
            for r in results
        ],
    }
    logger.info("Enrichment task complete for IOC {}: {} results", ioc_id, len(results))
    return summary
