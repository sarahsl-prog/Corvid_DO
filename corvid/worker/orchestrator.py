"""Enrichment orchestrator.

Runs all applicable enrichment providers concurrently for a given IOC
and optionally persists results to the database.
"""

import asyncio
from uuid import UUID

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from corvid.db.models import Enrichment
from corvid.worker.enrichment import BaseEnrichmentProvider, EnrichmentResult
from corvid.worker.normalizer import normalize_ioc


class EnrichmentOrchestrator:
    """Coordinates concurrent enrichment across multiple providers.

    Args:
        providers: List of enrichment provider instances to use.
    """

    def __init__(self, providers: list[BaseEnrichmentProvider]) -> None:
        self.providers = providers

    async def enrich_ioc(
        self, ioc_type: str, ioc_value: str
    ) -> list[EnrichmentResult]:
        """Run all applicable providers concurrently for an IOC.

        Args:
            ioc_type: The IOC type string (e.g. 'ip', 'domain').
            ioc_value: The IOC value (will be normalized).

        Returns:
            List of EnrichmentResults from all applicable providers.
        """
        normalized = normalize_ioc(ioc_value)
        applicable = [p for p in self.providers if p.supports(ioc_type)]

        if not applicable:
            logger.info("No applicable providers for IOC type: {}", ioc_type)
            return []

        logger.info(
            "Enriching {} ({}) with {} provider(s): {}",
            normalized,
            ioc_type,
            len(applicable),
            [p.source_name for p in applicable],
        )

        tasks = [p.enrich(ioc_type, normalized) for p in applicable]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        enrichment_results: list[EnrichmentResult] = []
        for r in results:
            if isinstance(r, Exception):
                logger.error("Provider raised exception: {}", r)
                enrichment_results.append(
                    EnrichmentResult(
                        source="unknown",
                        raw_response={},
                        summary="",
                        success=False,
                        error=str(r),
                    )
                )
            else:
                enrichment_results.append(r)

        successful = sum(1 for r in enrichment_results if r.success)
        logger.info(
            "Enrichment complete: {}/{} providers succeeded",
            successful,
            len(enrichment_results),
        )
        return enrichment_results

    async def enrich_and_store(
        self, db: AsyncSession, ioc_id: UUID, ioc_type: str, ioc_value: str
    ) -> list[EnrichmentResult]:
        """Enrich an IOC and persist successful results to the database.

        Args:
            db: Async database session.
            ioc_id: UUID of the IOC record to attach enrichments to.
            ioc_type: The IOC type string.
            ioc_value: The IOC value.

        Returns:
            List of EnrichmentResults from all applicable providers.
        """
        results = await self.enrich_ioc(ioc_type, ioc_value)

        for result in results:
            if result.success:
                enrichment = Enrichment(
                    ioc_id=ioc_id,
                    source=result.source,
                    raw_response=result.raw_response,
                    summary=result.summary,
                )
                db.add(enrichment)

        await db.commit()
        logger.info("Stored {} enrichment(s) for IOC {}", sum(1 for r in results if r.success), ioc_id)
        return results
