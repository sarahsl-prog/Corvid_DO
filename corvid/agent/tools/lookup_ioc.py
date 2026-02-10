"""Agent tool for looking up IOCs in the Corvid database.

Returns enrichment data, past analyses, severity scores, and tags
for an IOC. Called by the Gradient agent during analysis.
"""

from typing import Any
from uuid import UUID

from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from corvid.db.models import Analysis, CVEReference, Enrichment, IOC


async def lookup_ioc(
    db: AsyncSession,
    ioc_type: str,
    ioc_value: str,
) -> dict[str, Any]:
    """Look up an IOC in the Corvid database.

    Returns enrichment data, past analyses, severity score, and tags.
    Called by the Gradient agent during analysis.

    Args:
        db: Async database session.
        ioc_type: The IOC type (e.g., "ip", "domain", "hash_sha256").
        ioc_value: The IOC value to look up.

    Returns:
        Dict containing:
        - found: Whether the IOC exists in the database
        - ioc: IOC details (id, type, value, tags, severity_score, first_seen, last_seen)
        - enrichments: List of enrichment summaries by source
        - past_analyses: List of past analysis summaries
        - cve_references: List of associated CVE IDs
        - message: Human-readable status message
    """
    ioc_value_normalized = ioc_value.strip().lower()
    ioc_type_normalized = ioc_type.strip().lower()

    logger.debug("Looking up IOC: {} ({})", ioc_value_normalized, ioc_type_normalized)

    # Query IOC with enrichments loaded
    stmt = (
        select(IOC)
        .options(selectinload(IOC.enrichments))
        .where(IOC.type == ioc_type_normalized, IOC.value == ioc_value_normalized)
    )
    result = await db.execute(stmt)
    ioc = result.scalar_one_or_none()

    if not ioc:
        logger.info("IOC not found in database: {} ({})", ioc_value, ioc_type)
        return {
            "found": False,
            "ioc": None,
            "enrichments": [],
            "past_analyses": [],
            "cve_references": [],
            "message": f"IOC {ioc_value} ({ioc_type}) not found in database. "
            "Consider using enrich_external tool to gather threat intel.",
        }

    # Build enrichment summaries
    enrichments = []
    for enrichment in ioc.enrichments:
        enrichments.append(
            {
                "source": enrichment.source,
                "summary": enrichment.summary,
                "fetched_at": enrichment.fetched_at.isoformat() if enrichment.fetched_at else None,
                "raw_response": enrichment.raw_response,
            }
        )

    # Look up past analyses that include this IOC
    analyses_stmt = select(Analysis).where(Analysis.ioc_ids.contains([str(ioc.id)]))
    analyses_result = await db.execute(analyses_stmt)
    analyses = analyses_result.scalars().all()

    past_analyses = []
    for analysis in analyses:
        past_analyses.append(
            {
                "id": str(analysis.id),
                "summary": analysis.analysis_text[:500] if analysis.analysis_text else "",
                "confidence": analysis.confidence,
                "mitre_techniques": analysis.mitre_techniques,
                "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
            }
        )

    # Look up CVE references
    cve_stmt = select(CVEReference).where(CVEReference.ioc_id == ioc.id)
    cve_result = await db.execute(cve_stmt)
    cve_refs = cve_result.scalars().all()

    cve_references = [
        {
            "cve_id": ref.cve_id,
            "cvss_score": ref.cvss_score,
            "description": ref.description[:200] if ref.description else None,
        }
        for ref in cve_refs
    ]

    logger.info(
        "Found IOC {} with {} enrichments, {} past analyses, {} CVE refs",
        ioc_value,
        len(enrichments),
        len(past_analyses),
        len(cve_references),
    )

    return {
        "found": True,
        "ioc": {
            "id": str(ioc.id),
            "type": ioc.type,
            "value": ioc.value,
            "tags": ioc.tags or [],
            "severity_score": ioc.severity_score,
            "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
            "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
        },
        "enrichments": enrichments,
        "past_analyses": past_analyses,
        "cve_references": cve_references,
        "message": f"Found IOC with {len(enrichments)} enrichment(s) from sources: "
        + ", ".join(e["source"] for e in enrichments)
        if enrichments
        else "Found IOC but no enrichments available yet.",
    }


# Tool schema for Gradient agent registration
LOOKUP_IOC_SCHEMA = {
    "name": "lookup_ioc",
    "description": "Look up an IOC in the Corvid database to retrieve stored enrichments, "
    "past analyses, severity scores, and tags. Use this first to check if we "
    "already have intelligence on this indicator.",
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
                "description": "The IOC value to look up",
            },
        },
        "required": ["ioc_type", "ioc_value"],
    },
}
