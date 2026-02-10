"""Analysis endpoints for AI-powered IOC analysis.

Provides endpoints for:
- POST /analyze: Submit IOCs for Gradient agent analysis
- GET /{analysis_id}: Retrieve a stored analysis by ID
"""

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from corvid.agent import CorvidAgent, GuardrailError
from corvid.api.models.analysis import (
    AnalysisResponse,
    AnalysisResultItem,
    AnalyzeRequest,
    AnalyzeResponse,
)
from corvid.db.models import Analysis, IOC
from corvid.db.session import get_db
from corvid.worker.normalizer import normalize_ioc
from corvid.worker.orchestrator import EnrichmentOrchestrator
from corvid.worker.tasks import _build_providers

router = APIRouter(prefix="/analyses", tags=["Analyses"])


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_iocs(
    request: AnalyzeRequest,
    db: AsyncSession = Depends(get_db),
) -> AnalyzeResponse:
    """Submit IOC(s) for full AI-powered analysis.

    Pipeline:
    1. Validate and normalize each IOC
    2. Create/update IOC records in DB
    3. Run enrichment on each IOC
    4. Invoke Gradient agent with IOC data + enrichments
    5. Store analysis in DB
    6. Return structured results
    """
    logger.info(
        "Analyze request: {} IOC(s), priority={}, context_len={}",
        len(request.iocs),
        request.priority,
        len(request.context),
    )

    results: list[AnalysisResultItem] = []
    ioc_ids: list[UUID] = []
    agent = CorvidAgent()
    orchestrator = EnrichmentOrchestrator(_build_providers())

    # Track overall status
    success_count = 0
    failure_count = 0

    for ioc_input in request.iocs:
        ioc_type = ioc_input.type.value
        ioc_value = normalize_ioc(ioc_input.value)

        try:
            # Step 1: Create or get existing IOC record
            ioc = await _get_or_create_ioc(db, ioc_type, ioc_value, ioc_input.tags)
            ioc_ids.append(ioc.id)

            # Step 2: Run enrichment
            enrichment_results = await orchestrator.enrich_and_store(
                db=db,
                ioc_id=ioc.id,
                ioc_type=ioc_type,
                ioc_value=ioc_value,
            )

            # Step 3: Invoke agent
            agent_output = await agent.analyze_ioc(
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                context=request.context,
                db=db,
            )

            # Step 4: Build enrichments dict from results
            enrichments = {}
            for er in enrichment_results:
                if er.success:
                    enrichments[er.source] = {
                        "summary": er.summary,
                        "raw": er.raw_response,
                    }

            # Step 5: Build result item
            result_item = AnalysisResultItem(
                ioc=ioc_input,
                severity=agent_output.severity,
                confidence=agent_output.confidence,
                summary=agent_output.summary,
                related_cves=agent_output.related_cves,
                mitre_techniques=agent_output.mitre_techniques,
                enrichments=enrichments,
                recommended_actions=agent_output.recommended_actions,
            )
            results.append(result_item)
            success_count += 1

            # Update IOC severity based on analysis
            ioc.severity_score = agent_output.severity
            ioc.last_seen = datetime.now(timezone.utc)

        except GuardrailError as e:
            logger.warning("Guardrail error for IOC {}: {}", ioc_value, e)
            failure_count += 1
            # Add failed result with error info
            results.append(
                AnalysisResultItem(
                    ioc=ioc_input,
                    severity=0.0,
                    confidence=0.0,
                    summary=f"Analysis failed: {e}",
                    related_cves=[],
                    mitre_techniques=[],
                    enrichments={},
                    recommended_actions=["Retry analysis or investigate manually"],
                )
            )
        except Exception as e:
            logger.error("Analysis failed for IOC {}: {}", ioc_value, e)
            failure_count += 1
            results.append(
                AnalysisResultItem(
                    ioc=ioc_input,
                    severity=0.0,
                    confidence=0.0,
                    summary=f"Analysis failed: {e}",
                    related_cves=[],
                    mitre_techniques=[],
                    enrichments={},
                    recommended_actions=["Retry analysis or investigate manually"],
                )
            )

    # Determine overall status
    if failure_count == 0:
        status = "completed"
    elif success_count == 0:
        status = "failed"
    else:
        status = "partial"

    # Store analysis record
    analysis = Analysis(
        ioc_ids=[str(ioc_id) for ioc_id in ioc_ids],
        analysis_text=_build_analysis_text(results),
        confidence=sum(r.confidence for r in results) / len(results) if results else 0.0,
        mitre_techniques=list(set(t for r in results for t in r.mitre_techniques)),
        recommended_actions=list(set(a for r in results for a in r.recommended_actions)),
    )
    db.add(analysis)
    await db.commit()
    await db.refresh(analysis)

    logger.info(
        "Analysis complete: id={}, status={}, success={}, failed={}",
        analysis.id,
        status,
        success_count,
        failure_count,
    )

    return AnalyzeResponse(
        analysis_id=analysis.id,
        status=status,
        results=results,
    )


@router.get("/{analysis_id}", response_model=AnalysisResponse)
async def get_analysis(
    analysis_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> Analysis:
    """Retrieve a specific analysis by ID."""
    result = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
    analysis = result.scalar_one_or_none()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    logger.debug("Analysis retrieved: id={}", analysis_id)
    return analysis


async def _get_or_create_ioc(
    db: AsyncSession,
    ioc_type: str,
    ioc_value: str,
    tags: list[str],
) -> IOC:
    """Get existing IOC or create new one.

    Args:
        db: Database session.
        ioc_type: IOC type string.
        ioc_value: Normalized IOC value.
        tags: Tags to apply.

    Returns:
        IOC record (existing or newly created).
    """
    # Check for existing
    stmt = select(IOC).where(IOC.type == ioc_type, IOC.value == ioc_value)
    result = await db.execute(stmt)
    ioc = result.scalar_one_or_none()

    if ioc:
        # Update last_seen and merge tags
        ioc.last_seen = datetime.now(timezone.utc)
        existing_tags = set(ioc.tags or [])
        existing_tags.update(tags)
        ioc.tags = list(existing_tags)
        logger.debug("Found existing IOC: {}", ioc.id)
    else:
        # Create new
        ioc = IOC(
            type=ioc_type,
            value=ioc_value,
            tags=tags,
        )
        db.add(ioc)
        await db.flush()  # Get ID without committing
        logger.debug("Created new IOC: {}", ioc.id)

    return ioc


def _build_analysis_text(results: list[AnalysisResultItem]) -> str:
    """Build combined analysis text from all result items.

    Args:
        results: List of analysis result items.

    Returns:
        Combined analysis text for storage.
    """
    parts = []
    for r in results:
        parts.append(f"## {r.ioc.type.value}: {r.ioc.value}")
        parts.append(f"Severity: {r.severity}/10 (Confidence: {r.confidence})")
        parts.append(r.summary)
        if r.related_cves:
            parts.append(f"CVEs: {', '.join(r.related_cves)}")
        if r.mitre_techniques:
            parts.append(f"MITRE: {', '.join(r.mitre_techniques)}")
        parts.append("")

    return "\n".join(parts)
