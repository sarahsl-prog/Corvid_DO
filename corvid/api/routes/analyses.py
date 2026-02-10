"""Analysis retrieval endpoints.

The /analyze endpoint (POST) will be added in Phase 3 when the Gradient
agent is integrated. For now, this provides read-only access to stored analyses.
"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from corvid.api.models.analysis import AnalysisResponse
from corvid.db.models import Analysis
from corvid.db.session import get_db

router = APIRouter(prefix="/analyses", tags=["Analyses"])


@router.get("/{analysis_id}", response_model=AnalysisResponse)
async def get_analysis(analysis_id: UUID, db: AsyncSession = Depends(get_db)) -> Analysis:
    """Retrieve a specific analysis by ID."""
    result = await db.execute(select(Analysis).where(Analysis.id == analysis_id))
    analysis = result.scalar_one_or_none()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    logger.debug("Analysis retrieved: id={}", analysis_id)
    return analysis
