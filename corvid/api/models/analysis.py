"""Pydantic models for Analysis API responses."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class AnalysisResponse(BaseModel):
    """Response model for a threat analysis result."""

    id: UUID
    ioc_ids: list[UUID]
    analysis_text: str
    confidence: float
    mitre_techniques: list[str]
    recommended_actions: list[str]
    created_at: datetime

    model_config = {"from_attributes": True}
